#!/usr/bin/env python3
"""
BegonePOL helper: keeps the login in the desktop keyring and hands it to the plugin at launch.

As the Faugus pre-launch command (runs inside the Faugus sandbox, which has GTK 4, libadwaita and
libsecret):
    begonepol-helper.py [--slot <member row>] [account]
With several saved logins, the member row and/or Square Enix ID says which one to use. If a login is saved, it is written to $XDG_RUNTIME_DIR/begonepol/login (RAM only, mode 600) for
the plugin, which reads and deletes it straight away; otherwise the setup window opens first and the
plugin waits for it. The file is removed after 2 minutes if the game never gets that far.

To change the saved login later:
    begonepol-helper.py --setup [account]
(or "BegonePOL setup" in the application menu).

Keyring item: label "FINAL FANTASY XI - BegonePOL (<Square Enix ID>)", attributes application=begonepol,
account=<Square Enix ID>, slot=<member row>, otp=off|manual|auto; the secret is JSON
{"password": ..., "totp": <authenticator setup key, only for otp=auto>}.
Faugus needs: flatpak override --user --talk-name=org.freedesktop.secrets io.github.Faugus.faugus-launcher
"""

import base64
import hashlib
import hmac
import json
import os
import struct
import sys
import time

# Talk to the desktop keyring itself, not the flatpak portal's per-app file.
os.environ["SECRET_BACKEND"] = "service"

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
gi.require_version("Secret", "1")
from gi.repository import Adw, Gio, GLib, Gtk, Secret  # noqa: E402

SCHEMA = Secret.Schema.new(
    "org.freedesktop.Secret.Generic",
    Secret.SchemaFlags.DONT_MATCH_NAME,
    {
        "application": Secret.SchemaAttributeType.STRING,
        "account": Secret.SchemaAttributeType.STRING,
        "slot": Secret.SchemaAttributeType.STRING,
        "otp": Secret.SchemaAttributeType.STRING,
    },
)
MAX_PASSWORD = 15  # PlayOnline keeps the password in a 16 byte buffer with its terminator
HANDOFF_SECONDS = 120


def run_dir():
    d = os.path.join(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}", "begonepol")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


# --- keyring -----------------------------------------------------------------------------------

class Login:
    def __init__(self, account="", slot=1, otp="off", password="", totp=""):
        self.account, self.slot, self.otp, self.password, self.totp = account, slot, otp, password, totp


def load_logins():
    flags = Secret.SearchFlags.ALL | Secret.SearchFlags.UNLOCK | Secret.SearchFlags.LOAD_SECRETS
    found = []
    for item in Secret.password_search_sync(SCHEMA, {"application": "begonepol"}, flags, None):
        attrs = item.get_attributes()
        secret = item.retrieve_secret_sync(None)
        text = secret.get_text() if secret else ""
        try:
            data = json.loads(text) if text.startswith("{") else {"password": text}
        except ValueError:
            data = {"password": text}
        try:
            slot = int(attrs.get("slot", "1"))
        except ValueError:
            slot = 1
        found.append(Login(attrs.get("account", ""), slot, attrs.get("otp", "off"),
                           data.get("password", ""), data.get("totp", "")))
    return found


def save_login(login, replacing=None):
    """Store the login (one item per Square Enix ID and member row), replacing the one it was edited from."""
    for old in filter(None, (replacing, login)):
        Secret.password_clear_sync(SCHEMA, {"application": "begonepol", "account": old.account, "slot": str(old.slot)}, None)
    secret = {"password": login.password}
    if login.otp == "auto":
        secret["totp"] = login.totp
    ok = Secret.password_store_sync(
        SCHEMA,
        {"application": "begonepol", "account": login.account, "slot": str(login.slot), "otp": login.otp},
        Secret.COLLECTION_DEFAULT,
        f"FINAL FANTASY XI - BegonePOL ({login.account})",
        json.dumps(secret),
        None,
    )
    if not ok:
        raise RuntimeError("the keyring refused to store the login")


def write_handoff(login):
    d = run_dir()
    lines = [f"account={login.account}", f"slot={login.slot}", f"otp={login.otp}", f"password={login.password}"]
    if login.otp == "auto":
        lines.append(f"totp={login.totp}")
    tmp = os.path.join(d, "login.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, os.path.join(d, "login"))


# --- one-time passwords ------------------------------------------------------------------------

def clean_key(key):
    return "".join(key.split()).replace("-", "").rstrip("=").upper()


def totp_code(key, now=None):
    """RFC 6238 code (HMAC-SHA1, 30s, 6 digits), or None if the key isn't base32."""
    k = clean_key(key)
    if not k:
        return None
    try:
        raw = base64.b32decode(k + "=" * (-len(k) % 8))
    except ValueError:
        return None
    counter = int((time.time() if now is None else now) // 30)
    mac = hmac.new(raw, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


# --- setup window ------------------------------------------------------------------------------

class SetupWindow(Adw.ApplicationWindow):
    def __init__(self, app, existing, launching, choices=()):
        super().__init__(application=app, title="BegonePOL setup", default_width=520, default_height=860)
        self.existing = existing
        self.saved = None

        page = Adw.PreferencesPage()

        intro = Adw.PreferencesGroup(
            title="Log in to FINAL FANTASY XI automatically",
            description="BegonePOL signs in to PlayOnline for you. Your login is kept in your desktop "
                        "keyring, never in a file.",
        )
        if len(choices) > 1:
            # Several saved logins: pick which one to edit.
            names = Gtk.StringList.new([f"{c.account} (member {c.slot})" for c in choices])
            self.choice = Adw.ComboRow(title="Saved login", model=names)
            self.choice.set_selected(next((i for i, c in enumerate(choices) if c is existing), 0))
            self.choice.connect("notify::selected", lambda r, *_: self.fill(choices[r.get_selected()]))
            intro.add(self.choice)
        page.add(intro)

        acct = Adw.PreferencesGroup(title="Square Enix account")
        self.account = Adw.EntryRow(title="Square Enix ID")
        self.password = Adw.PasswordEntryRow(title="Password")
        self.slot = Adw.SpinRow.new_with_range(1, 4, 1)
        self.slot.set_title("PlayOnline member")
        self.slot.set_subtitle("Its row in PlayOnline's member list; 1 is the top")
        for row in (self.account, self.password, self.slot):
            acct.add(row)
        self.acct = acct
        page.add(acct)

        otp = Adw.PreferencesGroup(
            title="One-time password",
            description="If your Square Enix account uses two-step verification, PlayOnline also asks "
                        "for a one-time password. Turn this on for the member in PlayOnline's member "
                        "Settings too.",
        )
        self.has_otp = Adw.SwitchRow(title="Do you have a one-time password (MFA/2FA)?")
        self.auto_otp = Adw.SwitchRow(
            title="Automatically handle MFA?",
            subtitle="On: BegonePOL works out the code itself. Off: it asks you for the code at each login.",
        )
        self.key = Adw.PasswordEntryRow(title="Authenticator setup key")
        self.code = Adw.ActionRow(title="Current code", subtitle="Enter the setup key to see it")
        self.code.add_css_class("property")
        for row in (self.has_otp, self.auto_otp, self.key, self.code):
            otp.add(row)
        self.key_help = Gtk.Label(
            wrap=True, xalign=0, margin_top=8, css_classes=["dim-label", "caption"],
            label="The setup key is the text version of the QR code Square Enix shows when you add an "
                  "authenticator app (“Can't scan?”). The current code must match your app. "
                  "Keeping it here means anyone who can open your keyring has both of your factors.",
        )
        otp.add(self.key_help)
        page.add(otp)

        self.error = Gtk.Label(wrap=True, xalign=0, css_classes=["error"], visible=False, margin_start=12, margin_end=12)

        cancel = Gtk.Button(label="Cancel")
        cancel.connect("clicked", lambda *_: self.close())
        self.save = Gtk.Button(label="Save and log in" if launching else "Save", css_classes=["suggested-action"])
        self.save.connect("clicked", self.on_save)
        buttons = Gtk.Box(spacing=12, halign=Gtk.Align.END, margin_top=6, margin_bottom=12, margin_start=12, margin_end=12)
        buttons.append(cancel)
        buttons.append(self.save)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        page.set_vexpand(True)
        box.append(page)
        box.append(self.error)
        box.append(buttons)
        view = Adw.ToolbarView(content=box)
        view.add_top_bar(Adw.HeaderBar())
        self.set_content(view)
        self.set_default_widget(self.save)

        if existing:
            self.fill(existing)

        for w in (self.has_otp, self.auto_otp):
            w.connect("notify::active", lambda *_: self.sync())
        self.key.connect("changed", lambda *_: self.tick())
        self.sync()
        GLib.timeout_add_seconds(1, self.tick)

    def fill(self, login):
        self.existing = login
        self.account.set_text(login.account)
        self.password.set_text("")
        self.slot.set_value(login.slot)
        self.has_otp.set_active(login.otp != "off")
        self.auto_otp.set_active(login.otp == "auto")
        self.key.set_text(login.totp)
        self.acct.set_description("Leave the password empty to keep the saved one." if login.password else None)

    def sync(self):
        on = self.has_otp.get_active()
        self.auto_otp.set_sensitive(on)
        auto = on and self.auto_otp.get_active()
        for w in (self.key, self.code, self.key_help):
            w.set_visible(auto)
        self.tick()

    def tick(self):
        code = totp_code(self.key.get_text())
        if not self.key.get_text().strip():
            self.code.set_subtitle("Enter the setup key to see it")
        elif code is None:
            self.code.set_subtitle("That isn't a valid setup key")
        else:
            left = 30 - int(time.time()) % 30
            self.code.set_subtitle(f"{code[:3]} {code[3:]}   ({left}s left)")
        return True

    def fail(self, text):
        self.error.set_label(text)
        self.error.set_visible(True)

    def on_save(self, *_):
        account = self.account.get_text().strip()
        password = self.password.get_text()
        if not password and self.existing and self.existing.account == account and self.existing.slot == int(self.slot.get_value()):
            password = self.existing.password
        otp = "off" if not self.has_otp.get_active() else "auto" if self.auto_otp.get_active() else "manual"
        key = clean_key(self.key.get_text()) if otp == "auto" else ""
        if not account:
            return self.fail("Enter your Square Enix ID.")
        if not password:
            return self.fail("Enter your password.")
        if len(password.encode()) > MAX_PASSWORD:
            return self.fail(f"PlayOnline only takes passwords of up to {MAX_PASSWORD} characters.")
        if otp == "auto" and totp_code(key) is None:
            return self.fail("Enter the authenticator setup key, or turn off “Automatically handle MFA”.")
        login = Login(account, int(self.slot.get_value()), otp, password, key)
        try:
            save_login(login, self.existing if self.existing and self.existing.password else None)
        except Exception as e:  # keyring locked, no Secret Service, ...
            return self.fail(f"Couldn't save to the keyring: {e}")
        self.saved = login
        self.close()


def run_setup(existing, launching, choices=()):
    app = Adw.Application(application_id="io.github.voetre.BegonePOLSetup", flags=Gio.ApplicationFlags.NON_UNIQUE)
    result = {}

    def activate(a):
        win = SetupWindow(a, existing, launching, choices)
        win.connect("close-request", lambda w: result.__setitem__("login", w.saved) or False)
        win.present()

    app.connect("activate", activate)
    app.run([sys.argv[0]])
    return result.get("login")


def pick(logins, account, slot):
    """The saved login for this Square Enix ID and/or member row; with neither, the only one saved."""
    if account or slot:
        return next((l for l in logins if (not account or l.account == account) and (not slot or l.slot == slot)), None)
    return logins[0] if len(logins) == 1 else None


def main(argv):
    setup = "--setup" in argv
    slot = 0
    if "--slot" in argv:
        i = argv.index("--slot")
        slot = int(argv[i + 1])
        argv = argv[:i] + argv[i + 2:]
    args = [a for a in argv if not a.startswith("--")]
    account = args[0] if args else ""

    try:
        logins = load_logins()
    except GLib.Error as e:
        print(f"BegonePOL: can't read the keyring: {e.message}", file=sys.stderr)
        logins = []
    login = pick(logins, account, slot)

    if setup:
        run_setup(login or (logins[0] if logins else None), False, logins)
        return 0

    d = run_dir()
    marker = os.path.join(d, "setup")
    if login is None:
        # Tell the plugin to wait while the window is open.
        open(marker, "w").close()
        try:
            login = run_setup(Login(account, slot or 1) if account or slot else None, True)
        finally:
            os.remove(marker)
        if login is None:
            return 1
    write_handoff(login)
    login.password = login.totp = ""

    # Faugus doesn't wait for this command; stay around to clear the hand-off if nothing reads it.
    path = os.path.join(d, "login")
    time.sleep(HANDOFF_SECONDS)
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
