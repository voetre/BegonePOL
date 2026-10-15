#pragma once

/**
 * The login on Windows: kept in Windows Credential Manager (encrypted per Windows user), with a
 * setup window inside the plugin. Under Wine/Proton on Linux the desktop keyring and
 * begonepol-helper.py do this job instead (see platform.h); there this is only used when asked for
 * (arg "wincred"), because Wine keeps "Credential Manager" entries in the prefix's registry.
 *
 * One generic credential per PlayOnline member row: target "BegonePOL/member<n>", user name = the
 * Square Enix ID, secret = "otp=<off|manual|auto>\npassword=<...>\ntotp=<setup key>\n" (UTF-8).
 */

#include <wincred.h>
#include <commctrl.h>
#include <algorithm>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <string>
#include <vector>
#include "totp.h"

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")

namespace winlogin
{
    constexpr size_t MaxPassword = 15; // PlayOnline keeps it in a 16 byte buffer with its terminator

    struct Login
    {
        int slot = 0;
        std::string account;
        std::string otp = "off";
        char password[64]{};
        char totp[128]{};

        void Wipe(void)
        {
            ::SecureZeroMemory(password, sizeof(password));
            ::SecureZeroMemory(totp, sizeof(totp));
        }
    };

    inline bool IsWine(void)
    {
        const auto ntdll = ::GetModuleHandleW(L"ntdll.dll");
        return ntdll != nullptr && ::GetProcAddress(ntdll, "wine_get_version") != nullptr;
    }

    inline std::wstring Target(int slot)
    {
        return L"BegonePOL/member" + std::to_wstring(slot);
    }

    inline std::string Utf8(const wchar_t* text)
    {
        const auto n = ::WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
        std::string out(n > 0 ? n - 1 : 0, '\0');
        if (n > 1)
            ::WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), n, nullptr, nullptr);
        return out;
    }

    inline std::wstring Wide(const char* text)
    {
        const auto n = ::MultiByteToWideChar(CP_UTF8, 0, text, -1, nullptr, 0);
        std::wstring out(n > 0 ? n - 1 : 0, L'\0');
        if (n > 1)
            ::MultiByteToWideChar(CP_UTF8, 0, text, -1, out.data(), n);
        return out;
    }

    // Fills out from a credential; the secret is copied into out's fixed buffers and wiped here.
    inline bool FromCredential(const CREDENTIALW* c, Login& out)
    {
        int slot = 0;
        if (::swscanf_s(c->TargetName, L"BegonePOL/member%d", &slot) != 1 || slot < 1)
            return false;
        out.slot    = slot;
        out.account = c->UserName != nullptr ? Utf8(c->UserName) : "";
        char buf[512]{};
        const auto len = (std::min)(static_cast<size_t>(c->CredentialBlobSize), sizeof(buf) - 1);
        std::memcpy(buf, c->CredentialBlob, len);
        for (auto line = buf; *line != 0;)
        {
            auto end = line;
            while (*end != 0 && *end != '\n')
                end++;
            const auto next = *end != 0 ? end + 1 : end;
            *end = 0;
            if (const auto eq = std::strchr(line, '='))
            {
                *eq = 0;
                const auto val = eq + 1;
                if (std::strcmp(line, "otp") == 0)
                    out.otp = val;
                else if (std::strcmp(line, "password") == 0)
                    ::strncpy_s(out.password, val, _TRUNCATE);
                else if (std::strcmp(line, "totp") == 0)
                    ::strncpy_s(out.totp, val, _TRUNCATE);
            }
            line = next;
        }
        ::SecureZeroMemory(buf, sizeof(buf));
        return true;
    }

    // Saved logins, lowest member row first (secrets included; Wipe them when done).
    inline std::vector<Login> List(void)
    {
        std::vector<Login> out;
        DWORD count      = 0;
        PCREDENTIALW* cs = nullptr;
        if (!::CredEnumerateW(L"BegonePOL/member*", 0, &count, &cs))
            return out;
        for (DWORD i = 0; i < count; i++)
        {
            Login l;
            if (cs[i]->Type == CRED_TYPE_GENERIC && FromCredential(cs[i], l))
                out.push_back(l);
            l.Wipe();
            if (cs[i]->CredentialBlob != nullptr)
                ::SecureZeroMemory(cs[i]->CredentialBlob, cs[i]->CredentialBlobSize);
        }
        ::CredFree(cs);
        std::sort(out.begin(), out.end(), [](const Login& a, const Login& b) { return a.slot < b.slot; });
        return out;
    }

    inline void WipeAll(std::vector<Login>& logins)
    {
        for (auto& l : logins)
            l.Wipe();
    }

    inline bool Save(const Login& l)
    {
        char blob[512];
        const auto n = std::snprintf(blob, sizeof(blob), "otp=%s\npassword=%s\ntotp=%s\n", l.otp.c_str(), l.password, l.otp == "auto" ? l.totp : "");
        if (n <= 0 || n >= static_cast<int>(sizeof(blob)))
            return false;
        auto target = Target(l.slot);
        auto user   = Wide(l.account.c_str());
        CREDENTIALW c{};
        c.Type               = CRED_TYPE_GENERIC;
        c.TargetName         = target.data();
        c.Comment            = const_cast<wchar_t*>(L"FINAL FANTASY XI login for BegonePOL");
        c.CredentialBlobSize = static_cast<DWORD>(n);
        c.CredentialBlob     = reinterpret_cast<BYTE*>(blob);
        c.Persist            = CRED_PERSIST_LOCAL_MACHINE;
        c.UserName           = user.data();
        const auto ok        = ::CredWriteW(&c, 0) != FALSE;
        ::SecureZeroMemory(blob, sizeof(blob));
        return ok;
    }

    inline bool Forget(int slot)
    {
        return ::CredDeleteW(Target(slot).c_str(), CRED_TYPE_GENERIC, 0) != FALSE;
    }

    inline void CleanKey(const char* in, char (&out)[128])
    {
        size_t n = 0;
        for (auto p = in; *p != 0 && n + 1 < sizeof(out); p++)
            if (*p != ' ' && *p != '-' && *p != '=' && *p != '\t')
                out[n++] = (*p >= 'a' && *p <= 'z') ? static_cast<char>(*p - 32) : *p;
        out[n] = 0;
    }

    /**
     * The setup window: Square Enix ID, password, member row and one-time password settings, saved to
     * Credential Manager. Runs its own message loop on the calling thread. Returns true with out
     * filled (secrets included) when saved; false if closed or cancelled.
     */
    class Setup
    {
    public:
        bool Run(std::vector<Login>& saved, int preferSlot, bool launching, Login& out)
        {
            m_Saved     = &saved;
            m_Launching = launching;
            m_Out       = &out;

            INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES };
            ::InitCommonControlsEx(&icc);
            const auto inst = ::GetModuleHandleW(nullptr);
            WNDCLASSEXW wc{ sizeof(wc) };
            wc.lpfnWndProc   = WndProc;
            wc.hInstance     = inst;
            wc.hCursor       = ::LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
            wc.hbrBackground = ::GetSysColorBrush(COLOR_BTNFACE);
            wc.lpszClassName = L"BegonePOLSetup";
            ::RegisterClassExW(&wc);

            const auto screen = ::GetDC(nullptr);
            m_Scale           = ::GetDeviceCaps(screen, LOGPIXELSY) / 96.0;
            ::ReleaseDC(nullptr, screen);

            const DWORD style = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
            RECT r{ 0, 0, S(480), S(574) };
            ::AdjustWindowRectEx(&r, style, FALSE, 0);
            RECT wa{};
            ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
            const int w = r.right - r.left, h = r.bottom - r.top;
            m_Hwnd = ::CreateWindowExW(WS_EX_APPWINDOW, wc.lpszClassName, L"BegonePOL setup", style,
                wa.left + (wa.right - wa.left - w) / 2, wa.top + (wa.bottom - wa.top - h) / 2, w, h, nullptr, nullptr, inst, this);
            if (m_Hwnd == nullptr)
                return false;

            int pick = 0;
            for (size_t i = 0; i < saved.size(); i++)
                if (saved[i].slot == preferSlot)
                    pick = static_cast<int>(i);
            if (!saved.empty())
            {
                ::SendMessageW(m_Choice, CB_SETCURSEL, pick, 0);
                Fill(&saved[pick]);
            }
            else
                Fill(nullptr);
            Sync();

            ::ShowWindow(m_Hwnd, SW_SHOW);
            ::SetForegroundWindow(m_Hwnd);
            ::SetFocus(m_Account);
            ::SendMessageW(m_Account, EM_SETSEL, static_cast<WPARAM>(-1), -1);
            ::SetTimer(m_Hwnd, 1, 500, nullptr);
            MSG msg;
            while (m_Hwnd != nullptr && ::GetMessageW(&msg, nullptr, 0, 0) > 0)
            {
                if (::IsDialogMessageW(m_Hwnd, &msg))
                    continue;
                ::TranslateMessage(&msg);
                ::DispatchMessageW(&msg);
            }
            ::UnregisterClassW(wc.lpszClassName, inst);
            return m_Done;
        }

    private:
        enum : int { IdChoice = 10, IdAccount, IdPassword, IdSlot, IdHasOtp, IdAutoOtp, IdKey, IdSave, IdCancel, IdForget };

        int S(int v) const { return static_cast<int>(v * m_Scale + 0.5); }

        HWND Add(const wchar_t* cls, const wchar_t* text, DWORD style, int x, int y, int w, int h, int id = 0, DWORD ex = 0)
        {
            const auto c = ::CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | style, S(x), S(y), S(w), S(h), m_Hwnd,
                reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), ::GetModuleHandleW(nullptr), nullptr);
            ::SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(m_Font), FALSE);
            return c;
        }

        void Build(void)
        {
            NONCLIENTMETRICSW ncm{ sizeof(ncm) };
            ::SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
            m_Font = ::CreateFontIndirectW(&ncm.lfMessageFont);
            auto bold = ncm.lfMessageFont;
            bold.lfWeight = FW_BOLD;
            m_Bold = ::CreateFontIndirectW(&bold);

            int y = 14;
            auto title = Add(L"STATIC", L"Log in to FINAL FANTASY XI automatically", 0, 16, y, 448, 20);
            ::SendMessageW(title, WM_SETFONT, reinterpret_cast<WPARAM>(m_Bold), FALSE);
            y += 22;
            Add(L"STATIC", L"BegonePOL signs in to PlayOnline for you. Your login is kept in Windows Credential "
                           L"Manager, never in a file.", 0, 16, y, 448, 32);
            y += 40;
            if (m_Saved->size() > 1)
            {
                Add(L"STATIC", L"Saved login", 0, 16, y + 3, 150, 20);
                m_Choice = Add(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, 170, y, 294, 200, IdChoice);
                for (const auto& l : *m_Saved)
                {
                    const auto label = Wide(l.account.c_str()) + L" (member " + std::to_wstring(l.slot) + L")";
                    ::SendMessageW(m_Choice, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
                }
                y += 34;
            }

            auto group = Add(L"STATIC", L"Square Enix account", 0, 16, y, 448, 20);
            ::SendMessageW(group, WM_SETFONT, reinterpret_cast<WPARAM>(m_Bold), FALSE);
            y += 24;
            Add(L"STATIC", L"Square Enix ID", 0, 16, y + 3, 150, 20);
            m_Account = Add(L"EDIT", L"", ES_AUTOHSCROLL | WS_TABSTOP, 170, y, 294, 24, IdAccount, WS_EX_CLIENTEDGE);
            y += 30;
            Add(L"STATIC", L"Password", 0, 16, y + 3, 150, 20);
            m_Password = Add(L"EDIT", L"", ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP, 170, y, 294, 24, IdPassword, WS_EX_CLIENTEDGE);
            ::SendMessageW(m_Password, EM_SETLIMITTEXT, MaxPassword, 0);
            y += 28;
            m_KeepHint = Add(L"STATIC", L"Leave the password empty to keep the saved one.", 0, 170, y, 294, 18);
            y += 22;
            Add(L"STATIC", L"PlayOnline member", 0, 16, y + 3, 150, 20);
            m_Slot = Add(L"COMBOBOX", L"", CBS_DROPDOWNLIST | WS_TABSTOP, 170, y, 80, 200, IdSlot);
            for (const auto s : { L"1", L"2", L"3", L"4" })
                ::SendMessageW(m_Slot, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(s));
            Add(L"STATIC", L"Its row in PlayOnline's member list; 1 is the top.", 0, 260, y + 3, 204, 34);
            y += 44;

            group = Add(L"STATIC", L"One-time password", 0, 16, y, 448, 20);
            ::SendMessageW(group, WM_SETFONT, reinterpret_cast<WPARAM>(m_Bold), FALSE);
            y += 22;
            Add(L"STATIC", L"If your Square Enix account uses two-step verification, PlayOnline also asks for a one-time "
                           L"password. Turn it on for the member in PlayOnline's member Settings too.", 0, 16, y, 448, 34);
            y += 40;
            m_HasOtp = Add(L"BUTTON", L"Do you have a one-time password (MFA/2FA)?", BS_AUTOCHECKBOX | WS_TABSTOP, 16, y, 448, 22, IdHasOtp);
            y += 26;
            m_AutoOtp = Add(L"BUTTON", L"Automatically handle MFA?", BS_AUTOCHECKBOX | WS_TABSTOP, 16, y, 448, 22, IdAutoOtp);
            y += 22;
            m_AutoHint = Add(L"STATIC", L"On: BegonePOL works out the code itself. Off: it asks you for the code at each login.", 0, 34, y, 430, 34);
            y += 40;
            m_KeyLabel = Add(L"STATIC", L"Authenticator setup key", 0, 16, y + 3, 150, 20);
            m_Key = Add(L"EDIT", L"", ES_AUTOHSCROLL | ES_PASSWORD | WS_TABSTOP, 170, y, 294, 24, IdKey, WS_EX_CLIENTEDGE);
            ::SendMessageW(m_Key, EM_SETLIMITTEXT, 100, 0);
            y += 30;
            m_CodeLabel = Add(L"STATIC", L"Current code", 0, 16, y, 150, 20);
            m_Code = Add(L"STATIC", L"", 0, 170, y, 294, 20);
            y += 22;
            m_KeyHelp = Add(L"STATIC", L"The setup key is the text version of the QR code Square Enix shows when you add an "
                                       L"authenticator app (\"Can't scan?\"). The current code must match your app. Keeping it "
                                       L"here means anyone who can use your Windows account has both of your factors.", 0, 16, y, 448, 50);
            y += 54;
            m_Error = Add(L"STATIC", L"", 0, 16, y, 448, 34);

            y = 534;
            m_Forget = Add(L"BUTTON", L"Forget this login", WS_TABSTOP, 16, y, 130, 28, IdForget);
            Add(L"BUTTON", L"Cancel", WS_TABSTOP, 254, y, 100, 28, IdCancel);
            Add(L"BUTTON", m_Launching ? L"Save and log in" : L"Save", BS_DEFPUSHBUTTON | WS_TABSTOP, 364, y, 100, 28, IdSave);
        }

        void Fill(const Login* l)
        {
            m_Existing = l;
            ::SetWindowTextW(m_Account, l != nullptr ? Wide(l->account.c_str()).c_str() : L"");
            ::SetWindowTextW(m_Password, L"");
            ::SendMessageW(m_Slot, CB_SETCURSEL, l != nullptr ? (std::max)(0, (std::min)(3, l->slot - 1)) : 0, 0);
            const bool has = l != nullptr && l->otp != "off", autoOtp = l != nullptr && l->otp == "auto";
            ::SendMessageW(m_HasOtp, BM_SETCHECK, has ? BST_CHECKED : BST_UNCHECKED, 0);
            ::SendMessageW(m_AutoOtp, BM_SETCHECK, autoOtp ? BST_CHECKED : BST_UNCHECKED, 0);
            ::SetWindowTextW(m_Key, autoOtp ? Wide(l->totp).c_str() : L"");
            ::ShowWindow(m_KeepHint, l != nullptr && l->password[0] != 0 ? SW_SHOW : SW_HIDE);
            ::ShowWindow(m_Forget, l != nullptr ? SW_SHOW : SW_HIDE);
            ::SetWindowTextW(m_Error, L"");
        }

        bool Checked(HWND h) const { return ::SendMessageW(h, BM_GETCHECK, 0, 0) == BST_CHECKED; }

        void Sync(void)
        {
            const bool has = Checked(m_HasOtp);
            ::EnableWindow(m_AutoOtp, has);
            const auto show = has && Checked(m_AutoOtp) ? SW_SHOW : SW_HIDE;
            for (const auto h : { m_KeyLabel, m_Key, m_CodeLabel, m_Code, m_KeyHelp })
                ::ShowWindow(h, show);
            Tick();
        }

        void KeyText(char (&out)[128])
        {
            wchar_t wide[128]{};
            ::GetWindowTextW(m_Key, wide, 128);
            char raw[128]{};
            ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, raw, sizeof(raw), nullptr, nullptr);
            CleanKey(raw, out);
            ::SecureZeroMemory(wide, sizeof(wide));
            ::SecureZeroMemory(raw, sizeof(raw));
        }

        void Tick(void)
        {
            char key[128]{};
            KeyText(key);
            char code[7]{};
            const auto now = static_cast<uint64_t>(::time(nullptr));
            if (key[0] == 0)
                ::SetWindowTextW(m_Code, L"Enter the setup key to see it");
            else if (!totp::Code(key, now, code))
                ::SetWindowTextW(m_Code, L"That isn't a valid setup key");
            else
            {
                wchar_t text[64];
                ::swprintf_s(text, L"%.3S %.3S   (%llus left)", code, code + 3, 30 - now % 30);
                ::SetWindowTextW(m_Code, text);
            }
            ::SecureZeroMemory(key, sizeof(key));
            ::SecureZeroMemory(code, sizeof(code));
        }

        void Fail(const wchar_t* text) { ::SetWindowTextW(m_Error, text); }

        void OnSave(void)
        {
            wchar_t wide[64]{};
            ::GetWindowTextW(m_Account, wide, 64);
            Login l;
            l.account = Utf8(wide);
            while (!l.account.empty() && l.account.back() == ' ')
                l.account.pop_back();
            while (!l.account.empty() && l.account.front() == ' ')
                l.account.erase(0, 1);
            l.slot = static_cast<int>(::SendMessageW(m_Slot, CB_GETCURSEL, 0, 0)) + 1;
            l.otp  = !Checked(m_HasOtp) ? "off" : Checked(m_AutoOtp) ? "auto" : "manual";

            ::GetWindowTextW(m_Password, wide, 64);
            ::WideCharToMultiByte(CP_UTF8, 0, wide, -1, l.password, sizeof(l.password), nullptr, nullptr);
            ::SecureZeroMemory(wide, sizeof(wide));
            if (l.password[0] == 0 && m_Existing != nullptr && m_Existing->account == l.account && m_Existing->slot == l.slot)
                ::strcpy_s(l.password, m_Existing->password);
            if (l.otp == "auto")
                KeyText(l.totp);

            char probe[7];
            if (l.slot < 1)
                Fail(L"Pick the PlayOnline member.");
            else if (l.account.empty())
                Fail(L"Enter your Square Enix ID.");
            else if (l.password[0] == 0)
                Fail(L"Enter your password.");
            else if (std::strlen(l.password) > MaxPassword)
                Fail(L"PlayOnline only takes passwords of up to 15 characters.");
            else if (l.otp == "auto" && !totp::Code(l.totp, 0, probe))
                Fail(L"Enter the authenticator setup key, or turn off \"Automatically handle MFA\".");
            else if (!Save(l))
                Fail(L"Couldn't save to Windows Credential Manager.");
            else
            {
                // A login moved to another member row: drop the old entry.
                if (m_Existing != nullptr && m_Existing->slot != l.slot)
                    Forget(m_Existing->slot);
                ::SetWindowTextW(m_Password, L"");
                ::SetWindowTextW(m_Key, L"");
                *m_Out  = l;
                m_Done  = true;
                l.Wipe();
                ::DestroyWindow(m_Hwnd);
                return;
            }
            l.Wipe();
        }

        void OnForget(void)
        {
            if (m_Existing == nullptr)
                return;
            const auto text = L"Forget the saved login for " + Wide(m_Existing->account.c_str()) + L" (member " + std::to_wstring(m_Existing->slot) + L")?";
            if (::MessageBoxW(m_Hwnd, text.c_str(), L"BegonePOL setup", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return;
            Forget(m_Existing->slot);
            for (auto it = m_Saved->begin(); it != m_Saved->end(); ++it)
                if (&*it == m_Existing)
                {
                    it->Wipe();
                    m_Saved->erase(it);
                    break;
                }
            if (m_Choice != nullptr)
            {
                ::SendMessageW(m_Choice, CB_RESETCONTENT, 0, 0);
                for (const auto& l : *m_Saved)
                {
                    const auto label = Wide(l.account.c_str()) + L" (member " + std::to_wstring(l.slot) + L")";
                    ::SendMessageW(m_Choice, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
                }
                ::SendMessageW(m_Choice, CB_SETCURSEL, 0, 0);
            }
            Fill(m_Saved->empty() ? nullptr : &m_Saved->front());
            Sync();
            ::SetWindowTextW(m_Error, L"Forgotten.");
        }

        static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
        {
            auto self = reinterpret_cast<Setup*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
            switch (msg)
            {
            case WM_NCCREATE:
                self = reinterpret_cast<Setup*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
                self->m_Hwnd = hwnd;
                break;
            case WM_CREATE:
                self->Build();
                return 0;
            case WM_TIMER:
                self->Tick();
                return 0;
            case WM_CTLCOLORSTATIC:
                if (reinterpret_cast<HWND>(lp) == self->m_Error)
                {
                    ::SetTextColor(reinterpret_cast<HDC>(wp), RGB(190, 0, 0));
                    ::SetBkColor(reinterpret_cast<HDC>(wp), ::GetSysColor(COLOR_BTNFACE));
                    return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_BTNFACE));
                }
                break;
            case WM_COMMAND:
                switch (LOWORD(wp))
                {
                case IdHasOtp:
                case IdAutoOtp:
                    self->Sync();
                    return 0;
                case IdKey:
                    if (HIWORD(wp) == EN_CHANGE)
                        self->Tick();
                    return 0;
                case IdChoice:
                    if (HIWORD(wp) == CBN_SELCHANGE)
                    {
                        const auto i = static_cast<size_t>(::SendMessageW(self->m_Choice, CB_GETCURSEL, 0, 0));
                        if (i < self->m_Saved->size())
                            self->Fill(&(*self->m_Saved)[i]);
                        self->Sync();
                    }
                    return 0;
                case IdSave:
                case IDOK:
                    self->OnSave();
                    return 0;
                case IdCancel:
                case IDCANCEL:
                    ::DestroyWindow(hwnd);
                    return 0;
                case IdForget:
                    self->OnForget();
                    return 0;
                }
                break;
            case WM_CLOSE:
                ::DestroyWindow(hwnd);
                return 0;
            case WM_DESTROY:
                ::SetWindowTextW(self->m_Password, L"");
                ::SetWindowTextW(self->m_Key, L"");
                ::DeleteObject(self->m_Font);
                ::DeleteObject(self->m_Bold);
                self->m_Hwnd = nullptr;
                ::PostMessageW(nullptr, WM_NULL, 0, 0); // wake the loop so it sees the window is gone
                return 0;
            }
            return ::DefWindowProcW(hwnd, msg, wp, lp);
        }

        std::vector<Login>* m_Saved = nullptr;
        const Login* m_Existing     = nullptr;
        Login* m_Out                = nullptr;
        bool m_Launching            = true;
        bool m_Done                 = false;
        double m_Scale              = 1.0;
        HWND m_Hwnd = nullptr, m_Choice = nullptr, m_Account = nullptr, m_Password = nullptr, m_KeepHint = nullptr, m_Slot = nullptr;
        HWND m_HasOtp = nullptr, m_AutoOtp = nullptr, m_AutoHint = nullptr, m_KeyLabel = nullptr, m_Key = nullptr;
        HWND m_CodeLabel = nullptr, m_Code = nullptr, m_KeyHelp = nullptr, m_Error = nullptr, m_Forget = nullptr;
        HFONT m_Font = nullptr, m_Bold = nullptr;
    };
}
