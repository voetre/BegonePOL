/**
 * BegonePOL - Ashita v4 POL plugin
 *
 * Logs into PlayOnline from inside the process instead of typing into the window, so it works with
 * the window unfocused (or on another desktop) and never touches the clipboard.
 *
 * PlayOnline's login screen (app.dll, pol::CLoginMemberPasswordFrame) checks the typed password
 * locally: it scrambles the text and compares it with the copy stored in the selected member's
 * data, then carries on with the login using that stored member data. This plugin does the same
 * check with the saved login (desktop keyring via begonepol-helper.py under Wine/Proton on Linux, Windows Credential
 * Manager on Windows; see platform.h) and then calls the same continuation on
 * PlayOnline's UI thread. If the member is wrong it uses PlayOnline's own Back and member-select
 * handlers to pick the configured slot.
 *
 * Every PlayOnline function and global is found at runtime through RTTI (class name -> vtable) and
 * short code signatures inside those classes' handlers, so a PlayOnline patch that moves code
 * around makes the plugin stop with a log line instead of calling into the wrong place.
 *
 * Args ([ashita.polplugins.args] BegonePOL = ...): space separated
 *   (the account, member row and one-time password mode come from the saved login, set up in
 *    begonepol-helper.py's window on Linux or the plugin's own window on Windows; slot=<n> overrides
 *    the member row, or picks the saved login on Windows)
 *   setup            Windows: open the setup window before logging in (change or forget the login)
 *   wincred          use Windows Credential Manager even under Wine on Linux (testing)
 *   trace            log the login screen state every 2 seconds and what member-list clicks pass
 *   (by default the PlayOnline window is invisible, click-through and off the taskbar while logging in,
 *    so it's as if PlayOnline isn't there; it comes back only if the login fails or FFXI doesn't start)
 *   show             keep the PlayOnline window visible
 *   nosplash         don't show the small progress window that stays up until the FFXI window opens
 *   dryrun           do everything except press Login (for testing; nothing is sent to Square Enix)
 *   askcode          with dryrun: show the one-time password prompt even if the member doesn't use one
 *   menu             show PlayOnline's main menu instead of starting FFXI straight after the login
 *   realconnect      really connect to the content server when skipping the menu
 *   skiplogo         experimental: don't hold the PlayOnline logo for 5s (FFXI then failed to start
 *                    with "unknown error 0x80004002"; something else needs those seconds)
 *   prof             log where PlayOnline sleeps, per call site (for finding waits to skip)
 *   dump             also write the unpacked PlayOnline modules to logs\pol-dump (for reversing)
 *
 * The password and its scrambled form are never logged and are wiped from memory after use.
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include "Ashita.h"
#include <tlhelp32.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;
#include "totp.h"
#include "platform.h"
#include "winlogin.h"

#include <algorithm>
#include <atomic>
#include <ctime>
#include <cstdio>
#include <iterator>
#include <cstring>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "msimg32.lib")

namespace
{
    IAshitaCore* g_Core = nullptr;
    ILogManager* g_Log  = nullptr;

    constexpr UINT WM_POLLOGIN_TICK = WM_APP + 0x51;

    // Offsets into PlayOnline objects, taken from the app.dll handlers that use them.
    constexpr uint32_t FrameStateOffset     = 0x23C;  // bit 0 set: frame ignores input (closing / busy)
    constexpr uint32_t MgrCurrentMember     = 0x284;  // 1-based member slot currently selected
    constexpr uint32_t MgrMemberData        = 0x288;  // selected member's data
    constexpr uint32_t MemberStoredPassword = 0x4E;   // 16 scrambled bytes + length byte at +0x10
    constexpr uint32_t MgrUseSavedLogin     = 0x55FC; // picks which continuation the OK handler calls
    constexpr uint32_t PwListenerOffset     = 0x2A0;  // CLoginMemberPasswordFrame's action listener
    constexpr uint32_t ListListenerOffset   = 0x2C0;  // CLoginMemberListFrame's selection listener
    constexpr uint32_t ListSecondOffset     = 0x2C4;
    constexpr uint32_t EventSelectedIndex   = 0x2C;
    constexpr uint32_t EventSource          = 0x28;
    constexpr uint32_t ListTable            = 0x2A0;  // CLoginMemberListFrame -> CScrollTable
    constexpr uint32_t TableModel           = 0x224;  // CScrollTable -> CPolTable
    constexpr uint32_t TableSelection       = 0x218;  // CPolTable -> CDefaultListSelectionModel
    constexpr uint32_t SelSetInterval       = 0x14;   // selection model vtable: setSelectionInterval(a, b)
    constexpr uint32_t SelIsSelected        = 0x38;   // selection model vtable: isSelectedIndex(i)
    constexpr uint32_t SubListenerOffset    = 0x2A0;  // CLoginSubCommandFrame's button listener
    constexpr uint32_t SubLogInButton       = 0x2A4;  // Log In / Settings / Delete / Back
    constexpr uint32_t SubBackButton        = 0x2B0;
    constexpr uint32_t ConnListenerOffset   = 0x2A0;  // CLoginConnectionEthernetSqexFrame's action listener
    constexpr uint32_t ConnPasswordField    = 0x2A4;  // CScrollTextField holding the Square Enix password
    constexpr uint32_t ConnOtpField         = 0x2A8;  // CScrollTextField for the one-time password (hidden unless the member uses one)
    constexpr uint32_t ConnLoginButton      = 0x2B0;  // first of the frame's three buttons: Login
    constexpr uint32_t LoginUsesOtp         = 0x536B; // member login settings: byte, "uses a one-time password"
    constexpr uint32_t ScrollInnerField     = 0x228;  // CScrollTextField -> CPasswordField
    constexpr uint32_t FieldSetText         = 0x1DC;  // text component vtable: setText(const char*)

    using ThiscallInt   = void(__thiscall*)(void*, int);
    using ThiscallEvent = void(__thiscall*)(void*, void*);
    using Cdecl         = void(__cdecl*)(void);
    using SetInterval   = void(__thiscall*)(void*, int, int);
    using IsSelected    = bool(__thiscall*)(void*, int);
    using SetText       = void(__thiscall*)(void*, const char*);

    struct PolApi
    {
        uint8_t** pwFrame   = nullptr; // global: live CLoginMemberPasswordFrame (null when closed)
        uint8_t** listFrame = nullptr; // global: live CLoginMemberListFrame
        uint8_t** mgr       = nullptr; // global: login manager
        ThiscallInt hide    = nullptr; // frame->Close(1)
        Cdecl back          = nullptr; // password screen "Back": rebuilds the member list
        Cdecl proceedSaved  = nullptr; // continuation when MgrUseSavedLogin != 0
        Cdecl proceedNew    = nullptr; // continuation otherwise
        ThiscallEvent selectMember = nullptr;

        uint8_t** subFrame       = nullptr; // global: live CLoginSubCommandFrame (Log In / Settings / Delete / Back)
        ThiscallEvent subAction  = nullptr;
        uint8_t** connFrame     = nullptr; // global: live CConnectionFrame (any connection type)
        uint32_t* connSqexVt    = nullptr; // CLoginConnectionEthernetSqexFrame, the Square Enix ID login screen
        ThiscallEvent connAction = nullptr; // its OK/Cancel/help button handler
        uint8_t** loginOwner    = nullptr; // global: object holding the current member's login settings
        uint32_t loginSettings  = 0;       // their offset in it
        uint32_t* textFieldVt   = nullptr; // CTextField, in case the one-time password box is a plain one
        uint8_t** memberStore   = nullptr; // global: object holding the member list
        uint32_t memberCount    = 0;       // offset of the number of members in it
        uint32_t* scrollTableVt = nullptr;
        uint32_t* selModelVt    = nullptr;
        uint32_t* pwFieldVt     = nullptr;
    } g_Pol;

    struct Image
    {
        uint8_t* base      = nullptr;
        uint8_t* imgEnd    = nullptr;
        uint8_t* textBegin = nullptr;
        uint8_t* textEnd   = nullptr;
        uint8_t* dataBegin = nullptr; // .rdata
        uint8_t* dataEnd   = nullptr;
    };

    std::optional<Image> MapImage(const char* name)
    {
        const auto base = reinterpret_cast<uint8_t*>(::GetModuleHandleA(name));
        if (base == nullptr)
            return std::nullopt;
        const auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        Image img;
        img.base   = base;
        img.imgEnd = base + nt->OptionalHeader.SizeOfImage;
        auto sec   = IMAGE_FIRST_SECTION(nt);
        for (uint32_t x = 0; x < nt->FileHeader.NumberOfSections; x++, sec++)
        {
            const auto secName = std::string(reinterpret_cast<const char*>(sec->Name), strnlen(reinterpret_cast<const char*>(sec->Name), 8));
            if (secName == ".text")
            {
                img.textBegin = base + sec->VirtualAddress;
                img.textEnd   = img.textBegin + sec->Misc.VirtualSize;
            }
            else if (secName == ".rdata")
            {
                img.dataBegin = base + sec->VirtualAddress;
                img.dataEnd   = img.dataBegin + sec->Misc.VirtualSize;
            }
        }
        if (img.textBegin == nullptr || img.dataBegin == nullptr)
            return std::nullopt;
        return img;
    }

    // Byte signature with -1 as wildcard.
    uint8_t* Find(uint8_t* begin, uint8_t* end, const std::vector<int>& sig)
    {
        if (end - begin < static_cast<ptrdiff_t>(sig.size()))
            return nullptr;
        for (auto p = begin; p <= end - sig.size(); p++)
        {
            size_t x = 0;
            while (x < sig.size() && (sig[x] < 0 || p[x] == sig[x]))
                x++;
            if (x == sig.size())
                return p;
        }
        return nullptr;
    }

    std::vector<int> Bytes(uint32_t v)
    {
        return { static_cast<int>(v & 0xFF), static_cast<int>((v >> 8) & 0xFF), static_cast<int>((v >> 16) & 0xFF), static_cast<int>(v >> 24) };
    }

    std::vector<int> Concat(std::vector<int> a, const std::vector<int>& b, const std::vector<int>& c)
    {
        a.insert(a.end(), b.begin(), b.end());
        a.insert(a.end(), c.begin(), c.end());
        return a;
    }

    template<typename T>
    T RelCall(uint8_t* e8)
    {
        return reinterpret_cast<T>(e8 + 5 + *reinterpret_cast<int32_t*>(e8 + 1));
    }

#include "quicklaunch.h"
#include "profile.h"

    // MSVC RTTI: ".?AV<name>" type descriptor -> complete object locator with the given vptr
    // offset -> the vtable that points at it.
    uint32_t* FindVtable(const Image& img, const char* mangled, uint32_t offset)
    {
        std::vector<int> nameSig;
        for (auto c = mangled; *c; c++)
            nameSig.push_back(static_cast<uint8_t>(*c));
        nameSig.push_back(0);
        const auto name = Find(img.base, img.imgEnd, nameSig);
        if (name == nullptr)
            return nullptr;
        const auto td = reinterpret_cast<uint32_t>(name - 8);

        const auto begin = reinterpret_cast<uint32_t*>(img.dataBegin);
        const auto end   = reinterpret_cast<uint32_t*>(img.dataEnd);
        for (auto p = begin; p + 4 < end; p++)
        {
            // {signature 0, offset, cdOffset, pTypeDescriptor, pClassDescriptor}
            if (p[3] != td || p[0] != 0 || p[1] != offset)
                continue;
            const auto col = reinterpret_cast<uint32_t>(p);
            for (auto q = begin; q + 1 < end; q++)
                if (*q == col)
                    return q + 1;
        }
        return nullptr;
    }

    ThiscallEvent g_OrigSelect = nullptr;
    uint32_t* g_SpyVt          = nullptr;

    // trace: log what a real member-list click hands the selection handler.
    void __fastcall SelectSpy(uint8_t* self, void* /*edx*/, uint8_t* evt)
    {
        const auto ctl = *reinterpret_cast<uint8_t**>(self - 0x20);
        const auto dw  = reinterpret_cast<uint32_t*>(evt);
        g_Log->Logf(5, "BegonePOL", "spy: listener %p ctl %p evt %p vt %08X | %08X %08X %08X %08X %08X %08X %08X %08X | %08X %08X %08X %08X %08X %08X %08X %08X",
            self, ctl, evt, dw[0], dw[1], dw[2], dw[3], dw[4], dw[5], dw[6], dw[7], dw[8], dw[9], dw[10], dw[11], dw[12], dw[13], dw[14], dw[15], dw[16]);
        g_OrigSelect(self, evt);
    }

    void HookSelect(uint32_t* vt)
    {
        DWORD old = 0;
        if (!::VirtualProtect(&vt[1], 4, PAGE_EXECUTE_READWRITE, &old))
            return;
        g_OrigSelect = reinterpret_cast<ThiscallEvent>(vt[1]);
        vt[1] = reinterpret_cast<uint32_t>(&SelectSpy);
        ::VirtualProtect(&vt[1], 4, old, &old);
        g_SpyVt = vt;
        g_Log->Log(5, "BegonePOL", "spy: member-list selection handler hooked.");
    }

    void UnhookSelect(void)
    {
        DWORD old = 0;
        if (g_SpyVt == nullptr || !::VirtualProtect(&g_SpyVt[1], 4, PAGE_EXECUTE_READWRITE, &old))
            return;
        g_SpyVt[1] = reinterpret_cast<uint32_t>(g_OrigSelect);
        ::VirtualProtect(&g_SpyVt[1], 4, old, &old);
        g_SpyVt = nullptr;
    }

    bool ResolvePol(bool spy)
    {
        const auto img = MapImage("app.dll");
        if (!img)
        {
            g_Log->Log(2, "BegonePOL", "app.dll is not loaded or has an unexpected layout.");
            return false;
        }

        const auto pwVt   = FindVtable(*img, ".?AVCLoginMemberPasswordFrame@pol@@", PwListenerOffset);
        const auto listVt = FindVtable(*img, ".?AVCLoginMemberListFrame@pol@@", ListListenerOffset);
        const auto list2  = FindVtable(*img, ".?AVCLoginMemberListFrame@pol@@", ListSecondOffset);
        if (pwVt == nullptr || listVt == nullptr || list2 == nullptr)
        {
            g_Log->Logf(2, "BegonePOL", "RTTI lookup failed (password %p, list %p/%p).", pwVt, listVt, list2);
            return false;
        }

        // Password screen OK/Back handler (listener vtable slot 1).
        const auto handler    = reinterpret_cast<uint8_t*>(pwVt[1]);
        const auto handlerEnd = handler + 0x200;
        // compare(stored, typed) == 1 ? { Close(1); mgr->UseSaved() ? proceedSaved() : proceedNew(); }
        const auto ok = Find(handler, handlerEnd, { 0x8B, 0x0D, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x8D, 0x4D, -1, 0x51, 0x83, 0xC0, 0x4E, 0x50, 0xE8, -1, -1, -1, -1,
                                                    0x3C, 0x01, 0x59, 0x59, 0x75, -1, 0x6A, 0x01, 0x8D, 0x8E, 0x60, 0xFD, 0xFF, 0xFF, 0xE8, -1, -1, -1, -1,
                                                    0x8B, 0x0D, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0x85, 0xC0, 0x74, 0x07, 0xE8, -1, -1, -1, -1, 0xEB, -1, 0xE8 });
        // Back: Close(1); RebuildMemberList();
        const auto bk = Find(handler, handlerEnd, { 0x6A, 0x01, 0x8D, 0x8E, 0x60, 0xFD, 0xFF, 0xFF, 0xE8, -1, -1, -1, -1, 0xE8, -1, -1, -1, -1, 0xE9 });
        // Password frame constructor: mov [ebx], listenerVtable; mov [g_PasswordFrame], esi
        const auto pwCtor = Find(img->textBegin, img->textEnd, Concat({ 0xC7, 0x03 }, Bytes(reinterpret_cast<uint32_t>(pwVt)), { 0x89, 0x35 }));
        // Member list frame destructor: mov [ecx], vtable2; and [g_MemberListFrame], 0
        const auto listDtor = Find(img->textBegin, img->textEnd, Concat({ 0xC7, 0x01 }, Bytes(reinterpret_cast<uint32_t>(list2)), { 0x83, 0x25 }));
        if (ok == nullptr || bk == nullptr || pwCtor == nullptr || listDtor == nullptr)
        {
            g_Log->Logf(2, "BegonePOL", "Code signatures not found (ok %p, back %p, ctor %p, dtor %p); PlayOnline may have been updated.", ok, bk, pwCtor, listDtor);
            return false;
        }

        g_Pol.mgr          = *reinterpret_cast<uint8_t***>(ok + 2);
        g_Pol.hide         = RelCall<ThiscallInt>(ok + 0x26);
        g_Pol.proceedSaved = RelCall<Cdecl>(ok + 0x3A);
        g_Pol.proceedNew   = RelCall<Cdecl>(ok + 0x41);
        g_Pol.back         = RelCall<Cdecl>(bk + 0x0D);
        g_Pol.pwFrame      = *reinterpret_cast<uint8_t***>(pwCtor + 8);
        g_Pol.listFrame    = *reinterpret_cast<uint8_t***>(listDtor + 8);
        g_Pol.selectMember = reinterpret_cast<ThiscallEvent>(listVt[1]);

        // Square Enix ID login screen and the generic widgets it and the member list are built from.
        const auto connBase = FindVtable(*img, ".?AVCConnectionFrame@pol@@", 0);
        g_Pol.connSqexVt    = FindVtable(*img, ".?AVCLoginConnectionEthernetSqexFrame@pol@@", 0);
        const auto connLsn  = FindVtable(*img, ".?AVCLoginConnectionEthernetSqexFrame@pol@@", ConnListenerOffset);
        g_Pol.scrollTableVt = FindVtable(*img, ".?AVCScrollTable@pol@@", 0);
        g_Pol.selModelVt    = FindVtable(*img, ".?AVCDefaultListSelectionModel@pol@@", 0);
        g_Pol.pwFieldVt     = FindVtable(*img, ".?AVCPasswordField@pol@@", 0);
        if (!connBase || !g_Pol.connSqexVt || !connLsn || !g_Pol.scrollTableVt || !g_Pol.selModelVt || !g_Pol.pwFieldVt)
        {
            g_Log->Log(2, "BegonePOL", "RTTI lookup failed for the login screen widgets.");
            return false;
        }
        // CConnectionFrame destructor: mov [ecx], vtable; and [g_ConnectionType], 0; and [g_ConnectionFrame], 0
        const auto connDtor = Find(img->textBegin, img->textEnd, Concat({ 0xC7, 0x01 }, Bytes(reinterpret_cast<uint32_t>(connBase)), { 0x83, 0x25, -1, -1, -1, -1, 0x00, 0x83, 0x25 }));
        // Button handler: if (event->source == m_Dialog) ... else for (i < 3) if (event->source == m_Buttons[i]) ...
        const auto connHandler = reinterpret_cast<uint8_t*>(connLsn[1]);
        const auto connSig = Find(connHandler, connHandler + 0x60, { 0x8B, 0x44, 0x24, 0x04, 0x55, 0x8B, 0x68, 0x28, 0x56, 0x8B, 0xF1, 0x3B, 0x6E, 0x4C });
        const auto connLoop = Find(connHandler, connHandler + 0x80, { 0x3B, 0x6C, 0x9E, 0x10 });
        if (connDtor == nullptr || connSig != connHandler || connLoop == nullptr)
        {
            g_Log->Logf(2, "BegonePOL", "Login screen signatures not found (dtor %p, handler %p/%p); PlayOnline may have been updated.", connDtor, connSig, connLoop);
            return false;
        }
        g_Pol.connFrame  = *reinterpret_cast<uint8_t***>(connDtor + 0x0F);
        g_Pol.textFieldVt = FindVtable(*img, ".?AVCTextField@pol@@", 0);

        // Login screen constructor: mov ecx, [g_LoginOwner]; mov byte [ebp-4], 2; call GetLoginSettings (lea eax, [ecx+imm]; ret)
        const auto otpSig = Find(img->textBegin, img->textEnd, { 0x8B, 0x0D, -1, -1, -1, -1, 0xC6, 0x45, 0xFC, 0x02, 0xE8, -1, -1, -1, -1,
                                                                  0x6A, 0x27, 0x8B, 0xCE, 0x89, 0x45, 0xE8, 0xC6, 0x86, 0xD5, 0x02, 0x00, 0x00, 0x01 });
        const auto getter = otpSig ? RelCall<uint8_t*>(otpSig + 0x0A) : nullptr;
        if (getter != nullptr && getter[0] == 0x8D && getter[1] == 0x81 && getter[6] == 0xC3)
        {
            g_Pol.loginOwner    = *reinterpret_cast<uint8_t***>(otpSig + 2);
            g_Pol.loginSettings = *reinterpret_cast<uint32_t*>(getter + 2);
        }
        else
            g_Log->Log(3, "BegonePOL", "Couldn't find the member login settings; one-time password detection is off.");

        // Member list menu: call GetMemberCount (mov eax, [g_MemberStore]; mov eax, [eax+imm8]; ret); mov ebx, eax;
        // call GetMaxMembers; cmp ebx, eax; jge (the "Add Member" check)
        const auto countSig = Find(img->textBegin, img->textEnd, { 0xE8, -1, -1, -1, -1, 0x8B, 0xD8, 0xE8, -1, -1, -1, -1, 0x3B, 0xD8, 0x7D });
        const auto counter  = countSig ? RelCall<uint8_t*>(countSig) : nullptr;
        if (counter != nullptr && counter[0] == 0xA1 && counter[5] == 0x8B && counter[6] == 0x40 && counter[8] == 0xC3)
        {
            g_Pol.memberStore = *reinterpret_cast<uint8_t***>(counter + 1);
            g_Pol.memberCount = counter[7];
        }
        else
            g_Log->Log(3, "BegonePOL", "Couldn't find the member count; can't tell if PlayOnline has been set up.");

        // Member screen (Log In / Settings / Delete / Back).
        const auto subLsn = FindVtable(*img, ".?AVCLoginSubCommandFrame@pol@@", SubListenerOffset);
        if (subLsn == nullptr)
        {
            g_Log->Log(2, "BegonePOL", "RTTI lookup failed for the member screen.");
            return false;
        }
        // Destructor: mov [esi+2A0], listenerVtable; xor eax, eax; mov [g_SubCommandFrame], eax
        const auto subDtor = Find(img->textBegin, img->textEnd, Concat({ 0xC7, 0x86, 0xA0, 0x02, 0x00, 0x00 }, Bytes(reinterpret_cast<uint32_t>(subLsn)), { 0x33, 0xC0, 0xA3 }));
        // Handler: skip if busy; for (i < 4) if (event->source == m_Buttons[i]) ...
        const auto subHandler = reinterpret_cast<uint8_t*>(subLsn[1]);
        const auto subSig = Find(subHandler, subHandler + 0x40, { 0x8B, 0x45, 0x08, 0x33, 0xDB, 0x8B, 0xF1, 0x43, 0x84, 0x5E, 0x9C, 0x89, 0x85, -1, -1, -1, -1, 0x0F, 0x85, -1, -1, -1, -1,
                                                                  0x8B, 0x78, 0x28, 0x33, 0xD2, 0x8D, 0x46, 0x04, 0x3B, 0x38 });
        if (subDtor == nullptr || subSig == nullptr)
        {
            g_Log->Logf(2, "BegonePOL", "Member screen signatures not found (dtor %p, handler %p); PlayOnline may have been updated.", subDtor, subSig);
            return false;
        }
        g_Pol.subFrame  = *reinterpret_cast<uint8_t***>(subDtor + 0x0D);
        g_Pol.subAction = reinterpret_cast<ThiscallEvent>(subHandler);
        g_Pol.connAction = reinterpret_cast<ThiscallEvent>(connHandler);
        if (spy)
            HookSelect(listVt);

        const auto rva = [&](const void* p) { return static_cast<uint32_t>(reinterpret_cast<const uint8_t*>(p) - img->base); };
        g_Log->Logf(4, "BegonePOL", "app.dll @ %08X: mgr +%X, pwFrame +%X, listFrame +%X, close +%X, back +%X, proceed +%X/+%X, select +%X",
            reinterpret_cast<uint32_t>(img->base), rva(g_Pol.mgr), rva(g_Pol.pwFrame), rva(g_Pol.listFrame), rva(g_Pol.hide), rva(g_Pol.back),
            rva(g_Pol.proceedSaved), rva(g_Pol.proceedNew), rva(g_Pol.selectMember));
        g_Log->Logf(4, "BegonePOL", "app.dll member screen +%X/+%X, login screen +%X/+%X",
            rva(g_Pol.subFrame), rva(g_Pol.subAction), rva(g_Pol.connFrame), rva(g_Pol.connAction));
        return true;
    }

    /**
     * PlayOnline's password scramble (app.dll): the string including its terminator, reversed,
     * odd bytes inverted, each byte rotated left by (index & 7). The length byte sits at +0x10.
     */
    struct Scrambled
    {
        uint8_t bytes[16]{};
        int8_t length = 0;
    };

    bool Scramble(const char* text, Scrambled& out)
    {
        const auto len = std::strlen(text) + 1;
        if (len > sizeof(out.bytes))
            return false;
        out.length = static_cast<int8_t>(len);
        for (size_t i = 0; i < len; i++)
        {
            auto b = static_cast<uint8_t>(text[len - 1 - i]);
            if (i & 1)
                b = static_cast<uint8_t>(~b);
            const auto r = static_cast<uint32_t>(i & 7);
            out.bytes[i] = static_cast<uint8_t>((b << r) | (b >> ((8 - r) & 7)));
        }
        return true;
    }

    // Same comparison PlayOnline uses: the first max(length) bytes must match.
    bool MatchesStored(const Scrambled& want, const uint8_t* stored)
    {
        const auto storedLen = static_cast<int>(static_cast<int8_t>(stored[0x10]));
        const auto n = (std::max)(static_cast<int>(want.length), storedLen);
        if (n <= 0 || n > 16)
            return false;
        return std::memcmp(want.bytes, stored, n) == 0;
    }

    /**
     * PlayOnline's modules ship packed (empty .text, code in a POL1 section that is unpacked at
     * load). Write the unpacked in-memory image out as a PE Ghidra can load: raw offsets set to
     * virtual addresses and ImageBase set to the actual load address, so dumped addresses match
     * the running process.
     */
    bool DumpModule(const char* name, const std::string& dir)
    {
        const auto base = reinterpret_cast<uint8_t*>(::GetModuleHandleA(name));
        if (base == nullptr)
            return false;
        const auto dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        const auto nt   = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
        const auto size = nt->OptionalHeader.SizeOfImage;

        std::vector<uint8_t> buf(size, 0);
        for (uint32_t off = 0; off < size; off += 0x1000)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(base + off, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
                continue;
            std::memcpy(buf.data() + off, base + off, (std::min)(static_cast<DWORD>(0x1000), size - off));
        }

        const auto dnt = reinterpret_cast<IMAGE_NT_HEADERS32*>(buf.data() + dos->e_lfanew);
        dnt->OptionalHeader.ImageBase     = reinterpret_cast<uint32_t>(base);
        dnt->OptionalHeader.FileAlignment = dnt->OptionalHeader.SectionAlignment;
        auto sec = IMAGE_FIRST_SECTION(dnt);
        for (uint32_t x = 0; x < dnt->FileHeader.NumberOfSections; x++, sec++)
        {
            const auto vsize = (sec->Misc.VirtualSize + 0xFFF) & ~0xFFFu;
            sec->PointerToRawData = sec->VirtualAddress;
            sec->SizeOfRawData    = (std::min)(static_cast<DWORD>(vsize), size - sec->VirtualAddress);
            if (std::strncmp(reinterpret_cast<const char*>(sec->Name), ".text", 8) == 0)
                sec->Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;
        }

        const auto path = dir + "\\" + name + ".dump";
        const auto file = ::CreateFileA(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
            return false;
        DWORD written = 0;
        ::WriteFile(file, buf.data(), size, &written, nullptr);
        ::CloseHandle(file);
        g_Log->Logf(4, "BegonePOL", "Dumped %s (base %08X, %u bytes) to %s", name, reinterpret_cast<uint32_t>(base), written, path.c_str());
        return written == size;
    }
}

#include "splash.h"

class BegonePOL final : public IPolPlugin
{
public:
    const char* GetName(void) const override { return "BegonePOL"; }
    const char* GetAuthor(void) const override { return "Voetre"; }
    const char* GetDescription(void) const override { return "Hides PlayOnline, logs in for you and starts FINAL FANTASY XI straight away."; }
    const char* GetLink(void) const override { return ""; }
    double GetVersion(void) const override { return 1.0; }

    explicit BegonePOL(const char* args)
    {
        const std::string a = args != nullptr ? args : "";
        size_t pos = 0;
        while (pos < a.size())
        {
            const auto end = a.find(' ', pos);
            const auto tok = a.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
            if (tok.rfind("slot=", 0) == 0)
                m_Slot = std::atoi(tok.c_str() + 5);
            else if (tok.rfind("testmembers=", 0) == 0)
                m_TestMembers = std::atoi(tok.c_str() + 12);
            else if (tok == "trace")
                m_Trace = true;
            else if (tok == "dump")
                m_Dump = true;
            else if (tok == "show")
                m_Show = true;
            else if (tok == "nosplash")
                m_WantSplash = false;
            else if (tok == "dryrun")
                m_DryRun = true;
            else if (tok == "askcode")
                m_AskCodeTest = true;
            else if (tok == "menu")
                m_Quick = false;
            else if (tok == "realconnect")
                m_RealConnect = true;
            else if (tok == "skiplogo")
                m_SkipLogo = true;
            else if (tok == "logowait")
                m_SkipLogo = false;
            else if (tok == "prof")
                m_Prof = true;
            else if (tok == "setup")
                m_OpenSetup = true;
            else if (tok == "wincred")
                m_WinCred = true;
            pos = end == std::string::npos ? a.size() : end + 1;
        }
    }

    bool Initialize(IAshitaCore* core, ILogManager* log, uint32_t id) override
    {
        UNREFERENCED_PARAMETER(id);
        g_Core = core;
        g_Log  = log;
        s_Self = this;

        // A marker next to the dll means FFXI failed to start after a logo skip: keep POL's wait.
        if (::GetModuleFileNameA(reinterpret_cast<HMODULE>(&__ImageBase), quick::g_LogoMarker, MAX_PATH - 16) != 0)
        {
            if (const auto dot = std::strrchr(quick::g_LogoMarker, '.'))
                std::strcpy(dot, ".logowait");
            if (m_SkipLogo && ::GetFileAttributesA(quick::g_LogoMarker) != INVALID_FILE_ATTRIBUTES)
            {
                m_SkipLogo = false;
                g_Log->Logf(4, "BegonePOL", "Keeping PlayOnline's logo wait (FINAL FANTASY XI failed to start after a skip; delete %s to try again).", quick::g_LogoMarker);
            }
        }

        m_Platform = platform::Detect();
        if (m_Platform.kind == platform::Kind::Windows)
            g_Log->Log(4, "BegonePOL", "Running on Windows; the login is kept in Windows Credential Manager.");
        else
            g_Log->Logf(4, "BegonePOL", "Running under %s (host %s, found by: %s); the login comes from %s.", platform::Name(m_Platform.kind), m_Platform.host,
                m_Platform.why, UseKeyring() ? "the desktop keyring via begonepol-helper.py" : "Wine's Credential Manager");

        // Stay loaded even if the account can't be read, so a manual login still works.
        m_Loaded = ::GetTickCount();
        if (!LoadAccount())
            m_State = State::Failed;
        // Catch the PlayOnline window as it's created so it never appears on screen.
        else if (!m_Show)
        {
            // The PlayOnline window is created by the process's main thread, not the one loading plugins,
            // so watch window creation on every thread that exists right now.
            const auto snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            THREADENTRY32 te{ sizeof(te) };
            for (auto ok = ::Thread32First(snap, &te); ok && m_CbtCount < static_cast<int>(std::size(m_Cbts)); ok = ::Thread32Next(snap, &te))
                if (te.th32OwnerProcessID == ::GetCurrentProcessId())
                    if (const auto h = ::SetWindowsHookExW(WH_CBT, CbtProc, reinterpret_cast<HMODULE>(&__ImageBase), te.th32ThreadID))
                        m_Cbts[m_CbtCount++] = h;
            ::CloseHandle(snap);
            // In-context WinEvent hook: runs on whichever thread creates the window, before it's shown.
            m_WinEvent = ::SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW, reinterpret_cast<HMODULE>(&__ImageBase),
                WinEventProc, ::GetCurrentProcessId(), 0, WINEVENT_INCONTEXT);
            if (m_WantSplash)
                m_Splash.Open();
            if (m_Trace)
                g_Log->Logf(5, "BegonePOL", "diag: init on thread %lu, %d cbt hooks, winevent %p", ::GetCurrentThreadId(), m_CbtCount, m_WinEvent);
        }
        // Hook the network before PlayOnline starts, so its main menu can be skipped after the login.
        if (m_Quick)
            m_QuickOn = quick::Enable(m_Trace, m_RealConnect);
        m_Thread = ::CreateThread(nullptr, 0, ThreadMain, this, 0, nullptr);
        return true;
    }

    void Release(void) override
    {
        m_Stop = true;
        if (m_Thread != nullptr)
        {
            ::WaitForSingleObject(m_Thread, 2000);
            ::CloseHandle(m_Thread);
        }
        Unsubclass();
        DropCbt();
        m_Splash.Close();
        Reveal("plugin unloaded.");
        UnhookSelect();
        if (m_QuickOn)
            quick::Disable();
        ::SecureZeroMemory(&m_Password, sizeof(m_Password));
        ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
        ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
        s_Self = nullptr;
    }

private:
    enum class State { Waiting, Running, Done, Failed };

    /**
     * Login left by begonepol-helper.py (Faugus pre-launch) in $XDG_RUNTIME_DIR/begonepol/login: a
     * RAM-only, user-only file of key=value lines (account, slot, otp, password, totp). It is read once
     * and deleted straight away. While the helper's setup window is open (it leaves a "setup" marker)
     * this waits for it, so PlayOnline doesn't start until the login is saved.
     */
    bool ReadHandoff(void)
    {
        // Proton doesn't pass XDG_RUNTIME_DIR on to Windows programs; the container only has our own
        // /run/user/<uid>, so look for the hand-off folder there.
        std::string dir;
        WIN32_FIND_DATAA fd{};
        const auto f = ::FindFirstFileA("Z:\\run\\user\\*", &fd);
        if (f == INVALID_HANDLE_VALUE)
            return false;
        do
        {
            const auto d = std::string("Z:\\run\\user\\") + fd.cFileName + "\\begonepol";
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0 && fd.cFileName[0] >= '0' && fd.cFileName[0] <= '9'
                && ::GetFileAttributesA(d.c_str()) != INVALID_FILE_ATTRIBUTES)
                dir = d;
        } while (dir.empty() && ::FindNextFileA(f, &fd));
        ::FindClose(f);
        if (dir.empty())
            return false; // the helper never ran

        const auto path   = dir + "\\login";
        const auto marker = dir + "\\setup";
        const auto t0     = ::GetTickCount();
        auto setupLogged  = false;
        while (::GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES)
        {
            const auto inSetup = ::GetFileAttributesA(marker.c_str()) != INVALID_FILE_ATTRIBUTES;
            if (inSetup && !setupLogged)
            {
                setupLogged = true;
                g_Log->Log(4, "BegonePOL", "Waiting for the BegonePOL setup window to be filled in...");
            }
            if (::GetTickCount() - t0 > (inSetup ? 1800000u : 5000u))
                return false;
            ::Sleep(100);
        }
        ::Sleep(50); // the helper writes then renames, but give a slow rename a moment anyway
        const auto h = ::CreateFileA(path.c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE)
            return false;
        char buf[1024];
        DWORD got = 0;
        const auto ok = ::ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) != FALSE;
        ::CloseHandle(h);
        ::DeleteFileA(path.c_str());
        buf[ok ? got : 0] = 0;

        // key=value lines; values are copied straight into their fixed buffers.
        for (auto line = buf; *line != 0;)
        {
            auto end = line;
            while (*end != 0 && *end != '\n')
                end++;
            const auto next = *end != 0 ? end + 1 : end;
            while (end > line && end[-1] == '\r')
                end--;
            *end = 0;
            if (const auto eq = std::strchr(line, '='))
            {
                *eq = 0;
                const auto val = eq + 1;
                const auto len = static_cast<size_t>(end - val);
                if (std::strcmp(line, "account") == 0)
                    m_Account = val;
                else if (std::strcmp(line, "slot") == 0 && m_Slot == 0)
                    m_Slot = std::atoi(val);
                else if (std::strcmp(line, "otp") == 0)
                    m_Otp = std::strcmp(val, "auto") == 0 ? Otp::Auto : std::strcmp(val, "manual") == 0 ? Otp::Manual : Otp::Off;
                else if (std::strcmp(line, "password") == 0 && len < sizeof(m_Plain))
                    std::memcpy(m_Plain, val, len + 1);
                else if (std::strcmp(line, "totp") == 0 && len < sizeof(m_TotpKey))
                    std::memcpy(m_TotpKey, val, len + 1);
            }
            line = next;
        }
        ::SecureZeroMemory(buf, sizeof(buf));
        return m_Plain[0] != 0;
    }

    // Linux keeps the login in the desktop keyring (handed over by begonepol-helper.py); Windows, and
    // Wine on other hosts, in Credential Manager. "wincred" forces Credential Manager (for testing).
    bool UseKeyring(void) const
    {
        return m_Platform.kind == platform::Kind::WineLinux && !m_WinCred;
    }

    /**
     * The login from Windows Credential Manager. The member row comes from slot=<n>, or is the only
     * saved login; otherwise (nothing saved, several saved, or arg "setup") the setup window opens
     * first and PlayOnline waits for it.
     */
    bool ReadCredentials(void)
    {
        auto saved = winlogin::List();
        const winlogin::Login* use = nullptr;
        for (const auto& l : saved)
            if (m_Slot == 0 ? saved.size() == 1 : l.slot == m_Slot)
                use = &l;
        winlogin::Login fromSetup;
        if (use == nullptr || m_OpenSetup)
        {
            g_Log->Log(4, "BegonePOL", "Waiting for the BegonePOL setup window to be filled in...");
            winlogin::Setup setup;
            const auto ok = setup.Run(saved, use != nullptr ? use->slot : m_Slot, true, fromSetup);
            winlogin::WipeAll(saved);
            if (!ok)
            {
                fromSetup.Wipe();
                return false;
            }
            use = &fromSetup;
        }
        m_Account = use->account;
        m_Slot    = use->slot;
        m_Otp     = use->otp == "auto" ? Otp::Auto : use->otp == "manual" ? Otp::Manual : Otp::Off;
        ::strncpy_s(m_Plain, use->password, _TRUNCATE);
        ::strncpy_s(m_TotpKey, use->totp, _TRUNCATE);
        winlogin::WipeAll(saved);
        fromSetup.Wipe();
        return m_Plain[0] != 0;
    }

    bool LoadAccount(void)
    {
        if (!(UseKeyring() ? ReadHandoff() : ReadCredentials()))
        {
            ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
            ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
            g_Log->Log(2, "BegonePOL", UseKeyring() ? "No saved login (is begonepol-helper.py the Faugus pre-launch command, and was setup finished?). Log in yourself this time."
                                                    : "No saved login (the setup window was closed). Log in yourself this time.");
            return false;
        }
        if (!Scramble(m_Plain, m_Password))
        {
            ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
            ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
            g_Log->Log(2, "BegonePOL", "The saved password is longer than PlayOnline allows.");
            return false;
        }
        char probe[7];
        if (m_Otp == Otp::Auto && !totp::Code(m_TotpKey, 0, probe))
        {
            g_Log->Log(2, "BegonePOL", "The saved authenticator key isn't valid; you'll be asked for the one-time password instead.");
            m_Otp = Otp::Manual;
        }
        if (m_Otp != Otp::Auto)
            ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
        if (m_Slot < 1)
            m_Slot = 1;
        if (m_AskCodeTest && m_DryRun)
            m_Otp = Otp::Manual; // test the code prompt; a dry run never sends it
        g_Log->Logf(4, "BegonePOL", "Using account '%s', member slot %d, one-time password %s (login from %s).", m_Account.c_str(), m_Slot,
            m_Otp == Otp::Auto ? "entered automatically" : m_Otp == Otp::Manual ? "asked for" : "off", UseKeyring() ? "the keyring" : "Credential Manager");
        return true;
    }

    static DWORD __stdcall ThreadMain(LPVOID param)
    {
        const auto self = static_cast<BegonePOL*>(param);
        if (self->m_Trace)
            g_Log->Logf(5, "BegonePOL", "diag: plugin thread %lu running", ::GetCurrentThreadId());
        while (!self->m_Stop)
        {
            self->ThreadTick();
            ::Sleep(self->m_State == State::Waiting ? 20 : 100);
        }
        return 0;
    }

    // Plugin thread: wait for the PlayOnline window, hook its window procedure, then keep poking
    // the UI thread; the actual work happens in UiTick on PlayOnline's own thread.
    static BOOL CALLBACK FindPolWindow(HWND hwnd, LPARAM lp)
    {
        DWORD pid = 0;
        ::GetWindowThreadProcessId(hwnd, &pid);
        if (pid == ::GetCurrentProcessId() && IsPolWindow(hwnd))
        {
            *reinterpret_cast<HWND*>(lp) = hwnd;
            return FALSE;
        }
        return TRUE;
    }

    void ThreadTick(void)
    {
        if (m_Prof)
        {
            const auto now = ::GetTickCount();
            if (m_ProfStart == 0)
                m_ProfStart = now;
            if (now - m_ProfLast >= 1000)
            {
                m_ProfLast = now;
                int n = 0;
                for (const auto name : { "app.dll", "polcore.dll", "pol.exe", "PolContents.dll" })
                    n += prof::Patch(name);
                if (n != 0)
                    g_Log->Logf(5, "BegonePOL", "prof: +%lums patched %d sleep imports", now - m_ProfStart, n);
                prof::Report(m_ProfStart);
            }
        }
        if (m_CaughtBy != nullptr && !m_CaughtLogged)
        {
            m_CaughtLogged = true;
            g_Log->Logf(4, "BegonePOL", "PlayOnline window hidden %s.", m_CaughtBy);
            if (m_Trace)
                g_Log->Logf(5, "BegonePOL", "diag: window %p owned by thread %lu", m_HiddenHwnd, ::GetWindowThreadProcessId(m_HiddenHwnd, nullptr));
        }
        // Ashita reports the PlayOnline window several seconds after it appears, so look for it directly.
        if (!m_Show && m_HiddenHwnd == nullptr && m_WindowSeen == 0 && m_State == State::Waiting)
        {
            HWND found = nullptr;
            const auto t0 = ::GetTickCount();
            ::EnumWindows(FindPolWindow, reinterpret_cast<LPARAM>(&found));
            if (m_Trace && (t0 - m_LastPollLog > 500 || ::GetTickCount() - t0 > 100))
            {
                m_LastPollLog = t0;
                g_Log->Logf(5, "BegonePOL", "diag: poll took %lums, found %p", ::GetTickCount() - t0, found);
            }
            if (found != nullptr)
            {
                Conceal(found);
                m_CaughtBy = "by polling";
            }
        }
        if (m_Splash.IsOpen())
        {
            if (quick::g_MenuSkipped && ::GetModuleHandleA("FFXiMain.dll") == nullptr)
                m_Splash.SetStatus(L"Signed in. Starting FINAL FANTASY XI...");
            const auto ff = g_Core->GetProperties()->GetFinalFantasyHwnd();
            if (ff != nullptr && ::IsWindowVisible(ff))
                m_Splash.Close();
            else if (m_State == State::Failed || (!m_AskingCode && ::GetTickCount() - m_Loaded > 240000))
                m_Splash.Close();
        }
        const auto hwnd = g_Core->GetProperties()->GetPlayOnlineHwnd();
        if (hwnd == nullptr)
            return;
        if (m_WindowSeen == 0)
        {
            m_WindowSeen = ::GetTickCount();
            DropCbt();
            if (!m_Show && m_State != State::Failed)
                Conceal(hwnd);
        }
        WatchConcealed(hwnd);
        if (::GetModuleHandleA("app.dll") == nullptr)
            return;

        if (m_Dump && ::GetTickCount() - m_WindowSeen > 15000)
        {
            m_Dump = false;
            const auto dir = std::string(g_Core->GetInstallPath()) + "\\logs\\pol-dump";
            ::CreateDirectoryA(dir.c_str(), nullptr);
            for (const auto name : { "app.dll", "polcore.dll", "pol.exe" })
                DumpModule(name, dir);
        }

        if (m_QuickOn && (m_Trace || m_SkipLogo) && !m_ProbeDone)
        {
            const auto img = MapImage("pol.exe");
            if (img && quick::ProbeComErrors(img->textBegin, img->textEnd))
                m_ProbeDone = true;
            else if (m_WindowSeen != 0)
            {
                m_ProbeDone = true;
                if (m_Trace)
                    g_Log->Log(2, "BegonePOL", "diag: could not hook pol.exe's COM error function.");
            }
        }
        if (m_QuickOn && m_SkipLogo && !m_LogoDone)
        {
            const auto img = MapImage("pol.exe");
            const auto n   = img ? quick::SkipLogo(img->textBegin, img->textEnd) : 0;
            if (n == 2 || m_WindowSeen != 0)
            {
                m_LogoDone = true;
                if (n != 2)
                    g_Log->Logf(2, "BegonePOL", "Found %d of 2 logo waits to skip; PlayOnline may have been updated.", n);
                else
                {
                    quick::g_LogoSkipped = true;
                    if (m_Trace)
                        g_Log->Log(5, "BegonePOL", "diag: logo wait skipped.");
                }
            }
        }

        // app.dll unpacks itself after loading, so keep looking for the fade loops for a while.
        if (m_QuickOn && !m_FadesDone)
        {
            const auto img = MapImage("app.dll");
            const auto n   = img ? quick::SkipFades(img->textBegin, img->textEnd) : 0;
            if (n == 2 || ::GetTickCount() - m_WindowSeen > 20000)
            {
                m_FadesDone = true;
                if (n != 2)
                    g_Log->Logf(2, "BegonePOL", "Found %d of 2 fade loops to skip; PlayOnline may have been updated.", n);
                else if (m_Trace)
                    g_Log->Log(5, "BegonePOL", "diag: fade loops skipped.");
            }
        }

        if (m_State == State::Waiting)
        {
            if (!ResolvePol(m_Trace))
            {
                m_State = State::Failed;
                return;
            }
            m_Hwnd    = hwnd;
            m_OldProc = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(WndProc)));
            m_State   = State::Running;
            m_Started = ::GetTickCount();
            g_Log->Log(4, "BegonePOL", "Hooked the PlayOnline window; waiting for the login screen.");
            m_Splash.SetStatus(L"Loading PlayOnline...", true);
        }

        if (m_State == State::Running)
        {
            if (!m_AskingCode && ::GetTickCount() - m_Started > 180000)
            {
                g_Log->Log(2, "BegonePOL", "Gave up after 3 minutes without reaching the password screen.");
                m_State = State::Failed;
                return;
            }
            ::PostMessageW(m_Hwnd, WM_POLLOGIN_TICK, 0, 0);
        }
    }

    static LRESULT CALLBACK CbtProc(int code, WPARAM wp, LPARAM lp)
    {
        const auto self = s_Self;
        if (code == HCBT_CREATEWND && self != nullptr && self->m_HiddenHwnd == nullptr)
        {
            const auto cs   = reinterpret_cast<CBT_CREATEWNDW*>(lp)->lpcs;
            const auto name = cs->lpszName;
            if (self->m_Trace && cs->hwndParent == nullptr && (cs->style & WS_CHILD) == 0 && self->m_CbtSeen++ < 40)
                g_Log->Logf(5, "BegonePOL", "cbt: thread %lu top-level window '%ls' class '%ls' style %08X ex %08X at %d,%d %dx%d",
                    ::GetCurrentThreadId(), name != nullptr && !IS_INTRESOURCE(name) ? name : L"",
                    !IS_INTRESOURCE(cs->lpszClass) ? cs->lpszClass : L"#atom", cs->style, cs->dwExStyle, cs->x, cs->y, cs->cx, cs->cy);
            // The viewer window is created as class "PlayOnline<region>" and renamed "PlayOnline Viewer ..." later;
            // "PlayOnlineMask<region>" is a separate, never-visible helper.
            const auto cls = cs->lpszClass;
            const auto top = cs->hwndParent == nullptr && (cs->style & WS_CHILD) == 0;
            const auto pol = top && cls != nullptr && !IS_INTRESOURCE(cls)
                && std::wcsncmp(cls, L"PlayOnline", 10) == 0 && std::wcsstr(cls, L"Mask") == nullptr;
            // PlayOnline's untitled start-up dialog, which Wine shows as an unpainted white box.
            const auto startup = top && IS_INTRESOURCE(cls) && LOWORD(reinterpret_cast<ULONG_PTR>(cls)) == 32770 && (name == nullptr || IS_INTRESOURCE(name) || name[0] == 0);
            if (pol || startup)
            {
                const auto hwnd = reinterpret_cast<HWND>(wp);
                if (pol)
                {
                    self->m_OldExStyle = cs->dwExStyle;
                    self->m_HiddenHwnd = hwnd;
                    self->m_CbtCaught  = true;
                }
                cs->dwExStyle = (cs->dwExStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) & ~WS_EX_APPWINDOW;
                Invisible(hwnd);
            }
        }
        if (code == HCBT_ACTIVATE && self != nullptr && reinterpret_cast<HWND>(wp) == self->m_HiddenHwnd)
            ::SetLayeredWindowAttributes(self->m_HiddenHwnd, 0, 0, LWA_ALPHA);
        return ::CallNextHookEx(nullptr, code, wp, lp);
    }

    static bool IsPolWindow(HWND hwnd)
    {
        if (::GetAncestor(hwnd, GA_PARENT) != ::GetDesktopWindow())
            return false;
        wchar_t title[32]{};
        // InternalGetWindowText reads the title directly instead of messaging the (possibly busy) owner thread.
        return ::InternalGetWindowText(hwnd, title, 32) > 0 && std::wcsncmp(title, L"PlayOnline Viewer", 17) == 0;
    }

    static void CALLBACK WinEventProc(HWINEVENTHOOK, DWORD event, HWND hwnd, LONG obj, LONG child, DWORD, DWORD)
    {
        const auto self = s_Self;
        if (self == nullptr || hwnd == nullptr || obj != OBJID_WINDOW || child != CHILDID_SELF || self->m_HiddenHwnd != nullptr)
            return;
        if (!IsPolWindow(hwnd))
            return;
        self->Conceal(hwnd);
        self->m_CaughtBy = event == EVENT_OBJECT_CREATE ? "at creation (winevent)" : "as it was shown (winevent)";
    }

    // Keep a just-created window at zero opacity: Wine only creates the X window when it is first
    // shown, so the opacity is applied again at that point, then the window procedure is handed back.
    struct EarlyHook { HWND hwnd; WNDPROC orig; bool release; };
    static inline EarlyHook s_Early[4]{};

    static void Invisible(HWND hwnd)
    {
        for (auto& e : s_Early)
            if (e.hwnd == nullptr)
            {
                e.hwnd    = hwnd;
                e.release = false;
                e.orig    = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(EarlyProc)));
                return;
            }
    }

    static constexpr LONG HiddenEx = WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE;

    static void MakeInvisible(HWND hwnd)
    {
        const auto ex = ::GetWindowLongW(hwnd, GWL_EXSTYLE);
        if ((ex & HiddenEx) != HiddenEx || (ex & WS_EX_APPWINDOW) != 0)
            ::SetWindowLongW(hwnd, GWL_EXSTYLE, (ex | HiddenEx) & ~WS_EX_APPWINDOW);
        ::SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
    }

    // Wine ignores extended styles changed from the CBT hook, so the window is made layered and
    // transparent from its own WM_CREATE, and kept that way (PlayOnline resets its styles once)
    // until Reveal() releases it.
    static LRESULT CALLBACK EarlyProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        EarlyHook* e = nullptr;
        for (auto& x : s_Early)
            if (x.hwnd == hwnd)
                e = &x;
        if (e == nullptr)
            return ::DefWindowProcW(hwnd, msg, wp, lp);
        const auto orig = e->orig;
        if (s_Self != nullptr && s_Self->m_Trace && (msg == WM_CREATE || msg == WM_STYLECHANGED
            || (msg == WM_WINDOWPOSCHANGED && (reinterpret_cast<WINDOWPOS*>(lp)->flags & SWP_SHOWWINDOW) != 0)))
        {
            BYTE a = 0; DWORD f = 0;
            const auto ok = ::GetLayeredWindowAttributes(hwnd, nullptr, &a, &f);
            g_Log->Logf(5, "BegonePOL", "early: %p msg %04X ex %08X layered %d alpha %u visible %d",
                hwnd, msg, static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE)), ok, a, ::IsWindowVisible(hwnd));
        }
        if (!e->release)
        {
            if (msg == WM_STYLECHANGING && wp == static_cast<WPARAM>(GWL_EXSTYLE))
            {
                auto ss = reinterpret_cast<STYLESTRUCT*>(lp);
                ss->styleNew = (ss->styleNew | HiddenEx) & ~WS_EX_APPWINDOW;
            }
            if (msg == WM_WINDOWPOSCHANGING && (reinterpret_cast<WINDOWPOS*>(lp)->flags & SWP_SHOWWINDOW) != 0)
                MakeInvisible(hwnd);
        }
        const auto ret = ::CallWindowProcW(orig, hwnd, msg, wp, lp);
        if (!e->release && (msg == WM_CREATE || msg == WM_STYLECHANGED))
            MakeInvisible(hwnd);
        if (msg == WM_NCDESTROY || e->release)
        {
            if (reinterpret_cast<WNDPROC>(::GetWindowLongPtrW(hwnd, GWLP_WNDPROC)) == EarlyProc)
            {
                ::SetWindowLongPtrW(hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(orig));
                *e = {};
            }
            else if (msg == WM_NCDESTROY)
                *e = {};
        }
        return ret;
    }

    static void ReleaseEarly(HWND hwnd)
    {
        for (auto& e : s_Early)
            if (e.hwnd == hwnd)
                e.release = true;
    }

    void DropCbt(void)
    {
        if (m_WinEvent != nullptr)
            ::UnhookWinEvent(m_WinEvent);
        m_WinEvent = nullptr;
        for (int i = 0; i < m_CbtCount; i++)
            ::UnhookWindowsHookEx(m_Cbts[i]);
        m_CbtCount = 0;
    }

    // Make the PlayOnline window invisible and click-through without hiding it, so it keeps
    // rendering and its UI keeps ticking normally.
    void Conceal(HWND hwnd)
    {
        if (m_HiddenHwnd != nullptr && m_HiddenHwnd != hwnd)
        {
            Reveal("it isn't the window Ashita reports.");
            m_CbtCaught = false;
        }
        const auto already = m_HiddenHwnd == hwnd;
        if (m_HiddenHwnd != hwnd)
        {
            m_HiddenHwnd = hwnd;
            m_OldExStyle = ::GetWindowLongW(hwnd, GWL_EXSTYLE);
        }
        auto ex = (m_OldExStyle | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) & ~WS_EX_APPWINDOW;
        if (::GetWindowLongW(hwnd, GWL_EXSTYLE) != ex)
            ::SetWindowLongW(hwnd, GWL_EXSTYLE, ex);
        ::SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        if (m_CbtCaught && m_CaughtBy == nullptr)
            m_CaughtBy = "at creation (cbt)";
        if (!already && m_CaughtBy == nullptr)
            m_CaughtBy = "when Ashita reported it (it may have flashed)";
    }

    void Reveal(const char* why)
    {
        if (m_HiddenHwnd == nullptr)
            return;
        ReleaseEarly(m_HiddenHwnd);
        if (::IsWindow(m_HiddenHwnd))
        {
            ::SetLayeredWindowAttributes(m_HiddenHwnd, 0, 255, LWA_ALPHA);
            // Keep any style PlayOnline set itself since creation; only undo what was added to hide it.
            const auto ex = ::GetWindowLongW(m_HiddenHwnd, GWL_EXSTYLE);
            ::SetWindowLongW(m_HiddenHwnd, GWL_EXSTYLE, (ex & ~(HiddenEx | WS_EX_APPWINDOW)) | (m_OldExStyle & (HiddenEx | WS_EX_APPWINDOW)));
            ::RedrawWindow(m_HiddenHwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_FRAME | RDW_ALLCHILDREN);
        }
        m_HiddenHwnd = nullptr;
        g_Log->Logf(4, "BegonePOL", "PlayOnline window shown again: %s", why);
    }

    // Show the window again once FFXI has taken over, or if the login stalls or fails so the
    // user can see PlayOnline's error message and carry on by hand.
    void WatchConcealed(HWND hwnd)
    {
        if (m_HiddenHwnd == nullptr)
            return;
        if (m_HiddenHwnd != hwnd || !::IsWindow(m_HiddenHwnd))
            m_HiddenHwnd = nullptr;
        else if (::GetModuleHandleA("FFXiMain.dll") != nullptr)
        {
            m_Splash.SetStatus(L"Loading FINAL FANTASY XI...", true);
            Reveal("FFXI has started.");
        }
        else if (m_State == State::Failed)
            Reveal("automatic login failed.");
        else if (m_State == State::Done && ::GetTickCount() - m_DoneAt > 60000)
            Reveal("FFXI didn't start within a minute of logging in.");
    }

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        const auto self = s_Self;
        if (msg == WM_POLLOGIN_TICK)
        {
            if (self != nullptr)
                self->UiTick();
            return 0;
        }
        if (self == nullptr || self->m_OldProc == nullptr)
            return ::DefWindowProcW(hwnd, msg, wp, lp);
        return ::CallWindowProcW(self->m_OldProc, hwnd, msg, wp, lp);
    }

    void Unsubclass(void)
    {
        if (m_Hwnd != nullptr && m_OldProc != nullptr && ::IsWindow(m_Hwnd)
            && reinterpret_cast<WNDPROC>(::GetWindowLongPtrW(m_Hwnd, GWLP_WNDPROC)) == WndProc)
            ::SetWindowLongPtrW(m_Hwnd, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(m_OldProc));
    }

    static bool Busy(const uint8_t* frame)
    {
        return (frame[FrameStateOffset] & 1) != 0;
    }

    // Runs on PlayOnline's UI thread.
    void UiTick(void)
    {
        if (m_State != State::Running)
            return;
        const auto mgr = *g_Pol.mgr;
        if (mgr == nullptr)
            return;
        const auto now = ::GetTickCount();

        const auto pw      = *g_Pol.pwFrame;
        const auto list    = *g_Pol.listFrame;
        const auto conn    = *g_Pol.connFrame;
        const auto sub     = *g_Pol.subFrame;
        const auto current = *reinterpret_cast<int32_t*>(mgr + MgrCurrentMember);

        if (m_Trace && now - m_LastTrace > 2000)
        {
            m_LastTrace = now;
            g_Log->Logf(5, "BegonePOL", "trace: pw %p (%02X) list %p (%02X) sub %p (%02X) conn %p (%02X) member %d of %d",
                pw, pw ? pw[FrameStateOffset] : 0, list, list ? list[FrameStateOffset] : 0, sub, sub ? sub[FrameStateOffset] : 0,
                conn, conn ? conn[FrameStateOffset] : 0, current, MemberCount());
        }

        // A fresh PlayOnline has no members: leave it to the user to set one up. The list is only
        // drawn once the members are loaded; if PlayOnline opens some other screen instead, give it a while.
        const auto members = m_DryRun && m_TestMembers >= 0 ? m_TestMembers : MemberCount();
        if (members >= 0 && conn == nullptr && sub == nullptr && pw == nullptr
            && ((list != nullptr && !Busy(list)) || now - m_Started > 20000))
        {
            if (members == 0)
                return FailPrompt("PlayOnline has no members set up yet.",
                    L"PlayOnline hasn't been set up yet.\n\n"
                    L"Add a member in PlayOnline, link it to your Square Enix account and log in once yourself. "
                    L"After that, BegonePOL will log in for you.");
            if (members < m_Slot)
            {
                wchar_t text[256];
                ::swprintf_s(text, L"BegonePOL is set to log in as PlayOnline member %d, but PlayOnline has only %d.\n\n"
                                   L"Pick another member in \"BegonePOL setup\", or log in yourself this time.", m_Slot, members);
                return FailPrompt("The saved member row is past the end of PlayOnline's member list.", text);
            }
        }

        // Let each screen finish opening before touching it.
        const auto screen = conn ? conn : sub ? sub : pw ? pw : list;
        if (screen != m_Screen)
        {
            m_Screen     = screen;
            m_ScreenSeen = now;
        }
        if (now - m_LastAction < 300 || now - m_ScreenSeen < 300)
            return;

        if (conn != nullptr && !Busy(conn))
            return SubmitLogin(conn);

        if (sub != nullptr && !Busy(sub))
        {
            m_LastAction = now;
            if (++m_LogIns > 3)
                return Fail("Pressing Log In didn't open the login screen.");
            const auto back = current != m_Slot;
            wchar_t text[96];
            if (back)
                ::swprintf_s(text, L"Member %d is open; going back to the member list...", current);
            else
                ::swprintf_s(text, L"Opening the login screen for member %d...", m_Slot);
            m_Splash.SetStatus(text);
            g_Log->Logf(4, "BegonePOL", back ? "Member %d is open, want %d; pressing Back." : "Pressing Log In for member %d.", current, m_Slot);
            uint8_t evt[0x100]{};
            *reinterpret_cast<void**>(evt + EventSource) = *reinterpret_cast<void**>(sub + (back ? SubBackButton : SubLogInButton));
            g_Pol.subAction(sub + SubListenerOffset, evt);
            return;
        }

        if (pw != nullptr && !Busy(pw))
        {
            m_LastAction = now;
            if (current != m_Slot)
            {
                if (++m_Backs > 3)
                    return Fail("Still on the wrong member after 3 tries.");
                g_Log->Logf(4, "BegonePOL", "Password screen is for member %d, want %d; going back.", current, m_Slot);
                g_Pol.hide(pw, 1);
                g_Pol.back();
                return;
            }
            if (!MatchesStored(m_Password, mgr + MgrMemberData + MemberStoredPassword))
                return Fail("The stored password doesn't match the one PlayOnline has saved for this member; leaving the prompt for you.");

            g_Log->Logf(4, "BegonePOL", "Member password verified for member %d; continuing.", current);
            m_Splash.SetStatus(L"Entering the member password...");
            g_Pol.hide(pw, 1);
            if (*reinterpret_cast<int32_t*>(mgr + MgrUseSavedLogin) != 0)
                g_Pol.proceedSaved();
            else
                g_Pol.proceedNew();
            return;
        }

        if (pw == nullptr && list != nullptr && !Busy(list))
        {
            m_LastAction = now;
            if (++m_Selects > 4)
                return Fail("Selecting the member didn't move past the member list.");
            const auto table = *reinterpret_cast<uint8_t**>(list + ListTable);
            if (table == nullptr || *reinterpret_cast<uint32_t**>(table) != g_Pol.scrollTableVt)
                return Fail("The member list isn't laid out as expected.");
            const auto model = *reinterpret_cast<uint8_t**>(table + TableModel);
            const auto sel   = model ? *reinterpret_cast<uint8_t**>(model + TableSelection) : nullptr;
            if (sel == nullptr || *reinterpret_cast<uint32_t**>(sel) != g_Pol.selModelVt)
                return Fail("The member list's selection isn't laid out as expected.");
            const auto vt  = *reinterpret_cast<uint8_t***>(sel);
            const auto row = m_Slot - 1;

            // Select the row the way a click does; that may already open the next screen.
            if (!reinterpret_cast<IsSelected>(vt[SelIsSelected / 4])(sel, row))
            {
                wchar_t text[64];
                ::swprintf_s(text, L"Selecting PlayOnline member %d...", m_Slot);
                m_Splash.SetStatus(text);
                g_Log->Logf(4, "BegonePOL", "Selecting member %d in the list.", m_Slot);
                reinterpret_cast<SetInterval>(vt[SelSetInterval / 4])(sel, row, row);
                return;
            }
            // Row is selected but nothing happened: fire the list's selection handler like a click.
            g_Log->Logf(4, "BegonePOL", "Opening member %d.", m_Slot);
            uint8_t evt[0x100]{};
            *reinterpret_cast<int32_t*>(evt + EventSelectedIndex) = row;
            g_Pol.selectMember(list + ListListenerOffset, evt);
        }
    }

    // A text box inside one of the login screen's CScrollTextFields, or null if it isn't laid out as expected.
    static uint8_t* InnerField(uint8_t* conn, uint32_t offset)
    {
        const auto scroll = *reinterpret_cast<uint8_t**>(conn + offset);
        const auto field  = scroll ? *reinterpret_cast<uint8_t**>(scroll + ScrollInnerField) : nullptr;
        if (field == nullptr)
            return nullptr;
        const auto vt = *reinterpret_cast<uint32_t**>(field);
        return vt == g_Pol.pwFieldVt || (vt != nullptr && vt == g_Pol.textFieldVt) ? field : nullptr;
    }

    static void SetFieldText(uint8_t* field, const char* text)
    {
        const auto vt = *reinterpret_cast<uint8_t***>(field);
        reinterpret_cast<SetText>(vt[FieldSetText / 4])(field, text);
    }

    static uint64_t UnixTime(void)
    {
        FILETIME ft;
        ::GetSystemTimeAsFileTime(&ft);
        return ((static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) / 10000000ull - 11644473600ull;
    }

    // Square Enix ID login screen: put the password (and one-time password) in its fields and press Login.
    void SubmitLogin(uint8_t* conn)
    {
        m_LastAction = ::GetTickCount();
        if (*reinterpret_cast<uint32_t**>(conn) != g_Pol.connSqexVt)
            return Fail("This login screen type isn't supported (only Square Enix ID login is).");
        const auto field  = InnerField(conn, ConnPasswordField);
        const auto button = *reinterpret_cast<void**>(conn + ConnLoginButton);
        if (field == nullptr || *reinterpret_cast<uint32_t**>(field) != g_Pol.pwFieldVt || button == nullptr)
            return Fail("The login screen isn't laid out as expected.");

        // PlayOnline only shows (and sends) the one-time password box for members set to use one.
        const auto owner   = g_Pol.loginOwner ? *g_Pol.loginOwner : nullptr;
        const auto polOtp  = owner != nullptr ? owner[g_Pol.loginSettings + LoginUsesOtp] != 0 : m_Otp != Otp::Off;
        const auto first   = !m_OtpChecked;
        m_OtpChecked       = true;
        if (m_Trace && first)
        {
            g_Log->Logf(5, "BegonePOL", "diag: member uses a one-time password: %s", owner == nullptr ? "unknown" : polOtp ? "yes" : "no");
            const auto scroll = *reinterpret_cast<uint8_t**>(conn + ConnOtpField);
            const auto inner  = scroll ? *reinterpret_cast<uint8_t**>(scroll + ScrollInnerField) : nullptr;
            const auto vt     = inner ? *reinterpret_cast<uint32_t**>(inner) : nullptr;
            g_Log->Logf(5, "BegonePOL", "diag: one-time password box: %s (vt %p)",
                inner == nullptr ? "missing" : vt == g_Pol.pwFieldVt ? "CPasswordField" : vt == g_Pol.textFieldVt ? "CTextField" : "unknown", vt);
        }
        if (m_Otp != Otp::Off && !polOtp && m_DryRun)
        {
            if (first)
                g_Log->Log(3, "BegonePOL", "Dry run: this member isn't set to use a one-time password; carrying on to test the code step anyway.");
        }
        else if (m_Otp != Otp::Off && !polOtp)
            return FailPrompt("The saved login uses a one-time password, but this PlayOnline member isn't set to use one.",
                L"BegonePOL is set up to enter a one-time password, but this PlayOnline member isn't set to use one.\n\n"
                L"Turn on the one-time password in the member's Settings in PlayOnline, or turn it off in \"BegonePOL setup\". "
                L"You can log in yourself this time.");
        if (m_Otp == Otp::Off && polOtp)
        {
            g_Log->Log(3, "BegonePOL", "PlayOnline expects a one-time password for this member; asking for it.");
            m_Otp = Otp::Manual;
        }

        char code[16]{};
        if (m_Otp == Otp::Auto)
        {
            // Don't hand over a code that runs out while Square Enix checks it.
            const auto now = UnixTime();
            if (30 - now % 30 < 4)
                return;
            totp::Code(m_TotpKey, now, code);
            ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
        }
        else if (m_Otp == Otp::Manual)
        {
            if (!m_AskingCode)
            {
                m_AskingCode = true;
                m_Splash.AskCode();
                m_Splash.SetStatus(L"Enter the one-time password from your authenticator:");
                g_Log->Log(4, "BegonePOL", "Asking for the one-time password.");
                return;
            }
            const auto st = m_Splash.Code(code);
            if (st == Splash::CodeState::Asking)
                return;
            m_AskingCode = false;
            if (st != Splash::CodeState::Ready)
                return Fail("One-time password prompt closed; log in yourself.");
            const auto n = std::strlen(code);
            if (n < 6 || n > 8 || std::strspn(code, "0123456789") != n)
            {
                ::SecureZeroMemory(code, sizeof(code));
                g_Log->Log(3, "BegonePOL", "That one-time password isn't 6-8 digits; asking again.");
                return;
            }
            // The prompt may have waited a long time; restart the stall timers.
            m_Started = m_Loaded = ::GetTickCount();
        }
        const auto otpField = code[0] != 0 ? InnerField(conn, ConnOtpField) : nullptr;
        if (code[0] != 0 && otpField == nullptr)
        {
            ::SecureZeroMemory(code, sizeof(code));
            return Fail("The login screen's one-time password box isn't laid out as expected.");
        }

        if (m_DryRun)
        {
            ::SecureZeroMemory(code, sizeof(code));
            ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
            g_Log->Logf(4, "BegonePOL", "Dry run: reached the login screen%s; not pressing Login.",
                m_Otp == Otp::Auto ? " and generated the one-time password" : m_Otp == Otp::Manual ? " and got the one-time password" : "");
            Finish(State::Done);
            return;
        }
        SetFieldText(field, m_Plain);
        ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
        if (otpField != nullptr)
            SetFieldText(otpField, code);
        ::SecureZeroMemory(code, sizeof(code));

        uint8_t evt[0x100]{};
        *reinterpret_cast<void**>(evt + EventSource) = button;
        m_Splash.SetStatus(L"Signing in to your Square Enix account...", true);
        g_Log->Log(4, "BegonePOL", otpField != nullptr ? "Password and one-time password entered; pressing Login." : "Password entered; pressing Login.");
        g_Pol.connAction(conn + ConnListenerOffset, evt);
        Finish(State::Done);
    }

    // Number of PlayOnline members, or -1 if unknown.
    static int32_t MemberCount(void)
    {
        const auto store = g_Pol.memberStore ? *g_Pol.memberStore : nullptr;
        return store != nullptr ? *reinterpret_cast<int32_t*>(store + g_Pol.memberCount) : -1;
    }

    // Stop, show PlayOnline again and tell the user what to do there.
    void FailPrompt(const char* why, const wchar_t* text)
    {
        Fail(why);
        const auto copy = ::_wcsdup(text);
        const auto t    = ::CreateThread(nullptr, 0, [](LPVOID p) -> DWORD {
            ::MessageBoxW(nullptr, static_cast<wchar_t*>(p), L"BegonePOL", MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
            ::free(p);
            return 0;
        }, copy, 0, nullptr);
        if (t != nullptr)
            ::CloseHandle(t);
        else
            ::free(copy);
    }

    void Fail(const char* why)
    {
        g_Log->Log(2, "BegonePOL", why);
        Finish(State::Failed);
    }

    void Finish(State s)
    {
        m_DoneAt = ::GetTickCount();
        m_State  = s;
        ::SecureZeroMemory(&m_Password, sizeof(m_Password));
        ::SecureZeroMemory(m_Plain, sizeof(m_Plain));
        ::SecureZeroMemory(m_TotpKey, sizeof(m_TotpKey));
        m_AskingCode = false;
        Unsubclass();
    }

    static inline BegonePOL* s_Self = nullptr;

    std::string m_Account;
    int32_t m_Slot = 0;
    int32_t m_TestMembers = -1; // dry runs only: pretend PlayOnline has this many members
    enum class Otp { Off, Manual, Auto };
    Otp m_Otp = Otp::Off;
    char m_TotpKey[128]{};
    bool m_AskingCode = false;
    bool m_OtpChecked = false;
    Scrambled m_Password;
    char m_Plain[64]{};
    bool m_Dump = false;
    bool m_Trace = false;
    bool m_Show  = false;
    bool m_OpenSetup = false; // Credential Manager only: open the setup window before logging in
    bool m_WinCred   = false; // use Credential Manager even under Wine on Linux
    platform::Info m_Platform;
    HWND m_HiddenHwnd      = nullptr;
    Splash m_Splash;
    DWORD m_Loaded         = 0;
    HHOOK m_Cbts[64]{};
    int m_CbtCount         = 0;
    bool m_CbtCaught       = false;
    int m_CbtSeen          = 0;
    HWINEVENTHOOK m_WinEvent = nullptr;
    const char* volatile m_CaughtBy = nullptr;
    bool m_CaughtLogged    = false;
    bool m_WantSplash      = true;
    bool m_DryRun          = false;
    bool m_AskCodeTest     = false;
    bool m_Quick           = true;  // skip PlayOnline's main menu and start FFXI right after the login
    bool m_QuickOn         = false;
    bool m_FadesDone       = false;
    bool m_LogoDone        = false;
    bool m_ProbeDone       = false; // trace: pol.exe's COM error function hooked (or given up)
    bool m_SkipLogo        = true; // off with arg "logowait", or after a failed FFXI start (marker file)
    bool m_Prof            = false;
    DWORD m_ProfStart      = 0;
    DWORD m_ProfLast       = 0;
    bool m_RealConnect     = false;
    DWORD m_LastPollLog    = 0;
    LONG m_OldExStyle      = 0;
    DWORD m_DoneAt         = 0;

    volatile State m_State = State::Waiting;
    volatile bool m_Stop   = false;
    HANDLE m_Thread        = nullptr;
    HWND m_Hwnd            = nullptr;
    WNDPROC m_OldProc      = nullptr;
    DWORD m_WindowSeen     = 0;
    DWORD m_Started        = 0;
    DWORD m_LastAction     = 0;
    DWORD m_LastTrace      = 0;
    DWORD m_ScreenSeen     = 0;
    uint8_t* m_Screen      = nullptr;
    int m_Backs            = 0;
    int m_Selects          = 0;
    int m_LogIns           = 0;
};

extern "C" double __stdcall expGetInterfaceVersion(void)
{
    return ASHITA_INTERFACE_VERSION;
}

extern "C" IPolPlugin* __stdcall expCreatePolPlugin(const char* args)
{
    return new BegonePOL(args);
}

extern "C" void __stdcall expDestroyPlugin(void* instance)
{
    delete static_cast<BegonePOL*>(instance);
}
