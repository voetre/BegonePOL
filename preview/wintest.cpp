// Test harness for the Windows-only parts: platform detection, Credential Manager and the setup window.
//   wintest.exe detect | list | save <slot> <account> <otp> | forget <slot> | setup [slot]
// "save" uses a dummy password; nothing real is stored. Never prints secrets, only their lengths.
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../src/platform.h"
#include "../src/winlogin.h"

// "setup-drive": fill the setup window from a second thread and press Save, like a user would.
static const char* g_Account = "";
static const char* g_Password = "";
static DWORD __stdcall Drive(LPVOID)
{
    HWND w = nullptr;
    for (int i = 0; i < 100 && w == nullptr; i++, ::Sleep(50))
        w = ::FindWindowW(L"BegonePOLSetup", nullptr);
    ::Sleep(300);
    if (*g_Account != 0)
        ::SetDlgItemTextA(w, 11, g_Account);
    ::SetDlgItemTextA(w, 12, g_Password);
    ::SendMessageW(::GetDlgItem(w, 17), BM_CLICK, 0, 0);
    ::Sleep(300);
    if (::IsWindow(w))
    {
        char err[256]{};
        // the error label is the last STATIC before the buttons; find it by walking the children
        for (auto c = ::GetWindow(w, GW_CHILD); c != nullptr; c = ::GetWindow(c, GW_HWNDNEXT))
        {
            char cls[32]{}, text[256]{};
            ::GetClassNameA(c, cls, 32);
            ::GetWindowTextA(c, text, 256);
            if (::_stricmp(cls, "Static") == 0 && (std::strstr(text, "Enter") == text || std::strstr(text, "PlayOnline only") == text || std::strstr(text, "Couldn't") == text || std::strstr(text, "Pick") == text))
                ::strcpy_s(err, text);
        }
        std::printf("still open, error: %s\n", err);
        ::PostMessageW(w, WM_CLOSE, 0, 0);
    }
    return 0;
}

int main(int argc, char** argv)
{
    const char* cmd = argc > 1 ? argv[1] : "detect";
    if (std::strcmp(cmd, "detect") == 0)
    {
        const auto i = platform::Detect(argc > 2 ? std::atoi(argv[2]) : 0);
        std::printf("kind=%s host=%s why=%s\n", platform::Name(i.kind), i.host, i.why);
    }
    else if (std::strcmp(cmd, "list") == 0)
    {
        auto all = winlogin::List();
        for (const auto& l : all)
            std::printf("slot=%d account=%s otp=%s passwordlen=%zu totplen=%zu\n", l.slot, l.account.c_str(), l.otp.c_str(), std::strlen(l.password), std::strlen(l.totp));
        std::printf("%zu saved\n", all.size());
        winlogin::WipeAll(all);
    }
    else if (std::strcmp(cmd, "save") == 0 && argc >= 5)
    {
        winlogin::Login l;
        l.slot    = std::atoi(argv[2]);
        l.account = argv[3];
        l.otp     = argv[4];
        ::strcpy_s(l.password, "dummy-pass");
        ::strcpy_s(l.totp, "JBSWY3DPEHPK3PXP");
        std::printf("save=%d\n", winlogin::Save(l));
    }
    else if (std::strcmp(cmd, "forget") == 0 && argc >= 3)
        std::printf("forget=%d\n", winlogin::Forget(std::atoi(argv[2])));
    else if (std::strcmp(cmd, "setup") == 0 || std::strcmp(cmd, "setup-drive") == 0)
    {
        if (cmd[5] != 0)
        {
            g_Account  = argc > 3 ? argv[3] : "";
            g_Password = argc > 4 ? argv[4] : "";
            ::CreateThread(nullptr, 0, Drive, nullptr, 0, nullptr);
        }
        auto all = winlogin::List();
        winlogin::Login out;
        winlogin::Setup s;
        const auto ok = s.Run(all, argc > 2 ? std::atoi(argv[2]) : 0, true, out);
        std::printf("setup=%d slot=%d account=%s otp=%s passwordlen=%zu totplen=%zu\n", ok, out.slot, out.account.c_str(), out.otp.c_str(), std::strlen(out.password), std::strlen(out.totp));
        out.Wipe();
        winlogin::WipeAll(all);
    }
    return 0;
}
