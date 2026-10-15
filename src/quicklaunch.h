/**
 * Quick launch: skip PlayOnline's main menu and go straight into FINAL FANTASY XI after the login.
 *
 * Same idea as Ashita's quicky plugin (written from scratch here, no quicky code):
 *  - After the Square Enix login, PlayOnline fetches its main menu page (PML, PlayOnline's HTML) from
 *    the content server on port 51304. Connections to that port are tracked, nothing is sent on them,
 *    and the reply is a one-line page whose onopen handler is "gameto:1", i.e. start FINAL FANTASY XI.
 *  - select / __WSAFDIsSet report those sockets ready straight away, so PlayOnline never waits on them.
 *  - Two short fade loops in app.dll's hand-off to the game (30 and 12 frames of 16 ms) are skipped.
 *
 * Beyond quicky: the content-server connect is never made (PlayOnline just sees a connect that is "in
 * progress" and then ready), which saves a round trip to Japan, and the sockets read as ready on the first
 * select instead of the third.
 *
 * Included into begonepol.cpp's anonymous namespace (uses g_Log, Find).
 */

#pragma comment(lib, "ws2_32.lib")

namespace quick
{
    constexpr uint16_t ContentPort = 51304;

    constexpr char Page[] = "<pml><head><meta http-equiv=\"Content-Type\" content=\"text/x-playonline-pml;charset=UTF-8\">"
                            "<define name=\"$GAME_ID\" value=\"1\"></head><body onopen=\"eval:'gameto:'+$GAME_ID\"></body></pml>";

    struct Tracked
    {
        SOCKET s;
        fd_set* except; // last exceptfds PlayOnline passed for this socket; it never gets an error
        bool replied;
    };

    Tracked g_Socks[16]{};
    SRWLOCK g_Lock = SRWLOCK_INIT;
    bool g_Trace   = false;
    volatile bool g_MenuSkipped = false; // the content request was answered; FFXI is being started
    bool g_Connect = false; // really connect to the content server (like quicky) instead of faking it
    DWORD g_Since  = 0;
    volatile long g_IoLogs = 0;
    bool g_LogoSkipped = false;      // the logo wait was skipped this run
    char g_LogoMarker[MAX_PATH] = ""; // created when FFXI fails to start after a skip: next run keeps the wait // trace: send/recv lines logged after the menu skip (capped)

    Tracked* Lookup(SOCKET s)
    {
        for (auto& t : g_Socks)
            if (t.s == s && s != 0)
                return &t;
        return nullptr;
    }

    // ---- minimal inline hooks ----------------------------------------------------------------------

    // Length of one instruction, for the handful of opcodes that start Wine's ws2_32 exports
    // (push reg, mov reg/reg, mov reg/[ebp+d8], sub esp, mov reg/imm32, lea, test [abs], ...).
    // Returns 0 for anything else so an unexpected prologue makes the hook bail out instead of guessing.
    size_t InsnLen(const uint8_t* p)
    {
        const auto modrm = [](const uint8_t* m) -> size_t {
            const auto mod = m[0] >> 6, rm = m[0] & 7;
            size_t n       = 1;
            if (mod != 3 && rm == 4)
                n++;
            if (mod == 1)
                n += 1;
            else if (mod == 2 || (mod == 0 && rm == 5))
                n += 4;
            return n;
        };
        const auto op = p[0];
        if (op >= 0x50 && op <= 0x5F)
            return 1;
        if (op >= 0xB8 && op <= 0xBF)
            return 5;
        switch (op)
        {
            case 0x6A:
                return 2;
            case 0x68:
                return 5;
            case 0x89:
            case 0x8B:
            case 0x8D:
            case 0x31:
            case 0x33:
            case 0x85:
                return 1 + modrm(p + 1);
            case 0x83:
                return 1 + modrm(p + 1) + 1;
            case 0x81:
                return 1 + modrm(p + 1) + 4;
            case 0xF6:
                return (p[1] & 0x38) == 0 ? 1 + modrm(p + 1) + 1 : 0;
            case 0xFF:
                return (p[1] & 0x38) == 0x30 ? 1 + modrm(p + 1) : 0; // push r/m
            default:
                return 0;
        }
    }

    struct Hook
    {
        uint8_t* target = nullptr;
        uint8_t saved[16]{};
        size_t len = 0;
    };

    Hook g_Hooks[8];
    int g_HookCount = 0;
    uint8_t* g_Trampolines = nullptr;

    // Overwrites the start of target with a jump to detour; *original gets a trampoline to the real code.
    template<typename T>
    bool Install(uint8_t* target, T detour, T* original)
    {
        if (target == nullptr || g_HookCount >= static_cast<int>(std::size(g_Hooks)))
            return false;
        // Wine marks some exports as hot-patchable (mov edi, edi); skip nothing, the decoder handles 8B FF.
        size_t len = 0;
        while (len < 5)
        {
            const auto n = InsnLen(target + len);
            if (n == 0)
                return false;
            len += n;
        }
        if (g_Trampolines == nullptr)
            g_Trampolines = static_cast<uint8_t*>(::VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (g_Trampolines == nullptr)
            return false;
        auto tramp = g_Trampolines + g_HookCount * 32;
        std::memcpy(tramp, target, len);
        tramp[len] = 0xE9;
        *reinterpret_cast<int32_t*>(tramp + len + 1) = static_cast<int32_t>(target + len - (tramp + len + 5));
        ::FlushInstructionCache(::GetCurrentProcess(), tramp, len + 5);

        auto& h  = g_Hooks[g_HookCount];
        h.target = target;
        h.len    = len;
        std::memcpy(h.saved, target, len);

        DWORD old = 0;
        if (!::VirtualProtect(target, len, PAGE_EXECUTE_READWRITE, &old))
            return false;
        *original = reinterpret_cast<T>(tramp);
        uint8_t patch[16];
        std::memset(patch, 0x90, sizeof(patch));
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(patch + 1) = static_cast<int32_t>(reinterpret_cast<uint8_t*>(detour) - (target + 5));
        std::memcpy(target, patch, len);
        ::VirtualProtect(target, len, old, &old);
        ::FlushInstructionCache(::GetCurrentProcess(), target, len);
        g_HookCount++;
        return true;
    }

    // ---- ws2_32 detours ----------------------------------------------------------------------------

    using connect_t     = int(WSAAPI*)(SOCKET, const sockaddr*, int);
    using send_t        = int(WSAAPI*)(SOCKET, const char*, int, int);
    using recv_t        = int(WSAAPI*)(SOCKET, char*, int, int);
    using select_t      = int(WSAAPI*)(int, fd_set*, fd_set*, fd_set*, const timeval*);
    using closesocket_t = int(WSAAPI*)(SOCKET);
    using isset_t       = int(WSAAPI*)(SOCKET, fd_set*);

    connect_t Real_connect         = nullptr;
    send_t Real_send               = nullptr;
    recv_t Real_recv               = nullptr;
    select_t Real_select           = nullptr;
    closesocket_t Real_closesocket = nullptr;
    isset_t Real_isset             = nullptr;

    int WSAAPI My_connect(SOCKET s, const sockaddr* addr, int len)
    {
        uint16_t port = 0;
        char host[64] = "?";
        if (addr != nullptr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6))
        {
            port = ntohs(reinterpret_cast<const sockaddr_in*>(addr)->sin_port); // same offset for v6
            if (g_Trace)
                ::inet_ntop(addr->sa_family, addr->sa_family == AF_INET ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(addr)->sin_addr)
                                                                        : static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr),
                    host, sizeof(host));
        }
        if (g_Trace)
            g_Log->Logf(5, "BegonePOL", "net: connect %s:%u socket %u (+%lums)", host, port, static_cast<unsigned>(s), ::GetTickCount() - g_Since);
        if (port != ContentPort)
            return Real_connect(s, addr, len);

        ::AcquireSRWLockExclusive(&g_Lock);
        for (auto& t : g_Socks)
            if (t.s == 0)
            {
                t = { s, nullptr, false };
                break;
            }
        ::ReleaseSRWLockExclusive(&g_Lock);
        g_Log->Log(4, "BegonePOL", "Skipping the PlayOnline menu; starting FINAL FANTASY XI.");
        g_MenuSkipped = true;
        if (g_Connect)
            return Real_connect(s, addr, len);
        // Don't connect at all: behave like a non-blocking connect that's under way. The socket is then
        // reported writable by select, which is all PlayOnline waits for before it "sends" its request.
        ::WSASetLastError(WSAEWOULDBLOCK);
        return SOCKET_ERROR;
    }

    int WSAAPI My_send(SOCKET s, const char* buf, int len, int flags)
    {
        ::AcquireSRWLockShared(&g_Lock);
        const auto t = Lookup(s);
        ::ReleaseSRWLockShared(&g_Lock);
        if (t == nullptr)
        {
            const auto r = Real_send(s, buf, len, flags);
            if (g_Trace && g_MenuSkipped && g_IoLogs < 40)
            {
                g_IoLogs++;
                g_Log->Logf(5, "BegonePOL", "net: send %d bytes on socket %u -> %d (+%lums)", len, static_cast<unsigned>(s), r, ::GetTickCount() - g_Since);
            }
            return r;
        }
        if (g_Trace && buf != nullptr && len > 0)
        {
            // Request line only, without the query string (it can carry session data).
            int n = 0;
            while (n < len && n < 80 && buf[n] != '\r' && buf[n] != '\n' && buf[n] != '?')
                n++;
            g_Log->Logf(5, "BegonePOL", "net: content request '%.*s' (+%lums)", n, buf, ::GetTickCount() - g_Since);
        }
        return len;
    }

    int WSAAPI My_recv(SOCKET s, char* buf, int len, int flags)
    {
        ::AcquireSRWLockShared(&g_Lock);
        const auto t = Lookup(s);
        ::ReleaseSRWLockShared(&g_Lock);
        if (t == nullptr)
        {
            const auto r = Real_recv(s, buf, len, flags);
            if (g_Trace && g_MenuSkipped && g_IoLogs < 40)
            {
                g_IoLogs++;
                g_Log->Logf(5, "BegonePOL", "net: recv on socket %u -> %d (+%lums)", static_cast<unsigned>(s), r, ::GetTickCount() - g_Since);
            }
            return r;
        }

        char reply[1024];
        const auto n = std::snprintf(reply, sizeof(reply),
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache\r\n"
            "X-PlayOnline-Hello: BegonePOL\r\n"
            "Authentication-Info: rspauth=\"426567696e6f6e504f4c3a736b697021\"\r\n"
            "Content-Length: %u\r\n"
            "Keep-Alive: timeout=15, max=99\r\n"
            "Connection: Keep-Alive\r\n"
            "Content-Type: text/x-playonline-pml\r\n"
            "\r\n%s",
            static_cast<unsigned>(sizeof(Page) - 1), Page);
        if (n <= 0 || n >= len)
        {
            ::WSASetLastError(WSAEMSGSIZE);
            return SOCKET_ERROR;
        }
        std::memcpy(buf, reply, n);
        if (g_Trace)
            g_Log->Logf(5, "BegonePOL", "net: served the launch page (+%lums)", ::GetTickCount() - g_Since);
        t->replied = true;
        return n;
    }

    int WSAAPI My_select(int nfds, fd_set* r, fd_set* w, fd_set* e, const timeval* timeout)
    {
        // PlayOnline passes socket + 1 as nfds when it waits on one socket.
        ::AcquireSRWLockShared(&g_Lock);
        const auto t = Lookup(static_cast<SOCKET>(nfds - 1));
        ::ReleaseSRWLockShared(&g_Lock);
        if (t == nullptr)
            return Real_select(nfds, r, w, e, timeout);
        t->except = e;
        // Ready for whatever it asks (write after connect, read after the request); never an error.
        return (r != nullptr || w != nullptr) ? 1 : 0;
    }

    int WSAAPI My_isset(SOCKET s, fd_set* set)
    {
        ::AcquireSRWLockShared(&g_Lock);
        const auto t = Lookup(s);
        ::ReleaseSRWLockShared(&g_Lock);
        if (t == nullptr)
            return Real_isset(s, set);
        return set != t->except;
    }

    int WSAAPI My_closesocket(SOCKET s)
    {
        ::AcquireSRWLockExclusive(&g_Lock);
        if (const auto t = Lookup(s))
            *t = {};
        ::ReleaseSRWLockExclusive(&g_Lock);
        return Real_closesocket(s);
    }

    // ---- diagnostics: DLL loads during the hand-off to FFXI ----------------------------------------

    struct Ustr
    {
        USHORT Length, MaximumLength;
        PWSTR Buffer;
    };

    struct DllNotifyData
    {
        ULONG flags;
        const Ustr* fullName;
        const Ustr* baseName;
        void* base;
        ULONG size;
    };
    using DllNotify_t   = VOID(CALLBACK*)(ULONG, const DllNotifyData*, PVOID);
    using LdrRegister_t = LONG(NTAPI*)(ULONG, DllNotify_t, PVOID, PVOID*);
    void* g_DllCookie   = nullptr;

    VOID CALLBACK OnDll(ULONG reason, const DllNotifyData* d, PVOID)
    {
        if (!g_MenuSkipped || d == nullptr || d->baseName == nullptr)
            return;
        g_Log->Logf(5, "BegonePOL", "diag: %s %.*ls (+%lums)", reason == 1 ? "loaded" : "unloaded",
            static_cast<int>(d->baseName->Length / 2), d->baseName->Buffer, ::GetTickCount() - g_Since);
    }

    void WatchDlls(void)
    {
        const auto reg = reinterpret_cast<LdrRegister_t>(::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "LdrRegisterDllNotification"));
        if (reg == nullptr || reg(0, &OnDll, nullptr, &g_DllCookie) != 0)
            g_Log->Log(2, "BegonePOL", "diag: could not watch DLL loads.");
    }

    void UnwatchDlls(void)
    {
        using LdrUnregister_t = LONG(NTAPI*)(PVOID);
        if (g_DllCookie == nullptr)
            return;
        if (const auto un = reinterpret_cast<LdrUnregister_t>(::GetProcAddress(::GetModuleHandleA("ntdll.dll"), "LdrUnregisterDllNotification")))
            un(g_DllCookie);
        g_DllCookie = nullptr;
    }

    bool Enable(bool trace, bool realConnect)
    {
        g_Trace   = trace;
        g_Connect = realConnect;
        g_Since = ::GetTickCount();
        const auto ws = ::LoadLibraryA("ws2_32.dll");
        const auto get = [&](const char* name) { return reinterpret_cast<uint8_t*>(::GetProcAddress(ws, name)); };
        const auto ok = Install(get("connect"), &My_connect, &Real_connect)
            && Install(get("send"), &My_send, &Real_send)
            && Install(get("recv"), &My_recv, &Real_recv)
            && Install(get("select"), &My_select, &Real_select)
            && Install(get("__WSAFDIsSet"), &My_isset, &Real_isset)
            && Install(get("closesocket"), &My_closesocket, &Real_closesocket);
        if (trace)
            WatchDlls();
        if (!ok)
            g_Log->Logf(2, "BegonePOL", "Could not hook ws2_32 (%d of 6); PlayOnline's menu will show as usual.", g_HookCount);
        return ok;
    }

    void Disable(void)
    {
        UnwatchDlls();
        for (int x = g_HookCount - 1; x >= 0; x--)
        {
            auto& h   = g_Hooks[x];
            DWORD old = 0;
            if (::VirtualProtect(h.target, h.len, PAGE_EXECUTE_READWRITE, &old))
            {
                std::memcpy(h.target, h.saved, h.len);
                ::VirtualProtect(h.target, h.len, old, &old);
                ::FlushInstructionCache(::GetCurrentProcess(), h.target, h.len);
            }
        }
        g_HookCount = 0;
        // The trampolines stay allocated: another thread may still be inside one.
    }

    // ---- diagnostics: pol.exe's _com_issue_error ---------------------------------------------------

    // pol.exe turns every failed COM call into a _com_error through one small function
    // (mov eax, [esp+4]; push 0; push eax; call [raise]; ret 4). With trace or the logo skip on, it's hooked so the log
    // shows which call failed (HRESULT and the addresses it was called from) before PlayOnline's
    // "Unknown error 0x..." box comes up.
    using issue_t   = void(__stdcall*)(HRESULT);
    issue_t Real_issue = nullptr;

    void __stdcall My_issue(HRESULT hr)
    {
        void* frames[8]{};
        const auto n = ::RtlCaptureStackBackTrace(1, 8, frames, nullptr);
        char where[160] = "";
        for (USHORT i = 0, len = 0; i < n && len < sizeof(where) - 12; i++)
            len += static_cast<USHORT>(std::snprintf(where + len, sizeof(where) - len, " %p", frames[i]));
        g_Log->Logf(2, "BegonePOL", "diag: COM call failed with 0x%08lX (+%lums), called from%s", static_cast<unsigned long>(hr), ::GetTickCount() - g_Since, where);
        if (g_LogoSkipped && g_MenuSkipped && g_LogoMarker[0] != 0)
        {
            const auto f = ::CreateFileA(g_LogoMarker, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (f != INVALID_HANDLE_VALUE)
                ::CloseHandle(f);
            g_Log->Logf(2, "BegonePOL", "FINAL FANTASY XI failed to start after the logo wait was skipped; the next launches keep the wait (delete %s to try the skip again).", g_LogoMarker);
        }
        Real_issue(hr);
    }

    // pol.exe is packed, so this only finds the function once it's unpacked; true when hooked.
    bool ProbeComErrors(uint8_t* begin, uint8_t* end)
    {
        const auto a = Find(begin, end, { 0x8B, 0x44, 0x24, 0x04, 0x6A, 0x00, 0x50, 0xFF, 0x15, -1, -1, -1, -1, 0xC2, 0x04, 0x00 });
        if (a == nullptr || !Install(a, &My_issue, &Real_issue))
            return false;
        if (g_Trace)
            g_Log->Logf(5, "BegonePOL", "diag: COM error probe on %p.", a);
        return true;
    }

    // app.dll's hand-off to the game: "if (window shown) for (i < 30) { draw; Sleep(16); }" and the same
    // for 12 frames when it's the foreground window. Turn both conditional jumps into plain jumps.
    int SkipFades(uint8_t* begin, uint8_t* end)
    {
        int done = 0;
        const auto patch = [&](uint8_t* at) {
            if (at == nullptr || (*at != 0x74 && *at != 0xEB))
                return;
            DWORD old = 0;
            if (*at == 0x74 && ::VirtualProtect(at, 1, PAGE_EXECUTE_READWRITE, &old))
            {
                *at = 0xEB;
                ::VirtualProtect(at, 1, old, &old);
                ::FlushInstructionCache(::GetCurrentProcess(), at, 1);
            }
            done++;
        };
        // test eax, eax; je +20; and [ebp-14], 0; cmp [ebp-14], 30; jge +16
        if (const auto a = Find(begin, end, { 0x85, 0xC0, -1, 0x20, 0x83, 0x65, 0xEC, 0x00, 0x83, 0x7D, 0xEC, 0x1E, 0x7D, 0x16 }))
            patch(a + 2);
        // cmp [edi+4], eax; je +20; and [ebp-14], 0; cmp [ebp-14], 12; jge +16
        if (const auto b = Find(begin, end, { 0x39, 0x47, 0x04, -1, 0x20, 0x83, 0x65, 0xEC, 0x00, 0x83, 0x7D, 0xEC, 0x0C, 0x7D, 0x16 }))
            patch(b + 3);
        return done;
    }

    /**
     * pol.exe keeps its PlayOnline logo dialog up for at least 5 seconds before it shows the main
     * window, sleeping in 100ms steps while it waits (most of the time between start-up and the
     * member list). Make the minimum 0 so the logo goes as soon as start-up is done.
     * Returns how many of the two 5000ms compares are patched (2 = done).
     */
    int SkipLogo(uint8_t* begin, uint8_t* end)
    {
        int done = 0;
        const auto patch = [&](uint8_t* at) {
            if (at == nullptr)
                return;
            static const uint8_t ms5000[4] = { 0x88, 0x13, 0x00, 0x00 };
            if (std::memcmp(at, ms5000, 4) == 0)
            {
                DWORD old = 0;
                if (!::VirtualProtect(at, 4, PAGE_EXECUTE_READWRITE, &old))
                    return;
                std::memset(at, 0, 4);
                ::VirtualProtect(at, 4, old, &old);
                ::FlushInstructionCache(::GetCurrentProcess(), at, 4);
            }
            if (std::memcmp(at, "\0\0\0\0", 4) == 0)
                done++;
        };
        // push 5; call now; sub eax, [shown]; sbb edx, [shown+4]; test edx, edx; jg; jl; cmp eax, 5000
        if (const auto a = Find(begin, end, { 0x6A, 0x05, 0xE8, -1, -1, -1, -1, 0x2B, 0x05, -1, -1, -1, -1, 0x1B, 0x15, -1, -1, -1, -1, 0x85, 0xD2, 0x7F, -1, 0x7C, -1, 0x3D }))
            patch(a + 26);
        // mov [esp+8], edx; js; jg; cmp eax, 5000; jb (the loop after each 100ms sleep)
        if (const auto b = Find(begin, end, { 0x89, 0x54, 0x24, 0x08, 0x78, -1, 0x7F, -1, 0x3D, -1, -1, 0x00, 0x00, 0x72 }))
            patch(b + 9);
        return done;
    }
}
