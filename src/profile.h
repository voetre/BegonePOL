/**
 * Trace-only: where does PlayOnline sleep? Swaps app.dll / polcore.dll / pol.exe import slots for
 * Sleep and SleepEx with wrappers that add up the time per call site, logged once a second.
 * Included into begonepol.cpp's anonymous namespace.
 */
#include <intrin.h>

namespace prof
{
    using Sleep_t   = void(WINAPI*)(DWORD);
    using SleepEx_t = DWORD(WINAPI*)(DWORD, BOOL);

    struct Site
    {
        uintptr_t ret;
        DWORD ms, calls;
    };
    Site g_Sites[128]{};
    SRWLOCK g_Lock      = SRWLOCK_INIT;
    Sleep_t g_Sleep     = nullptr;
    SleepEx_t g_SleepEx = nullptr;

    void Add(uintptr_t ret, DWORD ms)
    {
        ::AcquireSRWLockExclusive(&g_Lock);
        for (auto& s : g_Sites)
            if (s.ret == ret || s.ret == 0)
            {
                s.ret = ret;
                s.ms += ms;
                s.calls++;
                break;
            }
        ::ReleaseSRWLockExclusive(&g_Lock);
    }

    void WINAPI MySleep(DWORD ms)
    {
        const auto t = ::GetTickCount();
        g_Sleep(ms);
        Add(reinterpret_cast<uintptr_t>(_ReturnAddress()), ::GetTickCount() - t);
    }

    DWORD WINAPI MySleepEx(DWORD ms, BOOL alertable)
    {
        const auto t = ::GetTickCount();
        const auto r = g_SleepEx(ms, alertable);
        Add(reinterpret_cast<uintptr_t>(_ReturnAddress()), ::GetTickCount() - t);
        return r;
    }

    int Patch(const char* module)
    {
        const auto base = reinterpret_cast<uint8_t*>(::GetModuleHandleA(module));
        if (base == nullptr)
            return 0;
        const auto nt = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + reinterpret_cast<IMAGE_DOS_HEADER*>(base)->e_lfanew);
        const auto end = base + nt->OptionalHeader.SizeOfImage;
        const uintptr_t targets[] = {
            reinterpret_cast<uintptr_t>(::GetProcAddress(::GetModuleHandleA("kernel32.dll"), "Sleep")),
            reinterpret_cast<uintptr_t>(::GetProcAddress(::GetModuleHandleA("kernelbase.dll"), "Sleep")),
            reinterpret_cast<uintptr_t>(::GetProcAddress(::GetModuleHandleA("kernel32.dll"), "SleepEx")),
            reinterpret_cast<uintptr_t>(::GetProcAddress(::GetModuleHandleA("kernelbase.dll"), "SleepEx")),
        };
        if (g_Sleep == nullptr)
        {
            g_Sleep   = reinterpret_cast<Sleep_t>(targets[0]);
            g_SleepEx = reinterpret_cast<SleepEx_t>(targets[2]);
        }
        int n = 0;
        for (auto p = base; p + 4 <= end; p += 0x1000)
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (::VirtualQuery(p, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
                continue;
            // Only data pages: import slots, not code.
            if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
                continue;
            for (auto q = reinterpret_cast<uintptr_t*>(p); q < reinterpret_cast<uintptr_t*>(p + 0x1000); q++)
                for (int x = 0; x < 4; x++)
                    if (targets[x] != 0 && *q == targets[x])
                    {
                        DWORD old = 0;
                        if (::VirtualProtect(q, 4, PAGE_READWRITE, &old))
                        {
                            *q = x < 2 ? reinterpret_cast<uintptr_t>(&MySleep) : reinterpret_cast<uintptr_t>(&MySleepEx);
                            ::VirtualProtect(q, 4, old, &old);
                            n++;
                        }
                    }
        }
        return n;
    }

    // Log call sites that slept 50ms or more since the last report, as module+rva.
    void Report(DWORD since)
    {
        Site copy[std::size(g_Sites)];
        ::AcquireSRWLockExclusive(&g_Lock);
        std::memcpy(copy, g_Sites, sizeof(copy));
        std::memset(g_Sites, 0, sizeof(g_Sites));
        ::ReleaseSRWLockExclusive(&g_Lock);
        for (const auto& s : copy)
        {
            if (s.ret == 0 || s.ms < 50)
                continue;
            HMODULE mod = nullptr;
            char name[MAX_PATH] = "?";
            ::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, reinterpret_cast<LPCSTR>(s.ret), &mod);
            if (mod != nullptr)
                ::GetModuleFileNameA(mod, name, sizeof(name));
            const auto slash = std::strrchr(name, '\\');
            g_Log->Logf(5, "BegonePOL", "prof: +%lums %s+%X slept %lums in %lu calls", ::GetTickCount() - since, slash ? slash + 1 : name,
                static_cast<unsigned>(s.ret - reinterpret_cast<uintptr_t>(mod)), s.ms, s.calls);
        }
    }
}
