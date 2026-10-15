#pragma once

/**
 * Which system the plugin is really running on: Windows itself, or Wine/Proton on Linux (or another
 * host). Wine can be set up to look like Windows (a Windows version in winecfg, Wine Staging's
 * HideWineExports, a Z: drive that happens to exist on Windows too), so no single sign decides it:
 * any one of several independent Wine traces counts, and the host is then read from Wine's host
 * version or the host's own files through Wine's Z: drive.
 */

#include <cstring>
#include <initializer_list>

namespace platform
{
    enum class Kind { Windows, WineLinux, WineOther };

    struct Info
    {
        Kind kind = Kind::Windows;
        char why[96]{};  // the first Wine sign found, for the log
        char host[64]{}; // host system name, when Wine
    };

    namespace detail
    {
        inline bool KeyExists(HKEY root, const wchar_t* path)
        {
            HKEY key = nullptr;
            if (::RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
                return false;
            ::RegCloseKey(key);
            return true;
        }

        inline bool FileExists(const char* path)
        {
            return ::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
        }
    }

    // skip (tests only): ignore some signs, as if Wine hid them; 1 exports, 2 registry, 4 loaded drivers, 8 files.
    inline Info Detect(int skip = 0)
    {
        Info info;
        const auto ntdll = (skip & 1) != 0 ? nullptr : ::GetModuleHandleW(L"ntdll.dll");
        using HostVersion = void(__cdecl*)(const char** sysname, const char** release);
        const auto hostVersion = ntdll != nullptr ? reinterpret_cast<HostVersion>(::GetProcAddress(ntdll, "wine_get_host_version")) : nullptr;

        // Wine traces, strongest first. Windows has none of these: the exports and drivers only exist
        // in Wine, and the registry keys are written by wineboot into every prefix.
        const char* why = nullptr;
        if (ntdll != nullptr && (::GetProcAddress(ntdll, "wine_get_version") != nullptr || hostVersion != nullptr))
            why = "ntdll exports wine_get_version";
        else if (ntdll != nullptr && ::GetProcAddress(ntdll, "__wine_dbg_output") != nullptr)
            why = "ntdll exports __wine_dbg_output";
        else if ((skip & 2) == 0 && (detail::KeyExists(HKEY_CURRENT_USER, L"Software\\Wine") || detail::KeyExists(HKEY_LOCAL_MACHINE, L"Software\\Wine")))
            why = "Software\\Wine registry key";
        else if ((skip & 4) == 0 && (::GetModuleHandleW(L"winex11.drv") != nullptr || ::GetModuleHandleW(L"winewayland.drv") != nullptr || ::GetModuleHandleW(L"winemac.drv") != nullptr))
            why = "Wine display driver loaded";
        else if ((skip & 8) == 0)
        {
            char sys[MAX_PATH]{};
            ::GetSystemDirectoryA(sys, MAX_PATH);
            for (const auto f : { "\\winex11.drv", "\\winewayland.drv", "\\winemac.drv", "\\winebus.sys", "\\wineboot.exe" })
            {
                char p[MAX_PATH + 32];
                ::strcpy_s(p, sys);
                ::strcat_s(p, f);
                if (detail::FileExists(p))
                {
                    why = "Wine system files present";
                    break;
                }
            }
        }
        if (why == nullptr)
            return info; // Windows

        ::strncpy_s(info.why, why, _TRUNCATE);

        // Which host: Wine says so directly unless its exports are hidden; otherwise look at the host's
        // own files through the Z: drive Wine maps to its root (a Windows Z: drive won't have these).
        const char* sysname = nullptr;
        if (hostVersion != nullptr)
        {
            const char* release = nullptr;
            hostVersion(&sysname, &release);
        }
        if (sysname == nullptr || *sysname == 0)
        {
            if (detail::FileExists("Z:\\proc\\self\\status") || detail::FileExists("Z:\\proc\\version"))
                sysname = "Linux";
            else if (detail::FileExists("Z:\\System\\Library\\CoreServices\\SystemVersion.plist"))
                sysname = "Darwin";
            else if (detail::FileExists("Z:\\etc\\os-release"))
                sysname = "Linux";
        }
        ::strncpy_s(info.host, sysname != nullptr ? sysname : "unknown", _TRUNCATE);
        info.kind = std::strcmp(info.host, "Linux") == 0 ? Kind::WineLinux : Kind::WineOther;
        return info;
    }

    inline const char* Name(Kind k)
    {
        switch (k)
        {
        case Kind::Windows:   return "Windows";
        case Kind::WineLinux: return "Wine/Proton on Linux";
        default:              return "Wine";
        }
    }
}
