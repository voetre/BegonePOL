#pragma once

#include "xiart.h"

#pragma comment(lib, "advapi32.lib")

// Small self-contained splash window shown while PlayOnline logs in behind it.
class Splash
{
public:
    void Open(void)
    {
        m_Thread = ::CreateThread(nullptr, 0, ThreadMain, this, 0, nullptr);
    }

    // Status line under the title. With timed, the seconds spent on this step are shown after it
    // (for the steps that wait on servers).
    void SetStatus(const wchar_t* status, bool timed = false)
    {
        ::AcquireSRWLockExclusive(&m_Lock);
        if (std::wcscmp(m_Status, status) != 0)
        {
            ::wcsncpy_s(m_Status, status, _TRUNCATE);
            m_Since = ::GetTickCount();
        }
        m_Timed = timed;
        ::ReleaseSRWLockExclusive(&m_Lock);
    }

    void Close(void)
    {
        if (m_Thread == nullptr)
            return;
        m_Closing = true;
        if (m_Hwnd != nullptr)
            ::PostMessageW(m_Hwnd, WM_CLOSE, 0, 0);
        if (::GetCurrentThreadId() != m_ThreadId)
            ::WaitForSingleObject(m_Thread, 2000);
        ::CloseHandle(m_Thread);
        m_Thread = nullptr;
    }

    bool IsOpen(void) const { return m_Thread != nullptr; }

    // One-time password prompt: a code box on the splash. Poll Code() for the answer.
    enum class CodeState { None, Asking, Ready, Cancelled };
    void AskCode(void)
    {
        ::AcquireSRWLockExclusive(&m_Lock);
        m_CodeState = CodeState::Asking;
        ::SecureZeroMemory(m_Code, sizeof(m_Code));
        ::ReleaseSRWLockExclusive(&m_Lock);
        if (m_Thread == nullptr)
            Open();
    }

    // Ready: the code is copied to out (and forgotten here).
    CodeState Code(char (&out)[16])
    {
        ::AcquireSRWLockExclusive(&m_Lock);
        const auto st = m_CodeState;
        if (st == CodeState::Ready)
        {
            std::memcpy(out, m_Code, sizeof(out));
            ::SecureZeroMemory(m_Code, sizeof(m_Code));
            m_CodeState = CodeState::None;
        }
        ::ReleaseSRWLockExclusive(&m_Lock);
        return st;
    }

    // The FFXI folder (with trailing backslash) from PlayOnline's registry entries.
    static bool FindFfxi(wchar_t (&out)[MAX_PATH])
    {
        for (const auto key : { L"SOFTWARE\\PlayOnlineUS\\InstallFolder", L"SOFTWARE\\PlayOnline\\InstallFolder", L"SOFTWARE\\PlayOnlineEU\\InstallFolder" })
        {
            DWORD size = sizeof(out) - sizeof(wchar_t);
            if (::RegGetValueW(HKEY_LOCAL_MACHINE, key, L"0001", RRF_RT_REG_SZ, nullptr, out, &size) != ERROR_SUCCESS || out[0] == 0)
                continue;
            const auto len = std::wcslen(out);
            if (out[len - 1] != L'\\' && len + 1 < MAX_PATH)
                ::wcscat_s(out, L"\\");
            return true;
        }
        return false;
    }

    bool LoadArt(const wchar_t* dir = nullptr)
    {
        wchar_t ffxi[MAX_PATH]{};
        if (dir != nullptr)
            ::wcscpy_s(ffxi, dir);
        return (dir != nullptr || FindFfxi(ffxi)) && m_Art.Load(ffxi, LogoWidth);
    }

    // Test hook for previews: show the code prompt layout without an edit box.
    void SetPrompt(bool on) { m_PreviewPrompt = on; }

    // Draws the splash into a w x h 32bpp top-down buffer (game art only; Paint falls back to GDI).
    void Render(uint32_t* bits, int w, int h)
    {
        if (m_Base.size() != static_cast<size_t>(w) * h)
        {
            // Static part, built once: menu window background and frame, then the title logo.
            m_Base.assign(static_cast<size_t>(w) * h, 0);
            xiart::Canvas base{ w, h, m_Base.data() };
            base.Window(m_Art, BackgroundOpacity);
            base.Blend((w - m_Art.logo.w) / 2, 14, m_Art.logo, 0, 0, m_Art.logo.w, m_Art.logo.h);
        }
        std::memcpy(bits, m_Base.data(), m_Base.size() * 4);
        xiart::Canvas c{ w, h, bits };
        const int top = 14 + m_Art.logo.h;

        wchar_t status[160];
        StatusText(status);
        c.Text(m_Art, status, 24, w - 24, top + 8);

        if (m_Prompt || m_PreviewPrompt)
        {
            // Code box: typed digits and a blinking cursor.
            const int bx = (w - 150) / 2, by = top + 28;
            c.Fill(bx, by, bx + 150, by + 34, 0x8C96B4);
            c.Fill(bx + 1, by + 1, bx + 149, by + 33, 0x0A1634);
            wchar_t typed[16];
            ::wcscpy_s(typed, m_PreviewPrompt ? L"123" : m_Typed);
            if (std::wcslen(typed) < 8 && (m_Frame / 10) % 2 == 0)
                ::wcscat_s(typed, L"_");
            c.Text(m_Art, typed, bx, bx + 150, by + 9);
            ::SecureZeroMemory(typed, sizeof(typed));
            c.Text(m_Art, L"Signs in at 6 digits  \u00B7  Esc to log in yourself", 24, w - 24, h - 36, 0xB0B4C8);
            return;
        }
        // Indeterminate progress: a highlight sweeping along a thin track.
        const int tx = 60, ty = top + 40, tw = w - 120, th = 4;
        c.Fill(tx, ty, tx + tw, ty + th, 0x101830);
        const int seg = tw / 4, pos = static_cast<int>(m_Frame * 6 % (tw + seg)) - seg;
        c.Fill(tx + (pos < 0 ? 0 : pos), ty, tx + ((pos + seg) > tw ? tw : pos + seg), ty + th, 0xC8D2F0);
    }

    void StatusText(wchar_t (&status)[160])
    {
        ::AcquireSRWLockShared(&m_Lock);
        if (m_Timed && ::GetTickCount() - m_Since >= 1000)
            ::swprintf_s(status, L"%s  %lus", m_Status, (::GetTickCount() - m_Since) / 1000);
        else
            ::wcscpy_s(status, m_Status);
        ::ReleaseSRWLockShared(&m_Lock);
    }

private:
    static constexpr int CodeEditId = 100;
    static constexpr int LogoWidth  = 320;
    static constexpr int BackgroundOpacity = 230; // the window background only; logo and text stay solid

    // Game-art mode: a per-pixel alpha window, redrawn with UpdateLayeredWindow (no WM_PAINT).
    void Present(HWND hwnd)
    {
        RECT rc;
        ::GetWindowRect(hwnd, &rc);
        const int w = rc.right - rc.left, h = rc.bottom - rc.top;
        BITMAPINFO bi{};
        bi.bmiHeader = { sizeof(BITMAPINFOHEADER), w, -h, 1, 32, BI_RGB };
        void* bits = nullptr;
        const auto screen = ::GetDC(nullptr);
        const auto dib = ::CreateDIBSection(screen, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
        if (dib != nullptr)
        {
            Render(static_cast<uint32_t*>(bits), w, h);
            const auto mem = ::CreateCompatibleDC(screen);
            const auto old = ::SelectObject(mem, dib);
            POINT src{ 0, 0 };
            SIZE size{ w, h };
            BLENDFUNCTION bf{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
            ::UpdateLayeredWindow(hwnd, screen, nullptr, &size, mem, &src, 0, &bf, ULW_ALPHA);
            ::SelectObject(mem, old);
            ::DeleteDC(mem);
            ::DeleteObject(dib);
        }
        ::ReleaseDC(nullptr, screen);
    }

    void ShowCodeBox(HWND hwnd)
    {
        if (m_Art.Ok())
        {
            // A layered window doesn't draw child controls, so the box is drawn by Render and
            // the splash takes the keys itself (WM_CHAR).
            ::SecureZeroMemory(m_Typed, sizeof(m_Typed));
            m_Prompt = true;
            ::ShowWindow(hwnd, SW_SHOW);
            ::SetForegroundWindow(hwnd);
            ::SetFocus(hwnd);
            return;
        }
        RECT rc;
        ::GetClientRect(hwnd, &rc);
        const auto inst = ::GetModuleHandleW(nullptr);
        m_CodeFont = ::CreateFontW(-24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        m_Edit = ::CreateWindowExW(0, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_CENTER | ES_NUMBER,
            (rc.right - 150) / 2, m_Art.Ok() ? 14 + m_Art.logo.h + 28 : 120, 150, 34, hwnd, reinterpret_cast<HMENU>(CodeEditId), inst, nullptr);
        ::SendMessageW(m_Edit, WM_SETFONT, reinterpret_cast<WPARAM>(m_CodeFont), TRUE);
        ::SendMessageW(m_Edit, EM_SETLIMITTEXT, 8, 0);
        ::SetWindowLongPtrW(m_Edit, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        m_EditOld = reinterpret_cast<WNDPROC>(::SetWindowLongPtrW(m_Edit, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(EditProc)));
        // Bring the splash forward so the code can be typed straight away.
        ::ShowWindow(hwnd, SW_SHOW);
        ::SetForegroundWindow(hwnd);
        ::SetFocus(m_Edit);
    }

    void EndCode(HWND hwnd, bool submit)
    {
        wchar_t text[16]{};
        if (m_Prompt)
            ::wcscpy_s(text, m_Typed);
        else
            ::GetWindowTextW(m_Edit, text, 16);
        ::AcquireSRWLockExclusive(&m_Lock);
        if (submit)
        {
            for (int i = 0; i < 15 && text[i] != 0; i++)
                m_Code[i] = static_cast<char>(text[i]);
            m_CodeState = CodeState::Ready;
        }
        else
            m_CodeState = CodeState::Cancelled;
        ::ReleaseSRWLockExclusive(&m_Lock);
        ::SecureZeroMemory(text, sizeof(text));
        if (m_Prompt)
        {
            ::SecureZeroMemory(m_Typed, sizeof(m_Typed));
            m_Prompt = false;
            return;
        }
        ::SetWindowTextW(m_Edit, L"");
        ::DestroyWindow(m_Edit);
        m_Edit = nullptr;
        ::DeleteObject(m_CodeFont);
        m_CodeFont = nullptr;
        ::InvalidateRect(hwnd, nullptr, FALSE);
    }

    static LRESULT CALLBACK EditProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        const auto self = reinterpret_cast<Splash*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        if (msg == WM_GETDLGCODE)
            return DLGC_WANTALLKEYS;
        if (msg == WM_KEYDOWN && (wp == VK_RETURN || wp == VK_ESCAPE))
        {
            if (wp == VK_ESCAPE || ::GetWindowTextLengthW(hwnd) >= 6)
                ::PostMessageW(::GetParent(hwnd), WM_APP + 2, wp == VK_RETURN, 0);
            return 0;
        }
        if (msg == WM_CHAR && (wp == L'\r' || wp == 27))
            return 0; // no beep
        return ::CallWindowProcW(self->m_EditOld, hwnd, msg, wp, lp);
    }

    static DWORD __stdcall ThreadMain(LPVOID param)
    {
        const auto self   = static_cast<Splash*>(param);
        self->m_ThreadId  = ::GetCurrentThreadId();
        const auto inst   = ::GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{ sizeof(wc) };
        wc.lpfnWndProc   = WndProc;
        wc.hInstance     = inst;
        wc.hCursor       = ::LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
        wc.lpszClassName = L"BegonePOLSplash";
        ::RegisterClassExW(&wc);

        // The game's own artwork, from the FFXI install; plain drawing if it can't be read.
        const bool art = self->LoadArt();
        const int w = art ? 480 : 460, h = art ? 310 : 190;
        RECT wa{};
        ::SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
        const auto hwnd = ::CreateWindowExW(WS_EX_APPWINDOW | (art ? WS_EX_LAYERED : 0), wc.lpszClassName, L"FINAL FANTASY XI - logging in", WS_POPUP,
            wa.left + (wa.right - wa.left - w) / 2, wa.top + (wa.bottom - wa.top - h) / 2, w, h, nullptr, nullptr, inst, self);
        if (hwnd == nullptr)
            return 0;
        self->m_Hwnd = hwnd;
        if (self->m_Closing)
            ::DestroyWindow(hwnd);
        else
        {
            if (art)
                self->Present(hwnd); // first frame before showing, so it never appears blank
            ::ShowWindow(hwnd, SW_SHOWNOACTIVATE);
            ::SetTimer(hwnd, 1, 50, nullptr);
        }
        MSG msg;
        while (::GetMessageW(&msg, nullptr, 0, 0) > 0)
        {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
        }
        self->m_Hwnd = nullptr;
        ::UnregisterClassW(wc.lpszClassName, inst);
        return 0;
    }

    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
    {
        auto self = reinterpret_cast<Splash*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
        switch (msg)
        {
        case WM_NCCREATE:
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams));
            break;
        case WM_TIMER:
            if (self != nullptr)
            {
                self->m_Frame++;
                if (self->m_CodeState == CodeState::Asking && self->m_Edit == nullptr && !self->m_Prompt)
                    self->ShowCodeBox(hwnd);
                if (self->m_Art.Ok())
                {
                    self->Present(hwnd);
                    return 0;
                }
            }
            ::InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_CHAR: // game-art code prompt: digits, Backspace, Enter, Esc
            if (self != nullptr && self->m_Prompt)
            {
                const auto len = std::wcslen(self->m_Typed);
                if (wp >= L'0' && wp <= L'9' && len < 8)
                {
                    self->m_Typed[len] = static_cast<wchar_t>(wp);
                    if (len + 1 == 6)
                        ::PostMessageW(hwnd, WM_APP + 2, TRUE, 0); // six digits typed: sign in
                }
                else if (wp == L'\b' && len > 0)
                    self->m_Typed[len - 1] = 0;
                else if (wp == L'\r' && len >= 6)
                    ::PostMessageW(hwnd, WM_APP + 2, TRUE, 0);
                else if (wp == 27)
                    ::PostMessageW(hwnd, WM_APP + 2, FALSE, 0);
                self->Present(hwnd);
            }
            return 0;
        case WM_ERASEBKGND:
            return 1;
        case WM_COMMAND: // six digits typed: sign in
            if (self != nullptr && LOWORD(wp) == CodeEditId && HIWORD(wp) == EN_CHANGE && self->m_Edit != nullptr && ::GetWindowTextLengthW(self->m_Edit) == 6)
                ::PostMessageW(hwnd, WM_APP + 2, TRUE, 0);
            return 0;
        case WM_APP + 2: // finish the code prompt outside the edit box's own message handling
            if (self != nullptr && (self->m_Edit != nullptr || self->m_Prompt))
                self->EndCode(hwnd, wp != 0);
            return 0;
        case WM_CTLCOLOREDIT:
            ::SetTextColor(reinterpret_cast<HDC>(wp), RGB(235, 240, 255));
            ::SetBkColor(reinterpret_cast<HDC>(wp), RGB(10, 22, 52));
            if (self != nullptr && self->m_EditBrush == nullptr)
                self->m_EditBrush = ::CreateSolidBrush(RGB(10, 22, 52));
            return self != nullptr ? reinterpret_cast<LRESULT>(self->m_EditBrush) : 0;
        case WM_NCHITTEST: // drag anywhere
            return HTCAPTION;
        case WM_PAINT:
            if (self != nullptr)
                self->Paint(hwnd);
            else
                ::ValidateRect(hwnd, nullptr);
            return 0;
        case WM_CLOSE:
            ::DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
        }
        return ::DefWindowProcW(hwnd, msg, wp, lp);
    }

    void Paint(HWND hwnd)
    {
        PAINTSTRUCT ps;
        const auto dc = ::BeginPaint(hwnd, &ps);
        RECT rc;
        ::GetClientRect(hwnd, &rc);
        const int w = rc.right, h = rc.bottom;

        if (m_Art.Ok()) // drawn by Present
        {
            ::EndPaint(hwnd, &ps);
            return;
        }

        // Double buffered so the animation doesn't flicker.
        const auto mem = ::CreateCompatibleDC(dc);
        const auto bmp = ::CreateCompatibleBitmap(dc, w, h);
        const auto oldBmp = ::SelectObject(mem, bmp);

        TRIVERTEX v[2] = { { 0, 0, 0x0800, 0x1000, 0x3000, 0 }, { w, h, 0x0000, 0x0400, 0x1000, 0 } };
        GRADIENT_RECT g{ 0, 1 };
        ::GradientFill(mem, v, 2, &g, 1, GRADIENT_FILL_RECT_V);

        const auto border = ::CreatePen(PS_SOLID, 1, RGB(90, 120, 190));
        const auto oldPen = ::SelectObject(mem, border);
        const auto oldBr  = ::SelectObject(mem, ::GetStockObject(NULL_BRUSH));
        ::Rectangle(mem, 0, 0, w, h);
        ::SelectObject(mem, oldBr);
        ::SelectObject(mem, oldPen);
        ::DeleteObject(border);

        ::SetBkMode(mem, TRANSPARENT);
        const auto title  = ::CreateFontW(-30, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        const auto body   = ::CreateFontW(-15, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
        const auto oldFnt = ::SelectObject(mem, title);
        RECT t{ 0, 38, w, 80 };
        ::SetTextColor(mem, RGB(235, 240, 255));
        ::DrawTextW(mem, L"FINAL FANTASY XI", -1, &t, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
        ::SelectObject(mem, body);
        RECT st{ 0, 92, w, 116 };
        ::SetTextColor(mem, RGB(160, 180, 220));
        wchar_t status[160];
        StatusText(status);
        ::DrawTextW(mem, status, -1, &st, DT_CENTER | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
        ::SelectObject(mem, oldFnt);
        ::DeleteObject(title);
        ::DeleteObject(body);

        if (m_Edit != nullptr)
        {
            // Code prompt: a hint under the box instead of the progress bar.
            const auto hintFont = ::CreateFontW(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, 0, 0, CLEARTYPE_QUALITY, 0, L"Segoe UI");
            const auto prev  = ::SelectObject(mem, hintFont);
            RECT hint{ 0, 160, w, 182 };
            ::SetTextColor(mem, RGB(120, 140, 180));
            ::DrawTextW(mem, L"Signs in at 6 digits  \u00B7  Esc to log in yourself", -1, &hint, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
            ::SelectObject(mem, prev);
            ::DeleteObject(hintFont);
            ::BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
            ::SelectObject(mem, oldBmp);
            ::DeleteObject(bmp);
            ::DeleteDC(mem);
            ::EndPaint(hwnd, &ps);
            return;
        }

        // Indeterminate progress: a highlight sweeping along a thin track.
        const int tx = 60, ty = 140, tw = w - 120, th = 4;
        RECT track{ tx, ty, tx + tw, ty + th };
        const auto trackBr = ::CreateSolidBrush(RGB(30, 45, 80));
        ::FillRect(mem, &track, trackBr);
        ::DeleteObject(trackBr);
        const int seg = tw / 4, pos = static_cast<int>(m_Frame * 6 % (tw + seg)) - seg;
        RECT bar{ tx + (pos < 0 ? 0 : pos), ty, tx + ((pos + seg) > tw ? tw : pos + seg), ty + th };
        const auto barBr = ::CreateSolidBrush(RGB(120, 170, 255));
        if (bar.right > bar.left)
            ::FillRect(mem, &bar, barBr);
        ::DeleteObject(barBr);

        ::BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
        ::SelectObject(mem, oldBmp);
        ::DeleteObject(bmp);
        ::DeleteDC(mem);
        ::EndPaint(hwnd, &ps);
    }

    HANDLE m_Thread                  = nullptr;
    DWORD m_ThreadId                 = 0;
    volatile HWND m_Hwnd             = nullptr;
    volatile bool m_Closing          = false;
    SRWLOCK m_Lock                   = SRWLOCK_INIT;
    wchar_t m_Status[128]            = L"Starting PlayOnline...";
    DWORD m_Since                    = ::GetTickCount();
    bool m_Timed                     = false;
    volatile uint32_t m_Frame        = 0;
    volatile CodeState m_CodeState   = CodeState::None;
    char m_Code[16]{};
    HWND m_Edit                      = nullptr;
    WNDPROC m_EditOld                = nullptr;
    HFONT m_CodeFont                 = nullptr;
    HBRUSH m_EditBrush               = nullptr;
    xiart::Art m_Art;
    std::vector<uint32_t> m_Base;
    bool m_PreviewPrompt             = false;
    bool m_Prompt                    = false;
    wchar_t m_Typed[16]{};
};
