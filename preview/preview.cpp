// Renders the splash (game art path) to BMP files without starting PlayOnline.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <vector>
#include "../src/splash.h"

static void Save(Splash& s, const char* file)
{
    const int w = 480, h = 310;
    std::vector<uint32_t> px(w * h);
    s.Render(px.data(), w, h);
    // Show it over a dark checkerboard, as the desktop would show through.
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++)
        {
            auto& p = px[y * w + x];
            const uint32_t bg = ((x / 24 + y / 24) & 1) ? 0x48 : 0x30, ia = 255 - (p >> 24);
            uint32_t c[3];
            for (int k = 0; k < 3; k++)
                c[k] = ((p >> (k * 8)) & 255) + bg * ia / 255;
            p = 0xFF000000 | (c[2] << 16) | (c[1] << 8) | c[0];
        }
    BITMAPFILEHEADER fh{ 0x4D42, static_cast<DWORD>(sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + px.size() * 4), 0, 0, sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) };
    BITMAPINFOHEADER ih{ sizeof(ih), w, -h, 1, 32, BI_RGB };
    auto f = std::fopen(file, "wb");
    std::fwrite(&fh, sizeof(fh), 1, f);
    std::fwrite(&ih, sizeof(ih), 1, f);
    std::fwrite(px.data(), 4, px.size(), f);
    std::fclose(f);
}

int wmain(int argc, wchar_t** argv)
{
    Splash s;
    const auto t = GetTickCount();
    if (!s.LoadArt(argc > 1 ? argv[1] : nullptr))
    {
        std::printf("art not found\n");
        return 1;
    }
    std::printf("art loaded in %lu ms\n", GetTickCount() - t);
    s.SetStatus(L"Signing in to your Square Enix account...");
    Save(s, "splash-status.bmp");
    s.SetStatus(L"Enter the one-time password from your authenticator:");
    s.SetPrompt(true);
    Save(s, "splash-prompt.bmp");
    return 0;
}
