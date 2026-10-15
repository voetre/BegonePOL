#pragma once

/**
 * Artwork for the splash, read from the user's own FINAL FANTASY XI install (nothing of the game's
 * is shipped with the plugin): the title screen logo, the text font and the default (type 1) menu
 * window. All of them are DXT-compressed textures inside the game's DAT files.
 *
 * Texture records: a flag byte (0xA1 = DXT), a 16 character name, a 40 byte BITMAPINFOHEADER,
 * the FourCC stored reversed ("1TXD"), the data size and 8 more bytes, then the blocks.
 * Like the PS2 original, alpha 0x80 means opaque, so alpha is doubled on load.
 */

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <vector>

namespace xiart
{
    // Premultiplied BGRA, top-down (the layout AlphaBlend and a 32bpp DIB section want).
    struct Image
    {
        int w = 0, h = 0;
        std::vector<uint32_t> px;
        bool Ok(void) const { return w > 0 && h > 0; }
    };

    inline std::vector<uint8_t> ReadAll(const wchar_t* path)
    {
        std::vector<uint8_t> out;
        const auto f = ::CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE)
            return out;
        LARGE_INTEGER size{};
        DWORD got = 0;
        if (::GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart < (64 << 20))
        {
            out.resize(static_cast<size_t>(size.QuadPart));
            if (!::ReadFile(f, out.data(), static_cast<DWORD>(out.size()), &got, nullptr) || got != out.size())
                out.clear();
        }
        ::CloseHandle(f);
        return out;
    }

    inline uint32_t Rgb565(uint16_t c, int& r, int& g, int& b)
    {
        r = ((c >> 11) & 31) * 255 / 31;
        g = ((c >> 5) & 63) * 255 / 63;
        b = (c & 31) * 255 / 31;
        return 0;
    }

    // Decodes rows [y0, y1) (multiples of 4) of the texture named name (16 chars) in dat.
    inline Image Texture(const std::vector<uint8_t>& dat, const char* name, int y0 = 0, int y1 = -1)
    {
        Image img;
        uint8_t key[21] = { 0xA1 };
        std::memcpy(key + 1, name, 16);
        std::memcpy(key + 17, "\x28\0\0\0", 4);
        size_t o = 0;
        for (; o + 69 < dat.size(); o++)
            if (std::memcmp(&dat[o], key, sizeof(key)) == 0)
                break;
        if (o + 69 >= dat.size())
            return img;
        int32_t w, h;
        std::memcpy(&w, &dat[o + 21], 4);
        std::memcpy(&h, &dat[o + 25], 4);
        const auto fcc = &dat[o + 57];
        const bool dxt1 = std::memcmp(fcc, "1TXD", 4) == 0;
        if (!dxt1 && std::memcmp(fcc, "3TXD", 4) != 0)
            return img;
        if (w <= 0 || h <= 0 || w > 4096 || h > 4096 || (w % 4) != 0 || (h % 4) != 0)
            return img;
        const size_t blockSize = dxt1 ? 8 : 16;
        const auto data = o + 69;
        if (data + static_cast<size_t>(w / 4) * (h / 4) * blockSize > dat.size())
            return img;
        if (y1 < 0 || y1 > h)
            y1 = h;
        y0 &= ~3;
        img.w = w;
        img.h = y1 - y0;
        img.px.assign(static_cast<size_t>(img.w) * img.h, 0);

        for (int by = y0 / 4; by < (y1 + 3) / 4; by++)
            for (int bx = 0; bx < w / 4; bx++)
            {
                const auto blk = &dat[data + (static_cast<size_t>(by) * (w / 4) + bx) * blockSize];
                const auto col = dxt1 ? blk : blk + 8;
                uint16_t c0, c1;
                uint32_t bits;
                std::memcpy(&c0, col, 2);
                std::memcpy(&c1, col + 2, 2);
                std::memcpy(&bits, col + 4, 4);
                int r[4], g[4], b[4], a[4] = { 255, 255, 255, 255 };
                Rgb565(c0, r[0], g[0], b[0]);
                Rgb565(c1, r[1], g[1], b[1]);
                if (!dxt1 || c0 > c1)
                {
                    r[2] = (2 * r[0] + r[1]) / 3, g[2] = (2 * g[0] + g[1]) / 3, b[2] = (2 * b[0] + b[1]) / 3;
                    r[3] = (r[0] + 2 * r[1]) / 3, g[3] = (g[0] + 2 * g[1]) / 3, b[3] = (b[0] + 2 * b[1]) / 3;
                }
                else
                {
                    r[2] = (r[0] + r[1]) / 2, g[2] = (g[0] + g[1]) / 2, b[2] = (b[0] + b[1]) / 2;
                    r[3] = g[3] = b[3] = 0, a[3] = 0;
                }
                for (int py = 0; py < 4; py++)
                {
                    const int y = by * 4 + py - y0;
                    if (y < 0 || y >= img.h)
                        continue;
                    for (int px = 0; px < 4; px++)
                    {
                        const int i = py * 4 + px;
                        const int k = (bits >> (i * 2)) & 3;
                        int alpha = a[k];
                        if (!dxt1)
                            alpha = ((blk[i / 2] >> ((i & 1) * 4)) & 15) * 17;
                        alpha = alpha * 2 > 255 ? 255 : alpha * 2;
                        const auto pr = r[k] * alpha / 255, pg = g[k] * alpha / 255, pb = b[k] * alpha / 255;
                        img.px[static_cast<size_t>(y) * img.w + bx * 4 + px] = (static_cast<uint32_t>(alpha) << 24) | (pr << 16) | (pg << 8) | pb;
                    }
                }
            }
        return img;
    }

    inline Image Crop(const Image& src, int x, int y, int w, int h)
    {
        Image out;
        if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > src.w || y + h > src.h)
            return out;
        out.w = w;
        out.h = h;
        out.px.resize(static_cast<size_t>(w) * h);
        for (int r = 0; r < h; r++)
            std::memcpy(&out.px[static_cast<size_t>(r) * w], &src.px[static_cast<size_t>(y + r) * src.w + x], w * 4);
        return out;
    }

    // Box-filtered downscale (premultiplied, so edges don't darken).
    inline Image Shrink(const Image& src, int w, int h)
    {
        Image out;
        out.w = w;
        out.h = h;
        out.px.resize(static_cast<size_t>(w) * h);
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++)
            {
                const int sx0 = x * src.w / w, sx1 = (std::max)(sx0 + 1, (x + 1) * src.w / w);
                const int sy0 = y * src.h / h, sy1 = (std::max)(sy0 + 1, (y + 1) * src.h / h);
                uint32_t s[4]{}, n = 0;
                for (int sy = sy0; sy < sy1; sy++)
                    for (int sx = sx0; sx < sx1; sx++, n++)
                    {
                        const auto p = src.px[static_cast<size_t>(sy) * src.w + sx];
                        for (int c = 0; c < 4; c++)
                            s[c] += (p >> (c * 8)) & 255;
                    }
                out.px[static_cast<size_t>(y) * w + x] = (s[3] / n << 24) | (s[2] / n << 16) | (s[1] / n << 8) | (s[0] / n);
            }
        return out;
    }

    // Bounding box of pixels with alpha above a threshold.
    inline void Bounds(const Image& img, int& x0, int& y0, int& x1, int& y1)
    {
        x0 = img.w, y0 = img.h, x1 = 0, y1 = 0;
        for (int y = 0; y < img.h; y++)
            for (int x = 0; x < img.w; x++)
                if ((img.px[static_cast<size_t>(y) * img.w + x] >> 24) > 16)
                {
                    x0 = (std::min)(x0, x), y0 = (std::min)(y0, y);
                    x1 = (std::max)(x1, x + 1), y1 = (std::max)(y1, y + 1);
                }
    }

    struct Art
    {
        Image logo;               // title screen logo, already scaled for the splash
        Image tile;               // menu window background, 128x128
        Image corner, hframe, vframe; // window border pieces, 32x32 each
        Image font;               // ASCII 0x20-0x7F: two rows of 64 cells, 16x16 each
        int advance[96]{};
        bool Ok(void) const { return logo.Ok() && tile.Ok() && corner.Ok() && hframe.Ok() && vframe.Ok() && font.Ok(); }

        // Loads everything from the FFXI folder (with trailing backslash); logoWidth is the target width.
        bool Load(const wchar_t* ffxi, int logoWidth)
        {
            wchar_t path[MAX_PATH];
            const auto at = [&](const wchar_t* rel) {
                ::swprintf_s(path, L"%s%s", ffxi, rel);
                return ReadAll(path);
            };

            // The title screen texture (several copies across ROM folders; any will do). The
            // logo is its middle band; the copyright and test lines above it are cut away.
            for (const auto rel : { L"ROM\\176\\74.DAT", L"ROM\\178\\13.DAT", L"ROM\\119\\50.DAT", L"ROM\\91\\16.DAT" })
            {
                const auto dat = at(rel);
                auto title = Texture(dat, "menu    titlwin ", 300, 920);
                if (!title.Ok())
                    continue;
                int x0, y0, x1, y1;
                Bounds(title, x0, y0, x1, y1);
                if (x1 <= x0 || y1 <= y0)
                    continue;
                const auto band = Crop(title, x0, y0, x1 - x0, y1 - y0);
                logo = Shrink(band, logoWidth, band.h * logoWidth / band.w);
                break;
            }

            const auto win = at(L"ROM\\0\\14.DAT"); // window type 1, the default
            tile   = Texture(win, "menu    newtex  ");
            corner = Texture(win, "menu    corner  ");
            hframe = Texture(win, "menu    hfr1    ");
            vframe = Texture(win, "menu    vfr1    ");

            const auto fnt = at(L"ROM\\0\\1.DAT");
            font = Texture(fnt, "font    moji    ", 0, 32);
            if (font.Ok())
            {
                // The glyphs are grey (the game tints them up); brighten to near white.
                for (auto& p : font.px)
                {
                    uint32_t c[4];
                    for (int k = 0; k < 4; k++)
                        c[k] = (p >> (k * 8)) & 255;
                    for (int k = 0; k < 3; k++)
                        c[k] = (std::min)(c[3], c[k] * 3 / 2);
                    p = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
                }
                // Proportional spacing: each glyph sits at the left of its cell.
                for (int i = 0; i < 96; i++)
                {
                    int right = 0;
                    for (int y = 0; y < 16; y++)
                        for (int x = 0; x < 16; x++)
                            if ((font.px[static_cast<size_t>((i / 64) * 16 + y) * font.w + (i % 64) * 16 + x] >> 24) > 24)
                                right = (std::max)(right, x + 1);
                    advance[i] = right == 0 ? 5 : right;
                }
            }
            return Ok();
        }
    };

    // A 32bpp top-down software canvas; Blend draws premultiplied pixels over it.
    struct Canvas
    {
        int w = 0, h = 0;
        uint32_t* px = nullptr;

        void Blend(int dx, int dy, const Image& src, int sx, int sy, int sw, int sh, uint32_t tint = 0xFFFFFF, uint32_t opacity = 255)
        {
            const uint32_t tr = (tint >> 16) & 255, tg = (tint >> 8) & 255, tb = tint & 255;
            for (int y = 0; y < sh; y++)
            {
                const int ty = dy + y;
                if (ty < 0 || ty >= h)
                    continue;
                for (int x = 0; x < sw; x++)
                {
                    const int tx = dx + x;
                    if (tx < 0 || tx >= w)
                        continue;
                    const auto s = src.px[static_cast<size_t>(sy + y) * src.w + sx + x];
                    const uint32_t a = (s >> 24) * opacity / 255;
                    if (a == 0)
                        continue;
                    // Premultiplied "over", keeping the canvas's own alpha (the window is translucent).
                    auto& d = px[static_cast<size_t>(ty) * w + tx];
                    const uint32_t sr = ((s >> 16) & 255) * tr * opacity / (255 * 255), sg = ((s >> 8) & 255) * tg * opacity / (255 * 255), sb = (s & 255) * tb * opacity / (255 * 255);
                    const uint32_t ia = 255 - a;
                    const uint32_t r = sr + ((d >> 16) & 255) * ia / 255, g = sg + ((d >> 8) & 255) * ia / 255, b = sb + (d & 255) * ia / 255;
                    const uint32_t da = a + (d >> 24) * ia / 255;
                    d = (da << 24) | (r << 16) | (g << 8) | b;
                }
            }
        }

        void Fill(int x0, int y0, int x1, int y1, uint32_t rgb)
        {
            for (int y = (std::max)(0, y0); y < (std::min)(h, y1); y++)
                for (int x = (std::max)(0, x0); x < (std::min)(w, x1); x++)
                    px[static_cast<size_t>(y) * w + x] = 0xFF000000 | rgb;
        }

        // The default FFXI menu window: striped tile (at the given opacity) plus the three-line border.
        // Start from a cleared (fully transparent) canvas.
        void Window(const Art& art, uint32_t opacity = 255)
        {
            for (int y = 0; y < h; y += art.tile.h)
                for (int x = 0; x < w; x += art.tile.w)
                    Blend(x, y, art.tile, 0, 0, (std::min)(art.tile.w, w - x), (std::min)(art.tile.h, h - y), 0xFFFFFF, opacity);
            const int q = art.corner.w / 2;
            for (int x = q; x < w - q; x++)
            {
                Blend(x, 0, art.hframe, q, 0, 1, q);
                Blend(x, h - q, art.hframe, q, q, 1, q);
            }
            for (int y = q; y < h - q; y++)
            {
                Blend(0, y, art.vframe, 0, q, q, 1);
                Blend(w - q, y, art.vframe, q, q, q, 1);
            }
            Blend(0, 0, art.corner, 0, 0, q, q);
            Blend(w - q, 0, art.corner, q, 0, q, q);
            Blend(0, h - q, art.corner, 0, q, q, q);
            Blend(w - q, h - q, art.corner, q, q, q, q);
        }

        static int Glyph(wchar_t c) { return c >= 0x20 && c < 0x80 ? c - 0x20 : '?' - 0x20; }

        int TextWidth(const Art& art, const wchar_t* text)
        {
            int n = 0;
            for (auto p = text; *p != 0; p++)
                n += art.advance[Glyph(*p)];
            return n;
        }

        // Centred in [x0, x1); cut with "..." if it doesn't fit.
        void Text(const Art& art, const wchar_t* text, int x0, int x1, int y, uint32_t tint = 0xFFFFFF)
        {
            wchar_t buf[192];
            ::wcsncpy_s(buf, text, _TRUNCATE);
            for (auto p = buf; *p != 0; p++)
                if (*p == 0x00B7) // middle dot isn't in the ASCII rows
                    *p = L'-';
            const int dots = art.advance[Glyph(L'.')] * 3;
            auto len = std::wcslen(buf);
            if (TextWidth(art, buf) > x1 - x0)
            {
                while (len > 0 && TextWidth(art, buf) + dots > x1 - x0)
                    buf[--len] = 0;
                ::wcscat_s(buf, L"...");
            }
            int x = x0 + (x1 - x0 - TextWidth(art, buf)) / 2;
            for (auto p = buf; *p != 0; p++)
            {
                const int g = Glyph(*p);
                Blend(x, y, art.font, (g % 64) * 16, (g / 64) * 16, 16, 16, tint);
                x += art.advance[g];
            }
        }
    };
}
