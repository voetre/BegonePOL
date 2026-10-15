#pragma once

/**
 * Time-based one-time passwords (RFC 6238: HMAC-SHA1, 30 second steps), the kind authenticator
 * apps show for a Square Enix account. Self-contained so it has no crypto library dependency.
 */

#include <cstdint>
#include <cstring>
#include <string>

namespace totp
{
    namespace detail
    {
        inline uint32_t Rol(uint32_t v, int n) { return (v << n) | (v >> (32 - n)); }

        struct Sha1
        {
            uint32_t h[5]{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
            uint8_t block[64]{};
            uint64_t length = 0;
            size_t used     = 0;

            void Compress(void)
            {
                uint32_t w[80];
                for (int i = 0; i < 16; i++)
                    w[i] = (uint32_t(block[i * 4]) << 24) | (uint32_t(block[i * 4 + 1]) << 16) | (uint32_t(block[i * 4 + 2]) << 8) | block[i * 4 + 3];
                for (int i = 16; i < 80; i++)
                    w[i] = Rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
                uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
                for (int i = 0; i < 80; i++)
                {
                    uint32_t f, k;
                    if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999; }
                    else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1; }
                    else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDC; }
                    else             { f = b ^ c ^ d;                    k = 0xCA62C1D6; }
                    const auto t = Rol(a, 5) + f + e + k + w[i];
                    e = d; d = c; c = Rol(b, 30); b = a; a = t;
                }
                h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
                std::memset(w, 0, sizeof(w));
            }

            void Update(const uint8_t* p, size_t n)
            {
                length += n;
                while (n-- != 0)
                {
                    block[used++] = *p++;
                    if (used == 64)
                    {
                        Compress();
                        used = 0;
                    }
                }
            }

            void Final(uint8_t out[20])
            {
                const auto bits = length * 8;
                const uint8_t one = 0x80, zero = 0;
                Update(&one, 1);
                while (used != 56)
                    Update(&zero, 1);
                uint8_t len[8];
                for (int i = 0; i < 8; i++)
                    len[i] = static_cast<uint8_t>(bits >> (56 - i * 8));
                Update(len, 8);
                for (int i = 0; i < 20; i++)
                    out[i] = static_cast<uint8_t>(h[i / 4] >> (24 - (i % 4) * 8));
                std::memset(block, 0, sizeof(block));
            }
        };

        inline void HmacSha1(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[20])
        {
            uint8_t k[64]{};
            if (keyLen > 64)
            {
                Sha1 s;
                s.Update(key, keyLen);
                s.Final(k);
            }
            else
                std::memcpy(k, key, keyLen);
            uint8_t pad[64];
            for (int i = 0; i < 64; i++)
                pad[i] = k[i] ^ 0x36;
            Sha1 inner;
            inner.Update(pad, 64);
            inner.Update(msg, msgLen);
            uint8_t ih[20];
            inner.Final(ih);
            for (int i = 0; i < 64; i++)
                pad[i] = k[i] ^ 0x5C;
            Sha1 outer;
            outer.Update(pad, 64);
            outer.Update(ih, 20);
            outer.Final(out);
            std::memset(k, 0, sizeof(k));
            std::memset(pad, 0, sizeof(pad));
            std::memset(ih, 0, sizeof(ih));
        }
    }

    // Base32 (RFC 4648) as authenticator setup keys are written: case, spaces, dashes and '=' ignored.
    inline bool Base32Decode(const char* text, uint8_t* out, size_t cap, size_t& len)
    {
        uint32_t acc = 0;
        int bits     = 0;
        len          = 0;
        for (auto p = text; *p != 0; p++)
        {
            auto c = *p;
            if (c == ' ' || c == '-' || c == '=')
                continue;
            if (c >= 'a' && c <= 'z')
                c = static_cast<char>(c - 32);
            int v;
            if (c >= 'A' && c <= 'Z')
                v = c - 'A';
            else if (c >= '2' && c <= '7')
                v = c - '2' + 26;
            else
                return false;
            acc = (acc << 5) | static_cast<uint32_t>(v);
            bits += 5;
            if (bits >= 8)
            {
                if (len == cap)
                    return false;
                bits -= 8;
                out[len++] = static_cast<uint8_t>(acc >> bits);
            }
        }
        return len != 0;
    }

    // Code for the given Unix time; false if the key isn't valid base32.
    inline bool Code(const char* base32Key, uint64_t unixTime, char out[7])
    {
        uint8_t key[64];
        size_t keyLen = 0;
        if (!Base32Decode(base32Key, key, sizeof(key), keyLen))
            return false;
        const auto counter = unixTime / 30;
        uint8_t msg[8];
        for (int i = 0; i < 8; i++)
            msg[i] = static_cast<uint8_t>(counter >> (56 - i * 8));
        uint8_t mac[20];
        detail::HmacSha1(key, keyLen, msg, sizeof(msg), mac);
        const auto off = mac[19] & 0x0F;
        const auto bin = ((mac[off] & 0x7Fu) << 24) | (uint32_t(mac[off + 1]) << 16) | (uint32_t(mac[off + 2]) << 8) | mac[off + 3];
        auto v = bin % 1000000u;
        for (int i = 5; i >= 0; i--, v /= 10)
            out[i] = static_cast<char>('0' + v % 10);
        out[6] = 0;
        std::memset(key, 0, sizeof(key));
        std::memset(mac, 0, sizeof(mac));
        return true;
    }
}
