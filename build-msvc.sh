#!/bin/bash
# Build BegonePOL.dll (an Ashita v4 POL plugin) with clang-cl against the MSVC CRT + Windows SDK
# splatted by xwin, so the plugin uses the same C++ ABI as Ashita itself.
#
# Needs:
#   clang-cl and lld-link (LLVM; set LLVM_BIN if they aren't in /usr/lib/llvm-21/bin or on PATH)
#   xwin --accept-license --arch x86 --cache-dir ~/.cache/xwin splat --output ~/.xwin
#   an Ashita v4 install (its plugins/sdk folder is used; set ASHITA_DIR)
#
# Usage: ./build-msvc.sh [install]   - "install" also copies the dll into $ASHITA_DIR/polplugins
set -euo pipefail
cd "$(dirname "$0")"

XWIN="${XWIN:-$HOME/.xwin}"
ASHITA_DIR="${ASHITA_DIR:?set ASHITA_DIR to your Ashita v4 folder, e.g. ~/Games/ffxi/drive_c/Ashita}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-21/bin}"
OUT=build-msvc

mkdir -p "$OUT/libalias"
# The SDK source asks for Psapi.lib; xwin only ships lower/upper-case names.
ln -sf "$XWIN/sdk/lib/um/x86/psapi.lib" "$OUT/libalias/Psapi.lib"

# A copy of the Ashita SDK: some of its bundled DirectX headers end in a DOS EOF (0x1A) that clang rejects.
if [ ! -f "$OUT/sdk/Ashita.h" ] || [ "$ASHITA_DIR/plugins/sdk/Ashita.h" -nt "$OUT/sdk/Ashita.h" ]; then
    rm -rf "$OUT/sdk"
    cp -r "$ASHITA_DIR/plugins/sdk" "$OUT/sdk"
    find "$OUT/sdk" \( -name '*.h' -o -name '*.inl' \) -exec sed -i 's/\x1a//g' {} +
fi

PATH="$LLVM_BIN:$PATH" clang-cl --target=i686-pc-windows-msvc /nologo /std:c++20 /O2 /EHsc /MT /LD \
    -Wno-unused-function -Wno-deprecated-volatile -fuse-ld=lld-link \
    /imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt" \
    /imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared" \
    /I "$OUT/sdk" /Fo"$OUT/" src/begonepol.cpp \
    /link /def:src/begonepol.def /libpath:"$OUT/libalias" /libpath:"$XWIN/crt/lib/x86" \
    /libpath:"$XWIN/sdk/lib/um/x86" /libpath:"$XWIN/sdk/lib/ucrt/x86" /out:"$OUT/BegonePOL.dll"

echo "Built $OUT/BegonePOL.dll"
if [ "${1:-}" = install ]; then
    cp "$OUT/BegonePOL.dll" "$ASHITA_DIR/polplugins/BegonePOL.dll"
    echo "Installed to $ASHITA_DIR/polplugins/BegonePOL.dll"
fi
