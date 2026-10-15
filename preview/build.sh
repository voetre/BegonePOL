#!/bin/bash
# Build preview.exe, which renders the splash to splash-status.bmp / splash-prompt.bmp without
# starting PlayOnline:  wine preview.exe "C:\path\to\FINAL FANTASY XI\"
# and wintest.exe, which tries the Windows-only parts (platform detection, Credential Manager, the
# setup window):  wintest.exe detect [skip mask] | list | save <slot> <account> <otp> | forget <slot> | setup [slot] | setup-drive <slot> <account> <password>
set -euo pipefail
cd "$(dirname "$0")"
XWIN="${XWIN:-$HOME/.xwin}"
LLVM_BIN="${LLVM_BIN:-/usr/lib/llvm-21/bin}"
PATH="$LLVM_BIN:$PATH" clang-cl --target=i686-pc-windows-msvc /nologo /std:c++20 /O2 /EHsc /MT -w -fuse-ld=lld-link \
    /imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt" /imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared" \
    preview.cpp /link /libpath:"$XWIN/crt/lib/x86" /libpath:"$XWIN/sdk/lib/um/x86" /libpath:"$XWIN/sdk/lib/ucrt/x86" \
    user32.lib gdi32.lib /out:preview.exe
PATH="$LLVM_BIN:$PATH" clang-cl --target=i686-pc-windows-msvc /nologo /std:c++20 /O2 /EHsc /MT -w -fuse-ld=lld-link \
    /imsvc "$XWIN/crt/include" /imsvc "$XWIN/sdk/include/ucrt" /imsvc "$XWIN/sdk/include/um" /imsvc "$XWIN/sdk/include/shared" \
    wintest.cpp /link /libpath:"$XWIN/crt/lib/x86" /libpath:"$XWIN/sdk/lib/um/x86" /libpath:"$XWIN/sdk/lib/ucrt/x86" \
    user32.lib gdi32.lib advapi32.lib comctl32.lib /out:wintest.exe
echo "Built preview/preview.exe and preview/wintest.exe"
