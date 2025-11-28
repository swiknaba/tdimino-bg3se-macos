#!/bin/bash
#
# Build Lua 5.4 as a universal static library for macOS
#

set -e

cd "$(dirname "$0")/src"

# Core Lua library sources (exclude lua.c and luac.c which are executables)
LUA_CORE="lapi.c lcode.c lctype.c ldebug.c ldo.c ldump.c lfunc.c lgc.c llex.c \
lmem.c lobject.c lopcodes.c lparser.c lstate.c lstring.c ltable.c \
ltm.c lundump.c lvm.c lzio.c"

LUA_LIB="lauxlib.c lbaselib.c lcorolib.c ldblib.c liolib.c \
lmathlib.c loadlib.c loslib.c lstrlib.c ltablib.c lutf8lib.c linit.c"

ALL_SOURCES="$LUA_CORE $LUA_LIB"

echo "Building Lua 5.4 universal static library..."

# Build for ARM64
echo "  Compiling for ARM64..."
mkdir -p ../build-arm64
for src in $ALL_SOURCES; do
    clang -c -arch arm64 -O2 -Wall -DLUA_USE_MACOSX -DLUA_USE_READLINE $src -o ../build-arm64/${src%.c}.o
done
ar rcs ../build-arm64/liblua.a ../build-arm64/*.o

# Build for x86_64
echo "  Compiling for x86_64..."
mkdir -p ../build-x86_64
for src in $ALL_SOURCES; do
    clang -c -arch x86_64 -O2 -Wall -DLUA_USE_MACOSX -DLUA_USE_READLINE $src -o ../build-x86_64/${src%.c}.o
done
ar rcs ../build-x86_64/liblua.a ../build-x86_64/*.o

# Create universal library
echo "  Creating universal library..."
cd ..
lipo -create build-arm64/liblua.a build-x86_64/liblua.a -output liblua-universal.a

echo ""
echo "Build complete!"
file liblua-universal.a
echo ""
echo "Size: $(ls -lh liblua-universal.a | awk '{print $5}')"
