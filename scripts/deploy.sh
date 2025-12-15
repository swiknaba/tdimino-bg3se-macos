#!/bin/bash
# Auto-deploy libbg3se.dylib to Steam folder after build

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DYLIB="$PROJECT_DIR/build/lib/libbg3se.dylib"
STEAM_DIR="$HOME/Library/Application Support/Steam/steamapps/common/Baldurs Gate 3"
STEAM_DYLIB="$STEAM_DIR/libbg3se.dylib"

if [[ ! -f "$BUILD_DYLIB" ]]; then
    echo "Error: Build dylib not found at $BUILD_DYLIB"
    exit 1
fi

if [[ ! -d "$STEAM_DIR" ]]; then
    echo "Error: Steam BG3 folder not found at $STEAM_DIR"
    exit 1
fi

# Compare timestamps
if [[ -f "$STEAM_DYLIB" ]]; then
    BUILD_TIME=$(stat -f %m "$BUILD_DYLIB")
    STEAM_TIME=$(stat -f %m "$STEAM_DYLIB")

    if [[ "$BUILD_TIME" -le "$STEAM_TIME" ]]; then
        echo "Steam dylib is up to date"
        exit 0
    fi
fi

cp "$BUILD_DYLIB" "$STEAM_DYLIB"
echo "Deployed: $(ls -lh "$STEAM_DYLIB" | awk '{print $5, $6, $7, $8}')"
