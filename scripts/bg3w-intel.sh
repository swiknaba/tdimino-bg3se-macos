#!/bin/bash
# BG3SE-macOS Steam Launch Script (Intel/Rosetta)
# Steam launch options: /path/to/bg3se-macos/scripts/bg3w-intel.sh %command%
#
# NOTE: This runs the game under Rosetta (x86_64). The Ghidra offsets are for ARM64,
# so most advanced features (Entity system, component access) will NOT work.
# Use bg3w.sh (ARM64) for full functionality.
#
# Steam passes the .app bundle path, but we need to run the actual executable
# inside Contents/MacOS/ for DYLD_INSERT_LIBRARIES to work.

# Get script directory (works even when called via symlink or absolute path)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Debug output
echo "=== BG3W Launch Script (Intel) ===" >> /tmp/bg3w_debug.log
echo "Date: $(date)" >> /tmp/bg3w_debug.log
echo "Script dir: $SCRIPT_DIR" >> /tmp/bg3w_debug.log
echo "Project root: $PROJECT_ROOT" >> /tmp/bg3w_debug.log
echo "Args: $@" >> /tmp/bg3w_debug.log

# Get the first argument (should be the .app bundle path)
APP_PATH="$1"
shift  # Remove first arg, keep any additional args

# If it's a .app bundle, extract the actual executable
if [[ "$APP_PATH" == *.app ]]; then
    EXEC_PATH="${APP_PATH}/Contents/MacOS/Baldur's Gate 3"
    echo "Detected .app bundle, using executable: $EXEC_PATH" >> /tmp/bg3w_debug.log
else
    EXEC_PATH="$APP_PATH"
    echo "Using path directly: $EXEC_PATH" >> /tmp/bg3w_debug.log
fi

# Verify executable exists
if [[ ! -f "$EXEC_PATH" ]]; then
    echo "ERROR: Executable not found: $EXEC_PATH" >> /tmp/bg3w_debug.log
    exit 1
fi

# Find dylib relative to script location
DYLIB="${PROJECT_ROOT}/build/lib/libbg3se.dylib"

if [[ ! -f "$DYLIB" ]]; then
    echo "ERROR: libbg3se.dylib not found at: $DYLIB" >> /tmp/bg3w_debug.log
    echo "ERROR: Build it first with: cd build && cmake .. && cmake --build ." >> /tmp/bg3w_debug.log
    exit 1
fi

echo "DYLIB: $DYLIB" >> /tmp/bg3w_debug.log
echo "Forcing x86_64 (Rosetta) architecture with inline DYLD_INSERT_LIBRARIES" >> /tmp/bg3w_debug.log
echo "===========================" >> /tmp/bg3w_debug.log

# Force x86_64 (Rosetta) architecture with inline env var
exec arch -x86_64 env DYLD_INSERT_LIBRARIES="$DYLIB" "$EXEC_PATH" "$@"
