#!/bin/bash
# Parallel Ghidra Analysis Runner
#
# Runs multiple Ghidra headless scripts in parallel to accelerate
# reverse engineering tasks like finding Init functions for all
# prototype managers.
#
# Usage:
#   ./scripts/parallel_ghidra.sh                    # Run all discovery scripts
#   ./scripts/parallel_ghidra.sh find_status_init   # Run specific script
#
# Output:
#   Results are written to /tmp/ghidra_parallel_*.log

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
GHIDRA_SCRIPTS="$PROJECT_DIR/ghidra/scripts"

# Timestamp for this run
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/tmp/ghidra_parallel_$TIMESTAMP"
mkdir -p "$OUTPUT_DIR"

echo "[*] Parallel Ghidra Analysis - $(date)"
echo "[*] Output directory: $OUTPUT_DIR"

# Discovery scripts to run in parallel
SCRIPTS=(
    "find_status_init.py:StatusPrototype::Init:0x1089bdb30"
    "find_passive_init.py:PassivePrototype::Init:0x108aeccd8"
    "find_interrupt_init.py:InterruptPrototype::Init:0x108aecce0"
    "find_boost_init.py:BoostPrototype::Init:0x108991528"
)

# Function to run a single Ghidra script
run_ghidra_script() {
    local script_entry="$1"
    local script_name=$(echo "$script_entry" | cut -d: -f1)
    local description=$(echo "$script_entry" | cut -d: -f2)
    local manager_addr=$(echo "$script_entry" | cut -d: -f3)

    local log_file="$OUTPUT_DIR/${script_name%.py}.log"

    echo "[+] Starting: $description"

    # Check if script exists, if not create a template
    if [[ ! -f "$GHIDRA_SCRIPTS/$script_name" ]]; then
        echo "[*] Creating template script: $script_name"
        cat > "$GHIDRA_SCRIPTS/$script_name" << PYTHON
# Auto-generated Ghidra script for finding $description
# Manager singleton at: $manager_addr
#
# Run with: ./ghidra/scripts/run_analysis.sh $script_name

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompileOptions, DecompInterface
import re

def find_init_function():
    """Find the Init function for the prototype manager."""

    manager_addr = toAddr("$manager_addr")
    print(f"[*] Searching for Init function related to manager at {manager_addr}")

    # Strategy 1: Find XREFs to manager singleton
    refs = getReferencesTo(manager_addr)
    print(f"[*] Found {len(list(refs))} references to manager singleton")

    # Strategy 2: Search for functions with "Init" in decompilation
    # that reference this manager
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    candidates = []
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        name = func.getName()
        # Look for Init-like function names
        if 'Init' in name and ('Prototype' in name or 'Status' in name or
                               'Passive' in name or 'Interrupt' in name or
                               'Boost' in name):
            addr = func.getEntryPoint()
            print(f"  [+] Candidate: {name} at {addr}")
            candidates.append((name, addr))

    # Strategy 3: Pattern scan for ADRP+LDR loading this manager
    print(f"\\n[*] Results:")
    for name, addr in candidates:
        print(f"  {name}: {addr}")

    return candidates

if __name__ == "__main__":
    print("[*] $script_name - Finding $description")
    find_init_function()
PYTHON
    fi

    # Run the script (async)
    "$GHIDRA_SCRIPTS/run_analysis.sh" "$script_name" > "$log_file" 2>&1 &
    echo $!  # Return PID
}

# If specific script requested, run just that one
if [[ -n "$1" ]]; then
    for entry in "${SCRIPTS[@]}"; do
        script_name=$(echo "$entry" | cut -d: -f1)
        if [[ "$script_name" == "$1.py" || "$script_name" == "$1" ]]; then
            echo "[*] Running single script: $script_name"
            run_ghidra_script "$entry"
            wait
            cat "$OUTPUT_DIR/${script_name%.py}.log"
            exit 0
        fi
    done
    echo "[!] Script not found: $1"
    exit 1
fi

# Run all scripts in parallel
echo "[*] Launching ${#SCRIPTS[@]} parallel Ghidra analyses..."
PIDS=()
for entry in "${SCRIPTS[@]}"; do
    pid=$(run_ghidra_script "$entry")
    PIDS+=($pid)
done

echo "[*] Waiting for all analyses to complete..."
echo "[*] PIDs: ${PIDS[*]}"

# Wait for all to complete
for pid in "${PIDS[@]}"; do
    wait $pid 2>/dev/null || true
done

echo ""
echo "[*] All analyses complete. Results:"
echo "========================================"

# Summarize results
for entry in "${SCRIPTS[@]}"; do
    script_name=$(echo "$entry" | cut -d: -f1)
    description=$(echo "$entry" | cut -d: -f2)
    log_file="$OUTPUT_DIR/${script_name%.py}.log"

    echo ""
    echo "### $description ###"
    if [[ -f "$log_file" ]]; then
        # Extract key findings (look for addresses)
        grep -E "(Candidate|Found|Init|0x10[0-9a-f]+)" "$log_file" | head -20
    else
        echo "  (no output)"
    fi
done

echo ""
echo "[*] Full logs in: $OUTPUT_DIR/"
