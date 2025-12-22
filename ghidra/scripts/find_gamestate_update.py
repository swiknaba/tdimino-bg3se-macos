#!/usr/bin/env python3
"""
find_gamestate_update.py - Find GameStateMachine::Update candidates

This script searches for functions that match the signature pattern of
GameStateMachine::Update(void* self, GameTime* time).

GameTime struct (from Windows BG3SE):
    double Time;      // 0x00: Total time in seconds
    float DeltaTime;  // 0x08: Frame delta time
    int32_t Ticks;    // 0x0C: Tick count
    double Unknown;   // 0x10: Unknown field
    Total size: 24 bytes (0x18)

The function should:
1. Take 2 parameters (self + GameTime*)
2. Be a virtual function (called through vtable)
3. Access fields at offsets 0x00, 0x08, 0x0C from second parameter
4. Be called frequently (game loop)

Run in Ghidra's Script Manager or via analyzeHeadless.
"""

# @category BG3SE
# @author bg3se-macos

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
import re

def get_decompiled(func):
    """Decompile a function and return the C code."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 30, monitor)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def analyze_function_for_gametime(func):
    """
    Check if function accesses GameTime-like struct patterns.
    Returns a score (higher = more likely to be GameStateMachine::Update).
    """
    code = get_decompiled(func)
    if not code:
        return 0, []

    score = 0
    evidence = []

    # Check for double access at offset 0x00 (Time field)
    if re.search(r'\*\(double\s*\*\)\s*\w+', code) or re.search(r'param_2\s*\+\s*0x0', code):
        score += 2
        evidence.append("double access (Time field)")

    # Check for float access at offset 0x08 (DeltaTime field)
    if re.search(r'\*\(float\s*\*\)\s*\(\s*\w+\s*\+\s*0x8\s*\)', code) or re.search(r'param_2\s*\+\s*8', code):
        score += 3
        evidence.append("float at +0x8 (DeltaTime)")

    # Check for int32 access at offset 0x0C (Ticks field)
    if re.search(r'\*\(int\s*\*\)\s*\(\s*\w+\s*\+\s*0xc\s*\)', code) or re.search(r'param_2\s*\+\s*0xc', code):
        score += 3
        evidence.append("int32 at +0xC (Ticks)")

    # Check for GameTime in demangled name
    if 'GameTime' in func.getName() or 'GameTime' in code:
        score += 5
        evidence.append("GameTime in name/code")

    # Check for GameStateMachine reference
    if 'GameStateMachine' in func.getName() or 'GameStateMachine' in code:
        score += 5
        evidence.append("GameStateMachine reference")

    # Check for Update in name
    if 'Update' in func.getName():
        score += 2
        evidence.append("Update in name")

    # Check parameter count (should be 2: self, GameTime*)
    params = func.getParameterCount()
    if params == 2:
        score += 2
        evidence.append("2 parameters")

    return score, evidence

def find_candidates():
    """Find GameStateMachine::Update candidates."""
    print("=" * 60)
    print("Searching for GameStateMachine::Update candidates...")
    print("=" * 60)

    candidates = []

    # Get all functions
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    count = 0
    for func in funcs:
        count += 1
        if count % 1000 == 0:
            print("  Analyzed {} functions...".format(count))

        name = func.getName()

        # Quick filter: look for relevant names
        if any(keyword in name for keyword in ['Update', 'Tick', 'GameState', 'DoWork']):
            score, evidence = analyze_function_for_gametime(func)
            if score > 0:
                candidates.append((score, func, evidence))

    # Sort by score (descending)
    candidates.sort(key=lambda x: -x[0])

    print("\n" + "=" * 60)
    print("Top candidates (by score):")
    print("=" * 60)

    for score, func, evidence in candidates[:20]:
        print("\n[Score: {}] {} @ 0x{:x}".format(score, func.getName(), func.getEntryPoint().getOffset()))
        print("  Evidence: {}".format(", ".join(evidence)))

    return candidates

def search_for_virtual_update():
    """
    Search for virtual functions that could be Update calls.
    In C++, virtual Update(GameTime*) would be at a consistent vtable offset.
    """
    print("\n" + "=" * 60)
    print("Searching for virtual Update patterns...")
    print("=" * 60)

    # Look for functions that call through vtable + common offset
    # GameStateMachine::Update is typically at vtable offset 0x90 based on DoWork decompilation

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    vtable_calls = []

    for func in funcs:
        name = func.getName()
        if 'DoWork' in name or 'GameStateWorker' in name:
            code = get_decompiled(func)
            if code:
                # Look for vtable calls at offset 0x90
                if '+0x90' in code or '+ 0x90' in code:
                    print("\nFound vtable+0x90 call in: {} @ 0x{:x}".format(
                        name, func.getEntryPoint().getOffset()))
                    # Extract the call target if possible
                    vtable_calls.append((func, code))

    return vtable_calls

def main():
    print("\n" + "=" * 60)
    print("BG3SE macOS - GameStateMachine::Update Finder")
    print("=" * 60 + "\n")

    # Method 1: Search by function characteristics
    candidates = find_candidates()

    # Method 2: Search for virtual Update calls from DoWork
    vtable_calls = search_for_virtual_update()

    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print("Found {} potential candidates".format(len(candidates)))
    print("Found {} DoWork functions with vtable+0x90 calls".format(len(vtable_calls)))
    print("\nManual inspection recommended for top candidates.")
    print("Look for functions that:")
    print("  1. Access param_2 as a 24-byte struct")
    print("  2. Read double at +0x00, float at +0x08, int32 at +0x0C")
    print("  3. Are called from game loop / DoWork")

if __name__ == "__main__":
    main()
