#!/usr/bin/env python3
"""
trace_dowork_update.py - Trace from DoWork to find Update function

Based on RE findings:
- ecl::GameStateThreaded::GameStateWorker::DoWork @ 0x102fd9c34
- This calls a virtual function at vtable offset 0x90
- That virtual function is likely GameStateMachine::Update(GameTime*)

This script:
1. Decompiles the known DoWork function
2. Finds the vtable call at offset 0x90
3. Traces to find what function is being called
4. Analyzes that function for GameTime struct access

Run in Ghidra's Script Manager.
"""

# @category BG3SE
# @author bg3se-macos

from ghidra.program.model.symbol import SymbolType
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSet
import re

DOWORK_ADDRESS = 0x102fd9c34  # ecl::GameStateThreaded::GameStateWorker::DoWork

def get_decompiled(func):
    """Decompile a function and return the C code."""
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    result = decomp.decompileFunction(func, 30, monitor)
    if result and result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def analyze_dowork():
    """Analyze the DoWork function to find the Update call."""
    print("=" * 60)
    print("Analyzing DoWork @ 0x{:x}".format(DOWORK_ADDRESS))
    print("=" * 60)

    fm = currentProgram.getFunctionManager()
    addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(DOWORK_ADDRESS)
    func = fm.getFunctionAt(addr)

    if not func:
        print("ERROR: Could not find function at 0x{:x}".format(DOWORK_ADDRESS))
        return None

    code = get_decompiled(func)
    if not code:
        print("ERROR: Could not decompile function")
        return None

    print("\nDecompiled code:")
    print("-" * 40)
    print(code[:2000])  # First 2000 chars
    print("-" * 40)

    # Look for vtable call pattern
    # In the decompilation we saw: (**(code **)(*plVar6 + 0x90))();
    vtable_match = re.search(r'\(\*\*\(code\s*\*\*\)\s*\(\s*\*?\w+\s*\+\s*0x90\s*\)\s*\)', code)
    if vtable_match:
        print("\nFound vtable+0x90 call: {}".format(vtable_match.group()))
        print("This is the Update virtual function call!")

    return code

def find_gamestatemachine_vtable():
    """
    Search for GameStateMachine vtable to find Update implementation.
    Virtual function at offset 0x90 / 8 = slot 18 in vtable.
    """
    print("\n" + "=" * 60)
    print("Searching for GameStateMachine vtables...")
    print("=" * 60)

    # Look for symbols containing GameStateMachine
    st = currentProgram.getSymbolTable()
    symbols = st.getSymbolIterator()

    vtables = []
    for sym in symbols:
        name = sym.getName()
        if 'GameStateMachine' in name and ('vtable' in name.lower() or 'vftable' in name.lower() or '::' in name):
            print("Found symbol: {} @ 0x{:x}".format(name, sym.getAddress().getOffset()))
            vtables.append(sym)

    return vtables

def find_update_by_xref():
    """
    Alternative: Find functions that are called with GameTime-like parameters.
    Look for callers that pass a struct with the right layout.
    """
    print("\n" + "=" * 60)
    print("Searching for Update candidates by parameter patterns...")
    print("=" * 60)

    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    candidates = []

    for func in funcs:
        name = func.getName()

        # Skip uninteresting functions
        if func.getParameterCount() != 2:
            continue

        # Quick name filter
        if not any(kw in name for kw in ['Update', 'Tick', 'Step', 'Process', 'Loop']):
            continue

        code = get_decompiled(func)
        if not code:
            continue

        # Look for GameTime field access patterns
        score = 0

        # Pattern 1: Access to param_2 with specific offsets
        if 'param_2' in code:
            # +0x00 double (Time)
            if re.search(r'\*\(double\s*\*\)\s*param_2', code):
                score += 3
            # +0x08 float (DeltaTime)
            if re.search(r'\*\(float\s*\*\)\s*\(\s*param_2\s*\+\s*8\s*\)', code):
                score += 3
            # +0x0C int (Ticks)
            if re.search(r'\*\(int\s*\*\)\s*\(\s*param_2\s*\+\s*0xc\s*\)', code):
                score += 3

        if score > 0:
            candidates.append((score, func, name))
            print("Candidate: {} @ 0x{:x} (score: {})".format(
                name, func.getEntryPoint().getOffset(), score))

    return candidates

def find_state_machine_members():
    """
    Find member functions of GameStateMachine class by looking
    at functions near the destructor we found.
    """
    print("\n" + "=" * 60)
    print("Analyzing GameStateMachine class structure...")
    print("=" * 60)

    # Known destructor addresses from earlier search
    destructor_addrs = [0x102fd9b2c, 0x102fd9b84]  # ~GameStateWorker

    fm = currentProgram.getFunctionManager()

    for dtor_addr in destructor_addrs:
        addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(dtor_addr)
        func = fm.getFunctionAt(addr)
        if func:
            print("\nDestructor: {} @ 0x{:x}".format(func.getName(), dtor_addr))

            # Look at functions in nearby address range (same class likely nearby)
            start = dtor_addr - 0x1000
            end = dtor_addr + 0x2000

            nearby = []
            all_funcs = fm.getFunctions(True)
            for f in all_funcs:
                faddr = f.getEntryPoint().getOffset()
                if start <= faddr <= end:
                    nearby.append((faddr, f.getName()))

            nearby.sort()
            print("\nNearby functions:")
            for faddr, fname in nearby[:30]:
                print("  0x{:x}: {}".format(faddr, fname))

def main():
    print("\n" + "=" * 60)
    print("BG3SE macOS - DoWork -> Update Tracer")
    print("=" * 60 + "\n")

    # Step 1: Analyze the known DoWork function
    analyze_dowork()

    # Step 2: Look for GameStateMachine vtables
    find_gamestatemachine_vtable()

    # Step 3: Find Update candidates by parameter patterns
    find_update_by_xref()

    # Step 4: Analyze class structure
    find_state_machine_members()

    print("\n" + "=" * 60)
    print("Analysis Complete")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Set breakpoint at DoWork (0x{:x})".format(DOWORK_ADDRESS))
    print("2. Step through to the vtable+0x90 call")
    print("3. Note the actual function address being called")
    print("4. Analyze that function for GameTime parameter usage")

if __name__ == "__main__":
    main()
