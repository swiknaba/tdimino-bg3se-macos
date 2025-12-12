# Find Prototype Manager Singleton Patterns
# Analyzes GetPassivePrototype and similar functions to discover singleton pointer locations
#
# Run: ./ghidra/scripts/run_analysis.sh find_prototype_manager_singletons.py

from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SymbolType
from progress_utils import init_progress, progress, finish_progress

import time

start_time = time.time()
init_progress("Prototype Manager Singleton Discovery")

# Known function addresses from MULTI_ISSUE.md
KNOWN_FUNCTIONS = {
    "GetPassivePrototype": 0x102655c14,
    "GetPassivePrototypes": 0x102014284,
    "HasInterruptWithContext": 0x101b93338,
    "EvaluateInterrupt": 0x101b94278,
    "~InterruptPrototypeManager": 0x101b96610,
    "~InterruptPrototype": 0x101b95af4,
}

# Track discovered singletons
discovered_singletons = []

def get_instructions_at(addr, count=50):
    """Get instructions starting at address"""
    instructions = []
    listing = currentProgram.getListing()
    current = addr
    for i in range(count):
        inst = listing.getInstructionAt(current)
        if inst is None:
            break
        instructions.append({
            'addr': current,
            'mnemonic': inst.getMnemonicString(),
            'operands': [str(inst.getOpObjects(j)[0]) if inst.getOpObjects(j) else ""
                        for j in range(inst.getNumOperands())],
            'full': str(inst)
        })
        current = inst.getNext().getAddress() if inst.getNext() else None
        if current is None:
            break
    return instructions

def find_adrp_ldr_pattern(instructions):
    """Find ADRP+LDR patterns that load global pointers"""
    patterns = []
    for i, inst in enumerate(instructions):
        if inst['mnemonic'] == 'adrp':
            # Look for LDR in next few instructions using same register
            reg = inst['operands'][0] if inst['operands'] else None
            if reg:
                for j in range(i+1, min(i+5, len(instructions))):
                    next_inst = instructions[j]
                    if next_inst['mnemonic'] == 'ldr':
                        # Check if it uses the ADRP result
                        if reg in next_inst['full']:
                            patterns.append({
                                'adrp_addr': inst['addr'],
                                'ldr_addr': next_inst['addr'],
                                'register': reg,
                                'adrp': inst['full'],
                                'ldr': next_inst['full']
                            })
    return patterns

def analyze_function(name, addr):
    """Analyze a function for singleton access patterns"""
    progress("Analyzing {} at 0x{:x}".format(name, addr))

    func_addr = toAddr(addr)
    func = getFunctionAt(func_addr)

    results = {
        'name': name,
        'address': addr,
        'function_found': func is not None,
        'adrp_patterns': [],
        'global_refs': [],
        'decompiled': None
    }

    if func:
        results['func_name'] = func.getName()
        results['func_size'] = func.getBody().getNumAddresses()

        # Get instructions
        instructions = get_instructions_at(func_addr, 100)

        # Find ADRP+LDR patterns
        patterns = find_adrp_ldr_pattern(instructions)
        results['adrp_patterns'] = patterns

        # Try to get decompiled output
        try:
            from ghidra.app.decompiler import DecompInterface
            decomp = DecompInterface()
            decomp.openProgram(currentProgram)
            decomp_results = decomp.decompileFunction(func, 30, monitor)
            if decomp_results.decompileCompleted():
                results['decompiled'] = decomp_results.getDecompiledFunction().getC()
        except Exception as e:
            results['decompiled_error'] = str(e)

    return results

def search_for_manager_symbols():
    """Search for prototype manager symbols in symbol table"""
    progress("Searching for prototype manager symbols...")

    manager_symbols = []
    symbol_table = currentProgram.getSymbolTable()

    # Search patterns
    patterns = [
        "PrototypeManager",
        "SpellPrototype",
        "StatusPrototype",
        "PassivePrototype",
        "InterruptPrototype",
        "BoostPrototype",
        "m_ptr",
        "gSpell",
        "gStatus",
        "gPassive",
        "gInterrupt"
    ]

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        for pattern in patterns:
            if pattern.lower() in name.lower():
                manager_symbols.append({
                    'name': name,
                    'address': sym.getAddress().getOffset(),
                    'type': str(sym.getSymbolType()),
                    'namespace': str(sym.getParentNamespace())
                })
                break

    return manager_symbols

def search_data_references():
    """Search for data references that might be singleton pointers"""
    progress("Searching for global data references...")

    # Look in .data and .bss sections for potential manager pointers
    data_refs = []

    # Common singleton address ranges (from previous analysis)
    # RPGStats::m_ptr was at 0x1089c5730
    # Look in similar address range for other managers
    search_ranges = [
        (0x1089c0000, 0x108a00000),  # Near RPGStats
        (0x108900000, 0x108a00000),  # Broader range
    ]

    memory = currentProgram.getMemory()
    for start, end in search_ranges:
        start_addr = toAddr(start)
        end_addr = toAddr(end)

        # Check if range exists
        block = memory.getBlock(start_addr)
        if block is None:
            continue

        # Look for references to this range from code
        ref_mgr = currentProgram.getReferenceManager()
        current = start_addr
        while current.getOffset() < end:
            refs = ref_mgr.getReferencesTo(current)
            for ref in refs:
                if ref.getReferenceType().isData():
                    data_refs.append({
                        'target': current.getOffset(),
                        'from': ref.getFromAddress().getOffset(),
                        'type': str(ref.getReferenceType())
                    })
            current = current.add(8)  # Move by pointer size

    return data_refs

def main():
    output_lines = []
    output_lines.append("# Prototype Manager Singleton Discovery Results\n")
    output_lines.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output_lines.append("---\n")

    # 1. Analyze known functions
    output_lines.append("## Function Analysis\n")

    for name, addr in KNOWN_FUNCTIONS.items():
        results = analyze_function(name, addr)

        output_lines.append("### {}\n".format(name))
        output_lines.append("- **Address:** `0x{:x}`\n".format(addr))
        output_lines.append("- **Function found:** {}\n".format(results['function_found']))

        if results['function_found']:
            output_lines.append("- **Function name:** `{}`\n".format(results.get('func_name', 'N/A')))
            output_lines.append("- **Size:** {} bytes\n".format(results.get('func_size', 'N/A')))

            if results['adrp_patterns']:
                output_lines.append("\n**ADRP+LDR Patterns (potential singleton loads):**\n")
                for p in results['adrp_patterns']:
                    output_lines.append("```\n")
                    output_lines.append("0x{:x}: {}\n".format(p['adrp_addr'].getOffset(), p['adrp']))
                    output_lines.append("0x{:x}: {}\n".format(p['ldr_addr'].getOffset(), p['ldr']))
                    output_lines.append("```\n")

            if results.get('decompiled'):
                # Truncate decompiled output
                decomp = results['decompiled']
                if len(decomp) > 2000:
                    decomp = decomp[:2000] + "\n... (truncated)"
                output_lines.append("\n**Decompiled (partial):**\n```c\n{}\n```\n".format(decomp))

        output_lines.append("\n---\n")

    # 2. Search for manager symbols
    output_lines.append("## Symbol Table Search\n")
    symbols = search_for_manager_symbols()

    if symbols:
        output_lines.append("| Name | Address | Type | Namespace |\n")
        output_lines.append("|------|---------|------|----------|\n")
        for sym in symbols[:50]:  # Limit output
            output_lines.append("| `{}` | `0x{:x}` | {} | {} |\n".format(
                sym['name'], sym['address'], sym['type'], sym['namespace']))
    else:
        output_lines.append("No prototype manager symbols found in symbol table.\n")

    output_lines.append("\n---\n")

    # 3. Summary
    output_lines.append("## Summary\n")
    output_lines.append("- Functions analyzed: {}\n".format(len(KNOWN_FUNCTIONS)))
    output_lines.append("- Symbols found: {}\n".format(len(symbols)))

    # Calculate duration
    duration = time.time() - start_time
    output_lines.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    # Write output
    output_path = "/tmp/prototype_manager_singletons.md"
    with open(output_path, 'w') as f:
        f.writelines(output_lines)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
