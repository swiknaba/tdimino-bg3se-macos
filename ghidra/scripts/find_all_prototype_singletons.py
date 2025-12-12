# Find All Prototype Manager Singletons
# Searches for ADRP+LDR patterns that load global pointers in manager address range
#
# Run: ./ghidra/scripts/run_analysis.sh find_all_prototype_singletons.py

from progress_utils import init_progress, progress, finish_progress
import time

start_time = time.time()
init_progress("Prototype Manager Singleton Search")

# Known addresses from previous analysis
KNOWN_GLOBALS = {
    0x1089c5730: "RPGStats::m_ptr",
    0x108aeccd8: "PassivePrototypeManager* (candidate)",
}

# Address ranges to search for singletons
# Based on PassivePrototypeManager being at 0x108aeccd8
SINGLETON_RANGES = [
    (0x108ae0000, 0x108af0000),  # Near PassivePrototypeManager
    (0x1089c0000, 0x1089d0000),  # Near RPGStats
]

# Functions that likely use prototype managers
SEARCH_FUNCTIONS = [
    ("SpellPrototypeManager", [
        "GetSpellPrototype",
        "SpellPrototype::Init",
        "RegisterSpell",
    ]),
    ("StatusPrototypeManager", [
        "GetStatusPrototype",
        "StatusPrototype::Init",
        "RegisterStatus",
    ]),
    ("InterruptPrototypeManager", [
        "HasInterruptWithContext",  # 0x101b93338
        "EvaluateInterrupt",        # 0x101b94278
        "GetInterruptPrototype",
    ]),
    ("PassivePrototypeManager", [
        "GetPassivePrototype",      # 0x102655c14
        "GetPassivePrototypes",     # 0x102014284
        "PassivePrototype::Init",
    ]),
]

def search_adrp_in_function(func_addr, target_ranges):
    """Search for ADRP instructions pointing to target ranges"""
    results = []

    func = getFunctionAt(toAddr(func_addr))
    if not func:
        return results

    listing = currentProgram.getListing()
    body = func.getBody()

    addr_iter = body.getAddresses(True)
    while addr_iter.hasNext():
        addr = addr_iter.next()
        inst = listing.getInstructionAt(addr)
        if inst is None:
            continue

        mnem = inst.getMnemonicString()
        if mnem == 'adrp':
            # Extract the page address from ADRP
            try:
                ops = inst.getOpObjects(1)
                if ops:
                    page_addr = ops[0].getValue()
                    # Check if in target range
                    for range_start, range_end in target_ranges:
                        if range_start <= page_addr < range_end:
                            # Look for following LDR
                            next_addr = inst.getNext()
                            if next_addr:
                                next_inst = listing.getInstructionAt(next_addr.getAddress())
                                if next_inst and next_inst.getMnemonicString() == 'ldr':
                                    results.append({
                                        'adrp_addr': addr.getOffset(),
                                        'page': page_addr,
                                        'adrp': str(inst),
                                        'ldr_addr': next_addr.getAddress().getOffset(),
                                        'ldr': str(next_inst),
                                    })
            except:
                pass

    return results

def search_by_symbol_patterns():
    """Search symbol table for prototype manager patterns"""
    progress("Searching symbol table for prototype patterns...")

    results = {}
    symbol_table = currentProgram.getSymbolTable()

    patterns = [
        "SpellPrototypeManager",
        "StatusPrototypeManager",
        "InterruptPrototypeManager",
        "PassivePrototypeManager",
        "BoostPrototypeManager",
        "GetSpellPrototype",
        "GetStatusPrototype",
        "GetPassivePrototype",
        "GetInterruptPrototype",
        "SyncStat",
        "eoc__g",  # Global singleton pattern
    ]

    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        for pattern in patterns:
            if pattern.lower() in name.lower():
                if pattern not in results:
                    results[pattern] = []
                results[pattern].append({
                    'name': name,
                    'address': sym.getAddress().getOffset(),
                    'type': str(sym.getSymbolType()),
                })
                break

    return results

def analyze_known_functions():
    """Analyze known prototype functions for singleton patterns"""
    progress("Analyzing known prototype functions...")

    # Known function addresses from MULTI_ISSUE.md
    known_funcs = {
        "GetPassivePrototype": 0x102655c14,
        "GetPassivePrototypes": 0x102014284,
        "HasInterruptWithContext": 0x101b93338,
        "EvaluateInterrupt": 0x101b94278,
    }

    results = {}
    for name, addr in known_funcs.items():
        progress("  Analyzing {}...".format(name))
        adrp_patterns = search_adrp_in_function(addr, SINGLETON_RANGES)
        if adrp_patterns:
            results[name] = {
                'address': addr,
                'adrp_patterns': adrp_patterns,
            }

    return results

def search_for_global_pointers():
    """Search data sections for potential singleton pointers"""
    progress("Searching data sections for global pointers...")

    results = []
    memory = currentProgram.getMemory()
    ref_mgr = currentProgram.getReferenceManager()

    # Search in .data and .bss sections
    for block in memory.getBlocks():
        block_name = block.getName()
        if block_name in ['.data', '__DATA', '__bss', '.bss']:
            progress("  Scanning {}...".format(block_name))
            start = block.getStart()
            end = block.getEnd()

            # Look for addresses in prototype manager range
            addr = start
            count = 0
            while addr.compareTo(end) < 0 and count < 10000:
                # Check references TO this address
                refs = ref_mgr.getReferencesTo(addr)
                ref_count = 0
                for ref in refs:
                    ref_count += 1
                    if ref_count > 0:
                        # This address is referenced - check if in our target range
                        addr_val = addr.getOffset()
                        for range_start, range_end in SINGLETON_RANGES:
                            if range_start <= addr_val < range_end:
                                results.append({
                                    'address': addr_val,
                                    'section': block_name,
                                    'ref_count': ref_count,
                                })
                                break
                        break

                addr = addr.add(8)
                count += 1

    return results

def main():
    output = []
    output.append("# All Prototype Manager Singletons Discovery\n")
    output.append("**Date:** {}\n".format(time.strftime('%Y-%m-%d %H:%M')))
    output.append("---\n\n")

    # 1. Search known functions
    output.append("## Known Function Analysis\n\n")
    func_results = analyze_known_functions()

    for name, data in func_results.items():
        output.append("### {}\n".format(name))
        output.append("- Address: `0x{:x}`\n".format(data['address']))
        output.append("- ADRP patterns found: {}\n\n".format(len(data['adrp_patterns'])))

        if data['adrp_patterns']:
            output.append("| Page Address | Calculated Global | ADRP | LDR |\n")
            output.append("|--------------|-------------------|------|-----|\n")
            for p in data['adrp_patterns'][:10]:
                # Try to calculate actual global address
                ldr_str = p['ldr']
                offset = 0
                # Extract offset from LDR instruction like "ldr x8,[x8, #0xcd8]"
                if '#0x' in ldr_str:
                    try:
                        offset_str = ldr_str.split('#0x')[1].split(']')[0]
                        offset = int(offset_str, 16)
                    except:
                        pass
                global_addr = p['page'] + offset

                # Check if known
                known_name = KNOWN_GLOBALS.get(global_addr, "")

                output.append("| `0x{:x}` | `0x{:x}` {} | {} | {} |\n".format(
                    p['page'], global_addr, known_name, p['adrp'], p['ldr']))
        output.append("\n")

    # 2. Symbol search
    output.append("## Symbol Table Results\n\n")
    symbol_results = search_by_symbol_patterns()

    for pattern, symbols in symbol_results.items():
        if symbols:
            output.append("### {}\n".format(pattern))
            output.append("| Name | Address | Type |\n")
            output.append("|------|---------|------|\n")
            for sym in symbols[:10]:
                output.append("| `{}` | `0x{:x}` | {} |\n".format(
                    sym['name'][:60], sym['address'], sym['type']))
            output.append("\n")

    # 3. Summary
    output.append("## Summary\n\n")
    output.append("### Confirmed Singleton Addresses\n\n")
    output.append("| Manager | Global Address | Source |\n")
    output.append("|---------|----------------|--------|\n")
    for addr, name in KNOWN_GLOBALS.items():
        output.append("| {} | `0x{:x}` | Known |\n".format(name, addr))

    # Add newly discovered from analysis
    for name, data in func_results.items():
        for p in data['adrp_patterns']:
            ldr_str = p['ldr']
            offset = 0
            if '#0x' in ldr_str:
                try:
                    offset_str = ldr_str.split('#0x')[1].split(']')[0]
                    offset = int(offset_str, 16)
                except:
                    pass
            global_addr = p['page'] + offset
            if global_addr not in KNOWN_GLOBALS:
                output.append("| From {} | `0x{:x}` | ADRP+LDR |\n".format(name, global_addr))

    duration = time.time() - start_time
    output.append("\n**Duration:** {:.1f} seconds\n".format(duration))

    # Write output
    output_path = "/tmp/all_prototype_singletons.md"
    with open(output_path, 'w') as f:
        f.writelines(output)

    print("Results written to {}".format(output_path))
    finish_progress()

if __name__ == "__main__":
    main()
