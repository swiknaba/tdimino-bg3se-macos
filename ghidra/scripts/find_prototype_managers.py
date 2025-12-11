# Find Prototype Manager singletons and Init functions
# These are needed for Ext.Stats.Sync() to update game caches
#
# Targets:
# - eoc::SpellPrototypeManager singleton
# - eoc::SpellPrototype::Init function
# - eoc::StatusPrototypeManager singleton
# - eoc::StatusPrototype::Init function
# - eoc::PassivePrototypeManager singleton
# - eoc::PassivePrototype::Init function
# - eoc::InterruptPrototypeManager singleton
# - eoc::InterruptPrototype::Init function

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.data import *
import re

def log(msg):
    print("[PrototypeMgr] %s" % msg)

def find_string_refs(search_str):
    """Find data references to a string"""
    results = []
    listing = currentProgram.getListing()
    memory = currentProgram.getMemory()

    # Search for the string in data
    data_iter = listing.getDefinedData(True)
    while data_iter.hasNext():
        data = data_iter.next()
        if data.hasStringValue():
            try:
                val = data.getValue()
                if val and search_str in str(val):
                    results.append(data.getAddress())
            except:
                pass
    return results

def find_string_address(search_str):
    """Search memory for a string and return its address"""
    memory = currentProgram.getMemory()
    search_bytes = search_str.encode('utf-8') + b'\x00'

    # Search in all memory blocks
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        start = block.getStart()
        end = block.getEnd()

        addr = memory.findBytes(start, end, search_bytes, None, True, monitor)
        if addr:
            return addr
    return None

def find_xrefs_to(addr):
    """Find all references to an address"""
    refs = []
    ref_mgr = currentProgram.getReferenceManager()
    ref_iter = ref_mgr.getReferencesTo(addr)
    while ref_iter.hasNext():
        ref = ref_iter.next()
        refs.append(ref.getFromAddress())
    return refs

def get_function_at(addr):
    """Get function containing address"""
    fm = currentProgram.getFunctionManager()
    return fm.getFunctionContaining(addr)

def analyze_prototype_manager(name, type_strings):
    """Analyze a prototype manager by searching for type-related strings"""
    log("=== Searching for %s ===" % name)

    for type_str in type_strings:
        log("Looking for string: '%s'" % type_str)

        # Find string in memory
        str_addr = find_string_address(type_str)
        if str_addr:
            log("  Found string at: %s" % str_addr)

            # Find code references to this string
            xrefs = find_xrefs_to(str_addr)
            log("  XREFs: %d" % len(xrefs))

            for xref in xrefs[:5]:  # Limit to first 5
                func = get_function_at(xref)
                if func:
                    log("    %s in function: %s @ %s" % (xref, func.getName(), func.getEntryPoint()))
                else:
                    log("    %s (no function)" % xref)
        else:
            log("  String not found")

def find_init_candidates():
    """Find functions that might be prototype Init functions by name patterns"""
    log("\n=== Searching for Init function candidates ===")

    fm = currentProgram.getFunctionManager()
    patterns = [
        "SpellPrototype",
        "StatusPrototype",
        "PassivePrototype",
        "InterruptPrototype",
        "PrototypeManager",
        "Prototype::Init",
        "Prototype__Init"
    ]

    func_iter = fm.getFunctions(True)
    found = []
    while func_iter.hasNext():
        func = func_iter.next()
        name = func.getName()
        for pattern in patterns:
            if pattern.lower() in name.lower():
                found.append((name, func.getEntryPoint()))
                break

    if found:
        log("Found %d candidates:" % len(found))
        for name, addr in sorted(found, key=lambda x: x[0]):
            log("  %s @ %s" % (name, addr))
    else:
        log("No candidates found by name")

def find_spell_type_usage():
    """Search for SpellType enum usage - Init functions parse this"""
    log("\n=== Searching for SpellType enum usage ===")

    # SpellType values that Init functions read
    spell_types = ["Zone", "MultiStrike", "Projectile", "Rush", "Shout", "Target", "Wall"]

    for spell_type in spell_types:
        str_addr = find_string_address(spell_type)
        if str_addr:
            log("Found '%s' at %s" % (spell_type, str_addr))
            xrefs = find_xrefs_to(str_addr)
            if xrefs:
                log("  XREFs from: %s" % ", ".join([str(x) for x in xrefs[:3]]))

def find_singleton_patterns():
    """Search for singleton accessor patterns"""
    log("\n=== Searching for singleton patterns ===")

    # Look for static global pointers that are typical singleton storage
    memory = currentProgram.getMemory()
    symbol_table = currentProgram.getSymbolTable()

    # Search for symbols with 'Prototype' in name
    symbols = symbol_table.getSymbolIterator()
    found_symbols = []
    while symbols.hasNext():
        sym = symbols.next()
        name = sym.getName()
        if "Prototype" in name or "prototype" in name:
            found_symbols.append((name, sym.getAddress(), sym.getSymbolType()))

    if found_symbols:
        log("Found %d prototype-related symbols:" % len(found_symbols))
        for name, addr, stype in found_symbols[:20]:
            log("  %s: %s @ %s" % (stype, name, addr))
    else:
        log("No prototype symbols found")

def main():
    log("Starting Prototype Manager discovery...")
    log("Base address: %s" % currentProgram.getImageBase())

    # Search for SpellPrototypeManager
    analyze_prototype_manager("SpellPrototypeManager", [
        "SpellData",
        "SpellType",
        "SpellFlags",
        "SpellId"
    ])

    # Search for StatusPrototypeManager
    analyze_prototype_manager("StatusPrototypeManager", [
        "StatusData",
        "StatusType",
        "StatusPropertyFlags"
    ])

    # Search for PassivePrototypeManager
    analyze_prototype_manager("PassivePrototypeManager", [
        "PassiveData",
        "PassivePrototype",
        "EnabledContext"
    ])

    # Search for function candidates
    find_init_candidates()

    # Search for SpellType usage
    find_spell_type_usage()

    # Search for singleton patterns
    find_singleton_patterns()

    log("\n=== Discovery complete ===")
    log("Use XREFs from type strings to trace back to manager singletons")
    log("Init functions typically take (Prototype*, FixedString const&) parameters")

if __name__ == "__main__":
    main()
