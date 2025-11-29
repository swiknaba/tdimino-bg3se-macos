# Ghidra script to find eoc:: GetComponent function addresses
# Target: Stats, BaseHp, Armor component accessors
# Run with: analyzeHeadless ... -postScript find_eoc_components.py

from ghidra.program.model.symbol import SymbolType

fm = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
refManager = currentProgram.getReferenceManager()
listing = currentProgram.getListing()
addrFactory = currentProgram.getAddressFactory()
imageBase = currentProgram.getImageBase()

print("=" * 70)
print("BG3 eoc:: Component GetComponent Address Discovery")
print("Image base: 0x{:x}".format(imageBase.getOffset()))
print("=" * 70)

# Target component strings we're looking for
target_components = [
    "eoc::StatsComponent",
    "eoc::BaseHpComponent",
    "eoc::ArmorComponent",
    "eoc::HealthComponent",
    "eoc::ClassesComponent",
    "eoc::WeaponComponent",
    "eoc::MovementComponent",
    "eoc::PassiveComponent",
]

print("\n=== Searching for eoc:: Component Strings ===")

found_strings = {}
for block in memory.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart()
    end = block.getEnd()

    for name in target_components:
        try:
            addr = memory.findBytes(start, end, name.encode('utf-8'), None, True, monitor)
            while addr is not None:
                found_strings[name] = addr
                print("Found '{}' at 0x{:x}".format(name, addr.getOffset()))
                # Try to find more instances
                next_start = addr.add(1)
                if next_start.compareTo(end) < 0:
                    addr = memory.findBytes(next_start, end, name.encode('utf-8'), None, True, monitor)
                else:
                    addr = None
        except Exception as e:
            print("Error searching for {}: {}".format(name, e))

print("\n=== Analyzing References to Component Strings ===")

# For each component string, find functions that reference it
candidate_functions = {}

for name, str_addr in found_strings.items():
    print("\nAnalyzing refs to '{}' @ 0x{:x}:".format(name, str_addr.getOffset()))
    refs = refManager.getReferencesTo(str_addr)

    candidates = []
    for ref in refs:
        from_addr = ref.getFromAddress()
        from_func = fm.getFunctionContaining(from_addr)

        if from_func:
            func_entry = from_func.getEntryPoint()
            func_name = from_func.getName()
            body_size = from_func.getBody().getNumAddresses()

            print("  Ref from: {} @ 0x{:x} (size: {} bytes)".format(
                func_name, func_entry.getOffset(), body_size))
            candidates.append((func_entry.getOffset(), func_name, body_size))

    candidate_functions[name] = candidates

print("\n=== Looking for GetComponent Pattern Functions ===")

# Look for functions with names containing Component or Get
for func in fm.getFunctions(True):
    name = func.getName()
    if 'Component' in name or 'GetRaw' in name:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        if size > 50 and size < 2000:
            print("  {} @ 0x{:x} ({} bytes)".format(name, entry, size))

print("\n=== Searching for Template Instantiations ===")

# Look for functions that might be GetComponent template instantiations
# These typically:
# 1. Have similar size to known GetComponent functions (100-400 bytes)
# 2. Reference a component type string
# 3. Have a particular call pattern

# Count functions by size to find patterns
size_counts = {}
for func in fm.getFunctions(True):
    size = func.getBody().getNumAddresses()
    if 80 <= size <= 400:
        if size not in size_counts:
            size_counts[size] = []
        size_counts[size].append((func.getEntryPoint().getOffset(), func.getName()))

# Show most common sizes (likely template instantiations)
print("\nMost common function sizes in GetComponent range (80-400 bytes):")
sorted_sizes = sorted(size_counts.items(), key=lambda x: len(x[1]), reverse=True)
for size, funcs in sorted_sizes[:10]:
    print("  Size {}: {} functions".format(size, len(funcs)))
    if len(funcs) <= 3:
        for addr, fname in funcs:
            print("    0x{:x} - {}".format(addr, fname))

print("\n=== Summary of Candidates per Component ===")

for name, candidates in candidate_functions.items():
    print("\n{}:".format(name))
    if not candidates:
        print("  No candidates found")
    else:
        # Sort by function size
        candidates.sort(key=lambda x: x[2])
        for addr, func_name, size in candidates[:10]:
            print("  0x{:x} - {} ({} bytes)".format(addr, func_name, size))

print("\n=== Cross-reference Analysis ===")

# For each candidate, see if it also references other ECS-related patterns
for name, candidates in candidate_functions.items():
    if not candidates:
        continue
    print("\n{}:".format(name))
    for addr, func_name, size in candidates[:3]:
        print("  Analyzing {} @ 0x{:x}:".format(func_name, addr))
        try:
            func_addr = addrFactory.getAddress(hex(addr))
            func = fm.getFunctionAt(func_addr)
            if func:
                body = func.getBody()
                # Check what this function references
                ref_to_strs = []
                for a in body.getAddresses(True):
                    for ref in refManager.getReferencesFrom(a):
                        to_addr = ref.getToAddress()
                        # Check if it references other component strings
                        for comp_name, comp_addr in found_strings.items():
                            if to_addr == comp_addr:
                                ref_to_strs.append(comp_name)
                if ref_to_strs:
                    print("    Also references: {}".format(", ".join(set(ref_to_strs))))
        except Exception as e:
            print("    Error: {}".format(e))

print("\n" + "=" * 70)
print("Analysis complete.")
print("=" * 70)
