# Ghidra script to find GetComponent functions near known addresses
# The ls:: GetComponent addresses are clustered - eoc:: might be too

from ghidra.program.model.symbol import SymbolType

fm = currentProgram.getFunctionManager()
memory = currentProgram.getMemory()
addrFactory = currentProgram.getAddressFactory()

print("=" * 70)
print("Searching for GetComponent patterns near known addresses")
print("=" * 70)

# Known ls:: GetComponent addresses (from Ghidra analysis)
known_addresses = {
    "ls::TransformComponent": 0x10010d5b00,
    "ls::LevelComponent": 0x10010d588c,
    "ls::PhysicsComponent": 0x101ba0898,
    "ls::VisualComponent": 0x102e56350,
}

print("\n=== Analyzing Known GetComponent Functions ===")

known_sizes = []
for name, addr in known_addresses.items():
    try:
        func_addr = addrFactory.getAddress(hex(addr))
        func = fm.getFunctionAt(func_addr)
        if func:
            size = func.getBody().getNumAddresses()
            known_sizes.append(size)
            print("{}: 0x{:x} - {} bytes".format(name, addr, size))
    except:
        pass

if known_sizes:
    avg_size = sum(known_sizes) // len(known_sizes)
    min_size = min(known_sizes) - 50
    max_size = max(known_sizes) + 50
    print("\nSize range: {} - {} bytes (avg: {})".format(min_size, max_size, avg_size))

print("\n=== Searching for Similar Functions Near Known Addresses ===")

# Search ranges around known addresses
search_ranges = [
    (0x10010d0000, 0x10010e0000, "Near Transform/Level"),
    (0x101b90000, 0x101bb0000, "Near Physics"),
    (0x102e50000, 0x102e60000, "Near Visual"),
    (0x1012a0000, 0x1012c0000, "Near combat helpers"),  # where LEGACY_IsInCombat is
]

for start, end, label in search_ranges:
    print("\n{} (0x{:x} - 0x{:x}):".format(label, start, end))
    count = 0
    for func in fm.getFunctions(True):
        entry = func.getEntryPoint().getOffset()
        if start <= entry <= end:
            size = func.getBody().getNumAddresses()
            # Look for functions with similar size to known GetComponents
            if min_size <= size <= max_size:
                name = func.getName()
                print("  0x{:x} - {} ({} bytes)".format(entry, name, size))
                count += 1
                if count > 20:
                    print("  ... (truncated)")
                    break

print("\n=== Looking for eoc:: String References in Functions ===")

# Search for functions that reference eoc:: strings (might be GetComponent or related)
eoc_strings = []
for block in memory.getBlocks():
    if not block.isInitialized():
        continue
    start = block.getStart()
    end = block.getEnd()

    for comp_name in ["eoc::Stats", "eoc::BaseHp", "eoc::Armor", "eoc::Health"]:
        try:
            addr = memory.findBytes(start, end, comp_name.encode('utf-8'), None, True, monitor)
            if addr:
                eoc_strings.append((comp_name, addr))
        except:
            pass

print("Found {} eoc:: string prefixes".format(len(eoc_strings)))

# Look at functions in the same memory region as these strings
if eoc_strings:
    string_region_start = min(s[1].getOffset() for s in eoc_strings) - 0x100000
    string_region_end = max(s[1].getOffset() for s in eoc_strings) + 0x100000

    print("\nFunctions in string region 0x{:x} - 0x{:x}:".format(
        string_region_start, string_region_end))

    count = 0
    for func in fm.getFunctions(True):
        entry = func.getEntryPoint().getOffset()
        if string_region_start <= entry <= string_region_end:
            size = func.getBody().getNumAddresses()
            if 50 <= size <= 500:
                name = func.getName()
                print("  0x{:x} - {} ({} bytes)".format(entry, name, size))
                count += 1
                if count > 30:
                    print("  ... (truncated)")
                    break

print("\n=== Alternative: Component Index-Based Access ===")

# Look for functions that might be doing component index lookup
# These often have a uint16_t comparison pattern
for func in fm.getFunctions(True):
    name = func.getName()
    if any(kw in name.lower() for kw in ['storage', 'rawcomponent', 'getraw', 'entitystorage']):
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  0x{:x} - {} ({} bytes)".format(entry, name, size))

print("\n" + "=" * 70)
