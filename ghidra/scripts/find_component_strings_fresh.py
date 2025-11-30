# Find component strings in the current database
# Search for actual string content rather than hardcoded addresses

from ghidra.program.model.data import StringDataType

memory = currentProgram.getMemory()
listing = currentProgram.getListing()
refManager = currentProgram.getReferenceManager()
fm = currentProgram.getFunctionManager()

print("=" * 60)
print("Finding Component Strings in Current Database")
print("=" * 60)

# Component names to search for
component_names = [
    "ls::TransformComponent",
    "ls::LevelComponent",
    "eoc::StatsComponent",
    "eoc::BaseHpComponent",
    "eoc::HealthComponent",
    "eoc::ArmorComponent",
    "UuidToHandleMappingComponent",
]

found_strings = {}

# Search through all defined strings
print("\nSearching for component strings...")
for data in listing.getDefinedData(True):
    if data.hasStringValue():
        try:
            value = data.getValue()
            if value:
                str_val = str(value)
                for comp_name in component_names:
                    if comp_name in str_val:
                        addr = data.getAddress().getOffset()
                        found_strings[comp_name] = addr
                        print("  Found '{}' at 0x{:x}".format(comp_name, addr))
        except:
            pass

print("\n=== Summary ===")
for name, addr in found_strings.items():
    print("  {} @ 0x{:x}".format(name, addr))

    # Get references to this address
    ghidra_addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)
    refs = refManager.getReferencesTo(ghidra_addr)
    ref_count = 0
    for ref in refs:
        from_addr = ref.getFromAddress()
        func = fm.getFunctionContaining(from_addr)
        if func:
            print("    XREF from {} @ 0x{:x}".format(func.getName(), func.getEntryPoint().getOffset()))
        else:
            print("    XREF from 0x{:x} (no function)".format(from_addr.getOffset()))
        ref_count += 1
        if ref_count >= 5:
            print("    ... more refs ...")
            break
    if ref_count == 0:
        print("    No references found")

print("\n" + "=" * 60)
print("Search complete")
print("=" * 60)
