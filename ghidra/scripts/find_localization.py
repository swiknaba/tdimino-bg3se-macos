# Find TranslatedStringRepository singleton in macOS BG3 binary
#@author BG3SE-macOS
#@category BG3
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.data import PointerDataType

def find_pattern_in_strings(pattern):
    """Search for strings containing a pattern."""
    results = []
    listing = currentProgram.getListing()
    str_iter = listing.getDefinedData(True)

    for data in str_iter:
        if data.hasStringValue():
            value = data.getValue()
            if value and pattern.lower() in str(value).lower():
                results.append((data.getAddress(), value))
    return results

def find_xrefs_to_string(string_addr):
    """Find all cross-references to a string address."""
    refs = getReferencesTo(string_addr)
    return [ref.getFromAddress() for ref in refs]

def main():
    print("=" * 60)
    print("Finding TranslatedStringRepository Singleton")
    print("=" * 60)

    # Strategy 1: Look for "TranslatedString" related strings
    print("\n[1] Searching for localization-related strings...")
    patterns = ["TranslatedString", "StringRepository", "loca", ".loca", "Localization"]

    for pattern in patterns:
        results = find_pattern_in_strings(pattern)
        if results:
            print(f"\nFound '{pattern}' strings:")
            for addr, val in results[:10]:
                print(f"  {addr}: {val[:60]}...")

    # Strategy 2: Look for symbols with "String" and "Repository"
    print("\n[2] Searching for symbols...")
    symbol_table = currentProgram.getSymbolTable()
    for sym in symbol_table.getAllSymbols(True):
        name = sym.getName()
        if "TranslatedString" in name or "StringRepository" in name:
            print(f"  Symbol: {name} at {sym.getAddress()}")

    # Strategy 3: Look for global pointers that might be the repository
    print("\n[3] Looking for global pointer patterns...")
    # The repository is accessed as: *ls__gTranslatedStringRepository
    # So we're looking for a double-pointer pattern

    # Search for "Unknown" or "handle" patterns in .loca files
    loca_patterns = find_pattern_in_strings("Unknown")
    if loca_patterns:
        print(f"\nFound {len(loca_patterns)} 'Unknown' strings (possible fallback texts)")

    print("\n[4] Looking for hash functions (used in RuntimeStringHandle lookup)...")
    # The repository uses a HashMap<RuntimeStringHandle, LSStringView>
    # RuntimeStringHandle is hashed by its FixedString component

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)

if __name__ == "__main__":
    main()
