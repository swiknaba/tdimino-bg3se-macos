#!/usr/bin/env python3
"""
Extract ARM64 component sizes from Ghidra decompilation via MCP.
This script uses the Ghidra MCP server to decompile AddComponent functions
and extract the SIZE parameter from ComponentFrameStorageAllocRaw calls.
"""

import re
import json
from collections import defaultdict

# This will be populated with results
results = []

# Function to extract size from decompiled code
def extract_size_from_decompilation(decompiled_code, function_name):
    """
    Extract SIZE parameter from ComponentFrameStorageAllocRaw pattern.
    Pattern: ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)
    """
    pattern = r'ComponentFrameStorageAllocRaw\s*\(\s*\(ComponentFrameStorage\s*\*\)\s*\([^)]+\)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,'

    matches = re.findall(pattern, decompiled_code)

    if matches:
        size_str = matches[0]
        # Convert to decimal
        if size_str.startswith('0x'):
            size = int(size_str, 16)
        else:
            size = int(size_str)

        return size

    return None

# Function to extract component name from full function signature
def extract_component_name(function_name):
    """
    Extract component name from templates like:
    AddComponent<eoc::AbilityBoostComponent,eoc::AbilityBoostComponent>
    """
    match = re.search(r'AddComponent<([^,>]+)', function_name)
    if match:
        return match.group(1)
    return None

# Function to organize by namespace
def get_namespace(component_name):
    """Extract namespace prefix (e.g., 'eoc', 'esv', 'ls', 'ecl', 'navcloud')"""
    if '::' in component_name:
        return component_name.split('::')[0]
    return 'global'

def format_results(results):
    """Format results organized by namespace"""
    by_namespace = defaultdict(list)

    for item in results:
        namespace = get_namespace(item['component'])
        by_namespace[namespace].append(item)

    # Sort namespaces
    output = []
    for namespace in sorted(by_namespace.keys()):
        output.append(f"\n## {namespace}::")
        output.append("-" * 80)

        # Sort by component name within namespace
        for item in sorted(by_namespace[namespace], key=lambda x: x['component']):
            notes = item.get('notes', '')
            output.append(f"{item['component']:<60} | {item['size']:>6} bytes | {notes}")

    return "\n".join(output)

if __name__ == "__main__":
    print("Component Size Extraction Script")
    print("=" * 80)
    print("\nThis script template needs to be integrated with Ghidra MCP calls.")
    print("\nExample result format:")

    # Example data
    example_results = [
        {"component": "eoc::ACOverrideFormulaBoostComponent", "size": 24, "notes": ""},
        {"component": "eoc::AbilityBoostComponent", "size": 16, "notes": ""},
        {"component": "eoc::AbilityFailedSavingThrowBoostComponent", "size": 1, "notes": "Single byte"},
        {"component": "eoc::AbilityOverrideMinimumBoostComponent", "size": 12, "notes": ""},
        {"component": "eoc::ActionResourceBlockBoostComponent", "size": 24, "notes": ""},
    ]

    print(format_results(example_results))
