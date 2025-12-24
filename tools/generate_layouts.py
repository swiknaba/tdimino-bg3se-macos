#!/usr/bin/env python3
"""
Generate C property layouts from Windows BG3SE component definitions.

This script reads the extracted Windows component data and generates
C code compatible with our component_offsets.h format.

Usage:
    python3 tools/generate_layouts.py > src/entity/generated_layouts.h
    python3 tools/generate_layouts.py --namespace eoc > eoc_layouts.h
    python3 tools/generate_layouts.py --list  # List all available components
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

# Windows sizes JSON
WINDOWS_SIZES_JSON = Path("ghidra/offsets/windows_reference_sizes.json")

# Ghidra sizes for ARM64 verification
GHIDRA_SIZES_DIR = Path("ghidra/offsets/components")

# Type mapping to our FIELD_TYPE_* constants
TYPE_MAPPING = {
    # Primitives
    "bool": ("FIELD_TYPE_BOOL", 1),
    "int8_t": ("FIELD_TYPE_INT8", 1),
    "uint8_t": ("FIELD_TYPE_UINT8", 1),
    "char": ("FIELD_TYPE_INT8", 1),
    "int16_t": ("FIELD_TYPE_INT16", 2),
    "uint16_t": ("FIELD_TYPE_UINT16", 2),
    "short": ("FIELD_TYPE_INT16", 2),
    "int32_t": ("FIELD_TYPE_INT32", 4),
    "uint32_t": ("FIELD_TYPE_UINT32", 4),
    "int": ("FIELD_TYPE_INT32", 4),
    "float": ("FIELD_TYPE_FLOAT", 4),
    "int64_t": ("FIELD_TYPE_INT64", 8),
    "uint64_t": ("FIELD_TYPE_UINT64", 8),
    "double": ("FIELD_TYPE_DOUBLE", 8),
    "__int64": ("FIELD_TYPE_INT64", 8),

    # Handles
    "EntityHandle": ("FIELD_TYPE_ENTITY_HANDLE", 8),
    "ComponentHandle": ("FIELD_TYPE_ENTITY_HANDLE", 8),

    # Strings
    "FixedString": ("FIELD_TYPE_FIXEDSTRING", 4),
    "Guid": ("FIELD_TYPE_GUID", 16),
    "STDString": (None, 32),       # Complex type, skip
    "STDWString": (None, 32),      # Complex type, skip
    "TranslatedString": (None, 40), # Complex type, skip

    # Vectors
    "glm::vec2": (None, 8),  # No VEC2 type, skip
    "glm::vec3": ("FIELD_TYPE_VEC3", 12),
    "glm::vec4": ("FIELD_TYPE_VEC4", 16),
    "glm::quat": ("FIELD_TYPE_VEC4", 16),

    # Common enums (all 4 bytes unless specified)
    "AbilityId": ("FIELD_TYPE_UINT8", 1),
    "SkillId": ("FIELD_TYPE_UINT8", 1),
    "SpellSchoolId": ("FIELD_TYPE_UINT8", 1),
}

# Size fallbacks for unknown types
TYPE_SIZE_FALLBACK = {
    "Array": 16,
    "StaticArray": 16,
    "HashSet": 48,
    "HashMap": 64,
    "MultiHashMap": 80,
    "SparseHashSet": 48,
    "SparseHashMap": 64,
    "std::optional": 16,
    "std::variant": 32,
    "Signal": 24,
    "BitSet": 24,
    "ecs::EntityRef": 16,
}


@dataclass
class FieldInfo:
    name: str
    type_str: str
    field_type: str  # FIELD_TYPE_*
    size: int
    offset: int
    is_readonly: bool = True


def parse_type(type_str: str) -> Tuple[str, int]:
    """Parse a C++ type and return (FIELD_TYPE_*, size)."""
    type_str = type_str.strip()

    # Remove const/volatile
    type_str = re.sub(r'\b(const|volatile|mutable)\b', '', type_str).strip()

    # Check for pointer - skip (not useful for Lua)
    if type_str.endswith('*'):
        return (None, 8)

    # Check for reference - skip (not useful for Lua)
    if type_str.endswith('&'):
        return (None, 8)

    # Check direct mapping
    if type_str in TYPE_MAPPING:
        return TYPE_MAPPING[type_str]

    # Check for templates
    template_match = re.match(r'^(\w+)<(.+)>$', type_str)
    if template_match:
        container = template_match.group(1)
        if container in TYPE_SIZE_FALLBACK:
            # Containers are opaque to Lua, skip
            return (None, TYPE_SIZE_FALLBACK[container])
        if container == "std::optional":
            inner_type, inner_size = parse_type(template_match.group(2))
            if inner_type is None:
                return (None, 16)
            # Optional adds bool + alignment
            return (inner_type, (inner_size + 7) // 8 * 8 + 8)

    # Check for qualified names
    if '::' in type_str:
        last_part = type_str.split('::')[-1]
        if last_part in TYPE_MAPPING:
            return TYPE_MAPPING[last_part]
        # Assume enum or struct (4 bytes)
        if 'Type' in last_part or 'Id' in last_part or 'Flags' in last_part:
            return ("FIELD_TYPE_INT32", 4)

    # Unknown - skip this field
    return (None, 0)


def calculate_offsets(fields: List[dict]) -> List[FieldInfo]:
    """Calculate field offsets with proper alignment."""
    result = []
    offset = 0

    for field in fields:
        type_str = field['type']
        name = field['name']

        field_type, size = parse_type(type_str)
        if field_type is None or size == 0:
            continue

        # Align offset
        align = min(size, 8)
        if align > 1 and offset % align != 0:
            offset = ((offset // align) + 1) * align

        result.append(FieldInfo(
            name=name,
            type_str=type_str,
            field_type=field_type,
            size=size,
            offset=offset,
            is_readonly=True
        ))

        offset += size

    return result


def load_ghidra_sizes() -> Dict[str, int]:
    """Load Ghidra-extracted sizes for ARM64 verification."""
    sizes = {}

    for md_file in GHIDRA_SIZES_DIR.glob("COMPONENT_SIZES*.md"):
        with open(md_file, 'r') as f:
            for line in f:
                if '---' in line or not line.strip().startswith('|'):
                    continue
                if '::' not in line:
                    continue

                parts = line.split('|')
                if len(parts) >= 3:
                    name = parts[1].strip()
                    size_field = parts[2].strip().replace('`', '')
                    size_field = re.sub(r'\s*\([^)]*\)', '', size_field).strip()

                    if '::' in name and name not in ('Component', 'Name'):
                        size = None
                        if size_field.startswith('0x'):
                            try:
                                size = int(size_field, 16)
                            except ValueError:
                                pass
                        else:
                            match = re.match(r'^(\d+)', size_field)
                            if match:
                                try:
                                    size = int(match.group(1))
                                except ValueError:
                                    pass

                        if size and 0 < size <= 10000:
                            sizes[name.lower()] = size

    return sizes


def generate_layout_code(name: str, info: dict, ghidra_sizes: Dict[str, int]) -> Optional[str]:
    """Generate C code for a component layout."""
    if info.get('is_tag', False):
        return None  # Skip tag components

    fields = info.get('fields', [])
    if not fields:
        return None  # No fields to expose

    field_infos = calculate_offsets(fields)
    if not field_infos:
        return None  # No usable fields

    # Get sizes
    windows_size = info['estimated_size']
    ghidra_size = ghidra_sizes.get(name.lower())

    # Use Ghidra size if available (more accurate for ARM64)
    actual_size = ghidra_size if ghidra_size else windows_size

    # Generate variable names (use Gen_ prefix for compatibility)
    safe_name = "Gen_" + name.replace('::', '_').replace('<', '_').replace('>', '_')
    safe_name = re.sub(r'[^a-zA-Z0-9_]', '', safe_name)

    short_name = name.split('::')[-1]
    if short_name.endswith('Component'):
        short_name = short_name[:-9]

    lines = []

    # Header comment
    lines.append(f"// {'='*70}")
    lines.append(f"// {name}")
    lines.append(f"// Generated from Windows BG3SE headers")
    if ghidra_size:
        lines.append(f"// ARM64 Size: 0x{ghidra_size:x} ({ghidra_size} bytes) - Ghidra verified")
    else:
        lines.append(f"// Windows Size: 0x{windows_size:x} ({windows_size} bytes) - Estimated")
    lines.append(f"// {'='*70}")
    lines.append("")

    # Property definitions
    lines.append(f"static const ComponentPropertyDef g_{safe_name}_Properties[] = {{")
    for fi in field_infos:
        readonly_str = "true" if fi.is_readonly else "false"
        lines.append(f'    {{ "{fi.name}", 0x{fi.offset:02x}, {fi.field_type}, 0, {readonly_str} }},')
    lines.append("};")
    lines.append("")

    # Layout definition
    lines.append(f"static const ComponentLayoutDef g_{safe_name}_Layout = {{")
    lines.append(f'    .componentName = "{name}",')
    lines.append(f'    .shortName = "{short_name}",')
    lines.append(f'    .componentTypeIndex = 0,')
    lines.append(f'    .componentSize = 0x{actual_size:x},')
    lines.append(f'    .properties = g_{safe_name}_Properties,')
    lines.append(f'    .propertyCount = sizeof(g_{safe_name}_Properties) / sizeof(g_{safe_name}_Properties[0]),')
    lines.append("};")
    lines.append("")

    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description='Generate C property layouts from Windows headers')
    parser.add_argument('--namespace', '-n', help='Filter by namespace (e.g., eoc, esv)')
    parser.add_argument('--list', '-l', action='store_true', help='List available components')
    parser.add_argument('--count', '-c', type=int, default=0, help='Limit number of components')
    args = parser.parse_args()

    os.chdir(Path(__file__).parent.parent)

    # Load data
    with open(WINDOWS_SIZES_JSON) as f:
        windows_data = json.load(f)

    ghidra_sizes = load_ghidra_sizes()

    # Filter by namespace if specified
    if args.namespace:
        ns_prefix = args.namespace + '::'
        windows_data = {k: v for k, v in windows_data.items()
                       if k.startswith(ns_prefix)}

    if args.list:
        for name in sorted(windows_data.keys()):
            info = windows_data[name]
            tag = " (tag)" if info.get('is_tag') else ""
            field_count = len(info.get('fields', []))
            print(f"{name}: {info['estimated_size']} bytes, {field_count} fields{tag}")
        return

    # Count Ghidra-verified components
    ghidra_verified = sum(1 for name in windows_data
                         if ghidra_sizes.get(name.lower()))

    # Generate header
    print("/**")
    print(" * generated_property_defs.h - Auto-generated component property definitions")
    print(" *")
    print(" * Generated from Windows BG3SE headers by tools/generate_layouts.py")
    print(f" * Total components: {len([n for n in windows_data if not windows_data[n].get('is_tag') and windows_data[n].get('fields')])}")
    print(f" * ARM64 verified (Ghidra): {ghidra_verified}")
    print(" *")
    print(" * SIZES: Ghidra-verified ARM64 sizes used where available,")
    print(" * otherwise Windows x64 estimates (may differ on ARM64).")
    print(" */")
    print("")
    print("#ifndef GENERATED_PROPERTY_DEFS_H")
    print("#define GENERATED_PROPERTY_DEFS_H")
    print("")
    print("#include \"component_property.h\"")
    print("")

    # Generate layouts and track which ones were actually generated
    count = 0
    generated = 0
    generated_names = []
    for name in sorted(windows_data.keys()):
        info = windows_data[name]
        code = generate_layout_code(name, info, ghidra_sizes)
        if code:
            print(code)
            generated += 1
            generated_names.append(name)
        count += 1
        if args.count and count >= args.count:
            break

    # Generate registry array (only include actually generated layouts)
    print(f"#define GENERATED_COMPONENT_COUNT {generated}")
    print("")
    print("static const ComponentLayoutDef* g_GeneratedComponentLayouts[] = {")
    for name in generated_names:
        safe_name = "Gen_" + name.replace('::', '_').replace('<', '_').replace('>', '_')
        safe_name = re.sub(r'[^a-zA-Z0-9_]', '', safe_name)
        print(f"    &g_{safe_name}_Layout,")
    print("    NULL")
    print("};")
    print("")
    print("#endif // GENERATED_PROPERTY_DEFS_H")

    import sys
    print(f"\n// Generated {generated} layouts from {len(windows_data)} components", file=sys.stderr)


if __name__ == "__main__":
    main()
