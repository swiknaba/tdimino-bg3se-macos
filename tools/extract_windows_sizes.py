#!/usr/bin/env python3
"""
Extract component struct sizes from Windows BG3SE headers.

This script parses the C++ component definitions from Windows BG3SE
and estimates struct sizes based on known type sizes. These estimates
can be cross-referenced with Ghidra-extracted ARM64 sizes.

Usage:
    python3 tools/extract_windows_sizes.py > ghidra/offsets/windows_reference_sizes.json
"""

import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# Windows BG3SE component headers directory
WINDOWS_COMPONENTS_DIR = Path("/Users/tomdimino/Desktop/Programming/bg3se/BG3Extender/GameDefinitions/Components")

# Type size database (x86_64, may differ on ARM64 for some types)
# Sizes in bytes
TYPE_SIZES = {
    # Primitives
    "bool": 1,
    "int8_t": 1,
    "uint8_t": 1,
    "char": 1,
    "int16_t": 2,
    "uint16_t": 2,
    "short": 2,
    "int32_t": 4,
    "uint32_t": 4,
    "int": 4,
    "float": 4,
    "int64_t": 8,
    "uint64_t": 8,
    "double": 8,
    "__int64": 8,

    # Pointers (64-bit)
    "void*": 8,

    # BG3SE basic types
    "EntityHandle": 8,        # TypedHandle<EntityHandleTag> with uint64_t Handle
    "ComponentHandle": 8,
    "NetId": 4,               # uint32_t
    "FixedString": 4,         # FixedStringId with uint32_t Index
    "Guid": 16,               # uint64_t Val[2]
    "glm::vec2": 8,           # 2 floats
    "glm::vec3": 12,          # 3 floats (may be padded to 16 in structs)
    "glm::vec4": 16,          # 4 floats
    "glm::quat": 16,          # 4 floats
    "glm::mat3": 36,          # 9 floats (may be padded to 48)
    "glm::mat4": 64,          # 16 floats
    "glm::mat3x4": 48,        # 12 floats

    # Container types (approximate, includes internal pointers/sizes)
    "Array": 16,              # T* buf_ + uint32_t capacity_ + uint32_t size_
    "StaticArray": 16,        # T* buf_ + uint32_t size_ (aligned to 16)
    "HashSet": 48,            # StaticArray + Array + Array
    "HashMap": 64,            # HashSet + UninitializedStaticArray (Values)
    "MultiHashMap": 80,       # Larger due to multiple value support
    "SparseHashSet": 48,
    "SparseHashMap": 64,

    # String types
    "STDString": 32,          # std::string with SSO
    "STDWString": 32,
    "LSStringView": 16,       # ptr + size
    "StringView": 16,
    "TranslatedString": 40,   # Handle + FallbackHandle + argumentString

    # Other BG3SE types
    "BitSet": 24,             # ptr + size + capacity
    "Signal": 24,
    "Version": 8,             # uint64_t
    "TemplateHandle": 8,
    "UserId": 4,
    "ActionOriginator": 40,
    "Background": 48,
    "AbilityId": 1,           # enum
    "SkillId": 1,             # enum
    "WeaponType": 4,
    "DamageType": 4,
    "SpellSchoolId": 1,
    "CriticalHitResult": 4,
    "StatsRollType": 4,
    "StatusType": 4,
    "stats::ConditionId": 4,
    "ComponentTypeIndex": 2,
    "ReplicationTypeIndex": 2,
    "QueryIndex": 2,

    # Resource references
    "resource::PresetData::Resource": 24,
    "ecs::EntityRef": 16,     # EntityHandle + EntityWorld*
}

# Regex patterns
STRUCT_START = re.compile(r'^struct\s+(\w+)(?:\s*:\s*public\s+(\w+))?\s*{?\s*$')
STRUCT_END = re.compile(r'^};?\s*$')
DEFINE_COMPONENT = re.compile(r'DEFINE_(?:PROXY_)?COMPONENT\s*\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)')
DEFINE_TAG_COMPONENT = re.compile(r'DEFINE_(?:ONEFRAME_)?TAG_COMPONENT\s*\(\s*([^,]+)\s*,\s*(\w+)\s*,\s*(\w+)\s*\)')
FIELD_PATTERN = re.compile(r'^\s*(?:\[\[[^\]]+\]\])?\s*([a-zA-Z_][a-zA-Z0-9_:<>,\s\*]+)\s+(\w+)(?:\s*{[^}]*})?(?:\s*\[[^\]]+\])?\s*;')
ARRAY_FIELD = re.compile(r'(\w+)\s*\[(\d+)\]')
TEMPLATE_TYPE = re.compile(r'^(\w+)<(.+)>$')


@dataclass
class ComponentInfo:
    name: str                     # C++ struct name
    engine_class: str             # Full namespace path (e.g., "eoc::HealthComponent")
    base_class: str               # Parent class
    fields: List[Tuple[str, str]] = field(default_factory=list)  # (type, name) pairs
    estimated_size: int = 0
    is_tag: bool = False


def parse_type_size(type_str: str) -> int:
    """Estimate size of a C++ type."""
    type_str = type_str.strip()

    # Remove const, volatile, etc.
    type_str = re.sub(r'\b(const|volatile|mutable)\b', '', type_str).strip()

    # Check for pointer
    if type_str.endswith('*'):
        return 8

    # Check for reference (treat as pointer for storage)
    if type_str.endswith('&'):
        return 8

    # Check for array suffix
    array_match = ARRAY_FIELD.search(type_str)
    if array_match:
        base_type = type_str[:array_match.start()].strip()
        count = int(array_match.group(2))
        return parse_type_size(base_type) * count

    # Check known types
    if type_str in TYPE_SIZES:
        return TYPE_SIZES[type_str]

    # Check template types (e.g., Array<EntityHandle>)
    template_match = TEMPLATE_TYPE.match(type_str)
    if template_match:
        container = template_match.group(1)
        # Container size doesn't depend on element type (it stores pointers)
        if container in TYPE_SIZES:
            return TYPE_SIZES[container]
        # Handle nested templates
        if container in ('Array', 'StaticArray', 'HashSet', 'HashMap',
                         'MultiHashMap', 'SparseHashSet', 'SparseHashMap',
                         'VirtualHashMap', 'VirtualMultiHashSet'):
            return TYPE_SIZES.get(container, 64)
        if container in ('std::optional',):
            inner = template_match.group(2).strip()
            # Optional adds 1 byte for has_value, plus alignment
            inner_size = parse_type_size(inner)
            if inner_size <= 8:
                return inner_size + 8  # Align to 8
            return inner_size + 16
        if container in ('std::variant',):
            # Variant: max size of alternatives + type index
            return 32  # Conservative estimate
        if container == 'TrackedCompactSet':
            return 24  # Similar to BitSet

    # Check for enum types (usually 4 bytes unless specified)
    if type_str.startswith('enum'):
        return 4

    # Check for qualified names (e.g., stats::ConditionId)
    if '::' in type_str:
        # Try the last part
        last_part = type_str.split('::')[-1]
        if last_part in TYPE_SIZES:
            return TYPE_SIZES[last_part]
        # Common enum/struct patterns
        if 'Type' in last_part or 'Id' in last_part or 'Flags' in last_part:
            return 4

    # Unknown type - return 8 as conservative estimate
    return 8


def calculate_struct_size(fields: List[Tuple[str, str]], base_size: int = 0) -> int:
    """Calculate struct size with proper alignment."""
    offset = base_size
    max_align = 1

    for type_str, name in fields:
        field_size = parse_type_size(type_str)

        # Determine alignment (simplified: use field size up to 8)
        align = min(field_size, 8)
        if align > 0:
            max_align = max(max_align, align)
            # Align offset
            if offset % align != 0:
                offset = ((offset // align) + 1) * align

        offset += field_size

    # Final struct alignment
    if max_align > 1 and offset % max_align != 0:
        offset = ((offset // max_align) + 1) * max_align

    return offset


def parse_component_file(filepath: Path) -> List[ComponentInfo]:
    """Parse a single component header file."""
    components = []
    current_struct = None
    brace_depth = 0

    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Skip comments and preprocessor
        if line.startswith('//') or line.startswith('#') or line.startswith('/*'):
            i += 1
            continue

        # Check for DEFINE_TAG_COMPONENT macro
        tag_match = DEFINE_TAG_COMPONENT.search(line)
        if tag_match:
            ns, name, comp_type = tag_match.groups()
            engine_class = f"{ns.strip()}::{name.strip()}"
            comp = ComponentInfo(
                name=name.strip(),
                engine_class=engine_class,
                base_class="BaseComponent",
                fields=[("uint8_t", "Dummy")],
                estimated_size=1,
                is_tag=True
            )
            components.append(comp)
            i += 1
            continue

        # Check for struct start
        struct_match = STRUCT_START.match(line)
        if struct_match and current_struct is None:
            name = struct_match.group(1)
            base = struct_match.group(2) or ""

            # Check if this might be a component
            if base in ('BaseComponent', 'BaseProxyComponent') or 'Component' in name:
                current_struct = ComponentInfo(
                    name=name,
                    engine_class="",
                    base_class=base
                )
                if '{' in line:
                    brace_depth = 1
                else:
                    brace_depth = 0
            i += 1
            continue

        # Track braces
        if current_struct is not None:
            if '{' in line:
                brace_depth += line.count('{')
            if '}' in line:
                brace_depth -= line.count('}')

            # Check for DEFINE_COMPONENT inside struct
            comp_match = DEFINE_COMPONENT.search(line)
            if comp_match:
                comp_type, engine_class = comp_match.groups()
                current_struct.engine_class = engine_class

            # Parse field
            if brace_depth == 1:  # Only parse top-level fields
                field_match = FIELD_PATTERN.match(line)
                if field_match:
                    field_type = field_match.group(1).strip()
                    field_name = field_match.group(2).strip()
                    # Skip static members and methods
                    if not field_type.startswith('static') and '(' not in line:
                        current_struct.fields.append((field_type, field_name))

            # Check for struct end
            if brace_depth == 0 and STRUCT_END.match(line):
                if current_struct.engine_class:  # Only save components with DEFINE_COMPONENT
                    base_size = 0
                    if current_struct.base_class == 'BaseComponent':
                        base_size = 0  # Empty base
                    elif current_struct.base_class == 'BaseProxyComponent':
                        base_size = 0  # Empty base

                    current_struct.estimated_size = calculate_struct_size(
                        current_struct.fields,
                        base_size
                    )
                    components.append(current_struct)
                current_struct = None

        i += 1

    return components


def extract_all_components() -> Dict[str, ComponentInfo]:
    """Extract all components from Windows BG3SE headers."""
    all_components = {}

    if not WINDOWS_COMPONENTS_DIR.exists():
        print(f"Error: Windows BG3SE components directory not found: {WINDOWS_COMPONENTS_DIR}",
              file=__import__('sys').stderr)
        return all_components

    for header_file in WINDOWS_COMPONENTS_DIR.glob('*.h'):
        components = parse_component_file(header_file)
        for comp in components:
            # Use engine_class as key
            all_components[comp.engine_class] = comp

    return all_components


def main():
    components = extract_all_components()

    # Convert to JSON-serializable format
    output = {}
    for engine_class, comp in sorted(components.items()):
        output[engine_class] = {
            "struct_name": comp.name,
            "estimated_size": comp.estimated_size,
            "base_class": comp.base_class,
            "is_tag": comp.is_tag,
            "fields": [{"type": t, "name": n} for t, n in comp.fields]
        }

    # Print summary stats
    import sys
    print(f"# Extracted {len(output)} components from Windows BG3SE headers", file=sys.stderr)

    # Count by namespace
    namespaces = {}
    for engine_class in output:
        ns = engine_class.split('::')[0] if '::' in engine_class else 'unknown'
        namespaces[ns] = namespaces.get(ns, 0) + 1
    print(f"# Namespaces: {dict(sorted(namespaces.items()))}", file=sys.stderr)

    # Output JSON
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
