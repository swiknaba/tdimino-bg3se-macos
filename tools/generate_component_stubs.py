#!/usr/bin/env python3
"""
generate_component_stubs.py - Generate BG3SE-macOS component stubs from Windows BG3SE headers

Parses the Windows BG3SE C++ headers to extract component struct definitions and generates
C code stubs for BG3SE-macOS. The generated stubs include field names and types but require
manual verification of ARM64 offsets.

Usage:
    python3 tools/generate_component_stubs.py [--high-priority] [--namespace eoc]

Options:
    --high-priority  Only generate stubs for commonly-used components
    --namespace NS   Only generate for a specific namespace (eoc, esv, ecl, ls)
    --output FILE    Output file (default: stdout)
    --list           Just list component names without generating code

Examples:
    # List all eoc:: components
    python3 tools/generate_component_stubs.py --namespace eoc --list

    # Generate stubs for high-priority components
    python3 tools/generate_component_stubs.py --high-priority > component_stubs.c
"""

import os
import re
import sys
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# Path to Windows BG3SE repository
WINDOWS_BG3SE_PATH = "/Users/tomdimino/Desktop/Programming/bg3se"
COMPONENTS_DIR = f"{WINDOWS_BG3SE_PATH}/BG3Extender/GameDefinitions/Components"

# High-priority components commonly used by mods
HIGH_PRIORITY_COMPONENTS = {
    # Core entity components
    "HealthComponent",
    "StatsComponent",
    "ArmorComponent",
    "BaseHpComponent",
    "DataComponent",
    "LevelComponent",

    # Character attributes
    "RaceComponent",
    "OriginComponent",
    "BackgroundComponent",
    "ClassesComponent",
    "ExperienceComponent",
    "AvailableLevelComponent",

    # Combat and stats
    "ActionResourcesComponent",
    "ResistancesComponent",
    "PassiveComponent",
    "PassiveContainerComponent",
    "TurnBasedComponent",
    "MovementComponent",

    # Equipment and inventory
    "WeaponComponent",
    "EquipableComponent",
    "ContainerComponent",  # inventory
    "OwnerComponent",      # inventory
    "MemberComponent",     # inventory
    "IsOwnedComponent",    # inventory
    "ValueComponent",

    # Spells and abilities
    "BookComponent",       # spell
    "ContainerComponent",  # spell
    "ConcentrationComponent",

    # Status and boosts
    "StatusContainerComponent",
    "BoostsContainerComponent",

    # Display
    "DisplayNameComponent",
    "TransformComponent",
    "VisualComponent",

    # God/deity
    "GodComponent",

    # Tags
    "TagComponent",
}

@dataclass
class StructField:
    """Represents a field in a component struct."""
    name: str
    cpp_type: str
    attributes: List[str] = field(default_factory=list)
    is_readonly: bool = False
    is_hidden: bool = False

    def to_c_type(self) -> str:
        """Convert C++ type to C type (approximate)."""
        type_map = {
            "int": "int32_t",
            "int8_t": "int8_t",
            "int16_t": "int16_t",
            "int32_t": "int32_t",
            "int64_t": "int64_t",
            "uint8_t": "uint8_t",
            "uint16_t": "uint16_t",
            "uint32_t": "uint32_t",
            "uint64_t": "uint64_t",
            "float": "float",
            "double": "double",
            "bool": "bool",
            "FixedString": "FixedString",  # Our custom type
            "Guid": "Guid",                # 16-byte UUID
            "EntityHandle": "EntityHandle", # 8-byte handle
            "glm::vec3": "Vec3",           # 12 bytes
            "glm::vec4": "Vec4",           # 16 bytes
            "glm::mat4": "Mat4",           # 64 bytes
        }

        t = self.cpp_type.strip()

        # Direct mapping
        if t in type_map:
            return type_map[t]

        # Array types
        if t.startswith("Array<") or t.startswith("std::vector<"):
            return "Array /* TODO: verify */"

        # HashMap types
        if t.startswith("HashMap<"):
            return "HashMap /* TODO: verify */"

        # std::array
        if t.startswith("std::array<"):
            return "StdArray /* TODO: verify */"

        # Pointer types
        if t.endswith("*"):
            return "void*"

        # Unknown - mark for manual review
        return f"UNKNOWN /* {t} */"

@dataclass
class ComponentDef:
    """Represents a component definition."""
    name: str
    full_name: str  # e.g., "eoc::HealthComponent"
    base_class: str
    fields: List[StructField] = field(default_factory=list)
    source_file: str = ""

    @property
    def namespace(self) -> str:
        """Extract namespace from full name."""
        if "::" in self.full_name:
            return self.full_name.rsplit("::", 1)[0]
        return ""

def parse_component_header(filepath: str) -> List[ComponentDef]:
    """Parse a single component header file."""
    components = []

    with open(filepath, 'r') as f:
        content = f.read()

    # Pattern for DEFINE_COMPONENT macro
    define_pattern = re.compile(
        r'DEFINE_COMPONENT\(\s*(\w+)\s*,\s*"([^"]+)"\s*\)'
    )

    # Pattern for struct definition with BaseComponent
    struct_pattern = re.compile(
        r'struct\s+(\w+)\s*:\s*(?:public\s+)?(\w+)\s*\{([^}]+(?:\{[^}]*\}[^}]*)*)\}',
        re.DOTALL
    )

    # Pattern for field definitions
    field_pattern = re.compile(
        r'(?:\[\[([^\]]+)\]\])?\s*'  # Optional attributes
        r'([a-zA-Z_][a-zA-Z0-9_:<>, ]*)\s+'  # Type
        r'([a-zA-Z_][a-zA-Z0-9_]*)\s*'  # Name
        r'(?:\{[^}]*\})?\s*;'  # Optional initializer
    )

    # Find all struct definitions
    for struct_match in struct_pattern.finditer(content):
        struct_name = struct_match.group(1)
        base_class = struct_match.group(2)
        struct_body = struct_match.group(3)

        # Check if this is a component (has DEFINE_COMPONENT or inherits from BaseComponent)
        if base_class not in ("BaseComponent", "BaseProxyComponent"):
            continue

        # Find DEFINE_COMPONENT macro in struct body
        define_match = define_pattern.search(struct_body)
        if not define_match:
            continue

        short_name = define_match.group(1)
        full_name = define_match.group(2)

        component = ComponentDef(
            name=short_name,
            full_name=full_name,
            base_class=base_class,
            source_file=os.path.basename(filepath)
        )

        # Parse fields
        for field_match in field_pattern.finditer(struct_body):
            attrs_str = field_match.group(1) or ""
            field_type = field_match.group(2).strip()
            field_name = field_match.group(3)

            # Skip DEFINE_COMPONENT line
            if "DEFINE_COMPONENT" in field_type or "DEFINE_ONEFRAME" in field_type:
                continue

            # Parse attributes
            attrs = [a.strip() for a in attrs_str.split(",") if a.strip()]

            field = StructField(
                name=field_name,
                cpp_type=field_type,
                attributes=attrs,
                is_readonly="bg3::readonly" in attrs,
                is_hidden="bg3::hidden" in attrs
            )

            component.fields.append(field)

        components.append(component)

    return components

def parse_all_components() -> List[ComponentDef]:
    """Parse all component definitions from Windows BG3SE."""
    components = []

    components_dir = Path(COMPONENTS_DIR)
    if not components_dir.exists():
        print(f"Error: Components directory not found: {COMPONENTS_DIR}", file=sys.stderr)
        return []

    for header_file in components_dir.glob("*.h"):
        try:
            file_components = parse_component_header(str(header_file))
            components.extend(file_components)
        except Exception as e:
            print(f"Warning: Error parsing {header_file}: {e}", file=sys.stderr)

    return components

def generate_c_stub(component: ComponentDef) -> str:
    """Generate C stub code for a component."""
    lines = []

    # Header comment
    lines.append(f"// {component.full_name}")
    lines.append(f"// Source: {component.source_file}")
    lines.append(f"// Fields: {len(component.fields)}")
    lines.append(f"// NOTE: ARM64 offsets need verification via Ghidra or runtime probing")
    lines.append("")

    # Generate property definitions
    c_name = component.full_name.replace("::", "_")
    lines.append(f"static const ComponentPropertyDef g_{component.name}_Properties[] = {{")

    offset = 0
    for field in component.fields:
        if field.is_hidden:
            lines.append(f"    // [hidden] {field.name}")
            continue

        c_type = field.to_c_type()
        readonly = "true" if field.is_readonly else "true"  # Default to true for safety

        # Estimate offset (VERY rough - ARM64 alignment can differ)
        size_estimate = {
            "int8_t": 1, "uint8_t": 1, "bool": 1,
            "int16_t": 2, "uint16_t": 2,
            "int32_t": 4, "uint32_t": 4, "float": 4,
            "int64_t": 8, "uint64_t": 8, "double": 8,
            "void*": 8, "FixedString": 8, "EntityHandle": 8,
            "Guid": 16, "Vec3": 12, "Vec4": 16, "Mat4": 64,
        }.get(c_type, 8)  # Default to 8 for unknown types

        # Align offset
        alignment = min(size_estimate, 8)
        offset = (offset + alignment - 1) // alignment * alignment

        lines.append(f"    {{ \"{field.name}\", 0x{offset:02X}, FIELD_TYPE_UNKNOWN, 0, {readonly} }},  // TODO: verify type and offset")

        offset += size_estimate

    lines.append("};")
    lines.append("")

    return "\n".join(lines)

def generate_registry_entry(component: ComponentDef) -> str:
    """Generate registry entry for g_AllComponentLayouts."""
    c_name = component.full_name.replace("::", "_")
    field_count = len([f for f in component.fields if not f.is_hidden])

    return f'    {{ "{component.full_name}", g_{component.name}_Properties, {field_count} }},'

def main():
    parser = argparse.ArgumentParser(description="Generate component stubs from Windows BG3SE headers")
    parser.add_argument("--high-priority", action="store_true", help="Only high-priority components")
    parser.add_argument("--namespace", type=str, help="Filter by namespace (eoc, esv, ecl, ls)")
    parser.add_argument("--output", type=str, help="Output file (default: stdout)")
    parser.add_argument("--list", action="store_true", help="Just list component names")
    args = parser.parse_args()

    # Parse all components
    components = parse_all_components()

    if not components:
        print("No components found!", file=sys.stderr)
        sys.exit(1)

    print(f"// Parsed {len(components)} components from Windows BG3SE headers", file=sys.stderr)

    # Filter by namespace
    if args.namespace:
        components = [c for c in components if c.full_name.startswith(args.namespace + "::")]
        print(f"// Filtered to {len(components)} {args.namespace}:: components", file=sys.stderr)

    # Filter by high-priority
    if args.high_priority:
        # Match by name (without Component suffix sometimes)
        def is_high_priority(component):
            name = component.name
            # Exact match
            if name in HIGH_PRIORITY_COMPONENTS:
                return True
            # Match with Component suffix
            if name + "Component" in HIGH_PRIORITY_COMPONENTS:
                return True
            # Match without Component suffix
            if name.replace("Component", "") in HIGH_PRIORITY_COMPONENTS:
                return True
            return False
        components = [c for c in components if is_high_priority(c)]
        print(f"// Filtered to {len(components)} high-priority components", file=sys.stderr)

    # Just list names
    if args.list:
        for c in sorted(components, key=lambda x: x.full_name):
            field_count = len([f for f in c.fields if not f.is_hidden])
            print(f"{c.full_name} ({field_count} fields)")
        return

    # Generate output
    output = []

    output.append("/**")
    output.append(" * Generated component stubs from Windows BG3SE headers")
    output.append(f" * Total: {len(components)} components")
    output.append(" *")
    output.append(" * WARNING: Offsets are ESTIMATES based on Windows x64 layout.")
    output.append(" * Each must be verified via Ghidra or runtime probing for ARM64.")
    output.append(" */")
    output.append("")
    output.append("#include \"component_offsets.h\"")
    output.append("")

    # Generate stubs
    for component in sorted(components, key=lambda x: x.full_name):
        output.append(generate_c_stub(component))

    # Generate registry entries
    output.append("// === Registry Entries (add to g_AllComponentLayouts) ===")
    output.append("")
    for component in sorted(components, key=lambda x: x.full_name):
        output.append(generate_registry_entry(component))

    result = "\n".join(output)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(result)
        print(f"Wrote to {args.output}", file=sys.stderr)
    else:
        print(result)

if __name__ == "__main__":
    main()
