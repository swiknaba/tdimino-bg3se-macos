#!/usr/bin/env python3
"""
find_multi_issue_offsets.py - Comprehensive Multi-Issue Offset Discovery

Accelerates discovery for 5 major issues simultaneously:
- Issue #40: StaticData (eoc__gGuidResourceManager)
- Issue #32: Stats Sync (Prototype managers)
- Issue #41: Resource/Template (Resource banks)
- Issue #38: Audio (Wwise symbols)
- Issue #37: Physics (Raycast functions)

Usage:
    ./ghidra/scripts/run_analysis.sh find_multi_issue_offsets.py

Monitor:
    tail -f /tmp/ghidra_progress.log

Output:
    /tmp/multi_issue_offsets.md
"""

from ghidra.program.model.symbol import SymbolType
from progress_utils import init_progress, progress, finish_progress
import time

# ==============================================================================
# Constants
# ==============================================================================

GHIDRA_BASE = 0x100000000
OUTPUT_FILE = "/tmp/multi_issue_offsets.md"

# Issue #40: StaticData patterns
STATIC_DATA_SYMBOLS = [
    "gGuidResourceManager",
    "GuidResourceManager",
    "ResourceDefinitions",
]
STATIC_DATA_STRINGS = [
    "Background",
    "Feat",
    "Origin",
    "Progression",
    "ClassDescription",
    "Race",
    "AbilityDistribution",
    "PassiveList",
    "SkillList",
    "CharacterCreationPreset",
]

# Issue #32: Prototype Manager patterns
PROTOTYPE_TYPES = ["Spell", "Status", "Passive", "Interrupt"]
PROTOTYPE_STRINGS = {
    "Spell": ["SpellData", "SpellType", "SpellFlags", "SpellId"],
    "Status": ["StatusData", "StatusType", "StatusPropertyFlags"],
    "Passive": ["PassiveData", "PassivePrototype", "EnabledContext"],
    "Interrupt": ["InterruptData", "InterruptPrototype"],
}

# Issue #41: Resource/Template patterns
RESOURCE_SYMBOLS = [
    "TemplateManager",
    "LocalTemplateCache",
    "ResourceManager",
    "ResourceBank",
    "GameObjectTemplate",
]
RESOURCE_STRINGS = [
    "RootTemplate",
    "Templates/",
    ".lsf",
]

# Issue #38: Wwise Audio patterns
WWISE_SYMBOLS = [
    "PostEvent",
    "SetPosition",
    "LoadBank",
    "UnloadBank",
    "StopAll",
    "SetRTPCValue",
    "SoundEngine",
]
WWISE_STRINGS = [
    "Play_",
    "Stop_",
    "Wwise",
    "AK::",
]

# Issue #37: Physics patterns
PHYSICS_SYMBOLS = [
    "Raycast",
    "RaycastClosest",
    "SweepSingle",
    "SweepSphere",
    "CollisionWorld",
    "PhysicsWorld",
    "PhysicsScene",
]
PHYSICS_STRINGS = [
    "RayCast",
    "Collision",
    "hkp",  # Havok prefix
    "btCollision",  # Bullet prefix
]

# ==============================================================================
# Core Utilities
# ==============================================================================

class SymbolSearcher:
    """Symbol and string search utilities."""

    def __init__(self, program):
        self.program = program
        self.memory = program.getMemory()
        self.symbol_table = program.getSymbolTable()
        self.listing = program.getListing()
        self.fm = program.getFunctionManager()

    def find_symbols_containing(self, pattern):
        """Find all symbols containing pattern."""
        results = []
        symbols = self.symbol_table.getAllSymbols(False)
        for sym in symbols:
            name = sym.getName()
            if pattern.lower() in name.lower():
                results.append({
                    'name': name,
                    'address': sym.getAddress(),
                    'type': str(sym.getSymbolType()),
                })
        return results

    def find_string_address(self, search_str):
        """Find address of a string in memory."""
        search_bytes = search_str.encode('utf-8')

        for block in self.memory.getBlocks():
            if not block.isInitialized():
                continue

            start = block.getStart()
            end = block.getEnd()

            try:
                addr = self.memory.findBytes(start, end, search_bytes, None, True, monitor)
                if addr:
                    return addr
            except:
                pass

        return None

    def find_xrefs_to(self, addr):
        """Find all cross-references to an address."""
        refs = []
        ref_mgr = self.program.getReferenceManager()
        ref_iter = ref_mgr.getReferencesTo(addr)
        while ref_iter.hasNext():
            ref = ref_iter.next()
            refs.append(ref.getFromAddress())
        return refs

    def get_function_at(self, addr):
        """Get function containing address."""
        return self.fm.getFunctionContaining(addr)

    def find_functions_by_name(self, pattern):
        """Find functions with name matching pattern."""
        results = []
        func_iter = self.fm.getFunctions(True)
        while func_iter.hasNext():
            func = func_iter.next()
            name = func.getName()
            if pattern.lower() in name.lower():
                results.append({
                    'name': name,
                    'address': func.getEntryPoint(),
                })
        return results


class OutputFormatter:
    """Generate console and markdown output."""

    def __init__(self):
        self.findings = {}
        self.start_time = time.time()

    def add_section(self, issue_id, title, findings):
        """Add a section of findings."""
        self.findings[issue_id] = {
            'title': title,
            'findings': findings,
        }

    def print_section(self, issue_id, title, findings):
        """Print a section to console."""
        print("\n" + "=" * 60)
        print("=== %s: %s ===" % (issue_id, title))
        print("=" * 60)

        if not findings:
            print("[-] No findings")
            return

        for category, items in findings.items():
            print("\n[%s]" % category)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        name = item.get('name', 'unknown')
                        addr = item.get('address', '?')
                        print("  [+] %s @ %s" % (name, addr))
                    else:
                        print("  [+] %s" % item)
            elif isinstance(items, dict):
                for k, v in items.items():
                    print("  [+] %s: %s" % (k, v))
            else:
                print("  [+] %s" % items)

    def generate_markdown(self):
        """Generate markdown documentation."""
        lines = [
            "# Multi-Issue Offset Discovery Results",
            "",
            "**Binary:** BG3 macOS ARM64",
            "**Date:** %s" % time.strftime("%Y-%m-%d %H:%M"),
            "**Script:** find_multi_issue_offsets.py",
            "**Duration:** %.1f seconds" % (time.time() - self.start_time),
            "",
        ]

        for issue_id, data in sorted(self.findings.items()):
            lines.append("---")
            lines.append("")
            lines.append("## %s: %s" % (issue_id, data['title']))
            lines.append("")

            findings = data['findings']
            if not findings:
                lines.append("*No findings*")
                lines.append("")
                continue

            for category, items in findings.items():
                lines.append("### %s" % category)
                lines.append("")

                if isinstance(items, list):
                    lines.append("| Name | Address | Offset |")
                    lines.append("|------|---------|--------|")
                    for item in items:
                        if isinstance(item, dict):
                            name = item.get('name', 'unknown')
                            addr = item.get('address', '?')
                            try:
                                offset = "+0x%x" % (addr.getOffset() - GHIDRA_BASE)
                            except:
                                offset = "?"
                            lines.append("| `%s` | `%s` | `%s` |" % (name, addr, offset))
                        else:
                            lines.append("| %s | - | - |" % item)
                elif isinstance(items, dict):
                    for k, v in items.items():
                        lines.append("- **%s:** `%s`" % (k, v))
                else:
                    lines.append("- %s" % items)

                lines.append("")

        # Summary
        lines.append("---")
        lines.append("")
        lines.append("## Summary")
        lines.append("")

        total_found = 0
        for issue_id, data in self.findings.items():
            findings = data['findings']
            count = 0
            for items in findings.values():
                if isinstance(items, list):
                    count += len(items)
                elif items:
                    count += 1

            status = "HIGH" if count >= 3 else "MEDIUM" if count >= 1 else "LOW"
            lines.append("- **%s:** %d findings (%s confidence)" % (issue_id, count, status))
            total_found += count

        lines.append("")
        lines.append("**Total findings:** %d" % total_found)
        lines.append("")

        return "\n".join(lines)


# ==============================================================================
# Issue Modules
# ==============================================================================

def discover_static_data(searcher):
    """Issue #40: Find StaticData / GuidResourceManager offsets."""
    findings = {
        'Singleton Symbols': [],
        'Resource Type Strings': [],
        'Related Functions': [],
    }

    # Search for GuidResourceManager symbols
    for pattern in STATIC_DATA_SYMBOLS:
        symbols = searcher.find_symbols_containing(pattern)
        for sym in symbols:
            findings['Singleton Symbols'].append(sym)

    # Search for ExtResourceManagerType enum strings
    for type_str in STATIC_DATA_STRINGS[:6]:  # Limit to first 6
        addr = searcher.find_string_address(type_str)
        if addr:
            findings['Resource Type Strings'].append({
                'name': type_str,
                'address': addr,
            })

    # Search for related functions
    for pattern in ["ResourceManager", "ResourceBank", "GuidResource"]:
        funcs = searcher.find_functions_by_name(pattern)
        for func in funcs[:5]:  # Limit
            findings['Related Functions'].append(func)

    return findings


def discover_prototype_managers(searcher):
    """Issue #32: Find Prototype Manager singletons."""
    findings = {
        'Manager Symbols': [],
        'Type Strings Found': [],
        'Init Function Candidates': [],
    }

    # Search for prototype manager symbols
    for proto_type in PROTOTYPE_TYPES:
        pattern = "%sPrototype" % proto_type
        symbols = searcher.find_symbols_containing(pattern)
        for sym in symbols[:5]:  # Limit per type
            findings['Manager Symbols'].append(sym)

    # Search for type strings that Init functions parse
    for proto_type, strings in PROTOTYPE_STRINGS.items():
        for type_str in strings[:2]:  # Limit per type
            addr = searcher.find_string_address(type_str)
            if addr:
                findings['Type Strings Found'].append({
                    'name': "%s: %s" % (proto_type, type_str),
                    'address': addr,
                })

    # Search for Init function candidates
    for pattern in ["Prototype::Init", "PrototypeManager", "SyncStat"]:
        funcs = searcher.find_functions_by_name(pattern)
        for func in funcs[:3]:
            findings['Init Function Candidates'].append(func)

    return findings


def discover_resources(searcher):
    """Issue #41: Find Resource/Template system offsets."""
    findings = {
        'Resource Symbols': [],
        'Template Strings': [],
        'Related Functions': [],
    }

    # Search for resource manager symbols
    for pattern in RESOURCE_SYMBOLS:
        symbols = searcher.find_symbols_containing(pattern)
        for sym in symbols[:5]:
            findings['Resource Symbols'].append(sym)

    # Search for template-related strings
    for template_str in RESOURCE_STRINGS:
        addr = searcher.find_string_address(template_str)
        if addr:
            findings['Template Strings'].append({
                'name': template_str,
                'address': addr,
            })

    # Search for related functions
    for pattern in ["Template", "Resource"]:
        funcs = searcher.find_functions_by_name(pattern)
        for func in funcs[:5]:
            findings['Related Functions'].append(func)

    return findings


def discover_audio(searcher):
    """Issue #38: Find Wwise audio engine symbols."""
    findings = {
        'Wwise Symbols': [],
        'Audio Strings': [],
        'Sound Functions': [],
    }

    # Search for Wwise symbols
    for pattern in WWISE_SYMBOLS:
        symbols = searcher.find_symbols_containing(pattern)
        for sym in symbols[:5]:
            findings['Wwise Symbols'].append(sym)

    # Search for audio event strings
    for audio_str in WWISE_STRINGS:
        addr = searcher.find_string_address(audio_str)
        if addr:
            findings['Audio Strings'].append({
                'name': audio_str,
                'address': addr,
            })

    # Search for sound-related functions
    for pattern in ["Sound", "Audio", "Music", "Wwise"]:
        funcs = searcher.find_functions_by_name(pattern)
        for func in funcs[:3]:
            findings['Sound Functions'].append(func)

    return findings


def discover_physics(searcher):
    """Issue #37: Find physics/raycast functions."""
    findings = {
        'Physics Symbols': [],
        'Physics Strings': [],
        'Raycast Functions': [],
    }

    # Search for physics symbols
    for pattern in PHYSICS_SYMBOLS:
        symbols = searcher.find_symbols_containing(pattern)
        for sym in symbols[:5]:
            findings['Physics Symbols'].append(sym)

    # Search for physics engine strings
    for phys_str in PHYSICS_STRINGS:
        addr = searcher.find_string_address(phys_str)
        if addr:
            findings['Physics Strings'].append({
                'name': phys_str,
                'address': addr,
            })

    # Search for raycast/sweep functions
    for pattern in ["Raycast", "Sweep", "Collision", "Physics"]:
        funcs = searcher.find_functions_by_name(pattern)
        for func in funcs[:3]:
            findings['Raycast Functions'].append(func)

    return findings


# ==============================================================================
# Main
# ==============================================================================

def main():
    """Main entry point."""
    init_progress("find_multi_issue_offsets.py")

    print("\n" + "=" * 70)
    print("BG3SE-macOS Multi-Issue Offset Discovery")
    print("=" * 70)
    print("Binary base: 0x%x" % GHIDRA_BASE)
    print("Output: %s" % OUTPUT_FILE)
    print("=" * 70 + "\n")

    # Initialize utilities
    progress("Initializing search utilities", 5)
    searcher = SymbolSearcher(currentProgram)
    formatter = OutputFormatter()

    # Issue modules with their discovery functions
    modules = [
        ("Issue #40", "StaticData (GuidResourceManager)", discover_static_data, 10),
        ("Issue #32", "Stats Sync (Prototype Managers)", discover_prototype_managers, 30),
        ("Issue #41", "Resource/Template", discover_resources, 50),
        ("Issue #38", "Audio (Wwise)", discover_audio, 70),
        ("Issue #37", "Physics (Raycast)", discover_physics, 85),
    ]

    # Run each module
    for issue_id, title, discover_func, pct in modules:
        progress("Discovering: %s" % title, pct)

        try:
            findings = discover_func(searcher)
            formatter.add_section(issue_id, title, findings)
            formatter.print_section(issue_id, title, findings)
        except Exception as e:
            print("[-] Error in %s: %s" % (issue_id, str(e)))
            formatter.add_section(issue_id, title, {'Error': str(e)})

    # Generate markdown output
    progress("Generating markdown output", 95)
    md_content = formatter.generate_markdown()

    try:
        with open(OUTPUT_FILE, 'w') as f:
            f.write(md_content)
        print("\n[+] Markdown output written to: %s" % OUTPUT_FILE)
    except Exception as e:
        print("[-] Failed to write output: %s" % str(e))

    # Final summary
    progress("Discovery complete", 98)
    print("\n" + "=" * 70)
    print("DISCOVERY COMPLETE")
    print("=" * 70)
    print("Review output: %s" % OUTPUT_FILE)
    print("Next steps:")
    print("  1. Review findings for each issue")
    print("  2. Use XREFs to trace from strings to singletons")
    print("  3. Verify offsets with runtime probing (Ext.Debug.ProbeStruct)")
    print("=" * 70)

    finish_progress()


if __name__ == "__main__":
    main()
