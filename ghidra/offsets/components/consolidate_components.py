#!/usr/bin/env python3
"""
Consolidate all component sizes from staging files into main documentation.
Creates modular files by namespace and a proper index.
"""

from collections import defaultdict
from pathlib import Path

STAGING_DIR = Path("../staging")
OUTPUT_DIR = Path(".")  # Current folder (components/)
INDEX_FILE = Path("../COMPONENT_SIZES.md")
MIN_FOR_SEPARATE_FILE = 10  # Minimum components to get own file

def parse_component_line(line):
    """Parse a markdown table line into component data."""
    line = line.strip()
    if not line.startswith("|"):
        return None

    parts = [p.strip() for p in line.split("|")]
    if len(parts) < 4:
        return None

    component = parts[1].replace('`', '')  # Remove backticks
    if not "::" in component or component == "Component":
        return None

    return {
        "name": component,
        "hex": parts[2] if len(parts) > 2 else "",
        "bytes": parts[3] if len(parts) > 3 else "",
        "notes": parts[4] if len(parts) > 4 else "",
    }

def get_namespace(name):
    """Extract namespace info from component name."""
    parts = name.split("::")
    root = parts[0]  # eoc, esv, ecl, ls, navcloud

    if "BoostComponent" in name and root == "eoc":
        return ("eoc", "boost")

    if len(parts) >= 3:
        return (root, parts[1])
    else:
        return (root, "core")

def read_all_sources():
    """Read all components from all files."""
    components = {}

    # Read from current folder (components/)
    for filepath in OUTPUT_DIR.glob("COMPONENT_SIZES_*.md"):
        with open(filepath) as f:
            for line in f:
                comp = parse_component_line(line)
                if comp and comp["name"] not in components:
                    components[comp["name"]] = comp

    # Read staging files (../staging/)
    if STAGING_DIR.exists():
        for filepath in STAGING_DIR.glob("*.md"):
            with open(filepath) as f:
                for line in f:
                    comp = parse_component_line(line)
                    if comp and comp["name"] not in components:
                        components[comp["name"]] = comp

    return components

def organize_components(components):
    """Organize by root namespace and sub-namespace."""
    organized = defaultdict(lambda: defaultdict(dict))

    for name, comp in components.items():
        root, sub = get_namespace(name)
        organized[root][sub][name] = comp

    return organized

def decide_file_structure(organized):
    """Decide which sub-namespaces get their own file."""
    files = []

    for root in sorted(organized.keys()):
        subs = organized[root]

        # Collect all components for this root
        all_for_root = {}
        for sub, comps in subs.items():
            all_for_root.update(comps)

        # If total for root is small, one file
        if len(all_for_root) < 50:
            files.append({
                "key": root,
                "filename": f"COMPONENT_SIZES_{root.upper()}.md",
                "title": f"{root.upper()}:: Components",
                "components": all_for_root
            })
            continue

        # Otherwise, split by sub-namespace
        misc = {}
        for sub, comps in sorted(subs.items()):
            if len(comps) >= MIN_FOR_SEPARATE_FILE:
                files.append({
                    "key": f"{root}_{sub}",
                    "filename": f"COMPONENT_SIZES_{root.upper()}_{sub.upper()}.md",
                    "title": f"{root}::{sub}:: Components",
                    "components": comps
                })
            else:
                misc.update(comps)

        # Leftover goes to misc
        if misc:
            files.append({
                "key": f"{root}_misc",
                "filename": f"COMPONENT_SIZES_{root.upper()}_MISC.md",
                "title": f"{root}:: Miscellaneous Components",
                "components": misc
            })

    return files

def write_component_file(info):
    """Write a component file."""
    filepath = OUTPUT_DIR / info["filename"]
    comps = sorted(info["components"].values(), key=lambda c: c["name"])

    lines = [
        f"# {info['title']} - ARM64 Sizes",
        "",
        "Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.",
        "",
        "| Component | Hex | Bytes | Notes |",
        "|-----------|-----|-------|-------|",
    ]

    for c in comps:
        lines.append(f"| {c['name']} | {c['hex']} | {c['bytes']} | {c['notes']} |")

    lines.extend(["", f"**Total: {len(comps)} components**", ""])

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))

    return len(comps)

def write_index(files, total):
    """Write the master index file."""
    # Group files by root namespace
    by_root = defaultdict(list)
    for f in files:
        root = f["key"].split("_")[0]
        by_root[root].append(f)

    lines = [
        "# ARM64 Component Sizes Index",
        "",
        f"**Total: {total} unique component sizes** extracted via Ghidra MCP decompilation.",
        "",
        "## Files by Namespace",
        "",
    ]

    for root in sorted(by_root.keys()):
        root_files = by_root[root]
        root_total = sum(len(f["components"]) for f in root_files)
        lines.append(f"### {root}:: ({root_total} components)")
        lines.append("")
        lines.append("| File | Contents | Count |")
        lines.append("|------|----------|-------|")
        for f in sorted(root_files, key=lambda x: x["filename"]):
            link = f"components/{f['filename']}"
            lines.append(f"| [{f['filename']}]({link}) | {f['title']} | {len(f['components'])} |")
        lines.append("")

    lines.extend([
        "## Coverage",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        "| Total BG3 components | 1,999 |",
        f"| Sizes extracted | {total} |",
        f"| Coverage | {total/1999*100:.1f}% |",
        "",
    ])

    with open(INDEX_FILE, 'w') as f:
        f.write('\n'.join(lines))

def write_folder_index(files, total):
    """Write an index inside the components folder."""
    filepath = OUTPUT_DIR / "INDEX.md"

    # Group files by root namespace
    by_root = defaultdict(list)
    for f in files:
        root = f["key"].split("_")[0]
        by_root[root].append(f)

    lines = [
        "# Component Sizes by Namespace",
        "",
        f"**{total} components** across {len(files)} files.",
        "",
    ]

    for root in sorted(by_root.keys()):
        root_files = by_root[root]
        root_total = sum(len(f["components"]) for f in root_files)
        lines.append(f"## {root}:: ({root_total})")
        lines.append("")
        for f in sorted(root_files, key=lambda x: x["filename"]):
            lines.append(f"- [{f['filename']}]({f['filename']}) - {len(f['components'])} components")
        lines.append("")

    with open(filepath, 'w') as f:
        f.write('\n'.join(lines))

def main():
    print("Consolidating all component sizes...")
    print()

    # Ensure output directory exists
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Read all sources
    components = read_all_sources()
    print(f"Found {len(components)} unique components")
    print()

    # Organize by namespace
    organized = organize_components(components)

    # Decide file structure
    files = decide_file_structure(organized)

    # Write each file
    total = 0
    for f in files:
        count = write_component_file(f)
        print(f"{f['filename']}: {count} components")
        total += count

    # Write indices
    write_index(files, total)
    write_folder_index(files, total)
    print(f"\nCOMPONENT_SIZES.md: index updated")
    print(f"components/INDEX.md: folder index created")

    print(f"\n=== TOTAL: {total} unique components ({total/1999*100:.1f}% coverage) ===")

if __name__ == "__main__":
    main()
