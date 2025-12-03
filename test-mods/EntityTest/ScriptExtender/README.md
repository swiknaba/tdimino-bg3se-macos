# EntityTest - BG3SE-macOS Test Mod

## Purpose

EntityTest is a diagnostic mod for validating the Entity Component System (ECS) implementation in BG3SE-macOS. It exercises core APIs that real mods depend on, providing immediate feedback on what's working.

## Design Philosophy

The mod is structured around **progressive testing**:

1. **Immediate tests** (SessionLoaded) - Test APIs available at session start
2. **Deferred tests** (Combat) - Test player entities after they're fully loaded

This mirrors how real mods interact with the game - some data is available immediately, some requires game state progression.

## What It Tests

### 1. EntityWorld Discovery
```lua
Ext.Entity.Discover()
```
Validates that the EntityWorld pointer was captured from game memory. This is the foundation for all entity operations.

### 2. TypeId Discovery
```lua
Ext.Entity.DiscoverTypeIds()
Ext.Entity.DumpTypeIds()
```
Tests runtime discovery of component type indices from `TypeId<T>::m_TypeIndex` globals. These indices are required for `GetComponent` calls.

### 3. GUID → Entity Lookup
```lua
Ext.Entity.Get(guid)
```
Tests the HashMap traversal that converts a 128-bit GUID string into an EntityHandle. Uses both:
- **Player GUIDs** - Known character GUIDs (Astarion, Lae'zel)
- **HashMap GUIDs** - Entities discovered from UuidToHandleMappingComponent

### 4. Component Access
```lua
entity:GetComponent("ecl::Character")
entity:GetComponent("eoc::combat::ParticipantComponent")
```
Tests the full component lookup pipeline:
- EntityStorageContainer::TryGet
- InstanceToPageMap traversal
- ComponentTypeToIndex mapping
- Component buffer access

### 5. Session Events
```lua
Ext.Events.SessionLoaded:Subscribe(callback)
```
Validates that engine lifecycle events fire correctly.

### 6. Osiris Integration
```lua
Ext.Osiris.RegisterListener("PROC_CharacterEnteredCombat", ...)
```
Tests that Osiris event hooks work for triggering deferred tests.

## File Structure

```
EntityTest/
└── ScriptExtender/
    ├── Config.json         # Mod configuration (Lua feature flag)
    ├── README.md           # This file
    └── Lua/
        └── BootstrapServer.lua  # Test implementation
```

## Config.json

```json
{
    "RequiredVersion": 1,
    "ModTable": "EntityTest",
    "FeatureFlags": ["Lua"]
}
```

- **RequiredVersion**: Minimum SE version (1 = any)
- **ModTable**: Lua global table name for this mod
- **FeatureFlags**: `["Lua"]` marks this as an SE mod

## Test GUIDs

The mod uses hardcoded GUIDs for testing:

| Character | GUID |
|-----------|------|
| Astarion | `c7c13742-bacd-460a-8f65-f864fe41f255` |
| Lae'zel | `58a69333-40bf-8358-1d17-fff240d7fb12` |

Plus dynamically discovered HashMap entities from `UuidToHandleMappingComponent`.

## Components Tested

| Component | Purpose |
|-----------|---------|
| `ecl::Character` | Client-side character data |
| `ecl::Item` | Client-side item data |
| `eoc::combat::ParticipantComponent` | Combat system |
| `ls::anubis::TreeComponent` | Animation/behavior trees |

## Usage

### Quick Start

```bash
# Copy to auto-detection path
cp -r test-mods/EntityTest /tmp/EntityTest_extracted

# Launch game
./scripts/bg3w.sh

# Watch output
tail -f /tmp/bg3se_macos.log | grep EntityTest
```

### Expected Output

```
[EntityTest] BootstrapServer.lua loaded!
[EntityTest] Module initialized. HashMap entities tested on load, players tested on combat.
[EntityTest] SessionLoaded - discovering EntityWorld...
[EntityTest] Discover result: true
[EntityTest] === TypeId Discovery Test ===
[EntityTest] DiscoverTypeIds found 11 indices
[EntityTest] === HashMap Entity Test ===
[EntityTest] Testing HashMap GUID: a5eaeafe-220d-bc4d-4cc3-b94574d334c7
[EntityTest]   Entity found: Entity(0x12345678)
[EntityTest]   Handle: 0x12345678
[EntityTest]   ecl::Character: nil
[EntityTest]   ecl::Item: FOUND at 0x...
```

### Combat Test

Enter combat to trigger player entity tests:

```
[EntityTest] Combat started - testing player entities
[EntityTest] Testing GUID: c7c13742-bacd-460a-8f65-f864fe41f255
[EntityTest]   Entity found: Entity(0x...)
[EntityTest]   ecl::Character: FOUND at 0x...
```

## Interpreting Results

| Result | Meaning |
|--------|---------|
| `Entity found` | GUID lookup working |
| `Entity NOT FOUND` | GUID not in HashMap (entity not loaded) |
| `Component: FOUND` | GetComponent pipeline working |
| `Component: nil` | TypeId not discovered or component not attached |
| `Discover result: false` | EntityWorld not captured (enter combat first) |

## Adding New Tests

1. Add component names to `testComponents` table
2. Add test GUIDs to `playerGuids` or `hashMapGuids`
3. Create new test functions following `testGetComponent()` pattern
4. Subscribe to appropriate events for timing

## Related Documentation

- [tools/test-mods/README.md](../../../tools/test-mods/README.md) - Test mod overview
- [ROADMAP.md](../../../ROADMAP.md) - Feature implementation status
- [ghidra/offsets/ENTITY_SYSTEM.md](../../../ghidra/offsets/ENTITY_SYSTEM.md) - ECS architecture
- [ghidra/offsets/COMPONENTS.md](../../../ghidra/offsets/COMPONENTS.md) - Component addresses
