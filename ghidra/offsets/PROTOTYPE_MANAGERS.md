# Prototype Manager Offsets (macOS ARM64)

## Overview

Prototype managers are singletons that hold parsed prototype data for spells, statuses, passives, and interrupts. When `Ext.Stats.Sync()` is called, the stats object must be registered with the appropriate prototype manager for the game to recognize and use it.

## Discovered Singleton Addresses

| Manager | Global Address | Discovery Method |
|---------|----------------|------------------|
| `RPGStats::m_ptr` | `0x1089c5730` | dlsym (exported) |
| `PassivePrototypeManager*` | `0x108aeccd8` | GetPassivePrototype ADRP+LDR |
| `BoostPrototypeManager::m_ptr` | `0x108991528` | Symbol table (not exported) |
| `InterruptPrototypeManager::GetPrototype` | `0x101b9686c` | Function address |

## Additional Global Addresses (from EvaluateInterrupt)

| Address | Usage |
|---------|-------|
| `0x108aefa98` | Memory manager (appears in multiple functions) |
| `0x108aecce0` | EvaluateInterrupt global (q0 vector load) |
| `0x108aecd70` | EvaluateInterrupt global (w20/w28 load) |

### ADRP+LDR Pattern Evidence

**GetPassivePrototype at `0x102655c14`:**
```asm
0x102655cfc: adrp x8,0x108aec000
0x102655d00: ldr x8,[x8, #0xcd8]    ; x8 = *(0x108aec000 + 0xcd8) = *0x108aeccd8
```

This loads the PassivePrototypeManager singleton pointer from global address `0x108aeccd8`.

**GetPassivePrototypes at `0x102014284`:**
```asm
0x1020142a8: adrp x8,0x1089c5000
0x1020142ac: ldr x23,[x8, #0x730]   ; x23 = RPGStats::m_ptr at 0x1089c5730
```

Confirms RPGStats access pattern.

## Related Functions

| Function | Address | Notes |
|----------|---------|-------|
| `GetPassivePrototype` | `0x102655c14` | Looks up passive by name in manager |
| `GetPassivePrototypes` | `0x102014284` | Gets all passives for a status |
| `HasInterruptWithContext` | `0x101b93338` | Uses InterruptPrototypeManager |
| `EvaluateInterrupt` | `0x101b94278` | Large function using interrupt manager |
| `~InterruptPrototypeManager` | `0x101b96610` | Destructor |
| `~InterruptPrototype` | `0x101b95af4` | Prototype destructor (1688 bytes) |

## Decompiled Insights

### PassivePrototype Access Pattern

From `GetPassivePrototype` decompilation:
```c
// Uses DEPRECATED_RefMapImpl for lookup
uVar4 = ls::DEPRECATED_RefMapImpl<...eoc::PassivePrototype...>::operator[](...);
return uVar4;
```

This means the manager stores passives in a `RefMap<FixedString, PassivePrototype>`.

### RPGStats Integration

From `GetPassivePrototypes`:
```c
lVar2 = RPGStats::m_ptr;
// Access ModifierLists at offset 0x68 (verified from STATS.md as 0x60)
plVar7 = *(long **)(*(long *)(RPGStats::m_ptr + 0x68) + (ulong)uVar1 * 8);
// Access FixedStrings pool at offset 0x348
puVar6 = (uint *)(*(long *)(lVar2 + 0x348) + (ulong)uVar1 * 4);
```

## Manager Structure Estimates

### PassivePrototypeManager (from RefMap pattern)

```c
struct PassivePrototypeManager {
    // RefMap stores Name -> PassivePrototype
    RefMap<FixedString, PassivePrototype> Passives;  // Likely at offset 0x00
    bool Initialized;                                  // Flag
};
```

### InterruptPrototype Structure (from destructor)

From `~InterruptPrototype` analysis, the struct is approximately 0x160+ bytes:
- Offset 0xC0: Array pointer
- Offset 0xCC: Array count
- Offset 0xD0: Buffer pointer
- Offset 0xD8: Buffer capacity
- Offset 0xF0: Another array
- Offset 0xFC: Count
- Offset 0x110: Field
- Offset 0x120: Yet another array
- Offset 0x12C: Count

## TODO: Additional Singletons to Discover

The following managers still need singleton pointer discovery:

| Manager | Strategy |
|---------|----------|
| `SpellPrototypeManager` | Find `GetSpellPrototype` function |
| `StatusPrototypeManager` | Find `GetStatusPrototype` function |
| `InterruptPrototypeManager` | Trace from `HasInterruptWithContext` |
| `BoostPrototypeManager` | Find `GetBoostPrototype` function |

### Recommended Ghidra Queries

```python
# Search for functions that load singleton-like patterns
# Look for ADRP to 0x108ae* range followed by LDR
```

## Symbol Table Findings

1585 prototype-related symbols found. Key patterns:
- `eoc::character_creation::_private::ReplaceDefaultValues<SpellPrototype>` at `0x100c48e18`
- `eoc::character_creation::_private::ReplaceDefaultValues<PassivePrototype>` at `0x100c51ae0`

These are initialization helpers used during game startup.

## Implementation Notes

### Implementation Complete (Dec 2025)

Created `src/stats/prototype_managers.h` and `src/stats/prototype_managers.c` with:

1. **Singleton Accessors**
   - `get_passive_prototype_manager()` - Uses 0x108aeccd8
   - `get_boost_prototype_manager()` - Uses 0x108991528
   - `get_interrupt_prototype_manager()` - Uses 0x108aecce0
   - `get_spell_prototype_manager()` - TBD (needs singleton discovery)
   - `get_status_prototype_manager()` - TBD (needs singleton discovery)

2. **Sync Functions**
   - `sync_spell_prototype()` - Placeholder (needs manager)
   - `sync_status_prototype()` - Placeholder (needs manager)
   - `sync_passive_prototype()` - Manager found, needs Init
   - `sync_interrupt_prototype()` - Manager found, needs Init

3. **Unified Interface**
   - `sync_stat_prototype(obj, name, type)` - Dispatches based on stat type

4. **Debug Functions (Lua)**
   - `Ext.Stats.DumpPrototypeManagers()` - Logs manager status
   - `Ext.Stats.ProbePrototypeManager(name)` - Probes manager structure
   - `Ext.Stats.GetPrototypeManagerPtrs()` - Returns raw pointers

### Accessing PassivePrototypeManager

```c
// Pattern from Ghidra analysis
#define OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR 0x108aeccd8ULL

static void* ghidra_to_runtime(uint64_t ghidra_addr) {
    return (void*)((uintptr_t)g_MainBinaryBase + (ghidra_addr - 0x100000000ULL));
}

void* get_passive_prototype_manager(void) {
    void **ptr_addr = (void**)ghidra_to_runtime(OFFSET_PASSIVE_PROTOTYPE_MANAGER_PTR);
    void *manager = NULL;
    safe_read_ptr(ptr_addr, &manager);
    return manager;
}
```

### SyncStat Implementation - Current State

```c
// Called from stats_sync() when type requires prototype sync
bool sync_stat_prototype(StatsObjectPtr obj, const char *name, const char *type) {
    if (strcmp(type, "SpellData") == 0) {
        return sync_spell_prototype(obj, name);
    }
    if (strcmp(type, "StatusData") == 0) {
        return sync_status_prototype(obj, name);
    }
    if (strcmp(type, "PassiveData") == 0) {
        return sync_passive_prototype(obj, name);
    }
    if (strcmp(type, "InterruptData") == 0) {
        return sync_interrupt_prototype(obj, name);
    }
    // Weapon, Armor, etc. don't need prototype sync
    return true;
}
```

### Next Steps for Full Implementation

1. **Discover SpellPrototypeManager singleton**
   - Analyze GetSpellPrototype at 0x10346e740
   - Find ADRP+LDR pattern loading singleton pointer

2. **Discover StatusPrototypeManager singleton**
   - Find GetStatusPrototype function
   - Extract singleton address from assembly

3. **Find Prototype Init functions**
   - Each prototype type has an Init function that parses stats::Object
   - Needed for creating new prototypes

4. **Implement HashMap insertion**
   - Managers use RefMap<FixedString, *Prototype>
   - Need to understand RefMap::Insert or operator[]

## Related Files

- `ghidra/offsets/STATS.md` - RPGStats structure details
- `ghidra/offsets/MULTI_ISSUE.md` - Full Ghidra discovery results
- `src/stats/stats_manager.c` - Current stats implementation
