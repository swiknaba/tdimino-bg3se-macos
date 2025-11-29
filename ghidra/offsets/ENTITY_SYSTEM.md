# Entity System Architecture

## Overview

BG3 uses an Entity Component System (ECS) with the same architecture on macOS as Windows.

## Namespace Structure

| Namespace | Purpose |
|-----------|---------|
| `ecs::` | Core ECS infrastructure (EntityWorld, EntityHandle) |
| `eoc::` | Engine of Creation - shared game components |
| `esv::` | Server-side components and systems |
| `ecl::` | Client-side components and systems |
| `ls::` | Larian Studios core (Transform, Level, etc.) |

## EntityHandle

64-bit packed value:
- **Bits 0-31**: Entity Index (within type)
- **Bits 32-47**: Salt (generation counter)
- **Bits 48-63**: Type Index (archetype)

```c
#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

static inline uint32_t entity_get_index(EntityHandle h) {
    return (uint32_t)(h & 0xFFFFFFFF);
}
static inline uint16_t entity_get_salt(EntityHandle h) {
    return (uint16_t)((h >> 32) & 0xFFFF);
}
static inline uint16_t entity_get_type(EntityHandle h) {
    return (uint16_t)((h >> 48) & 0xFFFF);
}
```

## Capturing EntityWorld

Global singletons (`esv::EoCServer`, `ecl::EoCClient`) are not exported.
We capture `EntityWorld*` by hooking functions that receive it:

**Target:** `eoc::CombatHelpers::LEGACY_IsInCombat`
- **Address:** `0x10124f92c`
- **Signature:** `bool (EntityHandle, EntityWorld&)`

```c
static EntityWorld *g_EntityWorld = NULL;

bool hook_LEGACY_IsInCombat(uint64_t handle, void *entityWorld) {
    if (!g_EntityWorld) {
        g_EntityWorld = entityWorld;
    }
    return original(handle, entityWorld);
}
```

## GUID to EntityHandle Lookup

**Singleton:** `ls::uuid::ToHandleMappingComponent`
**TryGetSingleton Address:** `0x1010dc924`

Contains `HashMap<Guid, EntityHandle> Mappings` at offset 0x0.

### HashMap Layout (64 bytes)

```
offset 0x00: StaticArray<int32_t> HashKeys   (bucket table)
offset 0x10: Array<int32_t> NextIds          (collision chain)
offset 0x20: Array<Guid> Keys                (key storage)
offset 0x30: StaticArray<EntityHandle> Values
```

### Lookup Algorithm

```c
EntityHandle lookup(HashMap *map, Guid *guid) {
    uint64_t hash = guid->lo ^ guid->hi;
    uint32_t bucket = hash % map->HashKeys.size;
    int32_t idx = map->HashKeys.buf[bucket];

    while (idx >= 0) {
        if (map->Keys.buf[idx].lo == guid->lo &&
            map->Keys.buf[idx].hi == guid->hi) {
            return map->Values.buf[idx];
        }
        idx = map->NextIds.buf[idx];
    }
    return ENTITY_HANDLE_INVALID;
}
```

## ECS Helper Functions

| Function | Address | Signature |
|----------|---------|-----------|
| `LEGACY_IsInCombat` | `0x10124f92c` | `(EntityHandle, EntityWorld&)` |
| `LEGACY_GetCombatFromGuid` | `0x101250074` | `(Guid&, EntityWorld&)` |
| `TryGetSingleton<UuidMapping>` | `0x1010dc924` | `(EntityWorld&)` |
