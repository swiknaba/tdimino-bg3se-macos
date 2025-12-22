# Implementation Plan: Ext.Resource API

## Overview

Implement `Ext.Resource.Get()` and `Ext.Resource.GetAll()` for Issue #41 remainder.

## Research Findings

### API Surface (from Windows BG3SE)
```lua
-- Get a single resource by ID and type
local resource = Ext.Resource.Get(resourceId, resourceType)

-- Get all resources of a type
local allResources = Ext.Resource.GetAll(resourceType)
```

### 34 ResourceBankType Values
```
Visual(0), VisualSet(1), Animation(2), AnimationSet(3), Texture(4),
Material(5), Physics(6), Effect(7), Script(8), Sound(9), Lighting(10),
Atmosphere(11), AnimationBlueprint(12), MeshProxy(13), MaterialSet(14),
BlendSpace(15), FCurve(16), Timeline(17), Dialog(18), VoiceBark(19),
TileSet(20), IKRig(21), Skeleton(22), VirtualTexture(23), TerrainBrush(24),
ColorList(25), CharacterVisual(26), MaterialPreset(27), SkinPreset(28),
ClothCollider(29), DiffusionProfile(30), LightCookie(31), TimelineScene(32),
SkeletonMirrorTable(33)
```

### Key Ghidra Discoveries

| Item | Address | Notes |
|------|---------|-------|
| ResourceBank constructor | `0x1060de464` | Called from InitEngine |
| ResourceContainer::GetResource | `0x1060cc608` | Hash table lookup |
| ResourceBank offset | `ResourceManager + 0x28` | Primary bank |
| Secondary bank | `ResourceManager + 0x30` | Client/server split? |
| Type bounds | `< 0x22` (34) | Validated in GetResource |

### ResourceContainer::GetResource Structure
```c
// Decompiled from 0x1060cc608
if ((type < 0x22) && (bank = *(this + type * 8 + 8), bank != 0)) {
    SRWKernelLock::ReadLock((bank + 0x20));
    hash = *fixedString;
    bucketCount = *(bank + 8);
    bucket = hash % bucketCount;
    // Traverse linked list for exact match
    // Return value at entry[2]
}
```

### Confirmed Addresses (Dec 21, 2025)

| Symbol | Address | Source |
|--------|---------|--------|
| `ls::ResourceManager::m_ptr` | `0x108a8f070` | ADRP+LDR in InitEngine |
| ResourceBank constructor | `0x1060de464` | Ghidra decompilation |
| ResourceContainer::GetResource | `0x1060cc608` | Ghidra decompilation |

**Discovery from InitEngine disassembly:**
```asm
105d197e4: adrp x25, 0x108a8f000
105d197e8: ldr  x28, [x25, #0x70]   ; ResourceManager = 0x108a8f000 + 0x70
105d1987c: str  x20, [x28, #0x28]   ; Bank[0] at +0x28
105d19908: str  x20, [x28, #0x30]   ; Bank[1] at +0x30
```

## Implementation Steps

### Step 1: Create Resource Manager Module

**File: `src/resource/resource_manager.h`**
```c
#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include <stdint.h>
#include <stdbool.h>

// ResourceBankType enum (34 values)
typedef enum {
    RESOURCE_VISUAL = 0,
    RESOURCE_VISUAL_SET = 1,
    // ... etc
    RESOURCE_SKELETON_MIRROR_TABLE = 33,
    RESOURCE_SENTINEL = 34
} ResourceBankType;

// Initialize resource system
void resource_manager_init(void);

// Get ResourceManager singleton
void* resource_manager_get(void);

// Get ResourceBank (type 0 = client, 1 = server?)
void* resource_manager_get_bank(int bank_index);

// Get a resource by type and FixedString
void* resource_get(ResourceBankType type, uint32_t fixed_string_id);

// Get all resources of a type (returns array)
typedef struct {
    void** items;
    size_t count;
} ResourceArray;
ResourceArray resource_get_all(ResourceBankType type);
void resource_array_free(ResourceArray* arr);

#endif
```

**File: `src/resource/resource_manager.c`**
- Read global pointer at discovered address
- Offset +0x28 for primary ResourceBank
- Call GetResource at 0x1060cc608 (or reimplement hash lookup)

### Step 3: Create Lua Bindings

**File: `src/lua/lua_resource.h`**
```c
void lua_resource_register(lua_State *L, int ext_table_index);
```

**File: `src/lua/lua_resource.c`**
```c
// Ext.Resource.Get(resourceId, type)
static int lua_resource_get(lua_State *L) {
    const char *resourceId = luaL_checkstring(L, 1);
    const char *typeName = luaL_checkstring(L, 2);

    ResourceBankType type = parse_resource_type(typeName);
    uint32_t fsId = fixed_string_to_id(resourceId);
    void *resource = resource_get(type, fsId);

    if (resource) {
        // Return resource table with properties
        push_resource_to_lua(L, resource, type);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

// Ext.Resource.GetAll(type)
static int lua_resource_get_all(lua_State *L) {
    const char *typeName = luaL_checkstring(L, 1);
    ResourceBankType type = parse_resource_type(typeName);

    ResourceArray arr = resource_get_all(type);
    lua_createtable(L, arr.count, 0);
    for (size_t i = 0; i < arr.count; i++) {
        push_resource_to_lua(L, arr.items[i], type);
        lua_rawseti(L, -2, i + 1);
    }
    resource_array_free(&arr);
    return 1;
}
```

### Step 4: Register in main.c

```c
#include "lua/lua_resource.h"

// In register_ext_namespace():
lua_newtable(L);  // Ext.Resource
lua_resource_register(L, lua_gettop(L));
lua_setfield(L, ext_index, "Resource");
```

### Step 5: Update Build System

**CMakeLists.txt additions:**
```cmake
src/resource/resource_manager.c
src/lua/lua_resource.c
```

## Testing

```lua
-- Test basic get
local visual = Ext.Resource.Get("some-visual-id", "Visual")
_D(visual)

-- Test get all
local allSounds = Ext.Resource.GetAll("Sound")
Ext.Print("Found " .. #allSounds .. " sounds")

-- Test each type
for i = 0, 33 do
    local typeName = Ext.Enums.ResourceBankType[i]
    local all = Ext.Resource.GetAll(typeName)
    Ext.Print(typeName .. ": " .. #all)
end
```

## Resource Property Exposure

Phase 1 (MVP): Just expose resource existence and ID
Phase 2: Expose common properties based on type:
- Visual: Model path, materials
- Sound: Audio file, duration
- Material: Shader, textures
- etc.

## Risks & Mitigations

1. **ResourceManager pointer not found via nm**
   - Fallback: Pattern scan for ADRP+LDR in InitEngine
   - Or hook InitEngine and capture pointer at runtime

2. **Hash table structure differs on macOS**
   - Verify with runtime probing before hardcoding

3. **SRW lock compatibility**
   - May need pthread_rwlock equivalent for thread safety

## Estimated Complexity

- **Low-Medium**: Similar pattern to StaticData capture
- ResourceManager is a singleton like other managers we've captured
- GetResource already reverse-engineered

## Files to Create/Modify

| File | Action |
|------|--------|
| `src/resource/resource_manager.h` | Create |
| `src/resource/resource_manager.c` | Create |
| `src/lua/lua_resource.h` | Create |
| `src/lua/lua_resource.c` | Create |
| `CMakeLists.txt` | Add source files |
| `src/injector/main.c` | Register Ext.Resource |
| `ghidra/offsets/RESOURCE.md` | Document offsets |
