# Resource System Offsets

Documentation for the `ls::ResourceManager` and `ls::ResourceBank` structures used by `Ext.Resource`.

## Global Pointers

| Symbol | Address | Notes |
|--------|---------|-------|
| `ls::ResourceManager::m_ptr` | `0x108a8f070` | Global singleton pointer |

**Discovery method:** Traced from `InitEngine` function at `0x105d197e4`:
```asm
105d197e4: adrp x25, 0x108a8f000
105d197e8: ldr  x28, [x25, #0x70]   ; x28 = ResourceManager ptr
```

## ResourceManager Structure

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x28 | `ResourceBank*` | Primary bank | Client-side resources |
| +0x30 | `ResourceBank*` | Secondary bank | Server-side resources? |

**Discovery method:** Store instructions after ResourceBank construction in `InitEngine`:
```asm
105d1987c: str x20, [x28, #0x28]   ; Store first ResourceBank at +0x28
105d19908: str x20, [x28, #0x30]   ; Store second ResourceBank at +0x30
```

## ResourceBank Structure

ResourceBank manages multiple ResourceContainers, one per resource type.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x08 | `ResourceContainer*[34]` | Type banks | Array indexed by ResourceBankType |

## ResourceContainer Structure

Each ResourceContainer holds resources of a single type using a hash table.

| Offset | Type | Field | Notes |
|--------|------|-------|-------|
| +0x08 | `uint32_t` | bucket_count | Number of hash buckets |
| +0x20 | `SRWKernelLock` | lock | Read-write lock for thread safety |

**From `ResourceContainer::GetResource` at `0x1060cc608`:**
```c
// Bounds check: type < 0x22 (34 types)
// Bank access: this + (type * 8) + 8
// Hash lookup: key % bucket_count, then linked list traversal
// Result at entry[2]
```

## ResourceBankType Enum

34 resource types (0-33):

| Value | Name | Description |
|-------|------|-------------|
| 0 | Visual | 3D model visuals |
| 1 | VisualSet | Visual collections |
| 2 | Animation | Animation data |
| 3 | AnimationSet | Animation collections |
| 4 | Texture | Texture maps |
| 5 | Material | Material definitions |
| 6 | Physics | Physics data |
| 7 | Effect | Visual effects |
| 8 | Script | Script resources |
| 9 | Sound | Audio files |
| 10 | Lighting | Light definitions |
| 11 | Atmosphere | Atmospheric effects |
| 12 | AnimationBlueprint | Animation blueprints |
| 13 | MeshProxy | Mesh proxies |
| 14 | MaterialSet | Material collections |
| 15 | BlendSpace | Animation blend spaces |
| 16 | FCurve | Function curves |
| 17 | Timeline | Timeline data |
| 18 | Dialog | Dialog resources |
| 19 | VoiceBark | Voice barks |
| 20 | TileSet | Tile sets |
| 21 | IKRig | Inverse kinematics rigs |
| 22 | Skeleton | Skeleton data |
| 23 | VirtualTexture | Virtual textures |
| 24 | TerrainBrush | Terrain brushes |
| 25 | ColorList | Color palettes |
| 26 | CharacterVisual | Character visuals |
| 27 | MaterialPreset | Material presets |
| 28 | SkinPreset | Skin presets |
| 29 | ClothCollider | Cloth collision |
| 30 | DiffusionProfile | SSS profiles |
| 31 | LightCookie | Light cookies |
| 32 | TimelineScene | Timeline scenes |
| 33 | SkeletonMirrorTable | Skeleton mirrors |

## Key Functions

| Function | Address | Signature |
|----------|---------|-----------|
| `ResourceBank::ResourceBank` | `0x1060de464` | Constructor |
| `ResourceContainer::GetResource` | `0x1060cc608` | `GetResource(type, FixedString&)` |

## Usage Pattern

```c
// Read ResourceManager global
void* resource_manager = *(void**)0x108a8f070;

// Get primary ResourceBank
void* resource_bank = *(void**)(resource_manager + 0x28);

// Get resource by type and FixedString
// Call ResourceContainer::GetResource or reimplement hash lookup
```

## Version Info

- **Game Version:** Baldur's Gate 3 macOS (current as of Dec 2024)
- **Binary:** `/Applications/Baldur's Gate 3.app/Contents/MacOS/Baldur's Gate 3`
- **Discovered:** Dec 21, 2025
