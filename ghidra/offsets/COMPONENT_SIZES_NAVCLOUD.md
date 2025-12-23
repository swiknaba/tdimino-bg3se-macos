# Navigation Cloud (navcloud::) Components - ARM64 Sizes

Navigation and pathfinding components for AI movement.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Agent Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::AgentComponent | 0x04 | 4 | Agent handle |
| navcloud::AgentChangedOneFrameComponent | 0x01 | 1 | Tag - agent changed |
| navcloud::InRangeComponent | 0x01 | 1 | Tag - in range |
| navcloud::LevelLoadedOneFrameComponent | 0x01 | 1 | Tag - level loaded |

## Obstacle Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::ObstacleComponent | 0x1c | 28 | Obstacle data |
| navcloud::ObstacleChangedOneFrameComponent | 0x01 | 1 | Tag - obstacle changed |

## Pathfinding

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::PathRequestComponent | 0x68 | 104 | Path request |
| navcloud::PathDebugComponent | 0xe0 | 224 | Path debug (largest!) |
| navcloud::PathInternalComponent | 0xb0 | 176 | Path internal |
| navcloud::OffMeshLinkComponent | 0x20 | 32 | Off-mesh link |

## Region Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::ObstacleMetaDataComponent | 0x60 | 96 | Obstacle metadata |
| navcloud::RegionDataComponent | 0x40 | 64 | Region data |
| navcloud::RegionLoadingComponent | 0x28 | 40 | Region loading |
| navcloud::RegionUnloadingComponent | 0x01 | 1 | Tag - region unloading |

## Generation Sub-namespace (navcloud::generate::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::generate::IsWaitingForGenerateComponent | 0x01 | 1 | Tag - waiting for gen |
| navcloud::generate::ZoneComponent | 0x10 | 16 | Zone data |

## Statistics

- **Total navcloud:: components:** 17
- **Smallest:** Multiple tag components (1 byte)
- **Largest:** PathDebugComponent (224 bytes), PathInternalComponent (176 bytes)
- **Pattern:** AI navigation uses tag components for state transitions, path components are substantial
- **New additions:** Region components for dynamic navmesh loading, path debug/internal data
