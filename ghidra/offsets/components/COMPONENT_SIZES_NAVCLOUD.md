# NAVCLOUD:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| navcloud::AgentChangedOneFrameComponent | 0x01 | 1 | Tag - agent changed |
| navcloud::AgentComponent | 0x04 | 4 | Agent handle |
| navcloud::InRangeComponent | 0x01 | 1 | Tag - in range |
| navcloud::LevelLoadedOneFrameComponent | 0x01 | 1 | Tag - level loaded |
| navcloud::ObstacleChangedOneFrameComponent | 0x01 | 1 | Tag - obstacle changed |
| navcloud::ObstacleComponent | 0x1c | 28 | Obstacle data |
| navcloud::ObstacleMetaDataComponent | 0x60 | 96 | Obstacle metadata |
| navcloud::OffMeshLinkComponent | 0x20 | 32 | Off-mesh link |
| navcloud::PathDebugComponent | 0xe0 | 224 | Path debug (largest!) |
| navcloud::PathInternalComponent | 0xb0 | 176 | Path internal |
| navcloud::PathRequestComponent | 0x68 | 104 | Path request |
| navcloud::RegionDataComponent | 0x40 | 64 | Region data |
| navcloud::RegionLoadingComponent | 0x28 | 40 | Region loading |
| navcloud::RegionUnloadingComponent | 0x01 | 1 | Tag - region unloading |
| navcloud::generate::IsWaitingForGenerateComponent | 0x01 | 1 | Tag - waiting for gen |
| navcloud::generate::ZoneComponent | 0x10 | 16 | Zone data |

**Total: 16 components**
