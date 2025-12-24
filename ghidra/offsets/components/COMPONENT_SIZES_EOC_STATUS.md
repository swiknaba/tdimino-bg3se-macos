# eoc::status:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::status::CauseComponent | 0x08 | 8 | Status cause (pointer/ID) |
| eoc::status::ContainerComponent | 0x40 | 64 | Status container |
| eoc::status::ExternalStatusBackupComponent | 0x30 | 48 | External status backup data |
| eoc::status::IDComponent | 0x04 | 4 | Status ID |
| eoc::status::IncapacitatedComponent | 0x50 | 80 | Incapacitated |
| eoc::status::IndicateDarknessComponent | 0x01 | 1 | Tag - darkness indicator |
| eoc::status::LifetimeComponent | 0x08 | 8 | Status lifetime |
| eoc::status::LoseControlComponent | 0x01 | 1 | Tag - lose control |
| eoc::status::TauntedComponent | 0x08 | 8 | Taunted status |
| eoc::status::visual::DisabledComponent | 0x30 | 48 | Visual disabled (HashTable) |

**Total: 10 components**
