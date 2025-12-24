# eoc::interrupt:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::interrupt::ActionStateComponent | 0x128 | 296 | Largest - interrupt sequence data |
| eoc::interrupt::ConditionallyDisabledComponent | 0x01 | 1 | Tag - conditionally disabled |
| eoc::interrupt::ContainerComponent | 0x10 | 16 | Container |
| eoc::interrupt::DataComponent | 0x20 | 32 | Data with GST node refs |
| eoc::interrupt::DecisionComponent | 0x40 | 64 | Hash table for decisions |
| eoc::interrupt::PreferencesComponent | 0x40 | 64 | Hash table for preferences |
| eoc::interrupt::PreparedComponent | 0x01 | 1 | Tag - prepared |
| eoc::interrupt::ZoneComponent | 0x10 | 16 | Zone data |
| eoc::interrupt::ZoneParticipantComponent | 0x40 | 64 | Hash table for participants |
| eoc::interrupt::ZoneSourceComponent | 0x01 | 1 | Tag - zone source |

**Total: 10 components**
