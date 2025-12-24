# esv::passive:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::passive:: | 4 |  |  |
| esv::passive::ActiveRollPassivesComponent | 24 (0x18) | ComponentFrameStorageAllocRaw(,0x18,) | Confirmed from decompilation |
| esv::passive::BoostsComponent | 0x340 | 832 |  |
| esv::passive::MigratableBoostsComponent | 0x90 | 144 |  |
| esv::passive::PassiveBaseComponent | 0x8 | 8 |  |
| esv::passive::PersistentDataComponent | 0x08 | 8 | Passive data |
| esv::passive::PostponedFunctorsComponent | 0x40 (64) |  |  |
| esv::passive::RequestTargetTrackingOneFrameComponent | 0x40 | 64 |  |
| esv::passive::ScriptPassivesComponent | 0x10 | 16 |  |
| esv::passive::ToggledPassivesComponent | 0x28 | 40 |  |

**Total: 10 components**
