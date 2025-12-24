# esv::character_creation:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::character_creation:: | 8 |  |  |
| esv::character_creation::AppearanceComponent | 0x4 | 4 |  |
| esv::character_creation::AppearanceVisualTagComponent | 0x10 | 16 | Has invoke function |
| esv::character_creation::BackupDefinitionComponent | 0xa8 | 168 | Has invoke function |
| esv::character_creation::DebugFullDefinitionRequestOneFrameComponent | 0x1b8 | 440 | Debug definition request (large!) |
| esv::character_creation::DefinitionCommonComponent | 0x8 | 8 |  |
| esv::character_creation::EquipmentSetRequestComponent | Not found | No GetComponent/AddComponent function |  |
| esv::character_creation::FullDefinitionComponent | 0x88 | 136 |  |
| esv::character_creation::GodComponent | 0x10 | 16 |  |
| esv::character_creation::IsCustomComponent | 0x01 | 1 | Tag - custom character |
| esv::character_creation::SessionOwnerComponent | 0x10 | 16 | Session owner |
| esv::character_creation::UpdatesComponent | esv::character_creation | Updates tracking |  |

**Total: 12 components**
