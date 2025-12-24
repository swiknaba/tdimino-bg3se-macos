# eoc::character_creation:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::character_creation::AppearanceComponent | 0x70 | 112 | Appearance data |
| eoc::character_creation::ChangeAppearanceDefinitionComponent | 0x2e0 | 736 |  |
| eoc::character_creation::CharacterChangedAppearanceComponent | 0x130 | 304 | Appearance change |
| eoc::character_creation::CharacterCreatedComponent | 0x3e0 | 992 | Character created (largest!) |
| eoc::character_creation::CharacterDefinitionComponent | 0x290 | 656 | Character definition (large!) |
| eoc::character_creation::CompanionDefinitionComponent | 0x140 | 320 |  |
| eoc::character_creation::DefinitionCommonComponent | 0xc0 | 192 | Definition common |
| eoc::character_creation::FullRespecDefinitionComponent | 0x268 | 616 |  |
| eoc::character_creation::LevelUpComponent | 0x10 | 16 | Has invoke pointer |
| eoc::character_creation::LevelUpDefinitionComponent | 0x330 | 816 |  |
| eoc::character_creation::RespecDefinitionComponent | 0x298 | 664 |  |
| eoc::character_creation::SessionCommonComponent | 0x0c | 12 | Session common |
| eoc::character_creation::StateComponent | 0x03 | 3 | Simple primitive |
| eoc::character_creation::definition::ChangeAppearanceComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |
| eoc::character_creation::definition::CreationComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |
| eoc::character_creation::definition::FullRespecComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |
| eoc::character_creation::definition::HenchmenComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |
| eoc::character_creation::definition::LevelUpComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |
| eoc::character_creation::definition::RespecComponent | - | - | Skipped: No ComponentFrameStorageAllocRaw found |

**Total: 19 components**
