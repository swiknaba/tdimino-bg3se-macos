# esv::character:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::character::AutomatedDialogActorComponent | 0x28 | 40 | Automated dialog |
| esv::character::CanOpenDoorsOverrideComponent | 0x01 | 1 | Tag - door override |
| esv::character::DefinitionComponent | 0xa8 | 168 | Character definition |
| esv::character::EntityMovingComponent | 0x01 | 1 | Tag - entity moving |
| esv::character::ExecuteTeleportRequestComponent | 0x18 | 24 | Execute teleport request |
| esv::character::ExternalResourcesComponent | 0x28 | 40 | External resources |
| esv::character::GameplayVisualComponent | 0x10 | 16 | Gameplay visual |
| esv::character::InheritedFactionRequestOneFrameComponent | 0x8 | 8 | OneFrame component |
| esv::character::LoadingAnimationSetComponent | 0x10 | 16 | Loading anim set |
| esv::character::SessionCommonComponent | 0x01 | 1 | Tag - session common |
| esv::character::TurnActionsComponent | 0x150 | 336 | Turn actions (large!) |

**Total: 11 components**
