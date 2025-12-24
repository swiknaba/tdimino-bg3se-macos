# eoc::analytics:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::analytics::EventApprovalRatingComponent | 0x40 | 64 | Approval rating event |
| eoc::analytics::EventCombatStartedComponent | 0x58 | 88 | Combat started event |
| eoc::analytics::EventCombatTurnComponent | 0x60 | 96 | Combat turn event |
| eoc::analytics::EventDisturbanceInvestigatedComponent | 0x18 | 24 | Disturbance investigated |
| eoc::analytics::EventDisturbanceResolvedComponent | 0x18 | 24 | Disturbance resolved |
| eoc::analytics::EventDisturbanceStartedComponent | 0x18 | 24 | Disturbance started |
| eoc::analytics::EventFTBStartedComponent | 0x20 | 32 | FTB started event |
| eoc::analytics::EventGlobalFlagSetComponent | 0x18 | 24 | Global flag set |
| eoc::analytics::EventGoalAchievedComponent | 0x20 | 32 | Goal achieved |
| eoc::analytics::EventGoldChangedComponent | 0x10 | 16 | Gold changed |
| eoc::analytics::EventInterruptUsedComponent | 0x20 | 32 | Interrupt used |
| eoc::analytics::EventInventoryAddedComponent | 0x40 | 64 | Inventory added |
| eoc::analytics::EventInventoryRemovedComponent | 48 (via `* 0x30`) |  |  |
| eoc::analytics::EventItemCombineComponent | 48 (via `* 0x30`) |  |  |
| eoc::analytics::EventItemUseComponent | 0x18 | 24 | Item usage tracking |
| eoc::analytics::EventLevelUpEndedComponent | 0x68 | 104 | Level up analytics |
| eoc::analytics::EventOsirisComponent | 0x28 | 40 | Osiris event tracking |
| eoc::analytics::EventRestTypeAndSuppliesChosenComponent | 0x38 | 56 | Rest choice analytics |
| eoc::analytics::EventRollComponent | 0x30 | 48 | Roll tracking |
| eoc::analytics::EventSaveGameErrorComponent | 0x10 | 16 | Save error tracking |
| eoc::analytics::EventSpellUseComponent | 0x80 | 128 | Spell usage (largest analytics!) |

**Total: 21 components**
