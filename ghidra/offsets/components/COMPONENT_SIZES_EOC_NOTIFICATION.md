# eoc::notification:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::notification::ApprovalRatingComponent | 0x28 | 40 | Approval rating |
| eoc::notification::BackgroundGoalComponent | 0x20 | 32 | Background goal |
| eoc::notification::CancelScriptAnimationComponent | 0x18 | 24 | Cancel script anim |
| eoc::notification::ConcentrationChangedComponent | 0x88 | 136 | Concentration changed |
| eoc::notification::EnemySightedComponent | 0x18 | 24 | Enemy sighted |
| eoc::notification::GatherAtCampCheckComponent | 2 | 0x2 | AddComponentUnchecked<eoc::notification::GatherAtCampCheckComponent> |
| eoc::notification::LearnedSpellComponent | 24 | 0x18 | AddComponent @ 0x101c05d8c |
| eoc::notification::LockpickedEventComponent | 32 | 0x20 | AddComponentUnchecked<eoc::notification::LockpickedEventComponent> |
| eoc::notification::PerformFailedComponent | 0x01 | 1 | Tag - perform failed |
| eoc::notification::PickUpResultNotificationComponent | 0x18 | 24 | Pickup result |
| eoc::notification::PingRequestComponent | 0x28 | 40 | Ping request |
| eoc::notification::PlayServerSoundComponent | 0x20 | 32 | Server sound |
| eoc::notification::ProfileShownTutorialsUpdateNotificationComponent | 0x38 | 56 | Tutorial update |
| eoc::notification::RandomCastResultComponent | 0x50 | 80 | Random cast result |
| eoc::notification::ReposeResultComponent | 1 | 0x1 | AddComponentUnchecked<eoc::notification::ReposeResultComponent> |
| eoc::notification::ScreenFadeFromServerComponent | 0x40 | 64 | Screen fade |
| eoc::notification::ShortRestResultComponent | 2 | 0x2 | AddComponentUnchecked<eoc::notification::ShortRestResultComponent> |
| eoc::notification::ShortRestStatusDurationIncreasedComponent | 0x10 | 16 | Short rest status |
| eoc::notification::ShowHudNotificationComponent | 0x30 | 48 | Show HUD notification |
| eoc::notification::SkillCheckNotificationComponent | 40 | 0x28 | AddComponentUnchecked<eoc::notification::SkillCheckNotificationComponent> |
| eoc::notification::SpellCastConfirmComponent | 0x30 | 48 | Spell cast confirm |
| eoc::notification::SpellCastFailedComponent | 24 | 0x18 | AddComponentUnchecked<eoc::notification::SpellCastFailedComponent> |
| eoc::notification::SpellCastMovementAndPrecalculationEndComponent | 24 | 0x18 | AddComponentUnchecked<eoc::notification::SpellCastMovementAndPrecalculationEndComponent> |
| eoc::notification::SpellCastRollAbortComponent | 16 | 0x10 | AddComponentUnchecked<eoc::notification::SpellCastRollAbortComponent> |
| eoc::notification::SpellCastZoneRangeComputedComponent | 16 | 0x10 | AddComponentUnchecked<eoc::notification::SpellCastZoneRangeComputedComponent> |
| eoc::notification::SpellPrepareStartEventComponent | 0x40 | 64 | Spell prepare start |
| eoc::notification::StatsAppliedComponent | 0x18 | 24 | Stats applied |
| eoc::notification::StopMovementComponent | 0x01 | 1 | Tag - stop movement |
| eoc::notification::SurfaceEnteredComponent | 0x18 | 24 | Surface entered |
| eoc::notification::SurfaceLeftComponent | 0x18 | 24 | Surface left |
| eoc::notification::TadpoleSuperPowerRequestComponent | 0x01 | 1 | Tag - tadpole power |
| eoc::notification::TradeEventComponent | 0x10 | 16 | Trade event |
| eoc::notification::UnlockedEventComponent | 32 | 0x20 | AddComponentUnchecked<eoc::notification::UnlockedEventComponent> |
| eoc::notification::UnsheathUserRequestFailedComponent | 0x10 | 16 | Unsheath request failure tracking |
| eoc::notification::UpdatePortraitMaterialRequestComponent | 0x10 | 16 | Portrait material |
| eoc::notification::VariableManagerDirtyComponent | 0x01 | 1 | Tag - variable dirty |
| eoc::notification::WorldAligningComponent | 0x38 | 56 | World aligning |

**Total: 37 components**
