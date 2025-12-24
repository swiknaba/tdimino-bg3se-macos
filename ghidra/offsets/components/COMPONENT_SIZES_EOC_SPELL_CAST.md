# eoc::spell_cast:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell_cast::AnimationInfoComponent | 0x30 | 48 | Animation info |
| eoc::spell_cast::AnimationRequestOneFrameComponent | 0x30 | 48 | Single-frame animation request |
| eoc::spell_cast::CacheComponent | 0x08 | 8 | Spell cache ref |
| eoc::spell_cast::CanBeTargetedComponent | 0x01 | 1 | Tag - can target |
| eoc::spell_cast::CastEventOneFrameComponent | 0x1C0 | 448 | Cast event (large!) |
| eoc::spell_cast::CastHitEventOneFrameComponent | 0x10 | 16 | Cast hit event |
| eoc::spell_cast::CastTextKeyEventOneFrameComponent | 0x10 | 16 | Spell cast text key event |
| eoc::spell_cast::CounteredEventOneFrameComponent | 0x01 | 1 | Spell countered event flag |
| eoc::spell_cast::DataCacheSingletonComponent | 0x40 | 64 | Data cache |
| eoc::spell_cast::DestroyEventOneFrameComponent | 0x10 | 16 | Spell cast destroy event |
| eoc::spell_cast::ExecutionTimeComponent | 0x08 | 8 | Spell execution timestamp |
| eoc::spell_cast::FinishedEventOneFrameComponent | 0x02 | 2 | Spell finished event flag |
| eoc::spell_cast::InterruptResultsComponent | 0x38 | 56 | Interrupt results |
| eoc::spell_cast::IsCastingComponent | 0x08 | 8 | Active casting indicator |
| eoc::spell_cast::LogicExecutionEndEventOneFrameComponent | 0x01 | 1 | Logic execution end event |
| eoc::spell_cast::LogicExecutionStartEventOneFrameComponent | 0x01 | 1 | Logic execution start event |
| eoc::spell_cast::MovementComponent | 0x1c | 28 | Movement data |
| eoc::spell_cast::OutcomeComponent | 0x01 | 1 | Tag - outcome |
| eoc::spell_cast::PrepareEndEventOneFrameComponent | 0x01 | 1 | Prepare phase end event |
| eoc::spell_cast::PrepareStartEventOneFrameComponent | 0x01 | 1 | Prepare phase start event |
| eoc::spell_cast::RollsComponent | 0x10 | 16 | Spell rolls |
| eoc::spell_cast::SpellCastConfirmComponent | 0x30 | 48 | Spell confirm |
| eoc::spell_cast::SpellCastFailedComponent | 0x18 | 24 | Spell failed |
| eoc::spell_cast::SpellCastMovementAndPrecalculationEndComponent | 0x18 | 24 | Movement end |
| eoc::spell_cast::SpellCastRollAbortComponent | 0x10 | 16 | Roll abort |
| eoc::spell_cast::SpellCastZoneRangeComputedComponent | 0x10 | 16 | Zone computed |
| eoc::spell_cast::SpellRollAbortEventOneFrameComponent | 0x1c0 | 448 | Spell roll abort event (large!) |
| eoc::spell_cast::SpellRollCastEventOneFrameComponent | 0x1c0 | 448 | Spell roll cast event (large!) |
| eoc::spell_cast::StateComponent | 0xc0 | 192 | Spell cast state (large!) |
| eoc::spell_cast::SurfaceCreationRequestOneFrameComponent | 0x30 | 48 | Surface creation request |
| eoc::spell_cast::SyncTargetingComponent | 0x98 | 152 | Sync targeting data |
| eoc::spell_cast::TargetHitEventOneFrameComponent | 0x1f8 | 504 | Large component |
| eoc::spell_cast::TargetPickedOneFrameComponent | 0x90 | 144 | Target picked event |
| eoc::spell_cast::TargetsChangedEventOneFrameComponent | 0x10 | 16 | Target list change event |

**Total: 34 components**
