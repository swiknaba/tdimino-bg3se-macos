# esv::crowds:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::crowds:: | 8 |  |  |
| esv::crowds::AnimationComponent | 0x0c | 12 | Animation state |
| esv::crowds::BehaviourRequestOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::crowds::DeactivateCharacterComponent | 0x01 | 1 | Tag component |
| esv::crowds::DespawnWithoutCharacterComponent | 0x01 | 1 | Tag component |
| esv::crowds::DetourComponent | 0x20 | 32 | Detour path data |
| esv::crowds::DetourIdlingComponent | 0x08 | 8 | Idle state |
| esv::crowds::DisableCharacterSpawningComponent | 0x01 | 1 | Tag component |
| esv::crowds::DynamicAnimationSetComponent | 0x10 | 16 | Animation set ref |
| esv::crowds::FadeComponent | 0x08 | 8 | Fade state |
| esv::crowds::FleeingCombatComponent | 0x08 | 8 | Fleeing combat data |
| esv::crowds::MoveToComponent | 0x24 | 36 | Movement target |
| esv::crowds::PatrolComponent | 0x30 | 48 | Patrol route |
| esv::crowds::SpawnComponent | 0x30 | 48 | Spawn config |
| esv::crowds::TriggerSpawnStateComponent | 0x0c | 12 | Spawn trigger state |

**Total: 15 components**
