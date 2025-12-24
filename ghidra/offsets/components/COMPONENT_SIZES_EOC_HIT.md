# eoc::hit:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::hit::AttackerComponent | TBD | TBD | Hit attacker data |
| eoc::hit::CancelRequestOneFrameComponent | 0x01 | 1 | Tag - cancel |
| eoc::hit::ConditionalRollAdjustmentOneFrameComponent | 0x88 | 136 | Roll adjustment |
| eoc::hit::HitNotificationEventOneFrameComponent | 0x50 | 80 | Hit notification |
| eoc::hit::HitNotificationRequestOneFrameComponent | 0x48 | 72 | Hit request |
| eoc::hit::HitResultEventOneFrameComponent | 0x1e8 | 488 | Hit result (large!) |
| eoc::hit::LifetimeComponent | 0x08 | 8 | Hit lifetime |
| eoc::hit::MetaComponent | 0x10 | 16 | Hit metadata |
| eoc::hit::ProxyComponent | 0x10 | 16 |  |
| eoc::hit::ProxyOwnerComponent | 0x10 | 16 |  |
| eoc::hit::ReactionComponent | TBD | TBD | Hit reaction |
| eoc::hit::TargetComponent | TBD | TBD | Hit target data |
| eoc::hit::ThrownObjectComponent | TBD | TBD | Thrown object hit data |
| eoc::hit::WeaponComponent | TBD | TBD | Weapon hit data |

**Total: 14 components**
