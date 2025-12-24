# esv::item:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::item::DestroyRequestComponent | 0x80 | 128 | Destroy request |
| esv::item::DestroyingEventOneFrameComponent | 0x01 | 1 | Destroying event |
| esv::item::DestroyingWaitingForDeactivationComponent | 0x02 | 2 | Waiting for deactivation |
| esv::item::DestroyingWaitingForEffectComponent | 0x4 | 4 |  |
| esv::item::DestroyingWaitingForFadeOut | 0x10 | 16 |  |
| esv::item::DynamicLayerOwnerComponent | 0x04 | 4 | Dynamic layer owner |
| esv::item::EntityMovingComponent | 0x01 | 1 | Entity moving flag |
| esv::item::InUseComponent | 0x30 | 48 | Item in use |
| esv::item::MarkEntityForDestructionComponent | 0x01 | 1 | Mark for destruction |
| esv::item::TransformedOnDestroyEventOneFrameComponent | 0x01 | 1 | Transform on destroy |
| esv::item::animation::FallbackTimerComponent | 0x04 | 4 | Fallback timer |
| esv::item::animation::PendingRequestComponent | 0x02 | 2 | Pending request |
| esv::item::animation::StateComponent | 0x06 | 6 | Animation state |

**Total: 13 components**
