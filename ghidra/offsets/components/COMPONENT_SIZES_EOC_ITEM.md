# eoc::item:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::item::CanBeWieldedComponent | 0x01 | 1 | Tag - wieldable |
| eoc::item::DestroyedComponent | 0x0c | 12 | Destroyed state (FixedString) |
| eoc::item::DestroyingComponent | 0x01 | 1 | Tag - destroying |
| eoc::item::DoorComponent | 0x01 | 1 | Tag - door |
| eoc::item::DyeComponent | 0x10 | 16 | Dye data (2x uint64) |
| eoc::item::ExamineDisabledComponent | 0x01 | 1 | Tag - examine disabled |
| eoc::item::HasMovedComponent | 0x01 | 1 | Tag - has moved |
| eoc::item::HasOpenedComponent | 0x01 | 1 | Tag - has opened |
| eoc::item::ISDoorClosedAnimationFinishedOneFrameComponent | 0x1 | 1 | OneFrame |
| eoc::item::ISDoorClosedAnimationRequestOneFrameComponent | 0x1 | 1 | OneFrame |
| eoc::item::ISDoorClosedComponent | 0x8 | 8 |  |
| eoc::item::ISDoorClosingComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item::ISDoorOpenedAnimationFinishedOneFrameComponent | 0x1 | 1 | OneFrame |
| eoc::item::ISDoorOpenedAnimationRequestOneFrameComponent | 0x1 | 1 | OneFrame |
| eoc::item::ISDoorOpenedComponent | 0x8 | 8 |  |
| eoc::item::ISDoorOpeningComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item::ISFallingComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item::ISRotateComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item::ISTeleportFallComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item::IdentityComponent | 0x01 | 1 | Tag - item identity |
| eoc::item::InUseComponent | 0x01 | 1 | Tag - in use |
| eoc::item::IsGoldComponent | 0x01 | 1 | Tag - is gold |
| eoc::item::IsPoisonedComponent | 0x01 | 1 | Tag - is poisoned |
| eoc::item::ItemComponent | 0x01 | 1 | Tag - base item |
| eoc::item::MapMarkerStyleComponent | 0x04 | 4 | Map marker style ID |
| eoc::item::MemberTransformComponent | 0x28 | 40 | Transform in container |
| eoc::item::NewInInventoryComponent | 0x01 | 1 | Tag - new in inventory |
| eoc::item::NewItemsInsideComponent | 0x01 | 1 | Tag - new items |
| eoc::item::NonTradableComponent | 0x01 | 1 | Tag - non-tradable |
| eoc::item::OriginalIdentityComponent | 0x01 | 1 | Tag - original identity |
| eoc::item::OwnedAsLootComponent | 0x01 | 1 | Tag - owned as loot |
| eoc::item::PortalComponent | 0x02 | 2 | Portal data (short) |
| eoc::item::ShouldDestroyOnSpellCastComponent | 0x01 | 1 | Tag - destroy on cast |
| eoc::item::StackComponent | 0x20 | 32 | Stack data |
| eoc::item::StackMemberComponent | 0x08 | 8 | Stack member ref |
| eoc::item::StateComponent | 0x01 | 1 | Tag - item state |
| eoc::item::WieldedComponent | 0x10 | 16 | Wielded item data |
| eoc::item::WieldingComponent | 0x08 | 8 | Wielding entity ref |
| eoc::item::animation::RequestComponent | 0x04 | 4 | Animation request ID |

**Total: 39 components**
