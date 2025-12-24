# eoc::inventory:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::inventory::CanBeInComponent | 0x01 | 1 | Tag - can be in inventory |
| eoc::inventory::CannotBePickpocketedComponent | 0x01 | 1 | Tag - no pickpocket |
| eoc::inventory::CannotBeTakenOutComponent | 0x01 | 1 | Tag - can't remove |
| eoc::inventory::ContainerComponent | 0x40 | 64 | Inventory container |
| eoc::inventory::DataComponent | 0x04 | 4 | Inventory data |
| eoc::inventory::DropOnDeathBlockedComponent | 0x01 | 1 | Tag - no drop on death |
| eoc::inventory::IsLockedComponent | 0x01 | 1 | Tag - locked |
| eoc::inventory::IsOwnedComponent | 0x08 | 8 | Owner entity ref |
| eoc::inventory::MemberComponent | 0x10 | 16 | Inventory member |
| eoc::inventory::MemberTransformComponent | 0x28 | 40 | Transform in container |
| eoc::inventory::NewItemsInsideComponent | 0x01 | 1 | Tag - new items |
| eoc::inventory::NonTradableComponent | 0x01 | 1 | Tag - non-tradable |
| eoc::inventory::OwnerComponent | 0x18 | 24 | Owner vector |
| eoc::inventory::StackComponent | 0x20 | 32 | Stack data |
| eoc::inventory::StackMemberComponent | 0x08 | 8 | Stack member ref |
| eoc::inventory::TopOwnerComponent | 0x08 | 8 | Top owner entity ref |
| eoc::inventory::TradeBuybackDataComponent | 0x18 | 24 | Buyback data |
| eoc::inventory::WeightComponent | 0x04 | 4 | Weight value |
| eoc::inventory::WieldingHistoryComponent | eoc::inventory | Inventory history |  |

**Total: 19 components**
