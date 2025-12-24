# esv::inventory:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::inventory::CharacterHasGeneratedTradeTreasureComponent | 0x01 | 1 | Trade treasure generated |
| esv::inventory::ContainerDataComponent | 0x08 | 8 | Container data |
| esv::inventory::EntityHasGeneratedTreasureComponent | 0x01 | 1 | Treasure generated |
| esv::inventory::GroupCheckComponent | 4 | GetComponent | `>> 0xe & 0x3fffc` pattern = 4 bytes |
| esv::inventory::IsReplicatedComponent | 0x01 | 1 | Tag - replicated |
| esv::inventory::IsReplicatedWithComponent | 0x01 | 1 | Tag - replicated with |
| esv::inventory::LootableReactionQueueSingletonComponent | 0x60 | 96 | Loot reaction queue |
| esv::inventory::MemberIsReplicatedWithComponent | 0x01 | 1 | Tag - member replicated |
| esv::inventory::MemberRemovedEventOneFrameComponent | 0x10 | 16 | Member removed event |
| esv::inventory::ReequipStackComponent | 0x40 | 64 | Reequip stack |
| esv::inventory::ReturnToOwnerComponent | 0x01 | 1 | Return to owner flag |
| esv::inventory::ShapeshiftAddedEquipmentComponent | 0x10 | 16 | Shapeshift equipment added |
| esv::inventory::ShapeshiftEquipmentHistoryComponent | 0x10 | 16 | Shapeshift history |
| esv::inventory::ShapeshiftUnequippedEquipmentComponent | 0x10 | 16 | Shapeshift unequipped |
| esv::inventory::StackBlockedDuringTradeComponent | 0x01 | 1 | Stack blocked in trade |

**Total: 15 components**
