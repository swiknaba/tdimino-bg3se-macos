# eoc::item_template:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::item_template::ActionTypeComponent | 0x30 | 48 | Action type with hash |
| eoc::item_template::CanMoveComponent | 0x01 | 1 | Tag - can move |
| eoc::item_template::ClimbOnComponent | 0x01 | 1 | Tag - climbable |
| eoc::item_template::DestroyedComponent | 0x01 | 1 | Tag - destroyed |
| eoc::item_template::InteractionDisabledComponent | 0x01 | 1 | Tag - no interaction |
| eoc::item_template::IsStoryItemComponent | 0x01 | 1 | Tag - story item |
| eoc::item_template::LadderComponent | 0x01 | 1 | Tag - ladder |
| eoc::item_template::ScriptControlledDoorComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |
| eoc::item_template::UseActionComponent | 0x10 | 16 |  |
| eoc::item_template::WalkOnComponent | 1 | `(ulong)(uVar3 >> 0x10)` - no multiplier |  |

**Total: 10 components**
