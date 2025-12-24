# esv::ai:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ai::AiComponent | 0x01 | 1 | Tag - AI enabled |
| esv::ai::combat:: | 4 |  |  |
| esv::ai::combat::ArchetypeComponent | 0x10 | 16 | Has invoke function |
| esv::ai::combat::InterestedInItemsComponent | 0x30 | 48 | Has invoke function |
| esv::ai::combat::InterestingItemComponent | 0x30 | 48 | Has invoke function |
| esv::ai::combat::InterestingItemsAddedOneFrameComponent | 0x01 | 1 | Combat items event |
| esv::ai::swarm::GroupsComponent | 0x40 | 64 | Has invoke function |
| esv::ai::swarm::MemberChangedEventOneFrameComponent | 0x8 | 8 | OneFrame, has invoke |
| esv::ai::swarm::NextActionComponent | 0x20 | 32 | Next swarm action |
| esv::ai::swarm::TurnActionsComponent | 0x190 | 400 | Swarm turn actions (large!) |

**Total: 10 components**
