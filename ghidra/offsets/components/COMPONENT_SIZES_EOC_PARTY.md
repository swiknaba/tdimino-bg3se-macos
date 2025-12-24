# eoc::party:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::party::BlockFollowComponent | 0x01 | 1 | Tag - block follow |
| eoc::party::CompositionComponent | 0x28 | 40 | Has invoke PTR |
| eoc::party::CurrentlyFollowingPartyComponent | 0x01 | 1 | Tag - following |
| eoc::party::FollowerComponent | 0x08 | 8 | Follower ref |
| eoc::party::MemberComponent | 0x38 | 56 | Party member data |
| eoc::party::OwneeCurrentComponent | 0x08 | 8 | Current ownee ref |
| eoc::party::PortalsComponent | 0x30 | 48 | Portal management |
| eoc::party::RecipesComponent | 0x10 | 16 | Recipe tracking |
| eoc::party::RestorePartyEventOneFrameComponent | 0x10 | 16 | Restore party |
| eoc::party::ViewComponent | 0x30 | 48 | Party view state |
| eoc::party::WaypointsComponent | 0x30 | 48 | Waypoint data |

**Total: 11 components**
