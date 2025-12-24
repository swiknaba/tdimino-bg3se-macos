# esv::escort:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::escort::FollowerComponent | 0x08 | 8 |  |
| esv::escort::GroupRequestCompletedComponent | 0x01 | 1 | Group request completed |
| esv::escort::GroupsSingletonComponent | 0x40 | 64 | Has vtable pointer |
| esv::escort::HasStragglersComponent | 0x01 | 1 | Has stragglers flag |
| esv::escort::LeaderComponent | 0x04 | 4 | Has vtable pointer |
| esv::escort::LeaderPriorityComponent | 0x40 | 64 | Leader priority |
| esv::escort::LeaderPriorityRequestCompletedComponent | 0x01 | 1 | Leader priority request done |
| esv::escort::LeaderRequestCompletedComponent | 0x01 | 1 | Leader request done |
| esv::escort::MemberChangedOneFrameComponent | 0x08 | 8 | Member changed event |
| esv::escort::MemberComponent | 0x04 | 4 | Escort member |
| esv::escort::StragglersTrackerComponent | esv::escort | No AddComponent/GetComponent with size found |  |

**Total: 11 components**
