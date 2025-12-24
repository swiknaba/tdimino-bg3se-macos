# esv::combat:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::combat::CanStartCombatComponent | 0x01 | 1 | Tag component |
| esv::combat::CombatScheduledForDeleteOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::combat::CombatStateComponent | 0x18 | 24 |  |
| esv::combat::CombatSwitchedComponent | 0x30 | 48 | Combat switch data |
| esv::combat::DelayedFanfareRemovedDuringCombatEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::combat::EnterRequestComponent | 0x30 | 48 | Combat enter request |
| esv::combat::FleeBlockedComponent | 0x01 | 1 | Tag component |
| esv::combat::FleeRequestComponent | Not found | No GetComponent function |  |
| esv::combat::GlobalCombatRequests | Not found | No GetComponent function |  |
| esv::combat::ImmediateJoinComponent | 0x01 | 1 | Tag component |
| esv::combat::IsInCombatComponent | 0x18 | 24 |  |
| esv::combat::JoinEventOneFrameComponent | 0x10 | 16 | Join event data |
| esv::combat::JoinInCurrentRoundFailedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::combat::JoinInCurrentRoundOneFrameComponent | 0x01 | 1 | Join combat event |
| esv::combat::JoiningComponent | 0x04 | 4 | Join state |
| esv::combat::LateJoinPenaltyComponent | 0x04 | 4 | Penalty value |
| esv::combat::LeaveRequestComponent | 0x01 | 1 | Tag component |
| esv::combat::LeftEventOneFrameComponent | 0x18 | 24 | Leave event data |
| esv::combat::MergeComponent | 16 (0x10) | Struct analysis | 2x EntityHandle = 16 bytes |
| esv::combat::SurfaceTeamSingletonComponent | 0x70 | 112 | Surface team mapping |
| esv::combat::SurprisedJoinRequestOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::combat::SurprisedStealthRequestOneFrameComponent | 0x01 | 1 | OneFrame event |

**Total: 22 components**
