# esv::ftb:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ftb::ModeChangedEventOneFrameComponent | 0x10 | 16 | Mode changed event |
| esv::ftb::PlayersTurnEndedEventOneFrameComponent | 0x01 | 1 | Players turn ended |
| esv::ftb::PlayersTurnStartedEventOneFrameComponent | 0x01 | 1 | Players turn started |
| esv::ftb::SurfaceTeamSingletonComponent | 0x70 | 112 | Surface team singleton |
| esv::ftb::TimeFactorRequestsSingletonComponent | esv::ftb | Singleton component |  |
| esv::ftb::TimeFactorResetRequestsSingletonComponent | esv::ftb | Singleton component |  |
| esv::ftb::TurnBasedChangesRequestSingletonComponent | esv::ftb | Singleton component |  |
| esv::ftb::TurnBasedComponent | 0x08 | 8 | Force turn-based |
| esv::ftb::ZoneComponent | 0x48 | 72 | Zone data |
| esv::ftb::ZoneInstigatorComponent | 0x10 | 16 | Zone instigator |

**Total: 10 components**
