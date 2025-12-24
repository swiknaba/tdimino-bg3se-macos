# eoc::platform:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::platform::DestructionParticipantComponent | 1 | `(uVar3 >> 0x10)` |  |
| eoc::platform::MovablePlatformComponent | 0x1 | 1 |  |
| eoc::platform::MoveOnSplineComponent | 0x1c | 28 | Has invoke PTR |
| eoc::platform::MoveOnSplineProgressComponent | 0x18 | 24 |  |
| eoc::platform::MoveToTargetComponent | 0x28 | 40 |  |
| eoc::platform::MoveToTargetProgressComponent | 0x0c | 12 | Move progress |
| eoc::platform::MovementComponent | 0x10 | 16 | Platform movement |
| eoc::platform::MovementPausedComponent | 0x01 | 1 | Tag - movement paused |
| eoc::platform::PassengerComponent | 0x30 | 48 | Passenger data |
| eoc::platform::PlatformComponent | 0x48 | 72 | Platform state |
| eoc::platform::RepresentativeComponent | 0x08 | 8 | Representative ref |

**Total: 11 components**
