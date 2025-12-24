# esv::death:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::death:: | 4 |  |  |
| esv::death::ApplyKnockedOutOneFrameComponent | 0x18 | 24 | OneFrame event |
| esv::death::DeathContinueComponent | 0x01 | 1 | Death continue flag |
| esv::death::DeathRequestOneFrameComponent | 0x88 | 136 | Death request event |
| esv::death::DelayDeathCauseComponent | 0x18 | 24 | Delayed death |
| esv::death::DelayedDeathComponent | 0x98 | 152 |  |
| esv::death::DiedEventOneFrameComponent | 0x01 | 1 | Died event |
| esv::death::DownedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::death::DyingWaitingForDeactivationComponent | 0x01 | 1 |  |
| esv::death::KillerComponent | 48 (0x30) | GetComponent via `* 0x30` | HashSet<EntityHandle> = 48 bytes |
| esv::death::ModifyDelayDeathRequestOneFrameComponent | 0x10 | 16 | Modify delay death |
| esv::death::OnDeathCompleteOneFrameComponent | 0x01 | 1 | Tag - death complete |
| esv::death::ResurrectedEventOneFrameComponent | 0x0c | 12 | OneFrame event |
| esv::death::ResurrectionRequestOneFrameComponent | 0x18 | 24 | OneFrame event |
| esv::death::TickOneFrameComponent | 0x01 | 1 | Tag - death tick |

**Total: 15 components**
