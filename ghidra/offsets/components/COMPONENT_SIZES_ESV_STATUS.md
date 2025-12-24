# esv::status:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::status:: | 4 |  |  |
| esv::status::CauseComponent | 0x58 | 88 |  |
| esv::status::DispelDestroyOneFrameComponent | 0x10 | 16 |  |
| esv::status::DownedChangedEventOneFrameComponent | 0x01 | 1 | OneFrame event |
| esv::status::LifeTimeComponent | 0x10 | 16 |  |
| esv::status::OwnershipComponent | 8 (0x8) | GetComponent via `>> 0xd & 0x7fff8` | EntityHandle = 8 bytes |
| esv::status::PerformingComponent | 4 (0x4) | Struct analysis | FixedString = 4 bytes |
| esv::status::StatusComponent | 40 | 0x28 | GetComponent @ 0x1048c9288 |
| esv::status::StatusIDComponent | 0x10 | 16 |  |
| esv::status::UniqueComponent | 0x40 | 64 | Unique status |

**Total: 10 components**
