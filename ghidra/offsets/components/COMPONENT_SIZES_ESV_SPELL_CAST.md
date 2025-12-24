# esv::spell_cast:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::spell_cast:: | 12 |  |  |
| esv::spell_cast::CastHitDelayComponent | 24 | 0x18 | GetComponent<esv::spell_cast::CastHitDelayComponent,false> |
| esv::spell_cast::ExternalsComponent | 16 | GetComponent | `<< 4` = 16 bytes |
| esv::spell_cast::HitRegisterComponent | Not found | No GetComponent function |  |
| esv::spell_cast::InterruptRequestsComponent | Not found | No GetComponent function |  |
| esv::spell_cast::MovementInfoComponent | Variable | Struct analysis | Contains optional<> types, complex |
| esv::spell_cast::PendingRequestsComponent | 48 (0x30) | Struct analysis | 3x Array<Request> = 48 bytes |
| esv::spell_cast::ProjectileCacheComponent | 984 | 0x3d8 | GetComponent @ 0x1056dafec |
| esv::spell_cast::ProjectilePathfindCacheComponent | 32 | 0x20 | GetComponent @ 0x1056dd310 |
| esv::spell_cast::UnsheathFallbackTimerComponent | esv::spell_cast | Timer component |  |
| esv::spell_cast::ZoneRangeComponent | esv::spell_cast | Server-side zone range |  |
| esv::spell_cast::random::ResultEventOneFrameComponent | 0x68 | 104 | Random result event |

**Total: 12 components**
