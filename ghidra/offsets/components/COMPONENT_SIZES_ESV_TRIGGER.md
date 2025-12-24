# esv::trigger:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::trigger::CachedLeaveEventsComponent | 0x10 | 16 | Cached leave events |
| esv::trigger::EventConfigComponent | 0x01 | 1 | Event config tag |
| esv::trigger::LoadedHandledComponent | 0x1 | 1 |  |
| esv::trigger::RegionOnEventRequestOneFrameComponent | 0x40 | 64 | Region event request |
| esv::trigger::RegisteredForComponent | 0x30 | 48 | Registered trigger |
| esv::trigger::RegistrationSettingsComponent | 0x1 | 1 | Single byte/enum |
| esv::trigger::TriggerInteractionsOneFrameComponent | 0x40 | 64 | Trigger interactions |
| esv::trigger::TriggerWorldAutoTriggeredComponent | 0x01 | 1 | Auto-triggered |
| esv::trigger::UpdatedRegisteredForComponent | 0x10 | 16 | Updated registration |
| esv::trigger::UpdatedRegisteredForItemsComponent | 0x10 | 16 | Updated items registration |

**Total: 10 components**
