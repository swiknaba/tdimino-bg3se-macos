# gui:: Miscellaneous Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| gui::AssignedCharactersSystem | 0x102287874 |  |  |
| gui::AvailableModsSystem | 0x10241a740 |  |  |
| gui::CreateVMTargetActionsSystem | 0x10225532c |  |  |
| gui::HotbarSystem | 0x1023af780 |  |  |
| gui::ModsOrderingSystem | SystemUpdate @ 0x10261c1c4 |  |  |
| gui::ResolutionSystem | 0x1025cecf8 |  |  |
| gui::SavegamesSystem | 0x10248f240 |  |  |
| gui::UIReadyComponent | 0x1025cf45c, 0x1025da10c | UI ready state |  |
| gui::contextmenu::WorldContextMenuSystem | 0x102255464 |  |  |
| gui::crossplay::CrossplayFriendSystem | 0x10236dcd4 |  |  |
| gui::hovering::PlayerHoveredSurfaceSystem | 0x1025cc33c |  |  |
| gui::input::TrackingSingletonComponent | 0x1025d9e9c, 0x1025d9fd4 | Input tracking |  |
| gui::lariannet::NotificationSingletonComponent | 0x1022590b4, 0x1025d9d64 | Larian.net notifications |  |
| gui::lariannet::PendingLoggedInComponent | 0x1025d99bc, 0x1025d9af4 | Login state |  |
| gui::lariannet::PendingPlatformComponent | 0x10225af80, 0x1025d9c2c | Platform state |  |
| gui::mod::AccountStateSystem | SystemUpdate @ 0x10261dbdc |  |  |
| gui::mod::AvailableModsUpdatedOneFrameComponent | 0x1022095e8, 0x1025d61ac | Mod updates |  |
| gui::mod::CanceledModSubscriptionOrDownloadSingletonComponent | 0x100ed2260, 0x10241e0a0 | Mod cancellation |  |
| gui::mod::DiskSpaceSystem | SystemUpdate @ 0x10261d978 |  |  |
| gui::mod::ProgressProcessorSystem | SystemUpdate @ 0x10261c804 |  |  |
| gui::mod::RequestSystem | 0x10241aec4 |  |  |
| gui::mod::RequestedModsSingletonComponent | 0x1025d5f3c, 0x1025d6074 | Mod requests |  |
| gui::notification::SystemNotificationSystem | 0x102370020 |  |  |
| gui::tooltip::CreateTooltipDataSystem | 0x1025f1d18 |  |  |
| gui::tooltips::WorldTooltipsComponent | 0x1025d6a34, 0x1025d6b6c | World tooltips |  |
| gui::tooltips::WorldTooltipsSystem | 0x1024c54f0 |  |  |
| gui::ugc::PermissionsChangedEventOneFrameComponent | 0x100ed1eb8, 0x10241c780 | UGC permissions |  |
| gui::vmcharacter::CharacterModeChangedSingletonComponent | 0x100ed1d80, 0x10222adfc | Character mode |  |
| gui::vmcharacter::VMCharacterActivatedSingletonComponent | 0x1021eb89c, 0x1025d68fc | Character activation |  |
| gui::vmcharacter::VMCharacterDeactivatedOneFrameComponent | 0x1021e8ab4, 0x1025d67c4 | Character deactivation |  |
| gui::vmcharacter::VMCharacterDeferredActivationSingletonComponent | 0x1021eb764, 0x1025d668c | Deferred activation |  |
| gui::vmitem::HasBeenDonatedOneFrameComponent | 0x10238d194, 0x1025d6554 | Item donation |  |
| gui::vmitem::HasBeenDonatedSystem | 0x10238ccf0 |  |  |
| gui::vmpassive::InitVMPassiveSystem | 0x1025cc0cc |  |  |
| gui::vmpassive::RegistrationNeededOneFrameComponent | 0x1025d62e4, 0x1025d641c | Passive registration |  |
| gui::vmpassive::TagParserSystem | 0x1025f1e50 |  |  |
| gui::vmplayer::VMPlayerUnregisteredCleanupSystem | 0x1025cc204 |  |  |

**Total: 37 components**
