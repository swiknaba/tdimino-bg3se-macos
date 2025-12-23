# Server (esv::) Components - ARM64 Sizes

Server-side components for authoritative game state.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Core Entities

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::Character | 0x08 | 8 | Ptr to 0x1a8 (424b) malloc |
| esv::Item | 0x08 | 8 | Ptr to 0xb0 (176b) malloc |
| esv::Projectile | 0x08 | 8 | Ptr to 0x5b8 (1464b) malloc |

## Base Data

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::BaseDataComponent | 0x18 | 24 | Base entity data |
| esv::BaseSizeComponent | 0x02 | 2 | Size value |
| esv::BaseStatsComponent | 0x04 | 4 | Base stats |
| esv::BaseWeaponComponent | 0x10 | 16 | Weapon data |

## Triggers

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::AIHintAreaTrigger | 0x08 | 8 | AI hint trigger |
| esv::AiGridAreaTrigger | 0x08 | 8 | AI grid trigger |
| esv::AtmosphereTrigger | 0x08 | 8 | Atmosphere trigger |
| esv::BlockBronzeTimelinePlacementTrigger | 0x08 | 8 | Timeline trigger |
| esv::CampChestTrigger | 0x08 | 8 | Camp chest trigger |
| esv::CampRegionTrigger | 0x08 | 8 | Camp region trigger |
| esv::ChasmSeederTrigger | 0x08 | 8 | Chasm seeder trigger |
| esv::CrimeAreaTrigger | 0x08 | 8 | Crime area trigger |

## Audio/Visual

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ActiveMusicVolumeComponent | 0x08 | 8 | Audio trigger |
| esv::DisplayNameListComponent | 0x28 | 40 | Name list |

## World

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ActivationGroupContainerComponent | 0x10 | 16 | Activation groups |
| esv::ChasmDataComponent | 0x30 | 48 | Chasm data |
| esv::Effect | 0x08 | 8 | Ptr to 0x70 (112b) malloc |
| esv::ExplorationAwardStateComponent | 0x10 | 16 | Exploration awards |
| esv::IconListComponent | 0x10 | 16 | Icon list |
| esv::IsMarkedForDeletionComponent | 0x01 | 1 | Deletion flag |
| esv::JumpFollowComponent | 0x150 | 336 | Jump follow (large!) |

## Network

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::NetComponent | 0x01 | 1 | Network flag |

## Camp/Triggers

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::SafePositionComponent | 0x10 | 16 | Safe position |
| esv::SafePositionUpdatedEventOneFrameComponent | 0x18 | 24 | Safe position updated |
| esv::MusicVolumeTriggerStateComponent | 0x10 | 16 | Music trigger state |
| esv::camp::TriggerComponent | 0x08 | 8 | Camp trigger |

## Death

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::death::DeathContinueComponent | 0x01 | 1 | Death continue flag |
| esv::death::DelayDeathCauseComponent | 0x18 | 24 | Delayed death |
| esv::death::DiedEventOneFrameComponent | 0x01 | 1 | Died event |
| esv::death::ModifyDelayDeathRequestOneFrameComponent | 0x10 | 16 | Modify delay death |
| esv::death::OnDeathCompleteOneFrameComponent | 0x01 | 1 | Tag - death complete |
| esv::death::TickOneFrameComponent | 0x01 | 1 | Tag - death tick |

## AI Systems (esv::ai::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ai::AiComponent | 0x01 | 1 | Tag - AI enabled |
| esv::ai::combat::InterestingItemsAddedOneFrameComponent | 0x01 | 1 | Combat items event |
| esv::ai::swarm::NextActionComponent | 0x20 | 32 | Next swarm action |
| esv::ai::swarm::TurnActionsComponent | 0x190 | 400 | Swarm turn actions (large!) |

## Boost (esv::boost::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::boost::ApplyRequestOneFrameComponent | 0x68 | 104 | Boost apply request |
| esv::boost::ApplyViaModRequestOneFrameComponent | 0x50 | 80 | Boost via mod request |
| esv::boost::ChangedEventOneFrameComponent | 0x10 | 16 | Boost changed event |
| esv::boost::ProviderComponent | 0x20 | 32 | Boost provider |
| esv::boost::RemoveRequestOneFrameComponent | 0x30 | 48 | Boost remove request |
| esv::boost::StatusBoostsRefreshedOneFrameComponent | 0x10 | 16 | Status boosts refreshed |

## Camp (esv::camp::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::camp::AvatarContainerRequestsComponent | 0x60 | 96 | Avatar container requests |
| esv::camp::AvatarContainerTriggerComponent | 0x08 | 8 | Avatar container trigger |
| esv::camp::DataComponent | 0x98 | 152 | Camp data |
| esv::camp::EndLongRestOneFrameComponent | 0x10 | 16 | End long rest event |
| esv::camp::PresenceComponent | 0x10 | 16 | Camp presence |
| esv::camp::QualityComponent | 0x04 | 4 | Camp quality |
| esv::camp::ReturnPointComponent | 0x10 | 16 | Return point |
| esv::camp::SettingsComponent | 0x40 | 64 | Camp settings |
| esv::camp::SuppliesSelectionStateChangedEventOneFrameComponent | 0x10 | 16 | Supplies selection changed |
| esv::camp::SuppliesToConsumeCacheSingletonComponent | 0x40 | 64 | Supplies cache |
| esv::camp::TriggerComponent | 0x08 | 8 | Camp trigger |

## Character (esv::character::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::character::AutomatedDialogActorComponent | 0x28 | 40 | Automated dialog |
| esv::character::CanOpenDoorsOverrideComponent | 0x01 | 1 | Tag - door override |
| esv::character::DefinitionComponent | 0xa8 | 168 | Character definition |
| esv::character::EntityMovingComponent | 0x01 | 1 | Tag - entity moving |
| esv::character::ExecuteTeleportRequestComponent | 0x18 | 24 | Execute teleport request |
| esv::character::ExternalResourcesComponent | 0x28 | 40 | External resources |
| esv::character::GameplayVisualComponent | 0x10 | 16 | Gameplay visual |
| esv::character::LoadingAnimationSetComponent | 0x10 | 16 | Loading anim set |
| esv::character::SessionCommonComponent | 0x01 | 1 | Tag - session common |
| esv::character::TurnActionsComponent | 0x150 | 336 | Turn actions (large!) |

## Character Creation (esv::character_creation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::character_creation::DebugFullDefinitionRequestOneFrameComponent | 0x1b8 | 440 | Debug definition request (large!) |
| esv::character_creation::IsCustomComponent | 0x01 | 1 | Tag - custom character |
| esv::character_creation::SessionOwnerComponent | 0x10 | 16 | Session owner |

## Combat (esv::combat::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::combat::JoinInCurrentRoundOneFrameComponent | 0x01 | 1 | Join combat event |

## Crowds (esv::crowds::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::crowds::FleeingCombatComponent | 0x08 | 8 | Fleeing combat data |

## Hit (esv::hit::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::hit::AnimationEventOneFrameComponent | 0x08 | 8 | Hit animation event |
| esv::hit::HitNotificationEventOneFrameComponent | 0x50 | 80 | Hit notification event |
| esv::hit::HitNotificationRequestOneFrameComponent | 0x48 | 72 | Hit notification request |
| esv::hit::HitResultEventOneFrameComponent | 0x1e8 | 488 | Hit result event (large!) |
| esv::hit::OnRollsResolvedEventOneFrameComponent | 0x18 | 24 | Rolls resolved event |
| esv::hit::RequestOneFrameComponent | 0x01 | 1 | Tag - hit request |

## Escort (esv::escort::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::escort::GroupRequestCompletedComponent | 0x01 | 1 | Group request completed |
| esv::escort::HasStragglersComponent | 0x01 | 1 | Has stragglers flag |

## FTB (esv::ftb::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ftb::PlayersTurnEndedEventOneFrameComponent | 0x01 | 1 | Players turn ended |

## Improvised Weapon (esv::improvised_weapon::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::improvised_weapon::CancelRequestOneFrameComponent | 0x01 | 1 | Cancel request |

## Interrupt (esv::interrupt::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::interrupt::ConditionalRollAdjustmentOneFrameComponent | 0x88 | 136 | Conditional roll adjustment |

## Inventory (esv::inventory::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::inventory::IsReplicatedComponent | 0x01 | 1 | Tag - replicated |
| esv::inventory::IsReplicatedWithComponent | 0x01 | 1 | Tag - replicated with |
| esv::inventory::MemberIsReplicatedWithComponent | 0x01 | 1 | Tag - member replicated |

## Save/Load (esv::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::SaveCompletedOneFrameComponent | 0x01 | 1 | Save completed event |
| esv::SaveWorldPrepareEventComponent | 0x01 | 1 | Save prepare event |
| esv::SaveWorldRequestComponent | 0x108 | 264 | Save world request (large!) |
| esv::savegame::LoadComponent | 0x01 | 1 | Tag - savegame load |

## Timeline (esv::timeline::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::timeline::ActorControlComponent | 0xb8 | 184 | Actor control (large!) |
| esv::timeline::InterruptActorComponent | 0x10 | 16 | Interrupt actor |
| esv::timeline::BackgroundActorRequestOneFrameComponent | 0x28 | 40 | Background actor request |
| esv::timeline::RemovedOneShotActorOneFrameComponent | 0x10 | 16 | Removed one-shot actor |

## Sight (esv::sight::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::sight::EntityLosCheckQueueComponent | 0x70 | 112 | Entity LOS check queue |
| esv::sight::EntityLosCheckResultComponent | 0x30 | 48 | Entity LOS check result |

## Summon (esv::summon::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::summon::AddConcentrationRequestOneFrameComponent | 0x48 | 72 | Add concentration request |
| esv::summon::CreateBaseRequestOneFrameComponent | 0x18 | 24 | Create base request |
| esv::summon::HandleSummonerEventRequestOneFrameComponent | 0x01 | 1 | Tag - handle summoner event |
| esv::summon::ReservePartySlotRequestOneFrameComponent | 0x10 | 16 | Reserve party slot |

## Teleport (esv::teleport::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::teleport::FinishedEventOneFrameComponent | 0x20 | 32 | Teleport finished event |

## Trigger (esv::trigger::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::trigger::RegionOnEventRequestOneFrameComponent | 0x40 | 64 | Region event request |
| esv::trigger::TriggerInteractionsOneFrameComponent | 0x40 | 64 | Trigger interactions |

## Gameplay Systems

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::falling::DataComponent | 0xc0 | 192 | Fall data (large!) |
| esv::ftb::TurnBasedComponent | 0x08 | 8 | Force turn-based |
| esv::hotbar::OrderComponent | 0x01 | 1 | Hotbar order flag |

## Constellation

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ConstellationComponent | 0x40 | 64 | Constellation data |
| esv::ConstellationHelperComponent | 0x18 | 24 | Constellation helper |

## Variable Manager

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::VariableManagerComponent | 0x01 | 1 | Tag - variable manager |
| esv::StatesComponent | 0x18 | 24 | States data |

## Ownership/Replication

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::ownership::OwneeHistoryComponent | 0x18 | 24 | Ownership history |
| esv::ownership::OwneeRequestComponent | 0x30 | 48 | Ownership request |
| esv::passive::PersistentDataComponent | 0x08 | 8 | Passive data |
| esv::pickpocket::PickpocketComponent | 0x10 | 16 | Pickpocket data |
| esv::projectile::AttachmentComponent | 0x08 | 8 | Projectile attachment |
| esv::replication::ReplicationDependencyComponent | 0x08 | 8 | Replication dep |
| esv::replication::ReplicationDependencyOwnerComponent | 0x10 | 16 | Replication owner |
| esv::replication::PrototypeModificationComponent | 0x10 | 16 | Prototype mods |
| esv::replication::IsReplicatedComponent | 0x01 | 1 | Tag - replicated |
| esv::replication::IsReplicatedWithComponent | 0x01 | 1 | Tag - replicated with |
| esv::replication::MemberIsReplicatedWithComponent | 0x01 | 1 | Tag - member replicated |

## Tag Components (esv::tags::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::tags::TemplateTagComponent | 0x10 | 16 | Template tags (GUID array) |
| esv::tags::BoostTagComponent | 0x10 | 16 | Boost tags |
| esv::tags::DebugTagComponent | 0x10 | 16 | Debug tags |
| esv::tags::DialogTagComponent | 0x10 | 16 | Dialog tags |
| esv::tags::OsirisTagComponent | 0x10 | 16 | Osiris tags |
| esv::tags::RaceTagComponent | 0x10 | 16 | Race tags |
| esv::tags::AnubisTagComponent | 0x10 | 16 | Anubis tags |

## Additional Triggers (esv::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::AvatarContainerTrigger | 0x78 | 120 | Avatar container |
| esv::ChasmRegionTrigger | 0x88 | 136 | Chasm region |
| esv::CrimeRegionTrigger | 0x80 | 128 | Crime region |
| esv::CrowdCharacterTrigger | 0x120 | 288 | Crowd character (largest!) |
| esv::EocAreaTrigger | 0x78 | 120 | EOC area |
| esv::EocPointTrigger | 0x78 | 120 | EOC point |
| esv::EventTrigger | 0x80 | 128 | Event trigger |
| esv::ExplorationTrigger | 0x90 | 144 | Exploration |
| esv::FloorTrigger | 0x80 | 128 | Floor trigger |
| esv::LightingTrigger | 0x90 | 144 | Lighting |
| esv::MusicVolumeTrigger | 0x88 | 136 | Music volume |
| esv::PortalTrigger | 0x78 | 120 | Portal |
| esv::RegionTrigger | 0x80 | 128 | Region |
| esv::RoomTrigger | 0x80 | 128 | Room |
| esv::SoundVolumeTrigger | 0xB0 | 176 | Sound volume (large!) |

## Shapeshift Components (esv::shapeshift::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::shapeshift::StatesComponent | 0x18 | 24 | Shapeshift states |

## Trigger Utility Components (esv::trigger::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| esv::trigger::CachedLeaveEventsComponent | 0x10 | 16 | Cached leave events |
| esv::trigger::EventConfigComponent | 0x01 | 1 | Event config tag |
| esv::trigger::RegisteredForComponent | 0x30 | 48 | Registered trigger |

## Statistics

- **Total esv:: components:** 160
- **Smallest:** Multiple tag components (1 byte)
- **Largest inline:** hit::HitResultEventOneFrameComponent (488 bytes), character_creation::DebugFullDefinitionRequestOneFrameComponent (440 bytes)
- **Largest heap:** Projectile heap allocation (1464 bytes)
- **Pattern:** Server components use 8-byte pointers to larger heap allocations for major entities
- **Trigger sizes:** Range from 120-288 bytes (CrowdCharacterTrigger largest)
- **OneFrame components:** 25+ event-driven transient components
