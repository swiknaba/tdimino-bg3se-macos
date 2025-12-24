# eoc:: Miscellaneous Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::action::ActionStateComponent | 0x08 | 8 | Action state |
| eoc::action::ActionUseConditionsComponent | 0x10 | 16 | Action use conditions |
| eoc::action::RequestPushComponent | 0x50 | 80 | Push request |
| eoc::active_roll::InProgressComponent | 0x01 | 1 | Tag - roll in progress |
| eoc::active_roll::ModifiersComponent | 0x90 | 144 | Roll modifiers |
| eoc::ai::combat::RequestCameraMoveComponent | 0x08 | 8 | Camera move request - Vector2f position |
| eoc::ai::swarm::ActiveComponent | 0x01 | 1 | Tag - swarm active (empty component) |
| eoc::ai::swarm::DebugSelectedComponent | 0x18 | 24 | Debug selected - 4-byte ID + DynamicArray (node pool) |
| eoc::ai::swarm::DebugTurnActionsComponent | 0x130 | 304 | Debug turn actions (large!) - full turn state with target GUID, spell IDs, action state, calculation state |
| eoc::ai::swarm::ExecutingActionComponent | 0x01 | 1 | Tag - executing action (empty component) |
| eoc::ai::swarm::MemberComponent | 0x04 | 4 | Swarm member ID - 4-byte group/swarm handle with NodePool release |
| eoc::ai::swarm::RequestCameraFollowGroupComponent | 0x10 | 16 | Camera follow request - DynamicArray of entity GUIDs |
| eoc::aigrid::AiGridLoadedOneFrameComponent | 0x01 | 1 | OneFrame - grid loaded |
| eoc::aigrid::RefreshAllLayersOneFrameRequestComponent | 0x01 | 1 | OneFrame - refresh layers |
| eoc::aigrid::SubgridProximityListChangedEventOneFrameComponent | 0x60 | 96 | OneFrame - subgrid change |
| eoc::ambush::AmbushingComponent | 0x01 | 1 | Tag - ambushing |
| eoc::animation::BlueprintRefreshedEventOneFrameComponent | 0x01 | 1 | Tag - blueprint refreshed event |
| eoc::animation::DoorAnimationFinishedOneFrameComponent | 0x18 | 24 | Door anim finished |
| eoc::animation::DoorEventCachingSingletonComponent | 0xc0 | 192 | Door event caching (singleton) |
| eoc::animation::GameplayEventsOneFrameComponent | 0x40 | 64 | Gameplay events (one frame) |
| eoc::animation::PlayAnimationComponent | 0x40 | 64 | Play animation |
| eoc::animation::RecoveryAnimationComponent | 0x04 | 4 | Recovery anim |
| eoc::animation::RefreshAnimationRequestOneFrameComponent | 0x10 | 16 | Refresh animation request |
| eoc::animation::TextKeyEventsOneFrameComponent | 0x40 | 64 | Text key events (one frame) |
| eoc::animation::TriggeredEventsOneFrameComponent | 0x40 | 64 | Triggered events (one frame) |
| eoc::approval::RatingsComponent | 0x70 | 112 | Approval ratings (HashTable) |
| eoc::armor_set::StateComponent | 0x01 | 1 | Tag - armor set |
| eoc::attitude::AttitudesToPlayersComponent | 0x40 | 64 | Attitudes (HashTable) |
| eoc::background::GoalsComponent | 0x40 | 64 | Background goals |
| eoc::calendar::DaysPassedComponent | 0x04 | 4 | Days passed counter |
| eoc::calendar::StartingDateComponent | 0x08 | 8 | Starting date |
| eoc::camera::ConversationCameraComponent | 0x08 | 8 | Conversation camera |
| eoc::camera::MoveComponent | 0x10 | 16 | Camera movement |
| eoc::camera::SelectedCameraComponent | 0x08 | 8 | Selected camera |
| eoc::camera::SilenceFadeComponent | 0x10 | 16 | Silence fade |
| eoc::camera::SpellWaitComponent | 0x04 | 4 | Spell camera wait |
| eoc::camp::AvatarContainerComponent | 0x01 | 1 | Avatar container |
| eoc::camp::ChestComponent | 0x28 | 40 | Camp chest data |
| eoc::camp::EndTheDayStateComponent | 0x10 | 16 | End day state |
| eoc::camp::PresenceComponent | 0x01 | 1 | Tag - camp presence |
| eoc::camp::QualityComponent | 0x08 | 8 | Camp quality |
| eoc::camp::SettingsComponent | 0x08 | 8 | Camp settings |
| eoc::camp::SupplyComponent | 0x04 | 4 | Supply count |
| eoc::camp::TotalSuppliesComponent | 0x04 | 4 | Total supplies |
| eoc::character::AppearanceComponent | 0x70 | 112 | Appearance data |
| eoc::character::CharacterComponent | 0x01 | 1 | Tag - is character |
| eoc::character::CharacterDefinitionComponent | 0x290 | 656 | Character definition (large!) |
| eoc::character::DefinitionCommonComponent | 0xc0 | 192 | Common definition |
| eoc::character::EquipmentVisualComponent | 0x01 | 1 | Equipment visual flag |
| eoc::character::MoveComponent | 0x10 | 16 | Move state |
| eoc::character::SessionCommonComponent | 0x0c | 12 | Session common |
| eoc::character::TradingComponent | 0x1 | 1 | Likely a flag or count |
| eoc::chasm::CanEnterChasmComponent | 0x1 | 1 | Likely a flag or bool |
| eoc::combat::DelayedFanfareComponent | 0x01 | 1 | Tag - delayed fanfare |
| eoc::combat::FleeingCombatComponent | 0x08 | 8 | Fleeing state |
| eoc::combat::InitiatorDebugComponent | 0x120 | 288 | Debug - 6 hash tables |
| eoc::combat::IsCombatPausedComponent | 0x01 | 1 | Simple primitive |
| eoc::combat::IsInCombatComponent | 0x01 | 1 | In combat flag |
| eoc::combat::IsThreatenedComponent | 0x10 | 16 | DynamicArray of threats |
| eoc::combat::ParticipantComponent | 0x28 | 40 | Combat participant data |
| eoc::combat::StateComponent | 0x98 | 152 | Full combat state |
| eoc::combat::ThreatRangeComponent | 0x0c | 12 | Range + flags |
| eoc::concentration::ConcentrationComponent | 0x50 | 80 | Concentration state |
| eoc::controller::LocomotionComponent | 0x84 | 132 | Movement locomotion |
| eoc::controller::NudgeDataComponent | 0x1c | 28 | Pathfinding nudge |
| eoc::crowds::AppearanceComponent | 0x40 | 64 | Crowd appearance |
| eoc::crowds::BehaviourComponent | 0x01 | 1 | Tag - behavior |
| eoc::crowds::CharacterComponent | 0x10 | 16 | Crowd character |
| eoc::crowds::CustomAnimationComponent | 0x04 | 4 | Custom anim |
| eoc::crowds::DeadReckoningComponent | 0x14 | 20 | Network prediction |
| eoc::crowds::IsFadingComponent | 0x01 | 1 | Tag - fading |
| eoc::crowds::ProxyComponent | 0x08 | 8 | Proxy ref |
| eoc::crowds::ProxyDynamicAnimationSetComponent | 0x10 | 16 | Dynamic anims |
| eoc::crowds::ProxyTransformComponent | 0x10 | 16 | Simple primitive |
| eoc::customdice::UsersDiceSingletonComponent | 0x40 | 64 | User dice data |
| eoc::death::DeadByDefaultComponent | 0x01 | 1 | Simple primitive |
| eoc::death::DeathComponent | 0x78 | 120 | Death state |
| eoc::death::DeathTypeComponent | 0x01 | 1 | Tag - death type |
| eoc::death::DiedEventOneFrameComponent | 0x01 | 1 | Tag - died event |
| eoc::death::DownedComponent | 0x18 | 24 | Downed state |
| eoc::death::ModifyDelayDeathRequestOneFrameComponent | 0x10 | 16 | Delay death request |
| eoc::death::StateComponent | 0x04 | 4 | Death state value |
| eoc::dialog::ActiveDialogActorComponent | 0x28 | 40 | Active dialog actor |
| eoc::dialog::DialoguePrivacySingletonComponent | 0x40 | 64 | HashTable<unsigned_int> |
| eoc::dialog::InitiatorComponent | 0x10 | 16 | Dialog initiator |
| eoc::dialog::IsListeningSingletonComponent | 0x40 | 64 | HashTable<ls::Guid> |
| eoc::dialog::NoPrivateDialogsSingletonComponent | 0x30 | 48 | HashTable<net::UserID> |
| eoc::dialog::StateComponent | 0x0c | 12 | Dialog state |
| eoc::door::ISDoorClosedAnimationFinishedOneFrameComponent | 0x01 | 1 | Tag - closed finished |
| eoc::door::ISDoorClosedAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - closed request |
| eoc::door::ISDoorClosedComponent | 0x08 | 8 | Door closed state |
| eoc::door::ISDoorOpenedAnimationFinishedOneFrameComponent | 0x01 | 1 | Tag - opened finished |
| eoc::door::ISDoorOpenedAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - opened request |
| eoc::door::ISDoorOpenedComponent | 0x08 | 8 | Door opened state |
| eoc::drop::AnimationComponent | 0x01 | 1 | Drop item animation |
| eoc::drop::DropEntityStateComponent | 0x01 | 1 | Simple primitive |
| eoc::drop::OriginalDropTargetComponent | 0x08 | 8 | Simple primitive |
| eoc::encumbrance::StateComponent | 0x04 | 4 |  |
| eoc::encumbrance::StatsComponent | 0x0c | 12 |  |
| eoc::exp::AvailableLevelComponent | 0x4 | 4 | Available level tracking |
| eoc::exp::CanLevelUpComponent | 0x01 | 1 | Simple primitive |
| eoc::exp::ExperienceComponent | 0x10 | 16 | XP |
| eoc::expertise::ExpertiseComponent | 0x30 | 48 | Expertise/proficiency data |
| eoc::falling::IsFallingComponent | 0x01 | 1 | Tag - is falling |
| eoc::floor::InfoComponent | 0x20 | 32 | Floor information |
| eoc::ftb::IsInFtbComponent | 0x01 | 1 | Tag - in FTB |
| eoc::ftb::JoinInCurrentRoundOneFrameComponent | 0x01 | 1 | Tag - join round |
| eoc::ftb::ParticipantComponent | 0x08 | 8 | FTB participant |
| eoc::ftb::RespectComponent | 0x01 | 1 | Tag - FTB respect |
| eoc::ftb::ZoneBlockReasonComponent | 0x01 | 1 | Tag - zone block reason |
| eoc::game::PauseComponent | 0x01 | 1 | Tag - game paused |
| eoc::gamestate::MainMenuPostInstantiateComponent | 0x01 | 1 | Tag - main menu |
| eoc::gamestate::PausedComponent | 0x01 | 1 | Tag - paused |
| eoc::gamestate::RunningComponent | 0x01 | 1 | Tag - running |
| eoc::gamestate::SavegameLoadComponent | 0x20 | 32 | Savegame load |
| eoc::gamestate::ScreenFadeComponent | 0x30 | 48 | Screen fade |
| eoc::gamestate::ServerTargetsNotificationComponent | 0x30 | 48 | Server targets |
| eoc::gamestate::TeleportRequestComponent | 0x38 | 56 | Teleport request |
| eoc::gamestate::UnloadLevelComponent | 0x01 | 1 | Tag - unload level |
| eoc::gamestate::UnloadModuleComponent | 0x01 | 1 | Tag - unload module |
| eoc::god::GodComponent | 0x28 | 40 | Deity/God data |
| eoc::god::TagComponent | 0x10 | 16 | Has invoke pointer |
| eoc::group::GroupRequestCompletedComponent | 0x01 | 1 | Tag - request complete |
| eoc::group::HasStragglersComponent | 0x01 | 1 | Tag - has stragglers |
| eoc::heal::BlockComponent | 0x01 | 1 | Tag - heal blocked |
| eoc::heal::MaxIncomingComponent | 0x01 | 1 | Tag - max incoming |
| eoc::heal::MaxOutgoingComponent | 0x01 | 1 | Tag - max outgoing |
| eoc::hearing::EnteredListenerRangeEventOneFrameComponent | 0x08 | 8 | Entered listener range |
| eoc::hearing::LeftListenerRangeEventOneFrameComponent | 0x08 | 8 | Left listener range |
| eoc::hotbar::ContainerComponent | 0x48 | 72 |  |
| eoc::hotbar::ContainerKeyCreatedOneFrameComponent | 0x4 | 4 | OneFrame |
| eoc::hotbar::CurrentDecksComponent | TBD | TBD | Current hotbar decks |
| eoc::identity::IdentityComponent | 0x01 | 1 | Tag - identity |
| eoc::identity::OriginalIdentityComponent | 0x01 | 1 | Tag - original identity |
| eoc::identity::StateComponent | 0x01 | 1 | Tag - identity state |
| eoc::improvised_weapon::CanBeWieldedComponent | 0x01 | 1 | Tag - can be wielded |
| eoc::improvised_weapon::WieldedComponent | 0x10 | 16 | Wielded weapon data |
| eoc::improvised_weapon::WieldingComponent | 0x08 | 8 | Wielding entity ref |
| eoc::item_template::ActionTypeComponent | 0x30 | 48 | Action type with hash |
| eoc::item_template::CanMoveComponent | 0x01 | 1 | Tag - can move |
| eoc::item_template::ClimbOnComponent | 0x01 | 1 | Tag - climbable |
| eoc::item_template::DestroyedComponent | 0x01 | 1 | Tag - destroyed |
| eoc::item_template::InteractionDisabledComponent | 0x01 | 1 | Tag - no interaction |
| eoc::item_template::IsStoryItemComponent | 0x01 | 1 | Tag - story item |
| eoc::item_template::LadderComponent | 0x01 | 1 | Tag - ladder |
| eoc::item_template::UseActionComponent | 0x10 | 16 |  |
| eoc::jump::ActivationEventOneFrameComponent | 0x1 | 1 | OneFrame |
| eoc::jump::AnimationRequestOneFrameComponent | 0xc | 12 | OneFrame |
| eoc::jump::InfoComponent | 0x20 | 32 | Jump mechanics |
| eoc::jump::StateComponent | 0x28 | 40 | Jump state |
| eoc::jump::TakeoffComponent | 0x30 | 48 | Jump takeoff |
| eoc::ladder::ClimbingComponent | 0x01 | 1 | Tag - on ladder |
| eoc::light::ActiveCharacterLightComponent | 0x04 | 4 | Character light |
| eoc::lock::AnimationStateComponent | 0x01 | 1 | Tag - lock anim |
| eoc::lock::KeyComponent | 0x04 | 4 | Key ID |
| eoc::lock::LifetimeComponent | 0x01 | 1 | Tag - lock lifetime |
| eoc::lock::LockComponent | 0x28 | 40 | Lock state |
| eoc::lookat::TargetComponent | 0x10 | 16 | Look-at target |
| eoc::loot::ContainerComponent | 0x18 | 24 | Loot container |
| eoc::loot::SpellLearningResultComponent | 0x18 | 24 | Spell learning result |
| eoc::movement::DashingComponent | 0x1c | 28 | Dashing state |
| eoc::movement::MovementContinueComponent | 0x01 | 1 | Tag - continue |
| eoc::movement::MovementRequestComponent | 0x38 | 56 | Movement request |
| eoc::multiplayer::HostComponent | 0x01 | 1 | Tag - is host |
| eoc::multiplayer::UserComponent | 0x04 | 4 | User ID |
| eoc::object_action::InstanceComponent | 0x88 | 136 | Object action instance |
| eoc::object_action::RequestComponent | 0x40 | 64 | Object action request |
| eoc::object_visual::AppearanceOverrideComponent | 0xd8 | 216 | Appearance override (large!) |
| eoc::object_visual::CharacterCreationTemplateOverrideComponent | 0x04 | 4 | CC template override |
| eoc::ownership::OwnedAsLootComponent | 0x1 | 1 |  |
| eoc::passive::UsageCountComponent | 0x40 | 64 | Passive usage counts |
| eoc::photo_mode::CameraTransformComponent | 0x28 | 40 | Camera transform |
| eoc::photo_mode::DummyAnimationStateComponent | 0x18 | 24 | Dummy anim state |
| eoc::photo_mode::DummyComponent | 0x10 | 16 | Photo mode dummy |
| eoc::photo_mode::DummyEquipmentVisualComponent | 4 | 0x4 | AddComponent<eoc::photo_mode::DummyEquipmentVisualComponent> |
| eoc::photo_mode::DummyShowSplatterComponent | 1 | 0x1 | AddComponent<eoc::photo_mode::DummyShowSplatterComponent> |
| eoc::photo_mode::DummyTransformComponent | 40 | 0x28 | AddComponent<eoc::photo_mode::DummyTransformComponent> |
| eoc::photo_mode::SessionComponent | 1 | 0x1 | AddComponent @ 0x101d2a994 |
| eoc::pickup::PickUpExecutingComponent | 0x1 | 1 |  |
| eoc::pickup::PickUpRequestComponent | 0x18 | 24 |  |
| eoc::portrait_painting::DataComponent | 0x58 | 88 | Portrait data |
| eoc::progression::FeatComponent | 128 | GetComponent | `<< 7` = 128 bytes |
| eoc::progression::LevelUpComponent | 0x10 | 16 | Level up data |
| eoc::progression::MetaComponent | 0x80 | 128 | Meta info |
| eoc::progression::PassivesComponent | 32 (0x20) | Struct analysis | 2x Array<FixedString> = 32 bytes |
| eoc::progression::ReplicatedFeatComponent | 0x18 | 24 | Replicated feats |
| eoc::projectile::SourceInfoComponent | 0x40 | 64 | Projectile source |
| eoc::quest::ModifiedJournalEntrySingletonComponent | 0x40 | 64 | Journal entries |
| eoc::ready_check::BlockedComponent | 0x1 | 1 |  |
| eoc::ready_check::ResultEventOneFrameComponent | 0x28 | 40 | Has invoke PTR, OneFrame |
| eoc::ready_check::StateComponent | 0xa8 | 168 | Has invoke PTR |
| eoc::ready_check::UserComponent | 0x38 | 56 | Ready check user |
| eoc::recruit::RecruiterComponent | 0x30 | 48 | Recruiter data |
| eoc::relation::FactionComponent | 0x30 | 48 | Faction data |
| eoc::relation::RelationComponent | 0x1a0 | 416 | Relations (large!) |
| eoc::replication::ChangesComponent | 0xa8 | 168 | Replication changes |
| eoc::repose::StateComponent | 0x30 | 48 | Rest state |
| eoc::rest::LongRestInScriptPhase | 0x1 | 1 |  |
| eoc::rest::LongRestState | 0x18 | 24 | Has invoke PTR |
| eoc::rest::LongRestTimeline | 0x10 | 16 |  |
| eoc::rest::LongRestTimers | 0x4 | 4 |  |
| eoc::rest::LongRestUsers | 0x78 | 120 | Has invoke PTR |
| eoc::rest::RestingEntities | 0xc8 | 200 | Has invoke PTR |
| eoc::rest::ShortRestComponent | 0x01 | 1 | Tag - short rest |
| eoc::reward::ChoiceComponent | 0x38 | 56 |  |
| eoc::reward::FillRewardInventoriesRequestComponent | 0x80 | 128 | Fill inventories |
| eoc::reward::GiveRewardRequestComponent | 0x10 | 16 | Give reward |
| eoc::reward::ShowRequestComponent | 0x30 | 48 |  |
| eoc::reward::TransferRewardsRequestComponent | 0x40 | 64 | Transfer rewards |
| eoc::room_portal::PortalComponent | 0x18 | 24 |  |
| eoc::room_portal::RoomStateComponent | 0x18 | 24 |  |
| eoc::ruleset::ModifiersComponent | 0x40 | 64 | Ruleset modifiers |
| eoc::ruleset::RulesetComponent | 0x60 | 96 |  |
| eoc::ruleset::RulesetModifiersComponent | 0x40 | 64 | @ 101d38200 |
| eoc::savegame::LoadComponent | 0x20 | 32 | Savegame load |
| eoc::savegame::MainMenuPostInstantiateComponent | 0x01 | 1 | Tag - menu instantiate |
| eoc::savegame::PausedComponent | 0x01 | 1 | Tag - paused |
| eoc::savegame::RunningComponent | 0x01 | 1 | Tag - running |
| eoc::savegame::UnloadLevelComponent | 0x01 | 1 | Tag - unload level |
| eoc::savegame::UnloadModuleComponent | 0x01 | 1 | Tag - unload module |
| eoc::screen_fade::ScreenFadeFromServerComponent | 0x40 | 64 | @ 101997ba4, @ 101da7d74 |
| eoc::script::AnimationStateComponent | 0x10 | 16 | Script animation state |
| eoc::script::AnimationStateRequestOneFrameComponent | 0x01 | 1 | Tag - anim state request |
| eoc::script::PlayAnimationComponent | 0x40 | 64 | Has invoke PTR |
| eoc::script::PlayAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - play anim request |
| eoc::shapeshift::AnimationComponent | 0x08 | 8 | Shapeshift animation |
| eoc::shapeshift::RecoveryAnimationComponent | 0x04 | 4 | @ 1019b1810, @ 101e0bd6c |
| eoc::shapeshift::ReplicatedChangesComponent | 0xa8 | 168 | @ 1019a6514, @ 101e0b05c |
| eoc::shapeshift::SourceCacheComponent | 0x10 | 16 | @ 1019adfc0, @ 101e0a37c |
| eoc::shapeshift::StateComponent | 0x18 | 24 | @ 1019aa430, @ 101e0972c |
| eoc::sight::BaseComponent | 0x10 | 16 | @ 1019bc190, @ 101e5c3c8 |
| eoc::sight::DataComponent | 0x28 | 40 | @ 1019b8928, @ 101e5b748 |
| eoc::sight::EntityViewshedComponent | 0x30 | 48 | Entity viewshed |
| eoc::sight::IgnoreSurfacesComponent | 0x30 | 48 | @ 1019c4398, @ 101e59e9c |
| eoc::sneak::IsSneakingComponent | 0x01 | 1 | Tag - is sneaking |
| eoc::sneak::RollsContainerComponent | 0x18 | 24 | Sneak rolls container |
| eoc::sound::DistantSoundInfoComponent | 0x10 | 16 | @ 1015cc304, @ 101eb33cc |
| eoc::sound::DistantSoundStateComponent | 0x78 | 120 | @ 1015d0908 |
| eoc::sound::FlagSwitchDataComponent | 0x10 | 16 | Has invoke PTR |
| eoc::sound::PerformanceZoneComponent | 0x80 | 128 | Has invoke PTR |
| eoc::spatial_grid::CharacterComponent | 0x01 | 1 | @ 101de3ac8 |
| eoc::spatial_grid::DataComponent | 0x98 | 152 | @ 101e55e34 |
| eoc::spatial_grid::ItemComponent | 0x01 | 1 | @ 101de2558 |
| eoc::splatter::StateComponent | 0x1c | 28 | Splatter state |
| eoc::splatter::SweatChangeComponent | 0x4 | 4 |  |
| eoc::splatter::UpdateAttachmetsRequestOneFrameComponent | 0x01 | 1 | Attachment update request |
| eoc::splatter::ValueChangedOneFrameComponent | 0x04 | 4 | Splatter value change |
| eoc::stats::AreaLevelComponent | 0x04 | 4 | Area level |
| eoc::stats::MusicalInstrumentComponent | 0x01 | 1 | Tag - musical instrument |
| eoc::stats::proficiency::IntrinsicallyProficientWielderComponent | 0x18 | 24 | Intrinsic proficiency |
| eoc::stats::proficiency::ProficiencyComponent | 0x08 | 8 | Proficiency data |
| eoc::stats::proficiency::ProficiencyGroupComponent | 0x08 | 8 | Proficiency group |
| eoc::steering::SyncComponent | 0x04 | 4 | Steering sync |
| eoc::story::CounterComponent | 0x0c | 12 | Story counter |
| eoc::story::DisplayedMessageComponent | 0x08 | 8 | Message ref |
| eoc::story::TimerComponent | 0x10 | 16 | Story timer |
| eoc::summon::AnimationComponent | 0x01 | 1 | Tag - summon anim |
| eoc::summon::ContainerComponent | 0xa0 | 160 | Summon container (large!) |
| eoc::summon::IsSpawnComponent | 0x01 | 1 | Tag - is spawn |
| eoc::summon::IsSummonComponent | 0x30 | 48 | Is summon |
| eoc::summon::LifetimeComponent | 0x08 | 8 | Lifetime |
| eoc::tadpole_tree::FullIllithidComponent | 0x1 | 1 |  |
| eoc::tadpole_tree::HalfIllithidComponent | 0x1 | 1 |  |
| eoc::tadpole_tree::PowerContainerComponent | 0x10 | 16 |  |
| eoc::tadpole_tree::TadpoledComponent | 0x1 | 1 |  |
| eoc::tadpole_tree::TreeStateComponent | 0x1 | 1 |  |
| eoc::tag::AvatarComponent | 0x01 | 1 | Tag - is avatar |
| eoc::tag::HasExclamationDialogComponent | 0x01 | 1 | Tag - has exclamation |
| eoc::tag::TraderComponent | 0x01 | 1 | Tag - is trader |
| eoc::templates::OriginalTemplateComponent | 0x08 | 8 |  |
| eoc::through::CanSeeThroughComponent | 0x1 | 1 |  |
| eoc::through::CanShootThroughComponent | 0x1 | 1 |  |
| eoc::through::CanWalkThroughComponent | 0x1 | 1 |  |
| eoc::through::ShootThroughTypeComponent | 0x01 | 1 | Tag - shoot through |
| eoc::thrown::AttachComponent | 0x10 | 16 | Thrown attach |
| eoc::thrown::IsThrownComponent | 0x10 | 16 | Thrown state |
| eoc::thrown::RotationParametersComponent | 0x38 | 56 | Rotation params |
| eoc::thrown::SpellPrepareAnimationRequest | 0x04 | 4 | Spell prep anim |
| eoc::thrown::ThrownAnimationRequestOneFrameComponent | 0x08 | 8 | Thrown weapon animation request |
| eoc::timeline::ActorVisualDataComponent | 0x08 | 8 | Actor visual data |
| eoc::timeline::HideEquipmentComponent | 0x01 | 1 | Tag - hide equipment |
| eoc::timeline::steering::TimelineSteeringComponent | 0x78 | 120 | Timeline steering |
| eoc::tracking::RequestTargetTrackingOneFrameComponent | 0x40 | 64 | Target tracking |
| eoc::trade::CanTradeComponent | 0x1 | 1 |  |
| eoc::trade::ShownTraderMapMarkerGuidComponent | 0x10 | 16 | Trader marker |
| eoc::trade::ShownTraderMapMarkerNameComponent | 0x10 | 16 | Trader name |
| eoc::trade::ShownTraderMapMarkerTranslateComponent | 0x0c | 12 | Trader translate |
| eoc::trade::TradeBuybackDataComponent | 0x18 | 24 | Buyback data |
| eoc::trade::TraderMapMarkerHostilePlayersComponent | 0x30 | 48 |  |
| eoc::translate::ChangedComponent | 0x40 | 64 |  |
| eoc::trap::DisarmingAnimationStateComponent | 0x01 | 1 | Tag - disarming |
| eoc::trigger::TypeComponent | 0x01 | 1 | Tag - trigger type |
| eoc::tutorial::RevealedEntriesComponent | 0x30 | 48 | Tutorial entries |
| eoc::unsheath::SpellAnimationOverrideComponent | 0x04 | 4 | Spell anim override |
| eoc::use::SocketComponent | 0x40 | 64 | Socket data |
| eoc::user::AvatarComponent | 0x0c | 12 | Avatar data |
| eoc::user::DismissedComponent | 0x1 | 1 |  |
| eoc::user::ReservedForComponent | 4 | 0x4 | AddComponent @ 0x101e2a99c |

**Total: 298 components**
