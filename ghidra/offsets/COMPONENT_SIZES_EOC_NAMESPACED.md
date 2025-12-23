# EOC Namespaced Components - ARM64 Sizes

Sub-namespace components within eoc:: (spell::, combat::, progression::, etc.)

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Spell Components (eoc::spell::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell::AddedSpellsComponent | 0x10 | 16 | DynamicArray<SpellMeta> |
| eoc::spell::AiConditionsComponent | 0x40 | 64 | HashTable for AI conditions |
| eoc::spell::AttackSpellOverrideComponent | 0x40 | 64 | HashTable<EAttackSpellType> |
| eoc::spell::BookComponent | 0x18 | 24 | Entity ID + DynamicArray |
| eoc::spell::BookCooldownsComponent | 0x10 | 16 | DynamicArray<CooldownData> |
| eoc::spell::BookPreparesComponent | 0x90 | 144 | Multiple arrays + HashTables |
| eoc::spell::CCPrepareSpellComponent | 0x10 | 16 | DynamicArray<MetaId> |
| eoc::spell::ContainerComponent | 0x10 | 16 | DynamicArray<SpellMeta> |
| eoc::spell::LearnedSpellsComponent | 0x70 | 112 | Multiple HashTables |
| eoc::spell::ModificationContainerComponent | 0x40 | 64 | HashMap modifications |
| eoc::spell::PlayerPrepareSpellComponent | 0x18 | 24 | DynamicArray + bool |
| eoc::spell::ScriptedExplosionComponent | 0x04 | 4 | Spell ID reference |

## Combat Components (eoc::combat::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::combat::DelayedFanfareComponent | 0x01 | 1 | Tag - delayed fanfare |
| eoc::combat::InitiatorDebugComponent | 0x120 | 288 | Debug - 6 hash tables |
| eoc::combat::IsInCombatComponent | 0x01 | 1 | In combat flag |
| eoc::combat::IsThreatenedComponent | 0x10 | 16 | DynamicArray of threats |
| eoc::combat::ParticipantComponent | 0x28 | 40 | Combat participant data |
| eoc::combat::StateComponent | 0x98 | 152 | Full combat state |
| eoc::combat::ThreatRangeComponent | 0x0c | 12 | Range + flags |

## Progression Components (eoc::progression::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ProgressionContainerComponent | 0x10 | 16 | Container |
| eoc::progression::LevelUpComponent | 0x10 | 16 | Level up data |
| eoc::progression::MetaComponent | 0x80 | 128 | Meta info |
| eoc::progression::ReplicatedFeatComponent | 0x18 | 24 | Replicated feats |

## Summon Components (eoc::summon::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::summon::AnimationComponent | 0x01 | 1 | Tag - summon anim |
| eoc::summon::ContainerComponent | 0xa0 | 160 | Summon container (large!) |
| eoc::summon::IsSpawnComponent | 0x01 | 1 | Tag - is spawn |
| eoc::summon::IsSummonComponent | 0x30 | 48 | Is summon |
| eoc::summon::LifetimeComponent | 0x08 | 8 | Lifetime |

## Concentration Components (eoc::concentration::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::concentration::ConcentrationComponent | 0x50 | 80 | Concentration state |

## Experience Components (eoc::exp::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::exp::ExperienceComponent | 0x10 | 16 | XP |

## Relation Components (eoc::relation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::relation::FactionComponent | 0x30 | 48 | Faction data |
| eoc::relation::RelationComponent | 0x1a0 | 416 | Relations (large!) |

## Status Components (eoc::status::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::status::CauseComponent | 0x08 | 8 | Status cause (pointer/ID) |
| eoc::status::ContainerComponent | 0x40 | 64 | Status container |
| eoc::status::IDComponent | 0x04 | 4 | Status ID |
| eoc::status::IncapacitatedComponent | 0x50 | 80 | Incapacitated |
| eoc::status::IndicateDarknessComponent | 0x01 | 1 | Tag - darkness indicator |
| eoc::status::LifetimeComponent | 0x08 | 8 | Status lifetime |
| eoc::status::LoseControlComponent | 0x01 | 1 | Tag - lose control |
| eoc::status::TauntedComponent | 0x08 | 8 | Taunted status |
| eoc::status::visual::DisabledComponent | 0x30 | 48 | Visual disabled (HashTable) |

## Inventory Components (eoc::inventory::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::inventory::CanBeInComponent | 0x01 | 1 | Tag - can be in inventory |
| eoc::inventory::CannotBePickpocketedComponent | 0x01 | 1 | Tag - no pickpocket |
| eoc::inventory::CannotBeTakenOutComponent | 0x01 | 1 | Tag - can't remove |
| eoc::inventory::ContainerComponent | 0x40 | 64 | Inventory container |
| eoc::inventory::DataComponent | 0x04 | 4 | Inventory data |
| eoc::inventory::DropOnDeathBlockedComponent | 0x01 | 1 | Tag - no drop on death |
| eoc::inventory::IsLockedComponent | 0x01 | 1 | Tag - locked |
| eoc::inventory::IsOwnedComponent | 0x08 | 8 | Owner entity ref |
| eoc::inventory::MemberComponent | 0x10 | 16 | Inventory member |
| eoc::inventory::MemberTransformComponent | 0x28 | 40 | Transform in container |
| eoc::inventory::NewItemsInsideComponent | 0x01 | 1 | Tag - new items |
| eoc::inventory::NonTradableComponent | 0x01 | 1 | Tag - non-tradable |
| eoc::inventory::OwnerComponent | 0x18 | 24 | Owner vector |
| eoc::inventory::StackComponent | 0x20 | 32 | Stack data |
| eoc::inventory::StackMemberComponent | 0x08 | 8 | Stack member ref |
| eoc::inventory::TopOwnerComponent | 0x08 | 8 | Top owner entity ref |
| eoc::inventory::TradeBuybackDataComponent | 0x18 | 24 | Buyback data |
| eoc::inventory::WeightComponent | 0x04 | 4 | Weight value |

## Interrupt Components (eoc::interrupt::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::interrupt::ActionStateComponent | 0x128 | 296 | Largest - interrupt sequence data |
| eoc::interrupt::ConditionallyDisabledComponent | 0x01 | 1 | Tag - conditionally disabled |
| eoc::interrupt::ContainerComponent | 0x10 | 16 | Container |
| eoc::interrupt::DataComponent | 0x20 | 32 | Data with GST node refs |
| eoc::interrupt::DecisionComponent | 0x40 | 64 | Hash table for decisions |
| eoc::interrupt::PreferencesComponent | 0x40 | 64 | Hash table for preferences |
| eoc::interrupt::PreparedComponent | 0x01 | 1 | Tag - prepared |
| eoc::interrupt::ZoneComponent | 0x10 | 16 | Zone data |
| eoc::interrupt::ZoneParticipantComponent | 0x40 | 64 | Hash table for participants |
| eoc::interrupt::ZoneSourceComponent | 0x01 | 1 | Tag - zone source |

## Approval/Attitude Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::approval::RatingsComponent | 0x70 | 112 | Approval ratings (HashTable) |
| eoc::armor_set::StateComponent | 0x01 | 1 | Tag - armor set |
| eoc::attitude::AttitudesToPlayersComponent | 0x40 | 64 | Attitudes (HashTable) |
| eoc::background::GoalsComponent | 0x40 | 64 | Background goals |

## Calendar Components (eoc::calendar::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::calendar::DaysPassedComponent | 0x04 | 4 | Days passed count |
| eoc::calendar::StartingDateComponent | 0x08 | 8 | Starting date |

## Camp Components (eoc::camp::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::camp::AvatarContainerComponent | 0x01 | 1 | Tag - avatar container |
| eoc::camp::ChestComponent | 0x28 | 40 | Camp chest data |
| eoc::camp::EndTheDayStateComponent | 0x10 | 16 | End day state |
| eoc::camp::PresenceComponent | 0x01 | 1 | Tag - camp presence |
| eoc::camp::QualityComponent | 0x08 | 8 | Camp quality |
| eoc::camp::SettingsComponent | 0x08 | 8 | Camp settings |
| eoc::camp::SupplyComponent | 0x04 | 4 | Supply count |
| eoc::camp::TotalSuppliesComponent | 0x04 | 4 | Total supplies |

## Camera Components (eoc::camera::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::camera::ConversationCameraComponent | 0x08 | 8 | Conversation camera |
| eoc::camera::MoveComponent | 0x10 | 16 | Camera movement |
| eoc::camera::SelectedCameraComponent | 0x08 | 8 | Selected camera |
| eoc::camera::SilenceFadeComponent | 0x10 | 16 | Silence fade |
| eoc::camera::SpellWaitComponent | 0x04 | 4 | Spell camera wait |

## Character Tag Components (eoc::character::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::character::CharacterComponent | 0x01 | 1 | Tag - is character |
| eoc::character::EquipmentVisualComponent | 0x01 | 1 | Tag - equipment visual |

## Controller Components (eoc::controller::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::controller::LocomotionComponent | 0x84 | 132 | Movement locomotion |
| eoc::controller::NudgeDataComponent | 0x1c | 28 | Pathfinding nudge |

## Crowds Components (eoc::crowds::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::crowds::AppearanceComponent | 0x40 | 64 | Crowd appearance |
| eoc::crowds::BehaviourComponent | 0x01 | 1 | Tag - behavior |
| eoc::crowds::CharacterComponent | 0x10 | 16 | Crowd character |
| eoc::crowds::CustomAnimationComponent | 0x04 | 4 | Custom anim |
| eoc::crowds::DeadReckoningComponent | 0x14 | 20 | Network prediction |
| eoc::crowds::IsFadingComponent | 0x01 | 1 | Tag - fading |
| eoc::crowds::ProxyComponent | 0x08 | 8 | Proxy ref |
| eoc::crowds::ProxyDynamicAnimationSetComponent | 0x10 | 16 | Dynamic anims |

## Custom Dice Components (eoc::customdice::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::customdice::UsersDiceSingletonComponent | 0x40 | 64 | User dice data |

## Death Components (eoc::death::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::death::DeathComponent | 0x78 | 120 | Death state |
| eoc::death::DeathTypeComponent | 0x01 | 1 | Tag - death type |
| eoc::death::DownedComponent | 0x18 | 24 | Downed state |
| eoc::death::StateComponent | 0x04 | 4 | Death state value |

## Jump/Movement Components (eoc::jump::, eoc::ladder::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::jump::InfoComponent | 0x20 | 32 | Jump mechanics |
| eoc::ladder::ClimbingComponent | 0x01 | 1 | Tag - on ladder |

## Light Components (eoc::light::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::light::ActiveCharacterLightComponent | 0x04 | 4 | Character light |

## Lock Components (eoc::lock::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::lock::AnimationStateComponent | 0x01 | 1 | Tag - lock anim |
| eoc::lock::KeyComponent | 0x04 | 4 | Key reference |
| eoc::lock::LifetimeComponent | 0x01 | 1 | Tag - lock lifetime |
| eoc::lock::LockComponent | 0x28 | 40 | Full lock data |

## LookAt Components (eoc::lookat::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::lookat::TargetComponent | 0x10 | 16 | Look-at target |

## Multiplayer Components (eoc::multiplayer::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::multiplayer::HostComponent | 0x01 | 1 | Tag - is host |
| eoc::multiplayer::UserComponent | 0x04 | 4 | User ID |

## Notification Components (eoc::notification::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::notification::ApprovalRatingComponent | 0x28 | 40 | Approval rating |
| eoc::notification::BackgroundGoalComponent | 0x20 | 32 | Background goal |
| eoc::notification::ConcentrationChangedComponent | 0x88 | 136 | Concentration changed |
| eoc::notification::EnemySightedComponent | 0x18 | 24 | Enemy sighted |
| eoc::notification::RandomCastResultComponent | 0x50 | 80 | Random cast result |
| eoc::notification::ShortRestStatusDurationIncreasedComponent | 0x10 | 16 | Short rest status |
| eoc::notification::ShowHudNotificationComponent | 0x30 | 48 | Show HUD notification |
| eoc::notification::SpellCastConfirmComponent | 0x30 | 48 | Spell cast confirm |
| eoc::notification::SpellPrepareStartEventComponent | 0x40 | 64 | Spell prepare start |
| eoc::notification::StatsAppliedComponent | 0x18 | 24 | Stats applied |
| eoc::notification::StopMovementComponent | 0x01 | 1 | Tag - stop movement |
| eoc::notification::SurfaceEnteredComponent | 0x18 | 24 | Surface entered |
| eoc::notification::SurfaceLeftComponent | 0x18 | 24 | Surface left |
| eoc::notification::TadpoleSuperPowerRequestComponent | 0x01 | 1 | Tag - tadpole power |
| eoc::notification::TradeEventComponent | 0x10 | 16 | Trade event |
| eoc::notification::UpdatePortraitMaterialRequestComponent | 0x10 | 16 | Portrait material |
| eoc::notification::VariableManagerDirtyComponent | 0x01 | 1 | Tag - variable dirty |
| eoc::notification::WorldAligningComponent | 0x38 | 56 | World aligning |

## Portrait Painting (eoc::portrait_painting::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::portrait_painting::DataComponent | 0x58 | 88 | Painting data |

## Quest/Journal (eoc::quest::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::quest::ModifiedJournalEntrySingletonComponent | 0x40 | 64 | Journal entries |

## Ready Check (eoc::ready_check::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ready_check::UserComponent | 0x38 | 56 | Ready check user |

## Recruit (eoc::recruit::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::recruit::RecruiterComponent | 0x30 | 48 | Recruiter data |

## Repose (eoc::repose::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::repose::StateComponent | 0x30 | 48 | Rest state |

## Rest (eoc::rest::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::rest::ShortRestComponent | 0x01 | 1 | Tag - short rest |

## Projectile Source (eoc::projectile::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::projectile::SourceInfoComponent | 0x40 | 64 | Projectile source |

## Stealth (eoc::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::StealthComponent | 0x24 | 36 | Stealth data |
| eoc::MovementComponent | 0x18 | 24 | Movement state |
| eoc::PassiveComponent | 0x20 | 32 | Passive ability |
| eoc::PassiveContainerComponent | 0x10 | 16 | Passive container |
| eoc::PlayerComponent | 0x01 | 1 | Tag - is player |

## Passive Components (eoc::passive::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::passive::UsageCountComponent | 0x40 | 64 | Passive usage counts |

## Visual/Animation Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::GameObjectVisualComponent | 0x14 | 20 | GameObject visual data |
| eoc::character::EquipmentVisualComponent | 0x01 | 1 | Equipment visual flag |
| eoc::object_visual::AppearanceOverrideComponent | 0xd8 | 216 | Appearance override (large!) |
| eoc::object_visual::CharacterCreationTemplateOverrideComponent | 0x04 | 4 | CC template override |
| eoc::timeline::ActorVisualDataComponent | 0x08 | 8 | Timeline actor visual |
| eoc::drop::AnimationComponent | 0x01 | 1 | Drop item animation |
| eoc::script::AnimationStateComponent | 0x10 | 16 | Script animation state |
| eoc::spell_cast::AnimationInfoComponent | 0x30 | 48 | Spell cast animation |
| eoc::notification::CancelScriptAnimationComponent | 0x18 | 24 | Cancel script anim |

## Dialog/Voice Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::VoiceComponent | 0x10 | 16 | Voice data |
| eoc::ServerRootLevelStartDialogComponent | 0x01 | 1 | Tag - dialog starter |
| eoc::tag::HasExclamationDialogComponent | 0x01 | 1 | Tag - has exclamation |

## Tag Components (eoc::tag::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::tag::AvatarComponent | 0x01 | 1 | Tag - is avatar |
| eoc::tag::TraderComponent | 0x01 | 1 | Tag - is trader |
| eoc::TagComponent | 0x10 | 16 | Tag with GUID data |
| eoc::OffStageComponent | 0x01 | 1 | Tag - off stage |

## Use/Usable Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::UseComponent | 0x50 | 80 | Primary use component |
| eoc::UseBoostsComponent | 0x10 | 16 | Use boosts array |
| eoc::item::InUseComponent | 0x01 | 1 | Tag - item in use |

## Camp Components (eoc::camp::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::camp::AvatarContainerComponent | 0x01 | 1 | Avatar container |

## Additional Boost Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::SightRangeAdditiveBoostComponent | 0x04 | 4 | Sight range |
| eoc::SpellResistanceBoostComponent | 0x01 | 1 | Tag - spell resist |

## Item Components (eoc::item::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::item::animation::RequestComponent | 0x04 | 4 | Animation request ID |
| eoc::item::CanBeWieldedComponent | 0x01 | 1 | Tag - wieldable |
| eoc::item::DestroyedComponent | 0x0c | 12 | Destroyed state (FixedString) |
| eoc::item::DestroyingComponent | 0x01 | 1 | Tag - destroying |
| eoc::item::DoorComponent | 0x01 | 1 | Tag - door |
| eoc::item::DyeComponent | 0x10 | 16 | Dye data (2x uint64) |
| eoc::item::ExamineDisabledComponent | 0x01 | 1 | Tag - examine disabled |
| eoc::item::HasMovedComponent | 0x01 | 1 | Tag - has moved |
| eoc::item::HasOpenedComponent | 0x01 | 1 | Tag - has opened |
| eoc::item::IdentityComponent | 0x01 | 1 | Tag - item identity |
| eoc::item::InUseComponent | 0x01 | 1 | Tag - in use |
| eoc::item::IsGoldComponent | 0x01 | 1 | Tag - is gold |
| eoc::item::IsPoisonedComponent | 0x01 | 1 | Tag - is poisoned |
| eoc::item::ItemComponent | 0x01 | 1 | Tag - base item |
| eoc::item::MapMarkerStyleComponent | 0x04 | 4 | Map marker style ID |
| eoc::item::MemberTransformComponent | 0x28 | 40 | Transform in container |
| eoc::item::NewInInventoryComponent | 0x01 | 1 | Tag - new in inventory |
| eoc::item::NewItemsInsideComponent | 0x01 | 1 | Tag - new items |
| eoc::item::NonTradableComponent | 0x01 | 1 | Tag - non-tradable |
| eoc::item::OriginalIdentityComponent | 0x01 | 1 | Tag - original identity |
| eoc::item::OwnedAsLootComponent | 0x01 | 1 | Tag - owned as loot |
| eoc::item::PortalComponent | 0x02 | 2 | Portal data (short) |
| eoc::item::ShouldDestroyOnSpellCastComponent | 0x01 | 1 | Tag - destroy on cast |
| eoc::item::StackComponent | 0x20 | 32 | Stack data |
| eoc::item::StackMemberComponent | 0x08 | 8 | Stack member ref |
| eoc::item::StateComponent | 0x01 | 1 | Tag - item state |
| eoc::item::WieldedComponent | 0x10 | 16 | Wielded item data |
| eoc::item::WieldingComponent | 0x08 | 8 | Wielding entity ref |

## Story Components (eoc::story::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::story::CounterComponent | 0x0c | 12 | Story counter |
| eoc::story::DisplayedMessageComponent | 0x08 | 8 | Message ref |
| eoc::story::TimerComponent | 0x10 | 16 | Story timer |

## Through/Thrown Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::through::ShootThroughTypeComponent | 0x01 | 1 | Tag - shoot through |
| eoc::thrown::AttachComponent | 0x10 | 16 | Thrown attach |
| eoc::thrown::IsThrownComponent | 0x10 | 16 | Thrown state |
| eoc::thrown::RotationParametersComponent | 0x38 | 56 | Rotation params |
| eoc::thrown::SpellPrepareAnimationRequest | 0x04 | 4 | Spell prep anim |

## Trade Components (eoc::trade::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::trade::ShownTraderMapMarkerGuidComponent | 0x10 | 16 | Trader marker |
| eoc::trade::ShownTraderMapMarkerNameComponent | 0x10 | 16 | Trader name |
| eoc::trade::ShownTraderMapMarkerTranslateComponent | 0x0c | 12 | Trader translate |
| eoc::trade::TradeBuybackDataComponent | 0x18 | 24 | Buyback data |

## Trigger Components (eoc::trigger::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::trigger::TypeComponent | 0x01 | 1 | Tag - trigger type |

## Trap/Tutorial Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::trap::DisarmingAnimationStateComponent | 0x01 | 1 | Tag - disarming |
| eoc::tutorial::RevealedEntriesComponent | 0x30 | 48 | Tutorial entries |

## Unsheath Components (eoc::unsheath::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::unsheath::SpellAnimationOverrideComponent | 0x04 | 4 | Spell anim override |

## Use Components (eoc::use::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::use::SocketComponent | 0x40 | 64 | Socket data |

## User Components (eoc::user::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::user::AvatarComponent | 0x0c | 12 | Avatar data |

## Steering Components (eoc::steering::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::steering::SyncComponent | 0x04 | 4 | Steering sync |

## Party Components (eoc::party::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::party::OwneeCurrentComponent | 0x08 | 8 | Current ownee ref |
| eoc::party::BlockFollowComponent | 0x01 | 1 | Tag - block follow |
| eoc::party::CurrentlyFollowingPartyComponent | 0x01 | 1 | Tag - following |
| eoc::party::FollowerComponent | 0x08 | 8 | Follower ref |
| eoc::party::MemberComponent | 0x38 | 56 | Party member data |
| eoc::party::PortalsComponent | 0x30 | 48 | Portal management |
| eoc::party::RecipesComponent | 0x10 | 16 | Recipe tracking |
| eoc::party::ViewComponent | 0x30 | 48 | Party view state |
| eoc::party::WaypointsComponent | 0x30 | 48 | Waypoint data |

## Notification Components (eoc::notification:: - extended)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::notification::PerformFailedComponent | 0x01 | 1 | Tag - perform failed |
| eoc::notification::PickUpResultNotificationComponent | 0x18 | 24 | Pickup result |
| eoc::notification::PingRequestComponent | 0x28 | 40 | Ping request |
| eoc::notification::PlayServerSoundComponent | 0x20 | 32 | Server sound |
| eoc::notification::ProfileShownTutorialsUpdateNotificationComponent | 0x38 | 56 | Tutorial update |
| eoc::notification::ScreenFadeFromServerComponent | 0x40 | 64 | Screen fade |

## Character Creation Components (eoc::character_creation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::character_creation::AppearanceComponent | 0x70 | 112 | Appearance data |
| eoc::character_creation::CharacterChangedAppearanceComponent | 0x130 | 304 | Appearance change |
| eoc::character_creation::CharacterCreatedComponent | 0x3e0 | 992 | Character created (largest!) |
| eoc::character_creation::CharacterDefinitionComponent | 0x290 | 656 | Character definition (large!) |
| eoc::character_creation::DefinitionCommonComponent | 0xc0 | 192 | Definition common |
| eoc::character_creation::SessionCommonComponent | 0x0c | 12 | Session common |

## Script Components (eoc::script::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::script::AnimationStateRequestOneFrameComponent | 0x01 | 1 | Tag - animation state request |

## Sight Components (eoc::sight::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::sight::EntityViewshedComponent | 0x30 | 48 | Entity viewshed data |

## Shapeshift Components (eoc::shapeshift::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::shapeshift::AnimationComponent | 0x08 | 8 | Shapeshift animation ref |

## Spell Cast Components (eoc::spell_cast:: - extended)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell_cast::AnimationInfoComponent | 0x30 | 48 | Animation info |
| eoc::spell_cast::CacheComponent | 0x08 | 8 | Spell cache ref |
| eoc::spell_cast::CanBeTargetedComponent | 0x01 | 1 | Tag - can target |
| eoc::spell_cast::CastEventOneFrameComponent | 0x1C0 | 448 | Cast event (large!) |
| eoc::spell_cast::CastHitEventOneFrameComponent | 0x10 | 16 | Cast hit event |
| eoc::spell_cast::DataCacheSingletonComponent | 0x40 | 64 | Data cache |
| eoc::spell_cast::InterruptResultsComponent | 0x38 | 56 | Interrupt results |
| eoc::spell_cast::MovementComponent | 0x1c | 28 | Movement data |
| eoc::spell_cast::OutcomeComponent | 0x01 | 1 | Tag - outcome |
| eoc::spell_cast::RollsComponent | 0x10 | 16 | Spell rolls |
| eoc::spell_cast::SpellCastConfirmComponent | 0x30 | 48 | Spell confirm |
| eoc::spell_cast::SpellCastFailedComponent | 0x18 | 24 | Spell failed |
| eoc::spell_cast::SpellCastMovementAndPrecalculationEndComponent | 0x18 | 24 | Movement end |
| eoc::spell_cast::SpellCastRollAbortComponent | 0x10 | 16 | Roll abort |
| eoc::spell_cast::SpellCastZoneRangeComputedComponent | 0x10 | 16 | Zone computed |
| eoc::spell_cast::SpellRollAbortEventOneFrameComponent | 0x1c0 | 448 | Spell roll abort event (large!) |
| eoc::spell_cast::SpellRollCastEventOneFrameComponent | 0x1c0 | 448 | Spell roll cast event (large!) |
| eoc::spell_cast::StateComponent | 0xc0 | 192 | Spell cast state (large!) |
| eoc::spell_cast::SurfaceCreationRequestOneFrameComponent | 0x30 | 48 | Surface creation request |
| eoc::spell_cast::SyncTargetingComponent | 0x98 | 152 | Sync targeting data |
| eoc::spell_cast::TargetPickedOneFrameComponent | 0x90 | 144 | Target picked event |

## Animation Components (eoc::animation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::animation::BlueprintRefreshedEventOneFrameComponent | 0x01 | 1 | Tag - blueprint refreshed event |
| eoc::animation::DoorAnimationFinishedOneFrameComponent | 0x18 | 24 | Door anim finished |
| eoc::animation::DoorEventCachingSingletonComponent | 0xc0 | 192 | Door event caching (singleton) |
| eoc::animation::GameplayEventsOneFrameComponent | 0x40 | 64 | Gameplay events (one frame) |
| eoc::animation::PlayAnimationComponent | 0x40 | 64 | Play animation |
| eoc::animation::RecoveryAnimationComponent | 0x04 | 4 | Recovery anim |
| eoc::animation::RefreshAnimationRequestOneFrameComponent | 0x10 | 16 | Refresh animation request |
| eoc::animation::TextKeyEventsOneFrameComponent | 0x40 | 64 | Text key events (one frame) |
| eoc::animation::TriggeredEventsOneFrameComponent | 0x40 | 64 | Triggered events (one frame) |

## Gamestate Components (eoc::gamestate::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::gamestate::MainMenuPostInstantiateComponent | 0x01 | 1 | Tag - main menu |
| eoc::gamestate::PausedComponent | 0x01 | 1 | Tag - paused |
| eoc::gamestate::RunningComponent | 0x01 | 1 | Tag - running |
| eoc::gamestate::SavegameLoadComponent | 0x20 | 32 | Savegame load |
| eoc::gamestate::ScreenFadeComponent | 0x30 | 48 | Screen fade |
| eoc::gamestate::ServerTargetsNotificationComponent | 0x30 | 48 | Server targets |
| eoc::gamestate::TeleportRequestComponent | 0x38 | 56 | Teleport request |
| eoc::gamestate::UnloadLevelComponent | 0x01 | 1 | Tag - unload level |
| eoc::gamestate::UnloadModuleComponent | 0x01 | 1 | Tag - unload module |

## Camera Components (eoc::camera::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::camera::ConversationCameraComponent | 0x08 | 8 | Conversation camera |
| eoc::camera::SelectedCameraComponent | 0x08 | 8 | Selected camera |
| eoc::camera::SilenceFadeComponent | 0x10 | 16 | Silence fade |

## Jump Components (eoc::jump:: - extended)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::jump::StateComponent | 0x28 | 40 | Jump state |
| eoc::jump::TakeoffComponent | 0x30 | 48 | Jump takeoff |

## Loot Components (eoc::loot::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::loot::ContainerComponent | 0x18 | 24 | Loot container |
| eoc::loot::SpellLearningResultComponent | 0x18 | 24 | Spell learning result |

## Hearing Components (eoc::hearing::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::hearing::EnteredListenerRangeEventOneFrameComponent | 0x08 | 8 | Entered listener range |
| eoc::hearing::LeftListenerRangeEventOneFrameComponent | 0x08 | 8 | Left listener range |

## Dialog Components (eoc::dialog::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::dialog::ActiveDialogActorComponent | 0x28 | 40 | Active dialog actor |
| eoc::dialog::DialoguePrivacySingletonComponent | 0x40 | 64 | HashTable<unsigned_int> |
| eoc::dialog::InitiatorComponent | 0x10 | 16 | Dialog initiator |
| eoc::dialog::IsListeningSingletonComponent | 0x40 | 64 | HashTable<ls::Guid> |
| eoc::dialog::NoPrivateDialogsSingletonComponent | 0x30 | 48 | HashTable<net::UserID> |
| eoc::dialog::StateComponent | 0x0c | 12 | Dialog state |

## Action Components (eoc::action::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::action::ActionStateComponent | 0x08 | 8 | Action state |
| eoc::action::RequestPushComponent | 0x50 | 80 | Push request |

## Object Action Components (eoc::object_action::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::object_action::RequestComponent | 0x40 | 64 | Object action request |
| eoc::object_action::InstanceComponent | 0x88 | 136 | Object action instance |

## Spell Components (eoc::spell:: - extended)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell::ModificationContainerComponent | 0x40 | 64 | Spell modifications |
| eoc::spell::ScriptedExplosionComponent | 0x04 | 4 | Scripted explosion |

## Replication Components (eoc::replication::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::replication::ChangesComponent | 0xa8 | 168 | Replication changes |

## Ruleset Components (eoc::ruleset::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ruleset::ModifiersComponent | 0x40 | 64 | Ruleset modifiers |

## Door Components (eoc::door::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::door::ISDoorClosedAnimationFinishedOneFrameComponent | 0x01 | 1 | Tag - closed finished |
| eoc::door::ISDoorClosedAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - closed request |
| eoc::door::ISDoorClosedComponent | 0x08 | 8 | Door closed state |
| eoc::door::ISDoorOpenedAnimationFinishedOneFrameComponent | 0x01 | 1 | Tag - opened finished |
| eoc::door::ISDoorOpenedAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - opened request |
| eoc::door::ISDoorOpenedComponent | 0x08 | 8 | Door opened state |

## Movement Components (eoc::movement::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::movement::DashingComponent | 0x1c | 28 | Dashing state |
| eoc::movement::MovementContinueComponent | 0x01 | 1 | Tag - continue |
| eoc::movement::MovementRequestComponent | 0x38 | 56 | Movement request |

## Savegame Components (eoc::savegame::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::savegame::LoadComponent | 0x20 | 32 | Savegame load |
| eoc::savegame::MainMenuPostInstantiateComponent | 0x01 | 1 | Tag - menu instantiate |
| eoc::savegame::PausedComponent | 0x01 | 1 | Tag - paused |
| eoc::savegame::RunningComponent | 0x01 | 1 | Tag - running |
| eoc::savegame::UnloadLevelComponent | 0x01 | 1 | Tag - unload level |
| eoc::savegame::UnloadModuleComponent | 0x01 | 1 | Tag - unload module |

## Shapeshift Components (eoc::shapeshift::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::shapeshift::AnimationComponent | 0x08 | 8 | Shapeshift animation |

## Sight Components (eoc::sight::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::sight::EntityViewshedComponent | 0x30 | 48 | Entity viewshed |

## Script Components (eoc::script::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::script::AnimationStateRequestOneFrameComponent | 0x01 | 1 | Tag - anim state request |
| eoc::script::PlayAnimationRequestOneFrameComponent | 0x01 | 1 | Tag - play anim request |

## Boost Components (eoc::boost::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::boost::ChangedEventOneFrameComponent | 0x10 | 16 | Boost changed event |
| eoc::BoostsComponent | 0x340 | 832 | All boosts container (LARGEST!) |

## Hit/Combat Event Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::hit::HitNotificationEventOneFrameComponent | 0x50 | 80 | Hit notification |
| eoc::hit::HitNotificationRequestOneFrameComponent | 0x48 | 72 | Hit request |
| eoc::hit::HitResultEventOneFrameComponent | 0x1e8 | 488 | Hit result (large!) |
| eoc::hit::CancelRequestOneFrameComponent | 0x01 | 1 | Tag - cancel |
| eoc::hit::ConditionalRollAdjustmentOneFrameComponent | 0x88 | 136 | Roll adjustment |

## FTB/Combat Turn Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ftb::JoinInCurrentRoundOneFrameComponent | 0x01 | 1 | Tag - join round |
| eoc::combat::FleeingCombatComponent | 0x08 | 8 | Fleeing state |

## Reward Components (eoc::reward::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::reward::FillRewardInventoriesRequestComponent | 0x80 | 128 | Fill inventories |
| eoc::reward::GiveRewardRequestComponent | 0x10 | 16 | Give reward |
| eoc::reward::TransferRewardsRequestComponent | 0x40 | 64 | Transfer rewards |

## Tracking Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::tracking::RequestTargetTrackingOneFrameComponent | 0x40 | 64 | Target tracking |

## Extended Death Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::death::DiedEventOneFrameComponent | 0x01 | 1 | Tag - died event |
| eoc::death::ModifyDelayDeathRequestOneFrameComponent | 0x10 | 16 | Delay death request |

## Group Components (eoc::group::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::group::GroupRequestCompletedComponent | 0x01 | 1 | Tag - request complete |
| eoc::group::HasStragglersComponent | 0x01 | 1 | Tag - has stragglers |

## Party Components (eoc::party:: - extended)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::party::RestorePartyEventOneFrameComponent | 0x10 | 16 | Restore party |

## Definition/Session Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::character::CharacterDefinitionComponent | 0x290 | 656 | Character definition (large!) |
| eoc::character::DefinitionCommonComponent | 0xc0 | 192 | Common definition |
| eoc::character::SessionCommonComponent | 0x0c | 12 | Session common |
| eoc::character::AppearanceComponent | 0x70 | 112 | Appearance data |
| eoc::character::MoveComponent | 0x10 | 16 | Move state |

## Analytics Components (eoc::analytics::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::analytics::EventApprovalRatingComponent | 0x40 | 64 | Approval rating event |
| eoc::analytics::EventCombatStartedComponent | 0x58 | 88 | Combat started event |
| eoc::analytics::EventCombatTurnComponent | 0x60 | 96 | Combat turn event |
| eoc::analytics::EventDisturbanceInvestigatedComponent | 0x18 | 24 | Disturbance investigated |
| eoc::analytics::EventDisturbanceResolvedComponent | 0x18 | 24 | Disturbance resolved |
| eoc::analytics::EventDisturbanceStartedComponent | 0x18 | 24 | Disturbance started |
| eoc::analytics::EventFTBStartedComponent | 0x20 | 32 | FTB started event |
| eoc::analytics::EventGlobalFlagSetComponent | 0x18 | 24 | Global flag set |
| eoc::analytics::EventGoalAchievedComponent | 0x20 | 32 | Goal achieved |
| eoc::analytics::EventGoldChangedComponent | 0x10 | 16 | Gold changed |
| eoc::analytics::EventInterruptUsedComponent | 0x20 | 32 | Interrupt used |
| eoc::analytics::EventInventoryAddedComponent | 0x40 | 64 | Inventory added |

## AI Components (eoc::ai::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ai::combat::RequestCameraMoveComponent | 0x08 | 8 | Camera move request - Vector2f position |
| eoc::ai::swarm::ActiveComponent | 0x01 | 1 | Tag - swarm active (empty component) |
| eoc::ai::swarm::DebugSelectedComponent | 0x18 | 24 | Debug selected - 4-byte ID + DynamicArray (node pool) |
| eoc::ai::swarm::DebugTurnActionsComponent | 0x130 | 304 | Debug turn actions (large!) - full turn state with target GUID, spell IDs, action state, calculation state |
| eoc::ai::swarm::ExecutingActionComponent | 0x01 | 1 | Tag - executing action (empty component) |
| eoc::ai::swarm::MemberComponent | 0x04 | 4 | Swarm member ID - 4-byte group/swarm handle with NodePool release |
| eoc::ai::swarm::RequestCameraFollowGroupComponent | 0x10 | 16 | Camera follow request - DynamicArray of entity GUIDs |

## Active Roll Components (eoc::active_roll::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::active_roll::InProgressComponent | 0x01 | 1 | Tag - roll in progress |
| eoc::active_roll::ModifiersComponent | 0x90 | 144 | Roll modifiers |

## Calendar Components (eoc::calendar::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::calendar::DaysPassedComponent | 0x04 | 4 | Days passed counter |
| eoc::calendar::StartingDateComponent | 0x08 | 8 | Starting date |

## Sneak Components (eoc::sneak::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::sneak::IsSneakingComponent | 0x01 | 1 | Tag - is sneaking |
| eoc::sneak::RollsContainerComponent | 0x18 | 24 | Sneak rolls container |

## Stats Proficiency Components (eoc::stats::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::stats::AreaLevelComponent | 0x04 | 4 | Area level |
| eoc::stats::MusicalInstrumentComponent | 0x01 | 1 | Tag - musical instrument |
| eoc::stats::proficiency::IntrinsicallyProficientWielderComponent | 0x18 | 24 | Intrinsic proficiency |
| eoc::stats::proficiency::ProficiencyComponent | 0x08 | 8 | Proficiency data |
| eoc::stats::proficiency::ProficiencyGroupComponent | 0x08 | 8 | Proficiency group |

## Ambush Components (eoc::ambush::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ambush::AmbushingComponent | 0x01 | 1 | Tag - ambushing |

## Analytics Components (eoc::analytics::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::analytics::EventItemUseComponent | 0x18 | 24 | Item usage tracking |
| eoc::analytics::EventLevelUpEndedComponent | 0x68 | 104 | Level up analytics |
| eoc::analytics::EventOsirisComponent | 0x28 | 40 | Osiris event tracking |
| eoc::analytics::EventRestTypeAndSuppliesChosenComponent | 0x38 | 56 | Rest choice analytics |
| eoc::analytics::EventRollComponent | 0x30 | 48 | Roll tracking |
| eoc::analytics::EventSaveGameErrorComponent | 0x10 | 16 | Save error tracking |
| eoc::analytics::EventSpellUseComponent | 0x80 | 128 | Spell usage (largest analytics!) |

## Falling Components (eoc::falling::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::falling::IsFallingComponent | 0x01 | 1 | Tag - is falling |

## Floor Components (eoc::floor::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::floor::InfoComponent | 0x20 | 32 | Floor information |

## FTB Components (eoc::ftb::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ftb::IsInFtbComponent | 0x01 | 1 | Tag - in FTB |
| eoc::ftb::ParticipantComponent | 0x08 | 8 | FTB participant |
| eoc::ftb::RespectComponent | 0x01 | 1 | Tag - FTB respect |
| eoc::ftb::ZoneBlockReasonComponent | 0x01 | 1 | Tag - zone block reason |

## Game Components (eoc::game::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::game::PauseComponent | 0x01 | 1 | Tag - game paused |

## God Components (eoc::god::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::god::GodComponent | 0x28 | 40 | Deity/God data |

## Heal Components (eoc::heal::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::heal::BlockComponent | 0x01 | 1 | Tag - heal blocked |
| eoc::heal::MaxIncomingComponent | 0x01 | 1 | Tag - max incoming |
| eoc::heal::MaxOutgoingComponent | 0x01 | 1 | Tag - max outgoing |

## Identity Components (eoc::identity::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::identity::IdentityComponent | 0x01 | 1 | Tag - identity |
| eoc::identity::OriginalIdentityComponent | 0x01 | 1 | Tag - original identity |
| eoc::identity::StateComponent | 0x01 | 1 | Tag - identity state |

## Improvised Weapon Components (eoc::improvised_weapon::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::improvised_weapon::CanBeWieldedComponent | 0x01 | 1 | Tag - can be wielded |
| eoc::improvised_weapon::WieldedComponent | 0x10 | 16 | Wielded weapon data |
| eoc::improvised_weapon::WieldingComponent | 0x08 | 8 | Wielding entity ref |

## Platform Components (eoc::platform::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::platform::MoveToTargetProgressComponent | 0x0c | 12 | Move progress |
| eoc::platform::MovementComponent | 0x10 | 16 | Platform movement |
| eoc::platform::MovementPausedComponent | 0x01 | 1 | Tag - movement paused |
| eoc::platform::PassengerComponent | 0x30 | 48 | Passenger data |
| eoc::platform::PlatformComponent | 0x48 | 72 | Platform state |
| eoc::platform::RepresentativeComponent | 0x08 | 8 | Representative ref |

## Portrait Painting Components (eoc::portrait_painting::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::portrait_painting::DataComponent | 0x58 | 88 | Portrait data |

## Projectile Components (eoc::projectile::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::projectile::SourceInfoComponent | 0x40 | 64 | Projectile source |

## Splatter Components (eoc::splatter::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::splatter::StateComponent | 0x1c | 28 | Splatter state |

## Timeline Components (eoc::timeline::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::timeline::ActorVisualDataComponent | 0x08 | 8 | Actor visual data |
| eoc::timeline::HideEquipmentComponent | 0x01 | 1 | Tag - hide equipment |
| eoc::timeline::steering::TimelineSteeringComponent | 0x78 | 120 | Timeline steering |

## Item Template Components (eoc::item_template::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::item_template::ActionTypeComponent | 0x30 | 48 | Action type with hash |
| eoc::item_template::CanMoveComponent | 0x01 | 1 | Tag - can move |
| eoc::item_template::ClimbOnComponent | 0x01 | 1 | Tag - climbable |
| eoc::item_template::DestroyedComponent | 0x01 | 1 | Tag - destroyed |
| eoc::item_template::InteractionDisabledComponent | 0x01 | 1 | Tag - no interaction |
| eoc::item_template::IsStoryItemComponent | 0x01 | 1 | Tag - story item |
| eoc::item_template::LadderComponent | 0x01 | 1 | Tag - ladder |

## Photo Mode Components (eoc::photo_mode::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::photo_mode::CameraTransformComponent | 0x28 | 40 | Camera transform |
| eoc::photo_mode::DummyAnimationStateComponent | 0x18 | 24 | Dummy anim state |
| eoc::photo_mode::DummyComponent | 0x10 | 16 | Photo mode dummy |

## Aigrid Components (eoc::aigrid::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::aigrid::AiGridLoadedOneFrameComponent | 0x01 | 1 | OneFrame - grid loaded |
| eoc::aigrid::RefreshAllLayersOneFrameRequestComponent | 0x01 | 1 | OneFrame - refresh layers |
| eoc::aigrid::SubgridProximityListChangedEventOneFrameComponent | 0x60 | 96 | OneFrame - subgrid change |

## Hit Components (eoc::hit::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::hit::LifetimeComponent | 0x08 | 8 | Hit lifetime |
| eoc::hit::MetaComponent | 0x10 | 16 | Hit metadata |

## Lock Components (eoc::lock::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::lock::KeyComponent | 0x04 | 4 | Key ID |
| eoc::lock::LockComponent | 0x28 | 40 | Lock state |

## Movement Components (eoc::movement::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::movement::DashingComponent | 0x1c | 28 | Dashing state |

## Spell Cast Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell_cast::AnimationRequestOneFrameComponent | 0x30 | 48 | Single-frame animation request |
| eoc::spell_cast::CastTextKeyEventOneFrameComponent | 0x10 | 16 | Spell cast text key event |
| eoc::spell_cast::CounteredEventOneFrameComponent | 0x01 | 1 | Spell countered event flag |
| eoc::spell_cast::DestroyEventOneFrameComponent | 0x10 | 16 | Spell cast destroy event |
| eoc::spell_cast::ExecutionTimeComponent | 0x08 | 8 | Spell execution timestamp |
| eoc::spell_cast::FinishedEventOneFrameComponent | 0x02 | 2 | Spell finished event flag |
| eoc::spell_cast::IsCastingComponent | 0x08 | 8 | Active casting indicator |
| eoc::spell_cast::LogicExecutionEndEventOneFrameComponent | 0x01 | 1 | Logic execution end event |
| eoc::spell_cast::LogicExecutionStartEventOneFrameComponent | 0x01 | 1 | Logic execution start event |
| eoc::spell_cast::PrepareEndEventOneFrameComponent | 0x01 | 1 | Prepare phase end event |
| eoc::spell_cast::PrepareStartEventOneFrameComponent | 0x01 | 1 | Prepare phase start event |
| eoc::spell_cast::TargetsChangedEventOneFrameComponent | 0x10 | 16 | Target list change event |

## Spell Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::spell::SpellInvalidationLockedComponent | 0x01 | 1 | Spell invalidation lock flag |

## Notification Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::notification::UnsheathUserRequestFailedComponent | 0x10 | 16 | Unsheath request failure tracking |

## Splatter Components (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::splatter::UpdateAttachmetsRequestOneFrameComponent | 0x01 | 1 | Attachment update request |
| eoc::splatter::ValueChangedOneFrameComponent | 0x04 | 4 | Splatter value change |

## Status Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::status::ExternalStatusBackupComponent | 0x30 | 48 | External status backup data |

## Thrown Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::thrown::ThrownAnimationRequestOneFrameComponent | 0x08 | 8 | Thrown weapon animation request |

## Timeline Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::SyncedTimelineActorControlComponent | 0x28 | 40 | Timeline actor control data |
| eoc::SyncedTimelineControlComponent | 0xf8 | 248 | Large timeline control structure |

## Turn/Combat Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::TurnBasedComponent | 0x30 | 48 | Turn-based combat data |
| eoc::TurnOrderComponent | 0x50 | 80 | Turn order tracking |
| eoc::TrackedSoundEntityComponent | 0x04 | 4 | Sound entity ID reference |
| eoc::ValueComponent | 0x08 | 8 | Simple value storage |

## Core Components Extended (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::HealthComponent | 0x28 | 40 | Health data structure |
| eoc::HearingComponent | 0x04 | 4 | Hearing range/data |
| eoc::IconComponent | 0x04 | 4 | Icon reference/handle |
| eoc::WeaponComponent | 0x50 | 80 | Weapon data with damage maps |
| eoc::WeaponSetComponent | 0x01 | 1 | Weapon set ID |

## Statistics

- **Total namespaced components:** 520
- **Namespaces covered:** 115
- **Largest:** eoc::BoostsComponent (832 bytes), eoc::character_creation::CharacterCreatedComponent (992 bytes)
- **OneFrame pattern:** 70+ components use OneFrameComponent for event-driven updates
- **Key namespaces:** item (30), spell_cast (33), notification (24), inventory (18), analytics (19), party (9), interrupt (10), animation (9), gamestate (9), camp (8), platform (6), character_creation (6), photo_mode (3), splatter (2)
