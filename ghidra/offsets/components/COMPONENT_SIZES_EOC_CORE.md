# eoc::core:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ActionResourcesComponent | 0x40 | 64 | Action points, resources |
| eoc::ActiveComponent | 0x01 | 1 | Active entity tag |
| eoc::ArmorComponent | 0x10 | 16 | AC |
| eoc::AttributeFlagsComponent | 0x04 | 4 | Attribute flags |
| eoc::BackgroundComponent | 0x10 | 16 | Background |
| eoc::BaseHpComponent | 0x08 | 8 | Base hit points |
| eoc::BaseStatsComponent | 0x1c | 28 | Base stats (STR/DEX/etc) |
| eoc::BodyTypeComponent | 0x02 | 2 | Body type enum |
| eoc::BoostConditionComponent | 0x08 | 8 | Condition ref |
| eoc::BoostInfoComponent | 0x58 | 88 | Boost metadata |
| eoc::BoostsComponent | 0x340 | 832 | All boosts container (LARGEST!) |
| eoc::BoostsContainerComponent | 0x10 | 16 | Container array |
| eoc::BoundComponent | 0x08 | 8 | Ptr to 0x90 heap |
| eoc::CanBeDisarmedComponent | 0x02 | 2 | Disarm flag |
| eoc::CanBeLootedComponent | 0x02 | 2 | Loot flag |
| eoc::CanDeflectProjectilesComponent | 0x02 | 2 | Deflect flag |
| eoc::CanDoActionsComponent | 0x02 | 2 | Can act flag |
| eoc::CanDoRestComponent | 0x06 | 6 | Rest flag |
| eoc::CanInteractComponent | 0x04 | 4 | Interact flag |
| eoc::CanModifyHealthComponent | 0x02 | 2 | Health mod flag |
| eoc::CanMoveComponent | 0x06 | 6 | Movement flag |
| eoc::CanSenseComponent | 0x02 | 2 | Sensing flag |
| eoc::CanSpeakComponent | 0x02 | 2 | Can speak flag |
| eoc::CanTravelComponent | 0x06 | 6 | Travel flag |
| eoc::CanTriggerRandomCastsComponent | 0x01 | 1 | Tag - wild magic |
| eoc::CharacterCreationStatsComponent | 0x58 | 88 | Character creation |
| eoc::ClassTagComponent | 16 | 0x10 | GetComponent<eoc::ClassTagComponent,false> |
| eoc::ClassesComponent | 0x10 | 16 | Class info array |
| eoc::ClientControlComponent | 0x01 | 1 | Client control flag |
| eoc::ClimbingComponent | 0x34 | 52 | Climbing state |
| eoc::CombinedLightComponent | 0x40 | 64 | Light combo |
| eoc::CustomIconComponent | 0x60 | 96 | Custom icon data |
| eoc::CustomIconsStorageSingletonComponent | 0x40 | 64 | Icon storage singleton |
| eoc::CustomNameComponent | 0x10 | 16 | Custom name string |
| eoc::CustomStatsComponent | 0x18 | 24 | Custom stats map |
| eoc::DarknessComponent | 0x10 | 16 | Darkness state |
| eoc::DataComponent | 0x0c | 12 | Generic data |
| eoc::DeadReckoningComponent | 0x10 | 16 | Network prediction |
| eoc::DeadReckoningSyncComponent | 0x14 | 20 | Network sync |
| eoc::DetachedComponent | 0x04 | 4 | Detached state |
| eoc::DifficultyCheckComponent | 0x48 | 72 | DC checks (HashTable) |
| eoc::DisabledEquipmentComponent | 0x01 | 1 | Tag - disabled equip |
| eoc::DisarmableComponent | 0x18 | 24 | Disarmable (GUID) |
| eoc::DisplayNameComponent | 0x20 | 32 | Display name (TranslatedString) |
| eoc::DualWieldingComponent | 0x07 | 7 | Dual-wield state |
| eoc::EquipableComponent | 0x18 | 24 | Equipable (GUID+slot) |
| eoc::FleeCapabilityComponent | 0x0c | 12 | Flee capability |
| eoc::FloatingComponent | 8 | GetComponent/AddComponent | `<< 3` = 8 bytes |
| eoc::FogVolumeRequestComponent | 0x10 | 16 | Fog volume request |
| eoc::GameObjectVisualComponent | 0x14 | 20 | GameObject visual data |
| eoc::GameOverComponent | - | - | Not extracted |
| eoc::GameplayLightComponent | - | - | Not extracted |
| eoc::GlobalLongRestDisabledComponent | 0x01 | 1 | Tag - long rest disabled |
| eoc::GlobalShortRestDisabledComponent | 0x01 | 1 | Tag - short rest disabled |
| eoc::GravityActiveComponent | 0x08 | 8 | Active gravity |
| eoc::GravityDisabledComponent | 0x01 | 1 | Tag - gravity disabled |
| eoc::GravityDisabledUntilMovedComponent | 0x28 | 40 | Gravity disabled until moved |
| eoc::HealthComponent | 0x28 | 40 | HP/temp HP |
| eoc::HearingComponent | 0x04 | 4 | Hearing range |
| eoc::IconComponent | 0x4 | 4 | Icon reference/handle |
| eoc::InteractionFilterComponent | - | - | Not extracted |
| eoc::InvisibilityComponent | 0x14 | 20 | Invisibility state |
| eoc::IsInTurnBasedModeComponent | 0x01 | 1 | Tag - in turn-based mode |
| eoc::ItemBoostsComponent | - | - | Stores boost refs |
| eoc::LevelComponent | 0x04 | 4 | Character level |
| eoc::LootComponent | 0x02 | 2 | Loot flags |
| eoc::LootingStateComponent | 0x10 | 16 | Looting state |
| eoc::MaterialParameterOverrideComponent | 0x20 | 32 | Material override |
| eoc::MovementComponent | 0x18 | 24 | Movement state |
| eoc::ObjectInteractionComponent | 0x10 | 16 | AddComponent<eoc::ObjectInteractionComponent> |
| eoc::ObjectSizeComponent | 2 (0x2) | AddComponent<eoc::ObjectSizeComponent> | 2x int8_t = 2 bytes |
| eoc::OffStageComponent | 0x01 | 1 | Tag - off stage |
| eoc::OriginAppearanceTagComponent | 16 (0x10) | GetComponent via `<< 4` | Array<Guid> = 16 bytes |
| eoc::OriginComponent | 0x18 | 24 | Origin story |
| eoc::OriginPassivesComponent | 16 (0x10) | Struct analysis | Array<ptr> = 16 bytes |
| eoc::OriginTagComponent | 16 (0x10) | GetComponent via `<< 4` | Array<Guid> = 16 bytes |
| eoc::PassiveComponent | 0x20 | 32 | Passive ability |
| eoc::PassiveContainerComponent | 0x10 | 16 | Passive abilities |
| eoc::PathingComponent | 0x50 | 80 | AddComponent<eoc::PathingComponent> |
| eoc::PickingStateComponent | 0x1 | 1 | AddComponent<eoc::PickingStateComponent> |
| eoc::PlayerComponent | 0x01 | 1 | Tag - is player |
| eoc::ProgressionContainerComponent | 0x10 | 16 | Container |
| eoc::RaceComponent | 0x10 | 16 | Race data |
| eoc::RequestedRollComponent | 0x1e0 | 480 | Requested roll (large!) |
| eoc::ResistancesComponent | - | - | Not extracted |
| eoc::ServerRootLevelLoadedComponent | - | - | Not extracted |
| eoc::ServerRootLevelStartDialogComponent | 0x01 | 1 | Tag - dialog starter |
| eoc::SimpleCharacterComponent | - | - | Not extracted |
| eoc::SpeakerComponent | 0x10 | 16 | Dialog speaker |
| eoc::StatsComponent | 0xa0 | 160 | Core stats |
| eoc::StatusImmunitiesComponent | - | - | Not extracted |
| eoc::StealthComponent | 0x24 | 36 | Stealth state |
| eoc::SteeringComponent | 0x20 | 32 | Movement steering |
| eoc::StoryShortRestDisabledComponent | 0x01 | 1 | Tag - story rest disabled |
| eoc::SurfacePathInfluencesComponent | - | - | Not extracted |
| eoc::SyncedTimelineActorControlComponent | 0x28 | 40 | Timeline actor control data |
| eoc::SyncedTimelineControlComponent | 0xf8 | 248 | Large timeline control structure |
| eoc::TagComponent | 0x10 | 16 | Entity tags |
| eoc::TimelineActorDataComponent | 40 | 0x28 | GetComponent (* 0x28) |
| eoc::TimelineDataComponent | 0xa8 | 168 |  |
| eoc::TrackedSoundEntityComponent | 0x04 | 4 | Sound entity handle |
| eoc::TurnBasedComponent | 0x30 | 48 | Turn-based state |
| eoc::TurnOrderComponent | 0x50 | 80 | Initiative order |
| eoc::UseBoostsComponent | 0x10 | 16 | Boost descriptions array |
| eoc::UseComponent | 0x50 | 80 | Usable items |
| eoc::ValueComponent | 0x8 | 8 | Simple value storage |
| eoc::VoiceComponent | 0x10 | 16 | Voice data |
| eoc::VoiceTagComponent | 0x10 | 16 | Voice tag |
| eoc::WeaponComponent | 0x50 | 80 | Weapon data |
| eoc::WeaponSetChangedEventOneFrameComponent | 0x02 | 2 | OneFrame event |
| eoc::WeaponSetComponent | 0x1 | 1 | Weapon set ID |
| eoc::WieldingComponent | 8 (via `<< 3`) |  |  |

**Total: 112 components**
