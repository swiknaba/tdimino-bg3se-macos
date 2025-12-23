# Client (ecl::) Components - ARM64 Sizes

Client-side components for rendering and UI.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Core Entities

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::Character | 0x158 | 344 | Character (inline) |
| ecl::Item | 0x70 | 112 | Item (inline) |
| ecl::Projectile | 0x240 | 576 | Projectile (largest!) |
| ecl::Scenery | 0x40 | 64 | Scenery (inline) |

## UI/Visual

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::EquipmentVisualsComponent | 0x48 | 72 | Equipment visuals |
| ecl::PaperdollComponent | 0x10 | 16 | Paperdoll UI |

## Timeline/Cutscene

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::ClientTimelineActorControlComponent | 0x28 | 40 | Timeline control |

## Triggers

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::AiSeederTrigger | 0x78 | 120 | AI seeder trigger |
| ecl::AtmosphereTrigger | 0x90 | 144 | Atmosphere trigger |
| ecl::CameraBlockerTrigger | 0x78 | 120 | Camera blocker |
| ecl::CameraLockTrigger | 0x80 | 128 | Camera lock |
| ecl::CinematicArenaTrigger | 0xb0 | 176 | Cinematic arena |
| ecl::CullTrigger | 0x78 | 120 | Cull trigger |
| ecl::FadeTrigger | 0x80 | 128 | Fade trigger |
| ecl::FloorTrigger | 0x80 | 128 | Floor trigger |
| ecl::LightingTrigger | 0x90 | 144 | Lighting trigger |
| ecl::NavigationCloudTrigger | 0x78 | 120 | Navigation cloud |
| ecl::PointSoundTrigger | 0xa8 | 168 | Point sound trigger |

## Camera

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::camera::CombatTargetComponent | 0x18 | 24 | Combat target |
| ecl::camera::CombatTargetRequestsComponent | 0x30 | 48 | Combat target requests |
| ecl::EocCameraBehavior | 0x40 | 64 | EOC camera behavior |
| ecl::GameCameraBehavior | 0x258 | 600 | Game camera (largest ecl!) |

## Character UI

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::CharacterIconResultComponent | 0x58 | 88 | Character icon result |
| ecl::CharacterLightComponent | 0x18 | 24 | Character lighting |
| ecl::MeshPreviewComponent | 0x58 | 88 | Mesh preview |

## Character Creation (ecl::character_creation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::character_creation::DefinitionStateComponent | 0xc8 | 200 | Definition state |
| ecl::character_creation::DummyDefinitionComponent | 0x1b0 | 432 | Dummy definition (large!) |

## Death (ecl::death::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::DeathDetachEffectRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::DeathEffectComponent | 0x08 | 8 | Ptr to 0x120 heap alloc |
| ecl::death::DeathImpactComponent | 0x18 | 24 | Death impact |
| ecl::death::SetVisualImmediateRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::death::StateComponent | 0x10 | 16 | Death state |

## Hit (ecl::hit::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::hit::HitVFXComponent | 0x240 | 576 | Hit VFX (large - malloc alloc) |

## Projectile (ecl::projectile::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::projectile::AttachmentComponent | 0x08 | 8 | Projectile attachment ref |

## Effect (ecl::effect::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::effect::DistributorTrackerComponent | 0x88 | 136 | Distributor tracker |
| ecl::effect::InfluenceTrackerComponent | 0x60 | 96 | Influence tracker |
| ecl::effect::InteractionEventOneFrameComponent | 0x28 | 40 | Interaction event |
| ecl::effect::SharedTimerComponent | 0x18 | 24 | Shared timer |
| ecl::effect::HandlerComponent | 0x08 | 8 | Effect handler ptr |
| ecl::effect::SpawnedComponent | 0x18 | 24 | Spawned effect |
| ecl::InvisibilityAttachmentComponent | 0x01 | 1 | Tag |
| ecl::ServerControlledEffectDestroyRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |
| ecl::ServerControlledEffectForgetRequestOneFrameComponent | 0x01 | 1 | OneFrame tag |

## Sound (ecl::sound::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::sound::CharacterSwitchDataComponent | 0x78 | 120 | Character switch data |
| ecl::sound::DecoratorSwitchDataComponent | 0x30 | 48 | Decorator switch data |
| ecl::sound::ItemSwitchDataComponent | 0x40 | 64 | Item switch data |
| ecl::sound::SoundCacheComponent | 0x28 | 40 | Sound cache |

## Spell Cast (ecl::spell_cast::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::spell_cast::PlaySoundRequestOneFrameComponent | 0x10 | 16 | Play sound request |
| ecl::spell_cast::SetSoundSwitchesRequestOneFrameComponent | 0x10 | 16 | Set sound switches |
| ecl::spell_cast::SoundImpactEventOneFrameComponent | 0x50 | 80 | Sound impact event |

## Relation (ecl::relation::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::relation::RelationChangedEventOneFrameComponent | 0x08 | 8 | Relation changed event |

## Crowds (ecl::crowds::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::crowds::SoundVolumeComponent | 0x38 | 56 | Sound volume |

## FTB (ecl::ftb::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::ftb::BlockedFTBToggleRequestOneFrameComponent | 0x04 | 4 | FTB toggle request |

## Dialog (ecl::dialog::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::dialog::BlockAfterGroupPrepareComponent | 0x01 | 1 | Tag - block after group |
| ecl::dialog::DialogTimelineUpdateStateComponent | 0x04 | 4 | Timeline update state |
| ecl::dialog::IsInDialogComponent | 0x01 | 1 | Tag - in dialog |

## Timeline (ecl::timeline::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::ClientTimelineActorControlComponent | 0x28 | 40 | Timeline control |
| ecl::ClientTimelineControlComponent | 0x88 | 136 | Client timeline control |
| ecl::timeline::VisualFXViewComponent | 0x88 | 136 | Visual FX view |
| ecl::TimelineAnimationStateComponent | 0x08 | 8 | Animation state |
| ecl::TimelineAutomatedLookatComponent | 0x20 | 32 | Automated lookat |
| ecl::TimelineCameraRequestComponent | 0x20 | 32 | Camera request |
| ecl::TimelineEmotionMaterialComponent | 0x90 | 144 | Emotion material (large!) |
| ecl::TimelineEyeLookAtOverrideComponent | 0x30 | 48 | Eye lookat override |
| ecl::TimelineMaterialComponent | 0x80 | 128 | Material component |
| ecl::TimelineShapeShiftComponent | 0x04 | 4 | Shapeshift |
| ecl::TimelineSplatterComponent | 0x24 | 36 | Splatter effect |
| ecl::TimelineSpringsComponent | 0x08 | 8 | Springs data |
| ecl::TimelineSteppingFadeComponent | 0x08 | 8 | Stepping fade |
| ecl::TimelineTransformComponent | 0x118 | 280 | Transform (largest timeline!) |
| ecl::timeline::CameraShotComponent | 0x68 | 104 | Camera shot |
| ecl::timeline::PlayerTransitionEventOneFrameComponent | 0x40 | 64 | Player transition event |
| ecl::timeline::QuestionHoldAutomationComponent | 0x1c | 28 | Question hold automation |
| ecl::timeline::TurnActionsDoneOneFrameComponent | 0x01 | 1 | Turn actions done tag |

## Inventory (ecl::inventory::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::inventory::ExamineInventoryComponent | 0x01 | 1 | Tag - examine inventory |

## Multiplayer (ecl::multiplayer::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::multiplayer::UsersComponent | 0x18 | 24 | Users component |

## Terrain/World

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::TerrainWalkableAreaComponent | 0x50 | 80 | Terrain walkable area |
| ecl::WalkableSurfaceComponent | 0x10 | 16 | Walkable surface |

## Tag Components (ecl:: general)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::tag::SpellCheckedTagComponent | 0x01 | 1 | Tag - spell checked |
| ecl::IgnoredComponent | 0x01 | 1 | Tag - ignored |
| ecl::InSelectComponent | 0x01 | 1 | Tag - in selection |
| ecl::IsHoveredOverComponent | 0x01 | 1 | Tag - hovered |
| ecl::SelectedComponent | 0x01 | 1 | Tag - selected |

## Additional Core Components (ecl::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ecl::DetachedComponent | 0x04 | 4 | Detached state |
| ecl::DifficultyCheckComponent | 0x48 | 72 | Difficulty check |
| ecl::DisabledEquipmentComponent | 0x01 | 1 | Tag - disabled equip |
| ecl::DisarmableComponent | 0x18 | 24 | Disarmable state |
| ecl::DisplayNameComponent | 0x20 | 32 | Display name |
| ecl::MovementComponent | 0x18 | 24 | Movement state |
| ecl::ObjectInteractionComponent | 0x10 | 16 | Object interaction |
| ecl::PathingComponent | 0x50 | 80 | Pathing (largest core) |
| ecl::PickingStateComponent | 0x01 | 1 | Tag - picking state |
| ecl::PlayerComponent | 0x01 | 1 | Tag - player |
| ecl::SyncedTimelineControlComponent | 0xf8 | 248 | Synced timeline control (large!) |
| ecl::TurnBasedComponent | 0x30 | 48 | Turn-based state |
| ecl::UseComponent | 0x50 | 80 | Use interaction data |
| ecl::VoiceComponent | 0x18 | 24 | Voice data |
| ecl::WeaponComponent | 0x50 | 80 | Weapon state |

## Statistics

- **Total ecl:: components:** 99
- **Smallest:** Multiple tag components (1 byte)
- **Largest:** GameCameraBehavior (600 bytes), Projectile (576 bytes), DummyDefinitionComponent (432 bytes)
- **New in Wave 7:** SyncedTimelineControlComponent (248), UseComponent (80), WeaponComponent (80), TurnBasedComponent (48)
- **Pattern:** Client components inline larger structures directly (vs server's pointer pattern)
- **Note:** Triggers range 120-176 bytes; camera components are largest (64-600 bytes)
- **Timeline components:** 18 timeline components (1-280 bytes)
- **OneFrame components:** 12+ event-driven transient components
