# Larian Shared (ls::) Components - ARM64 Sizes

Engine-level components shared between client and server.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Transform/Spatial

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::TransformComponent | 0x28 | 40 | Transform (pos/rot/scale) |
| ls::CopyParentVisibilityComponent | 0x08 | 8 | Parent visibility ref |
| ls::IsGlobalComponent | 0x01 | 1 | Tag - global entity |

## Animation

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::ActiveSkeletonSlotsComponent | 0x10 | 16 | Skeleton slots (DynamicArray) |
| ls::AnimationBlueprintComponent | 0x08 | 8 | Animation blueprint ptr |
| ls::AnimationSetComponent | 0x08 | 8 | Animation set ptr |
| ls::AnimationUpdateComponent | 0x01 | 1 | Tag - animation update |
| ls::animation::AnimationSetUpdateRequestComponent | 0x01 | 1 | Tag - set update request |
| ls::animation::DynamicAnimationTagsComponent | 0x10 | 16 | Dynamic animation tags |
| ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent | 0x10 | 16 | Load request |
| ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent | 0x30 | 48 | Remove request |
| ls::animation::TemplateAnimationSetOverrideComponent | 0x10 | 16 | Template override |

## Rendering/Visual

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::VisualComponent | 0x10 | 16 | Core visual component |
| ls::VisualChangedEventOneFrameComponent | 0x01 | 1 | Tag - visual changed |
| ls::VisualLoadDesciptionComponent | 0x08 | 8 | Load description |
| ls::VisualLoadedComponent | 0x01 | 1 | Tag - visual loaded |
| ls::VisualStreamComponent | 0x10 | 16 | Stream component |
| ls::VisualStreamHintComponent | 0x04 | 4 | Streaming hint |
| ls::VisualStreamLoadComponent | 0x08 | 8 | Stream load |
| ls::CullComponent | 0x02 | 2 | Culling flags |
| ls::DecalComponent | 0x08 | 8 | Decal pointer |
| ls::HiZComponent | 0x10 | 16 | Hierarchical Z-buffer |
| ls::HLODChildComponent | 0x08 | 8 | HLOD child ref |

## Physics

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::PhysicsComponent | 0x18 | 24 | Basic physics |
| ls::PhysicsSkinnedConnectedToComponent | 0x30 | 48 | Skinned physics connection |
| ls::PhysicsSkinnedConnectionComponent | 0x30 | 48 | Skinned connection details |
| ls::StaticLevelPhysicsComponent | 0x08 | 8 | Static physics ref |

## Effects/Environment

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::AlwaysUpdateEffectComponent | 0x01 | 1 | Tag - always update |
| ls::EffectComponent | 0x08 | 8 | Effect pointer |
| ls::EffectCreateOneFrameComponent | 0x01 | 1 | Tag - effect create |
| ls::FogVolumeComponent | 0x08 | 8 | Fog volume ptr |
| ls::GameplaySoundSetupRequestOneFrameComponent | 0x40 | 64 | Sound setup request |
| ls::OcclusionComponent | 0x08 | 8 | Occlusion data |
| ls::TerrainLoadComponent | 0x10 | 16 | Terrain loading |
| ls::LocalBoundComponent | 0x18 | 24 | Local bounds |

## Sound Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::SoundComponent | 0x20 | 32 | Sound component |
| ls::SoundRoomNeighborStateComponent | 0x20 | 32 | Sound room neighbor state |

## Level Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::LevelComponent | 0x10 | 16 | Level reference |
| ls::LevelInstanceComponent | 0x40 | 64 | Level instance data |
| ls::LevelInstanceLoadComponent | 0x01 | 1 | Tag - instance loading |
| ls::LevelRootComponent | 0x04 | 4 | Level root handle |
| ls::level::LevelInstanceLoadStateComponent | 0x01 | 1 | Tag - load state |

## Light Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::LightComponent | 0x110 | 272 | Light data (large!) |
| ls::LightFlickerComponent | 0x0c | 12 | Flicker params |
| ls::LightMovementComponent | 0x0c | 12 | Movement params |
| ls::LightProbeComponent | 0xe8 | 232 | Light probe (large!) |
| ls::OrthoCameraBehavior | 0x28 | 40 | Ortho camera |
| ls::FogVolumeComponent | 0x128 | 296 | Fog volume (largest ls!) |

## Clustering/Instancing

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::ClusterComponent | 0x01 | 1 | Tag - cluster member |
| ls::ClusterContentComponent | 0x30 | 48 | Cluster content data |
| ls::ClusterCullDataComponent | 0x08 | 8 | Cull data |
| ls::ClusterDistMaxComponent | 0x04 | 4 | Max distance |
| ls::ClusterDistMinComponent | 0x04 | 4 | Min distance |
| ls::ClusterPositionXComponent | 0x04 | 4 | Position X |
| ls::ClusterPositionYComponent | 0x04 | 4 | Position Y |
| ls::ClusterPositionZComponent | 0x04 | 4 | Position Z |
| ls::ClusterRadiusComponent | 0x04 | 4 | Radius |
| ls::InstancingBatchComponent | 0x30 | 48 | Batch data |
| ls::InstancingBatchLoadComponent | 0x08 | 8 | Batch load |
| ls::InstancingGroupComponent | 0x68 | 104 | Group data (large!) |

## Transform Sub-namespace (ls::transform::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::transform::GameplaySetTransformRequestsComponent | 0x80 | 128 | Transform requests |
| ls::transform::InventoryMemberSetTransformRequestComponent | 0x40 | 64 | Inventory transform |

## Trigger Sub-namespace (ls::trigger::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::trigger::UpdatedPhysicsComponent | 0x10 | 16 | Physics update |

## UUID Sub-namespace (ls::uuid::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::uuid::Component | 0x10 | 16 | UUID (GUID) |
| ls::uuid::ToHandleMappingComponent | 0x40 | 64 | Handle mapping |

## Anubis Sub-namespace (ls::anubis::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::anubis::EnabledComponent | 0x01 | 1 | Tag - enabled |
| ls::anubis::FrameworkReloadedOneFrameComponent | 0x01 | 1 | Tag - reloaded |
| ls::anubis::savegame::StateComponent | 0x88 | 136 | Savegame state |

## Debug

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::DebugComponent | 0x10 | 16 | Debug info |

## Save Sub-namespace (ls::save::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::save::SaveStateComponent | 0x38 | 56 | Save state |

## Scene Sub-namespace (ls::scene::)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::scene::NextSceneStageOneFrameComponent | 0x01 | 1 | Tag - next scene stage |
| ls::scene::SceneStageComponent | 0x04 | 4 | Scene stage |

## Additional Core Components

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::ActiveSkeletonSlotsComponent | 0x10 | 16 | Skeleton slots |
| ls::AlwaysUpdateEffectComponent | 0x01 | 1 | Tag - always update |
| ls::AnimationSetComponent | 0x08 | 8 | Animation set ptr |
| ls::AnimationUpdateComponent | 0x01 | 1 | Tag - anim update |
| ls::ArcBallCameraBehavior | 0x24 | 36 | Arc ball camera |
| ls::CameraComponent | 0xb0 | 176 | Camera (large!) |
| ls::ClothTeleportDataComponent | 0x08 | 8 | Cloth teleport |
| ls::Construction | 0x08 | 8 | Construction ptr |
| ls::ConstructionFilling | 0x08 | 8 | Construction fill |
| ls::ConstructionTile | 0x08 | 8 | Construction tile |
| ls::ConstructionTileBoneTransformSetComponent | 0x10 | 16 | Tile bone transform |
| ls::CullComponent | 0x02 | 2 | Cull flags |
| ls::CullTriggerPlanesComponent | 0x70 | 112 | Cull planes (large!) |
| ls::DecalComponent | 0x08 | 8 | Decal ptr |

## Cluster Extended (from staging)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::ClusterBoundComponent | 0x18 | 24 | Cluster bounding data |
| ls::ClusterBoundMaxComponent | 0x04 | 4 | Cluster maximum bound |
| ls::ClusterChildChangedOneFrameComponent | 0x10 | 16 | Cluster child change event |
| ls::ClusterChildComponent | 0x08 | 8 | Cluster child reference |
| ls::ClusterAttachRequestComponent | 0x01 | 1 | Cluster attach request flag |

## Physics Extended (from staging)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::PhysicsLoadComponent | 0x18 | 24 | Physics load state with flags |
| ls::PhysicsLoadedComponent | 0x01 | 1 | Load completion tag |
| ls::PhysicsPathLoadDesciptionComponent | 0x18 | 24 | STDString path |
| ls::PhysicsResourceLoadDesciptionComponent | 0x08 | 8 | Resource ID + flags |
| ls::PhysicsStreamLoadComponent | 0x01 | 1 | Stream load tag |
| ls::LightProbeLoadComponent | 0x08 | 8 | Light probe load state |

## Level Extended (from staging)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::LevelInstanceStateComponent | 0xD0 | 208 | Complex state data (large!) |
| ls::LevelIsOwnerComponent | 0x01 | 1 | Tag component |
| ls::LevelUnloadedOneFrameComponent | 0x04 | 4 | OneFrame with ID |

## Save/Scene Extended (from staging)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::SaveWithComponent | 0x08 | 8 | EntityRef for save grouping |
| ls::SavegameComponent | 0x01 | 1 | Tag component |
| ls::SceneAttachComponent | 0x08 | 8 | Scene pointer |
| ls::SeeThroughStateComponent | 0x40 | 64 | Multi-vector state |

## Statistics

- **Total ls:: components:** 106
- **Smallest:** ClusterComponent, EffectCreateOneFrameComponent, multiple tags (1 byte)
- **Largest:** LevelInstanceStateComponent (208 bytes), FogVolumeComponent (296 bytes), LightComponent (272 bytes)
- **Pattern:** Engine components use pointers for large data, inline for small fixed-size data
- **Sub-namespaces:** animation, transform, trigger, uuid, anubis, level, save, scene, sound
