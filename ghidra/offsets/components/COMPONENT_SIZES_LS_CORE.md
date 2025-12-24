# ls::core:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::ActiveSkeletonSlotsComponent | 0x10 | 16 | Skeleton slots |
| ls::AlwaysUpdateEffectComponent | 0x01 | 1 | Tag - always update |
| ls::AnimationBlueprintComponent | 0x08 | 8 | Animation blueprint ptr |
| ls::AnimationSetComponent | 0x08 | 8 | Animation set ptr |
| ls::AnimationUpdateComponent | 0x01 | 1 | Tag - anim update |
| ls::ArcBallCameraBehavior | 0x24 | 36 | Arc ball camera |
| ls::CameraComponent | 0xb0 | 176 | Camera (large!) |
| ls::ClothTeleportDataComponent | 0x08 | 8 | Cloth teleport |
| ls::ClusterAttachRequestComponent | 0x01 | 1 | Cluster attach request flag |
| ls::ClusterBoundComponent | 0x18 | 24 | Cluster bounding data |
| ls::ClusterBoundMaxComponent | 0x04 | 4 | Cluster maximum bound |
| ls::ClusterChildChangedOneFrameComponent | 0x10 | 16 | Cluster child change event |
| ls::ClusterChildComponent | 0x08 | 8 | Cluster child reference |
| ls::ClusterComponent | 0x01 | 1 | Tag - cluster member |
| ls::ClusterContentComponent | 0x30 | 48 | Cluster content data |
| ls::ClusterCullDataComponent | 0x08 | 8 | Cull data |
| ls::ClusterDistMaxComponent | 0x04 | 4 | Max distance |
| ls::ClusterDistMinComponent | 0x04 | 4 | Min distance |
| ls::ClusterPositionXComponent | 0x04 | 4 | Position X |
| ls::ClusterPositionYComponent | 0x04 | 4 | Position Y |
| ls::ClusterPositionZComponent | 0x04 | 4 | Position Z |
| ls::ClusterRadiusComponent | 0x04 | 4 | Radius |
| ls::Construction | 0x08 | 8 | Construction ptr |
| ls::ConstructionFilling | 0x08 | 8 | Construction fill |
| ls::ConstructionTile | 0x08 | 8 | Construction tile |
| ls::ConstructionTileBoneTransformSetComponent | 0x10 | 16 | Tile bone transform |
| ls::CopyParentVisibilityComponent | 0x08 | 8 | Parent visibility ref |
| ls::CullComponent | 0x02 | 2 | Cull flags |
| ls::CullTriggerPlanesComponent | 0x70 | 112 | Cull planes (large!) |
| ls::DebugComponent | 0x10 | 16 | Debug info |
| ls::DecalComponent | 0x08 | 8 | Decal ptr |
| ls::DefaultCameraBehavior | 0x1C | 28 | Default camera |
| ls::EditorCameraBehavior | 0x40 | 64 | Editor camera |
| ls::EffectCameraBehavior | 0x0C | 12 | Effect camera |
| ls::EffectComponent | 0x08 | 8 | Effect pointer |
| ls::EffectCreateOneFrameComponent | 0x01 | 1 | Tag - effect create |
| ls::FadeableObstructionComponent | 0x48 | 72 | Obstruction with HashTable |
| ls::FogVolumeComponent | 0x128 | 296 | Fog volume (largest ls!) |
| ls::GameplayEffectSetTimeFactorRequestsSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ls::GameplaySoundSetupRequestOneFrameComponent | 0x40 | 64 | Sound setup request |
| ls::GameplayVFXSetPlayTimeRequestsSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ls::GameplayVFXSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ls::HLODChildComponent | 0x08 | 8 | HLOD child ref |
| ls::HiZComponent | 0x10 | 16 | Hierarchical Z-buffer |
| ls::InstancingBatchComponent | 0x30 | 48 | Batch data |
| ls::InstancingBatchLoadComponent | 0x08 | 8 | Batch load |
| ls::InstancingGroupComponent | 0x68 | 104 | Group data (large!) |
| ls::InvisibleClimbingHelper | 0x08 | 8 | Climbing helper ptr |
| ls::IsGlobalComponent | 0x01 | 1 | Tag - global entity |
| ls::LevelComponent | 0x10 | 16 | Level reference |
| ls::LevelInstanceComponent | 0x40 | 64 | Level instance data |
| ls::LevelInstanceLoadComponent | 0x01 | 1 | Tag - instance loading |
| ls::LevelInstanceStateComponent | 0xD0 | 208 | Complex state data (large!) |
| ls::LevelIsOwnerComponent | 0x01 | 1 | Tag component |
| ls::LevelRootComponent | 0x04 | 4 | Level root handle |
| ls::LevelUnloadedOneFrameComponent | 0x04 | 4 | OneFrame with ID |
| ls::LightComponent | 0x110 | 272 | Light data (large!) |
| ls::LightFlickerComponent | 0x0c | 12 | Flicker params |
| ls::LightMovementComponent | 0x0c | 12 | Movement params |
| ls::LightProbeComponent | 0xe8 | 232 | Light probe (large!) |
| ls::LightProbeLoadComponent | 0x08 | 8 | Light probe load state |
| ls::LocalBoundComponent | 0x18 | 24 | Local bounds |
| ls::OcclusionComponent | 0x08 | 8 | Occlusion data |
| ls::OrthoCameraBehavior | 0x28 | 40 | Ortho camera |
| ls::ParentEntityComponent | 0x8 | 8 |  |
| ls::PhysicsComponent | 0x18 | 24 | Basic physics |
| ls::PhysicsLoadComponent | 0x18 | 24 | Physics load state with flags |
| ls::PhysicsLoadedComponent | 0x01 | 1 | Load completion tag |
| ls::PhysicsPathLoadDesciptionComponent | 0x18 | 24 | STDString path |
| ls::PhysicsResourceLoadDesciptionComponent | 0x08 | 8 | Resource ID + flags |
| ls::PhysicsSkinnedConnectedToComponent | 0x30 | 48 | Skinned physics connection |
| ls::PhysicsSkinnedConnectionComponent | 0x30 | 48 | Skinned connection details |
| ls::PhysicsStreamLoadComponent | 0x01 | 1 | Stream load tag |
| ls::RoomTriggerTagComponent | 0x01 | 1 | Room trigger tag |
| ls::SaveWithComponent | 0x08 | 8 | EntityRef for save grouping |
| ls::SavegameComponent | 0x01 | 1 | Tag component |
| ls::Scene | 0x08 | 8 | Scene ptr |
| ls::SceneAttachComponent | 0x08 | 8 | Scene pointer |
| ls::ScrollingObjectComponent | 0x30 | 48 | Scrolling object |
| ls::SeeThroughStateComponent | 0x40 | 64 | Multi-vector state |
| ls::SkeletonSoundObjectTransformComponent | 0x2c | GetComponent |  |
| ls::SkeletonSoundObjectsComponent | 0x100 | GetComponent |  |
| ls::SoundActivatedComponent | 0x1 | 1 |  |
| ls::SoundCameraComponent | 0x40 | GetComponent |  |
| ls::SoundComponent | 0x20 | 32 | Sound component |
| ls::SoundRoomCurrentStateComponent | 1 | AddComponentUnchecked<ls::SoundRoomCurrentStateComponent> | Tag component |
| ls::SoundRoomNeighborStateComponent | 0x20 | 32 | Sound room neighbor state |
| ls::SplineComponent | 0x08 | 8 | Spline ptr |
| ls::StaticLevelPhysicsComponent | 0x08 | 8 | Static physics ref |
| ls::StaticPhysicsComponent | 0x8 | 8 | Static physics ref |
| ls::TerrainLoadComponent | 0x10 | 16 | Terrain loading |
| ls::TerrainObject | 0x08 | 8 | Terrain object ptr |
| ls::TimeFactorComponent | 0x04 | 4 | Time factor |
| ls::TransformComponent | 0x28 | 40 | Transform (pos/rot/scale) |
| ls::VisualAttachRequestOneFrameComponent | ls | One-frame request |  |
| ls::VisualChangeRequestOneFrameComponent | ls | One-frame request |  |
| ls::VisualChangedEventOneFrameComponent | 0x01 | 1 | Tag - visual changed |
| ls::VisualComponent | 0x10 | 16 | Core visual component |
| ls::VisualLoadDesciptionComponent | 0x08 | 8 | Load description |
| ls::VisualLoadRequestsSingletonComponent | ls | Singleton |  |
| ls::VisualLoadedComponent | 0x01 | 1 | Tag - visual loaded |
| ls::VisualStreamComponent | 0x10 | 16 | Stream component |
| ls::VisualStreamHintComponent | 0x04 | 4 | Streaming hint |
| ls::VisualStreamLoadComponent | 0x08 | 8 | Stream load |
| ls::WorldMapCameraBehavior | 0x20 | GetComponent |  |

**Total: 105 components**
