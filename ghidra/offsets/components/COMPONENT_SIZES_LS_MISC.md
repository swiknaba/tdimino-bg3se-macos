# ls:: Miscellaneous Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::animation::AnimationSetUpdateRequestComponent | 0x01 | 1 | Tag - set update request |
| ls::animation::AnimationWaterfallComponent | 32 | 0x20 | AddComponent<ls::animation::AnimationWaterfallComponent> |
| ls::animation::DynamicAnimationTagsComponent | 0x10 | 16 | Dynamic animation tags |
| ls::animation::GameplayEventsSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent | 0x10 | 16 | Load request |
| ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent | 0x30 | 48 | Remove request |
| ls::animation::TemplateAnimationSetOverrideComponent | 0x10 | 16 | Template override |
| ls::animation::TextKeyEventsSingletonComponent | ls::animation | Singleton component |  |
| ls::anubis::EnabledComponent | 0x01 | 1 | Tag - enabled |
| ls::anubis::FrameworkReloadedOneFrameComponent | 0x01 | 1 | Tag - reloaded |
| ls::anubis::LoadCompleteOneFrameComponent | 0x1 | 1 | OneFrame component |
| ls::anubis::LoadRequestOneFrameComponent | 0x8 | 8 | OneFrame component |
| ls::anubis::savegame::StateComponent | 0x88 | 136 | Savegame state |
| ls::level::LevelInstanceLoadStateComponent | 0x01 | 1 | Tag - load state |
| ls::level::LevelInstanceTempDestroyedComponent | 8 (0x8) | Struct analysis | EntityHandle = 8 bytes |
| ls::save::SaveStateComponent | 0x38 | 56 | Save state |
| ls::scene::NextSceneStageOneFrameComponent | 0x01 | 1 | Tag - next scene stage |
| ls::scene::SceneStageComponent | 0x04 | 4 | Scene stage |
| ls::transform::GameplaySetTransformRequestsComponent | 0x80 | 128 | Transform requests |
| ls::transform::InventoryMemberSetTransformRequestComponent | 0x40 | 64 | Inventory transform |
| ls::trigger::IsInsideOfComponent | 16 (0x10) | AddComponent<ls::trigger::IsInsideOfComponent> | Array<Guid> = 16 bytes |
| ls::trigger::UpdatedContainerComponent | 0x10 | 16 | Has destructor |
| ls::trigger::UpdatedPhysicsComponent | 0x10 | 16 | Physics update |
| ls::uuid::Component | 0x10 | 16 | UUID (GUID) |
| ls::uuid::ToHandleMappingComponent | 0x40 | 64 | Handle mapping |

**Total: 25 components**
