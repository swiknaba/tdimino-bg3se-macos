# ls::animation:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| ls::animation::AnimationSetUpdateRequestComponent | 0x01 | 1 | Tag - set update request |
| ls::animation::AnimationWaterfallComponent | 32 | 0x20 | AddComponent<ls::animation::AnimationWaterfallComponent> |
| ls::animation::BlueprintOverrideComponent | 0x4 | GetComponent |  |
| ls::animation::DynamicAnimationTagsComponent | 0x10 | 16 | Dynamic animation tags |
| ls::animation::GameplayEventsSingletonComponent | Not found | Singleton - may not have standard allocation |  |
| ls::animation::LoadAnimationSetGameplayRequestOneFrameComponent | 0x10 | 16 | Load request |
| ls::animation::RemoveAnimationSetsGameplayRequestOneFrameComponent | 0x30 | 48 | Remove request |
| ls::animation::StoredPoseComponent | 0x90 | GetComponent |  |
| ls::animation::TemplateAnimationSetOverrideComponent | 0x10 | 16 | Template override |
| ls::animation::TextKeyEventsSingletonComponent | ls::animation | Singleton component |  |

**Total: 10 components**
