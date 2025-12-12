# Multi-Issue Offset Discovery Results

**Binary:** BG3 macOS ARM64
**Date:** 2025-12-12 09:25
**Script:** find_multi_issue_offsets.py
**Duration:** 93.4 seconds

---

## Issue #32: Stats Sync (Prototype Managers)

### Manager Symbols

| Name | Address | Offset |
|------|---------|--------|
| `__ZN3eoc18character_creation8_private20DefaultValuesManagerINS1_20ReplaceDefaultValuesINS_14SpellPrototypeEEEED1Ev` | `100c48e18` | `+0xc48e18` |
| `__ZN3eoc18character_creation8_private20DefaultValuesManagerINS1_20ReplaceDefaultValuesINS_14SpellPrototypeEEEED0Ev` | `100c48ebc` | `+0xc48ebc` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_14SpellPrototypeEEEE17LoadModuleObjectsERKNS_9ObjectSetINS_6ModuleELm0ENS_17DefaultComparatorISA_EEEE` | `100c48fbc` | `+0xc48fbc` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_14SpellPrototypeEEEE24LEGACY_LoadModuleObjectsERKNS_6ModuleE` | `100c4975c` | `+0xc4975c` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_14SpellPrototypeEEEE5ClearEv` | `100c49864` | `+0xc49864` |
| `__ZN2ls8FunctionIFvR10DamageListRKN3eoc21SpellPrototypeManagerERKNS3_22StatusPrototypeManagerERKNS3_20ConditionEnvironmentERKNS3_17ClassDescriptionsERKNS_8OptionalINS3_9interrupt21DamageRollAdjustmentsEEEbbEE18FunctorMethodsHeapIZN3esv21LEGACY_GetSpellDamageERKNS3_5spell9SpellInfoERKNS3_11StatsSystemERKN3ecs13EntityRefViewIJKNS3_24ActionResourcesComponentEKNS3_24BoostsContainerComponentEKNS3_16ClassesComponentEKNS3_13DataComponentEKNS3_24DifficultyCheckComponentEKNS3_15HealthComponentEKNS3_14LevelComponentEKNS3_20ResistancesComponentEKNS3_14StatsComponentEKNS3_12TagComponentEKNS3_18WeaponSetComponentEKNS3_9expertise18ExpertiseComponentEKNS3_4lock13LockComponentEKNS3_10shapeshift26ReplicatedChangesComponentEKNSQ_13BookComponentEKNS3_5stats11proficiency20ProficiencyComponentEKNS3_6status18ContainerComponentEKNS_4uuid9ComponentEEEERNS_5thoth6shared11ContextDataES28_E3$_0E4CallERNSN_7StorageES2_S6_S9_SC_SF_SL_bb` | `101107498` | `+0x1107498` |
| `__ZN2ls8FunctionIFvR10DamageListRKN3eoc21SpellPrototypeManagerERKNS3_22StatusPrototypeManagerERKNS3_20ConditionEnvironmentERKNS3_17ClassDescriptionsERKNS_8OptionalINS3_9interrupt21DamageRollAdjustmentsEEEbbEE18FunctorMethodsHeapIZN3esv21LEGACY_GetSpellDamageERKNS3_5spell9SpellInfoERKNS3_11StatsSystemERKN3ecs13EntityRefViewIJKNS3_24ActionResourcesComponentEKNS3_24BoostsContainerComponentEKNS3_16ClassesComponentEKNS3_13DataComponentEKNS3_24DifficultyCheckComponentEKNS3_15HealthComponentEKNS3_14LevelComponentEKNS3_20ResistancesComponentEKNS3_14StatsComponentEKNS3_12TagComponentEKNS3_18WeaponSetComponentEKNS3_9expertise18ExpertiseComponentEKNS3_4lock13LockComponentEKNS3_10shapeshift26ReplicatedChangesComponentEKNSQ_13BookComponentEKNS3_5stats11proficiency20ProficiencyComponentEKNS3_6status18ContainerComponentEKNS_4uuid9ComponentEEEERNS_5thoth6shared11ContextDataES28_E3$_0E4CopyEPNSN_11MethodTableERKNSN_7StorageERS2H_` | `101107bf4` | `+0x1107bf4` |
| `__ZN2ls8FunctionIFvR10DamageListRKN3eoc21SpellPrototypeManagerERKNS3_22StatusPrototypeManagerERKNS3_20ConditionEnvironmentERKNS3_17ClassDescriptionsERKNS_8OptionalINS3_9interrupt21DamageRollAdjustmentsEEEbbEE18FunctorMethodsHeapIZN3esv21LEGACY_GetSpellDamageERKNS3_5spell9SpellInfoERKNS3_11StatsSystemERKN3ecs13EntityRefViewIJKNS3_24ActionResourcesComponentEKNS3_24BoostsContainerComponentEKNS3_16ClassesComponentEKNS3_13DataComponentEKNS3_24DifficultyCheckComponentEKNS3_15HealthComponentEKNS3_14LevelComponentEKNS3_20ResistancesComponentEKNS3_14StatsComponentEKNS3_12TagComponentEKNS3_18WeaponSetComponentEKNS3_9expertise18ExpertiseComponentEKNS3_4lock13LockComponentEKNS3_10shapeshift26ReplicatedChangesComponentEKNSQ_13BookComponentEKNS3_5stats11proficiency20ProficiencyComponentEKNS3_6status18ContainerComponentEKNS_4uuid9ComponentEEEERNS_5thoth6shared11ContextDataES28_E3$_0E11MoveDestroyEPNSN_11MethodTableERNSN_7StorageEPS2H_` | `101107cdc` | `+0x1107cdc` |
| `__ZN2ls8FunctionIFvR10DamageListRKN3eoc21SpellPrototypeManagerERKNS3_22StatusPrototypeManagerERKNS3_20ConditionEnvironmentERKNS3_17ClassDescriptionsERKNS_8OptionalINS3_9interrupt21DamageRollAdjustmentsEEEbbEED1Ev` | `1011085cc` | `+0x11085cc` |
| `__ZN3eoc3hit19GetHitAnimationTypeERKNS_21SpellPrototypeManagerERKNS_22StatusPrototypeManagerERKN2ls11FixedStringESA_` | `101b90378` | `+0x1b90378` |
| `__ZN3eoc18character_creation8_private20DefaultValuesManagerINS1_20ReplaceDefaultValuesINS_16PassivePrototypeEEEED1Ev` | `100c51ae0` | `+0xc51ae0` |
| `__ZN3eoc18character_creation8_private20DefaultValuesManagerINS1_20ReplaceDefaultValuesINS_16PassivePrototypeEEEED0Ev` | `100c51b84` | `+0xc51b84` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_16PassivePrototypeEEEE17LoadModuleObjectsERKNS_9ObjectSetINS_6ModuleELm0ENS_17DefaultComparatorISA_EEEE` | `100c51c84` | `+0xc51c84` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_16PassivePrototypeEEEE24LEGACY_LoadModuleObjectsERKNS_6ModuleE` | `100c52424` | `+0xc52424` |
| `__ZN2ls19ModdableFilesLoaderINS_4GuidEN3eoc18character_creation8_private20ReplaceDefaultValuesINS2_16PassivePrototypeEEEE5ClearEv` | `100c5252c` | `+0xc5252c` |
| `__ZN3eoc9interrupt23HasInterruptWithContextERN3ecs9WorldViewIJKNS0_18ContainerComponentEKNS0_13DataComponentEEEERKNS_25InterruptPrototypeManagerERKN2ls2IDINS1_18EntityHandleTraitsEEENS0_8EContextE` | `101b93338` | `+0x1b93338` |
| `__ZN3eoc9interrupt30HasEnoughResourcesForInterruptERN3ecs9WorldViewIJKNS_33ActionResourceBlockBoostComponentEKNS_45ActionResourceConsumeMultiplierBoostComponentEKNS_24ActionResourcesComponentEKNS_23BoostConditionComponentEKNS_18BoostInfoComponentEKNS_24BoostsContainerComponentEKNS_6combat20ParticipantComponentEKNS_3ftb20ParticipantComponentEKNSI_16RespectComponentEKNS_15PlayerComponentEKNS_6status20LoseControlComponentEKNS_18TurnBasedComponentEEEERKNS_19ActionResourceTypesERKNS_18InterruptPrototypeERKN2ls2IDINS1_18EntityHandleTraitsEEERKNS12_7HashMapIS15_NS12_12DynamicArrayINS_15action_resource18ActionResourceCostENS12_15TaggedAllocatorIiEEEENS12_19HashTableOpsDefaultEEERNS12_5thoth6shared7MachineE` | `101b93750` | `+0x1b93750` |
| `__ZN3eoc9interrupt17EvaluateInterruptERN3ecs9WorldViewIJKNS_33ActionResourceBlockBoostComponentEKNS_45ActionResourceConsumeMultiplierBoostComponentEKNS_24ActionResourcesComponentEKNS_23BoostConditionComponentEKNS_18BoostInfoComponentEKNS_24BoostsContainerComponentEKNS_6combat20ParticipantComponentEKNS_3ftb20ParticipantComponentEKNSI_16RespectComponentEKNS_15HealthComponentEKNS0_30ConditionallyDisabledComponentEKNS0_18ContainerComponentEKNS0_13DataComponentEKNS0_20PreferencesComponentEKNS_17OffStageComponentEKNS_15PlayerComponentEKNS_6status20LoseControlComponentEKNS_18TurnBasedComponentEEEERN2ls5thoth6shared7MachineERKNS_19ActionResourceTypesERKNS_25InterruptPrototypeManagerERKNS18_2IDINS1_18EntityHandleTraitsEEES1N_S1N_S1N_RK8Vector3fS1Q_NS0_8EContextE` | `101b94278` | `+0x1b94278` |
| `~InterruptPrototype` | `101b95af4` | `+0x1b95af4` |
| `__ZN3eoc18InterruptPrototypeD1Ev` | `101b95af4` | `+0x1b95af4` |

### Init Function Candidates

| Name | Address | Offset |
|------|---------|--------|
| `RegisterSystem<ecl::GameAnalyticsSystem,BaseApp&,eoc::background::Goals_const&,eoc::ClassDescriptions_const&,eoc::RaceManager_const&,eoc::GodManager_const&,eoc::OriginManager_const&,eoc::BackgroundManager_const&,eoc::ProgressionManager_const&,eoc::SpellPrototypeManager&,eoc::BoostPrototypeManager&,eoc::CharacterCreationAppearanceVisualManager_const&,eoc::CharacterCreationSharedVisualManager_const&,eoc::CharacterCreationAppearanceMaterialManager_const&,ecl::EocClient&,ecl::ModManagerClient&,eoc::FactionContainer_const&,ecl::JournalManager&,eoc::EocProfileManager&,ecl::UIManager&,ecl::PlayerManager&,ecl::SavegameManager&,ls::UniquePtr<ecl::GameAnalyticsSystemHelper,void>,eoc::ruleset::Rulesets_const&,eoc::ruleset::RulesetModifiers_const&>` | `100f97de0` | `+0xf97de0` |
| `~InterruptPrototypeManager` | `101b96610` | `+0x1b96610` |
| `~InterruptPrototypeManager` | `101b96614` | `+0x1b96614` |
| `syncState` | `1008a4bb0` | `+0x8a4bb0` |
| `syncState` | `1008a5ba4` | `+0x8a5ba4` |
| `syncState` | `1008a6018` | `+0x8a6018` |

### Type Strings Found

| Name | Address | Offset |
|------|---------|--------|
| `Status: StatusData` | `107b72fbd` | `+0x7b72fbd` |
| `Status: StatusType` | `107855309` | `+0x7855309` |
| `Passive: PassiveData` | `107b73be3` | `+0x7b73be3` |
| `Passive: PassivePrototype` | `107b47d91` | `+0x7b47d91` |
| `Spell: SpellData` | `107864734` | `+0x7864734` |
| `Spell: SpellType` | `107849759` | `+0x7849759` |
| `Interrupt: InterruptData` | `10784ec29` | `+0x784ec29` |
| `Interrupt: InterruptPrototype` | `107b88d7e` | `+0x7b88d7e` |

---

## Issue #37: Physics (Raycast)

### Physics Strings

| Name | Address | Offset |
|------|---------|--------|
| `RayCast` | `107d323be` | `+0x7d323be` |
| `Collision` | `10782a87f` | `+0x782a87f` |

### Physics Symbols

| Name | Address | Offset |
|------|---------|--------|
| `multiQuery<physx::PxRaycastHit>` | `EXTERNAL:00000216` | `+0x-fffffdea` |
| `__ZN16PxOverflowBufferIN5physx12PxRaycastHitEED1Ev` | `100867fb8` | `+0x867fb8` |
| `raycast` | `100867fc4` | `+0x867fc4` |
| `__ZN5physx12NpBatchQuery7raycastERKNS_6PxVec3ES3_ftNS_7PxFlagsINS_9PxHitFlag4EnumEtEERKNS_17PxQueryFilterDataEPvPKNS_12PxQueryCacheE` | `100867fc4` | `+0x867fc4` |
| `__ZN16PxOverflowBufferIN5physx12PxRaycastHitEE14processTouchesEPKS1_j` | `100868bf0` | `+0x868bf0` |
| `RaycastClosest` | `105c5ed6c` | `+0x5c5ed6c` |
| `__ZNK3phx10PhysXScene14RaycastClosestERK8Vector3fS3_RN2ls10PhysicsHitENS4_12EPhysicsTypeEjjNS4_15EPhysicsContextEjjNS4_8FunctionIFbPKNS4_12PhysicsShapeEEEE` | `105c5ed6c` | `+0x5c5ed6c` |
| `RaycastClosest` | `105c679b4` | `+0x5c679b4` |
| `__ZN3phx17PhysXSceneHelpers14RaycastClosestEPN5physx7PxSceneERK8Vector3fS6_RN2ls10PhysicsHitENS7_12EPhysicsTypeEjjNS7_15EPhysicsContextEjjNS7_8FunctionIFbPKNS7_12PhysicsShapeEEEE` | `105c679b4` | `+0x5c679b4` |
| `RaycastClosest` | `105c8cc30` | `+0x5c8cc30` |
| `sweepSphereCapsule` | `100a72d8c` | `+0xa72d8c` |
| `__ZN5physx2Gu18sweepSphereCapsuleERKNS0_6SphereERKNS0_7CapsuleERKNS_6PxVec3EfRfRS7_SB_NS_7PxFlagsINS_9PxHitFlag4EnumEtEE` | `100a72d8c` | `+0xa72d8c` |
| `sweepSphereSphere` | `100a731dc` | `+0xa731dc` |
| `__ZN5physx2Gu17sweepSphereSphereERKNS_6PxVec3EfS3_fS3_RfRS1_` | `100a731dc` | `+0xa731dc` |
| `sweepSphereVSTri` | `100a7336c` | `+0xa7336c` |
| `GetRealPhysicsWorldTransform` | `105c7b4f4` | `+0x5c7b4f4` |
| `__ZNK3phx27PhysXSkinnedCollisionObject28GetRealPhysicsWorldTransformEPKN2ls12PhysicsShapeERNS1_9TransformE` | `105c7b4f4` | `+0x5c7b4f4` |
| `GetRealPhysicsWorldTransform` | `105c7c4dc` | `+0x5c7c4dc` |
| `__ZNK3phx18PhysXSkinnedObject28GetRealPhysicsWorldTransformEPKN2ls12PhysicsShapeERNS1_9TransformE` | `105c7c4dc` | `+0x5c7c4dc` |
| `__ZN3eoc6AiGridC1ERN2ls14LevelAllocatorERN3ecs11EntityWorldEPNS1_16PhysicsSceneBaseERNS1_5thoth6shared7MachineE` | `10116fd20` | `+0x116fd20` |
| `__ZN3eoc18CharacterFallCheckEPKNS_6AiGridEPKN2ls16PhysicsSceneBaseE8Vector3ffffbPf` | `101232ef0` | `+0x1232ef0` |
| `__ZN3eoc12SnapToGroundEPKN2ls16PhysicsSceneBaseEPKNS_6AiGridERK8Vector3ffRS7_` | `101232fec` | `+0x1232fec` |
| `__ZN3eoc12CoverManagerC1ERN2ls16PhysicsSceneBaseEb` | `101265f00` | `+0x1265f00` |
| `__ZNK3eoc12CoverManager14Check3DLineAnyERK8Vector3fS3_N2ls5FlagsItLt0ELi6EEENS4_8OptionalIRNS4_26PhysicsSceneScopedReadLockEEEfPNS0_8CoverHitENS4_11EObjectSizeE` | `101267804` | `+0x1267804` |

### Raycast Functions

| Name | Address | Offset |
|------|---------|--------|
| `raycast` | `100867fc4` | `+0x867fc4` |
| `raycast` | `1008969b0` | `+0x8969b0` |
| `multiQuery<physx::PxRaycastHit>` | `100896a04` | `+0x896a04` |
| `ProcessWaveTableNoSweep` | `100295e24` | `+0x295e24` |
| `ProcessWaveTableLinSweep` | `100296048` | `+0x296048` |
| `ProcessWaveTableLogSweep` | `1002962c8` | `+0x2962c8` |
| `getSelfCollision` | `10085b5c8` | `+0x85b5c8` |
| `checkCollision` | `10088d34c` | `+0x88d34c` |
| `fetchCollision` | `10088d448` | `+0x88d448` |
| `_PhysicsCalcIsVisibile` | `10083c2c4` | `+0x83c2c4` |
| `_PhysicsCalcMakeInvisibileOrReprio` | `10083c6cc` | `+0x83c6cc` |
| `PxGetPhysicsBinaryMetaData` | `10087c274` | `+0x87c274` |

---

## Issue #38: Audio (Wwise)

### Wwise Symbols

| Name | Address | Offset |
|------|---------|--------|
| `~AkMusicActionPostEvent` | `100184314` | `+0x184314` |
| `__ZN22AkMusicActionPostEventD1Ev` | `100184314` | `+0x184314` |
| `~AkMusicActionPostEvent` | `100184318` | `+0x184318` |
| `__ZN22AkMusicActionPostEventD0Ev` | `100184318` | `+0x184318` |
| `__ZN22AkMusicActionPostEvent4TypeEv` | `10018431c` | `+0x18431c` |
| `SetPosition` | `1001910f0` | `+0x1910f0` |
| `__ZN11CAkListener11SetPositionERK16AkWorldTransform` | `1001910f0` | `+0x1910f0` |
| `SetPosition` | `10019fc0c` | `+0x19fc0c` |
| `__ZN2AK11SoundEngine11SetPositionEyRK16AkWorldTransform18AkSetPositionFlags` | `10019fc0c` | `+0x19fc0c` |
| `SetPositionInternal` | `10019fc20` | `+0x19fc20` |
| `LoadBankItem` | `100168f44` | `+0x168f44` |
| `__ZN11AkMusicBank12LoadBankItemERKN6AkBank18AKBKSubHircSectionEP12CAkUsageSlotj` | `100168f44` | `+0x168f44` |
| `UnloadBankSlot` | `1001698bc` | `+0x1698bc` |
| `__ZN11AkMusicBank14UnloadBankSlotEP12CAkUsageSlot` | `1001698bc` | `+0x1698bc` |
| `LoadBank` | `1001a1c70` | `+0x1a1c70` |
| `UnloadBankSlot` | `1001698bc` | `+0x1698bc` |
| `__ZN11AkMusicBank14UnloadBankSlotEP12CAkUsageSlot` | `1001698bc` | `+0x1698bc` |
| `UnloadBank` | `1001a2074` | `+0x1a2074` |
| `__ZN2AK11SoundEngine10UnloadBankEjPKvj` | `1001a2074` | `+0x1a2074` |
| `UnloadBank` | `1001a2164` | `+0x1a2164` |
| `StopAll` | `1001889ec` | `+0x1889ec` |
| `__ZN16CAkMidiDeviceMgr7StopAllEjyj` | `1001889ec` | `+0x1889ec` |
| `StopAll` | `1001a3550` | `+0x1a3550` |
| `__ZN2AK11SoundEngine7StopAllEy` | `1001a3550` | `+0x1a3550` |
| `Sizeof_StopAll` | `1001a48c0` | `+0x1a48c0` |
| `SetRTPCValue` | `10019d710` | `+0x19d710` |
| `__ZN22CAkGlobalPluginContext12SetRTPCValueEjfyi20AkCurveInterpolationb` | `10019d710` | `+0x19d710` |
| `SetRTPCValueSync` | `10019ea18` | `+0x19ea18` |
| `__ZN22CAkGlobalPluginContext16SetRTPCValueSyncEjfyi20AkCurveInterpolationb` | `10019ea18` | `+0x19ea18` |
| `SetRTPCValue` | `1001a04ec` | `+0x1a04ec` |
| `__ZN2AK11SoundEngine13IsInitializedEv` | `10019d594` | `+0x19d594` |
| `__ZN2AK11SoundEngine22RegisterGlobalCallbackEPFvPNS_22IAkGlobalPluginContextE24AkGlobalCallbackLocationPvEjS4_12AkPluginTypejj` | `10019d6c0` | `+0x19d6c0` |
| `__ZN2AK11SoundEngine24UnregisterGlobalCallbackEPFvPNS_22IAkGlobalPluginContextE24AkGlobalCallbackLocationPvEj` | `10019d6f0` | `+0x19d6f0` |
| `__ZN2AK11SoundEngine15GetIDFromStringEPKc` | `10019d9bc` | `+0x19d9bc` |
| `__ZN2AK11SoundEngine4InitEP14AkInitSettingsP22AkPlatformInitSettings` | `10019ee60` | `+0x19ee60` |

### Sound Functions

| Name | Address | Offset |
|------|---------|--------|
| `GatherSounds` | `10016d05c` | `+0x16d05c` |
| `GatherSounds` | `100174a0c` | `+0x174a0c` |
| `GatherSounds` | `100179f64` | `+0x179f64` |
| `ResolveAudioNode` | `100175c20` | `+0x175c20` |
| `AkAudioObjectRegistry` | `10018f3e0` | `+0x18f3e0` |
| `WriteSystemAudioObjectPointers` | `10018f68c` | `+0x18f68c` |
| `CAkMusicActionSequencer` | `100166a98` | `+0x166a98` |
| `~CAkMusicActionSequencer` | `100166aac` | `+0x166aac` |
| `~CAkMusicActionSequencer` | `100166ac0` | `+0x166ac0` |
| `_ExecuteWwiseCmd` | `100189f64` | `+0x189f64` |
| `~WwiseIOHook` | `103808ae8` | `+0x3808ae8` |
| `~WwiseIOHook` | `103808aec` | `+0x3808aec` |

### Audio Strings

| Name | Address | Offset |
|------|---------|--------|
| `Stop_` | `107c2b01a` | `+0x7c2b01a` |
| `Wwise` | `107afc1a0` | `+0x7afc1a0` |
| `AK::` | `107afc37b` | `+0x7afc37b` |

---

## Issue #40: StaticData (GuidResourceManager)

### Resource Type Strings

| Name | Address | Offset |
|------|---------|--------|
| `Background` | `10784e236` | `+0x784e236` |
| `Feat` | `10782aecc` | `+0x782aecc` |
| `Origin` | `1078498d3` | `+0x78498d3` |
| `Progression` | `10784bb1b` | `+0x784bb1b` |
| `ClassDescription` | `10784eb0f` | `+0x784eb0f` |
| `Race` | `10784bb17` | `+0x784bb17` |

### Related Functions

| Name | Address | Offset |
|------|---------|--------|
| `SetResourceManager` | `10254ea00` | `+0x254ea00` |
| `__ZN3ecl5sound30GameplayActivationLegacyHelper20GatherItemSwitchDataERN3ecs9WorldViewIJKNS_9CharacterEKNS_4ItemEKNS_14TLPreviewDummyEKN3eoc12TagComponentEKN2ls14SoundComponentEKNS_9character17AssignedComponentEKNS_23GroundMaterialComponentEKNSA_9character18CharacterComponentEKNSA_5death14DeathComponentEKNSA_9inventory18ContainerComponentEKNSR_13DataComponentEKNSR_14OwnerComponentEKNSR_17TopOwnerComponentEKNSA_10shapeshift26ReplicatedChangesComponentEKNSA_5sound25DistantSoundInfoComponentEKNSA_16ClassesComponentEKNSA_13DataComponentEKNSA_18EquipableComponentEKNSA_17BodyTypeComponentEKNSA_19ObjectSizeComponentEKNSA_16PathingComponentEKNSA_15PlayerComponentEKNSA_13RaceComponentEKNSA_14StatsComponentEKNSA_15WeaponComponentEKNSA_18WeaponSetComponentEKNSD_4uuid9ComponentEKNSD_22SoundMaterialComponentEKNSD_15VisualComponentESK_KNSA_14ArmorComponentEKNSA_23AttributeFlagsComponentEKNSA_14BoundComponentES19_KNSA_26DisabledEquipmentComponentES1B_KNSR_16IsOwnedComponentEKNSR_15MemberComponentEKNSR_14StackComponentEKNSR_20StackMemberComponentEKNSR_15WeightComponentEKNSA_5stats26MusicalInstrumentComponentES1P_KNSD_18TransformComponentES1Y_KNSA_6status6visual17DisabledComponentEKNS_27InvisibilityVisualComponentENS0_28CharacterSwitchDataComponentENS0_23ItemSwitchDataComponentEKNSA_9armor_set14StateComponentEKNSA_4item13ItemComponentEKNSA_16SpeakerComponentEKNSD_14DebugComponentEEEERKNS2_8_private10EntityViewIJNSD_8TypeListIJEEENS38_IJSK_S20_S22_S24_S19_S26_S1B_S28_S2A_S2C_S2E_S2G_S2J_S1P_S2L_S1Y_S7_S9_EEEEEERS2T_RNS0_31ItemActivationRequestsComponentERNS0_36CharacterActivationRequestsComponentERK8RPGStatsRNSD_15ResourceManagerERKNS_14SpeakerManagerE` | `10350c7c0` | `+0x350c7c0` |
| `__ZN3ecl5sound30GameplayActivationLegacyHelper18LoadCharacterSoundERN3ecs9WorldViewIJKNS_9CharacterEKNS_4ItemEKNS_14TLPreviewDummyEKN3eoc12TagComponentEKN2ls14SoundComponentEKNS_9character17AssignedComponentEKNS_23GroundMaterialComponentEKNSA_9character18CharacterComponentEKNSA_5death14DeathComponentEKNSA_9inventory18ContainerComponentEKNSR_13DataComponentEKNSR_14OwnerComponentEKNSR_17TopOwnerComponentEKNSA_10shapeshift26ReplicatedChangesComponentEKNSA_5sound25DistantSoundInfoComponentEKNSA_16ClassesComponentEKNSA_13DataComponentEKNSA_18EquipableComponentEKNSA_17BodyTypeComponentEKNSA_19ObjectSizeComponentEKNSA_16PathingComponentEKNSA_15PlayerComponentEKNSA_13RaceComponentEKNSA_14StatsComponentEKNSA_15WeaponComponentEKNSA_18WeaponSetComponentEKNSD_4uuid9ComponentEKNSD_22SoundMaterialComponentEKNSD_15VisualComponentESK_KNSA_14ArmorComponentEKNSA_23AttributeFlagsComponentEKNSA_14BoundComponentES19_KNSA_26DisabledEquipmentComponentES1B_KNSR_16IsOwnedComponentEKNSR_15MemberComponentEKNSR_14StackComponentEKNSR_20StackMemberComponentEKNSR_15WeightComponentEKNSA_5stats26MusicalInstrumentComponentES1P_KNSD_18TransformComponentES1Y_KNSA_6status6visual17DisabledComponentEKNS_27InvisibilityVisualComponentENS0_28CharacterSwitchDataComponentENS0_23ItemSwitchDataComponentEKNSA_9armor_set14StateComponentEKNSA_4item13ItemComponentEKNSA_16SpeakerComponentEKNSD_14DebugComponentEEEERKNS2_8_private10EntityViewIJNSD_8TypeListIJEEENS38_IJS5_S7_S9_SC_SF_SQ_S15_SX_SZ_SI_S1J_EEEEEERS2S_RNS0_36CharacterActivationRequestsComponentERNS0_31ItemActivationRequestsComponentERNSD_15ResourceManagerERKNS_14SpeakerManagerE` | `10350eb7c` | `+0x350eb7c` |
| `__ZN3ecl5sound30GameplayActivationLegacyHelper20UnloadCharacterSoundERN3ecs9WorldViewIJKNS_9CharacterEKNS_4ItemEKNS_14TLPreviewDummyEKN3eoc12TagComponentEKN2ls14SoundComponentEKNS_9character17AssignedComponentEKNS_23GroundMaterialComponentEKNSA_9character18CharacterComponentEKNSA_5death14DeathComponentEKNSA_9inventory18ContainerComponentEKNSR_13DataComponentEKNSR_14OwnerComponentEKNSR_17TopOwnerComponentEKNSA_10shapeshift26ReplicatedChangesComponentEKNSA_5sound25DistantSoundInfoComponentEKNSA_16ClassesComponentEKNSA_13DataComponentEKNSA_18EquipableComponentEKNSA_17BodyTypeComponentEKNSA_19ObjectSizeComponentEKNSA_16PathingComponentEKNSA_15PlayerComponentEKNSA_13RaceComponentEKNSA_14StatsComponentEKNSA_15WeaponComponentEKNSA_18WeaponSetComponentEKNSD_4uuid9ComponentEKNSD_22SoundMaterialComponentEKNSD_15VisualComponentESK_KNSA_14ArmorComponentEKNSA_23AttributeFlagsComponentEKNSA_14BoundComponentES19_KNSA_26DisabledEquipmentComponentES1B_KNSR_16IsOwnedComponentEKNSR_15MemberComponentEKNSR_14StackComponentEKNSR_20StackMemberComponentEKNSR_15WeightComponentEKNSA_5stats26MusicalInstrumentComponentES1P_KNSD_18TransformComponentES1Y_KNSA_6status6visual17DisabledComponentEKNS_27InvisibilityVisualComponentENS0_28CharacterSwitchDataComponentENS0_23ItemSwitchDataComponentEKNSA_9armor_set14StateComponentEKNSA_4item13ItemComponentEKNSA_16SpeakerComponentEKNSD_14DebugComponentEEEERKNS2_8_private10EntityViewIJNSD_8TypeListIJEEENS38_IJS5_S7_S9_SC_SF_SQ_S15_SX_SZ_SI_S1J_EEEEEERS2S_RNS0_36CharacterActivationRequestsComponentERNS0_31ItemActivationRequestsComponentERNSD_15ResourceManagerERKNS_14SpeakerManagerERKNSD_8OptionalINSD_12TemplateInfoEEE` | `10350f5b8` | `+0x350f5b8` |
| `__ZN3ecl5sound30GameplayActivationLegacyHelper13LoadItemSoundERN3ecs9WorldViewIJKNS_9CharacterEKNS_4ItemEKNS_14TLPreviewDummyEKN3eoc12TagComponentEKN2ls14SoundComponentEKNS_9character17AssignedComponentEKNS_23GroundMaterialComponentEKNSA_9character18CharacterComponentEKNSA_5death14DeathComponentEKNSA_9inventory18ContainerComponentEKNSR_13DataComponentEKNSR_14OwnerComponentEKNSR_17TopOwnerComponentEKNSA_10shapeshift26ReplicatedChangesComponentEKNSA_5sound25DistantSoundInfoComponentEKNSA_16ClassesComponentEKNSA_13DataComponentEKNSA_18EquipableComponentEKNSA_17BodyTypeComponentEKNSA_19ObjectSizeComponentEKNSA_16PathingComponentEKNSA_15PlayerComponentEKNSA_13RaceComponentEKNSA_14StatsComponentEKNSA_15WeaponComponentEKNSA_18WeaponSetComponentEKNSD_4uuid9ComponentEKNSD_22SoundMaterialComponentEKNSD_15VisualComponentESK_KNSA_14ArmorComponentEKNSA_23AttributeFlagsComponentEKNSA_14BoundComponentES19_KNSA_26DisabledEquipmentComponentES1B_KNSR_16IsOwnedComponentEKNSR_15MemberComponentEKNSR_14StackComponentEKNSR_20StackMemberComponentEKNSR_15WeightComponentEKNSA_5stats26MusicalInstrumentComponentES1P_KNSD_18TransformComponentES1Y_KNSA_6status6visual17DisabledComponentEKNS_27InvisibilityVisualComponentENS0_28CharacterSwitchDataComponentENS0_23ItemSwitchDataComponentEKNSA_9armor_set14StateComponentEKNSA_4item13ItemComponentEKNSA_16SpeakerComponentEKNSD_14DebugComponentEEEERKNS2_8_private10EntityViewIJNSD_8TypeListIJEEENS38_IJS5_S7_S9_SC_SF_EEEEEERS2T_RNS0_31ItemActivationRequestsComponentERNS0_36CharacterActivationRequestsComponentERNSD_15ResourceManagerERKNS_14SpeakerManagerEb` | `10350fd14` | `+0x350fd14` |
| `~ResourceBank` | `1060cd0ac` | `+0x60cd0ac` |
| `~ResourceBank` | `1060cd130` | `+0x60cd130` |
| `~ResourceBank` | `1060cd4ac` | `+0x60cd4ac` |
| `~ResourceBank` | `1060cd524` | `+0x60cd524` |
| `ResourceBank` | `1060de464` | `+0x60de464` |

### Singleton Symbols

| Name | Address | Offset |
|------|---------|--------|
| `__ZN5EoCFS28strActionResourceDefinitionsE` | `108999138` | `+0x8999138` |
| `strActionResourceDefinitions` | `108999138` | `+0x8999138` |

---

## Issue #41: Resource/Template

### Resource Symbols

| Name | Address | Offset |
|------|---------|--------|
| `RegisterType<eoc::CampChestTemplateManager>` | `100c676f4` | `+0xc676f4` |
| `__ZN2ls11TypeContextINS_23ImmutableDataHeadmasterEE12RegisterTypeIN3eoc24CampChestTemplateManagerEEEiPi` | `100c676f4` | `+0xc676f4` |
| `RegisterType<eoc::AvatarContainerTemplateManager>` | `100c67bd4` | `+0xc67bd4` |
| `__ZN2ls11TypeContextINS_23ImmutableDataHeadmasterEE12RegisterTypeIN3eoc30AvatarContainerTemplateManagerEEEiPi` | `100c67bd4` | `+0xc67bd4` |
| `~AvatarContainerTemplateManager` | `1011980ac` | `+0x11980ac` |
| `__ZZN3ecs8_private24SystemRegistrationHelper14RegisterSystemIN3ecl16CharacterManagerEJRNS3_13EntityManagerERN2ls24AnimationBlueprintSystemERNS7_15TransformSystemERNS7_12VisualSystemERNS3_22EquipmentVisualsSystemERNS3_3exp16ExperienceSystemERNS3_11StatsSystemERNS3_9LEDSystemERKN3eoc16FactionContainerERKNSN_17EoCGlobalSwitchesERNS3_19GameAnalyticsSystemERNS7_15ResourceManagerERNS3_12StatusSystemERNS3_12LevelManagerERNS3_3HUBERNS3_9character11SoundSystemERNS3_17GameActionManagerERNS3_13PlayerManagerERNSN_21SpellPrototypeManagerEEEEvRNS_11EntityWorldEDpOT0_ENUlRNS_6SystemERKNS7_8GameTimeEE_8__invokeES1J_S1M_` | `101020a94` | `+0x1020a94` |
| `__ZZN3ecs8_private24SystemRegistrationHelper14RegisterSystemIN3ecl12MusicManagerEJRNS3_18character_creation6SystemERN2ls15ResourceManagerERNS3_13PlayerManagerEEEEvRNS_11EntityWorldEDpOT0_ENUlRNS_6SystemERKNS8_8GameTimeEE_8__invokeESJ_SM_` | `101058f18` | `+0x1058f18` |
| `__ZZN3ecs8_private24SystemRegistrationHelper14RegisterSystemIN3ecl11SoundSystemEJRNS3_12LevelManagerERN2ls15ResourceManagerERNS3_13PlayerManagerERNS3_13ShroudManagerEEEEvRNS_11EntityWorldEDpOT0_ENUlRNS_6SystemERKNS7_8GameTimeEE_8__invokeESK_SN_` | `101063a0c` | `+0x1063a0c` |
| `__ZN3eoc6crowds22GetAnimationDescriptorERKN2ls15ResourceManagerERKNS1_14VisualResourceERKNS1_11FixedStringERKNS1_4GuidE` | `10126cfc8` | `+0x126cfc8` |
| `__ZN3eoc11ItemHelpers13GetItemColorsERKN3ecs9WorldViewIJKNS_13DataComponentEKNS_4item12DyeComponentEEEERK8RPGStatsRKN2ls15ResourceManagerERKNSE_2IDINS1_18EntityHandleTraitsEEERKNSE_11FixedStringERNSE_12DynamicArrayINSE_25MaterialParameterOverrideI8Vector3fEENSE_15TaggedAllocatorIiEEEE` | `101ba0028` | `+0x1ba0028` |
| `__ZN2ls12ResourceBank5VisitEPNS_13ObjectVisitorE` | `1060cd088` | `+0x60cd088` |
| `~ResourceBank` | `1060cd0ac` | `+0x60cd0ac` |
| `__ZN2ls12ResourceBankD1Ev` | `1060cd0ac` | `+0x60cd0ac` |
| `~ResourceBank` | `1060cd130` | `+0x60cd130` |
| `__ZN2ls12ResourceBankD0Ev` | `1060cd130` | `+0x60cd130` |
| `__ZZN3esv13ActionHelpers17TeleportCharacterERKN2ls11FixedStringEPNS_9CharacterEPKNS_4ItemERK8Vector3fRK11QuaternionfS4_RNS1_2IDINS1_5thoth6shared21ConditionHandleTraitsEEEPKNS1_18GameObjectTemplateEbbENK3$_3clERNS1_12DynamicArrayIS6_NS1_15TaggedAllocatorIiEEEE` | `1010d6718` | `+0x10d6718` |
| `__ZN3eoc11IActionData5VisitEPN2ls13ObjectVisitorEPKNS1_18GameObjectTemplateE` | `1011233b0` | `+0x11233b0` |
| `__ZN3eoc19PlaySoundActionData5VisitEPN2ls13ObjectVisitorEPKNS1_18GameObjectTemplateE` | `10112395c` | `+0x112395c` |
| `__ZN3eoc20DisarmTrapActionData5VisitEPN2ls13ObjectVisitorEPKNS1_18GameObjectTemplateE` | `101123da8` | `+0x1123da8` |
| `__ZN3eoc14BookActionData5VisitEPN2ls13ObjectVisitorEPKNS1_18GameObjectTemplateE` | `101124260` | `+0x1124260` |

### Template Strings

| Name | Address | Offset |
|------|---------|--------|
| `RootTemplate` | `107b6af72` | `+0x7b6af72` |
| `Templates/` | `107b45f61` | `+0x7b45f61` |
| `.lsf` | `107b4a3b9` | `+0x7b4a3b9` |

### Related Functions

| Name | Address | Offset |
|------|---------|--------|
| `ComputeFiltering3D_Template<NoLogAttenuationDelta>` | `100193ad4` | `+0x193ad4` |
| `ComputeVolumeRays_Template<NoLogAttenuationDelta>` | `1001944f0` | `+0x1944f0` |
| `PrepareEventTemplate<char>` | `1001a29cc` | `+0x1a29cc` |
| `floor1_inverse2_template<floor_Tremor>` | `10029fd14` | `+0x29fd14` |
| `RegisterProperty<Noesis::Ptr<Noesis::DataTemplate>>` | `100438e00` | `+0x438e00` |
| `~DefaultResourceCallbacks` | `100162958` | `+0x162958` |
| `GetNativeResource` | `10016295c` | `+0x16295c` |
| `____ZN8Graphine7Granite5Metal8Internal24DefaultResourceCallbacks12CreateBufferEPU19objcproto9MTLDevice11objc_objectPU26objcproto15MTLCommandQueue11objc_objectmmPKvPPU19objcproto9MTLBuffer11objc_object_block_invoke` | `100162d7c` | `+0x162d7c` |
| `~DefaultResourceCallbacks` | `100162dbc` | `+0x162dbc` |
| `CreateSharedResources` | `10016336c` | `+0x16336c` |

---

## Summary

- **Issue #40:** 18 findings (HIGH confidence)
- **Issue #41:** 33 findings (HIGH confidence)
- **Issue #32:** 34 findings (HIGH confidence)
- **Issue #37:** 38 findings (HIGH confidence)
- **Issue #38:** 50 findings (HIGH confidence)

**Total findings:** 173
