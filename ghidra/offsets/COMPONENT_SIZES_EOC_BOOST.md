# EOC Boost Components - ARM64 Sizes

All `*BoostComponent` classes from the eoc namespace.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Boost Infrastructure

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::BoostInfoComponent | 0x58 | 88 | Boost metadata |
| eoc::BoostConditionComponent | 0x08 | 8 | Condition ref |
| eoc::BoostsContainerComponent | 0x10 | 16 | Container array |
| eoc::UseBoostsComponent | 0x10 | 16 | Use boosts (DynamicArray) |

## Ability Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::AbilityBoostComponent | 0x10 | 16 | Ability score boost |
| eoc::AbilityFailedSavingThrowBoostComponent | 0x01 | 1 | Failed save flag |
| eoc::AbilityOverrideMinimumBoostComponent | 0x0c | 12 | Ability minimum |
| eoc::NullifyAbilityBoostComponent | 0x01 | 1 | Tag - nullify ability |

## Action Resource Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ActionResourceBlockBoostComponent | 0x18 | 24 | Resource block |
| eoc::ActionResourceConsumeMultiplierBoostComponent | 0x20 | 32 | Consume multiplier |
| eoc::ActionResourceMultiplierBoostComponent | 0x20 | 32 | Resource multiplier |
| eoc::ActionResourcePreventReductionBoostComponent | 0x18 | 24 | Prevent reduction |
| eoc::ActionResourceReplenishTypeOverrideBoostComponent | 0x18 | 24 | Replenish override |
| eoc::ActionResourceValueBoostComponent | 0x28 | 40 | Resource value |

## Armor/Defense Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ACOverrideFormulaBoostComponent | 0x18 | 24 | AC formula override |
| eoc::ArmorAbilityModifierCapOverrideBoostComponent | 0x08 | 8 | Armor mod cap |
| eoc::ArmorClassBoostComponent | 0x04 | 4 | AC modifier |
| eoc::DodgeAttackRollBoostComponent | 0x0c | 12 | Dodge roll bonus |

## Damage Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::CharacterWeaponDamageBoostComponent | 0x28 | 40 | Weapon damage |
| eoc::DamageBonusBoostComponent | 0x28 | 40 | Damage bonus |
| eoc::DamageReductionBoostComponent | 0x38 | 56 | Damage reduction |
| eoc::DamageTakenBonusBoostComponent | 0x28 | 40 | Damage taken mod |
| eoc::EntityThrowDamageBoostComponent | 0x10 | 16 | Throw damage |
| eoc::HalveWeaponDamageBoostComponent | 0x01 | 1 | Tag - halve damage |
| eoc::IgnoreDamageThresholdMinBoostComponent | 0x04 | 4 | Min threshold |
| eoc::MonkWeaponDamageDiceOverrideBoostComponent | 0x04 | 4 | Monk martial arts |

## Combat Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::AdvantageBoostComponent | 0x18 | 24 | Advantage/disadvantage |
| eoc::AttackSpellOverrideBoostComponent | 0x08 | 8 | Attack spell |
| eoc::CriticalHitBoostComponent | 0x08 | 8 | Crit bonus |
| eoc::CriticalHitExtraDiceBoostComponent | 0x02 | 2 | Extra crit dice |
| eoc::DualWieldingBoostComponent | 0x01 | 1 | Tag - dual wield |

## Roll Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::MaximumRollResultBoostComponent | 0x02 | 2 | Max roll cap |
| eoc::MinimumRollResultBoostComponent | 0x02 | 2 | Min roll floor |

## Vision Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::DarkvisionRangeBoostComponent | 0x04 | 4 | Darkvision range |
| eoc::DarkvisionRangeMinBoostComponent | 0x04 | 4 | Min darkvision |
| eoc::DarkvisionRangeOverrideBoostComponent | 0x04 | 4 | Override darkvision |
| eoc::CanSeeThroughBoostComponent | 0x01 | 1 | Tag - see through |
| eoc::CanShootThroughBoostComponent | 0x01 | 1 | Tag - shoot through |

## Size/Movement Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ObjectSizeBoostComponent | 0x04 | 4 | Size modifier |
| eoc::ObjectSizeOverrideBoostComponent | 0x01 | 1 | Tag - size override |
| eoc::MovementSpeedLimitBoostComponent | 0x01 | 1 | Tag - speed limit |
| eoc::CarryCapacityMultiplierBoostComponent | 0x04 | 4 | Carry weight |

## Health/Hearing Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::MaxHitPointsBoostComponent | 0x18 | 24 | Max HP boost |
| eoc::HearingBoostComponent | 0x04 | 4 | Hearing range modifier |
| eoc::HealthRegenBoostComponent | 0x10 | 16 | Health regeneration |

## Ignore Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::IgnoreLowGroundPenaltyBoostComponent | 0x01 | 1 | Tag - ignore low ground |
| eoc::IgnorePointBlankDisadvantageBoostComponent | 0x01 | 1 | Tag - ignore point blank |
| eoc::IgnoreResistanceBoostComponent | 0x18 | 24 | Ignore specific resistance |
| eoc::IgnoreSurfaceCoverBoostComponent | 0x01 | 1 | Tag - ignore surface cover |

## Icon Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::SpellIconOverrideBoostComponent | 0x18 | 24 | Spell icon override |

## Miscellaneous Boosts

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ActiveCharacterLightBoostComponent | 0x04 | 4 | Character light |
| eoc::AddTagBoostComponent | 0x10 | 16 | Tag boost |
| eoc::AiArchetypeOverrideBoostComponent | 0x08 | 8 | AI archetype |
| eoc::AttributeBoostComponent | 0x04 | 4 | Attribute modifier |
| eoc::CanTriggerRandomCastsComponent | 0x01 | 1 | Tag - wild magic |
| eoc::CannotHarmCauseEntityBoostComponent | 0x04 | 4 | Prevent harm |
| eoc::ConcentrationIgnoreDamageBoostComponent | 0x01 | 1 | Tag - concentration |
| eoc::DownedStatusBoostComponent | 0x08 | 8 | Downed status |
| eoc::ExpertiseBonusBoostComponent | 0x01 | 1 | Tag - expertise |
| eoc::FactionOverrideBoostComponent | 0x18 | 24 | Faction override |
| eoc::GameplayLightBoostComponent | 0x10 | 16 | Gameplay light |
| eoc::TemporaryHPBoostComponent | 0x20 | 32 | Temp HP (DynamicArray) |
| eoc::UnlockInterruptBoostComponent | 0x04 | 4 | Interrupt unlock (handle) |

## Weapon Boosts (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::WeaponAttackRollAbilityOverrideBoostComponent | 0x01 | 1 | Single byte enum |
| eoc::WeaponAttackRollBonusBoostComponent | 0x20 | 32 | Stats expression for attack bonus |
| eoc::WeaponAttackTypeOverrideBoostComponent | 0x01 | 1 | Single byte enum |
| eoc::WeaponDamageBoostComponent | 0x30 | 48 | Damage type + stats expression |
| eoc::WeaponDamageDieOverrideBoostComponent | 0x0c | 12 | Damage die override data |
| eoc::WeaponDamageResistanceBoostComponent | 0x10 | 16 | Damage resistance array |
| eoc::WeaponDamageTypeOverrideBoostComponent | 0x01 | 1 | Single byte enum |
| eoc::WeaponEnchantmentBoostComponent | 0x04 | 4 | Enchantment value |
| eoc::WeaponPropertyBoostComponent | 0x04 | 4 | Weapon property flags |

## Weight/Size Boosts (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::WeightBoostComponent | 0x04 | 4 | Weight modifier |
| eoc::WeightCategoryBoostComponent | 0x04 | 4 | Weight category enum |

## Vision/FOV Boosts (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::HorizontalFOVOverrideBoostComponent | 0x04 | 4 | Field of view override |

## HP Boosts (from staging - Wave 7)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::IncreaseMaxHPBoostComponent | 0x30 | 48 | HP modification with expression data |

## Statistics

- **Total boost components:** 76
- **Tag components (1 byte):** 20
- **Common patterns:** 4-byte simple values, 8-byte handles, 24-byte GUID+flags, 40-byte damage expressions
- **New in Wave 7:** Weapon boosts (9), Weight boosts (2), FOV boost (1), HP boost (1)
