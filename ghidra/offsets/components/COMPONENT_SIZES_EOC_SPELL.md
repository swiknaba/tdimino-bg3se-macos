# eoc::spell:: Components - ARM64 Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

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
| eoc::spell::ModificationContainerComponent | 0x40 | 64 | Spell modifications |
| eoc::spell::PlayerPrepareSpellComponent | 0x18 | 24 | DynamicArray + bool |
| eoc::spell::ScriptedExplosionComponent | 0x04 | 4 | Scripted explosion |
| eoc::spell::SpellInvalidationLockedComponent | 0x01 | 1 | Spell invalidation lock flag |

**Total: 13 components**
