# Verified ARM64 Component Sizes

Extracted via Ghidra MCP decompilation of `AddComponent<T>` functions.

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Modular Documentation

Component sizes are organized into focused files by namespace:

| File | Contents | Count |
|------|----------|-------|
| [COMPONENT_SIZES_EOC_CORE.md](COMPONENT_SIZES_EOC_CORE.md) | Core eoc:: components (character, entity, capability) | 52 |
| [COMPONENT_SIZES_EOC_BOOST.md](COMPONENT_SIZES_EOC_BOOST.md) | All *BoostComponent classes | 76 |
| [COMPONENT_SIZES_EOC_NAMESPACED.md](COMPONENT_SIZES_EOC_NAMESPACED.md) | 115 sub-namespaces (spell, combat, inventory, analytics, camp, platform, photo_mode, script, sight, shapeshift, splatter, etc.) | 520 |
| [COMPONENT_SIZES_LS.md](COMPONENT_SIZES_LS.md) | Larian shared engine components (cluster, level, light, sound, scene, camera, physics-extended) | 106 |
| [COMPONENT_SIZES_ESV.md](COMPONENT_SIZES_ESV.md) | Server-side components (triggers, ai, camp, timeline, replication) | 160 |
| [COMPONENT_SIZES_ECL.md](COMPONENT_SIZES_ECL.md) | Client-side components (visual, effect, sound, dialog, timeline) | 99 |
| [COMPONENT_SIZES_NAVCLOUD.md](COMPONENT_SIZES_NAVCLOUD.md) | Navigation/pathfinding components (path, region, obstacle) | 17 |

## Statistics

- **Total BG3 components:** 1,999
- **Size-verified via Ghidra:** 1,030 components (Dec 23, 2025)
- **Coverage:** 51.5% of all components
- **AddComponent functions:** ~1,700 (extraction complete)
- **AddComponentUnchecked functions:** ~270 (extraction complete)
- **RemoveComponent functions:** ~500+ (component name discovery)

### By Namespace

| Namespace | Count | Notes |
|-----------|-------|-------|
| eoc:: core | 52 | Character data, entity state, capabilities |
| eoc:: boost | 76 | All boost components (weapon, health, weight, FOV boosts added Wave 7) |
| eoc:: namespaced | 520 | 115 sub-namespaces (item, inventory, spell, spell_cast, combat, analytics, camp, platform, photo_mode, script, sight, shapeshift, splatter, etc.) |
| ls:: | 106 | Engine (cluster, level, light, fog, transform, uuid, anubis, camera, physics-extended) |
| esv:: | 160 | Server-side (triggers, ai, camp, character, hit, timeline, shapeshift) |
| ecl:: | 99 | Client-side (timeline, effect, sound, dialog, inventory, hit, pathing, weapon, use, turnbased) |
| navcloud:: | 17 | Navigation/pathfinding (path, region, obstacle, off-mesh) |

### Size Distribution

| Size | Pattern | Example |
|------|---------|---------|
| 1 byte | Tag/presence marker | IsInCombatComponent, ActiveComponent |
| 2 bytes | Flags/small enum | CanSpeakComponent, CullComponent |
| 4 bytes | Integer/handle | LevelComponent, ArmorClassBoostComponent |
| 8 bytes | Pointer/resource ref | AnimationBlueprintComponent, esv::Character |
| 16 bytes | GUID reference | TagComponent, ClassesComponent |
| 24 bytes | GUID + flags | EquipableComponent, OriginComponent |
| 32-64 bytes | Damage/containers | DamageBonusBoostComponent (40), SocketComponent (64) |
| 80-136 bytes | Events/state | HitNotificationEventOneFrameComponent (80), ConcentrationChangedComponent (136) |
| 150-200 bytes | Complex state | StatsComponent (160), CharacterDefinitionComponent (656) |
| 400-500 bytes | Large events | CastEventOneFrameComponent (448), HitResultEventOneFrameComponent (488) |
| 800+ bytes | Massive containers | BoostsComponent (832 - LARGEST!), CharacterCreatedComponent (992) |

### Architectural Patterns

- **Server (esv::)**: 8-byte pointers to heap allocations (e.g., Projectile ptr → 1464 bytes)
- **Client (ecl::)**: Inline larger structures (e.g., Projectile = 576 bytes inline)
- **Boost components**: Mostly 1-24 bytes, tag components for simple flags
- **OneFrameComponents**: Event-driven ECS pattern for transient state (1-488 bytes)

## Components Not Found via AddComponent

These components may use different patterns:

- eoc::ClassComponent
- eoc::GodComponent
- eoc::AbilityComponent
- eoc::death::DeadComponent
- eoc::death::DyingComponent
- eoc::SightComponent
- eoc::ai::AiComponent
- eoc::movement::MovementComponent
- eoc::EquipmentVisualComponent
- eoc::TransformComponent
- esv::CharacterComponent
- esv::ItemComponent
- eoc::GenderComponent
- eoc::ActivationGroupContainerComponent
- eoc::AliveComponent

## Extraction Methodology

1. Search `AddComponent<T>` functions via Ghidra MCP
2. Decompile each function
3. Extract SIZE from `ComponentFrameStorageAllocRaw(..., SIZE, ...)`
4. Document in appropriate namespace file
