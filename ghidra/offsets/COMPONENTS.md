# Component Addresses

## Working Components (ls::)

| Component | GetComponent Address | Status |
|-----------|---------------------|--------|
| `ls::TransformComponent` | `0x10010d5b00` | ✅ Working |
| `ls::LevelComponent` | `0x10010d588c` | ✅ Working |
| `ls::PhysicsComponent` | `0x101ba0898` | ✅ Working |
| `ls::VisualComponent` | `0x102e56350` | ✅ Working |
| `ls::DebugComponent` | `0x101f22d80` | Discovered |
| `ls::CameraComponent` | `0x102f23c1c` | Discovered |
| `ls::EffectComponent` | `0x102ef2018` | Discovered |

## Pending Components (eoc::)

| Component | String Address | GetComponent | Status |
|-----------|----------------|--------------|--------|
| `eoc::StatsComponent` | `0x107b7ca22` | **TBD** | Stub ready |
| `eoc::BaseHpComponent` | `0x107b84c63` | **TBD** | Stub ready |
| `eoc::HealthComponent` | `0x107ba9b5c` | **TBD** | Stub ready |
| `eoc::ArmorComponent` | `0x107b7c9e7` | **TBD** | Stub ready |
| `eoc::ClassesComponent` | `0x107b7ca5d` | **TBD** | Stub ready |
| `eoc::WeaponComponent` | `0x107b7c9ab` | **TBD** | - |
| `eoc::MovementComponent` | `0x107b5debf` | **TBD** | - |

## Discovery Approaches

### 1. Runtime Detection
Hook functions that access these components:
- Damage calculation → Health, Armor, Stats
- Character sheet UI → Stats, Classes
- Combat system → Health, Stats

### 2. Pattern Matching
The ls:: GetComponent functions cluster around `0x10010d5xxx`.
Search for similar instruction patterns in other regions.

### 3. ComponentRegistry
Find the registry that maps ComponentTypeIndex → accessor functions.
Use generic `GetRawComponent(world, handle, typeIndex)`.

## Adding New Components

When an address is discovered:

1. Update `OFFSET_GET_*_COMPONENT` in `entity_system.c`
2. The stub accessor will automatically use it
3. Test with live game to verify structure offsets

```c
// In entity_system.c:
#define OFFSET_GET_STATS_COMPONENT    0x1XXXXXXXX  // Fill in discovered address
```
