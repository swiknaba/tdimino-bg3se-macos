# EOC Core Components - ARM64 Sizes

Core gameplay components from the eoc namespace (not including boost or namespaced components).

Pattern: `ComponentFrameStorageAllocRaw((ComponentFrameStorage*)(this_00 + 0x48), SIZE, ...)`

## Character Data

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::StatsComponent | 0xa0 | 160 | Core stats |
| eoc::HealthComponent | 0x28 | 40 | HP/temp HP |
| eoc::BaseHpComponent | 0x08 | 8 | Base hit points |
| eoc::BaseStatsComponent | 0x1c | 28 | Base stats (STR/DEX/etc) |
| eoc::LevelComponent | 0x04 | 4 | Character level |
| eoc::RaceComponent | 0x10 | 16 | Race data |
| eoc::OriginComponent | 0x18 | 24 | Origin story |
| eoc::BackgroundComponent | 0x10 | 16 | Background |
| eoc::BodyTypeComponent | 0x02 | 2 | Body type enum |
| eoc::CharacterCreationStatsComponent | 0x58 | 88 | Character creation |
| eoc::ClassesComponent | 0x10 | 16 | Class info array |

## Entity State

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ActiveComponent | 0x01 | 1 | Active entity tag |
| eoc::BoundComponent | 0x08 | 8 | Ptr to 0x90 heap |
| eoc::DetachedComponent | 0x04 | 4 | Detached state |
| eoc::ClientControlComponent | 0x01 | 1 | Client control flag |
| eoc::DataComponent | 0x0c | 12 | Generic data |
| eoc::AttributeFlagsComponent | 0x04 | 4 | Attribute flags |
| eoc::OffStageComponent | 0x01 | 1 | Tag - off stage |
| eoc::PlayerComponent | 0x01 | 1 | Tag - is player |

## Names/Display

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::DisplayNameComponent | 0x20 | 32 | Display name (TranslatedString) |
| eoc::CustomNameComponent | 0x10 | 16 | Custom name string |
| eoc::SpeakerComponent | 0x10 | 16 | Dialog speaker |

## Resources/Actions

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ActionResourcesComponent | 0x40 | 64 | Action points, resources |
| eoc::UseComponent | 0x50 | 80 | Usable items |
| eoc::PassiveContainerComponent | 0x10 | 16 | Passive abilities |
| eoc::CustomStatsComponent | 0x18 | 24 | Custom stats map |

## Equipment

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::ArmorComponent | 0x10 | 16 | AC |
| eoc::WeaponComponent | 0x50 | 80 | Weapon data |
| eoc::DisabledEquipmentComponent | 0x01 | 1 | Tag - disabled equip |
| eoc::DisarmableComponent | 0x18 | 24 | Disarmable (GUID) |
| eoc::DualWieldingComponent | 0x07 | 7 | Dual-wield state |
| eoc::EquipableComponent | 0x18 | 24 | Equipable (GUID+slot) |
| eoc::TagComponent | 0x10 | 16 | Entity tags |

## Movement

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::SteeringComponent | 0x20 | 32 | Movement steering |
| eoc::ClimbingComponent | 0x34 | 52 | Climbing state |
| eoc::DeadReckoningComponent | 0x10 | 16 | Network prediction |

## Checks/Difficulty

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::DifficultyCheckComponent | 0x48 | 72 | DC checks (HashTable) |

## Capability Components (eoc::Can*)

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::CanSpeakComponent | 0x02 | 2 | Can speak flag |
| eoc::CanDoActionsComponent | 0x02 | 2 | Can act flag |
| eoc::CanMoveComponent | 0x06 | 6 | Movement flag |
| eoc::CanSenseComponent | 0x02 | 2 | Sensing flag |
| eoc::CanBeDisarmedComponent | 0x02 | 2 | Disarm flag |
| eoc::CanBeLootedComponent | 0x02 | 2 | Loot flag |
| eoc::CanDeflectProjectilesComponent | 0x02 | 2 | Deflect flag |
| eoc::CanDoRestComponent | 0x06 | 6 | Rest flag |
| eoc::CanInteractComponent | 0x04 | 4 | Interact flag |
| eoc::CanModifyHealthComponent | 0x02 | 2 | Health mod flag |
| eoc::CanTravelComponent | 0x06 | 6 | Travel flag |
| eoc::HearingComponent | 0x04 | 4 | Hearing range |

## Turn-Based

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::TurnBasedComponent | 0x30 | 48 | Turn-based state |
| eoc::TurnOrderComponent | 0x50 | 80 | Initiative order |

## Sound

| Component | Hex | Bytes | Notes |
|-----------|-----|-------|-------|
| eoc::TrackedSoundEntityComponent | 0x04 | 4 | Sound entity handle |

## Statistics

- **Total core components:** 52
- **Smallest:** ActiveComponent, ClientControlComponent, OffStageComponent, PlayerComponent (1 byte)
- **Largest:** StatsComponent (160 bytes)
