# Component Structures

C structure definitions based on Windows BG3SE reference.

## Core Types

```c
typedef uint64_t EntityHandle;
#define ENTITY_HANDLE_INVALID 0xFFFFFFFFFFFFFFFFULL

typedef struct {
    uint64_t lo;
    uint64_t hi;
} Guid;
```

## ls:: Components

### TransformComponent
```c
typedef struct {
    float position[3];   // x, y, z
    float rotation[4];   // quaternion (x, y, z, w)
    float scale[3];      // x, y, z
} TransformComponent;
```

## eoc:: Components

### StatsComponent (0x94 bytes)
```c
typedef struct {
    int32_t InitiativeBonus;      // +0x00
    int32_t Abilities[7];         // +0x04 (STR, DEX, CON, INT, WIS, CHA, unused)
    int32_t AbilityModifiers[7];  // +0x20
    int32_t Skills[18];           // +0x3C
    int32_t ProficiencyBonus;     // +0x84
    int32_t SpellCastingAbility;  // +0x88 (AbilityId enum)
    int32_t field_8C;
    int32_t field_90;
    int32_t ArmorType;
    int32_t ArmorType2;
    int32_t UnarmedAttackAbility;
    int32_t RangedAttackAbility;
} StatsComponent;
```

### BaseHpComponent (0x08 bytes)
```c
typedef struct {
    int32_t Vitality;       // +0x00 - Base max HP
    int32_t VitalityBoost;  // +0x04 - Bonus max HP
} BaseHpComponent;
```

### HealthComponent
```c
typedef struct {
    int32_t CurrentHp;
    int32_t MaxHp;
    int32_t TempHp;
    // Additional fields TBD
} HealthComponent;
```

### ArmorComponent
```c
typedef struct {
    int32_t ArmorType;          // +0x00
    int32_t ArmorClass;         // +0x04
    int32_t AbilityModifierCap; // +0x08
    uint8_t ArmorClassAbility;  // +0x0C (AbilityId)
    uint8_t EquipmentType;      // +0x0D
} ArmorComponent;
```

### ClassesComponent
```c
typedef struct {
    Guid ClassUUID;
    Guid SubClassUUID;
    int32_t Level;
} ClassInfo;

typedef struct {
    // Dynamic array in practice
    ClassInfo *Classes;
    uint32_t NumClasses;
} ClassesComponent;
```

### WeaponComponent
```c
typedef struct {
    // LegacyRefMap<AbilityId, Array<RollDefinition>> Rolls;
    void *Rolls;
    void *Rolls2;
    float WeaponRange;
    float DamageRange;
    void *WeaponFunctors;
    uint32_t WeaponProperties;
    uint8_t WeaponGroup;
    uint8_t Ability;
    // ... more fields
} WeaponComponent;
```

## Data Structures

### HashMap<Guid, EntityHandle>
```c
typedef struct {
    int32_t *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayInt32;

typedef struct {
    int32_t *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayInt32;

typedef struct {
    Guid *buf;
    uint32_t capacity;
    uint32_t size;
} ArrayGuid;

typedef struct {
    EntityHandle *buf;
    uint32_t size;
    uint32_t _pad;
} StaticArrayEntityHandle;

// Total: 64 bytes
typedef struct {
    StaticArrayInt32 HashKeys;         // +0x00 (bucket table)
    ArrayInt32 NextIds;                // +0x10 (collision chain)
    ArrayGuid Keys;                    // +0x20
    StaticArrayEntityHandle Values;    // +0x30
} HashMapGuidEntityHandle;
```

## Ability IDs

```c
typedef enum {
    ABILITY_STRENGTH = 0,
    ABILITY_DEXTERITY = 1,
    ABILITY_CONSTITUTION = 2,
    ABILITY_INTELLIGENCE = 3,
    ABILITY_WISDOM = 4,
    ABILITY_CHARISMA = 5
} AbilityId;
```

## Skill IDs

```c
typedef enum {
    SKILL_ATHLETICS = 0,
    SKILL_ACROBATICS = 1,
    SKILL_SLEIGHT_OF_HAND = 2,
    SKILL_STEALTH = 3,
    SKILL_ARCANA = 4,
    SKILL_HISTORY = 5,
    SKILL_INVESTIGATION = 6,
    SKILL_NATURE = 7,
    SKILL_RELIGION = 8,
    SKILL_ANIMAL_HANDLING = 9,
    SKILL_INSIGHT = 10,
    SKILL_MEDICINE = 11,
    SKILL_PERCEPTION = 12,
    SKILL_SURVIVAL = 13,
    SKILL_DECEPTION = 14,
    SKILL_INTIMIDATION = 15,
    SKILL_PERFORMANCE = 16,
    SKILL_PERSUASION = 17
} SkillId;
```
