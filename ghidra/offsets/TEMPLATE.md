# Template System Offsets

Documentation of template manager structures and offsets for BG3 macOS ARM64.

**Last Updated:** 2025-12-21
**Game Version:** Patch 7 (macOS ARM64)
**Analysis Tool:** Ghidra + MCP

## Implementation Status

**Global Pointer Capture:** ✅ Working (no hooks needed)
**Template Iteration:** ✅ Working for CacheTemplateManager, LocalCacheTemplates
**Template Properties:** ✅ GUID at +0x10 (FixedString)

**Note:** ARM64 hooking was attempted but failed due to ADRP instruction constraints.
The solution uses direct global pointer reads instead.

## Template Manager Hierarchy

The template system follows a 4-level hierarchy for cascading template lookups:

```
GlobalTemplateBank (root templates from game data)
    ↓
LocalTemplateManager (level-specific templates)
    ↓
CacheTemplateManager (runtime cache)
    ↓
LocalCacheTemplates (level-specific cache)
```

## Discovered Functions

### GlobalTemplateBank

| Function | Address | Signature | Notes |
|----------|---------|-----------|-------|
| Constructor | `0x105f93b08` | `GlobalTemplateBank::GlobalTemplateBank(this)` | Initializes hash maps for templates |
| Destructor | `0x105f93ed8` | `~GlobalTemplateBank()` | |

### GlobalTemplateManager

| Function | Address | Signature | Notes |
|----------|---------|-----------|-------|
| `GetTemplateRaw` | `0x105f96304` | `GetTemplateRaw(this, FixedString const&)` | Primary template lookup; `this` = GlobalTemplateManager* |

**GetTemplateRaw Decompilation Analysis:**
- Takes `FixedString const&` as parameter (FixedString index)
- Uses `g_GlobalTemplateBankType` to select bank type (0, 1, or 2)
- Returns pointer to template or NULL
- Good hook target for auto-capture

### CacheTemplateManagerBase

| Function | Address | Signature | Notes |
|----------|---------|-----------|-------|
| Constructor | `0x105d314b8` | `CacheTemplateManagerBase()` | |
| `CacheTemplate` | `0x105d31ce4` | `CacheTemplate(this, GameObjectTemplate*, FixedString&, FixedString&)` | Caches a template; `this` = CacheTemplateManagerBase* |

### LocalTemplateManager

| Function | Address | Signature | Notes |
|----------|---------|-----------|-------|
| Constructor | `0x106010a70` | `LocalTemplateManager()` | |

### Specialized Template Managers

| Function | Address | Notes |
|----------|---------|-------|
| `RegisterType<AvatarContainerTemplateManager>` | `0x100c67bd4` | TypeContext registration |
| `RegisterType<CampChestTemplateManager>` | `0x100c676f4` | TypeContext registration |
| `CacheTemplateIfNeeded<CharacterTemplate>` | `0x105172b44` | Character template caching |
| `CacheTemplateIfNeeded<ItemTemplate>` | `0x10546b97c` | Item template caching |
| `GetTemplate<CharacterTemplate>` | `0x10341c388` | Character template lookup |
| `GetTemplate<ItemTemplate>` | `0x101bae864` | Item template lookup |

## Global Pointer Offsets (Verified 2025-12-21)

These offsets are relative to the main binary base. Read directly - no hooks needed!

From `CacheTemplateIfNeeded<CharacterTemplate>` at `0x105172b44`:

| Symbol | Offset | Type | Status |
|--------|--------|------|--------|
| `ls::GlobalTemplateManager::m_ptr` | `0x08a88508` | `GlobalTemplateManager*` | ✅ Captured |
| `CacheTemplateManager::m_ptr` | `0x08a309a8` | `CacheTemplateManager*` | ✅ Captured |
| `Level::s_CacheTemplateManager` | `0x08a735d8` | `CacheTemplateManager*` | ✅ Captured |
| `LevelManager::m_ptr` | `0x08a3be40` | `LevelManager*` | Available |
| `g_GlobalTemplateBankType` | - | `char` | Bank type (0, 1, or 2) |

**Usage in Code:**
```c
#define OFFSET_GLOBAL_TEMPLATE_MANAGER_PTR  0x08a88508
#define OFFSET_CACHE_TEMPLATE_MANAGER_PTR   0x08a309a8
#define OFFSET_LEVEL_CACHE_MANAGER_PTR      0x08a735d8

void* read_global_ptr(void* base, uint32_t offset) {
    void** ptr = (void**)((uintptr_t)base + offset);
    return *ptr;  // Returns the singleton pointer
}
```

## CacheTemplateManagerBase Structure (Verified 2025-12-21)

From decompilation of `CacheTemplateManagerBase::GetTemplate`:

| Offset | Type | Purpose |
|--------|------|---------|
| `+0x50` | `void*` | Hash bucket array pointer |
| `+0x58` | `uint32_t` | Bucket count (e.g., 769) |
| `+0x60` | `void*` | Next chain array (collision handling) |
| `+0x70` | `void*` | Key array (TemplateHandle values) |
| `+0x80` | `void*` | **Value array (GameObjectTemplate pointers!)** |
| `+0x98` | `uint32_t` | **Template count** |

**Template Iteration:**
```c
// Read template count
uint32_t count;
safe_memory_read(mgr + 0x98, &count, sizeof(count));

// Read value array pointer
void* value_array;
safe_memory_read(mgr + 0x80, &value_array, sizeof(value_array));

// Iterate templates
for (int i = 0; i < count; i++) {
    GameObjectTemplate* tmpl;
    safe_memory_read(value_array + i * 8, &tmpl, sizeof(tmpl));
    // Validate vtable before use!
}
```

## GameObjectTemplate Structure (Verified 2025-12-21)

Base structure for all template types (ARM64 offsets):

```c
typedef struct {
    void*    vmt;                    // +0x00: Virtual method table
    void*    tags;                   // +0x08: TemplateTagContainer* (unverified)
    uint32_t id_fs;                  // +0x10: FixedString - GUID string! ✅
    uint32_t template_name_fs;       // +0x14: FixedString index (name)
    uint32_t parent_template_id_fs;  // +0x18: FixedString parent ID
    uint32_t template_handle;        // +0x1C: Handle for runtime lookup
    // ... more type-specific fields follow
} GameObjectTemplate;
```

**Key Discovery:** The GUID is stored as a FixedString at offset +0x10, readable via
`Ext.Debug.ReadFixedString(tmpl + 0x10)`.

### VMT Layout (Virtual Methods)

| Index | Method | Notes |
|-------|--------|-------|
| 0 | Destructor | |
| 1 | GetName? | |
| 2 | DebugDump? | |
| 3 | GetType | Returns FixedString* to type name ("character", "item", etc.) |
| 5 | GetTypeId | Returns int* to TypeId |

## GlobalTemplateBank Structure

From constructor decompilation:

```c
typedef struct {
    void*       vmt;              // +0x00: PTR_Visit_10882ef20
    uint32_t    unknown_08;       // +0x08: 0x274d (magic?)
    uint32_t    unknown_18;       // +0x18: 0
    void*       templates_map;    // +0x10: HashMap for templates (size 0x13a68)
    // +0x20: More HashMap fields
    // +0x30: Another HashMap (size 0x9dd8)
    // +0x40: Another HashMap (size 0x9dd8)
    // +0x50: Small HashMap (size 0x128)
    // +0x60: flags 0x100000001
    // +0x68: 0xffffffff
} GlobalTemplateBank;
```

## Hook Strategy - BLOCKED by ARM64 Constraints

**Status:** ❌ Hooking abandoned in favor of global pointer reads.

### Why Hooking Failed

The `GetTemplateRaw` function at `0x105f96304` has an ADRP instruction at offset +0xC:
- Safe hook space: only 8 bytes (from +0x4 to +0xC)
- ARM64 absolute branch requires: 16 bytes
- Result: Hook installation corrupts the ADRP instruction → crash

```
GetTemplateRaw prologue:
+0x00: stp x20, x19, [sp, #-0x20]!
+0x04: stp x29, x30, [sp, #0x10]     ← Safe hook point
+0x08: add x29, sp, #0x10
+0x0C: adrp x8, 0x108a88000          ← PC-relative! Cannot overwrite
```

### Solution: Direct Global Pointer Reads

Instead of hooking, read the singleton pointers directly from the binary:

```c
void* main_base = get_main_binary_base();
void* global_mgr = *(void**)(main_base + 0x08a88508);
void* cache_mgr = *(void**)(main_base + 0x08a309a8);
```

This approach:
- ✅ No crash risk from hook installation
- ✅ No ARM64 instruction analysis needed
- ✅ Works reliably after game initialization
- ⚠️ Pointers are NULL at startup, need lazy initialization

## Related Functions

| Function | Address | Purpose |
|----------|---------|---------|
| `GetTemplateGuid` | `0x101b9fcd4` | Get GUID from template |
| `GetTemplateType` | `0x105c53ea4` | Get template type |
| `GetTemplateRoot` | `0x1004e830c` | Get root template |
| `GetTemplateChild` | `0x1004ea2a4` | Get child template |

## Type IDs

From `CacheTemplateIfNeeded<CharacterTemplate>` decompilation:

- `eoc::CharacterTemplate::TypeID` - Character template type identifier
- Used in VMT call `GetTypeId` (index 5) for type checking

## Notes

1. **Bank Type Selection**: The `g_GlobalTemplateBankType` variable (0, 1, or 2) determines which template bank to use. Type 2 uses thread-local storage via `tls_CurrentBankType`.

2. **Template Caching**: Templates are cached on first access. The `CacheTemplateIfNeeded` functions check if a template needs caching and call `CacheTemplate` if so.

3. **FixedString Keys**: Templates are keyed by FixedString indices, not raw strings. Use `fixed_string_resolve()` to get the string value.

4. **Large Structure Comparisons**: The `CacheTemplateIfNeeded` functions perform extensive field-by-field comparisons to check template equality (hundreds of fields for CharacterTemplate).
