/**
 * template_manager.h - Template Manager for BG3SE-macOS
 *
 * Provides access to game object templates (CharacterTemplate, ItemTemplate, etc.)
 * via captured template manager pointers.
 *
 * Template Hierarchy (from Windows BG3SE):
 *   GlobalTemplateBank -> LocalTemplateManager -> CacheTemplateManager -> LocalCacheTemplates
 */

#ifndef TEMPLATE_MANAGER_H
#define TEMPLATE_MANAGER_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// ============================================================================
// Template Type Enum
// ============================================================================

typedef enum {
    TEMPLATE_TYPE_UNKNOWN = 0,
    TEMPLATE_TYPE_CHARACTER,
    TEMPLATE_TYPE_ITEM,
    TEMPLATE_TYPE_SCENERY,
    TEMPLATE_TYPE_SURFACE,
    TEMPLATE_TYPE_PROJECTILE,
    TEMPLATE_TYPE_DECAL,
    TEMPLATE_TYPE_TRIGGER,
    TEMPLATE_TYPE_PREFAB,
    TEMPLATE_TYPE_LIGHT,
    TEMPLATE_TYPE_COUNT
} TemplateType;

// ============================================================================
// Manager Type Enum
// ============================================================================

typedef enum {
    TEMPLATE_MANAGER_GLOBAL_BANK = 0,     // GlobalTemplateBank (root templates)
    TEMPLATE_MANAGER_LOCAL,               // LocalTemplateManager (level templates)
    TEMPLATE_MANAGER_CACHE,               // CacheTemplateManager (runtime cache)
    TEMPLATE_MANAGER_LOCAL_CACHE,         // LocalCacheTemplates (level cache)
    TEMPLATE_MANAGER_COUNT
} TemplateManagerType;

// ============================================================================
// GameObjectTemplate Structure (simplified, based on Windows BG3SE)
// ============================================================================

/**
 * GUID structure (16 bytes)
 * Same as used in entity system
 */
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} TemplateGuid;

/**
 * GameObjectTemplate base structure (discovered via Ghidra + Frida)
 * All template types inherit from this base.
 *
 * NOTE: ARM64 offsets - may differ from Windows x64!
 */
typedef struct {
    void*    vmt;                    // +0x00: Virtual method table
    void*    tags;                   // +0x08: TemplateTagContainer*
    uint32_t id_fs;                  // +0x10: FixedString index (template ID)
    uint32_t template_name_fs;       // +0x14: FixedString index (name)
    uint32_t parent_template_id_fs;  // +0x18: FixedString parent ID
    uint32_t template_handle;        // +0x1C: Handle for runtime lookup
    // char* name;                   // +0x20: STDString (TODO: verify)
    // ... more type-specific fields follow
} GameObjectTemplate;

// ============================================================================
// Initialization
// ============================================================================

/**
 * Initialize the template manager system.
 * @param main_binary_base Base address of the main BG3 binary
 * @return true on success
 */
bool template_manager_init(void* main_binary_base);

/**
 * Check if template manager is ready (at least one manager captured).
 */
bool template_manager_ready(void);

// ============================================================================
// Manager Access
// ============================================================================

/**
 * Check if a specific template manager has been captured.
 */
bool template_has_manager(TemplateManagerType mgr_type);

/**
 * Get the raw manager pointer (for advanced use).
 */
void* template_get_manager_ptr(TemplateManagerType mgr_type);

// ============================================================================
// Template Access
// ============================================================================

/**
 * Get a template by GUID string from a specific manager.
 * @param mgr_type Which manager to search
 * @param guid_str GUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
 * @return GameObjectTemplate* or NULL
 */
GameObjectTemplate* template_get_by_guid(TemplateManagerType mgr_type, const char* guid_str);

/**
 * Get a template by GUID structure from a specific manager.
 */
GameObjectTemplate* template_get_by_guid_struct(TemplateManagerType mgr_type, const TemplateGuid* guid);

/**
 * Get a template by FixedString ID from a specific manager.
 */
GameObjectTemplate* template_get_by_fixedstring(TemplateManagerType mgr_type, uint32_t fs_id);

/**
 * Cascading template search (searches all managers in order).
 * This is the equivalent of Windows BG3SE GetTemplate().
 * Search order: LocalCache -> Cache -> Local -> Global
 */
GameObjectTemplate* template_get(const char* guid_str);

// ============================================================================
// Enumeration
// ============================================================================

/**
 * Get count of templates in a manager.
 * @return count, or -1 if manager not available
 */
int template_get_count(TemplateManagerType mgr_type);

/**
 * Get template by index from a manager.
 * @return GameObjectTemplate* or NULL
 */
GameObjectTemplate* template_get_by_index(TemplateManagerType mgr_type, int index);

/**
 * Callback type for template iteration
 */
typedef bool (*TemplateIterCallback)(GameObjectTemplate* tmpl, void* userdata);

/**
 * Iterate over all templates in a manager.
 * @param callback Function called for each template; return false to stop
 * @param userdata User data passed to callback
 * @return Number of templates iterated
 */
int template_iterate(TemplateManagerType mgr_type, TemplateIterCallback callback, void* userdata);

// ============================================================================
// Template Property Access
// ============================================================================

/**
 * Get template's GUID as string.
 * @param out_buf Buffer for GUID string (at least 37 bytes)
 * @return true on success
 */
bool template_get_guid_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size);

/**
 * Get template type (Character, Item, etc.)
 * @return TemplateType enum value
 */
TemplateType template_get_type(GameObjectTemplate* tmpl);

/**
 * Get template type name as string.
 */
const char* template_type_to_string(TemplateType type);

/**
 * Get the raw template type string by calling the virtual GetType() function.
 * This returns the actual type name from the game (e.g., "character", "item").
 * @param out_buf Buffer for the type string
 * @param buf_size Size of buffer
 * @return Pointer to buffer on success, NULL on failure
 */
const char* template_get_type_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size);

/**
 * Get the template's FixedString ID (for Ext.Stats correlation).
 */
uint32_t template_get_id_fs(GameObjectTemplate* tmpl);

/**
 * Get the template's FixedString Name.
 */
uint32_t template_get_name_fs(GameObjectTemplate* tmpl);

/**
 * Get the parent template's FixedString ID.
 */
uint32_t template_get_parent_template_id_fs(GameObjectTemplate* tmpl);

/**
 * Get the template's handle (for runtime lookup).
 */
uint32_t template_get_handle(GameObjectTemplate* tmpl);

/**
 * Get the template's ID as a resolved string.
 * @param out_buf Buffer for string (recommended 64+ bytes)
 * @param buf_size Size of buffer
 * @return Pointer to buffer on success, NULL on failure
 */
const char* template_get_id_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size);

/**
 * Get the template's name as a resolved string.
 * @param out_buf Buffer for string (recommended 256+ bytes)
 * @param buf_size Size of buffer
 * @return Pointer to buffer on success, NULL on failure
 */
const char* template_get_template_name_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size);

/**
 * Get the template's parent ID as a resolved string.
 * @param out_buf Buffer for string (recommended 64+ bytes)
 * @param buf_size Size of buffer
 * @return Pointer to buffer on success, NULL on failure
 */
const char* template_get_parent_template_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size);

// ============================================================================
// Frida Capture Integration
// ============================================================================

/**
 * Load captured template manager pointers from Frida capture file.
 * Call this after running the Frida capture script.
 * @return true if any managers were loaded
 */
bool template_load_frida_capture(void);

/**
 * Check if Frida capture file exists.
 */
bool template_frida_capture_available(void);

// ============================================================================
// Auto-Capture Hooks
// ============================================================================

/**
 * Install template manager hooks for auto-capture.
 * Should be called after main binary base is known.
 * Hooks GetTemplateRaw and CacheTemplate to capture manager pointers.
 * @param main_binary_base Base address of the main BG3 binary
 * @return true if at least one hook was installed
 */
bool template_install_hooks(void* main_binary_base);

// ============================================================================
// Debugging
// ============================================================================

/**
 * Dump template manager status to log.
 */
void template_dump_status(void);

/**
 * Dump template entries from a manager.
 */
void template_dump_entries(TemplateManagerType mgr_type, int max_entries);

#endif // TEMPLATE_MANAGER_H
