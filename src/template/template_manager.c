/**
 * template_manager.c - Template Manager Implementation for BG3SE-macOS
 *
 * Captures template manager pointers via Frida and provides access for Lua API.
 * Follows the same pattern as staticdata_manager.c.
 */

#include "template_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

// ============================================================================
// Constants and Offsets
// ============================================================================

// Template manager structure offsets (ARM64, discovered via Frida/Ghidra)
// These are placeholder values - need runtime verification!
#define TEMPLATE_MAP_OFFSET          0x08    // Offset to templates HashMap in manager
#define TEMPLATE_MAP_BUCKETS_OFFSET  0x00    // HashMap buckets
#define TEMPLATE_MAP_SIZE_OFFSET     0x10    // HashMap size/count
#define TEMPLATE_MAP_KEYS_OFFSET     0x28    // HashMap keys array
#define TEMPLATE_MAP_VALUES_OFFSET   0x38    // HashMap values array

// Frida capture file paths
#define FRIDA_CAPTURE_DIR            "/tmp"
#define FRIDA_CAPTURE_TEMPLATES      "/tmp/bg3se_templates.txt"
#define FRIDA_CAPTURE_GLOBAL_BANK    "/tmp/bg3se_globalbank.txt"
#define FRIDA_CAPTURE_CACHE_MGR      "/tmp/bg3se_cache_mgr.txt"

// ============================================================================
// Type Name Tables
// ============================================================================

static const char* s_manager_type_names[TEMPLATE_MANAGER_COUNT] = {
    "GlobalTemplateBank",
    "LocalTemplateManager",
    "CacheTemplateManager",
    "LocalCacheTemplates"
};

static const char* s_template_type_names[TEMPLATE_TYPE_COUNT] = {
    "Unknown",
    "Character",
    "Item",
    "Scenery",
    "Surface",
    "Projectile",
    "Decal",
    "Trigger",
    "Prefab",
    "Light"
};

// ============================================================================
// Module State
// ============================================================================

typedef struct {
    bool initialized;
    void* main_binary_base;

    // Captured manager pointers
    void* managers[TEMPLATE_MANAGER_COUNT];

    // Cached template counts (per manager)
    int template_counts[TEMPLATE_MANAGER_COUNT];

    // Captured individual templates (from Frida script)
    void** captured_templates;
    int captured_count;
    int captured_capacity;
} TemplateManagerState;

static TemplateManagerState g_template = {0};

// ============================================================================
// GUID Utilities
// ============================================================================

static bool parse_guid(const char* str, TemplateGuid* out) {
    if (!str || !out) return false;

    // Format: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    unsigned int d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11;

    if (sscanf(str, "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
               &d1, &d2, &d3, &d4, &d5, &d6, &d7, &d8, &d9, &d10, &d11) != 11) {
        return false;
    }

    out->data1 = d1;
    out->data2 = (uint16_t)d2;
    out->data3 = (uint16_t)d3;
    out->data4[0] = (uint8_t)d4;
    out->data4[1] = (uint8_t)d5;
    out->data4[2] = (uint8_t)d6;
    out->data4[3] = (uint8_t)d7;
    out->data4[4] = (uint8_t)d8;
    out->data4[5] = (uint8_t)d9;
    out->data4[6] = (uint8_t)d10;
    out->data4[7] = (uint8_t)d11;

    return true;
}

static void format_guid(const TemplateGuid* guid, char* out, size_t size) {
    if (!guid || !out || size < 37) return;

    snprintf(out, size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid->data1, guid->data2, guid->data3,
             guid->data4[0], guid->data4[1],
             guid->data4[2], guid->data4[3], guid->data4[4],
             guid->data4[5], guid->data4[6], guid->data4[7]);
}

// ============================================================================
// Frida Capture Loading
// ============================================================================

/**
 * Load captured template addresses from Frida output file.
 * File format (from discover_template_managers.js):
 *   # Captured templates
 *   count=N
 *   template[0]=0xADDRESS
 *   template[1]=0xADDRESS
 *   ...
 */
static bool load_captured_templates(void) {
    FILE* f = fopen(FRIDA_CAPTURE_TEMPLATES, "r");
    if (!f) {
        return false;
    }

    char line[256];
    int count = 0;

    // Parse header and count
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#') continue;  // Skip comments

        if (strncmp(line, "count=", 6) == 0) {
            count = atoi(line + 6);
            break;
        }
    }

    if (count <= 0 || count > 100000) {
        log_message("[Template] Invalid template count in capture file: %d", count);
        fclose(f);
        return false;
    }

    // Allocate storage for captured templates
    if (g_template.captured_templates) {
        free(g_template.captured_templates);
    }
    g_template.captured_templates = malloc(count * sizeof(void*));
    if (!g_template.captured_templates) {
        fclose(f);
        return false;
    }
    g_template.captured_capacity = count;
    g_template.captured_count = 0;

    // Parse template addresses
    while (fgets(line, sizeof(line), f) && g_template.captured_count < count) {
        if (strncmp(line, "template[", 9) == 0) {
            char* eq = strchr(line, '=');
            if (eq) {
                void* addr = NULL;
                if (sscanf(eq + 1, "%p", &addr) == 1 ||
                    sscanf(eq + 1, "0x%lx", (unsigned long*)&addr) == 1) {

                    // Validate the address is readable
                    uint64_t test = 0;
                    if (safe_memory_read_u64((mach_vm_address_t)addr, &test)) {
                        g_template.captured_templates[g_template.captured_count++] = addr;
                    }
                }
            }
        }
    }

    fclose(f);

    log_message("[Template] Loaded %d templates from Frida capture (expected %d)",
                g_template.captured_count, count);

    return g_template.captured_count > 0;
}

/**
 * Load captured manager pointer from a specific file.
 */
static void* load_manager_from_file(const char* filepath, const char* manager_name) {
    FILE* f = fopen(filepath, "r");
    if (!f) return NULL;

    char line[256];
    void* ptr = NULL;

    // First line should be the pointer address
    if (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%p", &ptr) != 1 &&
            sscanf(line, "0x%lx", (unsigned long*)&ptr) != 1) {
            ptr = NULL;
        }
    }

    fclose(f);

    if (ptr) {
        // Validate pointer is readable
        uint64_t test = 0;
        if (!safe_memory_read_u64((mach_vm_address_t)ptr, &test)) {
            log_message("[Template] %s pointer %p is not readable", manager_name, ptr);
            return NULL;
        }
        log_message("[Template] Loaded %s from capture: %p", manager_name, ptr);
    }

    return ptr;
}

// ============================================================================
// Initialization
// ============================================================================

bool template_manager_init(void* main_binary_base) {
    if (g_template.initialized) {
        return true;
    }

    g_template.main_binary_base = main_binary_base;

    // Clear manager pointers
    memset(g_template.managers, 0, sizeof(g_template.managers));
    memset(g_template.template_counts, -1, sizeof(g_template.template_counts));

    g_template.initialized = true;
    log_message("[Template] Template manager initialized");

    return true;
}

bool template_manager_ready(void) {
    if (!g_template.initialized) {
        return false;
    }

    // Check if any manager is captured
    for (int i = 0; i < TEMPLATE_MANAGER_COUNT; i++) {
        if (g_template.managers[i]) {
            return true;
        }
    }

    // Also consider ready if we have captured templates
    return g_template.captured_count > 0;
}

// ============================================================================
// Manager Access
// ============================================================================

bool template_has_manager(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return false;
    }
    return g_template.managers[mgr_type] != NULL;
}

void* template_get_manager_ptr(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return NULL;
    }
    return g_template.managers[mgr_type];
}

// ============================================================================
// Template Lookup
// ============================================================================

/**
 * Search captured templates for one matching the given GUID.
 * This is a linear search through Frida-captured template addresses.
 */
static GameObjectTemplate* find_in_captured(const TemplateGuid* guid) {
    if (!guid || g_template.captured_count == 0) return NULL;

    // Linear search through captured templates
    for (int i = 0; i < g_template.captured_count; i++) {
        GameObjectTemplate* tmpl = (GameObjectTemplate*)g_template.captured_templates[i];
        if (!tmpl) continue;

        // Read template's GUID (need to discover offset)
        // For now, assume GUID is at +0x10 (after VMT + tags)
        // This may need adjustment based on actual struct layout
        TemplateGuid tmpl_guid;
        if (!safe_memory_read((mach_vm_address_t)tmpl + 0x10,
                              &tmpl_guid, sizeof(tmpl_guid))) {
            continue;
        }

        if (memcmp(&tmpl_guid, guid, sizeof(TemplateGuid)) == 0) {
            return tmpl;
        }
    }

    return NULL;
}

/**
 * Search a template manager's HashMap for a template.
 * Requires knowing the HashMap layout (buckets, keys, values).
 */
static GameObjectTemplate* find_in_manager(void* manager, const TemplateGuid* guid) {
    if (!manager || !guid) return NULL;

    // TODO: Implement HashMap traversal once we understand the structure
    // For now, use captured templates only

    log_message("[Template] Manager HashMap lookup not yet implemented");
    return NULL;
}

GameObjectTemplate* template_get_by_guid(TemplateManagerType mgr_type, const char* guid_str) {
    TemplateGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }
    return template_get_by_guid_struct(mgr_type, &guid);
}

GameObjectTemplate* template_get_by_guid_struct(TemplateManagerType mgr_type, const TemplateGuid* guid) {
    if (!guid) return NULL;

    // If we have a manager pointer, search it
    void* manager = template_get_manager_ptr(mgr_type);
    if (manager) {
        GameObjectTemplate* tmpl = find_in_manager(manager, guid);
        if (tmpl) return tmpl;
    }

    // Fall back to captured templates
    return find_in_captured(guid);
}

GameObjectTemplate* template_get_by_fixedstring(TemplateManagerType mgr_type, uint32_t fs_id) {
    // TODO: Implement FixedString-based lookup
    // This requires finding the manager's name->template mapping
    (void)mgr_type;
    (void)fs_id;
    return NULL;
}

GameObjectTemplate* template_get(const char* guid_str) {
    TemplateGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }

    // Search order: LocalCache -> Cache -> Local -> Global
    TemplateManagerType search_order[] = {
        TEMPLATE_MANAGER_LOCAL_CACHE,
        TEMPLATE_MANAGER_CACHE,
        TEMPLATE_MANAGER_LOCAL,
        TEMPLATE_MANAGER_GLOBAL_BANK
    };

    for (int i = 0; i < 4; i++) {
        GameObjectTemplate* tmpl = template_get_by_guid_struct(search_order[i], &guid);
        if (tmpl) return tmpl;
    }

    // Also search captured templates (may not be associated with a manager)
    return find_in_captured(&guid);
}

// ============================================================================
// Enumeration
// ============================================================================

int template_get_count(TemplateManagerType mgr_type) {
    if (mgr_type < 0 || mgr_type >= TEMPLATE_MANAGER_COUNT) {
        return -1;
    }

    // If we don't have the manager, return captured count for GLOBAL_BANK
    if (!g_template.managers[mgr_type]) {
        if (mgr_type == TEMPLATE_MANAGER_GLOBAL_BANK && g_template.captured_count > 0) {
            return g_template.captured_count;
        }
        return -1;
    }

    // TODO: Read count from manager structure once we know the offset
    return g_template.template_counts[mgr_type];
}

GameObjectTemplate* template_get_by_index(TemplateManagerType mgr_type, int index) {
    if (index < 0) return NULL;

    // For captured templates (no manager)
    if (!g_template.managers[mgr_type]) {
        if (mgr_type == TEMPLATE_MANAGER_GLOBAL_BANK &&
            index < g_template.captured_count) {
            return (GameObjectTemplate*)g_template.captured_templates[index];
        }
        return NULL;
    }

    // TODO: Implement index-based access from manager
    return NULL;
}

int template_iterate(TemplateManagerType mgr_type, TemplateIterCallback callback, void* userdata) {
    if (!callback) return 0;

    int count = template_get_count(mgr_type);
    if (count <= 0) return 0;

    int iterated = 0;
    for (int i = 0; i < count; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(mgr_type, i);
        if (tmpl) {
            iterated++;
            if (!callback(tmpl, userdata)) {
                break;  // Callback requested stop
            }
        }
    }

    return iterated;
}

// ============================================================================
// Template Property Access
// ============================================================================

bool template_get_guid_string(GameObjectTemplate* tmpl, char* out_buf, size_t buf_size) {
    if (!tmpl || !out_buf || buf_size < 37) return false;

    // GUID is at the id_fs field, but we need to read the actual GUID bytes
    // This may be elsewhere in the structure - need to discover via Frida
    TemplateGuid guid;
    if (!safe_memory_read((mach_vm_address_t)tmpl + 0x10,
                          &guid, sizeof(guid))) {
        return false;
    }

    format_guid(&guid, out_buf, buf_size);
    return true;
}

TemplateType template_get_type(GameObjectTemplate* tmpl) {
    if (!tmpl) return TEMPLATE_TYPE_UNKNOWN;

    // Type is typically determined by VMT
    // TODO: Build VMT -> type mapping via runtime discovery

    // For now, return unknown
    return TEMPLATE_TYPE_UNKNOWN;
}

const char* template_type_to_string(TemplateType type) {
    if (type < 0 || type >= TEMPLATE_TYPE_COUNT) {
        return "Unknown";
    }
    return s_template_type_names[type];
}

uint32_t template_get_id_fs(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t fs = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->id_fs, &fs)) {
        return fs;
    }
    return 0;
}

uint32_t template_get_name_fs(GameObjectTemplate* tmpl) {
    if (!tmpl) return 0;

    uint32_t fs = 0;
    if (safe_memory_read_u32((mach_vm_address_t)&tmpl->template_name_fs, &fs)) {
        return fs;
    }
    return 0;
}

// ============================================================================
// Frida Capture Integration
// ============================================================================

bool template_load_frida_capture(void) {
    log_message("[Template] Loading Frida capture files...");

    bool loaded_any = false;

    // Load captured template addresses
    if (load_captured_templates()) {
        loaded_any = true;
    }

    // Try to load specific manager pointers
    void* global = load_manager_from_file(FRIDA_CAPTURE_GLOBAL_BANK, "GlobalTemplateBank");
    if (global) {
        g_template.managers[TEMPLATE_MANAGER_GLOBAL_BANK] = global;
        loaded_any = true;
    }

    void* cache = load_manager_from_file(FRIDA_CAPTURE_CACHE_MGR, "CacheTemplateManager");
    if (cache) {
        g_template.managers[TEMPLATE_MANAGER_CACHE] = cache;
        loaded_any = true;
    }

    if (loaded_any) {
        log_message("[Template] Frida capture loaded successfully");
    } else {
        log_message("[Template] No Frida capture files found");
    }

    return loaded_any;
}

bool template_frida_capture_available(void) {
    FILE* f = fopen(FRIDA_CAPTURE_TEMPLATES, "r");
    if (f) {
        fclose(f);
        return true;
    }

    f = fopen(FRIDA_CAPTURE_GLOBAL_BANK, "r");
    if (f) {
        fclose(f);
        return true;
    }

    return false;
}

// ============================================================================
// Debugging
// ============================================================================

void template_dump_status(void) {
    log_message("[Template] Template Manager Status:");
    log_message("  Initialized: %s", g_template.initialized ? "yes" : "no");
    log_message("  Binary Base: %p", g_template.main_binary_base);
    log_message("  Captured Templates: %d", g_template.captured_count);

    for (int i = 0; i < TEMPLATE_MANAGER_COUNT; i++) {
        void* mgr = g_template.managers[i];
        if (mgr) {
            log_message("  %s: %p", s_manager_type_names[i], mgr);
        } else {
            log_message("  %s: not captured", s_manager_type_names[i]);
        }
    }
}

void template_dump_entries(TemplateManagerType mgr_type, int max_entries) {
    int count = template_get_count(mgr_type);
    if (count < 0) {
        log_message("[Template] Manager %d not available", mgr_type);
        return;
    }

    int to_dump = (max_entries < 0 || max_entries > count) ? count : max_entries;
    log_message("[Template] Dumping %d of %d templates from %s:",
                to_dump, count, s_manager_type_names[mgr_type]);

    for (int i = 0; i < to_dump; i++) {
        GameObjectTemplate* tmpl = template_get_by_index(mgr_type, i);
        if (!tmpl) continue;

        char guid_str[40];
        if (template_get_guid_string(tmpl, guid_str, sizeof(guid_str))) {
            uint32_t id_fs = template_get_id_fs(tmpl);
            uint32_t name_fs = template_get_name_fs(tmpl);
            log_message("  [%d] %p: GUID=%s, id_fs=0x%x, name_fs=0x%x",
                        i, tmpl, guid_str, id_fs, name_fs);
        } else {
            log_message("  [%d] %p: (could not read properties)", i, tmpl);
        }
    }
}
