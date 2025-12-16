/**
 * staticdata_manager.c - StaticData Manager Implementation for BG3SE-macOS
 *
 * Captures static data managers via hooks and provides access for Lua API.
 */

#include "staticdata_manager.h"
#include "../core/logging.h"
#include "../core/safe_memory.h"
#include "../strings/fixed_string.h"
#include <dobby.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

// ============================================================================
// Constants and Offsets (Discovered via Ghidra)
// ============================================================================

// Function addresses (relative to base)
#define OFFSET_FEAT_GETFEATS          0x01b752b4  // FeatManager::GetFeats
#define OFFSET_GETALLFEATS            0x0120b3e8  // GetAllFeats (for context capture)

// ImmutableDataHeadmaster m_State pointer address (for TypeContext traversal)
#define OFFSET_MSTATE_PTR             0x083c4a68  // PTR_m_State - pointer to m_State

// FeatManager structure offsets
// NOTE: TypeContext gives us a METADATA structure, not the real FeatManager.
// We need to probe the metadata to find a pointer to the real FeatManager.
//
// TypeContext metadata structure:
//   +0x00: int32_t count (metadata count, e.g., 37)
//   +0x08-0x78: unknown (probe to find real manager pointer)
//
// Real FeatManager structure (from GetFeats hook):
//   +0x7C: int32_t count
//   +0x80: Feat* array
//
#define FEATMANAGER_REAL_COUNT_OFFSET    0x7C   // Real FeatManager count offset
#define FEATMANAGER_REAL_ARRAY_OFFSET    0x80   // Real FeatManager array offset
#define FEATMANAGER_META_COUNT_OFFSET    0x00   // TypeContext metadata count offset

// Structure offsets (verified via Windows BG3SE GuidResources.h)
// Base class GuidResource: VMT (8) + ResourceUUID (16) = 24 bytes (0x18)
// Then type-specific fields follow

// Feat structure
#define FEAT_SIZE                     0x128  // 296 bytes per feat
#define FEAT_OFFSET_NAME              0x18   // FixedString Name (after GuidResource base)

// Race structure
#define RACE_SIZE                     0x200  // Estimate - has many arrays
#define RACE_OFFSET_NAME              0x18   // FixedString Name (same as Feat)

// Origin structure
// Has uint8_t AvailableInCharacterCreation at +0x18 before Name
#define ORIGIN_SIZE                   0x180  // Estimate
#define ORIGIN_OFFSET_NAME            0x1C   // FixedString Name (aligned after uint8_t)

// Background structure - NO Name field, only DisplayName (TranslatedString)
#define BACKGROUND_SIZE               0x80   // Estimate
#define BACKGROUND_OFFSET_NAME        0      // No FixedString Name field!

// God structure
#define GOD_SIZE                      0x60   // Small structure
#define GOD_OFFSET_NAME               0x18   // FixedString Name

// ClassDescription structure
// Has Guid ParentGuid (16 bytes) at +0x18 before Name
#define CLASS_SIZE                    0x100  // Estimate
#define CLASS_OFFSET_NAME             0x28   // FixedString Name (after ParentGuid)

// ============================================================================
// Manager Configuration (per-type structure info)
// ============================================================================

typedef struct {
    int count_offset;    // Offset to count field in manager
    int array_offset;    // Offset to array pointer in manager
    int entry_size;      // Size of each entry
    int name_offset;     // Offset to Name FixedString in entry (0 = no name)
    const char* capture_file;  // Path to Frida capture file
} ManagerConfig;

static const ManagerConfig g_manager_configs[STATICDATA_COUNT] = {
    // STATICDATA_FEAT
    { 0x7C, 0x80, FEAT_SIZE, FEAT_OFFSET_NAME, "/tmp/bg3se_featmanager.txt" },
    // STATICDATA_RACE
    { 0x7C, 0x80, RACE_SIZE, RACE_OFFSET_NAME, "/tmp/bg3se_racemanager.txt" },
    // STATICDATA_BACKGROUND
    { 0x7C, 0x80, BACKGROUND_SIZE, 0, "/tmp/bg3se_backgroundmanager.txt" },  // No Name
    // STATICDATA_ORIGIN
    { 0x7C, 0x80, ORIGIN_SIZE, ORIGIN_OFFSET_NAME, "/tmp/bg3se_originmanager.txt" },
    // STATICDATA_GOD
    { 0x7C, 0x80, GOD_SIZE, GOD_OFFSET_NAME, "/tmp/bg3se_godmanager.txt" },
    // STATICDATA_CLASS
    { 0x7C, 0x80, CLASS_SIZE, CLASS_OFFSET_NAME, "/tmp/bg3se_classmanager.txt" },
    // STATICDATA_PROGRESSION
    { 0x7C, 0x80, 0x200, 0x18, "/tmp/bg3se_progressionmanager.txt" },
    // STATICDATA_ACTIONRESOURCE
    { 0x7C, 0x80, 0x80, 0x18, "/tmp/bg3se_actionresourcemanager.txt" },
    // STATICDATA_FEATDESCRIPTION
    { 0x7C, 0x80, 0x80, 0, "/tmp/bg3se_featdescmanager.txt" },  // Has TranslatedString, not FixedString
};

// ============================================================================
// Type Name Table
// ============================================================================

static const char* s_type_names[STATICDATA_COUNT] = {
    "Feat",
    "Race",
    "Background",
    "Origin",
    "God",
    "Class",
    "Progression",
    "ActionResource",
    "FeatDescription"
};

// Manager type names as they appear in TypeContext (for name-based capture)
static const char* s_manager_type_names[STATICDATA_COUNT] = {
    "eoc::FeatManager",
    "eoc::RaceManager",
    "eoc::BackgroundManager",
    "eoc::OriginManager",
    "eoc::GodManager",
    "eoc::ClassManager",
    "eoc::ProgressionManager",
    "eoc::ActionResourceManager",
    "eoc::FeatDescriptionManager"
};

// ============================================================================
// Module State
// ============================================================================

static struct {
    bool initialized;
    void* main_binary_base;

    // Captured manager pointers (from TypeContext - metadata structures)
    void* managers[STATICDATA_COUNT];

    // Real manager pointers (probed from metadata or captured via hooks)
    void* real_managers[STATICDATA_COUNT];

    // Original function pointers (for hooks)
    void* orig_feat_getfeats;
} g_staticdata = {0};

// ============================================================================
// TypeContext Traversal (Alternative capture method)
// ============================================================================

/**
 * TypeInfo structure in ImmutableDataHeadmaster TypeContext
 */
typedef struct TypeInfo {
    void*    manager_ptr;     // +0x00: Pointer to manager instance
    void*    type_name;       // +0x08: FixedString or char* type name
    uint32_t name_length;     // +0x10: Type name length
    uint32_t padding;         // +0x14: Padding
    struct TypeInfo* next;    // +0x18: Next TypeInfo in list
} TypeInfo;

// ============================================================================
// Real Manager Discovery (Probing)
// ============================================================================

/**
 * Check if a pointer looks like a valid FeatManager.
 * Valid FeatManager has:
 *   - count at +0x7C: reasonable value (1-1000)
 *   - array at +0x80: non-null pointer to heap
 * Uses safe memory reads to prevent crashes.
 */
static bool looks_like_real_feat_manager(void* ptr) {
    if (!ptr) return false;

    // Safely read count at +0x7C
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)ptr + FEATMANAGER_REAL_COUNT_OFFSET, &count)) {
        return false;  // Memory not readable
    }

    // Count should be reasonable (37 feats expected, allow some margin)
    if (count <= 0 || count > 1000) return false;

    // Safely read array pointer at +0x80
    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)ptr + FEATMANAGER_REAL_ARRAY_OFFSET, &array)) {
        return false;  // Memory not readable
    }

    // Array pointer should be non-null and look like a heap address
    if (!array) return false;
    uintptr_t arr_addr = (uintptr_t)array;

    // Heap addresses on macOS are typically > 0x600000000000
    // But code pointers are ~0x100000000
    // Allow anything that's not obviously wrong
    if (arr_addr < 0x100000000ULL) return false;

    return true;
}

/**
 * Try to find the real FeatManager by probing the TypeContext metadata structure.
 * The metadata might contain a pointer to the real manager.
 * Uses safe memory reads to prevent crashes.
 */
static void* probe_for_real_feat_manager(void* metadata) {
    if (!metadata) return NULL;

    log_message("[StaticData] Probing metadata %p for real FeatManager...", metadata);

    // First check: is the metadata itself the real manager?
    if (looks_like_real_feat_manager(metadata)) {
        int32_t count = 0;
        safe_memory_read_i32((mach_vm_address_t)metadata + FEATMANAGER_REAL_COUNT_OFFSET, &count);
        log_message("[StaticData] Metadata IS the real FeatManager (count@+0x7C=%d)", count);
        return metadata;
    }

    // Safely read metadata count at +0x00 (should be 37 for feats)
    int32_t meta_count = 0;
    if (safe_memory_read_i32((mach_vm_address_t)metadata + FEATMANAGER_META_COUNT_OFFSET, &meta_count)) {
        log_message("[StaticData] Metadata count@+0x00=%d", meta_count);
    } else {
        log_message("[StaticData] Could not read metadata count at +0x00");
    }

    // Probe for pointers at various offsets that could point to real manager
    // Common offsets: +0x08, +0x10, +0x18, +0x20, +0x28, +0x30, etc.
    int offsets_to_probe[] = {0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40,
                              0x48, 0x50, 0x58, 0x60, 0x68, 0x70, 0x78};
    int num_offsets = sizeof(offsets_to_probe) / sizeof(offsets_to_probe[0]);

    for (int i = 0; i < num_offsets; i++) {
        int offset = offsets_to_probe[i];
        void* candidate = NULL;

        // Safely read the candidate pointer
        if (!safe_memory_read_pointer((mach_vm_address_t)metadata + offset, &candidate)) {
            continue;  // Memory not readable at this offset
        }

        if (candidate && looks_like_real_feat_manager(candidate)) {
            int32_t count = 0;
            void* array = NULL;
            safe_memory_read_i32((mach_vm_address_t)candidate + FEATMANAGER_REAL_COUNT_OFFSET, &count);
            safe_memory_read_pointer((mach_vm_address_t)candidate + FEATMANAGER_REAL_ARRAY_OFFSET, &array);
            log_message("[StaticData] FOUND real FeatManager at metadata+0x%02X: %p (count=%d, array=%p)",
                        offset, candidate, count, array);
            return candidate;
        }
    }

    log_message("[StaticData] Could not find real FeatManager from metadata");
    return NULL;
}

/**
 * Capture all known managers by traversing the ImmutableDataHeadmaster TypeContext.
 * The type_name field is a raw C string pointer (verified at runtime).
 * Returns number of managers captured.
 * Uses safe memory reads to prevent crashes.
 */
static int capture_managers_via_typecontext(void) {
    if (!g_staticdata.main_binary_base) {
        return 0;
    }

    // Safely get pointer to m_State
    void* m_state = NULL;
    mach_vm_address_t ptr_mstate_addr = (mach_vm_address_t)g_staticdata.main_binary_base + OFFSET_MSTATE_PTR;
    if (!safe_memory_read_pointer(ptr_mstate_addr, &m_state)) {
        log_message("[StaticData] Could not read m_State pointer at %p", (void*)ptr_mstate_addr);
        return 0;
    }
    if (!m_state) {
        log_message("[StaticData] m_State is NULL - TypeContext not available yet");
        return 0;
    }

    log_message("[StaticData] TypeContext traversal: m_State at %p", m_state);

    // Safely read TypeInfo head at m_State + 8
    TypeInfo* typeinfo = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)m_state + 8, (void**)&typeinfo)) {
        log_message("[StaticData] Could not read TypeInfo head pointer");
        return 0;
    }

    int captured = 0;
    int count = 0;
    while (typeinfo && count < 200) {  // Safety limit (100+ managers exist)
        // Safely read TypeInfo fields
        void* manager_ptr = NULL;
        void* type_name_ptr = NULL;
        TypeInfo* next_ptr = NULL;

        if (!safe_memory_read_pointer((mach_vm_address_t)&typeinfo->manager_ptr, &manager_ptr) ||
            !safe_memory_read_pointer((mach_vm_address_t)&typeinfo->type_name, &type_name_ptr) ||
            !safe_memory_read_pointer((mach_vm_address_t)&typeinfo->next, (void**)&next_ptr)) {
            log_message("[StaticData] Could not read TypeInfo fields at %p, stopping traversal", typeinfo);
            break;
        }

        // Check if this TypeInfo has a valid manager and name
        if (manager_ptr && type_name_ptr) {
            // Safely read type name string (up to 128 chars)
            char name[128] = {0};
            if (safe_memory_read_string((mach_vm_address_t)type_name_ptr, name, sizeof(name))) {
                // Log first 20 entries and any containing "Feat" or "Manager"
                if (count < 20 || strstr(name, "Feat") || strstr(name, "Manager")) {
                    log_message("[StaticData] TypeInfo[%d]: %s @ %p", count, name, manager_ptr);
                }

                // Try to match against known manager names
                for (int i = 0; i < STATICDATA_COUNT; i++) {
                    // Only capture if not already captured
                    if (!g_staticdata.managers[i] && strcmp(name, s_manager_type_names[i]) == 0) {
                        g_staticdata.managers[i] = manager_ptr;
                        log_message("[StaticData] Captured %s metadata: %p", s_type_names[i], manager_ptr);

                        // For FeatManager, probe to find the real manager
                        if (i == STATICDATA_FEAT) {
                            void* real_mgr = probe_for_real_feat_manager(manager_ptr);
                            if (real_mgr) {
                                g_staticdata.real_managers[i] = real_mgr;
                            }
                        }

                        captured++;
                        break;
                    }
                }
            }
        }

        typeinfo = next_ptr;
        count++;
    }

    log_message("[StaticData] TypeContext traversal: scanned %d entries, captured %d managers", count, captured);
    return captured;
}

/**
 * Legacy function for debugging - traverses and logs all TypeInfo entries.
 */
static void* find_manager_via_typecontext(const char* type_name) {
    if (!g_staticdata.main_binary_base || !type_name) {
        return NULL;
    }

    // Get pointer to m_State
    void** ptr_mstate = (void**)((uint8_t*)g_staticdata.main_binary_base + OFFSET_MSTATE_PTR);
    void* m_state = *ptr_mstate;
    if (!m_state) {
        log_message("[StaticData] m_State is NULL");
        return NULL;
    }

    log_message("[StaticData] m_State at %p", m_state);

    // TypeInfo head is at m_State + 8
    TypeInfo* typeinfo = *(TypeInfo**)((uint8_t*)m_state + 8);

    int count = 0;
    while (typeinfo && count < 200) {  // Safety limit
        // Check if this TypeInfo has a valid manager
        if (typeinfo->manager_ptr && typeinfo->type_name) {
            // type_name is a raw C string (verified at runtime)
            const char* name = (const char*)typeinfo->type_name;
            log_message("[StaticData] TypeInfo[%d]: mgr=%p, name=%s",
                        count, typeinfo->manager_ptr, name);
        }

        typeinfo = typeinfo->next;
        count++;
    }

    log_message("[StaticData] Traversed %d TypeInfo entries", count);
    return NULL;
}

// ============================================================================
// Hook Functions
// ============================================================================

/**
 * Hook for FeatManager::GetFeats
 * Signature: void GetFeats(OutputArray* out, FeatManager* this)
 * On ARM64: x0 = out, x1 = FeatManager*
 */
typedef void (*FeatGetFeats_t)(void* out, void* feat_manager);
static FeatGetFeats_t g_orig_FeatGetFeats = NULL;

static void hook_FeatGetFeats(void* out, void* feat_manager) {
    // Capture FeatManager pointer
    if (feat_manager && !g_staticdata.managers[STATICDATA_FEAT]) {
        g_staticdata.managers[STATICDATA_FEAT] = feat_manager;
        log_message("[StaticData] Captured FeatManager via GetFeats hook: %p", feat_manager);

        // Log structure info using GetFeats-verified offsets (0x7C, 0x80)
        int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_REAL_COUNT_OFFSET);
        void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_REAL_ARRAY_OFFSET);
        log_message("[StaticData] FeatManager structure: count@+0x7C=%d, array@+0x80=%p", count, array);

        // Verify by reading first feat entry
        if (array && count > 0) {
            uint8_t* first_feat = (uint8_t*)array;
            log_message("[StaticData] First feat at %p, first 16 bytes: %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                first_feat,
                first_feat[0], first_feat[1], first_feat[2], first_feat[3],
                first_feat[4], first_feat[5], first_feat[6], first_feat[7],
                first_feat[8], first_feat[9], first_feat[10], first_feat[11],
                first_feat[12], first_feat[13], first_feat[14], first_feat[15]);
        }
    }

    // Call original
    if (g_orig_FeatGetFeats) {
        g_orig_FeatGetFeats(out, feat_manager);
    }
}

/**
 * Hook for GetAllFeats (called from character creation UI)
 * Signature: void GetAllFeats(Environment* param_1)
 * The FeatManager is at param_1 + 0x130
 */
typedef void (*GetAllFeats_t)(void* environment);
static GetAllFeats_t g_orig_GetAllFeats = NULL;

static void hook_GetAllFeats(void* environment) {
    log_message("[StaticData] GetAllFeats called with env=%p", environment);

    // Try to capture FeatManager from environment + 0x130
    if (environment && !g_staticdata.managers[STATICDATA_FEAT]) {
        void* feat_manager = *(void**)((uint8_t*)environment + 0x130);
        if (feat_manager) {
            g_staticdata.managers[STATICDATA_FEAT] = feat_manager;
            log_message("[StaticData] Captured FeatManager from env+0x130: %p", feat_manager);

            // Log structure info
            int32_t count = *(int32_t*)((uint8_t*)feat_manager + FEATMANAGER_REAL_COUNT_OFFSET);
            void* array = *(void**)((uint8_t*)feat_manager + FEATMANAGER_REAL_ARRAY_OFFSET);
            log_message("[StaticData] FeatManager: count=%d, array=%p", count, array);
        }
    }

    // Call original
    if (g_orig_GetAllFeats) {
        g_orig_GetAllFeats(environment);
    }
}

// ============================================================================
// Initialization
// ============================================================================

bool staticdata_manager_init(void *main_binary_base) {
    if (g_staticdata.initialized) {
        return true;
    }

    g_staticdata.main_binary_base = main_binary_base;

    // Clear manager pointers
    memset(g_staticdata.managers, 0, sizeof(g_staticdata.managers));

    // NOTE: GetFeats/GetAllFeats hooks DISABLED - they break feat selection UI
    // The hook intercepts correctly but breaks the original function call.
    // For now, use TypeContext capture for FeatManager instead.
    // TODO: Debug why original function call fails after hook

    log_message("[StaticData] GetFeats hooks DISABLED (broke feat UI) - using TypeContext only");

    g_staticdata.initialized = true;
    log_message("[StaticData] Static data manager initialized");

    return true;
}

bool staticdata_manager_ready(void) {
    if (!g_staticdata.initialized) {
        return false;
    }

    // Check if at least one manager is captured
    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (g_staticdata.managers[i]) {
            return true;
        }
    }

    return false;
}

const char* staticdata_type_name(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return NULL;
    }
    return s_type_names[type];
}

int staticdata_type_from_name(const char* name) {
    if (!name) return -1;

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        if (strcasecmp(s_type_names[i], name) == 0) {
            return i;
        }
    }

    return -1;
}

// ============================================================================
// Manager Access
// ============================================================================

bool staticdata_has_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return false;
    }

    // If not captured yet, try TypeContext capture (lazy initialization)
    if (!g_staticdata.managers[type] && g_staticdata.initialized) {
        capture_managers_via_typecontext();
    }

    return g_staticdata.managers[type] != NULL;
}

void* staticdata_get_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return NULL;
    }
    return g_staticdata.managers[type];
}

bool staticdata_capture_manager(StaticDataType type) {
    // TODO: Call known accessor functions to trigger hook capture
    // For now, managers are captured lazily when game code calls them
    return staticdata_has_manager(type);
}

// ============================================================================
// Data Access - FeatManager specific
// ============================================================================

/**
 * Get the effective FeatManager pointer and determine which offsets to use.
 * Prefers real_managers (has real data) over managers (metadata only).
 */
static void* get_effective_feat_manager(bool* is_real) {
    // Prefer real manager if available
    if (g_staticdata.real_managers[STATICDATA_FEAT]) {
        if (is_real) *is_real = true;
        return g_staticdata.real_managers[STATICDATA_FEAT];
    }

    // Fall back to metadata
    if (g_staticdata.managers[STATICDATA_FEAT]) {
        if (is_real) *is_real = false;
        return g_staticdata.managers[STATICDATA_FEAT];
    }

    return NULL;
}

static int feat_get_count(void) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr) return -1;

    // Use correct offset based on manager type
    int offset = is_real ? FEATMANAGER_REAL_COUNT_OFFSET : FEATMANAGER_META_COUNT_OFFSET;
    return *(int32_t*)((uint8_t*)mgr + offset);
}

static void* feat_get_by_index(int index) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr) return NULL;

    // Can only get entries from real manager (metadata has no array)
    if (!is_real) {
        log_message("[StaticData] Cannot get feat by index - only metadata captured, not real manager");
        return NULL;
    }

    // Use safe memory reads to prevent crashes
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + FEATMANAGER_REAL_COUNT_OFFSET, &count)) {
        log_message("[StaticData] Cannot read feat count at %p+0x%x", mgr, FEATMANAGER_REAL_COUNT_OFFSET);
        return NULL;
    }
    if (index < 0 || index >= count) return NULL;

    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + FEATMANAGER_REAL_ARRAY_OFFSET, &array)) {
        log_message("[StaticData] Cannot read feat array at %p+0x%x", mgr, FEATMANAGER_REAL_ARRAY_OFFSET);
        return NULL;
    }
    if (!array) return NULL;

    // Calculate entry address - each feat is FEAT_SIZE bytes
    void* entry = (uint8_t*)array + (index * FEAT_SIZE);

    // Verify the entry address is readable before returning
    int32_t test_read = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)entry, &test_read)) {
        log_message("[StaticData] Feat entry %d at %p is not readable (array=%p, size=%d)",
                    index, entry, array, FEAT_SIZE);
        return NULL;
    }

    return entry;
}

static void* feat_get_by_guid(const StaticDataGuid* guid) {
    bool is_real = false;
    void* mgr = get_effective_feat_manager(&is_real);
    if (!mgr || !guid) return NULL;

    // Can only search from real manager
    if (!is_real) {
        log_message("[StaticData] Cannot get feat by GUID - only metadata captured");
        return NULL;
    }

    int32_t count = *(int32_t*)((uint8_t*)mgr + FEATMANAGER_REAL_COUNT_OFFSET);
    void* array = *(void**)((uint8_t*)mgr + FEATMANAGER_REAL_ARRAY_OFFSET);
    if (!array) return NULL;

    // Linear search through feats comparing GUIDs
    // GUID is at offset +0x08 in each feat (after VMT pointer)
    for (int i = 0; i < count; i++) {
        void* entry = (uint8_t*)array + (i * FEAT_SIZE);
        // GUID starts at +0x08 (after 8-byte VMT/header)
        if (memcmp((uint8_t*)entry + 0x08, guid, sizeof(StaticDataGuid)) == 0) {
            return entry;
        }
    }

    return NULL;
}

// ============================================================================
// Data Access - Generic (config-based)
// ============================================================================

/**
 * Get effective manager pointer for a type.
 * Prefers real_managers over metadata managers.
 */
static void* get_effective_manager(StaticDataType type, bool* is_real) {
    if (type < 0 || type >= STATICDATA_COUNT) return NULL;

    // Prefer real manager if available
    if (g_staticdata.real_managers[type]) {
        if (is_real) *is_real = true;
        return g_staticdata.real_managers[type];
    }

    // Fall back to metadata
    if (g_staticdata.managers[type]) {
        if (is_real) *is_real = false;
        return g_staticdata.managers[type];
    }

    return NULL;
}

/**
 * Generic count getter using config.
 */
static int generic_get_count(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) return -1;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr) return -1;

    const ManagerConfig* config = &g_manager_configs[type];
    int offset = is_real ? config->count_offset : FEATMANAGER_META_COUNT_OFFSET;

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + offset, &count)) {
        return -1;
    }
    return count;
}

/**
 * Generic entry getter by index using config.
 */
static void* generic_get_by_index(StaticDataType type, int index) {
    if (type < 0 || type >= STATICDATA_COUNT) return NULL;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr) return NULL;

    // Can only get entries from real manager (metadata has no array)
    if (!is_real) {
        return NULL;
    }

    const ManagerConfig* config = &g_manager_configs[type];

    // Read count
    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + config->count_offset, &count)) {
        return NULL;
    }
    if (index < 0 || index >= count) return NULL;

    // Read array pointer
    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + config->array_offset, &array)) {
        return NULL;
    }
    if (!array) return NULL;

    // Calculate entry address
    void* entry = (uint8_t*)array + (index * config->entry_size);

    // Verify the entry address is readable
    int32_t test_read = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)entry, &test_read)) {
        return NULL;
    }

    return entry;
}

/**
 * Generic GUID lookup using config.
 */
static void* generic_get_by_guid(StaticDataType type, const StaticDataGuid* guid) {
    if (type < 0 || type >= STATICDATA_COUNT || !guid) return NULL;

    bool is_real = false;
    void* mgr = get_effective_manager(type, &is_real);
    if (!mgr || !is_real) return NULL;

    const ManagerConfig* config = &g_manager_configs[type];

    int32_t count = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + config->count_offset, &count)) {
        return NULL;
    }

    void* array = NULL;
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + config->array_offset, &array)) {
        return NULL;
    }
    if (!array) return NULL;

    // Linear search through entries comparing GUIDs
    // GUID is at offset +0x08 in each entry (after VMT pointer)
    for (int i = 0; i < count; i++) {
        void* entry = (uint8_t*)array + (i * config->entry_size);

        // Read and compare GUID at +0x08
        uint8_t guid_bytes[16];
        bool readable = true;
        for (int j = 0; j < 16 && readable; j++) {
            if (!safe_memory_read_u8((mach_vm_address_t)entry + 0x08 + j, &guid_bytes[j])) {
                readable = false;
            }
        }

        if (readable && memcmp(guid_bytes, guid, sizeof(StaticDataGuid)) == 0) {
            return entry;
        }
    }

    return NULL;
}

int staticdata_get_count(StaticDataType type) {
    // Use feat-specific for backwards compatibility, generic for others
    if (type == STATICDATA_FEAT) {
        return feat_get_count();
    }
    return generic_get_count(type);
}

StaticDataPtr staticdata_get_by_index(StaticDataType type, int index) {
    if (type == STATICDATA_FEAT) {
        return feat_get_by_index(index);
    }
    return generic_get_by_index(type, index);
}

StaticDataPtr staticdata_get_by_guid(StaticDataType type, const StaticDataGuid* guid) {
    if (type == STATICDATA_FEAT) {
        return feat_get_by_guid(guid);
    }
    return generic_get_by_guid(type, guid);
}

// ============================================================================
// GUID Parsing
// ============================================================================

static bool parse_guid(const char* str, StaticDataGuid* out) {
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

StaticDataPtr staticdata_get_by_guid_string(StaticDataType type, const char* guid_str) {
    StaticDataGuid guid;
    if (!parse_guid(guid_str, &guid)) {
        return NULL;
    }
    return staticdata_get_by_guid(type, &guid);
}

// ============================================================================
// Entry Property Access
// ============================================================================

bool staticdata_get_guid(StaticDataType type, StaticDataPtr entry, StaticDataGuid* out_guid) {
    if (!entry || !out_guid) return false;

    // GUID is at +0x08 in the Feat structure (after 8-byte VMT header)
    // Different static data types may have different layouts
    int guid_offset = 0x08;  // Default: after VMT
    switch (type) {
        case STATICDATA_FEAT:
            guid_offset = 0x08;  // Verified via Ghidra
            break;
        default:
            guid_offset = 0x08;  // TODO: Verify for other types
            break;
    }

    // Use safe memory read to prevent crashes
    uint8_t guid_bytes[16];
    mach_vm_address_t guid_addr = (mach_vm_address_t)entry + guid_offset;

    // Read GUID bytes safely (16 bytes = sizeof(StaticDataGuid))
    for (int i = 0; i < 16; i++) {
        uint8_t byte = 0;
        if (!safe_memory_read_u8(guid_addr + i, &byte)) {
            log_message("[StaticData] Cannot read GUID byte %d at %p", i, (void*)(guid_addr + i));
            return false;
        }
        guid_bytes[i] = byte;
    }

    memcpy(out_guid, guid_bytes, sizeof(StaticDataGuid));
    return true;
}

bool staticdata_get_guid_string(StaticDataType type, StaticDataPtr entry, char* out_buf, size_t buf_size) {
    if (!entry || !out_buf || buf_size < 37) return false;

    StaticDataGuid guid;
    if (!staticdata_get_guid(type, entry, &guid)) {
        return false;
    }

    snprintf(out_buf, buf_size, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             guid.data1, guid.data2, guid.data3,
             guid.data4[0], guid.data4[1],
             guid.data4[2], guid.data4[3], guid.data4[4],
             guid.data4[5], guid.data4[6], guid.data4[7]);

    return true;
}

const char* staticdata_get_name(StaticDataType type, StaticDataPtr entry) {
    if (!entry) return NULL;

    // Name offset depends on type - different layouts per GuidResource subclass
    int name_offset = 0;

    switch (type) {
        case STATICDATA_FEAT:
            name_offset = FEAT_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_RACE:
            name_offset = RACE_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_ORIGIN:
            name_offset = ORIGIN_OFFSET_NAME;  // 0x1C (after uint8_t)
            break;
        case STATICDATA_BACKGROUND:
            // Background has no FixedString Name - only TranslatedString DisplayName
            return NULL;
        case STATICDATA_GOD:
            name_offset = GOD_OFFSET_NAME;  // 0x18
            break;
        case STATICDATA_CLASS:
            name_offset = CLASS_OFFSET_NAME;  // 0x28 (after ParentGuid)
            break;
        default:
            name_offset = 0x18;  // Default assumption
            break;
    }

    if (name_offset == 0) {
        return NULL;  // Type has no Name field
    }

    // Read FixedString index safely
    uint32_t fs_index = 0;
    if (!safe_memory_read_u32((mach_vm_address_t)entry + name_offset, &fs_index)) {
        log_message("[StaticData] Cannot read name FixedString at %p+0x%x", entry, name_offset);
        return NULL;
    }

    // Check for null/invalid index
    if (fs_index == 0 || fs_index == 0xFFFFFFFF) {
        return NULL;
    }

    // Resolve via GlobalStringTable
    const char* name = fixed_string_resolve(fs_index);
    if (!name) {
        // Log once per session for debugging
        static int logged_failures = 0;
        if (logged_failures < 5) {
            log_message("[StaticData] Failed to resolve FixedString 0x%08X for %s entry at %p",
                        fs_index, staticdata_type_name(type), entry);
            logged_failures++;
        }
    }

    return name;
}

const char* staticdata_get_display_name(StaticDataType type, StaticDataPtr entry) {
    // TODO: Implement localized name lookup
    (void)type;
    (void)entry;
    return NULL;
}

// ============================================================================
// File-Based Frida Capture Integration
// ============================================================================

/**
 * Generic capture loader for any manager type.
 * File format:
 *   Line 1: Manager pointer (hex)
 *   Line 2: Count
 *   Line 3: Array pointer (hex)
 */
static bool load_captured_manager(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) return false;

    const ManagerConfig* config = &g_manager_configs[type];
    const char* capture_file = config->capture_file;

    FILE* f = fopen(capture_file, "r");
    if (!f) {
        return false;
    }

    char line1[64], line2[64], line3[64];
    if (!fgets(line1, sizeof(line1), f) ||
        !fgets(line2, sizeof(line2), f) ||
        !fgets(line3, sizeof(line3), f)) {
        fclose(f);
        return false;
    }
    fclose(f);

    // Parse pointer addresses
    void* mgr = NULL;
    int count = 0;
    void* array = NULL;

    if (sscanf(line1, "%p", &mgr) != 1 && sscanf(line1, "0x%lx", (unsigned long*)&mgr) != 1) {
        log_message("[StaticData] Failed to parse %s pointer from capture file", s_type_names[type]);
        return false;
    }
    count = atoi(line2);
    if (sscanf(line3, "%p", &array) != 1 && sscanf(line3, "0x%lx", (unsigned long*)&array) != 1) {
        log_message("[StaticData] Failed to parse %s array pointer from capture file", s_type_names[type]);
        return false;
    }

    // Validate the captured data
    if (!mgr || count <= 0 || count > 10000 || !array) {
        log_message("[StaticData] Invalid %s captured data: mgr=%p count=%d array=%p",
                    s_type_names[type], mgr, count, array);
        return false;
    }

    // Verify the pointers are still valid using type-specific offsets
    int32_t verify_count = 0;
    void* verify_array = NULL;
    if (!safe_memory_read_i32((mach_vm_address_t)mgr + config->count_offset, &verify_count) ||
        !safe_memory_read_pointer((mach_vm_address_t)mgr + config->array_offset, &verify_array)) {
        log_message("[StaticData] Captured %s pointer no longer valid (game restarted?)", s_type_names[type]);
        return false;
    }

    if (verify_count != count || verify_array != array) {
        log_message("[StaticData] Captured %s data mismatch (count=%d vs %d, array=%p vs %p)",
                    s_type_names[type], verify_count, count, verify_array, array);
        // Use the verified values instead
        count = verify_count;
        array = verify_array;
    }

    // Store as real manager
    g_staticdata.real_managers[type] = mgr;
    log_message("[StaticData] Loaded REAL %s from capture file: %p (count=%d, array=%p)",
                s_type_names[type], mgr, count, array);

    return true;
}

// Legacy wrapper for FeatManager
static bool load_captured_featmanager(void) {
    return load_captured_manager(STATICDATA_FEAT);
}

/**
 * Lua-callable function to load captured managers from Frida.
 * Call this after running the Frida capture script.
 */
bool staticdata_load_frida_capture(void) {
    const char* capture_file = g_manager_configs[STATICDATA_FEAT].capture_file;
    log_message("[StaticData] Attempting to load Frida capture from %s", capture_file);
    return load_captured_featmanager();
}

/**
 * Load captured manager pointers for a specific type.
 */
bool staticdata_load_frida_capture_type(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        log_message("[StaticData] Invalid type %d for LoadFridaCapture", type);
        return false;
    }
    const char* capture_file = g_manager_configs[type].capture_file;
    log_message("[StaticData] Attempting to load %s capture from %s",
                s_type_names[type], capture_file);
    return load_captured_manager(type);
}

/**
 * Check if Frida capture is available (file exists and is recent).
 */
bool staticdata_frida_capture_available(void) {
    const char* capture_file = g_manager_configs[STATICDATA_FEAT].capture_file;
    FILE* f = fopen(capture_file, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

/**
 * Check if Frida capture is available for a specific type.
 */
bool staticdata_frida_capture_available_type(StaticDataType type) {
    if (type < 0 || type >= STATICDATA_COUNT) {
        return false;
    }
    const char* capture_file = g_manager_configs[type].capture_file;
    FILE* f = fopen(capture_file, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

// ============================================================================
// Debugging
// ============================================================================

void staticdata_try_typecontext_capture(void) {
    log_message("[StaticData] Attempting TypeContext capture...");
    int captured = capture_managers_via_typecontext();
    log_message("[StaticData] Captured %d managers via TypeContext", captured);

    // Also try to load Frida capture if available
    if (staticdata_frida_capture_available()) {
        load_captured_featmanager();
    }
}

void staticdata_dump_status(void) {
    log_message("[StaticData] Manager Status:");
    log_message("  Initialized: %s", g_staticdata.initialized ? "yes" : "no");
    log_message("  Base: %p", g_staticdata.main_binary_base);

    for (int i = 0; i < STATICDATA_COUNT; i++) {
        void* meta = g_staticdata.managers[i];
        void* real = g_staticdata.real_managers[i];

        if (real) {
            int32_t count = *(int32_t*)((uint8_t*)real + FEATMANAGER_REAL_COUNT_OFFSET);
            void* array = *(void**)((uint8_t*)real + FEATMANAGER_REAL_ARRAY_OFFSET);
            log_message("  %s: REAL %p (count=%d, array=%p) [metadata=%p]",
                        s_type_names[i], real, count, array, meta);
        } else if (meta) {
            int32_t meta_count = *(int32_t*)((uint8_t*)meta + FEATMANAGER_META_COUNT_OFFSET);
            log_message("  %s: METADATA ONLY %p (meta_count=%d) - NO REAL DATA",
                        s_type_names[i], meta, meta_count);
        } else {
            log_message("  %s: not captured", s_type_names[i]);
        }
    }
}

void staticdata_dump_entries(StaticDataType type, int max_entries) {
    int count = staticdata_get_count(type);
    if (count < 0) {
        log_message("[StaticData] Type %s not available", staticdata_type_name(type));
        return;
    }

    int to_dump = (max_entries < 0 || max_entries > count) ? count : max_entries;
    log_message("[StaticData] Dumping %d of %d %s entries:", to_dump, count, staticdata_type_name(type));

    for (int i = 0; i < to_dump; i++) {
        void* entry = staticdata_get_by_index(type, i);
        if (!entry) continue;

        char guid_str[40];
        if (staticdata_get_guid_string(type, entry, guid_str, sizeof(guid_str))) {
            log_message("  [%d] GUID=%s", i, guid_str);
        } else {
            log_message("  [%d] ptr=%p", i, entry);
        }
    }
}

/**
 * Diagnostic: Dump the first few entries of the feat array to understand memory layout.
 */
void staticdata_dump_feat_memory(void) {
    void* mgr = g_staticdata.real_managers[STATICDATA_FEAT];
    if (!mgr) {
        log_message("[StaticData] No real FeatManager captured for memory dump");
        return;
    }

    int32_t count = 0;
    void* array = NULL;

    if (!safe_memory_read_i32((mach_vm_address_t)mgr + FEATMANAGER_REAL_COUNT_OFFSET, &count)) {
        log_message("[StaticData] Cannot read count for memory dump");
        return;
    }
    if (!safe_memory_read_pointer((mach_vm_address_t)mgr + FEATMANAGER_REAL_ARRAY_OFFSET, &array)) {
        log_message("[StaticData] Cannot read array pointer for memory dump");
        return;
    }

    log_message("[StaticData] MEMORY DUMP: mgr=%p, count=%d, array=%p", mgr, count, array);
    log_message("[StaticData] FEAT_SIZE=%d (0x%X), expected array range: %p - %p",
                FEAT_SIZE, FEAT_SIZE, array, (uint8_t*)array + (count * FEAT_SIZE));

    // Check if array pointer itself is readable
    int32_t test = 0;
    if (!safe_memory_read_i32((mach_vm_address_t)array, &test)) {
        log_message("[StaticData] ARRAY BASE IS NOT READABLE at %p!", array);
        return;
    }

    // Dump first 64 bytes of array base
    log_message("[StaticData] First 64 bytes at array base %p:", array);
    for (int row = 0; row < 4; row++) {
        char hex[128] = {0};
        char* p = hex;
        for (int col = 0; col < 16; col++) {
            uint8_t byte = 0;
            mach_vm_address_t addr = (mach_vm_address_t)array + (row * 16) + col;
            if (safe_memory_read_u8(addr, &byte)) {
                p += sprintf(p, "%02X ", byte);
            } else {
                p += sprintf(p, "?? ");
            }
        }
        log_message("  +0x%02X: %s", row * 16, hex);
    }

    // Try to dump first 3 "entries" at different sizes to help identify structure
    log_message("[StaticData] Testing different entry sizes:");
    int test_sizes[] = {8, 16, 32, 64, 128, 256, FEAT_SIZE};
    for (int s = 0; s < sizeof(test_sizes)/sizeof(test_sizes[0]); s++) {
        int size = test_sizes[s];
        log_message("  Entry size=%d:", size);

        for (int i = 0; i < 3 && i < count; i++) {
            void* entry = (uint8_t*)array + (i * size);
            uint64_t val = 0;
            if (safe_memory_read_u64((mach_vm_address_t)entry, &val)) {
                log_message("    [%d] %p: first8=0x%016llx", i, entry, (unsigned long long)val);
            } else {
                log_message("    [%d] %p: UNREADABLE", i, entry);
            }
        }
    }
}

void staticdata_probe_manager(StaticDataType type, int probe_range) {
    void* mgr = g_staticdata.managers[type];
    if (!mgr) {
        log_message("[StaticData] Cannot probe %s - manager not captured", staticdata_type_name(type));
        return;
    }

    log_message("[StaticData] Probing %s manager at %p (range: 0x%X):",
                staticdata_type_name(type), mgr, probe_range);

    // Dump hex view of manager structure
    uint8_t* data = (uint8_t*)mgr;
    for (int offset = 0; offset < probe_range; offset += 16) {
        char hex[64] = {0};
        char ascii[20] = {0};

        for (int i = 0; i < 16 && (offset + i) < probe_range; i++) {
            sprintf(hex + strlen(hex), "%02X ", data[offset + i]);
            ascii[i] = isprint(data[offset + i]) ? data[offset + i] : '.';
        }

        log_message("  +0x%02X: %-48s %s", offset, hex, ascii);
    }
}
