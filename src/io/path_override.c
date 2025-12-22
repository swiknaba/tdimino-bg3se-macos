/**
 * path_override.c - Path Override System Implementation
 *
 * Simple dynamic array implementation for path overrides.
 * Thread-safe using pthread read-write locks.
 */

#include "path_override.h"
#include "../core/logging.h"

#include <stdlib.h>
#include <string.h>
#include <pthread.h>

// ============================================================================
// Internal Data Structures
// ============================================================================

typedef struct {
    char *original;
    char *override;
} PathEntry;

typedef struct {
    PathEntry *entries;
    int count;
    int capacity;
    pthread_rwlock_t lock;
    bool initialized;
} PathOverrideMap;

static PathOverrideMap s_map = {0};

// Initial and growth capacity
#define INITIAL_CAPACITY 16
#define GROWTH_FACTOR 2

// ============================================================================
// Internal Helpers
// ============================================================================

static bool ensure_capacity(void) {
    if (s_map.count < s_map.capacity) {
        return true;
    }

    int new_capacity = s_map.capacity == 0 ? INITIAL_CAPACITY : s_map.capacity * GROWTH_FACTOR;
    PathEntry *new_entries = realloc(s_map.entries, new_capacity * sizeof(PathEntry));
    if (!new_entries) {
        log_message("[PathOverride] Failed to grow capacity to %d", new_capacity);
        return false;
    }

    s_map.entries = new_entries;
    s_map.capacity = new_capacity;
    return true;
}

static int find_entry(const char *original) {
    for (int i = 0; i < s_map.count; i++) {
        if (strcmp(s_map.entries[i].original, original) == 0) {
            return i;
        }
    }
    return -1;
}

// ============================================================================
// Public API
// ============================================================================

void path_override_init(void) {
    if (s_map.initialized) {
        return;
    }

    memset(&s_map, 0, sizeof(s_map));
    pthread_rwlock_init(&s_map.lock, NULL);
    s_map.initialized = true;

    log_message("[PathOverride] Initialized");
}

void path_override_shutdown(void) {
    if (!s_map.initialized) {
        return;
    }

    pthread_rwlock_wrlock(&s_map.lock);

    // Free all entries
    for (int i = 0; i < s_map.count; i++) {
        free(s_map.entries[i].original);
        free(s_map.entries[i].override);
    }
    free(s_map.entries);

    s_map.entries = NULL;
    s_map.count = 0;
    s_map.capacity = 0;

    pthread_rwlock_unlock(&s_map.lock);
    pthread_rwlock_destroy(&s_map.lock);

    s_map.initialized = false;

    log_message("[PathOverride] Shutdown");
}

void path_override_add(const char *original, const char *override) {
    if (!s_map.initialized || !original || !override) {
        return;
    }

    pthread_rwlock_wrlock(&s_map.lock);

    // Check if already exists
    int idx = find_entry(original);
    if (idx >= 0) {
        // Update existing entry
        free(s_map.entries[idx].override);
        s_map.entries[idx].override = strdup(override);
        log_message("[PathOverride] Updated: %s -> %s", original, override);
    } else {
        // Add new entry
        if (!ensure_capacity()) {
            pthread_rwlock_unlock(&s_map.lock);
            return;
        }

        s_map.entries[s_map.count].original = strdup(original);
        s_map.entries[s_map.count].override = strdup(override);
        s_map.count++;
        log_message("[PathOverride] Added: %s -> %s", original, override);
    }

    pthread_rwlock_unlock(&s_map.lock);
}

const char *path_override_get(const char *original) {
    if (!s_map.initialized || !original) {
        return NULL;
    }

    pthread_rwlock_rdlock(&s_map.lock);

    const char *result = NULL;
    int idx = find_entry(original);
    if (idx >= 0) {
        result = s_map.entries[idx].override;
    }

    pthread_rwlock_unlock(&s_map.lock);
    return result;
}

bool path_override_remove(const char *original) {
    if (!s_map.initialized || !original) {
        return false;
    }

    pthread_rwlock_wrlock(&s_map.lock);

    int idx = find_entry(original);
    if (idx < 0) {
        pthread_rwlock_unlock(&s_map.lock);
        return false;
    }

    // Free the entry
    free(s_map.entries[idx].original);
    free(s_map.entries[idx].override);

    // Move last entry to fill the gap (if not already last)
    if (idx < s_map.count - 1) {
        s_map.entries[idx] = s_map.entries[s_map.count - 1];
    }
    s_map.count--;

    log_message("[PathOverride] Removed: %s", original);

    pthread_rwlock_unlock(&s_map.lock);
    return true;
}

void path_override_clear(void) {
    if (!s_map.initialized) {
        return;
    }

    pthread_rwlock_wrlock(&s_map.lock);

    for (int i = 0; i < s_map.count; i++) {
        free(s_map.entries[i].original);
        free(s_map.entries[i].override);
    }
    s_map.count = 0;

    log_message("[PathOverride] Cleared all overrides");

    pthread_rwlock_unlock(&s_map.lock);
}

int path_override_count(void) {
    if (!s_map.initialized) {
        return 0;
    }

    pthread_rwlock_rdlock(&s_map.lock);
    int count = s_map.count;
    pthread_rwlock_unlock(&s_map.lock);

    return count;
}
