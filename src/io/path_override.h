/**
 * path_override.h - Path Override System for Ext.IO
 *
 * Allows mods to redirect file loads from one path to another.
 * Thread-safe using pthread read-write locks.
 */

#ifndef PATH_OVERRIDE_H
#define PATH_OVERRIDE_H

#include <stdbool.h>

/**
 * Initialize the path override system.
 * Must be called before any other path_override functions.
 */
void path_override_init(void);

/**
 * Shutdown the path override system.
 * Frees all allocated memory.
 */
void path_override_shutdown(void);

/**
 * Add a path override mapping.
 *
 * @param original The original path that should be redirected
 * @param override The path to redirect to
 */
void path_override_add(const char *original, const char *override);

/**
 * Get the override for a path.
 *
 * @param original The path to look up
 * @return The override path if found, NULL otherwise.
 *         The returned string is owned by the path_override system.
 */
const char *path_override_get(const char *original);

/**
 * Remove a path override.
 *
 * @param original The original path to remove
 * @return true if the path was removed, false if not found
 */
bool path_override_remove(const char *original);

/**
 * Clear all path overrides.
 */
void path_override_clear(void);

/**
 * Get the number of active path overrides.
 */
int path_override_count(void);

#endif // PATH_OVERRIDE_H
