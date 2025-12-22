/**
 * timer.c - Timer system implementation
 *
 * Uses a fixed-size timer pool and a min-heap priority queue for efficient
 * "get next timer to fire" operations. Timers store Lua callback references
 * via luaL_ref to prevent garbage collection.
 */

#include "timer.h"
#include "../core/logging.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <mach/mach_time.h>
#include <lauxlib.h>

// ============================================================================
// Timer Structure
// ============================================================================

typedef struct {
    double fire_time;        // Monotonic time when timer should fire (ms)
    double repeat_interval;  // 0 for one-shot, >0 for repeating (ms)
    int callback_ref;        // Lua registry reference (LUA_NOREF if inactive)
    uint32_t invoke_id;      // Incremented on pause/resume to invalidate stale queue entries
    bool paused;
    bool active;             // Slot in use
} Timer;

// ============================================================================
// Priority Queue Entry
// ============================================================================

typedef struct {
    double fire_time;
    TimerHandle handle;
    uint32_t invoke_id;      // Must match timer's invoke_id to be valid
} TimerQueueEntry;

// ============================================================================
// Static State
// ============================================================================

// Timer pool
static Timer s_timers[TIMER_MAX_COUNT];
static int s_timer_count = 0;

// Priority queue (min-heap)
#define QUEUE_MAX_SIZE 512
static TimerQueueEntry s_queue[QUEUE_MAX_SIZE];
static int s_queue_size = 0;

// Time conversion
static mach_timebase_info_data_t s_timebase_info;
static uint64_t s_start_time = 0;
static bool s_initialized = false;

// Game time tracking
static double s_game_time_ms = 0.0;       // Total game time in milliseconds
static double s_delta_time_ms = 0.0;       // Last frame's delta in milliseconds
static int64_t s_tick_count = 0;           // Total tick count
static bool s_game_paused = false;         // True when game time is paused

// ============================================================================
// Time Functions
// ============================================================================

static void init_timebase(void) {
    if (s_initialized) return;

    mach_timebase_info(&s_timebase_info);
    s_start_time = mach_absolute_time();
    s_initialized = true;
}

double timer_get_monotonic_ms(void) {
    if (!s_initialized) init_timebase();

    uint64_t elapsed = mach_absolute_time() - s_start_time;
    // Convert to nanoseconds, then to milliseconds
    uint64_t nanos = elapsed * s_timebase_info.numer / s_timebase_info.denom;
    return (double)nanos / 1000000.0;
}

double timer_get_microsec_time(void) {
    if (!s_initialized) init_timebase();

    uint64_t elapsed = mach_absolute_time() - s_start_time;
    // Convert to nanoseconds, then to microseconds
    uint64_t nanos = elapsed * s_timebase_info.numer / s_timebase_info.denom;
    return (double)nanos / 1000.0;
}

int64_t timer_get_epoch_seconds(void) {
    return (int64_t)time(NULL);
}

const char* timer_get_clock_time(void) {
    static char buffer[32];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    return buffer;
}

// ============================================================================
// Priority Queue (Min-Heap)
// ============================================================================

static void queue_swap(int i, int j) {
    TimerQueueEntry tmp = s_queue[i];
    s_queue[i] = s_queue[j];
    s_queue[j] = tmp;
}

static void queue_sift_up(int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (s_queue[idx].fire_time < s_queue[parent].fire_time) {
            queue_swap(idx, parent);
            idx = parent;
        } else {
            break;
        }
    }
}

static void queue_sift_down(int idx) {
    while (true) {
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;
        int smallest = idx;

        if (left < s_queue_size && s_queue[left].fire_time < s_queue[smallest].fire_time) {
            smallest = left;
        }
        if (right < s_queue_size && s_queue[right].fire_time < s_queue[smallest].fire_time) {
            smallest = right;
        }

        if (smallest != idx) {
            queue_swap(idx, smallest);
            idx = smallest;
        } else {
            break;
        }
    }
}

static bool queue_push(double fire_time, TimerHandle handle, uint32_t invoke_id) {
    if (s_queue_size >= QUEUE_MAX_SIZE) {
        LOG_TIMER_WARN("Queue full, cannot schedule timer");
        return false;
    }

    s_queue[s_queue_size].fire_time = fire_time;
    s_queue[s_queue_size].handle = handle;
    s_queue[s_queue_size].invoke_id = invoke_id;
    queue_sift_up(s_queue_size);
    s_queue_size++;
    return true;
}

static TimerQueueEntry queue_pop(void) {
    TimerQueueEntry top = s_queue[0];
    s_queue_size--;
    if (s_queue_size > 0) {
        s_queue[0] = s_queue[s_queue_size];
        queue_sift_down(0);
    }
    return top;
}

static bool queue_empty(void) {
    return s_queue_size == 0;
}

static TimerQueueEntry queue_top(void) {
    return s_queue[0];
}

// ============================================================================
// Timer Pool
// ============================================================================

static int timer_pool_alloc(void) {
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        if (!s_timers[i].active) {
            return i;
        }
    }
    return -1;  // Pool full
}

static Timer *timer_get(TimerHandle handle) {
    // Handles are 1-based (0 = invalid), convert to 0-based index
    if (handle == 0) return NULL;
    uint32_t idx = (uint32_t)((handle - 1) & 0xFFFFFFFF);
    if (idx >= TIMER_MAX_COUNT) return NULL;
    if (!s_timers[idx].active) return NULL;
    return &s_timers[idx];
}

// ============================================================================
// Public API
// ============================================================================

void timer_init(void) {
    init_timebase();

    // Clear timer pool
    memset(s_timers, 0, sizeof(s_timers));
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        s_timers[i].callback_ref = LUA_NOREF;
    }
    s_timer_count = 0;

    // Clear queue
    s_queue_size = 0;

    LOG_TIMER_INFO("Timer system initialized");
}

void timer_shutdown(lua_State *L) {
    timer_clear_all(L);
    LOG_TIMER_INFO("Timer system shut down");
}

TimerHandle timer_create(lua_State *L, double delay_ms, int callback_ref, double repeat_ms) {
    int idx = timer_pool_alloc();
    if (idx < 0) {
        LOG_TIMER_ERROR("Timer pool exhausted (%d max)", TIMER_MAX_COUNT);
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        return 0;
    }

    double now = timer_get_monotonic_ms();

    Timer *timer = &s_timers[idx];
    timer->fire_time = now + delay_ms;
    timer->repeat_interval = repeat_ms;
    timer->callback_ref = callback_ref;
    timer->invoke_id = 0;
    timer->paused = false;
    timer->active = true;
    s_timer_count++;

    // Handles are 1-based (0 = invalid/error)
    TimerHandle handle = (TimerHandle)(idx + 1);

    if (!queue_push(timer->fire_time, handle, timer->invoke_id)) {
        // Queue full, cancel the timer
        timer->active = false;
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        timer->callback_ref = LUA_NOREF;
        s_timer_count--;
        return 0;
    }

    return handle;
}

bool timer_cancel(lua_State *L, TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer) return false;

    // Release Lua callback reference
    if (timer->callback_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
        timer->callback_ref = LUA_NOREF;
    }

    timer->active = false;
    s_timer_count--;

    // Note: We don't remove from queue - the entry will be ignored when popped
    // because active=false

    return true;
}

bool timer_pause(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer || timer->paused) return false;

    double now = timer_get_monotonic_ms();

    // Store remaining time
    timer->fire_time = timer->fire_time - now;  // Store as delta
    timer->paused = true;
    timer->invoke_id++;  // Invalidate any queued entries

    return true;
}

bool timer_resume(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    if (!timer || !timer->paused) return false;

    double now = timer_get_monotonic_ms();

    // Restore fire time
    timer->fire_time = now + timer->fire_time;  // fire_time was storing delta
    timer->paused = false;

    // Re-queue the timer
    if (!queue_push(timer->fire_time, handle, timer->invoke_id)) {
        LOG_TIMER_WARN("Failed to resume timer (queue full)");
        timer->paused = true;  // Restore paused state
        return false;
    }

    return true;
}

bool timer_is_paused(TimerHandle handle) {
    Timer *timer = timer_get(handle);
    return timer && timer->paused;
}

void timer_update(lua_State *L) {
    if (!L) return;

    double now = timer_get_monotonic_ms();

    while (!queue_empty() && queue_top().fire_time <= now) {
        TimerQueueEntry entry = queue_pop();
        Timer *timer = timer_get(entry.handle);

        // Validate: timer exists, active, not paused, invoke_id matches
        if (!timer || !timer->active || timer->paused ||
            timer->invoke_id != entry.invoke_id) {
            continue;  // Stale entry, skip
        }

        // Cache values BEFORE lua_pcall (callback might cancel/modify timer)
        bool is_repeating = (timer->repeat_interval > 0);
        double repeat_interval = timer->repeat_interval;
        int callback_ref = timer->callback_ref;

        // Fire callback
        lua_rawgeti(L, LUA_REGISTRYINDEX, callback_ref);
        lua_pushinteger(L, (lua_Integer)entry.handle);

        if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_TIMER_ERROR("Callback error: %s", err ? err : "(unknown)");
            lua_pop(L, 1);
        }

        // Re-fetch timer (callback may have cancelled it or modified state)
        timer = timer_get(entry.handle);

        // Repeat or release
        if (timer && timer->active && is_repeating) {
            timer->fire_time = now + repeat_interval;
            if (!queue_push(timer->fire_time, entry.handle, timer->invoke_id)) {
                // Queue full, cancel the timer
                LOG_TIMER_WARN("Queue full during repeat, cancelling timer");
                if (timer->callback_ref != LUA_NOREF) {
                    luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
                    timer->callback_ref = LUA_NOREF;
                }
                timer->active = false;
                s_timer_count--;
            }
        } else if (timer && timer->active) {
            // One-shot timer completed
            if (timer->callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, timer->callback_ref);
                timer->callback_ref = LUA_NOREF;
            }
            timer->active = false;
            s_timer_count--;
        }
        // If !timer || !timer->active, callback cancelled itself - already cleaned up
    }
}

void timer_clear_all(lua_State *L) {
    for (int i = 0; i < TIMER_MAX_COUNT; i++) {
        if (s_timers[i].active) {
            if (L && s_timers[i].callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, s_timers[i].callback_ref);
            }
            s_timers[i].callback_ref = LUA_NOREF;
            s_timers[i].active = false;
        }
    }
    s_timer_count = 0;
    s_queue_size = 0;

    LOG_TIMER_INFO("All timers cleared");
}

// ============================================================================
// Game Time Tracking
// ============================================================================

void timer_tick(double delta_ms) {
    s_delta_time_ms = delta_ms;
    s_tick_count++;

    // Only accumulate game time if not paused
    if (!s_game_paused) {
        s_game_time_ms += delta_ms;
    }
}

void timer_pause_game_time(void) {
    if (!s_game_paused) {
        s_game_paused = true;
        LOG_TIMER_INFO("Game time paused at %.3f seconds", s_game_time_ms / 1000.0);
    }
}

void timer_resume_game_time(void) {
    if (s_game_paused) {
        s_game_paused = false;
        LOG_TIMER_INFO("Game time resumed at %.3f seconds", s_game_time_ms / 1000.0);
    }
}

bool timer_is_game_paused(void) {
    return s_game_paused;
}

double timer_get_game_time(void) {
    // Return in seconds (matching Windows BG3SE GameTime.Time)
    return s_game_time_ms / 1000.0;
}

double timer_get_delta_time(void) {
    // Return in seconds (matching Windows BG3SE GameTime.DeltaTime)
    return s_delta_time_ms / 1000.0;
}

int64_t timer_get_tick_count(void) {
    return s_tick_count;
}

// ============================================================================
// Persistent Timer Structures
// ============================================================================

typedef struct {
    char name[TIMER_CALLBACK_NAME_MAX];
    int callback_ref;  // Lua registry reference
    bool active;
} PersistentHandler;

typedef struct {
    double fire_time;        // Monotonic time when timer should fire (ms)
    double repeat_interval;  // 0 for one-shot, >0 for repeating (ms)
    char handler_name[TIMER_CALLBACK_NAME_MAX];
    char args_json[TIMER_ARGS_JSON_MAX];
    uint32_t invoke_id;
    bool paused;
    bool active;
} PersistentTimer;

// ============================================================================
// Persistent Timer State
// ============================================================================

#define PERSISTENT_HANDLER_MAX 32

static PersistentHandler s_handlers[PERSISTENT_HANDLER_MAX];
static int s_handler_count = 0;

static PersistentTimer s_persistent_timers[PERSISTENT_TIMER_MAX];
static int s_persistent_timer_count = 0;

// Persistent timer queue (separate from regular timers)
#define PERSISTENT_QUEUE_MAX 128
static TimerQueueEntry s_persistent_queue[PERSISTENT_QUEUE_MAX];
static int s_persistent_queue_size = 0;

// ============================================================================
// Persistent Queue Operations
// ============================================================================

static void persistent_queue_swap(int i, int j) {
    TimerQueueEntry tmp = s_persistent_queue[i];
    s_persistent_queue[i] = s_persistent_queue[j];
    s_persistent_queue[j] = tmp;
}

static void persistent_queue_sift_up(int idx) {
    while (idx > 0) {
        int parent = (idx - 1) / 2;
        if (s_persistent_queue[idx].fire_time < s_persistent_queue[parent].fire_time) {
            persistent_queue_swap(idx, parent);
            idx = parent;
        } else {
            break;
        }
    }
}

static void persistent_queue_sift_down(int idx) {
    while (true) {
        int left = 2 * idx + 1;
        int right = 2 * idx + 2;
        int smallest = idx;

        if (left < s_persistent_queue_size &&
            s_persistent_queue[left].fire_time < s_persistent_queue[smallest].fire_time) {
            smallest = left;
        }
        if (right < s_persistent_queue_size &&
            s_persistent_queue[right].fire_time < s_persistent_queue[smallest].fire_time) {
            smallest = right;
        }

        if (smallest != idx) {
            persistent_queue_swap(idx, smallest);
            idx = smallest;
        } else {
            break;
        }
    }
}

static bool persistent_queue_push(double fire_time, TimerHandle handle, uint32_t invoke_id) {
    if (s_persistent_queue_size >= PERSISTENT_QUEUE_MAX) {
        LOG_TIMER_WARN("Persistent queue full");
        return false;
    }

    s_persistent_queue[s_persistent_queue_size].fire_time = fire_time;
    s_persistent_queue[s_persistent_queue_size].handle = handle;
    s_persistent_queue[s_persistent_queue_size].invoke_id = invoke_id;
    persistent_queue_sift_up(s_persistent_queue_size);
    s_persistent_queue_size++;
    return true;
}

static TimerQueueEntry persistent_queue_pop(void) {
    TimerQueueEntry top = s_persistent_queue[0];
    s_persistent_queue_size--;
    if (s_persistent_queue_size > 0) {
        s_persistent_queue[0] = s_persistent_queue[s_persistent_queue_size];
        persistent_queue_sift_down(0);
    }
    return top;
}

static bool persistent_queue_empty(void) {
    return s_persistent_queue_size == 0;
}

static TimerQueueEntry persistent_queue_top(void) {
    return s_persistent_queue[0];
}

// ============================================================================
// Persistent Handler Management
// ============================================================================

static PersistentHandler *find_handler(const char *name) {
    for (int i = 0; i < PERSISTENT_HANDLER_MAX; i++) {
        if (s_handlers[i].active && strcmp(s_handlers[i].name, name) == 0) {
            return &s_handlers[i];
        }
    }
    return NULL;
}

bool timer_register_persistent_handler(lua_State *L, const char *name, int callback_ref) {
    if (!name || strlen(name) == 0) {
        LOG_TIMER_ERROR("Handler name cannot be empty");
        if (callback_ref != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        }
        return false;
    }

    if (strlen(name) >= TIMER_CALLBACK_NAME_MAX) {
        LOG_TIMER_ERROR("Handler name too long: %s", name);
        if (callback_ref != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
        }
        return false;
    }

    // Check if handler already exists
    PersistentHandler *existing = find_handler(name);
    if (existing) {
        // Replace existing handler
        if (existing->callback_ref != LUA_NOREF) {
            luaL_unref(L, LUA_REGISTRYINDEX, existing->callback_ref);
        }
        existing->callback_ref = callback_ref;
        LOG_TIMER_INFO("Replaced persistent handler: %s", name);
        return true;
    }

    // Find empty slot
    for (int i = 0; i < PERSISTENT_HANDLER_MAX; i++) {
        if (!s_handlers[i].active) {
            strncpy(s_handlers[i].name, name, TIMER_CALLBACK_NAME_MAX - 1);
            s_handlers[i].name[TIMER_CALLBACK_NAME_MAX - 1] = '\0';
            s_handlers[i].callback_ref = callback_ref;
            s_handlers[i].active = true;
            s_handler_count++;
            LOG_TIMER_INFO("Registered persistent handler: %s", name);
            return true;
        }
    }

    LOG_TIMER_ERROR("Handler pool exhausted (%d max)", PERSISTENT_HANDLER_MAX);
    if (callback_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, callback_ref);
    }
    return false;
}

bool timer_unregister_persistent_handler(lua_State *L, const char *name) {
    PersistentHandler *handler = find_handler(name);
    if (!handler) {
        return false;
    }

    if (handler->callback_ref != LUA_NOREF) {
        luaL_unref(L, LUA_REGISTRYINDEX, handler->callback_ref);
    }
    handler->callback_ref = LUA_NOREF;
    handler->active = false;
    handler->name[0] = '\0';
    s_handler_count--;

    LOG_TIMER_INFO("Unregistered persistent handler: %s", name);
    return true;
}

// ============================================================================
// Persistent Timer Creation/Cancellation
// ============================================================================

static int persistent_timer_pool_alloc(void) {
    for (int i = 0; i < PERSISTENT_TIMER_MAX; i++) {
        if (!s_persistent_timers[i].active) {
            return i;
        }
    }
    return -1;
}

static PersistentTimer *persistent_timer_get(TimerHandle handle) {
    // Persistent handles use high bit set to distinguish from regular timers
    if ((handle & 0x80000000) == 0) return NULL;
    uint32_t idx = (uint32_t)((handle & 0x7FFFFFFF) - 1);
    if (idx >= PERSISTENT_TIMER_MAX) return NULL;
    if (!s_persistent_timers[idx].active) return NULL;
    return &s_persistent_timers[idx];
}

TimerHandle timer_create_persistent(lua_State *L, double delay_ms, const char *handler_name,
                                     const char *args_json, double repeat_ms) {
    (void)L;  // Unused but kept for API consistency

    // Validate handler exists
    PersistentHandler *handler = find_handler(handler_name);
    if (!handler) {
        LOG_TIMER_ERROR("Persistent handler not found: %s", handler_name);
        return 0;
    }

    int idx = persistent_timer_pool_alloc();
    if (idx < 0) {
        LOG_TIMER_ERROR("Persistent timer pool exhausted (%d max)", PERSISTENT_TIMER_MAX);
        return 0;
    }

    double now = timer_get_monotonic_ms();

    PersistentTimer *timer = &s_persistent_timers[idx];
    timer->fire_time = now + delay_ms;
    timer->repeat_interval = repeat_ms;
    strncpy(timer->handler_name, handler_name, TIMER_CALLBACK_NAME_MAX - 1);
    timer->handler_name[TIMER_CALLBACK_NAME_MAX - 1] = '\0';

    if (args_json && strlen(args_json) > 0) {
        strncpy(timer->args_json, args_json, TIMER_ARGS_JSON_MAX - 1);
        timer->args_json[TIMER_ARGS_JSON_MAX - 1] = '\0';
    } else {
        timer->args_json[0] = '\0';
    }

    timer->invoke_id = 0;
    timer->paused = false;
    timer->active = true;
    s_persistent_timer_count++;

    // Handle uses high bit to distinguish from regular timers
    TimerHandle handle = (TimerHandle)(0x80000000 | (idx + 1));

    if (!persistent_queue_push(timer->fire_time, handle, timer->invoke_id)) {
        timer->active = false;
        s_persistent_timer_count--;
        return 0;
    }

    LOG_TIMER_INFO("Created persistent timer: handler=%s delay=%.1fms repeat=%.1fms",
                   handler_name, delay_ms, repeat_ms);
    return handle;
}

bool timer_cancel_persistent(lua_State *L, TimerHandle handle) {
    (void)L;

    PersistentTimer *timer = persistent_timer_get(handle);
    if (!timer) return false;

    timer->active = false;
    s_persistent_timer_count--;

    LOG_TIMER_INFO("Cancelled persistent timer: handler=%s", timer->handler_name);
    return true;
}

// ============================================================================
// Persistent Timer Update
// ============================================================================

void timer_update_persistent(lua_State *L) {
    if (!L) return;

    double now = timer_get_monotonic_ms();

    while (!persistent_queue_empty() && persistent_queue_top().fire_time <= now) {
        TimerQueueEntry entry = persistent_queue_pop();
        PersistentTimer *timer = persistent_timer_get(entry.handle);

        if (!timer || !timer->active || timer->paused ||
            timer->invoke_id != entry.invoke_id) {
            continue;
        }

        // Find the handler
        PersistentHandler *handler = find_handler(timer->handler_name);
        if (!handler) {
            LOG_TIMER_WARN("Handler not found for persistent timer: %s", timer->handler_name);
            timer->active = false;
            s_persistent_timer_count--;
            continue;
        }

        // Cache values before callback
        bool is_repeating = (timer->repeat_interval > 0);
        double repeat_interval = timer->repeat_interval;

        // Fire callback with: handler(handle, args_json)
        lua_rawgeti(L, LUA_REGISTRYINDEX, handler->callback_ref);
        lua_pushinteger(L, (lua_Integer)entry.handle);

        // Parse args_json if present
        if (timer->args_json[0] != '\0') {
            lua_pushstring(L, timer->args_json);
        } else {
            lua_pushnil(L);
        }

        if (lua_pcall(L, 2, 0, 0) != LUA_OK) {
            const char *err = lua_tostring(L, -1);
            LOG_TIMER_ERROR("Persistent callback error (%s): %s",
                           timer->handler_name, err ? err : "(unknown)");
            lua_pop(L, 1);
        }

        // Re-fetch timer (callback may have modified it)
        timer = persistent_timer_get(entry.handle);

        if (timer && timer->active && is_repeating) {
            timer->fire_time = now + repeat_interval;
            if (!persistent_queue_push(timer->fire_time, entry.handle, timer->invoke_id)) {
                LOG_TIMER_WARN("Queue full during repeat, cancelling persistent timer");
                timer->active = false;
                s_persistent_timer_count--;
            }
        } else if (timer && timer->active) {
            // One-shot completed
            timer->active = false;
            s_persistent_timer_count--;
        }
    }
}

// ============================================================================
// Persistent Timer Export/Import (for save/load)
// ============================================================================

char* timer_export_persistent(void) {
    // Simple JSON array format
    // Calculate required buffer size
    size_t buf_size = 2048 + (PERSISTENT_TIMER_MAX * 256);
    char *json = (char *)malloc(buf_size);
    if (!json) return NULL;

    double now = timer_get_monotonic_ms();

    char *p = json;
    p += sprintf(p, "{\"timers\":[");

    bool first = true;
    for (int i = 0; i < PERSISTENT_TIMER_MAX; i++) {
        PersistentTimer *timer = &s_persistent_timers[i];
        if (!timer->active) continue;

        if (!first) {
            p += sprintf(p, ",");
        }
        first = false;

        // Calculate remaining time
        double remaining = timer->paused ? timer->fire_time : (timer->fire_time - now);
        if (remaining < 0) remaining = 0;

        // Escape args_json for JSON
        p += sprintf(p, "{\"handler\":\"%s\",\"remaining\":%.1f,\"repeat\":%.1f,\"paused\":%s,\"args\":",
                     timer->handler_name, remaining, timer->repeat_interval,
                     timer->paused ? "true" : "false");

        if (timer->args_json[0] != '\0') {
            // Already JSON, just include it
            p += sprintf(p, "%s", timer->args_json);
        } else {
            p += sprintf(p, "null");
        }
        p += sprintf(p, "}");
    }

    p += sprintf(p, "]}");
    return json;
}

int timer_import_persistent(lua_State *L, const char *json) {
    if (!json || !L) return 0;

    // Simple parsing - look for timer entries
    // Format: {"timers":[{"handler":"name","remaining":100,"repeat":0,"paused":false,"args":null}]}

    int count = 0;
    const char *p = json;

    // Skip to timers array
    p = strstr(p, "\"timers\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;
    p++;

    while (*p) {
        // Skip whitespace
        while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;

        if (*p == ']') break;
        if (*p == ',') { p++; continue; }
        if (*p != '{') break;

        // Parse timer object
        char handler[TIMER_CALLBACK_NAME_MAX] = {0};
        double remaining = 0;
        double repeat = 0;
        bool paused = false;
        char args[TIMER_ARGS_JSON_MAX] = {0};

        // Find handler
        const char *h = strstr(p, "\"handler\"");
        if (h) {
            h = strchr(h, ':');
            if (h) {
                h++;
                while (*h == ' ' || *h == '"') h++;
                const char *end = strchr(h, '"');
                if (end) {
                    size_t len = end - h;
                    if (len < TIMER_CALLBACK_NAME_MAX) {
                        strncpy(handler, h, len);
                    }
                }
            }
        }

        // Find remaining
        const char *r = strstr(p, "\"remaining\"");
        if (r) {
            r = strchr(r, ':');
            if (r) {
                r++;
                remaining = strtod(r, NULL);
            }
        }

        // Find repeat
        const char *rp = strstr(p, "\"repeat\"");
        if (rp) {
            rp = strchr(rp, ':');
            if (rp) {
                rp++;
                repeat = strtod(rp, NULL);
            }
        }

        // Find paused
        const char *pa = strstr(p, "\"paused\"");
        if (pa) {
            pa = strchr(pa, ':');
            if (pa) {
                pa++;
                while (*pa == ' ') pa++;
                paused = (*pa == 't');
            }
        }

        // Find args (complex - could be object or null)
        const char *ar = strstr(p, "\"args\"");
        if (ar) {
            ar = strchr(ar, ':');
            if (ar) {
                ar++;
                while (*ar == ' ') ar++;
                if (*ar != 'n') {  // not null
                    // Find matching brace/bracket or end
                    int depth = 0;
                    const char *start = ar;
                    while (*ar) {
                        if (*ar == '{' || *ar == '[') depth++;
                        else if (*ar == '}' || *ar == ']') {
                            if (depth == 0) break;
                            depth--;
                        }
                        ar++;
                    }
                    size_t len = ar - start;
                    if (len < TIMER_ARGS_JSON_MAX) {
                        strncpy(args, start, len);
                    }
                }
            }
        }

        // Skip to end of object
        int depth = 1;
        while (*p && depth > 0) {
            if (*p == '{') depth++;
            else if (*p == '}') depth--;
            p++;
        }

        // Create the timer if handler is valid
        if (handler[0] != '\0' && find_handler(handler)) {
            TimerHandle handle = timer_create_persistent(L, remaining, handler,
                                                          args[0] ? args : NULL, repeat);
            if (handle != 0) {
                if (paused) {
                    PersistentTimer *timer = persistent_timer_get(handle);
                    if (timer) {
                        timer->paused = true;
                        timer->fire_time = remaining;  // Store as delta when paused
                        timer->invoke_id++;
                    }
                }
                count++;
            }
        }
    }

    LOG_TIMER_INFO("Imported %d persistent timers from save", count);
    return count;
}

void timer_clear_persistent(lua_State *L) {
    // Clear all handlers
    for (int i = 0; i < PERSISTENT_HANDLER_MAX; i++) {
        if (s_handlers[i].active) {
            if (L && s_handlers[i].callback_ref != LUA_NOREF) {
                luaL_unref(L, LUA_REGISTRYINDEX, s_handlers[i].callback_ref);
            }
            s_handlers[i].callback_ref = LUA_NOREF;
            s_handlers[i].active = false;
            s_handlers[i].name[0] = '\0';
        }
    }
    s_handler_count = 0;

    // Clear all persistent timers
    for (int i = 0; i < PERSISTENT_TIMER_MAX; i++) {
        s_persistent_timers[i].active = false;
    }
    s_persistent_timer_count = 0;
    s_persistent_queue_size = 0;

    LOG_TIMER_INFO("All persistent timers and handlers cleared");
}
