# Logging and Debugging Improvements Plan

## Executive Summary

This plan outlines improvements to the BG3SE-macOS logging and debugging infrastructure to accelerate API development and testing. The focus is on:
1. Exposing existing C-level logging to Lua modders
2. Enhancing the test framework for better coverage
3. Adding event tracing for debugging one-frame component events
4. Preparing groundwork for VS Code integration (Issue #42)

---

## Current State Analysis

### Strengths

**C-Level Logging System** (`src/core/logging.h/.c`)
- Mature module-aware logging with 14 modules (Core, Console, Lua, Osiris, Entity, Events, Stats, Timer, Hooks, Mod, Memory, Persist, Game, Input)
- Four log levels (DEBUG, INFO, WARN, ERROR)
- Multiple outputs (file, syslog, console, callback)
- JSON and human-readable formats
- Environment variable configuration
- Thread-safe with pthread mutex
- Callback system for external integration (up to 8 listeners)

**Console System** (`src/console/console.c/.h`)
- Unix domain socket server (`/tmp/bg3se.sock`)
- File-based fallback (`~/Library/Application Support/BG3SE/commands.txt`)
- Multi-line mode (`--[[` / `]]--`)
- `!command` prefix for registered handlers
- Thread-safe overlay queue for AppKit integration

**Debug API** (`src/lua/lua_debug.c/.h`)
- 20+ functions for memory introspection
- Safe memory layer with mach_vm_read_overwrite
- Pointer validation and classification
- Struct probing utilities
- Time utilities for debugging

**Test Framework** (`src/lua/lua_ext.c` lines 806-873)
- `!test [filter]` console command
- Tests for Stats, JSON, Timer, Events, Debug, Enums
- Global helpers: `_P`, `_D`, `_DS`, `_H`, `_PTR`, `_PE`

### Gaps Identified

1. **Logging not accessible from Lua** - C logging is powerful but modders can't use it
2. **No event tracing** - Can't observe one-frame component events in real-time
3. **Inline tests** - Tests hardcoded as C strings, hard to maintain
4. **No async test support** - Can't test timer callbacks, event handlers
5. **No TypeId discovery feedback** - Hard to know which components are recognized
6. **No log rotation** - Log file grows indefinitely
7. **No profiling** - No way to measure API performance

---

## Proposed Improvements

### Phase 1: Lua Logging API (Priority: HIGH)

Expose the existing C logging system to Lua scripts.

**New API: `Ext.Log`**
```lua
-- Log with level
Ext.Log.Debug("Events", "Handler %s fired with %d args", name, argCount)
Ext.Log.Info("Stats", "Loaded stat: %s", statName)
Ext.Log.Warn("Entity", "Component not found: %s", typeName)
Ext.Log.Error("Lua", "Script error: %s", err)

-- Query/set log levels
local level = Ext.Log.GetLevel("Events")  -- Returns "DEBUG", "INFO", etc.
Ext.Log.SetLevel("Events", "DEBUG")       -- Per-module control
Ext.Log.SetGlobalLevel("INFO")            -- All modules

-- Get available modules
local modules = Ext.Log.GetModules()      -- {"Core", "Console", "Lua", ...}
```

**Implementation:**
```c
// In new file: src/lua/lua_logging.c
static int lua_log_debug(lua_State* L) {
    const char* module = luaL_checkstring(L, 1);
    const char* msg = luaL_checkstring(L, 2);
    LogModule mod = log_module_from_string(module);
    if (mod != LOG_MODULE_INVALID) {
        log_write(LOG_LEVEL_DEBUG, mod, "%s", msg);
    }
    return 0;
}

// Register in lua_ext.c
lua_newtable(L);
lua_pushcfunction(L, lua_log_debug);
lua_setfield(L, -2, "Debug");
// ... Info, Warn, Error, GetLevel, SetLevel, GetModules
lua_setfield(L, -2, "Log");
```

**Files to modify:**
- New: `src/lua/lua_logging.c`, `src/lua/lua_logging.h`
- Edit: `src/lua/lua_ext.c` (register Ext.Log table)
- Edit: `src/core/logging.c` (add `log_module_from_string()`)

**Effort:** 2-3 hours

---

### Phase 2: Event Tracing Mode (Priority: HIGH)

Add ability to trace all event activity in real-time for debugging.

**New API: `Ext.Debug.TraceEvents`**
```lua
-- Enable event tracing (all events)
Ext.Debug.TraceEvents(true)

-- Enable for specific events only
Ext.Debug.TraceEvents(true, {"LevelUp", "TurnStarted", "StatusApplied"})

-- Disable
Ext.Debug.TraceEvents(false)
```

**Output Example:**
```
[TRACE] [Events] LevelUp: Polling esv::stats::LevelChangedOneFrameComponent...
[TRACE] [Events] LevelUp: Found 1 entity with component (typeIndex=42)
[TRACE] [Events] LevelUp: Dispatching to 2 handlers
[TRACE] [Events] LevelUp: Handler 1 (priority=100) completed in 0.12ms
[TRACE] [Events] LevelUp: Handler 2 (priority=50) completed in 0.05ms
[TRACE] [Events] LevelUp: Event dispatch complete (0.17ms total)
```

**Implementation:**
- Add `g_event_trace_enabled` flag and `g_traced_events` bitfield
- Modify `events_poll_one_frame_components()` to log when tracing
- Add timing via `mach_absolute_time()` for handler duration

**Files to modify:**
- Edit: `src/lua/lua_events.c` (add tracing logic)
- Edit: `src/lua/lua_debug.c` (add TraceEvents function)

**Effort:** 1-2 hours

---

### Phase 3: TypeId Discovery Feedback (Priority: HIGH)

Show which component TypeIds were successfully resolved at runtime.

**New Console Command: `!typeids`**
```
> !typeids
Component TypeId Resolution Status:
------------------------------------
esv::TurnStartedEventOneFrameComponent    RESOLVED (typeIndex=42)
esv::TurnEndedEventOneFrameComponent      RESOLVED (typeIndex=43)
esv::stats::LevelChangedOneFrameComponent RESOLVED (typeIndex=44)
esv::CombatJoinedEventOneFrameComponent   UNRESOLVED (typeIndex=65535)

Resolved: 3/4 (75%)
```

**Implementation:**
```c
// In component_typeid.c
void dump_typeid_status(void) {
    int resolved = 0, total = 0;
    for (int i = 0; g_KnownTypeIds[i].name != NULL; i++) {
        total++;
        uint16_t idx = get_component_type_index(g_KnownTypeIds[i].name);
        const char* status = (idx != 0xFFFF) ? "RESOLVED" : "UNRESOLVED";
        if (idx != 0xFFFF) resolved++;
        console_printf("%-50s %s (typeIndex=%u)\n",
            g_KnownTypeIds[i].name, status, idx);
    }
    console_printf("\nResolved: %d/%d (%d%%)\n", resolved, total, resolved*100/total);
}
```

**Files to modify:**
- Edit: `src/entity/component_typeid.c` (add dump function)
- Edit: `src/lua/lua_ext.c` (register `!typeids` command)

**Effort:** 1 hour

---

### Phase 4: Enhanced Test Framework (Priority: MEDIUM)

Improve the `!test` command with better output and async support.

**New Features:**
```lua
-- Better assertion helpers
Ext.Test.AssertEquals(a, b, "values should match")
Ext.Test.AssertNil(val, "should be nil")
Ext.Test.AssertType(val, "table", "should be table")
Ext.Test.AssertThrows(fn, "should throw")

-- Async test support
Ext.Test.Async("Timer fires callback", function(done)
    Ext.Timer.WaitFor(100, function()
        done()  -- Marks test as passed
    end)
end, 1000)  -- 1 second timeout

-- Run specific test
!test Timer

-- Verbose output
!test -v

-- Summary at end
!test
[PASS] Stats.Get returns table
[PASS] Stats.Get property access
[FAIL] Timer callback fires (timeout after 1000ms)
[PASS] Events.Subscribe returns ID
----
Results: 3 passed, 1 failed, 4 total
```

**Implementation:**
- Add `Ext.Test` table with assertion helpers
- Add async test runner with timeout tracking via Tick event
- Better output formatting with color support

**Files to modify:**
- New: `src/lua/lua_test.c`, `src/lua/lua_test.h`
- Edit: `src/lua/lua_ext.c` (move tests to dedicated file)

**Effort:** 3-4 hours

---

### Phase 5: Log Rotation (Priority: MEDIUM)

Prevent log file from growing indefinitely.

**Configuration:**
```bash
export BG3SE_LOG_MAX_SIZE=10M      # Rotate at 10MB
export BG3SE_LOG_MAX_FILES=5       # Keep 5 rotated files
```

**Behavior:**
- When `bg3se.log` exceeds max size, rotate to `bg3se.log.1`
- Previous `bg3se.log.1` becomes `bg3se.log.2`, etc.
- Delete oldest when max files exceeded

**Implementation:**
- Add size check in `log_write()`
- Implement rotation in `src/core/logging.c`

**Files to modify:**
- Edit: `src/core/logging.c`

**Effort:** 1-2 hours

---

### Phase 6: Profiling API (Priority: MEDIUM)

Add simple profiling for API performance measurement.

**New API: `Ext.Debug.Profile`**
```lua
-- Time a single function call
local result, timeMs = Ext.Debug.Time(function()
    return Ext.Stats.Get("Weapon_Longsword")
end)
print("Stats.Get took " .. timeMs .. "ms")

-- Named profiler for aggregation
Ext.Debug.ProfileStart("GetAllEntities")
local entities = Ext.Entity.GetAllEntities()
Ext.Debug.ProfileStop("GetAllEntities")

-- Later...
Ext.Debug.ProfileReport()
-- Output:
-- GetAllEntities: 15 calls, avg 2.3ms, total 34.5ms
-- Stats.Get: 142 calls, avg 0.1ms, total 14.2ms
```

**Implementation:**
- Use `mach_absolute_time()` for high-precision timing
- Store profiling data in global table

**Files to modify:**
- Edit: `src/lua/lua_debug.c`

**Effort:** 2 hours

---

### Phase 7: VS Code DAP Foundation (Priority: LOW)

Prepare groundwork for Issue #42 (VS Code Integration).

**Socket-Based Debug Protocol:**
```
┌─────────────┐      TCP 8172      ┌─────────────┐
│   VS Code   │ ◄──────────────────►│   BG3SE     │
│   (DAP)     │                    │   Debugger  │
└─────────────┘                    └─────────────┘
```

**MVP Capabilities:**
1. Pause/Resume execution
2. Step into/over/out
3. Breakpoints (line-based)
4. Variable inspection
5. Call stack view

**Implementation Approach:**
- Integrate `mobdebug.lua` or implement custom DAP server
- Use existing callback system for debug hooks
- Leverage `lua_sethook()` for line/call events

**Files to create:**
- New: `src/debug/dap_server.c`, `src/debug/dap_server.h`
- New: `src/debug/debugger.lua` (Lua-side hooks)

**Effort:** 2-3 weeks (separate issue tracking)

---

## Implementation Priority

| Phase | Feature | Priority | Effort | Impact |
|-------|---------|----------|--------|--------|
| 1 | Lua Logging API | HIGH | 2-3h | Modders can use proper logging |
| 2 | Event Tracing | HIGH | 1-2h | Debug one-frame events |
| 3 | TypeId Feedback | HIGH | 1h | Faster component troubleshooting |
| 4 | Enhanced Tests | MEDIUM | 3-4h | Better test coverage |
| 5 | Log Rotation | MEDIUM | 1-2h | Prevent disk fill |
| 6 | Profiling API | MEDIUM | 2h | Performance measurement |
| 7 | VS Code DAP | LOW | 2-3 weeks | Full debugging (Issue #42) |

**Recommended Order:** 1 → 3 → 2 → 4 → 5 → 6 → 7

Phases 1-3 directly address the immediate pain point of debugging API development.
Phase 4-6 improve developer experience.
Phase 7 is a larger effort tracked in Issue #42.

---

## Success Metrics

After implementing Phases 1-3:
- Modders can see event activity via `Ext.Debug.TraceEvents(true)`
- TypeId resolution issues are immediately visible via `!typeids`
- Logs include module context for filtering
- API development cycle is faster due to better visibility

---

## Related GitHub Issues

| Issue | Title | Relevance to This Plan |
|-------|-------|------------------------|
| **#42** | Debugger Support (VS Code Integration) | Phase 7 foundation work |
| **#36** | Ext.IMGUI Debug Overlay | Could integrate log viewer widget |
| **#8** | Technical Debt: stability, testing | Phase 4 test framework improvements |
| **#51** | Ext.Events Expansion | Phase 2 event tracing helps verify |
| **#7** | Type system and IDE integration | Complements debugging with autocomplete |
| **#48** | Ext.Types Full Reflection | `GetFunctionLocation()` aids debugging |
| **#53** | Stats Functor System | Phase 2 tracing useful for functor debugging |
| **#46** | API Context Annotations | Phase 1 logs could include C/S/R context |

**Not directly related:** #38 (Audio), #37 (Physics), #35 (UI), #6 (NetChannel), #24 (Process question)

---

## Next Steps

1. **Immediate**: Implement Phase 1 (Lua Logging API) and Phase 3 (TypeId Feedback)
2. **This Week**: Implement Phase 2 (Event Tracing)
3. **Ongoing**: Phase 4-6 as time permits
4. **Future**: Phase 7 tracked separately in Issue #42
