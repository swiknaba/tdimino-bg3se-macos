/**
 * BG3SE-macOS - Lua Context Management Implementation
 *
 * Manages the current Lua execution context (Server/Client).
 * Used for API partitioning and proper bootstrap file loading.
 */

#include "lua_context.h"
#include "logging.h"

#include <lauxlib.h>

// ============================================================================
// Static State
// ============================================================================

static LuaContext g_current_context = LUA_CONTEXT_NONE;
static int g_initialized = 0;

// Context name strings
static const char* g_context_names[] = {
    "None",
    "Server",
    "Client"
};

// ============================================================================
// Context Management Implementation
// ============================================================================

void lua_context_init(void) {
    if (g_initialized) return;

    g_current_context = LUA_CONTEXT_NONE;
    g_initialized = 1;

    LOG_LUA_INFO("Lua context system initialized");
}

void lua_context_set(LuaContext ctx) {
    if (ctx < LUA_CONTEXT_NONE || ctx > LUA_CONTEXT_CLIENT) {
        LOG_LUA_ERROR("Invalid context value: %d", ctx);
        return;
    }

    LuaContext old_ctx = g_current_context;
    g_current_context = ctx;

    if (old_ctx != ctx) {
        LOG_LUA_INFO("Lua context changed: %s -> %s",
                    lua_context_get_name(old_ctx),
                    lua_context_get_name(ctx));
    }
}

LuaContext lua_context_get(void) {
    return g_current_context;
}

int lua_context_is_server(void) {
    return g_current_context == LUA_CONTEXT_SERVER;
}

int lua_context_is_client(void) {
    return g_current_context == LUA_CONTEXT_CLIENT;
}

const char* lua_context_get_name(LuaContext ctx) {
    if (ctx >= LUA_CONTEXT_NONE && ctx <= LUA_CONTEXT_CLIENT) {
        return g_context_names[ctx];
    }
    return "Unknown";
}

// ============================================================================
// Lua API Implementation
// ============================================================================

int lua_ext_context_isserver(lua_State *L) {
    (void)L;  // Unused but required by Lua C API signature
    lua_pushboolean(L, lua_context_is_server());
    return 1;
}

int lua_ext_context_isclient(lua_State *L) {
    (void)L;  // Unused but required by Lua C API signature
    lua_pushboolean(L, lua_context_is_client());
    return 1;
}

int lua_ext_context_getcontext(lua_State *L) {
    (void)L;  // Unused but required by Lua C API signature
    lua_pushstring(L, lua_context_get_name(g_current_context));
    return 1;
}
