/**
 * BG3SE-macOS - Lua Context Management
 *
 * Tracks whether Lua code is executing in Server or Client context.
 * This enables proper API partitioning:
 * - Server context: Osiris calls, entity/stats writes
 * - Client context: Input, UI operations
 * - Both: Reading data, events, timers
 */

#ifndef LUA_CONTEXT_H
#define LUA_CONTEXT_H

#include <lua.h>

// ============================================================================
// Context Types
// ============================================================================

typedef enum {
    LUA_CONTEXT_NONE = 0,    // No context set (initialization)
    LUA_CONTEXT_SERVER = 1,  // Server context (Osiris, game logic)
    LUA_CONTEXT_CLIENT = 2   // Client context (UI, input)
} LuaContext;

// ============================================================================
// Context Management API
// ============================================================================

/**
 * Initialize the context system.
 * Called once during Lua runtime initialization.
 */
void lua_context_init(void);

/**
 * Set the current execution context.
 * Called when entering server or client bootstrap loading.
 */
void lua_context_set(LuaContext ctx);

/**
 * Get the current execution context.
 */
LuaContext lua_context_get(void);

/**
 * Check if currently in server context.
 * Returns 1 if server context, 0 otherwise.
 */
int lua_context_is_server(void);

/**
 * Check if currently in client context.
 * Returns 1 if client context, 0 otherwise.
 */
int lua_context_is_client(void);

/**
 * Get context name as string.
 * Returns "Server", "Client", or "None".
 */
const char* lua_context_get_name(LuaContext ctx);

// ============================================================================
// Lua API Functions
// ============================================================================

/**
 * Ext.IsServer() - Returns true if in server context
 */
int lua_ext_context_isserver(lua_State *L);

/**
 * Ext.IsClient() - Returns true if in client context
 */
int lua_ext_context_isclient(lua_State *L);

/**
 * Ext.GetContext() - Returns "Server", "Client", or "None"
 */
int lua_ext_context_getcontext(lua_State *L);

#endif // LUA_CONTEXT_H
