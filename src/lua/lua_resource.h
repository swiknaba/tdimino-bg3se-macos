/**
 * lua_resource.h - Lua bindings for Ext.Resource API
 *
 * Provides Lua access to game resources (Visual, Sound, Material, etc.)
 */

#ifndef LUA_RESOURCE_H
#define LUA_RESOURCE_H

#include <lua.h>

/**
 * Register Ext.Resource API with the Lua state.
 *
 * @param L Lua state
 * @param ext_table_idx Stack index of Ext table
 */
void lua_resource_register(lua_State *L, int ext_table_idx);

#endif // LUA_RESOURCE_H
