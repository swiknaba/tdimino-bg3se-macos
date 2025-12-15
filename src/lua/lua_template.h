/**
 * lua_template.h - Lua bindings for Ext.Template API
 *
 * Provides Lua access to game object templates (CharacterTemplate, ItemTemplate, etc.)
 */

#ifndef LUA_TEMPLATE_H
#define LUA_TEMPLATE_H

#include <lua.h>

/**
 * Register Ext.Template namespace and functions.
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_template_register(lua_State* L, int ext_table_index);

#endif // LUA_TEMPLATE_H
