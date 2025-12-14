/**
 * lua_debug.h - Debug/Introspection API for BG3SE-macOS
 *
 * Provides low-level memory reading and struct probing utilities for
 * rapid iteration on offset discovery and runtime debugging.
 *
 * All memory reads use safe_memory APIs to prevent crashes on invalid addresses.
 */

#ifndef LUA_DEBUG_H
#define LUA_DEBUG_H

#include <lua.h>
#include <lauxlib.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Low-level Memory Reading (Ext.Debug.*)
// ============================================================================

/**
 * Ext.Debug.ReadPtr(addr) - Read pointer value at address
 * @param addr Address as integer
 * @return Pointer value as integer, or nil on invalid address
 */
int lua_debug_read_ptr(lua_State *L);

/**
 * Ext.Debug.ReadU32(addr) - Read uint32 at address
 * @param addr Address as integer
 * @return Value as integer, or nil on invalid address
 */
int lua_debug_read_u32(lua_State *L);

/**
 * Ext.Debug.ReadU64(addr) - Read uint64 at address
 * @param addr Address as integer
 * @return Value as integer, or nil on invalid address
 */
int lua_debug_read_u64(lua_State *L);

/**
 * Ext.Debug.ReadI32(addr) - Read int32 at address
 * @param addr Address as integer
 * @return Value as integer, or nil on invalid address
 */
int lua_debug_read_i32(lua_State *L);

/**
 * Ext.Debug.ReadFloat(addr) - Read float at address
 * @param addr Address as integer
 * @return Value as number, or nil on invalid address
 */
int lua_debug_read_float(lua_State *L);

/**
 * Ext.Debug.ReadString(addr, maxLen) - Read null-terminated string
 * @param addr Address as integer
 * @param maxLen Maximum length (default 256)
 * @return String, or nil on invalid address
 */
int lua_debug_read_string(lua_State *L);

/**
 * Ext.Debug.ReadFixedString(addr) - Read FixedString value
 * @param addr Address pointing to a FixedString index
 * @return Resolved string, or nil on invalid address
 */
int lua_debug_read_fixedstring(lua_State *L);

// ============================================================================
// Struct Probing Utilities (Ext.Debug.*)
// ============================================================================

/**
 * Ext.Debug.ProbeStruct(base, startOffset, endOffset, stride) - Probe memory range
 * @param base Base address
 * @param startOffset Start offset from base (default 0)
 * @param endOffset End offset from base (default 0x100)
 * @param stride Step size (default 8)
 * @return Table: { [offset] = { ptr=..., u32=..., i32=..., float=... } }
 */
int lua_debug_probe_struct(lua_State *L);

/**
 * Ext.Debug.FindArrayPattern(base, range) - Find array-like structures
 * Scans for patterns typical of game arrays: (ptr, u32 capacity, u32 size)
 * @param base Base address to scan from
 * @param range Number of bytes to scan (default 0x1000)
 * @return Table of candidate offsets with their values
 */
int lua_debug_find_array_pattern(lua_State *L);

/**
 * Ext.Debug.ProbeFixedStringArray(base, offset, count) - Read array of FixedStrings
 * @param base Base address
 * @param offset Offset to array start (default 0)
 * @param count Number of entries to read (default 10, max 1000)
 * @return Table of { index, fs_index, value } entries
 */
int lua_debug_probe_fixedstring_array(lua_State *L);

/**
 * Ext.Debug.HexDump(addr, size) - Format memory as hex dump
 * @param addr Address
 * @param size Number of bytes (default 64)
 * @return Formatted hex dump string
 */
int lua_debug_hex_dump(lua_State *L);

// ============================================================================
// Time and Session Utilities (Ext.Debug.*)
// ============================================================================

/**
 * Ext.Debug.Time() - Get current time as HH:MM:SS string
 * Useful for correlating console commands with log output.
 * @return Time string like "14:35:22"
 */
int lua_debug_time(lua_State *L);

/**
 * Ext.Debug.Timestamp() - Get current Unix timestamp
 * @return Unix timestamp (seconds since epoch)
 */
int lua_debug_timestamp(lua_State *L);

/**
 * Ext.Debug.SessionStart() - Get session start time as HH:MM:SS
 * @return Time string when BG3SE was initialized
 */
int lua_debug_session_start(lua_State *L);

/**
 * Ext.Debug.SessionAge() - Get seconds since session started
 * @return Number of seconds since BG3SE was initialized
 */
int lua_debug_session_age(lua_State *L);

/**
 * Ext.Debug.PrintTime(msg) - Print message with timestamp prefix
 * Shortcut for Ext.Print("[HH:MM:SS] " .. msg)
 * @param msg Message to print
 */
int lua_debug_print_time(lua_State *L);

// ============================================================================
// Pointer Validation and Classification (Ext.Debug.*)
// ============================================================================

/**
 * Ext.Debug.IsValidPointer(addr) - Check if pointer is readable
 * @param addr Address to check
 * @return true if the address can be read, false otherwise
 */
int lua_debug_is_valid_pointer(lua_State *L);

/**
 * Ext.Debug.ClassifyPointer(addr) - Classify what a pointer likely points to
 * Helps identify pointer types during reverse engineering.
 * @param addr Address to classify
 * @return Table with fields:
 *   - type: "null"|"small_int"|"invalid"|"string"|"vtable"|"heap"|"data"|"stack"
 *   - readable: boolean
 *   - preview: string (if type is "string")
 *   - value: integer (if type is "small_int")
 */
int lua_debug_classify_pointer(lua_State *L);

// ============================================================================
// Registration
// ============================================================================

/**
 * Register Ext.Debug namespace functions
 * @param L Lua state
 * @param ext_table_index Stack index of Ext table
 */
void lua_ext_register_debug(lua_State *L, int ext_table_index);

#ifdef __cplusplus
}
#endif

#endif // LUA_DEBUG_H
