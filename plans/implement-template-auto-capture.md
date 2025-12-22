# Plan: Template Manager Auto-Capture

## Status: ✅ COMPLETE (2025-12-21)

## Summary

Template auto-capture implemented using **direct global pointer reads** instead of function hooking. ARM64 ADRP constraints blocked the original hook-based approach, but Ghidra analysis revealed global singleton pointers that can be read directly.

## What Works

| API | Status | Notes |
|-----|--------|-------|
| `Ext.Template.IsReady()` | ✅ | Returns true after lazy init |
| `Ext.Template.GetCount("Cache")` | ✅ | Returns template count (e.g., 61) |
| `Ext.Template.GetCount("LocalCache")` | ✅ | Returns template count (e.g., 19) |
| `Ext.Template.GetAllCacheTemplates()` | ✅ | Returns array with GUIDs |
| `Ext.Template.GetAllLocalCacheTemplates()` | ✅ | Returns array with GUIDs |
| `Ext.Template.DumpStatus()` | ✅ | Shows captured managers |

## Solution: Direct Global Pointer Read

Instead of hooking functions, we read template manager singletons directly from known offsets.

### Global Pointer Offsets (Verified 2025-12-21)

| Pointer | Offset from Base | Status |
|---------|------------------|--------|
| `ls::GlobalTemplateManager::m_ptr` | `0x08a88508` | ✅ Captured |
| `CacheTemplateManager::m_ptr` | `0x08a309a8` | ✅ Captured |
| `Level::s_CacheTemplateManager` | `0x08a735d8` | ✅ Captured |
| `LevelManager::m_ptr` | `0x08a3be40` | Available |

### CacheTemplateManagerBase Structure (Verified 2025-12-21)

| Offset | Type | Purpose |
|--------|------|---------|
| `+0x50` | `void*` | Hash bucket array pointer |
| `+0x58` | `uint32_t` | Bucket count |
| `+0x60` | `void*` | Next chain array |
| `+0x70` | `void*` | Key array (TemplateHandle) |
| `+0x80` | `void*` | **Value array (template pointers)** |
| `+0x98` | `uint32_t` | **Template count** |

### GameObjectTemplate Structure

| Offset | Type | Purpose |
|--------|------|---------|
| `+0x00` | `void*` | vtable pointer |
| `+0x10` | `uint32_t` | **FixedString index containing GUID** |

## Why Hooks Failed

The `GetTemplateRaw` function has an ADRP instruction at offset +0xC:

```
+0x00: stp x20, x19, [sp, #-0x20]!
+0x04: stp x29, x30, [sp, #0x10]     ← Safe hook point
+0x08: add x29, sp, #0x10
+0x0C: adrp x8, 0x108a88000          ← PC-relative! Cannot overwrite
```

- **Safe space:** Only 8 bytes (+0x4 to +0xC)
- **Required:** 16 bytes for absolute branch (when trampoline is far)
- **Result:** Hook corrupts ADRP instruction → crash

## Key Discoveries

1. **GUID is a FixedString**: Template GUID at +0x10 is a FixedString index, not raw bytes. Must resolve via `fixed_string_resolve()`.

2. **Lazy initialization**: Global pointers are NULL at startup. Must retry on first API access.

3. **Vtable validation**: Value array may contain invalid pointers. Check vtable before accessing template properties.

4. **Hash table layout**: CacheTemplateManagerBase uses a hash table with separate arrays for buckets, chains, keys, and values.

## Files Modified

| File | Changes |
|------|---------|
| `src/template/template_manager.c` | Global pointer offsets, iteration implementation, GUID fix |
| `src/lua/lua_template.c` | Simplified push_template_to_lua |
| `ghidra/offsets/TEMPLATE.md` | Comprehensive documentation |

## Lessons Learned

1. **ARM64 ADRP constraints**: Functions with early ADRP (within first 12 bytes) cannot be safely hooked with Dobby
2. **Global pointers as alternative**: Many game singletons are accessible via direct pointer reads
3. **FixedString everywhere**: BG3 stores strings as FixedString indices, including GUIDs
4. **Safe memory access**: Always use safe_memory_read() for game memory access
5. **Vtable validation**: Check vtable pointer is in valid code range before using template

## Testing Commands

```lua
-- Check status
Ext.Template.IsReady()
Ext.Template.DumpStatus()

-- Get counts
Ext.Template.GetCount("Cache")
Ext.Template.GetCount("LocalCache")

-- Iterate templates
local templates = Ext.Template.GetAllCacheTemplates()
for i, t in ipairs(templates) do
    print(t.Guid)
end
```
