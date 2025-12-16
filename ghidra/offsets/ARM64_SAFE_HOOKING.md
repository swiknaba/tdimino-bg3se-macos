# ARM64 Safe Hooking Implementation

**Issue:** #44 - ARM64-Safe Inline Hooking
**Status:** Implemented (Dec 2025)

## Problem Statement

ARM64's `ADRP+LDR` instruction pairs encode PC-relative offsets. When Dobby relocates instructions to a trampoline, the PC changes, causing the offset calculation to point to wrong addresses. This corrupts function prologues that load global pointers.

**Symptoms:**
- Hooks intercept correctly but break original function call
- Game crashes or behaves incorrectly after hook
- Feat selection UI broken when GetFeats hooked

## Solution: Skip-and-Redirect Hooking

Instead of relocating ADRP+LDR instructions, we:
1. Analyze the function prologue to find ADRP patterns
2. Skip past all PC-relative instructions
3. Install hook at the safe point (after ADRP+LDR sequence)
4. Trampoline executes skipped prologue + continues to original

## Implementation Files

| File | Purpose |
|------|---------|
| `src/hooks/arm64_decode.h` | ARM64 instruction decoding API |
| `src/hooks/arm64_decode.c` | Instruction decoder implementation |
| `src/hooks/arm64_hook.h` | Safe hooking API |
| `src/hooks/arm64_hook.c` | Skip-and-redirect hook implementation |
| `tools/frida/analyze_prologue.js` | Frida script for runtime prologue analysis |

## ARM64 Instruction Patterns

### ADRP (Address of Page)
```
Encoding: 1 immlo[1:0] 10000 immhi[18:0] Rd[4:0]
Mask:     0x9F000000
Opcode:   0x90000000

Computes: Xd = (PC & ~0xFFF) + (imm21 << 12)
```

### LDR Immediate (64-bit)
```
Encoding: 11 111 0 01 01 imm12[11:0] Rn[4:0] Rt[4:0]
Mask:     0xFFC00000
Opcode:   0xF9400000

Computes: Xt = *(Xn + imm12 * 8)
```

### ADRP+LDR Pattern
```asm
ADRP X8, #0x1089b0000     ; X8 = page containing global
LDR  X8, [X8, #0xac80]    ; X8 = *(X8 + 0xac80) = global value
```

## API Usage

### Analyzing a Function
```c
#include "arm64_hook.h"

void* func = (void*)0x101b752b4;

// Check if function has ADRP in prologue
if (arm64_has_prologue_adrp(func)) {
    // Get safe hook point
    int offset = arm64_get_recommended_hook_offset(func);
    printf("Safe to hook at +%d bytes\n", offset);
}

// Detailed analysis with logging
arm64_analyze_and_log(func, "MyFunction");
```

### Installing a Safe Hook
```c
#include "arm64_hook.h"

typedef void (*OrigFunc_t)(void* arg);
OrigFunc_t g_original = NULL;

void my_hook(void* arg) {
    // Pre-processing
    printf("Hooked! arg=%p\n", arg);

    // Call original (via trampoline that includes skipped prologue)
    if (g_original) {
        g_original(arg);
    }
}

bool install_hook(void* target) {
    void* original = NULL;
    ARM64HookHandle* handle = arm64_safe_hook(target, my_hook, &original);

    if (handle) {
        g_original = (OrigFunc_t)original;
        return true;
    }
    return false;
}
```

### Hook at Specific Offset
```c
// If you know the safe offset from Frida analysis
ARM64HookHandle* handle = arm64_hook_at_offset(
    target,
    16,  // Skip 16 bytes (4 instructions)
    my_hook,
    &original
);
```

## Trampoline Structure

When hooking at offset N:
```
Trampoline layout:
  [0..N-1]    Original prologue (runs ADRP+LDR at correct PC)
  [N..N+3]    Overwritten instructions from hook point
  [N+4..]     Branch back to original (after hook point)

Hook point:
  [target+N]  Branch to replacement function
```

## Key Functions

| Function | Description |
|----------|-------------|
| `arm64_is_adrp(insn)` | Check if instruction is ADRP |
| `arm64_is_ldr_imm(insn)` | Check if instruction is LDR immediate |
| `arm64_is_pc_relative(insn)` | Check if any PC-relative instruction |
| `arm64_decode_adrp_target(insn, pc)` | Compute ADRP target page |
| `arm64_analyze_prologue(func, max, out)` | Full prologue analysis |
| `arm64_find_safe_hook_point(func, max)` | Find safe offset |
| `arm64_safe_hook(target, replacement, out_orig)` | Install safe hook |
| `arm64_unhook(handle)` | Remove hook |

## FeatManager::GetFeats Analysis

**Address:** `0x101b752b4`
**Offset:** `0x01b752b4` from base

Expected prologue pattern:
```asm
+00: STP  x29, x30, [sp, #-0x20]!  ; Save frame
+04: ADRP x8, #page                 ; Load global page - UNSAFE
+08: LDR  x8, [x8, #offset]        ; Load global ptr  - UNSAFE
+0C: MOV  x29, sp                   ; Frame pointer
+10: ...                            ; Safe to hook here
```

**Safe hook point:** After ADRP+LDR pair (typically +0x10 or +0x14)

## Integration with StaticData

The StaticData manager uses ARM64 safe hooks for FeatManager::GetFeats:

```c
// staticdata_manager.c
static bool install_feat_getfeats_safe_hook(void* base) {
    void* target = (uint8_t*)base + OFFSET_FEAT_GETFEATS;

    // Analyze prologue
    arm64_analyze_and_log(target, "FeatManager::GetFeats");

    // Check for ADRP
    if (arm64_has_prologue_adrp(target)) {
        // Install safe hook
        void* original = NULL;
        g_staticdata.feat_getfeats_hook = arm64_safe_hook(
            target, hook_FeatGetFeats, &original);

        if (g_staticdata.feat_getfeats_hook) {
            g_orig_FeatGetFeats = (FeatGetFeats_t)original;
            return true;
        }
    }
    return false;
}
```

## Testing

### With Frida
```bash
# Attach to running game and analyze prologue
frida -p $(pgrep -f "Baldur") -l tools/frida/analyze_prologue.js
```

### In-Game
The safe hook is automatically installed on session start. Check logs:
```
[StaticData] Analyzing FeatManager::GetFeats prologue at 0x...
[ARM64] === Prologue Analysis: ... ===
[ARM64] +00: ... ADRP ... [PC-relative - UNSAFE]
[ARM64] +04: ... LDR ...
[ARM64] +08: ... <-- SAFE HOOK POINT
[StaticData] ARM64 safe hook installed successfully!
```

## Fallback Behavior

If safe hook installation fails:
1. Falls back to TypeContext capture
2. Frida scripts remain available for manual capture
3. Game functionality preserved (no crashes)

## Future Improvements

1. **ADRP Recalculation:** Instead of skipping, recalculate ADRP immediate for new PC
2. **Pattern Database:** Build catalog of function patterns for known hooks
3. **Automatic Detection:** Scan all hook targets at load time
