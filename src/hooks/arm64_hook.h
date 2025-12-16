/**
 * ARM64 Safe Hooking Module
 * Issue #44 - ARM64-Safe Inline Hooking
 *
 * Provides safe hooking for functions with ADRP+LDR PC-relative patterns
 * in their prologues. Uses skip-and-redirect strategy to avoid corrupting
 * PC-relative addressing.
 */

#ifndef ARM64_HOOK_H
#define ARM64_HOOK_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "arm64_decode.h"

// =============================================================================
// Hook Configuration
// =============================================================================

#define ARM64_HOOK_MAX_SKIP_BYTES 64     // Maximum bytes to skip before hooking
#define ARM64_HOOK_MIN_TRAMPOLINE 20     // Minimum trampoline allocation size
#define ARM64_HOOK_MAX_TRAMPOLINES 64    // Maximum concurrent hooks

// =============================================================================
// Hook Handle Structure
// =============================================================================

typedef struct {
    void* target_func;          // Original function address
    void* replacement_func;     // Replacement function address
    void* trampoline;          // Trampoline for calling original

    int skip_bytes;            // Bytes skipped (prologue we run in-place)
    int hook_offset;           // Offset where actual hook is installed

    uint32_t* saved_insns;     // Saved instructions (for restoration)
    int saved_insn_count;      // Number of saved instructions

    ARM64PrologueAnalysis prologue;  // Prologue analysis results

    bool active;               // Is hook currently active?
} ARM64HookHandle;

// =============================================================================
// Hook Management Functions
// =============================================================================

/**
 * Install a safe hook on a function with ADRP+LDR in prologue.
 *
 * Strategy: Analyze prologue, find safe hook point after PC-relative
 * instructions, install hook there. The original prologue runs unmodified.
 *
 * @param target        Function to hook
 * @param replacement   Replacement function (receives same args as original)
 * @param out_original  [out] Function pointer to call original implementation
 * @return              Hook handle on success, NULL on failure
 */
ARM64HookHandle* arm64_safe_hook(
    void* target,
    void* replacement,
    void** out_original
);

/**
 * Install hook at a specific offset in the function.
 *
 * Use when you know the safe offset (e.g., from Frida analysis).
 *
 * @param target        Function to hook
 * @param skip_bytes    Bytes to skip before installing hook
 * @param replacement   Replacement function
 * @param out_original  [out] Function pointer to call original
 * @return              Hook handle on success, NULL on failure
 */
ARM64HookHandle* arm64_hook_at_offset(
    void* target,
    int skip_bytes,
    void* replacement,
    void** out_original
);

/**
 * Remove a previously installed hook.
 *
 * @param handle  Hook handle from arm64_safe_hook or arm64_hook_at_offset
 * @return        true on success, false on failure
 */
bool arm64_unhook(ARM64HookHandle* handle);

/**
 * Remove all installed hooks.
 */
void arm64_unhook_all(void);

// =============================================================================
// Query Functions
// =============================================================================

/**
 * Check if a function has problematic ADRP patterns in prologue.
 *
 * @param func_addr  Function to check
 * @return           true if ADRP found in first 16 bytes
 */
bool arm64_has_prologue_adrp(void* func_addr);

/**
 * Get recommended hook offset for a function.
 *
 * @param func_addr  Function to analyze
 * @return           Safe hook offset in bytes, or -1 if none found
 */
int arm64_get_recommended_hook_offset(void* func_addr);

/**
 * Analyze a function and print results to log.
 */
void arm64_analyze_and_log(void* func_addr, const char* func_name);

// =============================================================================
// Low-level Utilities
// =============================================================================

/**
 * Allocate executable memory near target address.
 *
 * On ARM64, branch instructions have limited range. This tries to allocate
 * memory within ±128MB of the target.
 *
 * @param near_addr  Address to allocate near
 * @param size       Size in bytes
 * @return           Allocated address, or NULL on failure
 */
void* arm64_alloc_near(void* near_addr, size_t size);

/**
 * Free memory allocated by arm64_alloc_near.
 */
void arm64_free_near(void* addr, size_t size);

/**
 * Create a branch instruction to a target address.
 *
 * @param from      Source address (where branch will be placed)
 * @param to        Target address
 * @param is_call   true for BL (call), false for B (jump)
 * @return          Encoded branch instruction, or 0 if out of range
 */
uint32_t arm64_encode_branch(void* from, void* to, bool is_call);

/**
 * Write an instruction to memory (handles page protection).
 *
 * @param addr  Address to write to
 * @param insn  Instruction to write
 * @return      true on success
 */
bool arm64_write_instruction(void* addr, uint32_t insn);

/**
 * Write multiple instructions to memory.
 */
bool arm64_write_instructions(void* addr, const uint32_t* insns, int count);

// =============================================================================
// Initialization
// =============================================================================

/**
 * Initialize the ARM64 hooking system.
 * Called automatically on first use.
 */
void arm64_hook_init(void);

/**
 * Cleanup the ARM64 hooking system.
 * Removes all hooks and frees resources.
 */
void arm64_hook_cleanup(void);

#endif // ARM64_HOOK_H
