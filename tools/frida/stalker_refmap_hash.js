/**
 * Frida Stalker script to trace RefMap hash function in BG3
 *
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 * !! WARNING: THIS SCRIPT CRASHES BG3 - USE trace_refmap_light.js !!
 * !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * Stalker.follow() recompiles every instruction the thread executes.
 * For a 1GB game binary, this causes:
 *   - Massive memory overhead
 *   - JIT recompilation lag
 *   - Thread timing violations -> crash
 *
 * Use trace_refmap_light.js instead (Interceptor-only, no Stalker).
 *
 * Original Purpose: Discover the exact hash algorithm used by SpellPrototypeManager's
 * RefMap to enable proper insertion of new spell prototypes.
 *
 * DEPRECATED - Kept for reference only.
 */

'use strict';

// Known offsets from Ghidra analysis
const OFFSETS = {
    // Module base will be resolved at runtime
    GET_SPELL_PROTOTYPE: 0x10346e740,      // GetSpellPrototype function
    REFMAP_FIND: 0x1011bbc5c,              // DEPRECATED_RefMapImpl::GetOrAdd
    SPELL_PROTOTYPE_MGR: 0x1089bac80       // SpellPrototypeManager singleton
};

// State for instruction tracing
let traceActive = false;
let instructionLog = [];
let registersAtEntry = {};

function getModuleBase() {
    const module = Process.findModuleByName("Baldur's Gate 3");
    if (!module) {
        console.log("[!] BG3 module not found");
        return null;
    }
    return module.base;
}

function resolveAddress(offset) {
    const base = getModuleBase();
    if (!base) return null;
    // The offsets in STATS.md include the base, so we need to subtract
    // Assuming offset is relative to module base (common Ghidra convention)
    return base.add(offset - 0x100000000);  // Adjust for typical macOS ASLR
}

function hexdump(addr, length) {
    try {
        const data = Memory.readByteArray(addr, length);
        const bytes = new Uint8Array(data);
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0') + ' ';
        }
        return hex.trim();
    } catch (e) {
        return '<unreadable>';
    }
}

function setupStalker(targetAddr, description) {
    console.log(`[*] Setting up Stalker on ${description} at ${targetAddr}`);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            console.log(`\n[+] ${description} called`);
            console.log(`    this: ${this.context.x0}`);
            console.log(`    arg1 (FixedString*): ${args[1]}`);

            // Read the FixedString value (uint32_t)
            try {
                const fsValue = args[1].readU32();
                console.log(`    FixedString value: ${fsValue} (0x${fsValue.toString(16)})`);
                console.log(`    Expected bucket (mod 12289): ${fsValue % 12289}`);
            } catch (e) {
                console.log(`    Could not read FixedString: ${e}`);
            }

            // Store entry context
            registersAtEntry = {
                x0: this.context.x0,
                x1: this.context.x1,
                x2: this.context.x2,
                x8: this.context.x8,
                x9: this.context.x9
            };

            // Start instruction-level tracing
            instructionLog = [];
            traceActive = true;

            const threadId = Process.getCurrentThreadId();
            Stalker.follow(threadId, {
                events: {
                    call: true,
                    ret: true,
                    compile: false
                },

                transform: function(iterator) {
                    let instruction;
                    while ((instruction = iterator.next()) !== null) {
                        // Log interesting instructions
                        const addr = instruction.address;
                        const mnemonic = instruction.mnemonic;
                        const opStr = instruction.opStr;

                        // Focus on arithmetic and memory operations (hash computation)
                        if (traceActive) {
                            const interestingOps = [
                                'mul', 'madd', 'msub',          // Multiplication
                                'udiv', 'sdiv',                  // Division
                                'and', 'orr', 'eor', 'bic',     // Bitwise
                                'lsl', 'lsr', 'asr', 'ror',     // Shifts
                                'add', 'sub',                    // Arithmetic
                                'ldr', 'str',                    // Memory
                                'ubfx', 'sbfx', 'ubfiz'         // Bitfield extract
                            ];

                            if (interestingOps.some(op => mnemonic.startsWith(op))) {
                                instructionLog.push({
                                    addr: addr.toString(),
                                    mnemonic: mnemonic,
                                    opStr: opStr
                                });
                            }
                        }

                        iterator.keep();
                    }
                }
            });
        },

        onLeave: function(retval) {
            traceActive = false;

            const threadId = Process.getCurrentThreadId();
            Stalker.unfollow(threadId);
            Stalker.garbageCollect();

            console.log(`[+] ${description} returned: ${retval}`);
            console.log(`[*] Captured ${instructionLog.length} interesting instructions`);

            // Dump instruction trace (limit to first 200)
            if (instructionLog.length > 0) {
                console.log('\n[*] Instruction trace (hash computation candidates):');
                const limit = Math.min(instructionLog.length, 200);
                for (let i = 0; i < limit; i++) {
                    const inst = instructionLog[i];
                    console.log(`    ${inst.addr}: ${inst.mnemonic} ${inst.opStr}`);
                }
                if (instructionLog.length > limit) {
                    console.log(`    ... (${instructionLog.length - limit} more)`);
                }
            }

            // Look for division by 12289 (RefMap capacity)
            const divInstructions = instructionLog.filter(i =>
                i.mnemonic === 'udiv' || i.mnemonic === 'sdiv'
            );
            if (divInstructions.length > 0) {
                console.log('\n[!] Division instructions found (likely modulo):');
                divInstructions.forEach(i => {
                    console.log(`    ${i.addr}: ${i.mnemonic} ${i.opStr}`);
                });
            }

            // Look for multiplication (often used in hash functions)
            const mulInstructions = instructionLog.filter(i =>
                i.mnemonic === 'mul' || i.mnemonic === 'madd'
            );
            if (mulInstructions.length > 0) {
                console.log('\n[!] Multiplication instructions (hash multiplier?):');
                mulInstructions.forEach(i => {
                    console.log(`    ${i.addr}: ${i.mnemonic} ${i.opStr}`);
                });
            }

            // Look for XOR operations (common in hash functions)
            const xorInstructions = instructionLog.filter(i => i.mnemonic === 'eor');
            if (xorInstructions.length > 0) {
                console.log('\n[!] XOR instructions (hash mixing?):');
                xorInstructions.forEach(i => {
                    console.log(`    ${i.addr}: ${i.mnemonic} ${i.opStr}`);
                });
            }
        }
    });
}

// Alternative: Simple intercept to watch hash behavior without full Stalker
function setupSimpleTrace(targetAddr, description) {
    console.log(`[*] Setting up simple trace on ${description} at ${targetAddr}`);

    Interceptor.attach(targetAddr, {
        onEnter: function(args) {
            // For GetOrAdd: this=RefMap, arg0=FixedString*, arg1=bool*
            const refmap = this.context.x0;
            const fsPtr = args[1];

            try {
                const fsValue = fsPtr.readU32();

                // Read RefMap structure
                const capacity = refmap.add(0x10).readU32();
                const buckets = refmap.add(0x08).readPointer();

                console.log(`\n[+] RefMap::GetOrAdd`);
                console.log(`    RefMap: ${refmap}`);
                console.log(`    FixedString: ${fsValue} (0x${fsValue.toString(16)})`);
                console.log(`    Capacity: ${capacity}`);
                console.log(`    Simple mod: ${fsValue % capacity}`);

                // Try to find the actual bucket by scanning
                this.fsValue = fsValue;
                this.capacity = capacity;
                this.refmap = refmap;
            } catch (e) {
                console.log(`[!] Error reading args: ${e}`);
            }
        },

        onLeave: function(retval) {
            try {
                // The return value points to the value slot
                // We can try to figure out which bucket it's in
                console.log(`    Result slot: ${retval}`);

                // The slot should be at: node + 0x10, where node is in a bucket chain
                // Can probe memory around return value to understand structure
            } catch (e) {
                console.log(`[!] Error in onLeave: ${e}`);
            }
        }
    });
}

// Hook to dump all GetSpellPrototype calls
function hookGetSpellPrototype() {
    const base = getModuleBase();
    if (!base) {
        console.log("[!] Could not get module base");
        return;
    }

    // The offset needs adjustment - let's try finding the function
    console.log(`[*] Module base: ${base}`);

    // Try pattern scanning for GetSpellPrototype
    // Function should have ADRP+LDR pattern loading SpellPrototypeManager
    const pattern = '?? ?? ?? ?? ?? ?? 00 91';  // Example pattern, adjust as needed

    // For now, try the documented offset with base adjustment
    const funcAddr = base.add(OFFSETS.GET_SPELL_PROTOTYPE - 0x100000000);

    console.log(`[*] Attempting to hook at ${funcAddr}`);

    try {
        Interceptor.attach(funcAddr, {
            onEnter: function(args) {
                console.log(`[+] GetSpellPrototype called`);
                try {
                    // Read FixedString from arg
                    const fs = args[0].readU32();
                    console.log(`    Spell FixedString: ${fs} (0x${fs.toString(16)})`);
                } catch (e) {
                    console.log(`    Args: x0=${this.context.x0}, x1=${this.context.x1}`);
                }
            }
        });
        console.log("[+] Hook installed successfully");
    } catch (e) {
        console.log(`[!] Failed to hook: ${e}`);
        console.log("[*] Function may be at different offset due to ASLR");
    }
}

// Export functions for interactive use
rpc.exports = {
    traceRefMap: function() {
        hookGetSpellPrototype();
    },

    readRefMapAt: function(addr) {
        const ptr = ptr(addr);
        console.log(`[*] Reading RefMap at ${ptr}`);
        try {
            const buckets = ptr.add(0x08).readPointer();
            const capacity = ptr.add(0x10).readU32();
            const nextChain = ptr.add(0x18).readPointer();
            const keys = ptr.add(0x28).readPointer();
            const values = ptr.add(0x38).readPointer();

            console.log(`    Buckets: ${buckets}`);
            console.log(`    Capacity: ${capacity}`);
            console.log(`    NextChain: ${nextChain}`);
            console.log(`    Keys: ${keys}`);
            console.log(`    Values: ${values}`);

            // Sample first few keys
            console.log(`\n    First 10 keys:`);
            for (let i = 0; i < 10; i++) {
                const key = keys.add(i * 4).readU32();
                console.log(`      [${i}] = ${key} (bucket would be ${key % capacity})`);
            }
        } catch (e) {
            console.log(`[!] Error: ${e}`);
        }
    },

    findSpellInRefMap: function(refmapAddr, fsValue) {
        const ptr = ptr(refmapAddr);
        const keys = ptr.add(0x28).readPointer();
        const values = ptr.add(0x38).readPointer();
        const capacity = ptr.add(0x10).readU32();

        console.log(`[*] Searching for FixedString ${fsValue} in ${capacity} slots`);

        for (let i = 0; i < capacity; i++) {
            const key = keys.add(i * 4).readU32();
            if (key === fsValue) {
                const value = values.add(i * 8).readPointer();
                console.log(`[+] Found at index ${i}!`);
                console.log(`    Key: ${key}`);
                console.log(`    Value (prototype ptr): ${value}`);
                console.log(`    Expected bucket (simple mod): ${key % capacity}`);
                console.log(`    Actual bucket: ${i}`);
                return i;
            }
        }
        console.log(`[-] Not found`);
        return -1;
    }
};

// Auto-run on load
console.log('[*] BG3 RefMap Hash Stalker loaded');
console.log('[*] Available RPC exports:');
console.log('    - traceRefMap(): Start tracing GetSpellPrototype calls');
console.log('    - readRefMapAt(addr): Dump RefMap structure');
console.log('    - findSpellInRefMap(addr, fs): Search for FixedString in RefMap');
console.log('');
console.log('[*] To use interactively:');
console.log('    rpc.exports.traceRefMap()');
