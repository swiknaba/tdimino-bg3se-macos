/**
 * trace_refmap_light.js - Lightweight RefMap tracing (NO STALKER)
 *
 * IMPORTANT: This script uses ONLY Interceptor hooks, not Stalker.
 * Stalker recompiles every instruction and crashes BG3.
 *
 * Usage:
 *   frida -p $(pgrep "Baldur") -l trace_refmap_light.js
 */

'use strict';

// Known offsets from Ghidra analysis (STATS.md)
const OFFSETS = {
    GET_SPELL_PROTOTYPE: 0x10346e740,   // GetSpellPrototype (wrapper)
    REFMAP_GET_OR_ADD: 0x1011bbc5c,     // DEPRECATED_RefMapImpl::GetOrAdd
    SPELL_PROTOTYPE_MGR: 0x1089bac80,   // SpellPrototypeManager singleton
    SPELL_PROTOTYPE_INIT: 0x101f72754   // SpellPrototype::Init
};

// Ghidra base offset (typical macOS load address)
const GHIDRA_BASE = 0x100000000;

function getModuleBase() {
    const module = Process.findModuleByName("Baldur's Gate 3");
    if (!module) {
        console.log("[!] BG3 module not found");
        return null;
    }
    console.log(`[*] Module base: ${module.base}`);
    return module.base;
}

function resolveOffset(ghidraOffset) {
    const base = getModuleBase();
    if (!base) return null;
    return base.add(ghidraOffset - GHIDRA_BASE);
}

function setupLightweightHooks() {
    const base = getModuleBase();
    if (!base) return;

    // Hook GetOrAdd to observe hash behavior
    const getOrAddAddr = resolveOffset(OFFSETS.REFMAP_GET_OR_ADD);
    console.log(`[*] Hooking RefMap::GetOrAdd at ${getOrAddAddr}`);

    try {
        Interceptor.attach(getOrAddAddr, {
            onEnter: function(args) {
                // GetOrAdd(RefMap* this, FixedString* key, bool* wasAdded)
                this.refmap = this.context.x0;
                this.keyPtr = args[1];

                try {
                    this.fsValue = this.keyPtr.readU32();

                    // Read RefMap capacity from structure
                    const capacity = this.refmap.add(0x10).readU32();
                    const simpleMod = this.fsValue % capacity;

                    console.log(`\n[+] RefMap::GetOrAdd called`);
                    console.log(`    FixedString: ${this.fsValue} (0x${this.fsValue.toString(16)})`);
                    console.log(`    Capacity: ${capacity}`);
                    console.log(`    Simple key % cap: ${simpleMod}`);

                    this.capacity = capacity;
                } catch (e) {
                    console.log(`[!] Read error: ${e}`);
                }
            },
            onLeave: function(retval) {
                // Return value is pointer to value slot (node + 0x10)
                // The node is in a linked list starting at bucket[hash]
                console.log(`    Return (value slot): ${retval}`);

                // Try to determine actual bucket by examining node structure
                try {
                    // Node layout: next_ptr(8) + key(8) + value(8)
                    // retval points to value, so node = retval - 0x10
                    const node = retval.sub(0x10);
                    const storedKey = node.add(0x08).readU64();
                    console.log(`    Node at: ${node}`);
                    console.log(`    Stored key: ${storedKey}`);
                } catch (e) {
                    // May fail if retval is special value
                }
            }
        });
        console.log("[+] GetOrAdd hook installed");
    } catch (e) {
        console.log(`[!] Failed to hook GetOrAdd: ${e}`);
    }

    // Hook SpellPrototype::Init to see when prototypes are populated
    const initAddr = resolveOffset(OFFSETS.SPELL_PROTOTYPE_INIT);
    console.log(`[*] Hooking SpellPrototype::Init at ${initAddr}`);

    try {
        Interceptor.attach(initAddr, {
            onEnter: function(args) {
                // Init(SpellPrototype* this, FixedString const& spellName)
                // ARM64: const& = pointer
                const prototype = this.context.x0;
                const namePtr = args[1];

                try {
                    const fs = namePtr.readU32();
                    console.log(`\n[+] SpellPrototype::Init`);
                    console.log(`    Prototype: ${prototype}`);
                    console.log(`    SpellName FS: ${fs} (0x${fs.toString(16)})`);
                } catch (e) {
                    console.log(`[!] Init read error: ${e}`);
                }
            }
        });
        console.log("[+] Init hook installed");
    } catch (e) {
        console.log(`[!] Failed to hook Init: ${e}`);
    }
}

// RPC exports for interactive probing
rpc.exports = {
    // Dump RefMap structure at address
    dumpRefMap: function(addrStr) {
        const addr = ptr(addrStr);
        console.log(`\n[*] RefMap at ${addr}:`);
        try {
            const buckets = addr.add(0x08).readPointer();
            const capacity = addr.add(0x10).readU32();
            const nextChain = addr.add(0x18).readPointer();
            const keys = addr.add(0x28).readPointer();
            const values = addr.add(0x38).readPointer();

            console.log(`    Buckets: ${buckets}`);
            console.log(`    Capacity: ${capacity}`);
            console.log(`    NextChain: ${nextChain}`);
            console.log(`    Keys: ${keys}`);
            console.log(`    Values: ${values}`);

            // Sample entries
            console.log(`\n    Sample entries (first 10 non-zero):`);
            let found = 0;
            for (let i = 0; i < capacity && found < 10; i++) {
                const key = keys.add(i * 4).readU32();
                if (key !== 0) {
                    const value = values.add(i * 8).readPointer();
                    console.log(`      [${i}] key=${key} (mod=${key % capacity}) val=${value}`);
                    found++;
                }
            }
        } catch (e) {
            console.log(`[!] Error: ${e}`);
        }
    },

    // Search for a FixedString in RefMap
    findKey: function(addrStr, fsValue) {
        const addr = ptr(addrStr);
        const keys = addr.add(0x28).readPointer();
        const values = addr.add(0x38).readPointer();
        const capacity = addr.add(0x10).readU32();

        console.log(`[*] Searching for ${fsValue} in RefMap...`);
        for (let i = 0; i < capacity; i++) {
            const key = keys.add(i * 4).readU32();
            if (key === fsValue) {
                const value = values.add(i * 8).readPointer();
                console.log(`[+] FOUND at index ${i}`);
                console.log(`    Expected (key % cap): ${fsValue % capacity}`);
                console.log(`    Actual index: ${i}`);
                console.log(`    Value: ${value}`);
                return { index: i, expected: fsValue % capacity, value: value.toString() };
            }
        }
        console.log(`[-] Not found`);
        return null;
    }
};

console.log('');
console.log('=== BG3 RefMap Light Tracer ===');
console.log('');
console.log('This script uses ONLY Interceptor hooks (no Stalker).');
console.log('Stalker caused crashes due to full instruction recompilation.');
console.log('');

setupLightweightHooks();

console.log('');
console.log('[*] Hooks installed. Cast a spell or load a save to trigger.');
console.log('[*] RPC exports available: dumpRefMap(addr), findKey(addr, fs)');
