/**
 * Frida Instruction Trace for Complex Flow Analysis
 *
 * Enhanced instruction tracing for understanding complex code paths
 * like hash function computations, prototype initialization, and
 * multi-step data structure operations.
 *
 * Features:
 * - TraceBuffer for efficient capture
 * - Register state snapshots
 * - Memory access tracking
 * - Color-coded output
 * - Export to JSON for offline analysis
 *
 * Usage:
 *   frida -U -n "Baldur's Gate 3" -l itrace_complex_flows.js
 */

'use strict';

// ANSI color codes for output
const Colors = {
    RESET: '\x1b[0m',
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m',
    CYAN: '\x1b[36m',
    GRAY: '\x1b[90m'
};

// Trace configuration
const TraceConfig = {
    maxInstructions: 5000,
    captureRegisters: true,
    captureMemory: true,
    showAddresses: true,
    filterArithmetic: true
};

// Trace buffer for collected data
class TraceBuffer {
    constructor(maxSize) {
        this.maxSize = maxSize;
        this.entries = [];
        this.startTime = Date.now();
    }

    add(entry) {
        if (this.entries.length >= this.maxSize) {
            return false;
        }
        entry.timestamp = Date.now() - this.startTime;
        this.entries.push(entry);
        return true;
    }

    clear() {
        this.entries = [];
        this.startTime = Date.now();
    }

    toJSON() {
        return JSON.stringify({
            captured: this.entries.length,
            maxSize: this.maxSize,
            durationMs: Date.now() - this.startTime,
            entries: this.entries
        }, null, 2);
    }

    summarize() {
        const mnemonicCounts = {};
        this.entries.forEach(e => {
            mnemonicCounts[e.mnemonic] = (mnemonicCounts[e.mnemonic] || 0) + 1;
        });
        return mnemonicCounts;
    }
}

// Global trace buffer
let globalBuffer = new TraceBuffer(TraceConfig.maxInstructions);

// Known function addresses (from Ghidra analysis)
const KnownFunctions = {
    SpellPrototypeInit: 0x101f72754,
    RefMapGetOrAdd: 0x1011bbc5c,
    GetSpellPrototype: 0x10346e740,
    StatusInit: 0x0,  // TODO: Discover
    PassiveInit: 0x0  // TODO: Discover
};

function colorize(text, color) {
    return `${color}${text}${Colors.RESET}`;
}

function formatAddress(addr) {
    return colorize(`0x${addr.toString(16).padStart(12, '0')}`, Colors.GRAY);
}

function formatMnemonic(mnemonic) {
    // Color-code by instruction type
    if (['mul', 'madd', 'msub', 'udiv', 'sdiv'].includes(mnemonic)) {
        return colorize(mnemonic.padEnd(8), Colors.RED);  // Arithmetic
    }
    if (['eor', 'and', 'orr', 'bic'].includes(mnemonic)) {
        return colorize(mnemonic.padEnd(8), Colors.YELLOW);  // Bitwise
    }
    if (['lsl', 'lsr', 'asr', 'ror'].includes(mnemonic)) {
        return colorize(mnemonic.padEnd(8), Colors.MAGENTA);  // Shifts
    }
    if (['ldr', 'str', 'ldp', 'stp'].includes(mnemonic)) {
        return colorize(mnemonic.padEnd(8), Colors.CYAN);  // Memory
    }
    if (['bl', 'blr', 'b', 'ret'].includes(mnemonic)) {
        return colorize(mnemonic.padEnd(8), Colors.GREEN);  // Control flow
    }
    return mnemonic.padEnd(8);
}

function captureRegisters(context) {
    return {
        x0: context.x0.toString(),
        x1: context.x1.toString(),
        x2: context.x2.toString(),
        x8: context.x8.toString(),
        x9: context.x9.toString(),
        x10: context.x10.toString(),
        sp: context.sp.toString()
    };
}

function setupDetailedTrace(targetAddr, name) {
    console.log(`[*] Setting up detailed trace on ${name} at ${ptr(targetAddr)}`);

    Interceptor.attach(ptr(targetAddr), {
        onEnter: function(args) {
            console.log(`\n${colorize('[+] ENTER:', Colors.GREEN)} ${name}`);

            // Capture entry state
            const entryRegs = captureRegisters(this.context);
            console.log(`    ${colorize('x0:', Colors.CYAN)} ${entryRegs.x0}`);
            console.log(`    ${colorize('x1:', Colors.CYAN)} ${entryRegs.x1}`);

            globalBuffer.clear();

            // Start Stalker with detailed transform
            const threadId = Process.getCurrentThreadId();
            Stalker.follow(threadId, {
                events: { call: true, ret: true },

                transform: function(iterator) {
                    let instruction;
                    while ((instruction = iterator.next()) !== null) {
                        const addr = instruction.address;
                        const mnemonic = instruction.mnemonic;
                        const opStr = instruction.opStr;

                        // Build entry
                        const entry = {
                            addr: addr.toString(),
                            mnemonic: mnemonic,
                            operands: opStr
                        };

                        // Filter if configured
                        if (TraceConfig.filterArithmetic) {
                            const interesting = [
                                'mul', 'madd', 'msub', 'udiv', 'sdiv',
                                'and', 'orr', 'eor', 'bic',
                                'lsl', 'lsr', 'asr', 'ror',
                                'ubfx', 'sbfx', 'ubfiz'
                            ];
                            if (interesting.some(op => mnemonic.startsWith(op))) {
                                globalBuffer.add(entry);
                            }
                        } else {
                            globalBuffer.add(entry);
                        }

                        iterator.keep();
                    }
                }
            });

            this.threadId = threadId;
        },

        onLeave: function(retval) {
            Stalker.unfollow(this.threadId);
            Stalker.garbageCollect();

            console.log(`${colorize('[+] LEAVE:', Colors.RED)} ${name}`);
            console.log(`    ${colorize('Return:', Colors.CYAN)} ${retval}`);
            console.log(`    ${colorize('Captured:', Colors.CYAN)} ${globalBuffer.entries.length} instructions`);

            // Print summary
            const summary = globalBuffer.summarize();
            console.log(`\n${colorize('Instruction Summary:', Colors.YELLOW)}`);
            Object.entries(summary)
                .sort((a, b) => b[1] - a[1])
                .slice(0, 10)
                .forEach(([mnem, count]) => {
                    console.log(`    ${formatMnemonic(mnem)} x ${count}`);
                });

            // Print trace (first N entries)
            console.log(`\n${colorize('Instruction Trace:', Colors.YELLOW)}`);
            const limit = Math.min(globalBuffer.entries.length, 100);
            for (let i = 0; i < limit; i++) {
                const e = globalBuffer.entries[i];
                console.log(`  ${formatAddress(e.addr)} ${formatMnemonic(e.mnemonic)} ${e.operands}`);
            }
            if (globalBuffer.entries.length > limit) {
                console.log(`  ${colorize('...', Colors.GRAY)} (${globalBuffer.entries.length - limit} more)`);
            }
        }
    });
}

// Memory watchpoint helper
function watchMemory(addr, size, label) {
    const watchAddr = ptr(addr);
    console.log(`[*] Watching ${size} bytes at ${watchAddr} (${label})`);

    MemoryAccessMonitor.enable([{
        base: watchAddr,
        size: size
    }], {
        onAccess: function(details) {
            console.log(`[!] Memory ${details.operation} at ${details.address}`);
            console.log(`    From: ${details.from}`);
            if (details.operation === 'write') {
                console.log(`    Value: ${Memory.readByteArray(details.address, Math.min(size, 16))}`);
            }
        }
    });
}

// Export functions for interactive use
rpc.exports = {
    // Trace a specific function
    trace: function(addr, name) {
        setupDetailedTrace(addr, name || `func_${addr}`);
    },

    // Trace SpellPrototype::Init
    traceSpellInit: function() {
        setupDetailedTrace(KnownFunctions.SpellPrototypeInit, 'SpellPrototype::Init');
    },

    // Trace RefMap::GetOrAdd
    traceRefMap: function() {
        setupDetailedTrace(KnownFunctions.RefMapGetOrAdd, 'RefMap::GetOrAdd');
    },

    // Get trace buffer as JSON
    getTrace: function() {
        return globalBuffer.toJSON();
    },

    // Save trace to file
    saveTrace: function(filename) {
        const path = filename || '/tmp/bg3_itrace.json';
        const file = new File(path, 'w');
        file.write(globalBuffer.toJSON());
        file.flush();
        file.close();
        console.log(`[+] Trace saved to ${path}`);
    },

    // Clear trace buffer
    clearTrace: function() {
        globalBuffer.clear();
        console.log('[*] Trace buffer cleared');
    },

    // Get instruction summary
    getSummary: function() {
        return globalBuffer.summarize();
    },

    // Configure trace options
    configure: function(options) {
        Object.assign(TraceConfig, options);
        console.log('[*] Configuration updated:', JSON.stringify(TraceConfig));
    },

    // Watch memory region
    watch: function(addr, size, label) {
        watchMemory(addr, size, label);
    }
};

// Auto-start message
console.log(`
${colorize('=== BG3 Instruction Trace ===', Colors.GREEN)}

${colorize('Available RPC exports:', Colors.YELLOW)}
  rpc.exports.trace(addr, name)     - Trace function at address
  rpc.exports.traceSpellInit()      - Trace SpellPrototype::Init
  rpc.exports.traceRefMap()         - Trace RefMap::GetOrAdd
  rpc.exports.getTrace()            - Get trace buffer as JSON
  rpc.exports.saveTrace(path)       - Save trace to file
  rpc.exports.clearTrace()          - Clear trace buffer
  rpc.exports.getSummary()          - Get instruction counts
  rpc.exports.configure(opts)       - Set trace options
  rpc.exports.watch(addr, sz, lbl)  - Watch memory region

${colorize('Example:', Colors.CYAN)}
  rpc.exports.traceSpellInit()
  // ... trigger spell prototype initialization in game ...
  rpc.exports.saveTrace('/tmp/spell_init.json')
`);
