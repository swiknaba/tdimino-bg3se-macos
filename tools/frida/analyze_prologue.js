/**
 * Meridian Investigation: ARM64 Prologue Analyzer
 * Issue #44 - ARM64-Safe Inline Hooking
 *
 * Run with: frida -p <PID> -l analyze_prologue.js
 *
 * Purpose: Analyze function prologues to find ADRP+LDR patterns
 * and determine safe hook points that avoid PC-relative corruption.
 */

// ARM64 instruction masks and opcodes
const ARM64_ADRP_MASK = 0x9F000000;  // Mask for ADRP detection
const ARM64_ADRP_OP = 0x90000000;    // ADRP opcode
const ARM64_LDR_IMM_MASK = 0xFFC00000;  // Mask for LDR immediate (unsigned offset)
const ARM64_LDR_IMM_OP = 0xF9400000;    // LDR Xt, [Xn, #imm] (64-bit)
const ARM64_LDR_IMM_32_OP = 0xB9400000; // LDR Wt, [Xn, #imm] (32-bit)
const ARM64_STP_MASK = 0x7FC00000;      // STP mask
const ARM64_STP_PRE_OP = 0x29800000;    // STP pre-index
const ARM64_SUB_SP_MASK = 0xFF0003FF;   // SUB SP, SP, #imm mask
const ARM64_SUB_SP_OP = 0xD10003FF;     // SUB SP, SP, #imm (stack frame)

// Find main module
var mainModule = null;
Process.enumerateModules().forEach(function(mod) {
    if (mod.name.indexOf("Baldur") !== -1 && mod.name.indexOf(".dylib") === -1) {
        mainModule = mod;
    }
});
if (!mainModule) {
    Process.enumerateModules().forEach(function(mod) {
        if (!mainModule || mod.size > mainModule.size) mainModule = mod;
    });
}
console.log("[*] Main module: " + mainModule.name + " @ " + mainModule.base);

/**
 * Decode ARM64 instruction type
 */
function decodeInstruction(insn, pc) {
    var result = {
        raw: insn,
        hex: "0x" + insn.toString(16).padStart(8, '0'),
        type: "unknown",
        details: {}
    };

    // Check for ADRP
    if ((insn & ARM64_ADRP_MASK) === ARM64_ADRP_OP) {
        result.type = "ADRP";
        var rd = insn & 0x1F;  // Destination register
        var immlo = (insn >> 29) & 0x3;  // Low 2 bits of immediate
        var immhi = (insn >> 5) & 0x7FFFF;  // High 19 bits of immediate
        var imm = (immhi << 2) | immlo;  // Full 21-bit immediate

        // Sign extend the 21-bit value
        if (imm & 0x100000) {
            imm |= 0xFFE00000;  // Sign extend to 32 bits
            imm = imm | 0;  // Convert to signed
        }

        // Calculate target page address
        var pcPage = pc.and(ptr("0xFFFFFFFFFFFFF000"));
        var offset = ptr(imm).shl(12);
        var targetPage = pcPage.add(offset);

        result.details = {
            rd: "x" + rd,
            imm21: imm,
            targetPage: targetPage.toString()
        };
        return result;
    }

    // Check for LDR immediate (64-bit)
    if ((insn & ARM64_LDR_IMM_MASK) === ARM64_LDR_IMM_OP) {
        result.type = "LDR_IMM64";
        var rt = insn & 0x1F;  // Target register
        var rn = (insn >> 5) & 0x1F;  // Base register
        var imm12 = (insn >> 10) & 0xFFF;  // 12-bit unsigned offset (scaled by 8)
        var offset = imm12 * 8;  // Scale by 8 for 64-bit loads

        result.details = {
            rt: "x" + rt,
            rn: "x" + rn,
            offset: offset,
            offsetHex: "0x" + offset.toString(16)
        };
        return result;
    }

    // Check for LDR immediate (32-bit)
    if ((insn & ARM64_LDR_IMM_MASK) === ARM64_LDR_IMM_32_OP) {
        result.type = "LDR_IMM32";
        var rt = insn & 0x1F;
        var rn = (insn >> 5) & 0x1F;
        var imm12 = (insn >> 10) & 0xFFF;
        var offset = imm12 * 4;  // Scale by 4 for 32-bit loads

        result.details = {
            rt: "w" + rt,
            rn: "x" + rn,
            offset: offset,
            offsetHex: "0x" + offset.toString(16)
        };
        return result;
    }

    // Check for STP pre-index (common prologue)
    if ((insn & ARM64_STP_MASK) === ARM64_STP_PRE_OP) {
        result.type = "STP_PRE";
        var rt1 = insn & 0x1F;
        var rn = (insn >> 5) & 0x1F;
        var rt2 = (insn >> 10) & 0x1F;
        var imm7 = (insn >> 15) & 0x7F;
        // Sign extend
        if (imm7 & 0x40) imm7 |= 0xFFFFFF80;
        var offset = imm7 * 8;

        result.details = {
            rt1: "x" + rt1,
            rt2: "x" + rt2,
            rn: "x" + rn,
            offset: offset
        };
        return result;
    }

    // Generic identification based on common patterns
    if ((insn & 0xFF000000) === 0xD1000000) {
        result.type = "SUB";  // SUB immediate
    } else if ((insn & 0xFF000000) === 0x91000000) {
        result.type = "ADD";  // ADD immediate
    } else if ((insn & 0xFC000000) === 0x94000000) {
        result.type = "BL";  // Branch with link
    } else if ((insn & 0xFC000000) === 0x14000000) {
        result.type = "B";  // Unconditional branch
    } else if ((insn & 0xFF000000) === 0xAA000000) {
        result.type = "MOV_REG";  // MOV (register)
    } else if ((insn & 0xFF800000) === 0xF9000000) {
        result.type = "STR_IMM";  // STR immediate
    }

    return result;
}

/**
 * Analyze a function's prologue for ADRP+LDR patterns
 */
function analyzePrologue(funcAddr, numInstructions) {
    numInstructions = numInstructions || 16;

    console.log("\n" + "=".repeat(70));
    console.log("PROLOGUE ANALYSIS: " + funcAddr);
    console.log("=".repeat(70));

    var analysis = {
        address: funcAddr.toString(),
        instructions: [],
        adrpPatterns: [],
        safeHookPoint: -1,
        firstUnsafeInsn: -1
    };

    var lastAdrp = null;
    var unsafeRangeEnd = 0;

    for (var i = 0; i < numInstructions; i++) {
        var pc = funcAddr.add(i * 4);
        var insn = pc.readU32();
        var decoded = decodeInstruction(insn, pc);

        analysis.instructions.push({
            offset: i * 4,
            pc: pc.toString(),
            decoded: decoded
        });

        // Format output
        var line = "+" + (i * 4).toString(16).padStart(2, '0') + ": ";
        line += decoded.hex + "  ";
        line += decoded.type.padEnd(12);

        if (decoded.type === "ADRP") {
            line += decoded.details.rd + ", page=" + decoded.details.targetPage;
            lastAdrp = {
                offset: i * 4,
                rd: decoded.details.rd,
                targetPage: decoded.details.targetPage
            };
            unsafeRangeEnd = Math.max(unsafeRangeEnd, (i + 2) * 4);  // ADRP + at least next insn

            if (analysis.firstUnsafeInsn < 0) {
                analysis.firstUnsafeInsn = i * 4;
            }
        } else if (decoded.type === "LDR_IMM64" || decoded.type === "LDR_IMM32") {
            line += decoded.details.rt + ", [" + decoded.details.rn + ", #" + decoded.details.offsetHex + "]";

            // Check if this LDR uses the ADRP register
            if (lastAdrp && decoded.details.rn === lastAdrp.rd) {
                var targetAddr = ptr(lastAdrp.targetPage).add(decoded.details.offset);
                line += " --> " + targetAddr;

                analysis.adrpPatterns.push({
                    adrpOffset: lastAdrp.offset,
                    ldrOffset: i * 4,
                    register: lastAdrp.rd,
                    targetPage: lastAdrp.targetPage,
                    ldrOffset: decoded.details.offset,
                    resolvedTarget: targetAddr.toString()
                });
                lastAdrp = null;
                unsafeRangeEnd = Math.max(unsafeRangeEnd, (i + 1) * 4);
            }
        } else if (decoded.type === "STP_PRE") {
            line += decoded.details.rt1 + ", " + decoded.details.rt2 + ", [" + decoded.details.rn + ", #" + decoded.details.offset + "]!";
        }

        // Mark unsafe/safe
        var isSafe = (i * 4) >= unsafeRangeEnd;
        if (decoded.type === "ADRP" || (decoded.type.startsWith("LDR") && lastAdrp)) {
            line += " [UNSAFE - PC-relative]";
        } else if (isSafe && analysis.safeHookPoint < 0 && i > 0) {
            line += " [SAFE HOOK POINT]";
            analysis.safeHookPoint = i * 4;
        }

        console.log(line);
    }

    // Summary
    console.log("\n--- Analysis Summary ---");
    console.log("First unsafe instruction: +" + (analysis.firstUnsafeInsn >= 0 ? "0x" + analysis.firstUnsafeInsn.toString(16) : "none"));
    console.log("ADRP+LDR patterns found: " + analysis.adrpPatterns.length);

    if (analysis.adrpPatterns.length > 0) {
        console.log("\nADRP+LDR Pattern Details:");
        analysis.adrpPatterns.forEach(function(p, idx) {
            console.log("  Pattern " + idx + ":");
            console.log("    ADRP at +" + p.adrpOffset.toString(16) + " -> page " + p.targetPage);
            console.log("    LDR  at +" + p.ldrOffset.toString(16) + " -> offset 0x" + p.ldrOffset.toString(16));
            console.log("    Resolved target: " + p.resolvedTarget);
        });
    }

    console.log("\nRecommended safe hook point: +" + (analysis.safeHookPoint >= 0 ? "0x" + analysis.safeHookPoint.toString(16) : "NONE FOUND"));

    return analysis;
}

/**
 * Hex dump with instruction boundaries
 */
function hexDumpInstructions(addr, count) {
    console.log("\n--- Raw Hex Dump (" + count + " instructions) ---");
    var bytes = addr.readByteArray(count * 4);
    console.log(hexdump(bytes, {offset: 0, length: count * 4, header: true, ansi: true}));
}

// ============================================================================
// Target Functions to Analyze
// ============================================================================

// FeatManager::GetFeats @ 0x101b752b4 (primary target for Issue #44)
var FEATMANAGER_GETFEATS_OFFSET = 0x01b752b4;

// Additional functions we might want to hook in the future
var FUNCTIONS_TO_ANALYZE = [
    { name: "FeatManager::GetFeats", offset: 0x01b752b4 },
    { name: "GetAllFeats", offset: 0x0120b3e8 },
    { name: "GetFeatsForProgression", offset: 0x0339fab4 }
];

// Analyze primary target
console.log("\n" + "#".repeat(70));
console.log("# MERIDIAN INVESTIGATION: ARM64 Prologue Analysis");
console.log("# Issue #44 - ARM64-Safe Inline Hooking");
console.log("#".repeat(70));

var getFeatsAddr = mainModule.base.add(FEATMANAGER_GETFEATS_OFFSET);
console.log("\nPrimary target: FeatManager::GetFeats @ " + getFeatsAddr);

// Dump hex first
hexDumpInstructions(getFeatsAddr, 16);

// Detailed analysis
var analysis = analyzePrologue(getFeatsAddr, 20);

// Store for later use
global.lastAnalysis = analysis;
global.analyzePrologue = analyzePrologue;
global.mainModule = mainModule;

// Export utility functions
global.analyzeFunction = function(offset, count) {
    var addr = mainModule.base.add(offset);
    return analyzePrologue(addr, count || 16);
};

global.analyzeAll = function() {
    FUNCTIONS_TO_ANALYZE.forEach(function(f) {
        var addr = mainModule.base.add(f.offset);
        console.log("\n\n>>> Analyzing: " + f.name);
        analyzePrologue(addr, 16);
    });
};

console.log("\n" + "=".repeat(70));
console.log("Commands available:");
console.log("  analyzeFunction(offset, count) - Analyze function at offset");
console.log("  analyzeAll() - Analyze all known hook targets");
console.log("  lastAnalysis - Results from last analysis");
console.log("=".repeat(70));
