# Frida Component Discovery Tools

This directory contains Frida scripts for runtime component discovery on macOS ARM64.

## Why Frida?

The BG3 macOS binary has component strings as RTTI metadata with **no XREFs** in static analysis.
The game uses runtime type indices (uint16_t) to identify components, not direct function pointers.
Frida allows us to:

1. Hook functions at runtime to observe their arguments
2. Discover component type indices as they're accessed
3. Build a name → index mapping without hardcoding addresses

## Prerequisites

Install Frida:

```bash
pip install frida-tools
```

Or via Homebrew:

```bash
brew install frida-tools
```

## Scripts

### capture_singletons.js

**NEW** - Capture singleton pointers for reverse engineering:
- PhysicsScene via AiGrid constructor
- SpellPrototype::Init calls
- EntityWorld via IsInCombat

```bash
frida -U -n "Baldur's Gate 3" -l capture_singletons.js
```

### capture_physics.js

**NEW** - Specialized script for Issue #37 (Ext.Level/Physics):
- Hooks AiGrid constructor to capture PhysicsScene*
- Triggers when loading saves or changing areas

```bash
frida -U -n "Baldur's Gate 3" -l capture_physics.js
```

### stalker_refmap_hash.js

**NEW** - Instruction-level tracing to discover RefMap hash function (Issue #32):
- Uses Frida Stalker for instruction-level code tracing
- Captures arithmetic/bitwise operations during hash computation
- Helps complete Stats Sync for NEW spell prototypes

```bash
frida -U -n "Baldur's Gate 3" -l stalker_refmap_hash.js
```

**Interactive RPC exports:**
```javascript
// Start tracing GetSpellPrototype calls
rpc.exports.traceRefMap()

// Dump RefMap structure at address
rpc.exports.readRefMapAt("0x600003c90960")

// Search for FixedString in RefMap (linear scan)
rpc.exports.findSpellInRefMap("0x600003c90960", 512753744)
```

### itrace_complex_flows.js

**NEW** - Enhanced instruction tracing for complex code paths:
- TraceBuffer for efficient capture up to 5000 instructions
- Color-coded output by instruction type (arithmetic, bitwise, memory, control flow)
- Export traces to JSON for offline analysis
- Memory watchpoint support

```bash
frida -U -n "Baldur's Gate 3" -l itrace_complex_flows.js
```

**Interactive RPC exports:**
```javascript
// Trace any function by address
rpc.exports.trace("0x101f72754", "SpellPrototype::Init")

// Pre-configured traces
rpc.exports.traceSpellInit()    // SpellPrototype::Init
rpc.exports.traceRefMap()       // RefMap::GetOrAdd

// Manage trace data
rpc.exports.getTrace()          // Get JSON
rpc.exports.saveTrace('/tmp/trace.json')
rpc.exports.getSummary()        // Instruction counts
rpc.exports.clearTrace()

// Configure options
rpc.exports.configure({ maxInstructions: 10000, filterArithmetic: false })

// Memory watchpoints
rpc.exports.watch("0x600003c90960", 64, "RefMap header")
```

### discover_components.js

Main discovery script that:
- Finds component string references in memory
- Hooks GetRawComponent to observe type indices
- Builds a component registry from runtime observations

**Usage:**

```bash
# Attach to running BG3
frida -n "Baldur's Gate 3" -l discover_components.js

# Or with the app bundle name
frida -n "Baldur's Gate 3" --runtime=v8 -l discover_components.js
```

**Interactive Commands:**

Once attached, use these functions in the Frida REPL:

```javascript
// Set GetRawComponent address (if discovered manually via Ghidra)
setGetRawComponent("0x1012345678")

// Manually register a component index
setComponentIndex("eoc::HealthComponent", 42, 64)

// Show current discoveries
dumpDiscoveries()

// Save discoveries to JSON file
saveDiscoveries()
```

## Discovery Workflow

### Step 1: Find GetRawComponent

Method A: Pattern scan (automatic)
```bash
frida -n "Baldur's Gate 3" -l discover_components.js
# Script will attempt automatic discovery
```

Method B: Ghidra analysis
1. Search for functions with signature: `(void*, uint64_t, uint16_t, size_t, bool) -> void*`
2. Look for EntityStorage access pattern
3. Find function that checks `type & 0x8000` (one-frame flag)

Method C: Trace from known functions
```javascript
// Hook a function we know accesses components
// and trace back to find GetRawComponent
Interceptor.attach(ptr("0x..."), {
    onEnter: function(args) {
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

### Step 2: Discover Component Indices

Once GetRawComponent is hooked:
1. Play the game normally
2. Enter combat (triggers Health, Stats, etc. access)
3. Open inventory (triggers Item, Equipment access)
4. Move characters (triggers Transform access)
5. Run `dumpDiscoveries()` to see what was found

### Step 3: Export Results

```javascript
saveDiscoveries()
```

This creates `/tmp/bg3se_component_discovery.json` with format:

```json
{
  "timestamp": "2025-11-30T...",
  "getRawComponentAddr": "0x1012345678",
  "components": [
    {"index": 42, "name": "unknown_42", "size": 64, "accessCount": 1523},
    ...
  ]
}
```

### Step 4: Update Component Registry

Use discoveries to update `src/entity/component_registry.c`:

```c
component_registry_register("eoc::HealthComponent", 42, 64, false);
```

## Troubleshooting

### "Could not find BG3 module"

On macOS, the game might have a different process name. Try:

```bash
# List running processes
frida-ps | grep -i baldur

# Attach by PID
frida -p <PID> -l discover_components.js
```

### "Access violation" when hooking

Some memory regions are protected. Try:
1. Attaching earlier (before game fully loads)
2. Using spawn instead of attach: `frida -f "/path/to/game" -l script.js`

### Script errors on ARM64

Ensure you're using the correct register names:
- ARM64: x0-x28, sp, lr (not eax, ebx, etc.)
- Function arguments: x0, x1, x2, x3, x4, x5, x6, x7
- Return value: x0

## Integration with BG3SE

The discoveries from Frida can be integrated in two ways:

### Manual Integration
1. Export discoveries to JSON
2. Update component_registry.c with indices
3. Rebuild BG3SE

### Runtime Integration (Advanced)
1. BG3SE reads discoveries from shared memory or IPC
2. Call `component_set_get_raw_component_addr()` and `component_add_frida_discovery()`
3. No rebuild needed

## References

- [Frida JavaScript API](https://frida.re/docs/javascript-api/)
- [ARM64 Calling Convention](https://developer.arm.com/documentation/den0024/a/The-ABI-for-ARM-64-bit-Architecture/Register-use-in-the-AArch64-Procedure-Call-Standard)
- bg3se EntitySystem.cpp: Component access patterns
