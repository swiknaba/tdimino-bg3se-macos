# Acceleration Strategies for BG3SE-macOS

Research and tools for reaching Windows BG3SE parity faster.

## Philosophy: Port-the-Pattern

**Treat Windows BG3SE as spec + reference implementation.** The biggest multiplier is recognizing that Windows BG3SE achieves breadth via a small number of reusable "primitive engines":

| Primitive | Windows Implementation | macOS Approach |
|-----------|------------------------|----------------|
| **ECS Mapping** | `EntitySystemHelpersBase` + `GenericPropertyMap` | TypeId-based traversal (no monolithic dispatcher) |
| **Guid Resource Banks** | `GuidResourceBankHelper<T>` template | TypeContext traversal + hook-based capture |
| **Networking** | `Ext.Net.*` + `NetChannel.lua` | Minimal C bridge + port Lua wrappers |

**Key insight:** Port the *API contract* and *data model* (platform-independent), replace only the *mechanism* (ARM64/macOS-specific).

**Intentional divergence:** On macOS ARM64, templates are often inlined with no stable dispatcher function. Use traversal-based approaches rather than searching for a single "GetRawComponent" anchor.

---

## Component Parity (Issue #33)

### Statistics

| Metric | Count |
|--------|-------|
| Total TypeIds in macOS binary | 1,999 |
| `eoc::` namespace (mod-relevant) | 701 |
| `esv::` namespace (server) | 596 |
| `ecl::` namespace (client) | 429 |
| `ls::` namespace (base) | 233 |
| Currently implemented | 36 (~1.8%) |

### Automation Tools

**1. TypeId Extraction (`tools/extract_typeids.py`)**

Extracts all component TypeId addresses from the macOS binary:

```bash
# Generate C header with all TypeIds
python3 tools/extract_typeids.py > src/entity/generated_typeids.h

# Search for specific component
python3 tools/extract_typeids.py 2>&1 | grep HealthComponent
```

Output format:
```c
#define TYPEID_EOC_HEALTHCOMPONENT 0x10890a360ULL
```

**2. Component Stub Generator (`tools/generate_component_stubs.py`)**

Parses Windows BG3SE headers to extract field names and types:

```bash
# List all eoc:: components with field counts
python3 tools/generate_component_stubs.py --namespace eoc --list

# Generate stubs for high-priority components
python3 tools/generate_component_stubs.py --high-priority > stubs.c

# Generate all stubs for a namespace
python3 tools/generate_component_stubs.py --namespace eoc > eoc_stubs.c
```

### Why Full Automation Isn't Possible

Windows BG3SE uses `make_property_map.py` to auto-generate Lua bindings because they have:
- **Compile-time access** to C++ struct definitions
- **PropertyMap macros** resolved by the compiler
- **Automatic offset calculation** by the C++ compiler

We're working with:
- **Stripped binary** - no debug symbols
- **ARM64 architecture** - different alignment than x64
- **Runtime verification needed** - must probe memory or analyze disassembly

### Recommended Workflow

For each component:

1. **Get TypeId address:**
   ```bash
   nm -gU "/path/to/BG3" | c++filt | grep "TypeId.*ComponentName.*ComponentTypeIdContext"
   ```

2. **Get field names from Windows headers:**
   ```bash
   python3 tools/generate_component_stubs.py --namespace eoc --list | grep ComponentName
   ```

3. **Verify ARM64 offsets** (choose one):
   - **Ghidra:** Analyze accessor functions
   - **Runtime probing:** `Ext.Debug.ProbeStruct()` on live entity
   - **Pattern matching:** Similar components often have similar layouts

4. **Add to codebase:**
   - `src/entity/component_typeid.c` - TypeId entry
   - `src/entity/component_offsets.h` - Property definitions + registry

5. **Test:**
   ```lua
   local e = Ext.Entity.Get("GUID")
   _D(e.YourComponent)
   ```

## Static Data & Resources (Issues #40, #41)

### Windows Pattern (from `StaticData.inl`)

Windows BG3SE uses template-based helpers:

```cpp
template <class T>
class GuidResourceBankHelper : public GuidResourceBankHelperBase {
    bool Push(lua_State* L, Guid resourceGuid) override {
        auto resource = bank_->Resources.try_get(resourceGuid);
        if (resource) {
            MakeObjectRef(L, resource, LifetimeHandle{});
            return true;
        }
        return false;
    }
    Array<Guid> GetAll() { return bank_->Resources.keys(); }
};
```

### Implementation Strategy

1. **Find resource manager singletons** via Ghidra
2. **Discover `ExtResourceManagerType` enum values** in macOS binary
3. **Port the helper pattern** using C equivalents
4. **Register Lua bindings** for `Ext.StaticData.Get()`, `GetAll()`

## Stats Sync (Issue #32)

### Windows Pattern

```cpp
RPGStats::SyncWithPrototypeManager(Object* object) {
    switch (object->ModifierListIndex) {
        case SpellData:
            SpellPrototypeManager::SyncStat();
            break;
        case StatusData:
            StatusPrototypeManager::SyncStat();
            break;
        // ...
    }
}
```

### Required Discoveries

| Component | What to Find |
|-----------|--------------|
| SpellPrototypeManager | Singleton address, `SyncStat` function |
| StatusPrototypeManager | Singleton address, `SyncStat` function |
| PassivePrototypeManager | Singleton address, `SyncStat` function |
| InterruptPrototypeManager | Singleton address, `SyncStat` function |

### Ghidra Research

```bash
# Search for prototype manager references
./ghidra/scripts/run_analysis.sh find_prototype_managers.py
```

## Client Lua State (Issue #15)

### Windows Architecture

- `ServerExtensionState` - Server-side Lua state
- `ClientExtensionState` - Client-side Lua state
- Context switching based on thread/caller

### Implementation Approach

1. **Find client-side hooks** - Different from server Osiris hooks
2. **Create separate Lua state** - With client-specific APIs
3. **Implement context detection** - Determine which state to use
4. **Port client-only APIs** - `Ext.UI`, `Ext.IMGUI`, etc.

## NetChannel API (Issue #6)

### Complexity

This is the most complex remaining feature:
- Requires network stack analysis
- Platform-specific socket handling differences
- Message serialization/deserialization
- No easy automation path

### Research Needed

1. Find `NetChannel` class in macOS binary
2. Analyze message format
3. Hook send/receive functions
4. Implement Lua bindings

## Exa MCP Research Findings (Dec 2025)

Comprehensive research using Exa MCP server for automation strategies.

### Debugger Support (Issue #42)

**Key Finding:** The Debug Adapter Protocol (DAP) is the standard for VS Code integration.

**Discovered Implementations:**
| Project | Description | Relevance |
|---------|-------------|-----------|
| `tomblind/local-lua-debugger-vscode` | Pure Lua debugger for VS Code | Best reference - no C dependencies |
| `LuaPanda` | Tencent's Lua debugger | Architecture patterns for breakpoints |
| `lua-debug` | actboy168's debugger | Hook-based debugging |
| `one-small-step-for-vimkind` | nvim-lua/lsp integration | Debug hooks example |
| `Emmy Debugger` | IntelliJ Lua plugin | Production-quality implementation |

**Acceleration Strategy:**
1. **Use DAP reference implementations** - Don't reinvent the protocol
2. **Start with local-lua-debugger** - Pure Lua, easy to port
3. **Hook `debug.sethook()`** - Standard Lua debug hooks
4. Port existing DAP JSON message handling

**Estimated Effort Reduction:** ~60% (vs building from scratch)

### NetChannel API (Issue #6)

**Key Finding:** Steam network interception has established patterns.

**Discovered Techniques:**
| Technique | Source | Applicability |
|-----------|--------|---------------|
| Steam NetHook2 | SteamRE project | Message format inspection |
| Unity Netcode | Unity docs | Serialization patterns |
| Source engine netcode | Valve RE | Packet structure analysis |
| Frida for network hooks | Various | Runtime interception |

**Acceleration Strategy:**
1. **Use Frida for initial exploration** - Hook send/receive functions
2. **Analyze message format first** - Before implementing Lua API
3. **Study Windows BG3SE `NetChannel` class** - Port serialization logic
4. **Focus on common message types** - Chat, sync, custom

**Estimated Effort Reduction:** ~30% (still very complex)

### Stats Sync / Prototype Managers (Issue #32)

**Key Finding:** Frida dynamic instrumentation can discover singletons at runtime.

**Discovered Techniques:**
```javascript
// Frida pattern for singleton discovery
Interceptor.attach(Module.findExportByName(null, "SomeManagerFunction"), {
    onEnter: function(args) {
        console.log("Manager ptr: " + this.context.x0);
    }
});
```

**Acceleration Strategy:**
1. **Hook known prototype functions** - `GetSpellPrototype`, `GetStatusPrototype`
2. **Trace back to singleton** - Follow this pointer to manager
3. **Dump `Init` function** - Decompile to understand property parsing
4. **ARM64 struct analysis** - Use `Ext.Debug.ProbeStruct()` for layout

**Estimated Effort Reduction:** ~40%

### Client Lua State (Issue #15)

**Key Finding:** Game modding projects use hook-based state injection.

**Discovered Patterns:**
```c
// From pLua - inject into existing Lua state
// 1. Find lua_State* via function hooking
hookso arg $PID xxx.so lua_settop 1  // Gets first arg (lua_State*)

// 2. Inject custom code
hookso call $PID libplua.so lrealstart i=$LUA_STATE
```

**Acceleration Strategy:**
1. **Hook client-side Lua functions** - Find client lua_State*
2. **Mirror server state pattern** - Reuse existing infrastructure
3. **Separate API registration** - Client-only vs server-only APIs
4. **Use thread-local storage** - For context detection

**Recommended Implementation Order:**
1. Find client Lua state pointer via hooks
2. Create `ClientExtensionState` mirroring server
3. Register client-specific APIs (Ext.UI, Ext.IMGUI)
4. Implement context switching

**Estimated Effort Reduction:** ~50%

### Static Data / Resources (Issue #40)

**Key Finding:** Windows BG3SE `GuidResourceBankHelper` is well-documented.

**Acceleration Strategy:**
1. **Find `ExtResourceManagerType` enum** - Search binary for resource type strings
2. **Locate resource bank singletons** - Pattern scan for VMT addresses
3. **Port `StaticData.inl` directly** - C equivalent of template helpers
4. **Test with common resources** - Backgrounds, Feats, Origins first

**Estimated Effort Reduction:** ~70% (clearest Windows pattern)

## ARM64 Reverse Engineering Patterns

### Common Offset Patterns in Assembly

```asm
; Load from struct offset
LDR x8, [x19, #0x348]    ; x8 = struct->field_at_0x348

; Store to struct offset
STR x0, [x20, #0x14C]    ; struct->field_at_0x14C = x0

; Pointer arithmetic (array access)
ADD x0, x8, x9, LSL #3   ; x0 = base + (index * 8)

; VMT call
LDR x8, [x0]             ; x8 = object->vtable
LDR x9, [x8, #0x10]      ; x9 = vtable[2] (method at offset 0x10)
BLR x9                   ; call method
```

### Ghidra Python for Offset Discovery

```python
# Find all functions that access a specific offset
for func in currentProgram.getFunctionManager().getFunctions(True):
    for instr in func.getBody().getAddresses(True):
        inst = getInstructionAt(instr)
        if inst and "LDR" in str(inst) and "#0x348" in str(inst):
            print(f"Found at {func.getName()}: {inst}")
```

## osgrep Research Queries

Useful queries for Windows BG3SE exploration:

```bash
cd /Users/tomdimino/Desktop/Programming/bg3se

# Component system
osgrep "how are component properties registered"
osgrep "entity system initialization TypeId"
osgrep "component binding to Lua"

# Prototype managers
osgrep "prototype manager sync"
osgrep "SpellPrototypeManager singleton"

# Resource system
osgrep "GuidResourceBank initialization"
osgrep "ExtResourceManagerType enum"

# Network
osgrep "NetChannel message serialization"
osgrep "multiplayer synchronization"

# Client state
osgrep "ClientExtensionState initialization"
osgrep "client vs server Lua context"

# Debugger
osgrep "debug adapter protocol DAP"
osgrep "Lua breakpoint implementation"
```

## Issue Acceleration Matrix (Dec 2025 Deep Audit)

| Issue | Feature | Acceleration | Key Technique |
|-------|---------|--------------|---------------|
| #33 Components | Component Layouts | **80%** | Existing tools: `extract_typeids.py` + `generate_component_stubs.py` |
| #39 Localization | Ext.Localization | **75%** | Simple string table lookup, minimal API surface |
| #36 IMGUI | Ext.IMGUI | **70%** | Official ImGui Metal backend exists |
| #40 StaticData | Ext.StaticData | **70%** | Symbol `eoc__gGuidResourceManager` is exported |
| #41 Resource | Ext.Resource/Template | **65%** | Same pattern as StaticData |
| #42 Debugger | VS Code Debugger | **60%** | DAP protocol has reference implementations |
| #15 Client State | Client Lua State | **50%** | Mirror server pattern, hook game state |
| #37 Level | Ext.Level (Physics) | **50%** | Find physics engine, port LevelLib.inl |
| #38 Audio | Ext.Audio | **45%** | Wwise SDK has documented API |
| #32 Stats Sync | Prototype Managers | **40%** | Frida for singleton discovery, Ghidra findings exist |
| #6 NetChannel | NetChannel API | **30%** | Network stack analysis needed, but Lua wrappers portable |
| #35 Ext.UI | Noesis UI | **25%** | Deep game UI integration required |

## Prioritized Implementation Order

### Tier 1: High Acceleration (70-80%) - Do First
1. **#33 Components** - Tools ready, incremental progress
2. **#39 Localization** - Quick win, small API (~2 hours)
3. **#36 IMGUI** - Official Metal backend, standalone implementation
4. **#40 StaticData** - Exported symbol, clear Windows pattern

### Tier 2: Medium Acceleration (40-60%) - Second Priority
5. **#42 Debugger** - DAP reference implementations available
6. **#15 Client State** - Mirror existing server state pattern
7. **#32 Stats Sync** - Ghidra findings for `GetPassivePrototype` at `0x102655c14`

### Tier 3: Lower Acceleration (25-30%) - Complex
8. **#6 NetChannel** - Complex, but Lua wrappers (`NetChannel.lua`, `NetworkManager.lua`) portable
9. **#35 Ext.UI** - Deep Noesis integration required

## osgrep Key Findings (Dec 2025)

### StaticData (#40) - Key Pattern
```cpp
// BG3Extender/GameDefinitions/EntitySystem.cpp:1364
resource::GuidResourceBankBase* EntitySystemHelpersBase::GetRawResourceManager(ExtResourceManagerType type)
{
    auto index = staticDataIndices_[(unsigned)type];
    auto defns = GetStaticSymbols().eoc__gGuidResourceManager;  // <- EXPORTED!
    auto res = (*defns)->Definitions.try_get(index);
}
```

### Client State (#15) - Key Pattern
```cpp
// BG3Extender/Lua/Client/LuaClient.cpp:80
void ClientState::Initialize()
{
    State::Initialize();
    library_.Register(L);
    gExtender->GetClient().GetExtensionState().LuaLoadBuiltinFile("ClientStartup.lua");
}
```

### NetChannel (#6) - Lua Wrappers Available
- `BG3Extender/LuaScripts/Libs/NetChannel.lua` - Pure Lua, can port directly
- `BG3Extender/LuaScripts/Libs/NetworkManager.lua` - Channel management

### IMGUI (#36) - Official Metal Backend
```cpp
// From imgui_impl_metal example
ImGui_ImplMetal_Init(device);
ImGui_ImplMetal_NewFrame(renderPassDescriptor);
ImGui::NewFrame();
ImGui::Render();
ImGui_ImplMetal_RenderDrawData(ImGui::GetDrawData(), commandBuffer, renderEncoder);
```

## Reference Files by Issue

| Issue | Key Reference Files |
|-------|---------------------|
| #40 StaticData | `BG3Extender/Lua/Libs/StaticData.inl`, `GameDefinitions/Resources.h` |
| #39 Localization | `BG3Extender/Lua/Libs/Localization.inl` (~100 lines) |
| #36 IMGUI | `BG3Extender/Lua/Client/IMGUI/Objects.h`, `IMGUIManager.h` |
| #15 Client State | `BG3Extender/Lua/Client/LuaClient.cpp`, `ExtensionStateClient.cpp` |
| #6 NetChannel | `BG3Extender/LuaScripts/Libs/NetChannel.lua`, `NetworkManager.lua` |
| #32 Stats Sync | `BG3Extender/GameDefinitions/Stats/Stats.cpp` - `SyncWithPrototypeManager()` |
| #42 Debugger | `LuaDebugger/DAPProtocol.cs` - DAP implementation |

## Recommended Next Steps

1. **#39 Localization** - Quick win (~2 hours), high acceleration
2. **#40 StaticData** - dlsym `eoc__gGuidResourceManager`, port StaticData.inl
3. **#36 IMGUI** - Include ImGui + Metal backend, hook render loop
4. **#33 Components** - Continue incremental component additions
5. **Create Frida scripts** for runtime singleton discovery (Stats Sync, Client State)
6. **Document NetChannel message format** - Long-term research task
