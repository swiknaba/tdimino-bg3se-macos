# Osiris Offsets (libOsiris.dylib)

## Global Symbols

| Symbol | Offset | Description |
|--------|--------|-------------|
| `_OsiFunctionMan` | `0x0009f348` | Global pointer to OsiFunctionManager |
| `pFunctionData` | `0x0002a04c` | Function lookup method in OsiFunctionManager |
| `COsiris::Event` | `0x000513cc` | Event dispatch entry point |

## OsiFunctionManager Structure

```c
// OsiFunctionManager contains the function registry
// Access: *(void**)(_OsiFunctionMan)
struct OsiFunctionManager {
    // ... vtable and other fields
    // FunctionData is accessed via pFunctionData method
};
```

## Function Lookup

```c
// To look up an Osiris function by name:
// 1. Get OsiFunctionMan pointer from global
// 2. Call pFunctionData method with function name
// 3. Returns FunctionData* or NULL

typedef void* (*pFunctionDataFn)(void *osfm, const char *name, int arity);
```

## Event Hooking

The `COsiris::Event` function is called for all Osiris events:
- Before handlers (can modify parameters)
- After handlers (for observation)

Signature: `void Event(uint32_t funcId, OsiArgs* args)`
