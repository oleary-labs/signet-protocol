# Barretenberg WASM in Go via wazero

**Status: Deferred** — viable approach, not yet implemented.

## Goal

Embed the Barretenberg UltraHonk prover/verifier directly in the Go node process so
`ValidateAuthProof` and `POST /v1/auth` (production mode) can verify ZK proofs without
shelling out to the `bb` CLI.

## WASM Binary

Source: `barretenberg-threads.wasm.gz` from the `@aztec/bb.js` npm package (v4.0.4 tested).

```
npm pack @aztec/bb.js
tar -xzf aztec-bb.js-*.tgz package/dest/node/barretenberg_wasm/barretenberg-threads.wasm.gz
gunzip barretenberg-threads.wasm.gz   # ~10 MB decompressed
```

Embed in Go with `//go:embed`.

## Import Surface (8 total)

Discovered via `wasm-objdump -x barretenberg.wasm`:

| Module | Name | Sig | Notes |
|--------|------|-----|-------|
| `env` | `logstr` | `(i32)->nil` | Null-terminated C string ptr → log |
| `env` | `throw_or_abort_impl` | `(i32)->nil` | Null-terminated C string ptr → panic |
| `env` | `env_hardware_concurrency` | `()->i32` | Return thread count; return 1 to disable threading |
| `env` | `memory` | shared linear | initial=33 pages, max=65536, **shared=true** |
| `wasi_snapshot_preview1` | `clock_time_get` | `(i32,i64,i32)->i32` | Standard WASI — wazero built-in |
| `wasi_snapshot_preview1` | `proc_exit` | `(i32)->nil` | Standard WASI — wazero built-in |
| `wasi_snapshot_preview1` | `random_get` | `(i32,i32)->i32` | Standard WASI — wazero built-in |
| `wasi` | `thread-spawn` | `(i32)->i32` | Spawn WASM thread; stub as no-op when `env_hardware_concurrency=1` |

The 3 `env` host functions plus `thread-spawn` are trivial to implement. The 3 standard
WASI functions are provided by wazero's WASI Preview 1 module.

**Threading:** if `env_hardware_concurrency()` returns `1`, Barretenberg disables its
internal thread pool. The `wasi.thread-spawn` import is never invoked in that case. The
`shared=true` memory flag is still required by the module's import declaration, so wazero
must be configured with WASM threads support enabled.

## Key Exports

| Export | Sig | Purpose |
|--------|-----|---------|
| `_initialize` | `()->nil` | Module init — call once after instantiation |
| `bbmalloc` | `(i32)->i32` | Allocate N bytes in WASM heap, return ptr |
| `bbfree` | `(i32)->nil` | Free WASM heap allocation |
| `bbapi` | `(i32,i32,i32,i32)->nil` | Main dispatch entry point |

## `bbapi` Calling Convention

From the `@aztec/bb.js` TypeScript source (`cbindCall` in `barretenberg_wasm_main`):

```
bbapi(inputPtr i32, inputLen i32, outputPtrSlot i32, outputSizeSlot i32)
```

**Setup:**
1. `bbmalloc(inputLen)` → `inputPtr`; write msgpack input there.
2. Allocate an output metadata area (8 bytes): `[scratchDataPtr u32le, scratchDataSize u32le]`.
   Pre-fill with a scratch buffer pointer and its size so the WASM can return in-place
   without malloc if the result fits.
3. Call `bbapi(inputPtr, inputLen, outputMetaPtr, outputMetaPtr+4)`.
4. Read back `outputDataPtr` and `outputSize` from the metadata area.
5. Copy `memory[outputDataPtr : outputDataPtr+outputSize]` → result bytes.
6. If `outputDataPtr != scratchDataPtr`, call `bbfree(outputDataPtr)`.

**Message format:**

```
input  = msgpack([["CircuitVerify", <command object>]])
output = msgpack(["CircuitVerifyResponse", <result>])
     or msgpack(["ErrorResponse",  {"message": "..."}])
```

Commands and response shapes are defined in
`@aztec/bb.js/dest/node/cbind/generated/api_types.js`.

**Relevant commands for proof verification:**

- `CircuitVerify` — verify a UltraHonk proof given a VK + proof bytes + public inputs.
- `CircuitComputeVk` — compute a verification key from a compiled circuit artifact.

## wazero vs wasmer-go

**Use wazero** (`github.com/tetratelabs/wazero`):

- Pure Go, zero CGo — no cross-compilation issues.
- Full WASI Preview 1 built in.
- WASM threads proposal (shared memory + `thread-spawn`) supported as an experimental
  feature since v1.8. Enable with `wazero.NewRuntimeConfigInterpreter()` or the
  optimizing compiler with `experimental.WithCoreFeatures(api.CoreFeaturesV2 | experimental.CoreFeaturesThreads)`.
- Used in production (Arcjet, OPA, others).

wasmer-go requires CGo and provides no advantage here.

## Implementation Sketch

```go
// node/zkverify/verifier.go

package zkverify

import (
    _ "embed"
    "context"
    "fmt"

    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/api"
    "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
    "github.com/vmihailenco/msgpack/v5"
)

//go:embed barretenberg-threads.wasm
var wasmBytes []byte

type Verifier struct {
    rt  wazero.Runtime
    mod api.Module
}

func New(ctx context.Context) (*Verifier, error) {
    cfg := wazero.NewRuntimeConfig().
        WithCoreFeatures(api.CoreFeaturesV2 /* | threads */)
    rt := wazero.NewRuntimeWithConfig(ctx, cfg)

    wasi_snapshot_preview1.MustInstantiate(ctx, rt)

    // Provide env host functions
    _, err := rt.NewHostModuleBuilder("env").
        NewFunctionBuilder().WithFunc(logstr).Export("logstr").
        NewFunctionBuilder().WithFunc(throwOrAbort).Export("throw_or_abort_impl").
        NewFunctionBuilder().WithFunc(func() uint32 { return 1 }).Export("env_hardware_concurrency").
        Instantiate(ctx)
    if err != nil {
        return nil, err
    }

    // Stub wasi.thread-spawn (never called when concurrency=1)
    _, err = rt.NewHostModuleBuilder("wasi").
        NewFunctionBuilder().WithFunc(func(arg uint32) uint32 { return 0 }).Export("thread-spawn").
        Instantiate(ctx)
    if err != nil {
        return nil, err
    }

    mod, err := rt.Instantiate(ctx, wasmBytes)
    if err != nil {
        return nil, err
    }

    mod.ExportedFunction("_initialize").Call(ctx)

    return &Verifier{rt: rt, mod: mod}, nil
}

func (v *Verifier) VerifyUltraHonk(ctx context.Context, vk, proof, publicInputs []byte) (bool, error) {
    // encode CircuitVerify command as msgpack
    // call bbapi via cbindCall pattern
    // decode response
    // ...
    return false, fmt.Errorf("not yet implemented")
}
```

## Open Questions

1. **Shared memory instantiation** — wazero's threads support is experimental; needs a
   quick spike to confirm the module instantiates without errors before committing further.

2. **VK format** — the node needs a copy of the circuit's verification key. Options:
   - Embed the precomputed VK (`circuits/jwt_auth/target/proof/vk`) at build time.
   - Recompute it at startup from the compiled circuit JSON (`jwt_auth.json`) via
     `CircuitComputeVk`.

3. **Public inputs serialisation** — the `CircuitVerify` command takes public inputs as
   field elements. Need to map the `AuthProof` fields
   (`Sub`, `Iss`, `Exp`, `Aud`, `Azp`, `JWKSModulus`, `SessionPub`) to the circuit's
   public input layout as declared in `circuits/jwt_auth/src/main.nr`.

4. **msgpack schema** — the `api_types.js` generated file defines the exact field names.
   Replicate in Go (or generate from the circuit manifest).

5. **Performance** — wazero's interpreter is slower than native; the optimizing compiler
   is faster but may not yet support the threads proposal. Verification should be
   fast enough (~tens of ms) even in interpreter mode; proving is too slow for the
   in-process path and should remain a CLI call or external service.

## Related Files

- `circuits/jwt_auth/src/main.nr` — Noir circuit; defines public inputs
- `circuits/jwt_auth/target/jwt_auth.json` — compiled circuit artifact
- `circuits/jwt_auth/target/proof/vk` — precomputed verification key
- `circuits/jwt_auth/target/proof/proof` — sample proof (for integration tests)
- `cmd/zkbench/main.go` — end-to-end pipeline benchmark using `bb` CLI
- `node/auth.go:288` — TODO stub for `ValidateAuthProof`
- `node/node.go:395` — TODO stub for `POST /v1/auth` production mode
