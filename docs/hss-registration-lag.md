# HSS Registration Lag

## Summary

We traced the long Option A registration delay to a mix of server-side and client-side issues around how the NEAR signer WASM was built and loaded.

The main problems were:

1. The relay HSS hot path was loading the wrong WASM build.
2. The relay bootstrap-grant route was kicking off expensive warmup work on the request path.
3. The browser HSS path was also using an unoptimized NEAR signer WASM build in development.

After fixing those issues, the registration HSS timings dropped into the expected range:

- registration HSS `prepare`: about `360ms`
- registration HSS `finalize`: about `986ms`
- post-registration session HSS `prepare`: about `335ms`
- post-registration session HSS `finalize`: about `531ms`

At that point, the remaining registration time was mostly real NEAR account creation and access-key visibility checks.

## Was The Server Using A Debug Build?

Yes.

That was one of the main causes.

The relay HSS path was supposed to use an optimized server-side WASM package, but it was falling back to the source-tree browser/dev package instead:

- wrong path fallback loaded `wasm/near_signer/pkg/wasm_signer_worker_bg.wasm`
- that package had been built with `wasm-pack --dev --no-opt`

That produced multi-second HSS timings on the server:

- `prepare`: about `3.7s` to `4.0s`
- `finalize`: about `10s+`

The fix was to make the relay use the dedicated optimized server package:

- [server/src/core/ThresholdService/ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
- [sdk/scripts/build/build-dev.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-dev.sh)
- [sdk/scripts/build/build-prod.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-prod.sh)

The relay now loads:

- `sdk/dist/esm/server/wasm/near_signer/pkg-server/wasm_signer_worker_bg.wasm`

and that package is built with `--release`.

## Was The Server Building The WASM Worker Dynamically?

Not in the sense of compiling Rust source on every request.

But it **was** lazily loading and compiling the WASM module at runtime on first use, and that still mattered.

Two separate behaviors contributed to the lag:

1. `warmRegistrationRuntime()` performed expensive signer/HSS initialization on the Node event loop.
2. The bootstrap-grant routes triggered that warmup in a fire-and-forget way immediately after issuing a grant.

That created a misleading gap where the relay only showed:

- `[relay][bootstrap-grants] issued`

and then appeared idle for many seconds before the next HSS request log arrived.

The issue was not that the route was waiting on warmup explicitly. The issue was that the warmup still ran on the same process and could monopolize the event loop after the response was sent.

The fix was:

- remove `warmRegistrationRuntime()` from the bootstrap-grant routes
- keep warmup as an explicit startup concern instead of piggy-backing it onto the first user request

Files:

- [server/src/router/express/routes/bootstrapGrants.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/bootstrapGrants.ts)
- [server/src/router/cloudflare/routes/bootstrapGrants.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/bootstrapGrants.ts)
- [examples/relay-server/src/index.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/src/index.ts)

## Client-Side Issue

The relay was not the only problem.

After the relay was fixed, we still observed a long gap between:

1. the first managed bootstrap grant
2. the second managed bootstrap grant for `/registration/threshold-ed25519/hss/prepare`

That proved the delay was happening in the local browser HSS preparation step before the relay `prepare` request was even sent.

The cause was the same class of bug on the client side:

- the browser HSS path and `near-signer.worker` were still using `wasm/near_signer/pkg`
- in development, that package was also built with `wasm-pack --dev --no-opt`

The fix was to build the active browser NEAR signer package in release mode even in the dev SDK build:

- [sdk/scripts/build/build-dev.sh](/Users/pta/Dev/rust/simple-threshold-signer/sdk/scripts/build/build-dev.sh)

After that change:

- the browser NEAR signer WASM asset dropped from about `10.2MB` to about `1.2MB`
- the long client-side HSS preparation gap collapsed

## What The Logs Mean Now

Once the fixes landed, the HSS path looked healthy.

Example:

```text
[threshold-ed25519][registration] hss prepare timings { wasmPrepareMs: 360, totalMs: 360 }
[threshold-ed25519][registration] hss finalize timings { hssFinalizeMs: 985, totalMs: 986 }
```

At that point the remaining registration cost was mostly the real account creation path:

```text
Atomic registration account creation ... reached EXECUTED_OPTIMISTIC in 2460ms
Atomic registration account creation ... key visibility verified=true in 2049ms
```

So the remaining latency after the fixes is mostly:

- NEAR account creation
- final access-key visibility verification
- normal client/network/UI overhead

## Final Answer

Yes, the server HSS hot path was effectively using a debug/unoptimized build before the fix.

No, the server was not recompiling Rust on each request, but it was lazily loading and compiling WASM at runtime, and that warmup was being triggered at the wrong time from the bootstrap-grant route path.

The final fix was a combination of:

- serving and loading the correct optimized server HSS WASM package
- removing relay warmup from bootstrap-grant request handling
- switching the active browser NEAR signer WASM package to release mode as well
