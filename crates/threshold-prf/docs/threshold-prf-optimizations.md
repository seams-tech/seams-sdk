# `threshold-prf` High-Impact Optimization Plan

Date created: June 12, 2026

## Scope

This plan covers only high-impact performance work for
[crates/threshold-prf](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf).

The local crypto path is already fast: recorded `2-of-3` Option A results
are about `0.10 ms` native and about `0.21 ms` in the local Node/V8 WASM proxy.
End-to-end latency risk is therefore more likely to come from Worker startup,
WASM initialization, storage, request dispatch, serialization, and Option B
coordination.

Active optimization work should answer production questions or reduce cost in a
path known to be hot. Micro-optimizations stay deferred until deployed
measurements show they matter.

## High-Impact Tasks

### 1. Deployed Worker Benchmarks

Measure the real runtime path before changing crypto internals.

- [x] Add a Cloudflare Worker benchmark harness for the exported
  `wasm/threshold_prf` functions.
- [ ] Measure warm Worker execution for:
  - `threshold_prf_derive_ecdsa_hss_y_relayer`
  - `threshold_prf_derive_ed25519_hss_server_inputs`
  - Router/A/B Candidate A signer partial evaluation after Worker wiring exists
  - Router/A/B Candidate A recipient combine after Worker wiring exists
- [ ] Measure cold Worker execution separately:
  - isolate startup
  - WASM module initialization
  - first request after deploy
  - first request after idle
- [ ] Measure non-crypto request overhead separately:
  - request dispatch
  - Durable Object or storage access
  - share unwrap/decrypt boundary
  - serialization and deserialization
  - Option B network or coordinator hop
- [ ] Add the deployed results to
  [benchmarks.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/benchmarks.md).

Exit criteria:

- warm and cold paths are reported separately
- crypto time is separated from runtime and storage overhead
- production latency claims no longer depend on local Node/V8 proxy numbers

Harness status:

- Worker fixture:
  [worker-bench](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/worker-bench)
- Build command: `just threshold-prf-worker-bench-build`
- Local Wrangler command: `just threshold-prf-worker-bench-dev`
- Deploy command: `just threshold-prf-worker-bench-deploy`
- Deployed sampling command: `just threshold-prf-worker-bench-run <worker-url>`

### 2. WASM Initialization And Request-Path Amortization

If Worker measurements show startup or initialization cost dominates, reduce
that cost before touching curve arithmetic.

- [x] Confirm whether the WASM module is initialized once per isolate or once
  per request.
- [x] Cache initialized module state at the Worker isolate boundary where the
  runtime allows it.
- [x] Avoid repeated package imports and redundant `init_threshold_prf` calls in
  hot request paths.
- [x] Add a regression benchmark that catches accidental per-request WASM
  initialization.
- [x] Document the expected initialization lifecycle in
  [benchmarks.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/benchmarks.md).

Exit criteria:

- a warm request avoids repeated WASM initialization
- cold-start cost is measured and documented
- a benchmark fails if warm requests regress to cold-start behavior

Status as of June 13, 2026:

- The Worker benchmark fixture uses module-scope `wasmReadyPromise` state, so a
  warm `/bench` request reuses the initialized WASM module inside the same
  isolate.
- The server SDK `ensureThresholdPrfWasm()` path uses a module-scope init
  promise and avoids redundant `init_threshold_prf()` calls after the first
  successful load in a process.
- `just threshold-prf-worker-bench-init-check` starts local Wrangler and fails
  if the second `/bench` request reports `wasmWasReadyBeforeRequest: false`.
- Deployed cold-start measurement remains pending until live Cloudflare testing
  resumes.

### 3. DLEQ Hot-Path Optimization

Optimize DLEQ only if deployed or integration benchmarks show proof generation
or verification is a meaningful part of the request budget.

#### Precomputed Commitments

`SigningRootShareCommitmentV1::from_share` is stable for a share within a
root-share epoch.

- [ ] Add an internal proof-generation helper that accepts a previously
  validated commitment.
- [ ] Verify the commitment share ID matches the signing-root share ID.
- [ ] Bind cached commitments to the root-share epoch at the caller boundary.
- [ ] Add rejection tests for stale or mismatched commitments.
- [ ] Benchmark DLEQ proof generation with and without commitment reuse.

#### Public-Data Verification Acceleration

DLEQ verification operates on public proof, commitment, partial, context, and
nonce-derived points. A variable-time verification helper may be acceptable if
the public-input argument is explicit and reviewed.

- [ ] Audit every input to the proposed variable-time operation.
- [ ] Document the public-input argument at the call site.
- [ ] Prototype accelerated DLEQ verification behind a private helper.
- [ ] Keep the existing verification path if the speedup is too small to justify
  the extra code.
- [ ] Benchmark native, local WASM, and deployed Worker verification.

Exit criteria:

- no secret scalar enters a variable-time path
- DLEQ rejection tests still cover wrong context, wrong commitment, wrong share
  ID, malformed proof, and duplicate bundle cases
- benchmarks show a meaningful improvement in a real hot path

## Deferred Work

These tasks are intentionally outside the active plan because they are unlikely
to affect end-to-end latency at the current baseline:

- prepared context internals for the simple Option A helper
- transcript allocation cleanup
- pair-shaped internal APIs
- clone cleanup in verified combine
- tighter native Criterion thresholds
- replacing `curve25519-dalek`
- introducing a new curve abstraction

Move one of these tasks into the active plan only after profiling identifies it
as material in the deployed path.

## Release Gates

- [x] Record native baseline with:

```bash
just threshold-prf-bench-gate
```

- [x] Record local WASM baseline with:

```bash
just threshold-prf-wasm-bench
```

- [x] Add local WASM t-of-N benchmark coverage for before/after API
  migration comparisons.
- [x] Add production WASM bundle-size measurement with:

```bash
just threshold-prf-wasm-size
```

- [x] Record t-of-N before-API-migration baseline for native performance,
  local WASM performance, and production WASM package size.
- [ ] Record deployed Worker baseline before merging any performance-focused
  implementation change.
- [ ] Treat any output-vector change as a protocol change.
- [x] Keep benchmark reports tied to a date, runtime, git revision, command,
  and worktree state.

Status as of June 13, 2026:

- Native Criterion coverage now includes share-wire Option A and verified DLEQ
  combine paths.
- Local Node/V8 WASM coverage now includes the same share-wire Option A and
  verified DLEQ combine paths, plus `2-of-3` and `3-of-5` Option A and DLEQ
  paths.
- Production WASM bundle-size measurement records raw, gzip, and brotli sizes
  for before/after refactor comparisons.
- Native share-wire Option A is about `0.10 ms`; local Node/V8 WASM share-wire
  Option A is about `0.21 ms`.
- Native verified DLEQ combine is about `0.25 ms`; local Node/V8 WASM verified
  DLEQ combine is about `0.52 ms`.
- The data does not justify DLEQ micro-optimization before deployed Worker or
  integration profiling identifies it as a real hot path.

## Non-Goals

- changing v1 transcript framing
- changing v1 wire formats
- changing output encodings
- optimizing direct reference evaluation for production use
- blocking integration on local micro-optimizations
