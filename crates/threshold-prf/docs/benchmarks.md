# Threshold PRF Benchmarks

Date created: April 16, 2026
Last updated: June 13, 2026

## Scope

This document tracks the active `t-of-N` benchmark surface for
`threshold-prf`.

The crate runs server-side, so production bundle size is an operational signal
and platform-limit check. It is not a user-facing web bundle target.

## Commands

Native Criterion benchmark:

```bash
just threshold-prf-bench
```

Native guardrail check:

```bash
just threshold-prf-bench-check
```

Local Node/V8 WASM benchmark:

```bash
just threshold-prf-wasm-bench
```

Production WASM package-size check:

```bash
just threshold-prf-wasm-size
```

Generated package smoke:

```bash
just threshold-prf-wasm-smoke
```

Cloudflare Worker benchmark harness:

```bash
just threshold-prf-worker-bench-build
just threshold-prf-worker-bench-init-check
just threshold-prf-worker-bench-deploy
just threshold-prf-worker-bench-run https://threshold-prf-worker-bench.<account>.workers.dev
```

Live Cloudflare testing is deferred.

## Active Native Guardrails

The guardrail check reads Criterion mean confidence-interval upper bounds after
`just threshold-prf-bench` has produced fresh results.

| Benchmark | Native guardrail |
| --- | ---: |
| `generate_signing_root` | <= 100 us |
| `split_signing_root_2_of_3` | <= 100 us |
| `split_signing_root_3_of_5` | <= 100 us |
| `evaluate_direct_reference` | <= 1 ms |
| `evaluate_partial` | <= 1 ms |
| `combine_partials_2_of_3` | <= 1 ms |
| `combine_partials_3_of_5` | <= 1 ms |
| `one_runtime_evaluate_2_of_3_partials_and_combine` | <= 2 ms |
| `one_runtime_evaluate_3_of_5_partials_and_combine` | <= 2 ms |
| `evaluate_partial_with_dleq_proof` | <= 2 ms |
| `verify_partial_dleq_proof` | <= 2 ms |
| `combine_verified_partials_3_of_5` | <= 4 ms |

These thresholds catch large regressions before integration. They are looser
than local Apple M4 Pro measurements and are not portable performance claims
for CI or Cloudflare Workers.

## Retained Local Baseline

Environment:

- Date: June 13, 2026 Asia/Tokyo
- Machine: Apple M4 Pro, Darwin arm64
- Runtime: `node v22.13.0`
- Native command: `just threshold-prf-bench`
- Native guard command: `just threshold-prf-bench-check`
- Local WASM command: `just threshold-prf-wasm-bench`
- Bundle-size command: `just threshold-prf-wasm-size`

Native Criterion mean estimates:

| Benchmark | Mean |
| --- | ---: |
| `one_runtime_evaluate_2_of_3_partials_and_combine` | 103.775 us |
| `one_runtime_evaluate_3_of_5_partials_and_combine` | 153.817 us |
| `combine_partials_2_of_3` | 55.170 us |
| `combine_partials_3_of_5` | 82.456 us |
| `combine_verified_partials_3_of_5` | 367.413 us |

Local Node/V8 WASM results:

| Benchmark | Iterations | Time/op |
| --- | ---: | ---: |
| `one_runtime_2_of_3_evaluate_partials_and_combine` | 20,000 | 214.509 us |
| `one_runtime_3_of_5_evaluate_partials_and_combine` | 10,000 | 324.272 us |
| `evaluate_partial_with_dleq_proof` | 10,000 | 201.487 us |
| `verify_partial_dleq_proof` | 10,000 | 200.762 us |
| `combine_verified_partials_3_of_5` | 3,000 | 769.549 us |

Interpretation:

- `2-of-3` one-runtime derivation remains about `0.10 ms` native and about
  `0.21 ms` in the local Node/V8 WASM proxy.
- `3-of-5` one-runtime derivation is about 1.5x the `2-of-3` path, matching
  the extra interpolation and partial-evaluation work.
- `3-of-5` verified combine remains sub-millisecond in the local Node/V8
  proxy.
- The native guardrail check passed all active benchmark thresholds.

## Production WASM Package Size

Latest retained size check after distributed-combine exports:

| Artifact | Raw | Gzip | Brotli |
| --- | ---: | ---: | ---: |
| `threshold_prf_bg.wasm` | 87.8 KiB | 39.9 KiB | 33.3 KiB |
| `threshold_prf.js` | 17.1 KiB | 3.0 KiB | 2.7 KiB |
| package total | 111.6 KiB | 44.5 KiB | 37.3 KiB |

The generated package smoke currently checks 32 outputs and 7 rejection
cases.

## WASM Initialization Lifecycle

Expected lifecycle:

- Cloudflare Worker benchmark isolates cache threshold-prf WASM initialization
  in module-scope state. The first `/bench` request in an isolate initializes
  WASM, and subsequent warm `/bench` requests reuse the cached init promise.
- The server SDK `ensureThresholdPrfWasm()` path also keeps a module-scope init
  promise, so repeated derivations in one process avoid redundant
  `init_threshold_prf()` calls.
- New Worker isolates and new server processes pay initialization cost again.

Regression guard:

```bash
just threshold-prf-worker-bench-init-check
```

The guard starts local Wrangler, sends two `/bench` requests to the fixture, and
fails if the second request reports `wasmWasReadyBeforeRequest: false`.

## Cloudflare Worker Harness

Source:

- [worker-bench](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/worker-bench)
- [worker-bench-build.mjs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/scripts/worker-bench-build.mjs)
- [worker-bench-init-check.mjs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/scripts/worker-bench-init-check.mjs)
- [worker-bench-run.mjs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/scripts/worker-bench-run.mjs)

Measured deployed results: pending.

Record the first deployed run with:

- date
- Cloudflare account/region details that are safe to disclose
- git revision and worktree state
- Worker URL or deployment version
- command and iteration count
- first-request and warm-request samples
- WASM initialization time
- in-isolate crypto timings
- client-observed request latency

## Performance Readiness Decision

Decision: threshold-prf performance is sufficient for server SDK one-runtime
integration.

Rationale:

- The `2-of-3` path is about `0.10 ms` native and about `0.21 ms` in the
  local Node/V8 WASM proxy.
- Existing ECDSA bootstrap and Ed25519 Yao ceremony paths are tens to hundreds
  of milliseconds, so threshold-prf derivation is not a first-order latency source.
- Further threshold-prf micro-optimization should wait for deployed Worker
  measurements or a demonstrated hot path.
- Real Cloudflare Worker runtime benchmarks are still required before making
  Worker production latency claims or treating coordination costs as known.

## Optimization Policy

High-impact optimization work should target measured runtime costs:

- deployed Worker cold and warm request timings
- storage and decrypt overhead around sealed share resolution
- WASM initialization lifecycle regressions
- distributed-combine coordination overhead
- DLEQ proof generation or verification only when profiling shows it is
  material

The local crypto path is already fast enough that transcript allocation cleanup,
prepared-context internals, clone cleanup, or curve abstraction work should wait
for a measured bottleneck.
