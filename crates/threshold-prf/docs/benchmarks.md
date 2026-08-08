# Threshold PRF Benchmarks

Date created: April 16, 2026
Last updated: June 13, 2026

## Scope

This document tracks the active `t-of-N` benchmark surface for
`threshold-prf`.

The native crate is the production implementation. The local Node/V8 WASM
benchmark exercises the separate benchmark wrapper and provides a comparative
runtime signal.

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
for CI.

## Retained Local Baseline

Environment:

- Date: June 13, 2026 Asia/Tokyo
- Machine: Apple M4 Pro, Darwin arm64
- Runtime: `node v22.13.0`
- Native command: `just threshold-prf-bench`
- Native guard command: `just threshold-prf-bench-check`
- Local WASM command: `just threshold-prf-wasm-bench`

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

## Performance Readiness Decision

Decision: threshold-prf performance is sufficient for server SDK one-runtime
integration.

Rationale:

- The `2-of-3` path is about `0.10 ms` native and about `0.21 ms` in the
  local Node/V8 WASM proxy.
- Existing ECDSA bootstrap and Ed25519 Yao ceremony paths are tens to hundreds
  of milliseconds, so threshold-prf derivation is not a first-order latency source.
- Further threshold-prf micro-optimization should wait for a demonstrated hot
  path.

## Optimization Policy

High-impact optimization work should target measured runtime costs:

- measured native or local WASM runtime costs
- DLEQ proof generation or verification only when profiling shows it is
  material

The local crypto path is already fast enough that transcript allocation cleanup,
prepared-context internals, clone cleanup, or curve abstraction work should wait
for a measured bottleneck.
