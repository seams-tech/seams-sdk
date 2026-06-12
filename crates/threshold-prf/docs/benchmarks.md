# Threshold PRF Benchmarks

Date created: April 16, 2026

Benchmark harness:

```bash
cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline
```

Repeatable repo-local command:

```bash
just threshold-prf-bench
```

Native benchmark guardrail check:

```bash
just threshold-prf-bench-gate
```

The guardrail check is intended to catch large regressions before integration.
It is not a portable performance claim across CI machines or Cloudflare Worker
runtimes.

Local Node/V8 WASM benchmark:

```bash
just threshold-prf-wasm-bench
```

This builds `crates/threshold-prf/wasm-bench` with
`wasm-pack --target nodejs --release` and runs the resulting
`wasm32-unknown-unknown` module under Node/V8. It is a closer proxy for Worker
WASM overhead than native Criterion, but it is still not a real Cloudflare
Worker isolate measurement.

Cloudflare Worker benchmark harness:

```bash
just threshold-prf-worker-bench-build
just threshold-prf-worker-bench-deploy
just threshold-prf-worker-bench-run https://threshold-prf-worker-bench.<account>.workers.dev
```

This builds the exported `wasm/threshold_prf` package into
`crates/threshold-prf/worker-bench/vendor/threshold_prf`, deploys a small
benchmark Worker, and records deployed samples under
`crates/threshold-prf/target/worker-bench`. The Worker reports first request in
isolate, WASM initialization time, in-isolate dispatch-loop cost, ECDSA
`y_relayer` derivation, and Ed25519 server-input derivation. Cold-path
measurement requires a fresh deployment or an idle isolate before the first
`/bench` request.

The initial benchmark suite measures:

- signing-root generation
- 2-of-3 splitting
- direct reference evaluation
- one partial evaluation
- two-partial combine
- full Option A evaluation
- canonical Option A derivation helper
- canonical Option A derivation from share wires
- DLEQ proof generation
- DLEQ proof verification
- DLEQ verified combine
- share refresh

## Local Results

Environment:

- Date: April 16, 2026
- Machine: Apple M4 Pro, Darwin arm64
- Command: `cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 396.14-400.83 ns |
| `split_signing_root_2_of_3` | 617.99-623.84 ns |
| `evaluate_direct_reference` | 27.999-28.270 us |
| `evaluate_partial` | 25.556-25.856 us |
| `combine_partials` | 58.312-58.986 us |
| `option_a_evaluate_two_partials_and_combine` | 109.04-109.70 us |
| `refresh_signing_root_shares_2_of_3` | 21.097-21.420 us |

## DLEQ Prototype Local Results

Environment:

- Date: April 16, 2026
- Machine: Apple M4 Pro, Darwin arm64
- Command: `cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 412.82-418.43 ns |
| `split_signing_root_2_of_3` | 619.58-625.34 ns |
| `evaluate_direct_reference` | 28.953-29.319 us |
| `evaluate_partial` | 26.367-26.709 us |
| `combine_partials` | 60.116-60.787 us |
| `option_a_evaluate_two_partials_and_combine` | 112.78-114.36 us |
| `evaluate_partial_with_dleq_proof` | 108.60-109.96 us |
| `verify_partial_dleq_proof` | 103.70-104.88 us |
| `refresh_signing_root_shares_2_of_3` | 15.939-16.165 us |

Interpretation:

- Option A is roughly 0.11 ms of local CPU work before existing HSS signing work.
- Option B should have similar total crypto work, plus network/coordination overhead between workers.
- DLEQ adds roughly 0.11 ms for proof generation per worker partial and roughly
  0.10 ms for verification per partial on this machine.
- These numbers are local development measurements, not Cloudflare Worker production measurements.

## Post-Core Native Results

Environment:

- Date: April 16, 2026
- Machine: Apple M4 Pro, Darwin arm64
- OS: macOS 15.7.1, Darwin 24.6.0
- Rust: `rustc 1.86.0 (05f9846f8 2025-03-31)`
- Cargo: `cargo 1.86.0 (adf9b6ad1 2025-02-28)`
- Git revision: `a51e23a1` with uncommitted `threshold-prf` and `justfile`
  changes
- Command: `just threshold-prf-bench-gate`
- Harness command: `cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline`
- Core benchmark dependencies: `curve25519-dalek 4.1.3`,
  `rand_core 0.6.4`, `sha2 0.10.9`, `subtle 2.6.1`, `zeroize 1.8.2`,
  `criterion 0.5.1`, `rand_chacha 0.3.1`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 402.15-404.48 ns |
| `split_signing_root_2_of_3` | 634.52-641.81 ns |
| `evaluate_direct_reference` | 28.949-29.198 us |
| `evaluate_partial` | 26.492-26.682 us |
| `combine_partials` | 59.826-60.495 us |
| `option_a_evaluate_two_partials_and_combine` | 111.91-113.12 us |
| `evaluate_partial_with_dleq_proof` | 108.73-109.92 us |
| `verify_partial_dleq_proof` | 104.40-106.89 us |
| `refresh_signing_root_shares_2_of_3` | 16.026-16.620 us |

Interpretation:

- Post-core Option A remains roughly 0.11-0.12 ms of native CPU work before HSS
  signing.
- DLEQ proof generation and verification remain roughly 0.11 ms each per
  partial on this machine.
- The native guardrail check passed for all nine benchmark targets measured in
  that run.
- Native performance is sufficient for integration. Cloudflare Worker/WASM
  measurements are still required before making Worker latency claims.

## Native Guardrail Thresholds

The current native benchmark gate checks Criterion's mean confidence-interval
upper bound after `just threshold-prf-bench` has produced fresh results.

| Benchmark | Native guardrail |
| --- | ---: |
| `generate_signing_root` | <= 100 us |
| `split_signing_root_2_of_3` | <= 100 us |
| `evaluate_direct_reference` | <= 1 ms |
| `evaluate_partial` | <= 1 ms |
| `combine_partials` | <= 1 ms |
| `option_a_evaluate_two_partials_and_combine` | <= 2 ms |
| `derive_output_from_signing_root_shares` | <= 2 ms |
| `derive_output_from_signing_root_share_wires` | <= 2 ms |
| `evaluate_partial_with_dleq_proof` | <= 2 ms |
| `verify_partial_dleq_proof` | <= 2 ms |
| `combine_verified_partials` | <= 4 ms |
| `refresh_signing_root_shares_2_of_3` | <= 1 ms |

These thresholds are intentionally looser than the Apple M4 Pro measurements.
They are release/integration guardrails for major regressions, not fine-grained
microbenchmark regression targets.

## Post-Optimization Native Results

Change measured:

- `evaluate_partial_with_dleq_proof` now computes the PRF input point once and
  reuses it for partial generation and DLEQ proof generation.

Environment:

- Date: April 16, 2026
- Machine: Apple M4 Pro, Darwin arm64
- Command: `just threshold-prf-bench-gate`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 391.33-394.89 ns |
| `split_signing_root_2_of_3` | 634.86-646.06 ns |
| `evaluate_direct_reference` | 29.194-30.239 us |
| `evaluate_partial` | 26.578-27.721 us |
| `combine_partials` | 60.016-61.164 us |
| `option_a_evaluate_two_partials_and_combine` | 113.07-117.61 us |
| `evaluate_partial_with_dleq_proof` | 103.03-108.91 us |
| `verify_partial_dleq_proof` | 103.71-112.96 us |
| `refresh_signing_root_shares_2_of_3` | 16.407-17.174 us |

Interpretation:

- DLEQ proof generation improved by roughly 4-8% in this run.
- Option A remains roughly 0.11-0.12 ms of native CPU work.
- All nine native guardrail thresholds measured in that run passed.

## Canonical Option A Helper Native Results

Change measured:

- added `derive_output_from_signing_root_shares`, the canonical one-runtime
  Option A helper that computes two threshold partials and combines them without
  reconstructing `k_org`

Environment:

- Date: April 17, 2026 Asia/Tokyo
- Machine: Apple M4 Pro, Darwin arm64
- Command: `just threshold-prf-bench-gate`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 384.34-389.69 ns |
| `split_signing_root_2_of_3` | 603.32-610.92 ns |
| `evaluate_direct_reference` | 27.210-27.330 us |
| `evaluate_partial` | 25.670-26.055 us |
| `combine_partials` | 56.380-56.876 us |
| `option_a_evaluate_two_partials_and_combine` | 107.96-108.56 us |
| `derive_output_from_signing_root_shares` | 101.33-101.77 us |
| `evaluate_partial_with_dleq_proof` | 97.964-98.440 us |
| `verify_partial_dleq_proof` | 99.601-101.16 us |
| `refresh_signing_root_shares_2_of_3` | 14.546-14.694 us |

Interpretation:

- The canonical Option A helper is roughly `0.10 ms` of native CPU work before
  HSS signing.
- The helper is slightly faster than the manually sequenced Option A benchmark
  because it computes the context binding once and reuses it internally.
- All 10 native guardrail thresholds passed.

## Expanded Native Results

Change measured:

- added Criterion coverage for `derive_output_from_signing_root_share_wires`
- added Criterion coverage for `combine_verified_partials`
- extended the native guardrail checker to cover all 12 benchmark targets

Environment:

- Date: June 13, 2026 Asia/Tokyo
- Machine: Apple M4 Pro, Darwin arm64
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Git revision before this benchmark-doc update: `b7ceb493`
- Command: `just threshold-prf-bench-gate`

Results:

| Benchmark | Time |
| --- | ---: |
| `generate_signing_root` | 380.024-387.285 ns |
| `split_signing_root_2_of_3` | 577.364-589.422 ns |
| `evaluate_direct_reference` | 26.117-26.263 us |
| `evaluate_partial` | 23.759-24.137 us |
| `combine_partials` | 54.926-55.893 us |
| `option_a_evaluate_two_partials_and_combine` | 105.158-105.835 us |
| `derive_output_from_signing_root_shares` | 98.202-99.195 us |
| `derive_output_from_signing_root_share_wires` | 98.065-99.171 us |
| `evaluate_partial_with_dleq_proof` | 95.270-95.763 us |
| `verify_partial_dleq_proof` | 109.228-109.982 us |
| `combine_verified_partials` | 245.174-246.586 us |
| `refresh_signing_root_shares_2_of_3` | 15.002-15.088 us |

Interpretation:

- Share-wire Option A derivation remains about `0.10 ms` native.
- DLEQ verified combine is about `0.25 ms` native because it verifies both
  proof bundles and combines the partials.
- Native threshold-prf crypto remains below the expected latency floor for HSS
  registration and signing flows.
- All 12 native guardrail thresholds passed.

## Local Node/V8 WASM Results

Environment:

- Date: April 17, 2026 Asia/Tokyo
- Runtime: `node v22.13.0`
- Target: `wasm32-unknown-unknown` via `wasm-pack --target nodejs --release`
- Command: `just threshold-prf-wasm-bench`
- Optimized `.wasm` size: 95,466 bytes

Results:

| Benchmark | Iterations | Time/op |
| --- | ---: | ---: |
| `option_a_evaluate_two_partials_and_combine` | 20,000 | 222.018 us |
| `derive_output_from_signing_root_shares` | 20,000 | 212.441 us |
| `evaluate_partial_with_dleq_proof` | 10,000 | 210.613 us |
| `verify_partial_dleq_proof` | 10,000 | 211.491 us |

Interpretation:

- The Node/V8 WASM proxy is roughly 2x slower than native for the measured hot
  paths, but still sub-millisecond.
- The canonical Option A helper remains slightly faster than the manually
  sequenced Option A benchmark in this proxy runtime.
- Option A remains comfortably below the 5 ms initial Worker/WASM target.
- DLEQ proof generation and verification also remain sub-millisecond in this
  proxy runtime.
- These results do not include Cloudflare Worker isolate startup, request
  dispatch, Durable Object, storage, or network overhead.

## Expanded Local Node/V8 WASM Results

Change measured:

- added local WASM coverage for `derive_output_from_signing_root_share_wires`
- added local WASM coverage for `combine_verified_partials`

Environment:

- Date: June 13, 2026 Asia/Tokyo
- Runtime: `node v22.13.0`
- Target: `wasm32-unknown-unknown` via `wasm-pack --target nodejs --release`
- Command: `just threshold-prf-wasm-bench`
- Git revision before this benchmark-doc update: `21ecbb5f`
- Optimized `.wasm` size: 100,866 bytes

Results:

| Benchmark | Iterations | Time/op |
| --- | ---: | ---: |
| `option_a_evaluate_two_partials_and_combine` | 20,000 | 217.592 us |
| `derive_output_from_signing_root_shares` | 20,000 | 208.479 us |
| `derive_output_from_signing_root_share_wires` | 20,000 | 211.322 us |
| `evaluate_partial_with_dleq_proof` | 10,000 | 204.796 us |
| `verify_partial_dleq_proof` | 10,000 | 206.334 us |
| `combine_verified_partials` | 5,000 | 522.854 us |

Interpretation:

- Share-wire Option A remains about `0.21 ms` in the local Node/V8 WASM proxy.
- DLEQ verified combine is about `0.52 ms` in the local Node/V8 WASM proxy.
- The WASM proxy is still sub-millisecond for the measured threshold-prf crypto
  paths.
- These results still exclude Cloudflare Worker isolate startup, request
  dispatch, Durable Object, storage, and network overhead.

## Cloudflare Worker Harness

Harness added: June 12, 2026.

Source:

- [worker-bench](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/worker-bench)
- [worker-bench-build.mjs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/scripts/worker-bench-build.mjs)
- [worker-bench-run.mjs](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/scripts/worker-bench-run.mjs)

Commands:

```bash
just threshold-prf-worker-bench-build
just threshold-prf-worker-bench-dev
just threshold-prf-worker-bench-deploy
just threshold-prf-worker-bench-run https://threshold-prf-worker-bench.<account>.workers.dev
```

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

Decision: threshold-PRF performance is sufficient for server SDK Option A
integration.

Rationale:

- The canonical Option A helper is about `0.10 ms` native and about `0.21 ms`
  in the local Node/V8 WASM proxy.
- Existing ECDSA and Ed25519 HSS ceremony paths are tens to hundreds of
  milliseconds, so threshold-PRF derivation is not a first-order latency source.
- Further threshold-PRF micro-optimization should not block integration.
- Real Cloudflare Worker runtime benchmarks are still required before making
  Worker production latency claims or before treating Option B coordination
  costs as known.
