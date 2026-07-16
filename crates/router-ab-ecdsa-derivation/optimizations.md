# `router-ab-ecdsa-derivation` Optimizations

Last updated: 2026-05-20

Removal note: entries that refer to the old Router A/B ECDSA derivation context version are
historical. The active crate no longer retains those code paths, fixtures, or
benchmarks.

## Purpose

This file is the optimization ledger for `router-ab-ecdsa-derivation`.

It records:

- benchmark suite shape
- baseline results
- target budgets
- dominant cost centers
- each optimization attempt
- whether the attempt was accepted or rejected

No optimization should land without benchmark evidence against this ledger.

## Benchmark Suite

Dedicated benchmark suite:

- [benches/performance_baseline.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/benches/performance_baseline.rs)
- [benchmarks/router-ab-ecdsa-derivation-wasm/src/runner.mjs](/Users/pta/Dev/rust/simple-threshold-signer/benchmarks/router-ab-ecdsa-derivation-wasm/src/runner.mjs)

Measured paths:

1. `context_binding`
2. `client_share`
3. `relayer_share_and_identity`
4. `bootstrap_adapter`
5. `first_presign_roundtrip`
6. `sign_bridge_full`
7. `explicit_export`

Command:

```bash
cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline
```

WASM command:

```bash
pnpm benchmark:router-ab-ecdsa-derivation:wasm
```

Representative benchmark input:

- committed fixture corpus entry: `role_local_v1`

## Baseline

Baseline run:

- date: 2026-04-08
- implementation state: current crate-local reference path
- fixture: `derived-beta`

Median baseline results:

| Path | Median |
| --- | ---: |
| `canonical_derivation` | `26.871 µs` |
| `share_derivation` | `112.53 µs` |
| `bootstrap_adapter` | `187.75 µs` |
| `sign_bridge` | `38.319 ms` |
| `explicit_export` | `188.70 µs` |

## WASM Baseline

Initial Node-hosted wasm baseline:

- date: 2026-04-09
- runtime: Node-hosted wasm via `wasm/eth_signer/pkg` web target
- fixture: `derived-beta`
- note: this is Cloudflare-worker-adjacent runtime measurement, not a deployed
  worker benchmark

Median wasm results:

| Path | Median |
| --- | ---: |
| `canonical_derivation_wasm` | `0.113 ms` |
| `share_derivation_wasm` | `0.452 ms` |
| `bootstrap_non_export_wasm` | `0.585 ms` |
| `sign_non_export_wasm` | `117.168 ms` |
| `explicit_export_wasm` | `0.55 ms` |

WASM sign-stage breakdown from the profiled runner:

| Path | Median |
| --- | ---: |
| `sign_parse_input_wasm` | `~0 ms` |
| `sign_prepare_session_wasm` | `~1 ms` |
| `sign_presign_roundtrip_wasm` | `~118-120 ms` |
| `sign_client_signature_share_wasm` | `~0 ms` |
| `sign_finalize_signature_wasm` | `~1 ms` |
| `sign_total_core_wasm` | `~120-121 ms` |

Current role-local WASM numbers are pending. The existing Node-hosted WASM
runner still targets the pre-role-local binding names and needs to be updated
before it can measure the active API shape.

## Initial Target Budgets

These are crate-level optimization budgets for the current reference
implementation. They are not final product SLOs.

| Path | Regression Guardrail | Optimization Target |
| --- | ---: | ---: |
| `canonical_derivation` | `<= 35 µs` | `<= 22 µs` |
| `share_derivation` | `<= 140 µs` | `<= 90 µs` |
| `bootstrap_adapter` | `<= 230 µs` | `<= 150 µs` |
| `sign_bridge` | `<= 45 ms` | `<= 25 ms` |
| `explicit_export` | `<= 230 µs` | `<= 150 µs` |

WASM observation:

- bootstrap and export remain sub-millisecond even through the wasm boundary
- the wasm sign path is the only first-order cost center at about `119 ms`
- the wasm hotspot is overwhelmingly the presign roundtrip, not JS payload
  parsing or final signature assembly

## Dominant Cost Centers

Current dominant cost center:

- `sign_bridge`

Why:

- it measures at roughly `38.319 ms`
- every other benchmarked path is below `0.2 ms`
- it dominates the current crate runtime profile by a wide margin

Optimization priority:

1. `sign_bridge`
2. `share_derivation`
3. `bootstrap_adapter`
4. `explicit_export`
5. `canonical_derivation`

That means early optimization work should target the threshold-signing bridge,
not derivation micro-optimizations.

## Acceptance Rule

An optimization attempt is accepted only if all of these are true:

1. it preserves the current specs and one-key invariant
2. it does not weaken the export/signing boundary
3. it passes the crate test suite
4. it improves the relevant benchmark path or meaningfully simplifies the code
   without regressions

## Current Stop Point

Current native role-local benchmark snapshot:

| Path | Current band |
| --- | ---: |
| `context_binding` | `~668 ns` |
| `client_share` | `~34 µs` |
| `relayer_share_and_identity` | `~63 µs` |
| `bootstrap_adapter` | `~215 µs` |
| `explicit_export` | `~355 µs` |
| `sign_bridge_full` | `~40 ms` |
| `first_presign_roundtrip` | `~39 ms` |

Decision:

- optimization is complete enough for the crate phase
- derivation/bootstrap/export paths remain sub-millisecond after role-local
  derivation
- the only remaining hotspot is the upstream triples stage
- recent backend-adjacent micro-cuts have mostly been regressions or noise

That means the next crate work should be:

1. formal verification reconciliation
2. crate cleanup and docs consistency
3. only then, if needed, a higher-bar backend-level triples optimization pass

This ledger should not accept more optimization work unless there is either:

- a concrete product requirement that `~40 ms` sign latency is still too high,
  or
- a clear backend-level optimization candidate inside `do_generation_many::<2>`
  with benchmark-backed justification

For wasm specifically, this also means:

- keep `wasm/eth_signer` on `opt-level = "z"` unless bundle-size priorities
  change
- prefer runtime-path reductions inside the presign/triples stage over size-for-speed
  build-profile changes

## Optimization Log

### Entry 0: Benchmark Baseline Established

- date: 2026-04-08
- change:
  - added dedicated crate-local benchmark suite
  - ran initial baseline
- command:
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline`
- result:
  - accepted
- notes:
  - `sign_bridge` is the only first-order optimization target at the moment
  - derivation and bootstrap/export paths are already small relative to the
    signing bridge

### Entry 0.5: WASM Benchmark Baseline Established

- date: 2026-04-09
- change:
  - added a dedicated wasm benchmark suite through `wasm/eth_signer`
  - ran the first Node-hosted wasm baseline for the `router-ab-ecdsa-derivation` lifecycle
- command:
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - accepted
- wasm medians:
  - `canonical_derivation_wasm`: `0.113 ms`
  - `share_derivation_wasm`: `0.452 ms`
  - `bootstrap_non_export_wasm`: `0.585 ms`
  - `sign_non_export_wasm`: `117.168 ms`
  - `explicit_export_wasm`: `0.55 ms`
- notes:
  - the wasm boundary preserves the same shape as native: derivation,
    bootstrap, and export are small
  - the only first-order wasm hotspot is the sign path
  - wasm sign latency is about `3x` the native crate sign path, which is the
    relevant Cloudflare-adjacent baseline for future optimization work

### Entry 0.6: WASM Sign-Stage Split

- date: 2026-04-09
- change:
  - added a profiled wasm sign entrypoint through
    [wasm/eth_signer/src/router_ab_ecdsa_derivation.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/eth_signer/src/router_ab_ecdsa_derivation.rs)
  - extended the wasm runner to report internal sign buckets in
    [benchmarks/router-ab-ecdsa-derivation-wasm/src/runner.mjs](/Users/pta/Dev/rust/simple-threshold-signer/benchmarks/router-ab-ecdsa-derivation-wasm/src/runner.mjs)
- command:
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - accepted
- findings:
  - `sign_parse_input_wasm`: `~0 ms`
  - `sign_prepare_session_wasm`: `~1 ms`
  - `sign_presign_roundtrip_wasm`: `~118-120 ms`
  - `sign_client_signature_share_wasm`: `~0 ms`
  - `sign_finalize_signature_wasm`: `~1 ms`
  - `sign_total_core_wasm`: `~120-121 ms`
- conclusion:
  - the wasm sign overhead is not a JS decode/encode problem
  - almost all wasm sign latency still lives in the presign/triples roundtrip
  - the next useful optimization attempts should stay focused on that path

### Entry 1: Sign Bridge Split Baseline

- date: 2026-04-08
- change:
  - split the sign path benchmark into setup and full-path measurements
- command:
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline`
- result:
  - accepted
- split medians:

| Path | Median |
| --- | ---: |
| `sign_session_prepare` | `213.09 µs` |
| `presign_session_init_pair` | `7.4505 µs` |
| `sign_bridge_full` | `41.214 ms` |

- conclusion:
  - session preparation is not the problem
  - presign-session initialization is negligible
  - the real cost remains inside the threshold presign/sign execution loop
  - the next optimization pass should target the body of
    active role-local sign execution
    and the underlying `signer-core` threshold ECDSA path, not session setup

### Entry 2: Sign Bridge Inner Split

- date: 2026-04-08
- change:
  - split the full sign path into presign roundtrip vs final arithmetic steps
- command:
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline`
- result:
  - accepted
- split medians:

| Path | Median |
| --- | ---: |
| `presign_protocol_roundtrip` | `41.866 ms` |
| `client_signature_share_compute` | `53.333 µs` |
| `signature_finalize` | `197.05 µs` |
| `sign_bridge_full` | `43.175 ms` |

- conclusion:
  - the presign protocol roundtrip is overwhelmingly the dominant hotspot
  - client signature-share computation is negligible relative to presign
  - final signature assembly is also negligible relative to presign
  - the first real optimization pass should target the `ThresholdEcdsaPresignSession`
    polling/message path, not the final compute/finalize helpers

### Entry 3: Presign Protocol Phase Split

- date: 2026-04-08
- change:
  - split the presign protocol into pre-start, start-transition, and post-start
    phases
- commands:
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- presign_after_start`
- result:
  - accepted
- split medians:

| Path | Median |
| --- | ---: |
| `presign_before_start` | `40.145 ms` |
| `presign_start_transition` | `3.8312 µs` |
| `presign_after_start` | `220.35 µs` |

- conclusion:
  - the presign hotspot is almost entirely in the pre-`start_presign` phase
  - the `start_presign` transition itself is negligible
  - the post-start tail to completion is also negligible
  - the first optimization pass should target the triples/pre-start
    `ThresholdEcdsaPresignSession` roundtrip, not any final presign tail

### Entry 4: Direct Two-Party Relay In The Presign Driver

- date: 2026-04-08
- change:
  - removed extra pending-queue churn in the 2-party presign driver
  - relayed outgoing messages directly between client and relayer sessions in:
    - [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/src/integration/mod.rs)
    - [benches/performance_baseline.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/benches/performance_baseline.rs)
- rationale:
  - code inspection showed the expensive pre-`start_presign` phase lives in
    `signer-core`'s `PresignStage::Triples`, driven by:
    - `generate_triple_many::<2>(...)` in
      [threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
    - repeated `proto.poke()` calls during `PresignStage::Triples`
  - the wrapper was adding avoidable queue/drain overhead on top of that path
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
- result:
  - accepted
- before:
  - `sign_bridge_full`: `41.203 ms`
  - `presign_protocol_roundtrip`: `40.769 ms`
  - `presign_before_start`: `40.145 ms`
- after:
  - `sign_bridge_full`: `38.391 ms`
  - `presign_protocol_roundtrip`: `38.260 ms`
  - `presign_before_start`: `38.302 ms`
- conclusion:
  - this is a real wrapper-level win
  - it saves roughly `2.8 ms` on the full sign path
  - the hotspot is still the pre-start triples phase, but the queue/drain layer
    was non-trivial enough to remove
  - the next optimization pass should go deeper into the `Triples` stage itself

### Entry 5: Signer-Core Allocation-Light Presign Driver

- date: 2026-04-08
- change:
  - attempted to push the presign driver deeper into `signer-core`
  - added an allocation-light internal advance path for the 2-party presign
    loop, then rewired `router-ab-ecdsa-derivation` to use it
- files touched during the attempt:
  - [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
  - [src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/src/integration/mod.rs)
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
- result:
  - rejected and reverted
- measured regression before revert:
  - `sign_bridge_full`: `38.391 ms -> 41.610 ms`
  - `presign_protocol_roundtrip`: `38.260 ms -> 41.926 ms`
  - `presign_before_start`: `38.302 ms -> 41.605 ms`
- restored post-revert rerun:
  - `sign_bridge_full`: `39.703 ms`
  - `presign_protocol_roundtrip`: `39.328 ms`
  - `presign_before_start`: `38.706 ms`
- conclusion:
  - pushing the driver deeper into `signer-core` did not help
  - the accepted wrapper-level direct relay remains the correct kept state
  - the next target is the upstream triples implementation itself, especially
    `generate_triple_many::<2>` / `do_generation_many::<2>`

### Entry 6: Upstream Triples-Stage Inspection

- date: 2026-04-08
- change:
  - inspected the upstream threshold-signatures triples implementation to pin
    the next backend-level target
- files inspected:
  - [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
  - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/src/ecdsa/ot_based_ecdsa/triples/generation.rs`
  - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/benches/advanced_ot_based_ecdsa.rs`
- result:
  - accepted as measurement and inspection work
- findings:
  - almost all remaining sign cost still lives before `start_presign()`
  - that cost is dominated by `generate_triple_many::<2>` via
    `do_generation_many::<2>`
  - the hot path performs repeated per-triple vector building and accumulation:
    - `my_commitments`, `my_randomizers`, polynomial vectors, commitment vectors
    - `ParticipantMap` arrays for commitment collection
    - repeated `Vec` allocations for proof nonces and serialized share bundles
    - multiple `recv_from_others` loops that aggregate `Vec` payloads for both
      triples in lockstep
- conclusion:
  - the next worthwhile optimization pass is backend-level work inside
    `do_generation_many::<2>`, not more wrapper churn around `poll()`

### Entry 7: Allocation-Light Poll Progress Shape

- date: 2026-04-08
- change:
  - attempted to remove `String` allocations from
    `ThresholdEcdsaPresignProgress` by changing `stage` and `event` to
    borrowed static strings
- files touched during the attempt:
  - [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
  - [wasm/eth_signer/src/threshold.rs](/Users/pta/Dev/rust/simple-threshold-signer/wasm/eth_signer/src/threshold.rs)
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo check --manifest-path wasm/eth_signer/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
- result:
  - rejected and reverted
- measured regression before revert:
  - `sign_bridge_full`: `44.910 ms`
  - `presign_protocol_roundtrip`: `49.192 ms`
  - `presign_before_start`: `41.090 ms`
- restored post-revert rerun:
  - `sign_bridge_full`: `42.322 ms`
  - `presign_protocol_roundtrip`: `40.666 ms`
  - `presign_before_start`: `40.126 ms`
- conclusion:
  - removing the progress-string allocations did not produce a real win
  - the remaining hotspot is still the triples stage itself, not the progress
    envelope around `poll()`

### Entry 8: Internal Non-Allocating Poll Path For The Crate Sign Driver

- date: 2026-04-09
- change:
  - added a non-allocating internal presign event path in
    [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
  - switched the `router-ab-ecdsa-derivation` sign driver to use that internal path plus
    `is_triples_done()` instead of hot-loop string comparisons in
    [crates/router-ab-ecdsa-derivation/src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/src/integration/mod.rs)
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - accepted
- native result:
  - focused Criterion reported `sign_bridge_full` improvement in the
    `~1.8% to ~4.7%` range over the prior state
  - `presign_protocol_roundtrip` moved slightly in the right direction and
    stayed near the previous band
- wasm result:
  - `sign_non_export_wasm`: `120.948 ms -> 119.73 ms`
  - `sign_presign_roundtrip_wasm`: `~119.5 ms -> ~118 ms`
- conclusion:
  - this is a small but real runtime-path improvement without touching the
    `opt-level = "z"` wasm size posture
  - the remaining wasm hotspot is still the presign/triples stage itself

### Entry 9: Reused Outgoing Buffers In The Internal Presign Loop

- date: 2026-04-09
- change:
  - attempted to reuse outgoing message buffers across internal presign polls
    in:
    - [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
    - [crates/router-ab-ecdsa-derivation/src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/src/integration/mod.rs)
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: no statistically significant change
    - `presign_protocol_roundtrip`: no statistically significant change
    - `presign_before_start`: no statistically significant change
  - wasm:
    - `sign_non_export_wasm`: `119.73 ms -> 119.817 ms`
    - `sign_presign_roundtrip_wasm`: remained about `117-118 ms`
- conclusion:
  - reusing the outer outgoing buffers does not move the real hotspot enough
    to justify the extra code
  - keep the smaller internal-poll cleanup, but stop chasing outer-loop buffer
    churn

### Entry 10: Upstream Triples Preallocation For `N=2`

- date: 2026-04-09
- change:
  - attempted a narrow preallocation pass in upstream
    `do_generation_many::<2>` by replacing obvious hot `vec![]` sites with
    fixed-capacity `Vec::with_capacity(N)` allocation in:
    - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/src/ecdsa/ot_based_ecdsa/triples/generation.rs`
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: `40.698-41.279 ms` with Criterion reporting a
      statistically significant regression in the `~3.0% to ~5.3%` range
    - `presign_protocol_roundtrip`: `40.888-41.210 ms`, slightly worse and at
      best noise-adjacent
    - `presign_before_start`: no meaningful improvement
  - wasm:
    - `sign_non_export_wasm`: `119.817 ms -> 122.912 ms`
    - `sign_presign_roundtrip_wasm`: `~117-118 ms -> ~121.5 ms`
    - `sign_total_core_wasm`: `~119 ms -> ~123.5 ms`
- conclusion:
  - the obvious small-vector preallocation pass in the upstream triples stage
    made both native and wasm sign latency worse
  - this suggests the remaining cost is not improved by simple outer-container
    capacity tuning alone
  - the next deeper candidate should focus on clone pressure or more targeted
    fixed-size handling, not broad `Vec::with_capacity(N)` replacement

### Entry 11: Upstream Triples Clone-Pressure Reduction

- date: 2026-04-09
- change:
  - attempted a narrow clone reduction in upstream
    `do_generation_many::<2>` by:
    - precomputing the local `big_e` zero-coefficient view once
    - moving the local `big_e_v`, `big_f_v`, and `big_l_v` commitment vectors
      into the accumulation path instead of cloning them element-by-element
  - attempted in:
    - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/src/ecdsa/ot_based_ecdsa/triples/generation.rs`
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: `40.689-41.023 ms`, with Criterion reporting a
      statistically significant improvement in the `~2.6% to ~5.1%` range
    - `presign_protocol_roundtrip`: `40.356-40.659 ms`, with Criterion
      reporting change within the noise threshold
    - `presign_before_start`: `39.940-40.156 ms`, with Criterion reporting
      change within the noise threshold
  - wasm:
    - `sign_non_export_wasm`: `119.73 ms -> 119.685 ms`
    - `sign_presign_roundtrip_wasm`: `~118 ms -> ~117 ms`
    - `sign_total_core_wasm`: `~120 ms -> ~119 ms`
- conclusion:
  - this clone cut is too small for the current wasm-focused optimization goal
  - it slightly improved native full-sign and nudged wasm in the right
    direction, but it did not materially move the actual wasm hotspot
  - the next candidate should target fixed-size 2-party collection handling or
    transcript/proof setup churn rather than another narrow clone-only cut

### Entry 12: Fixed-Size 2-Party Receive Gathering Fast Path

- date: 2026-04-09
- change:
  - attempted a fixed-size 2-party cleanup in the shared protocol helper by
    special-casing `recv_from_others(...)` for `participants.len() == 2` in:
    - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/src/protocol/helpers.rs`
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: `41.635-42.202 ms`, with Criterion reporting a
      statistically significant regression in the `~1.6% to ~3.3%` range
    - `presign_protocol_roundtrip`: `41.193-41.644 ms`, with Criterion
      reporting a statistically significant regression in the `~1.7% to ~3.5%`
      range
    - `presign_before_start`: `40.984-41.481 ms`, with Criterion reporting a
      statistically significant regression in the `~2.4% to ~4.5%` range
  - wasm:
    - `sign_non_export_wasm`: `119.73 ms -> 120.985 ms`
    - `sign_presign_roundtrip_wasm`: `~118 ms -> ~119 ms`
    - `sign_total_core_wasm`: `~120 ms -> ~121 ms`
- conclusion:
  - helper-level 2-party specialization in the shared receive path made the
    real hotspot worse
  - the next useful candidate should move away from receive-helper shaping and
    toward transcript/proof setup churn or a more targeted triples-internal
    specialization

### Entry 13: Pre-Forked Transcript Reuse In Upstream Triples Proof Setup

- date: 2026-04-09
- change:
  - attempted to reduce transcript/proof setup churn in upstream
    `do_generation_many::<2>` by pre-forking per-label participant transcripts
    once and cloning those forked transcripts inside the proof loops
  - attempted in:
    - `~/.cargo/git/checkouts/threshold-signatures-947608b8269c8901/db609be/src/ecdsa/ot_based_ecdsa/triples/generation.rs`
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: `41.658-42.854 ms`, with Criterion reporting no
      statistically significant change
    - `presign_protocol_roundtrip`: `40.843-41.417 ms`, with Criterion
      reporting change within the noise threshold
    - `presign_before_start`: `40.890-41.331 ms`, with Criterion reporting no
      statistically significant change
  - wasm:
    - `sign_non_export_wasm`: `119.73 ms -> 121.329 ms`
    - `sign_presign_roundtrip_wasm`: `~118 ms -> ~120.5 ms`
    - `sign_total_core_wasm`: `~120 ms -> ~121.5 ms`
- conclusion:
  - transcript pre-fork reuse is not a meaningful win for the current wasm
    hotspot and in practice regressed the wasm sign path
  - there is no evidence that repeated transcript `fork(...)` setup is the
    dominant remaining cost
  - the next step should either be a much more targeted triples-internal
    specialization or to stop the pass rather than keep chasing backend
    micro-cuts

### Entry 14: Owned-Message Same-Process Presign Driver Path

- date: 2026-04-09
- change:
  - attempted a deeper same-process driver refactor by adding an owned-message
    delivery path in:
    - [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
    - [crates/router-ab-ecdsa-derivation/src/integration/mod.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/src/integration/mod.rs)
  - the goal was to move outgoing `Vec<u8>` protocol payloads directly between
    the two local presign sessions without cloning them back through `&[u8]`
- commands:
  - `cargo test --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml`
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline -- 'sign_bridge_full|presign_protocol_roundtrip|presign_before_start'`
  - `pnpm benchmark:router-ab-ecdsa-derivation:wasm`
- result:
  - rejected and reverted
- measured outcome before revert:
  - native:
    - `sign_bridge_full`: `41.875-42.572 ms`, with Criterion reporting no
      statistically significant change
    - `presign_protocol_roundtrip`: `40.350-41.091 ms`, with Criterion
      reporting no statistically significant change
    - `presign_before_start`: `40.028-40.116 ms`, with Criterion reporting a
      statistically significant improvement in the `~2.1% to ~3.2%` range
  - wasm:
    - `sign_non_export_wasm`: `119.73 ms -> 123.628 ms`
    - `sign_presign_roundtrip_wasm`: `~118 ms -> ~122 ms`
    - `sign_total_core_wasm`: `~120 ms -> ~123 ms`
- conclusion:
  - moving owned message buffers directly between the two local sessions does
    not translate into a real end-to-end win
  - it helped one native pre-start bucket but materially regressed the wasm
    sign path, so it is not acceptable under the current `opt-level = "z"`
    wasm target
  - after this deeper-driver rejection, the remaining optimization space looks
    increasingly high-risk for limited likely payoff

### Entry 15: Role-Local Router A/B ECDSA derivation Boundary Snapshot

- date: 2026-05-20
- change:
  - replaced joined-root derivation with role-local client and relayer share
    derivation
  - updated the native benchmark suite to measure the active role-local API
    shape
  - recorded crate-local logical request/response and retained-state byte-size
    estimates from `role_local_v1`
- command:
  - `cargo bench --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --bench performance_baseline`
- result:
  - accepted
- native means:
  - `context_binding`: `668.03 ns`
  - `client_share`: `33.785 us`
  - `relayer_share_and_identity`: `63.104 us`
  - `bootstrap_adapter`: `215.38 us`
  - `first_presign_roundtrip`: `39.272 ms`
  - `sign_bridge_full`: `39.736 ms`
  - `explicit_export`: `354.66 us`
- logical byte-size estimates:
  - threshold request: `60 bytes`
  - prepare non-export request: `201 bytes`
  - bootstrap non-export response: `127 bytes`
  - bootstrap explicit-export response: `159 bytes`
  - retained server state: `183 bytes`
  - retained client role share: `310 bytes`
- conclusion:
  - role-local derivation keeps setup and export work sub-millisecond
  - the signing hot path remains about `40 ms`
  - current role-local WASM latency and bundle size still need a refreshed
    `wasm/eth_signer` benchmark runner

