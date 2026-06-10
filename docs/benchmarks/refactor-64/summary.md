# Refactor 64 HSS Runtime Benchmark Notes

Date: June 8, 2026

## Experiment: A2B Destination Reuse

Candidate:

- Reuse discarded SHA-512 round-state slots as destinations for
  `new_a_bits` and `new_e_bits`.
- Preserve existing A2B child labels, provenance inputs, commitments, and gate
  schedule.

Outcome:

- Rejected. The native release benchmark showed a median win, but the
  browser/WASM registration smoke did not improve the HSS worker path.
- No code from this candidate is retained.

Raw native benchmark files:

- `docs/benchmarks/refactor-64/ddh-hidden-eval-baseline.json`
- `docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-destination-reuse.json`
- `docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-destination-reuse-repeat.json`

Validation run while the candidate was applied:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`
- `pnpm -C sdk type-check`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`

## Native Hidden-Eval Comparison

Baseline:

- Command: `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 8`
- Output: `docs/benchmarks/refactor-64/ddh-hidden-eval-baseline.json`

Candidate repeat:

- Command: `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 16`
- Output: `docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-destination-reuse-repeat.json`

| Bucket              | Before p50 (ms) | After p50 (ms) | p50 delta | Before p95 (ms) | After p95 (ms) | p95 delta |
| ------------------- | --------------: | -------------: | --------: | --------------: | -------------: | --------: |
| `total_hidden_eval` |         225.886 |        215.406 |    -4.64% |         228.610 |        233.822 |    +2.28% |
| `round_core`        |         135.558 |        129.326 |    -4.60% |         136.588 |        144.567 |    +5.84% |
| `round_new_a_bits`  |          32.864 |         31.331 |    -4.67% |          33.613 |         33.693 |    +0.24% |
| `round_new_e_bits`  |          32.897 |         31.533 |    -4.15% |          33.119 |         37.659 |   +13.71% |
| `round_maj`         |          27.062 |         25.738 |    -4.89% |          27.263 |         27.557 |    +1.08% |
| `round_ch`          |          22.050 |         21.088 |    -4.36% |          22.205 |         24.289 |    +9.39% |

Native interpretation:

- The candidate likely reduced allocator/object churn in native release p50.
- It did not produce a clean p95 improvement.

## Browser/WASM Smoke Comparison

Baseline run: `20260607-152114Z`

Candidate smoke run: `20260607-171754Z`

| Scenario                                  | HSS eval p50 before | HSS eval p50 after | HSS eval p95 before | HSS eval p95 after | Round core p50 before | Round core p50 after |
| ----------------------------------------- | ------------------: | -----------------: | ------------------: | -----------------: | --------------------: | -------------------: |
| `passkey_ed25519_only_wallet_iframe`      |               631ms |              648ms |               634ms |              669ms |                 296ms |                303ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` |               646ms |              648ms |               649ms |              650ms |                 301ms |                302ms |
| `passkey_ed25519_only_host_origin`        |               644ms |              656ms |               658ms |              674ms |                 301ms |                302ms |
| `passkey_ed25519_and_ecdsa_host_origin`   |               647ms |              653ms |               654ms |              663ms |                 301ms |                304ms |

Browser/WASM interpretation:

- The destination-reuse patch did not move `hiddenEvalRoundNewABitsMs` or
  `hiddenEvalRoundNewEBitsMs` at the smoke-run resolution.
- `hiddenEvalTotalMs` and `hiddenEvalRoundCoreMs` were flat to slightly worse.
- Further work should measure allocation/object construction directly before
  another local scratch-reuse patch.

## Direct Ed25519 HSS WASM Artifact Baseline

Benchmark:

- Command: `pnpm benchmark:ed25519-hss:wasm`
- Run ID: `2026-06-08T01-36-06-388Z`
- Local output: `benchmarks/ed25519-hss-wasm/out/2026-06-08T01-36-06-388Z/summary.md`
- Scope: direct WASM exports for the Ed25519 HSS client-owned staged evaluator
  artifact path

| Path                                         |  Wall p50 |  Wall p95 | Hidden eval p50 | Round core p50 | Output projector p50 |
| -------------------------------------------- | --------: | --------: | --------------: | -------------: | -------------------: |
| `node_client_artifact_serialized_state_wasm` | 764.857ms | 767.512ms |       639.320ms |      295.063ms |            279.851ms |
| `node_client_artifact_worker_handle_wasm`    | 690.641ms | 713.274ms |       653.588ms |      302.380ms |            288.159ms |
| `browser_client_artifact_worker_handle_wasm` | 339.650ms | 342.400ms |       326.400ms |      187.250ms |             78.450ms |

Selected sub-buckets:

| Path                                         | `new_a_bits` p50 | `new_e_bits` p50 | `ch` p50 | `maj` p50 | Message schedule p50 |
| -------------------------------------------- | ---------------: | ---------------: | -------: | --------: | -------------------: |
| `node_client_artifact_worker_handle_wasm`    |         45.723ms |         45.849ms | 31.374ms |  38.007ms |             58.219ms |
| `browser_client_artifact_worker_handle_wasm` |         43.950ms |         43.800ms | 30.050ms |  36.750ms |             55.400ms |

Interpretation:

- The Node worker-handle path lines up with the full registration smoke order of
  magnitude and gives a faster loop for candidate testing.
- The Chromium direct-artifact path is much faster than the full wallet-iframe
  registration smoke. Use it as a lower-bound artifact benchmark, then confirm
  promising changes with `benchmark:registration-flow:smoke`.
- `new_a_bits`, `new_e_bits`, `ch`, `maj`, and message schedule medians are
  similar between Node and browser. `hiddenEvalOutputProjectorMs` is the largest
  browser-vs-Node split in this run.

## Direct Ed25519 HSS Logical Counter Smoke

Benchmark:

- Command: `node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --warmup 0 --iterations 1 --browser-warmup 0 --browser-iterations 1`
- Run ID: `2026-06-08T01-58-13-255Z`
- Local output: `benchmarks/ed25519-hss-wasm/out/2026-06-08T01-58-13-255Z/summary.md`
- Scope: direct WASM exports for the Ed25519 HSS client-owned staged evaluator
  artifact path after adding logical hidden-eval object counters

Smoke timings:

| Path                                         |  Wall p50 | Hidden eval p50 | Round core p50 | Output projector p50 |
| -------------------------------------------- | --------: | --------------: | -------------: | -------------------: |
| `node_client_artifact_serialized_state_wasm` | 752.964ms |       626.613ms |      291.839ms |            271.711ms |
| `node_client_artifact_worker_handle_wasm`    | 673.365ms |       637.631ms |      294.181ms |            279.821ms |
| `browser_client_artifact_worker_handle_wasm` | 355.400ms |       332.400ms |      188.500ms |             80.400ms |

Logical object counters:

| Counter                                               | Count |
| ----------------------------------------------------- | ----: |
| `hiddenEvalLogicalLocalWordMaterializations`          | 12800 |
| `hiddenEvalLogicalSharedWordMaterializations`         |  1024 |
| `hiddenEvalLogicalTransportWordMaterializations`      |  1536 |
| `hiddenEvalLogicalCommitmentMaterializations`         | 17928 |
| `hiddenEvalLogicalProvenanceDigestMaterializations`   | 15360 |
| `hiddenEvalLogicalCommitmentDerivations`              |  2048 |
| `hiddenEvalLogicalProvenanceDigestDerivations`        | 13824 |
| `hiddenEvalLogicalLabelWrites`                        | 57128 |
| `hiddenEvalLogicalLabelFormatAllocations`             |   265 |

Interpretation:

- The counters are deterministic across Node and Chromium in this smoke run,
  which makes them useful as regression guards for representation changes.
- These are logical materialization counts derived from public stage shapes and
  output vectors. They are not allocator-byte measurements.
- The counter baseline supports the next representation-audit question: which
  commitment, provenance, and label materializations are production-critical,
  validation-only, or diagnostics-only.

## Direct Ed25519 HSS Production No-Checkpoint Smoke

Candidate:

- Keep checkpoint digests on trace, continuation, and validation APIs.
- Route the client-owned artifact builder through a one-shot production helper
  that returns only `DdhHiddenEvalRun` plus `DdhHiddenEvalStageProfile`.
- Preserve commitments, provenance digests, output bundles, and run bindings.

Benchmark:

- Command: `node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --warmup 0 --iterations 1 --browser-warmup 0 --browser-iterations 1`
- Run ID: `2026-06-08T02-11-25-255Z`
- Local output: `benchmarks/ed25519-hss-wasm/out/2026-06-08T02-11-25-255Z/summary.md`

| Path                                         |  Wall p50 | Hidden eval p50 | Round core p50 | Output projector p50 |
| -------------------------------------------- | --------: | --------------: | -------------: | -------------------: |
| `node_client_artifact_serialized_state_wasm` | 762.818ms |       637.025ms |      295.658ms |            277.883ms |
| `node_client_artifact_worker_handle_wasm`    | 685.641ms |       648.085ms |      298.954ms |            285.711ms |
| `browser_client_artifact_worker_handle_wasm` | 350.700ms |       327.600ms |      187.300ms |             78.800ms |

Interpretation:

- This is a clean production/validation separation, but it is not a proven
  latency win from the one-iteration smoke.
- The browser direct-artifact path was slightly faster than the previous
  one-iteration logical-counter smoke; Node paths were flat to worse.
- Keep only with protocol tests passing, and use later multi-iteration runs for
  performance claims.

## Registration Flow Smoke With Respond Route Diagnostics

Benchmark:

- Command: `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Run ID: `20260608-030241Z`
- Local output:
  `benchmarks/registration-flow/out/20260608-030241Z/summary.md`
- Docs mirror: `docs/benchmarks/registration-flow.md`
- Scope: full registration product flow after wiring
  `wallets_register_hss_respond` diagnostics through the server response and
  SDK timing sanitizer

| Scenario | SDK p50 | Browser p50 | Client artifact p50 | Start route p50 | HSS respond route p50 | Finalize route p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 2557ms | 3935ms | 668ms | 373ms | 93ms | 455ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 2433ms | 3739ms | 678ms | 383ms | 106ms | 462ms |
| `passkey_ed25519_only_host_origin` | 2432ms | 3315ms | 679ms | 375ms | 94ms | 459ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 2473ms | 3363ms | 674ms | 376ms | 106ms | 457ms |

Selected route sub-buckets:

| Bucket | p50 range |
| --- | ---: |
| `registrationHssPrepareMs` | 372ms-381ms |
| `registrationHssRespondPrepareDeliveryMs` | 73ms-74ms |
| `registrationHssRespondEncodeDeliveryMs` | 5ms-6ms |
| `registrationHssFinalizeSerializedSessionMaterializeMs` | 241ms-244ms |
| `registrationHssFinalizeReportMs` | 4ms-5ms |
| `registrationHssFinalizeEncodeReportMs` | 3ms-4ms |

Interpretation:

- The respond route is now visible and accounts for only about 93ms-106ms p50
  server-side.
- Finalize remains expensive because `registrationHssFinalizeMs` is about
  453ms-460ms p50, with serialized server-session materialization alone at
  241ms-244ms p50.
- The client-owned artifact remains the largest single SDK bucket at
  668ms-679ms p50.
- The next useful optimization targets are client artifact representation,
  server HSS prepare, and finalize serialized server-session materialization.

## Registration Flow Smoke With Finalize Cached-Session Fast Path

Candidate:

- When finalize receives a staged evaluator artifact as bytes, reuse the cached
  prepared server session if the prepared-session handle is still live.
- Fall back to decoding and materializing `ServerDriverState` from serialized
  bytes when the prepared-session cache entry is gone.
- Preserve the same finalization report, output messages, and serialized-state
  fallback behavior.

Benchmark:

- Command: `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Baseline run ID: `20260608-030241Z`
- Candidate run ID: `20260608-051326Z`
- Local output:
  `benchmarks/registration-flow/out/20260608-051326Z/summary.md`
- Docs mirror: `docs/benchmarks/registration-flow.md`

| Scenario | SDK p50 before | SDK p50 after | Finalize route p50 before | Finalize route p50 after | Serialized session materialize p50 before | Serialized session materialize p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 2557ms | 2239ms | 455ms | 222ms | 241ms | 0ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 2433ms | 2167ms | 462ms | 218ms | 244ms | 0ms |
| `passkey_ed25519_only_host_origin` | 2432ms | 1972ms | 459ms | 218ms | 242ms | 0ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 2473ms | 1989ms | 457ms | 216ms | 241ms | 0ms |

Interpretation:

- Keep. The candidate removes the serialized server-session materialization from
  the normal product finalize path.
- `registrationHssFinalizeSerializedSessionMaterializeMs` fell from about
  241ms-244ms p50 to `0ms` p50 in all smoke scenarios.
- SDK registration p50 improved by 266ms-484ms.
- The remaining HSS bottlenecks are client artifact construction and server HSS
  prepare.

## Registration Flow Smoke With Start Branch Diagnostics

Benchmark:

- Command: `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Run ID: `20260608-053047Z`
- Local output:
  `benchmarks/registration-flow/out/20260608-053047Z/summary.md`
- Scope: full registration product flow after adding start-route branch
  diagnostics for signing-root server-input derivation and server-session
  preparation

| Scenario | Start route p50 | HSS prepare p50 | Server-input derive p50 | Server-session prepare p50 | Prepare session core p50 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 371ms | 370ms | 366ms | 356ms | 354ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 373ms | 371ms | 367ms | 357ms | 356ms |
| `passkey_ed25519_only_host_origin` | 373ms | 372ms | 368ms | 359ms | 357ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 373ms | 371ms | 367ms | 358ms | 356ms |

Interpretation:

- Start remains about 371ms-373ms p50 because two expensive branches run in
  parallel.
- Signing-root server-input derivation is about 366ms-368ms p50.
- Server-session preparation is about 356ms-359ms p50.
- Inside server-session preparation, `prepare_prime_order_succinct_hss` accounts
  for almost all measured time; driver-state extraction, client offer creation,
  caching, and state encoding are each single-digit milliseconds.
- The next start-route work must address threshold-PRF server-input derivation,
  HSS session preparation itself, or move one/both branches off the post-auth
  critical path.

## Direct Ed25519 HSS Output-Projector Sub-Buckets

Benchmark:

- Command:
  `pnpm -C sdk build:wasm && node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --warmup 1 --iterations 4 --browser-warmup 1 --browser-iterations 2`
- Run ID: `2026-06-08T06-47-28-133Z`
- Local output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T06-47-28-133Z/summary.md`
- Scope: direct WASM artifact benchmark after adding output-projector
  sub-bucket instrumentation

Selected p50 buckets:

| Path | Wall p50 | Hidden eval p50 | Output projector p50 | Core p50 | Mask add p50 | Client output p50 | Tau double p50 | Relayer output p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 763.722ms | 630.937ms | 272.041ms | 37.723ms | 57.778ms | 57.696ms | 57.800ms | 57.855ms |
| `node_client_artifact_worker_handle_wasm` | 695.211ms | 658.556ms | 292.192ms | 39.794ms | 61.105ms | 60.915ms | 61.439ms | 60.861ms |
| `browser_client_artifact_worker_handle_wasm` | 335.000ms | 322.050ms | 77.650ms | 38.450ms | 7.850ms | 7.850ms | 7.850ms | 7.850ms |

Interpretation:

- The masked output-projector path was spending four modular additions after
  reduction: `a + tau`, `(a + tau) + mask`, `tau + tau`, and
  `a + (tau + tau)`.
- The direct Node worker-handle path showed roughly 244ms p50 in those four
  additions; the browser lower-bound path showed roughly 31ms p50.
- This made the output projector a good candidate for a semantics-preserving
  algebra cleanup before deeper representation work.

## Direct Ed25519 HSS Shared Client-Base Candidate

Candidate:

- Compute `client_base = a + tau` once in the output projector.
- In client-masked mode, compute `client_output = client_base + mask` and
  `x_relayer_base = client_base + tau`.
- Remove the separate `mask + tau` and `tau + tau` intermediates.
- Keep projection-mode branching public, fixed-width loop bounds, output
  labels, commitments, and bundle labels.

Benchmark:

- Command:
  `pnpm -C sdk build:wasm && node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --warmup 1 --iterations 4 --browser-warmup 1 --browser-iterations 2`
- Baseline run ID: `2026-06-08T06-47-28-133Z`
- Candidate run ID: `2026-06-08T06-53-24-480Z`
- Local output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T06-53-24-480Z/summary.md`

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Output projector p50 before | Output projector p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 763.722ms | 703.604ms | 630.937ms | 577.723ms | 272.041ms | 219.694ms |
| `node_client_artifact_worker_handle_wasm` | 695.211ms | 624.634ms | 658.556ms | 588.499ms | 292.192ms | 228.596ms |
| `browser_client_artifact_worker_handle_wasm` | 335.000ms | 329.050ms | 322.050ms | 315.900ms | 77.650ms | 69.900ms |

Validation:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --test mod protocol_validation`

Interpretation:

- Keep. The direct artifact benchmark shows a clear client-artifact win,
  especially on the Node worker-handle path used for fast candidate iteration.
- The candidate removes two modular additions from the masked output-projector
  path. Product registration still spends most time in hidden-eval round core,
  server-input derivation, and HSS prepare.
- Constant-time review: no new secret-dependent branch, index, allocation size,
  or loop bound was introduced. The only branch remains the public client
  output projection mode.

## Registration Flow Smoke With Shared Client-Base Candidate

Benchmark:

- Command:
  `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Baseline run ID: `20260608-053047Z`
- Candidate run ID: `20260608-065437Z`
- Local output:
  `benchmarks/registration-flow/out/20260608-065437Z/summary.md`
- Docs mirror: `docs/benchmarks/registration-flow.md`

| Scenario | SDK p50 before | SDK p50 after | Browser p50 before | Browser p50 after | Client artifact p50 before | Client artifact p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 2112ms | 2060ms | 3210ms | 3166ms | 668ms | 624ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 2134ms | 2103ms | 3228ms | 3207ms | 673ms | 627ms |
| `passkey_ed25519_only_host_origin` | 1933ms | 1842ms | 2816ms | 2730ms | 666ms | 617ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 1958ms | 1871ms | 2845ms | 2761ms | 668ms | 617ms |

Interpretation:

- Keep. All four smoke scenarios passed, and the targeted client artifact
  bucket improved by 44ms-51ms p50.
- Product total p50 improved by 31ms-91ms SDK-side and 21ms-116ms
  browser-observed, with normal benchmark noise still visible in auth and
  start-route buckets.
- Output projector p50 in the product worker diagnostics is now roughly
  217ms-221ms, down from roughly 267ms-273ms in the previous retained run.

## Direct Ed25519 HSS Mixed Shared-Mask Candidate

Candidate:

- Keep `client_base = a + tau` from the retained shared client-base candidate.
- In client-masked mode, compute `client_output = client_base + mask` directly
  from the shared mask bits.
- Avoid materializing the shared mask as a split local word before the modular
  addition.
- Keep projection-mode branching public, fixed-width loop bounds, output
  labels, commitments, and bundle labels.

Benchmark:

- Command:
  `pnpm -C sdk build:wasm && node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --warmup 1 --iterations 4 --browser-warmup 1 --browser-iterations 2`
- Baseline run ID: `2026-06-08T06-53-24-480Z`
- Candidate run ID: `2026-06-08T09-19-30-202Z`
- Local output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T09-19-30-202Z/summary.md`

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Output projector p50 before | Output projector p50 after | Output-projector local words before | Output-projector local words after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 703.604ms | 654.719ms | 577.723ms | 527.669ms | 219.694ms | 170.220ms | 3072 | 2560 |
| `node_client_artifact_worker_handle_wasm` | 624.634ms | 573.910ms | 588.499ms | 537.080ms | 228.596ms | 176.670ms | 3072 | 2560 |
| `browser_client_artifact_worker_handle_wasm` | 329.050ms | 329.450ms | 315.900ms | 316.600ms | 69.900ms | 70.500ms | 3072 | 2560 |

Interpretation:

- Keep, pending the registration-flow smoke confirmation below. The direct Node
  paths improve by about 49ms-51ms wall p50 and about 50ms-51ms hidden-eval p50.
- The direct browser lower-bound path is effectively flat, which means this is
  primarily a Node/WASM worker-handle and product-worker win.
- The materialization counter moves in the intended direction: masked
  output-projector local-word materializations fall from `3072` to `2560`.
- Constant-time review: the new loop iterates over public fixed-width mask bits
  and validates public word widths. It introduces no secret-dependent branch,
  index, allocation size, or loop bound.

Validation:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --test mod hidden_eval_equivalence`
- `cargo check --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`

## Registration Flow Smoke With Mixed Shared-Mask Candidate

Benchmark:

- Command:
  `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang pnpm benchmark:registration-flow:smoke`
- Baseline run ID: `20260608-065437Z`
- Candidate run ID: `20260608-092157Z`
- Local output:
  `benchmarks/registration-flow/out/20260608-092157Z/summary.md`
- Docs mirror: `docs/benchmarks/registration-flow.md`

| Scenario | SDK p50 before | SDK p50 after | Browser p50 before | Browser p50 after | Client artifact p50 before | Client artifact p50 after | Output projector p50 before | Output projector p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 2060ms | 1997ms | 3166ms | 3334ms | 624ms | 573ms | 217ms | 169ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 2103ms | 2036ms | 3207ms | 3115ms | 627ms | 569ms | 217ms | 168ms |
| `passkey_ed25519_only_host_origin` | 1842ms | 1717ms | 2730ms | 2594ms | 617ms | 563ms | 220ms | 170ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 1871ms | 1750ms | 2761ms | 2635ms | 617ms | 563ms | 221ms | 170ms |

Interpretation:

- Keep. All four smoke scenarios passed, and the targeted client artifact
  bucket improved by 51ms-58ms p50.
- Product output-projector p50 improved by 48ms-51ms, matching the direct
  Node/WASM signal.
- SDK total p50 improved by 63ms-125ms. Browser-observed totals improved in
  three scenarios and regressed in the first wallet-iframe scenario, so browser
  total should still be treated as noisy auth/setup timing rather than the
  primary keep signal for this narrow HSS executor change.
- The next worthwhile HSS executor step is a packed or arena-backed
  representation candidate gated by the byte-equivalence harness.

## Native Hidden-Eval Allocation Probe

Benchmark:

- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval_alloc -- --samples 5 --warmup 1 --output docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json`
- Output:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json`
- Scope: native release allocation-counting probe for the prepared-session
  path, direct hidden-eval profiling path, hidden-output materialization, and
  same-process delivery path

Selected medians:

| Operation | Allocated bytes | Allocation calls | Peak live above start |
| --- | ---: | ---: | ---: |
| `prepare_prime_order_succinct_hss` | 4,593,083 | 17,409 | 2,071,815 |
| `profile_hidden_eval_for_clear_input` | 12,282,621 | 45,859 | 1,443,232 |
| `materialize_hidden_outputs_for_debug` | 235,690 | 27 | 204,970 |
| `evaluate_for_clear_input_debug_timed` | 14,940,254 | 48,630 | 2,285,531 |

Interpretation:

- Packed/arena work is justified. Hidden-eval still allocates about `12.3MB`
  and performs about `45.9k` allocation calls per profiled native release
  execution.
- Materializing hidden outputs is small compared with hidden-eval itself.
- The first representation candidate should target internal local bit-side
  storage in `hidden_eval_executor`: keep packed share bits, but reduce repeated
  allocation of commitment and provenance side vectors in fixed-width hot
  helpers.

## Rejected Packed Local Metadata Candidate

Candidate:

- Replace parallel commitment/provenance vectors in `LocalBitWordSide` with a
  single packed metadata vector.
- Keep protocol structs, wire structs, labels, commitments, provenance bytes,
  and backend version unchanged.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-packed-metadata.json`
- Candidate direct WASM run ID: `2026-06-08T12-24-44-719Z`
- Candidate direct WASM output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T12-24-44-719Z/summary.md`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 12,282,621 | 12,276,093 | 45,859 | 45,025 |
| `evaluate_for_clear_input_debug_timed` | 14,940,254 | 14,933,726 | 48,630 | 47,796 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 654.719ms | 650.252ms | 527.669ms | 528.635ms | 295.633ms | 292.677ms |
| `node_client_artifact_worker_handle_wasm` | 573.910ms | 572.709ms | 537.080ms | 537.530ms | 298.745ms | 294.829ms |
| `browser_client_artifact_worker_handle_wasm` | 329.450ms | 335.000ms | 316.600ms | 321.900ms | 186.950ms | 192.600ms |

Outcome:

- Rejected. Allocation calls improved by only about `1.8%`, allocated bytes
  barely moved, and the direct browser artifact path regressed by about
  `5ms-6ms`.
- The next representation candidate needs a real scratch/arena lifetime change
  that avoids temporary side-vector allocation, not just a narrower metadata
  container.

## Rejected Round-State Scratch Reuse Candidate

Candidate:

- Add an `into` variant for arithmetic-to-Boolean conversion.
- Reuse the two SHA-512 round-state buffers displaced by each state rotation as
  the next round's `new_a` and `new_e` output buffers.
- Keep protocol structs, wire structs, labels, commitments, provenance bytes,
  and backend version unchanged.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-state-scratch.json`
- Candidate direct WASM run ID: `2026-06-08T12-48-31-686Z`
- Candidate direct WASM output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T12-48-31-686Z/summary.md`
- Candidate registration-flow smoke run ID: `20260608-125008Z`
- Candidate registration-flow output:
  `benchmarks/registration-flow/out/20260608-125008Z/summary.md`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 12,282,621 | 10,985,757 | 45,859 | 44,911 |
| `evaluate_for_clear_input_debug_timed` | 14,940,254 | 13,643,390 | 48,630 | 47,682 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 654.719ms | 655.154ms | 527.669ms | 529.882ms | 295.633ms | 297.739ms |
| `node_client_artifact_worker_handle_wasm` | 573.910ms | 577.042ms | 537.080ms | 541.559ms | 298.745ms | 301.776ms |
| `browser_client_artifact_worker_handle_wasm` | 329.450ms | 324.400ms | 316.600ms | 311.550ms | 186.950ms | 184.650ms |

Registration-flow smoke result:

| Scenario | Client artifact p50 before | Client artifact p50 after | SDK p50 before | SDK p50 after | Browser p50 before | Browser p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 573ms | 576ms | 1997ms | 2032ms | 3334ms | 3127ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 569ms | 573ms | 2036ms | 2054ms | 3115ms | 3149ms |
| `passkey_ed25519_only_host_origin` | 563ms | 565ms | 1717ms | 1907ms | 2594ms | 2618ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 563ms | 566ms | 1750ms | 1768ms | 2635ms | 2657ms |

Outcome:

- Rejected for latency. The native allocation reduction was real, but the
  product client artifact bucket regressed by `2ms-4ms` p50 across all four
  smoke scenarios.
- The direct browser artifact path improved by about `5ms`, while both Node
  direct paths regressed slightly. The mixed signal is not enough to retain a
  code change whose product bucket does not improve.
- The next candidate should avoid moving owned state words through extra
  `mem::replace` traffic and instead reduce object construction in the
  arithmetic kernels or switch to a representation with fewer owned side
  vectors.

## Retained Extra-Material Iterator Candidate

Candidate:

- Replace the per-call `Vec<&[u8]>` material buffer in
  `split_local_bit_pair_to_arithmetic_word_pair_naive` with a direct iterator
  over the same provenance and commitment slices.
- Add an internal `build_local_word_pair_public_from_extra_material` helper so
  callers can stream extra material without allocating a temporary vector.
- Keep digest domains, labels, material ordering, commitments, provenance
  bytes, protocol structs, wire structs, and backend version unchanged.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-extra-material-iter.json`
- Candidate direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Candidate direct WASM output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T13-21-25-923Z/summary.md`
- Candidate registration-flow smoke run ID: `20260608-132219Z`
- Candidate registration-flow output:
  `benchmarks/registration-flow/out/20260608-132219Z/summary.md`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 12,282,621 | 7,695,101 | 45,859 | 44,963 |
| `evaluate_for_clear_input_debug_timed` | 14,940,254 | 10,352,734 | 48,630 | 47,734 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 654.719ms | 653.739ms | 527.669ms | 528.559ms | 295.633ms | 294.879ms |
| `node_client_artifact_worker_handle_wasm` | 573.910ms | 571.721ms | 537.080ms | 536.132ms | 298.745ms | 298.554ms |
| `browser_client_artifact_worker_handle_wasm` | 329.450ms | 324.600ms | 316.600ms | 311.550ms | 186.950ms | 184.700ms |

Registration-flow smoke result:

| Scenario | Client artifact p50 before | Client artifact p50 after | SDK p50 before | SDK p50 after | Browser p50 before | Browser p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 573ms | 570ms | 1997ms | 1985ms | 3334ms | 3336ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 569ms | 568ms | 2036ms | 2036ms | 3115ms | 3366ms |
| `passkey_ed25519_only_host_origin` | 563ms | 561ms | 1717ms | 1721ms | 2594ms | 2603ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 563ms | 558ms | 1750ms | 1744ms | 2635ms | 2624ms |

Outcome:

- Kept. The product client-artifact bucket improved by `1ms-5ms` p50 across all
  four smoke scenarios.
- Native allocation dropped by about `4.59MB` per profiled hidden-eval run while
  preserving byte-equivalence.
- Browser-observed total remains noisy because auth/setup timing dominates the
  full flow. The targeted HSS client artifact bucket is the keep signal for
  this narrow executor change.

## Rejected Fused Output Canonicalization Candidate

Candidate:

- Fuse `canonicalize_hidden_bit_output_words` so it constructs canonical output
  words directly from `SplitLocalBitWord` sides instead of first materializing a
  temporary shared-bit vector.
- Keep output commitments and provenance semantics unchanged.

Benchmarks:

- Baseline for this comparison:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-extra-material-iter.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-output-canonicalize-fused.json`
- Baseline direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Candidate direct WASM run ID: `2026-06-08T13-34-44-648Z`
- Candidate direct WASM output:
  `benchmarks/ed25519-hss-wasm/out/2026-06-08T13-34-44-648Z/summary.md`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 7,695,101 | 7,572,221 | 44,963 | 44,959 |
| `evaluate_for_clear_input_debug_timed` | 10,352,734 | 10,229,854 | 47,734 | 47,730 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 653.739ms | 682.092ms | 528.559ms | 553.144ms | 294.879ms | 306.696ms |
| `node_client_artifact_worker_handle_wasm` | 571.721ms | 580.508ms | 536.132ms | 544.202ms | 298.554ms | 301.885ms |
| `browser_client_artifact_worker_handle_wasm` | 324.600ms | 323.700ms | 311.550ms | 310.900ms | 184.700ms | 184.150ms |

Outcome:

- Rejected. The allocation reduction was only about `123KB` and `4` allocation
  calls per hidden-eval profile, while Node direct artifact latency regressed.
- The next candidate should target a larger allocation source or a path that
  improves both Node and browser direct artifact timings.

## Cumulative Checkpoint Allocation Probe

Benchmark:

- Command:
  `cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval_alloc -- --samples 5 --warmup 1 --output docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-checkpoints.json`
- Output:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-checkpoints.json`
- Baseline: retained extra-material iterator candidate

Cumulative medians:

| Checkpoint | Allocated bytes | Allocation calls | Incremental bytes | Incremental calls |
| --- | ---: | ---: | ---: | ---: |
| `input_sharing` | 394,456 | 2,076 | 394,456 | 2,076 |
| `add_stage` | 440,939 | 2,595 | 46,483 | 519 |
| `message_schedule` | 2,200,491 | 4,551 | 1,759,552 | 1,956 |
| `round_core` | 3,770,745 | 8,039 | 1,570,254 | 3,488 |
| `output_projector` | 7,695,101 | 44,963 | 3,924,356 | 36,924 |

Interpretation:

- The output-projector stage is the largest remaining allocation source after
  the retained extra-material iterator change.
- Message schedule and round core still allocate meaningful bytes, but their
  allocation-call counts are much smaller than output projection.
- Future allocation experiments should report both direct artifact latency and
  product registration smoke before being retained.

## Rejected Output-Projector Label-Reuse Candidate

Candidate:

- Reuse `String` buffers in output-projector modular subtraction/select loops.
- Remove duplicate `false_*` vectors in `select_local_bit_words`.
- Preserve label bytes, branch conditions, fixed-width loop bounds,
  commitments, provenance bytes, protocol structs, wire structs, and backend
  version.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-checkpoints.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-output-label-reuse.json`
- Baseline direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Candidate direct WASM run ID: `2026-06-08T13-52-54-926Z`
- Candidate registration-flow smoke run ID: `20260608-135345Z`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 7,695,101 | 6,419,990 | 44,963 | 15,003 |
| `evaluate_for_clear_input_debug_timed` | 10,352,734 | 9,077,623 | 47,734 | 17,774 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Output projector p50 before | Output projector p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 653.739ms | 644.950ms | 528.559ms | 518.804ms | 169.979ms | 166.892ms |
| `node_client_artifact_worker_handle_wasm` | 571.721ms | 570.104ms | 536.132ms | 533.834ms | 175.074ms | 174.356ms |
| `browser_client_artifact_worker_handle_wasm` | 324.600ms | 322.850ms | 311.550ms | 309.850ms | 68.100ms | 68.000ms |

Registration-flow smoke result:

| Scenario | Client artifact p50 before | Client artifact p50 after | Worker p50 before | Worker p50 after | Hidden eval p50 before | Hidden eval p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 570ms | 574ms | 570ms | 570ms | 526ms | 527ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 568ms | 567ms | 568ms | 566ms | 525ms | 523ms |
| `passkey_ed25519_only_host_origin` | 561ms | 585ms | 559ms | 583ms | 523ms | 545ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 558ms | 582ms | 557ms | 579ms | 520ms | 542ms |

Outcome:

- Rejected. The allocation drop was real and direct artifact timings improved,
  but the product registration smoke regressed the host-origin client artifact
  bucket by `22ms-24ms` p50.
- No code from this candidate is retained. The allocation-probe checkpoint
  instrumentation is retained because it is diagnostics-only.

## Rejected Output-Projector Select-Stream Candidate

Candidate:

- Stream `select_local_bit_words` through a repeated-selector raw multiplication
  helper instead of allocating cloned selector vectors and a separate gated
  delta output vector.
- Preserve multiplication labels as `{label}/bit/{idx}` and selected XOR labels
  as `{label}/selected/{idx}`.
- Preserve public fixed-width loop bounds, commitments, provenance digests,
  protocol structs, wire structs, and backend version.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-extra-material-iter.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-select-stream.json`
- Baseline direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Candidate direct WASM run ID: `2026-06-08T14-38-26-384Z`
- Candidate registration-flow smoke run ID: `20260608-143926Z`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 7,695,101 | 6,658,481 | 44,963 | 39,863 |
| `evaluate_for_clear_input_debug_timed` | 10,352,734 | 9,316,114 | 47,734 | 42,634 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 653.739ms | 618.379ms | 528.559ms | 497.402ms | 294.879ms | 279.577ms |
| `node_client_artifact_worker_handle_wasm` | 571.721ms | 546.493ms | 536.132ms | 512.242ms | 298.554ms | 288.143ms |
| `browser_client_artifact_worker_handle_wasm` | 324.600ms | 314.250ms | 311.550ms | 301.650ms | 184.700ms | 181.150ms |

Registration-flow smoke result:

| Scenario | Client artifact p50 before | Client artifact p50 after | Worker p50 before | Worker p50 after | Hidden eval p50 before | Hidden eval p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 570ms | 587ms | 570ms | 585ms | 526ms | 538ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 568ms | 598ms | 568ms | 594ms | 525ms | 546ms |
| `passkey_ed25519_only_host_origin` | 561ms | 587ms | 559ms | 583ms | 523ms | 546ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 558ms | 573ms | 557ms | 569ms | 520ms | 532ms |

Outcome:

- Rejected. Native allocation and direct artifact timings improved, but the
  product registration smoke regressed client artifact p50 by `15ms-30ms`
  across all scenarios.
- No code from this candidate is retained.

## Rejected A2B Output Recycling Candidate

Candidate:

- Add an A2B `_into` helper for round-core `new_a_bits` and `new_e_bits`.
- Recycle the SHA-512 state words displaced during round-state rotation as the
  next round's A2B output buffers.
- Preserve A2B child labels, carry-gadget labels, provenance inputs,
  commitments, protocol structs, wire structs, and backend version.

Benchmarks:

- Baseline allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-extra-material-iter.json`
- Candidate allocation probe:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-a2b-output-recycle.json`
- Baseline direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Candidate direct WASM run ID: `2026-06-08T14-47-37-017Z`

Allocation result:

| Operation | Allocated bytes before | Allocated bytes after | Allocation calls before | Allocation calls after |
| --- | ---: | ---: | ---: | ---: |
| `profile_hidden_eval_for_clear_input` | 7,695,101 | 6,398,237 | 44,963 | 44,015 |
| `evaluate_for_clear_input_debug_timed` | 10,352,734 | 9,055,870 | 47,734 | 46,786 |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 653.739ms | 670.966ms | 528.559ms | 543.907ms | 294.879ms | 299.419ms |
| `node_client_artifact_worker_handle_wasm` | 571.721ms | 589.144ms | 536.132ms | 552.428ms | 298.554ms | 307.500ms |
| `browser_client_artifact_worker_handle_wasm` | 324.600ms | 327.200ms | 311.550ms | 314.250ms | 184.700ms | 186.150ms |

Outcome:

- Rejected before product smoke. The native allocation-byte reduction was real,
  but direct artifact latency regressed on Node and browser.
- No code from this candidate is retained.

## Retained Local Multiplication Provenance-Fold Candidate

Candidate:

- Compute local multiplication-material `triple-a`, `triple-b`, and `triple-c`
  provenance digests once per gate instead of once per side.
- Compute raw local multiplication output-pair provenance once when left and
  right outputs use identical provenance inputs.
- Preserve label bytes, provenance inputs, commitments, protocol structs, wire
  structs, fixed public loop bounds, and backend version.
- Logical hidden-eval counters stay unchanged because the transcript shape is
  unchanged; this candidate reduces physical hash work.

Benchmarks:

- Native CPU sample:
  `docs/benchmarks/refactor-64/profiles/ddh-hidden-eval-native-sample.txt`
- Native baseline:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-native-sample-report.json`
- First-fold native candidate:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-local-mul-material-provenance-once.json`
- Combined native candidate:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-local-mul-provenance-folds.json`
- Baseline direct WASM run ID: `2026-06-08T13-21-25-923Z`
- Combined direct WASM run ID: `2026-06-09T14-04-45-320Z`
- Combined registration-flow smoke run ID: `20260609-140541Z`

Native hidden-eval result:

| Bucket | Baseline p50 | First fold p50 | Combined p50 |
| --- | ---: | ---: | ---: |
| `total_hidden_eval` | 218.663ms | 195.181ms | 189.487ms |
| `round_core` | 132.136ms | 116.578ms | 112.497ms |
| `message_schedule` | 39.653ms | 36.585ms | 35.244ms |
| `output_projector` | 42.089ms | 37.449ms | 37.351ms |
| `delivery_total` | 258.719ms | 235.456ms | 229.660ms |

Direct artifact result:

| Path | Wall p50 before | Wall p50 after | Hidden eval p50 before | Hidden eval p50 after | Round core p50 before | Round core p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 653.739ms | 607.865ms | 528.559ms | 483.519ms | 294.879ms | 264.962ms |
| `node_client_artifact_worker_handle_wasm` | 571.721ms | 528.232ms | 536.132ms | 492.469ms | 298.554ms | 268.718ms |
| `browser_client_artifact_worker_handle_wasm` | 324.600ms | 288.250ms | 311.550ms | 275.250ms | 184.700ms | 159.650ms |

Registration-flow smoke result:

| Scenario | Client artifact p50 before | Client artifact p50 after | Worker p50 before | Worker p50 after | Hidden eval p50 before | Hidden eval p50 after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 570ms | 538ms | 570ms | 533ms | 526ms | 489ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 568ms | 540ms | 568ms | 537ms | 525ms | 493ms |
| `passkey_ed25519_only_host_origin` | 561ms | 527ms | 559ms | 524ms | 523ms | 487ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 558ms | 527ms | 557ms | 526ms | 520ms | 489ms |

Outcome:

- Retained. Byte-equivalence passed, native p50 improved by `29.176ms`,
  direct browser worker artifact p50 improved by `36.350ms`, and product
  client-artifact p50 improved by `28ms-34ms` across the four smoke scenarios.
- CPU attribution now points the next search toward remaining physical
  hash/provenance reductions before a broader output-projector or A2B
  representation rewrite.

## Retained Raw Batch Multiplication Output Provenance-Fold Candidate

Candidate:

- Fold the raw batch multiplication output-pair provenance derivation so each
  left/right output pair derives one shared provenance digest.
- Preserve the existing `eval-mul-local` domain, label bytes, width, zero
  left/right digest words, material digest, `d_open`, `e_open`, commitments,
  protocol structs, wire structs, fixed public loop bounds, and backend version.
- Logical hidden-eval counters stay unchanged because the transcript shape is
  unchanged; this candidate reduces physical hash work in the batch path.

Benchmarks:

- Native candidate:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-local-mul-batch-output-provenance-fold.json`
- Direct WASM candidate run ID: `2026-06-09T14-19-03-120Z`
- Registration-flow smoke run ID: `20260609-141952Z`

Native hidden-eval result:

| Bucket | Previous retained p50 | Batch fold p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 189.487ms | 185.329ms |
| `round_core` | 112.497ms | 109.710ms |
| `message_schedule` | 35.244ms | 34.546ms |
| `output_projector` | 37.351ms | 36.790ms |

Direct artifact result:

| Path | Previous retained wall p50 | Batch fold wall p50 | Previous hidden eval p50 | Batch fold hidden eval p50 | Previous round core p50 | Batch fold round core p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 607.865ms | 600.249ms | 483.519ms | 474.873ms | 264.962ms | 257.669ms |
| `node_client_artifact_worker_handle_wasm` | 528.232ms | 529.447ms | 492.469ms | 493.849ms | 268.718ms | 268.368ms |
| `browser_client_artifact_worker_handle_wasm` | 288.250ms | 285.200ms | 275.250ms | 272.300ms | 159.650ms | 157.350ms |

Registration-flow smoke result:

| Scenario | Previous client artifact p50 | Batch fold client artifact p50 | Previous worker p50 | Batch fold worker p50 | Previous hidden eval p50 | Batch fold hidden eval p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 538ms | 531ms | 533ms | 528ms | 489ms | 484ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 540ms | 530ms | 537ms | 527ms | 493ms | 484ms |
| `passkey_ed25519_only_host_origin` | 527ms | 517ms | 524ms | 517ms | 487ms | 481ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 527ms | 521ms | 526ms | 520ms | 489ms | 484ms |

Outcome:

- Retained. Byte-equivalence passed, native p50 improved by another `4.158ms`,
  direct browser worker artifact p50 improved by `3.050ms`, and product
  client-artifact p50 improved by `6ms-10ms` across the four smoke scenarios.
- The remaining obvious duplicate hash/provenance opportunities are now
  smaller; add physical hash-invocation counters before the next candidate if
  code inspection does not identify a clearly byte-identical fold.

## Physical Hash Counter Probe

Candidate:

- Add a diagnostic `hss-physical-counters` crate feature.
- Count physical BLAKE3 families during hidden-eval execution:
  keyed digest derivations, derived-owner commitment hashes, add-bit hashes,
  multiplication-material hashes, and multiplication output-seed hashes.
- Keep counters out of default builds; counter-enabled latency is diagnostic
  only because the atomic increments add overhead.

Benchmark:

- Command:
  `cargo run --release --features hss-physical-counters --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 1 --output docs/benchmarks/refactor-64/ddh-hidden-eval-physical-hash-counters.json`
- Output:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-physical-hash-counters.json`

Counter result:

| Counter | Count |
| --- | ---: |
| `physical_keyed_digest_derivations` | 344,846 |
| `physical_derived_commitment_hashes` | 584,220 |
| `physical_add_bit_hashes` | 0 |
| `physical_mul_material_hashes` | 31,232 |
| `physical_mul_output_seed_hashes` | 0 |

Interpretation:

- Physical hash work is dominated by derived-owner commitment hashes and keyed
  digest derivations.
- Logical counters remain useful for transcript shape, but they no longer
  predict physical hash volume after byte-identical hash folds.
- The next keyed-digest optimization should add domain breakdown first; a broad
  keyed-digest change is too coarse to evaluate safely.

## Physical Keyed-Digest Domain Counter Probe

Candidate:

- Extend the diagnostic `hss-physical-counters` feature with fixed keyed-digest
  domain counters.
- Count the major `derive_digest_for_key` domain families during one profiled
  hidden-eval execution.
- Keep the counters out of default builds; the atomic increments are diagnostic
  overhead.

Benchmark:

- Command:
  `cargo run --release --features hss-physical-counters --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 1 --output docs/benchmarks/refactor-64/ddh-hidden-eval-keyed-domain-counters.json`
- Output:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-keyed-domain-counters.json`

Counter result:

| Counter | Count |
| --- | ---: |
| `physical_keyed_digest_derivations` | 344,846 |
| `physical_keyed_digest_eval_xor_local_word` | 164,286 |
| `physical_keyed_digest_eval_add_local` | 14,064 |
| `physical_keyed_digest_eval_mul_local_material` | 93,696 |
| `physical_keyed_digest_eval_mul_local` | 43,008 |
| `physical_keyed_digest_phase_a_arith_share_to_bool` | 28,672 |
| `physical_keyed_digest_phase_a_bool_to_arith_base` | 896 |
| `physical_keyed_digest_phase_a_arith_to_bool_zero` | 224 |
| `physical_keyed_digest_compose_word_from_share_bits` | 0 |
| `physical_keyed_digest_share_word` | 0 |
| `physical_keyed_digest_other` | 0 |

Interpretation:

- All keyed digest derivations were classified; `other=0`.
- `eval_xor_local_word` is the largest keyed-digest family and should be the
  next keyed-digest audit target.
- `eval_mul_local_material` and `eval_mul_local` remain worth checking for
  further byte-identical folds after the previous multiplication provenance
  folds.
- Broad prefix-hasher work is not justified by itself after the
  derived-commitment prefix-hasher regression.

Follow-up audit:

- `xor_local_word_pairs_public` already folds paired left/right provenance into
  one keyed digest.
- Single-side raw XOR helpers use side-specific labels in current transcript
  bytes. Folding those paths would require a backend-versioned protocol change.
- No immediate byte-identical `eval_xor_local_word` quick fold is retained from
  this audit.

## Physical Derived-Commitment Domain Counter Probe

Candidate:

- Extend the diagnostic `hss-physical-counters` feature with fixed
  derived-commitment domain counters.
- Tag known local-word commitment builders with their public provenance domain.
- Keep the default `commit_word` path available and count uncategorized derived
  commitments under `other`.

Benchmark:

- Command:
  `cargo run --release --features hss-physical-counters --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 1 --output docs/benchmarks/refactor-64/ddh-hidden-eval-derived-commitment-domain-counters.json`
- Output:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-derived-commitment-domain-counters.json`

Counter result:

| Counter | Count |
| --- | ---: |
| `physical_derived_commitment_hashes` | 584,220 |
| `physical_derived_commitment_eval_xor_local_word` | 275,324 |
| `physical_derived_commitment_eval_add_local` | 28,128 |
| `physical_derived_commitment_eval_mul_local_material` | 187,392 |
| `physical_derived_commitment_eval_mul_local` | 62,464 |
| `physical_derived_commitment_phase_a_arith_share_to_bool` | 28,672 |
| `physical_derived_commitment_phase_a_bool_to_arith_base` | 1,792 |
| `physical_derived_commitment_phase_a_arith_to_bool_zero` | 448 |
| `physical_derived_commitment_compose_word_from_share_bits` | 0 |
| `physical_derived_commitment_share_word` | 0 |
| `physical_derived_commitment_other` | 0 |

Interpretation:

- All derived commitment hashes were classified; `other=0`.
- `eval_xor_local_word` is the largest commitment domain, but the immediate
  XOR quick-fold audit already found no byte-identical fold under the current
  backend version.
- `eval_mul_local_material` and `eval_mul_local` are the next narrow audit
  targets before moving to a broader arena-backed representation.

Follow-up audit:

- The retained multiplication provenance folds already derive shared left/right
  provenance once for multiplication material and output pairs.
- The remaining multiplication commitments use distinct side labels and word
  bytes, so there is no byte-identical commitment fold left under the current
  transcript.
- Further reduction in this family should come from representation-level
  deferred/materialized commitments, or from a deliberate backend-versioned
  protocol change.

## Retained Carry-Core Local Adder Candidate

Candidate:

- Keep local adder carry-chain intermediates as no-commitment share/provenance
  cores.
- Compute local multiplication material cores directly for carry-gate outputs.
- Materialize commitments only for values that leave the carry-only path, such
  as `sum`, `xor_ab`, `a_xor_carry`, output bundles, and multiplication inputs.
- Preserve labels, provenance inputs, commitments at materialization points,
  protocol structs, wire structs, fixed public loop bounds, and backend version.

Benchmarks:

- Native physical counter run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-carry-core-physical-counters.json`
- Native hidden-eval run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-carry-core-native.json`
- Direct WASM run ID: `2026-06-09T16-10-54-140Z`
- Registration-flow smoke run ID: `20260609-161140Z`

Physical counter result:

| Counter | Previous | Carry-core |
| --- | ---: | ---: |
| `physical_keyed_digest_derivations` | 344,846 | 320,270 |
| `physical_keyed_digest_eval_add_local` | 14,064 | 5,872 |
| `physical_keyed_digest_eval_mul_local_material` | 93,696 | 81,408 |
| `physical_keyed_digest_eval_mul_local` | 43,008 | 38,912 |
| `physical_derived_commitment_hashes` | 584,220 | 537,116 |
| `physical_derived_commitment_eval_add_local` | 28,128 | 11,744 |
| `physical_derived_commitment_eval_mul_local_material` | 187,392 | 162,816 |
| `physical_derived_commitment_eval_mul_local` | 62,464 | 59,392 |

Native hidden-eval result:

| Bucket | Previous retained p50 | Carry-core p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 185.329ms | 176.690ms |
| `round_core` | 109.710ms | 110.680ms |
| `message_schedule` | 34.546ms | 35.602ms |
| `output_projector` | 36.790ms | 26.857ms |

Direct artifact result:

| Path | Previous retained wall p50 | Carry-core wall p50 | Previous hidden eval p50 | Carry-core hidden eval p50 | Previous round core p50 | Carry-core round core p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 600.249ms | 589.036ms | 474.873ms | 465.129ms | 257.669ms | 260.753ms |
| `node_client_artifact_worker_handle_wasm` | 529.447ms | 516.769ms | 493.849ms | 480.108ms | 268.368ms | 269.239ms |
| `browser_client_artifact_worker_handle_wasm` | 285.200ms | 263.500ms | 272.300ms | 250.750ms | 157.350ms | 154.850ms |

Registration-flow smoke result:

| Scenario | Previous client artifact p50 | Carry-core client artifact p50 | Previous worker p50 | Carry-core worker p50 | Previous hidden eval p50 | Carry-core hidden eval p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 531ms | 517ms | 528ms | 513ms | 484ms | 469ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 530ms | 518ms | 527ms | 515ms | 484ms | 472ms |
| `passkey_ed25519_only_host_origin` | 517ms | 519ms | 517ms | 513ms | 481ms | 476ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 521ms | 507ms | 520ms | 508ms | 484ms | 471ms |

Outcome:

- Retained. Byte-equivalence passed, native hidden-eval p50 improved by
  `8.639ms`, direct browser worker artifact p50 improved by `21.700ms`, and
  product client-artifact p50 improved in three of four scenarios while the
  remaining host-origin Ed25519-only scenario was effectively flat.
- This is the first retained representation-level commitment materialization
  candidate. Further core/deferred-commitment work should be limited to paths
  where the caller can prove commitments are not consumed before the next
  materialization boundary.

## Retained A2B Source/Carry-Core Candidate

Candidate:

- Keep cross-share A2B source bit words as no-commitment share/provenance
  cores.
- Keep A2B carry-gate and next-carry intermediates as share/provenance cores.
- Materialize `xor_ab`, `sum`, and `a_xor_carry` because `xor_ab` and
  `a_xor_carry` feed multiplication commitments, and `sum` leaves the
  conversion.
- Preserve labels, provenance inputs, emitted commitments, protocol structs,
  wire structs, fixed public loop bounds, and backend version.

Benchmarks:

- Native physical counter run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-core-physical-counters.json`
- Native hidden-eval run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-core-native.json`
- Direct WASM run ID: `2026-06-09T16-27-57-114Z`
- Registration-flow smoke run ID: `20260609-162843Z`

Physical counter result:

| Counter | Carry-core | A2B core |
| --- | ---: | ---: |
| `physical_keyed_digest_derivations` | 320,270 | 277,262 |
| `physical_keyed_digest_eval_mul_local_material` | 81,408 | 38,400 |
| `physical_keyed_digest_eval_mul_local` | 38,912 | 38,912 |
| `physical_keyed_digest_phase_a_arith_share_to_bool` | 28,672 | 28,672 |
| `physical_derived_commitment_hashes` | 537,116 | 365,084 |
| `physical_derived_commitment_eval_xor_local_word` | 272,252 | 243,580 |
| `physical_derived_commitment_eval_mul_local_material` | 162,816 | 76,800 |
| `physical_derived_commitment_eval_mul_local` | 59,392 | 30,720 |
| `physical_derived_commitment_phase_a_arith_share_to_bool` | 28,672 | 0 |

Native hidden-eval result:

| Bucket | Carry-core p50 | A2B core p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 176.690ms | 144.601ms |
| `round_core` | 110.680ms | 87.942ms |
| `message_schedule` | 35.602ms | 26.448ms |
| `output_projector` | 26.857ms | 26.469ms |

Direct artifact result:

| Path | Carry-core wall p50 | A2B core wall p50 | Carry-core hidden eval p50 | A2B core hidden eval p50 | Carry-core round core p50 | A2B core round core p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 589.036ms | 544.354ms | 465.129ms | 422.228ms | 260.753ms | 231.277ms |
| `node_client_artifact_worker_handle_wasm` | 516.769ms | 472.168ms | 480.108ms | 436.696ms | 269.239ms | 239.052ms |
| `browser_client_artifact_worker_handle_wasm` | 263.500ms | 223.000ms | 250.750ms | 210.450ms | 154.850ms | 125.750ms |

Registration-flow smoke result:

| Scenario | Carry-core client artifact p50 | A2B core client artifact p50 | Carry-core worker p50 | A2B core worker p50 | Carry-core hidden eval p50 | A2B core hidden eval p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 517ms | 477ms | 513ms | 460ms | 469ms | 425ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 518ms | 474ms | 515ms | 470ms | 472ms | 427ms |
| `passkey_ed25519_only_host_origin` | 519ms | 466ms | 513ms | 466ms | 476ms | 430ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 507ms | 466ms | 508ms | 467ms | 471ms | 430ms |

Outcome:

- Retained. Byte-equivalence passed, counter-enabled equivalence passed,
  native hidden-eval p50 improved by `32.089ms`, direct browser worker
  artifact p50 improved by `40.500ms`, and product client-artifact p50
  improved by `40ms-53ms` across the four smoke scenarios.
- This is the second retained deferred-commitment representation candidate.
  The next candidate should extend the same proof discipline to a larger
  stage-owned representation or to output projection.

## Retained Output-Boundary Paired Transport Materialization Candidate

Candidate:

- Build the left and right `x_relayer_base` transport bundles from one
  canonical output word list and one bundle commitment.
- Preserve emitted transport bundle bytes, labels, owner, side tags,
  commitments, protocol structs, wire structs, fixed public loop bounds, and
  backend version.
- Keep canonicalization and bundle commitment work at the output boundary, then
  project the already-canonical words into the two side-specific transport
  bundles.

Benchmarks:

- Native hidden-eval run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-output-transport-pair-native.json`
- Direct WASM run ID: `2026-06-09T16-43-10-136Z`
- Registration-flow smoke run ID: `20260609-164356Z`

Native hidden-eval result:

| Bucket | A2B core p50 | Paired transport p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 144.601ms | 138.394ms |
| `round_core` | 87.942ms | 84.740ms |
| `message_schedule` | 26.448ms | 25.528ms |
| `output_projector` | 26.469ms | 24.878ms |

Direct artifact result:

| Path | A2B core wall p50 | Paired transport wall p50 | A2B core hidden eval p50 | Paired transport hidden eval p50 | A2B core output projector p50 | Paired transport output projector p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `node_client_artifact_serialized_state_wasm` | 544.354ms | 542.139ms | 422.228ms | 420.589ms | 148.771ms | 146.153ms |
| `node_client_artifact_worker_handle_wasm` | 472.168ms | 459.469ms | 436.696ms | 424.758ms | 154.993ms | 148.823ms |
| `browser_client_artifact_worker_handle_wasm` | 223.000ms | 215.650ms | 210.450ms | 203.250ms | 44.750ms | 41.900ms |

Registration-flow smoke result:

| Scenario | A2B core client artifact p50 | Paired transport client artifact p50 | A2B core worker p50 | Paired transport worker p50 | A2B core hidden eval p50 | Paired transport hidden eval p50 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `passkey_ed25519_only_wallet_iframe` | 477ms | 467ms | 460ms | 463ms | 425ms | 420ms |
| `passkey_ed25519_and_ecdsa_wallet_iframe` | 474ms | 466ms | 470ms | 461ms | 427ms | 419ms |
| `passkey_ed25519_only_host_origin` | 466ms | 455ms | 466ms | 459ms | 430ms | 422ms |
| `passkey_ed25519_and_ecdsa_host_origin` | 466ms | 455ms | 467ms | 460ms | 430ms | 423ms |

Outcome:

- Retained. Byte-equivalence passed, native hidden-eval p50 improved by
  `6.207ms`, direct browser worker artifact p50 improved by `7.350ms`, and
  product client-artifact p50 improved by `8ms-11ms` across the four smoke
  scenarios.
- Product worker p50 improved in three scenarios and regressed by `3ms` in the
  first wallet-iframe scenario. The keep signal is the consistent
  client-artifact and hidden-eval improvement across all scenarios.
- Constant-time review: the candidate introduces no new secret-dependent
  branch, index, allocation size, or loop bound. The only branch inside bundle
  projection is the public `DdhHssShareSide` selection used to emit the left
  and right transport bundles.

## Rejected E2 Core-Input Bridge Candidate

Candidate:

- Add core-only conversions for local, shared, and transport bit-word inputs.
- Feed fixed-width adder `xor_ab` through existing core-input helpers where the
  input commitment is carried only as unused local-word metadata.
- Preserve `xor_ab`, `sum`, and `a_xor_carry` materialization boundaries,
  emitted commitments, labels, protocol structs, wire structs, fixed public
  loop bounds, and backend version.

Benchmark:

- Native hidden-eval run:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-core-input-bridge-native.json`

Native hidden-eval result:

| Bucket | Paired transport p50 | Core-input bridge p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 138.394ms | 140.966ms |
| `round_core` | 84.740ms | 86.277ms |
| `message_schedule` | 25.528ms | 26.015ms |
| `output_projector` | 24.878ms | 25.195ms |

Outcome:

- Rejected before direct WASM and product smoke. The native benchmark regressed
  the targeted executor p50 by `2.572ms`.
- The code slice was reverted. The design lesson is that a tiny core-input
  bridge that only avoids temporary local-word structs is too small; the next
  arena attempt needs a larger `CoreBitWordSide` representation or a different
  critical-path target.

## Rejected Derived Commitment Prefix-Hasher Candidate

Candidate:

- Reuse a preinitialized BLAKE3 hasher containing only the
  `derived-commitment/v0` domain prefix.
- Preserve the exact commitment transcript order:
  domain, side label, word bytes, provenance digest.

Benchmark:

- Native candidate:
  `docs/benchmarks/refactor-64/ddh-hidden-eval-derived-commitment-prefix-hasher.json`

Native hidden-eval result:

| Bucket | Previous retained p50 | Prefix-hasher p50 |
| --- | ---: | ---: |
| `total_hidden_eval` | 185.329ms | 192.030ms |
| `round_core` | 109.710ms | 113.911ms |
| `message_schedule` | 34.546ms | 36.073ms |
| `output_projector` | 36.790ms | 38.214ms |

Outcome:

- Rejected. Byte-equivalence passed, but native hidden-eval p50 regressed by
  `6.701ms`.
- No code from this candidate is retained.
