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
