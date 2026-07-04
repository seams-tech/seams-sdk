# HSS Protocol And Runtime Latency

Date created: June 8, 2026

Status: active; output projector client-base, mixed shared-mask, staged output
boundary, repeated-selector select batch, carry-core, A2B source/carry-core,
output-boundary paired transport candidates, and Phase 7I clamped scalar
reduction retained; A2B v2 committed-root carry material and the v3 `Maj`
pair-XOR provenance fold retained; v4 `Ch` gated-select root retained; direct
WASM artifact benchmark, logical object counters, server ceremony sub-bucket
timings, wallet-iframe transport timing, and physical hash/domain counters
added.

Experiment ledger: `crates/ed25519-hss/docs/optimization-experiment-ledger.md`
is the canonical index of retained, rejected, and instrumentation-only
optimization experiments. Check it before retrying a current-backend micro-edit,
output-projector rewrite, A2B/B2A protocol root, multiplication-material root,
or arena representation change.

June 10 update: the backend-versioned semantic output-projector root
rewrite was implemented and rejected. Product smoke regressed to
`503-519ms` artifact p50, and the main regression came from losing the retained
mixed shared-mask path. After restoring that path, smoke `20260610-154615Z`
returned to baseline/noise at `468/470/467/466ms`; masked client-output p50 is
back to `4ms`. The retained source state keeps only the product-neutral
`output_projector_binding_v1` scaffold as protocol hardening and future-version
plumbing; continue latency work with A2B v2 or critical-path overlap.

June 11 update: A2B v2 committed-root carry material is implemented as the live
candidate under `ddh_hss_backend_v2_a2b_committed_root`. The first SHA-256
per-bit carry-material attempt regressed, but the BLAKE3-base version improved
native hidden-eval p50 from the scaffold baseline `126.177ms` to `118.436ms`.
Direct browser/WASM also moved in the same direction: `browser_ddh_mean_ns` is
`170.5ms` versus the typed-backend reference `200.867ms`. Product registration
smoke `20260610-170749Z` passed all four scenarios and moved
`ed25519EvaluationArtifactMs` p50 to `445/445/443/443ms`, improving over the
output-projector scaffold smoke `468/470/467/466ms` and staying effectively
flat against the stronger retained Phase 7I smoke `450/445/443/442ms`.
Stale-backend boundary hardening now rejects old backend wire strings while
deserializing serialized client/server driver states and staged artifacts. The
legacy backend and A2B kernel enum variants were deleted, so stale material
cannot become internal state. A2B carry-gate hardening also rejects wrong-index
carry material before multiplication. Remaining finalization work is the last
retained/rejected decision pass.

June 11 B2A-root update: the first B2A-only core-sigma root experiment was
implemented under temporary backend string `ddh_hss_backend_v3_b2a_root` and
rejected. It improved targeted B2A physical counters from `896` keyed digests /
`1792` derived commitments to `768` / `1536`, but native hidden-eval p50 stayed
around `124.2-124.6ms`, above the retained A2B v2 best `118.436ms`. The code
path was reverted to `ddh_hss_backend_v2_a2b_committed_root`; benchmark outputs
remain under `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/`.
The restored-backend benchmark reference-matched at `124.5294375ms`, confirming
the B2A-root run was noise-band rather than a retained p50 win.
The next HSS-runtime design target is a multiplication/XOR commitment-root
shape because the dominant physical-counter buckets are
`eval_xor_local_word` and `eval_mul_local_material`, while B2A base material is
small in comparison.

June 11 `Maj` pair-XOR update: a cheaper transient `Maj` fold is retained under
`ddh_hss_backend_v3_a2b_maj_pair_xor`. It reduces keyed digest derivations by
`10,240`, all from `eval_xor_local_word`, while leaving derived commitments
flat. Native total hidden-eval p50 is `118.248ms`, improving over the latest
reverted baseline `124.529ms` and matching the previous best retained A2B
BLAKE3-base run.

June 11 `Ch` gated-select update: the root-bound `Ch` helper is retained under
`ddh_hss_backend_v4_ch_gated_select_root`. It keeps final `choose` outputs
committed, removes transient committed `yz` material and materialized
gated-product commitments, and derives select multiplication material from a
`Ch` root-base digest. Physical counters moved materially, native total
hidden-eval p50 improved from `118.248ms` to `108.737ms`, direct browser/WASM
moved from `172.800ms` to `168.567ms`, and product smoke `20260611-041314Z`
passed all four scenarios with `ed25519EvaluationArtifactMs` p50
`430/431/422/420ms`.

June 11 local-add carry-root update: the proposed v5 carry-root helper was
implemented experimentally and rejected. It kept emitted `sum` bits committed
and removed transient `a_xor_carry` commitments, reducing physical derived
commitments from `195,972` to `192,900` while leaving keyed digests flat at
`222,402`. The latency result did not justify the added root-material hashing:
native p50 stayed in the `108.432-110.754ms` noise band against retained v4
`108.737ms`, and the trimmed browser/WASM run regressed to `171.600ms` versus
retained v4 `168.567ms`. Source is restored to the retained v4 backend; the
v5 benchmark JSONs remain under
`crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-6/` as rejection
evidence.

## Goal

Make Ed25519 HSS registration fast enough that choosing HSS is primarily a
trust-model decision, not a latency compromise.

The near-term target is to cut HSS critical-path runtime significantly while
preserving protocol correctness, transcript binding, provenance where required,
and constant-time behavior. The longer-term target is to make HSS viable on
browser, native, iOS, and selected embedded runtimes.

This plan follows Path A: preserve the current HSS trust model. Exportability
and threshold-at-registration are requirements. Do not replace HSS with a flow
where the client creates the full Ed25519 seed, computes the full scalar, and
then splits or seals a server component. That path preserves exportability, but
it collapses the threshold property at registration because the client
temporarily knows the full export seed and signing scalar.

## Relationship To Existing Plans

- `docs/refactor-55-hss-optimize-registration.md` owns the registration-specific
  HSS optimization history and current Phase E1 A2B/boolean-helper spec.
- `docs/refactor-59-optimize.md` owns full registration benchmarking and the
  measured `1500ms` registration target gap.
- `docs/refactor-65-hss-optional.md` owns optional bootstrap profiles for
  runtimes where HSS should not be mandatory.
- This plan owns deeper HSS protocol/runtime performance work.

Historical `ed25519-hss` optimization notes:

- `crates/ed25519-hss/optimization.md` is the crate-level optimization
  entrypoint and must be checked before adding new refactor-64 candidates.
- `crates/ed25519-hss/docs/plans/optimization-v3.md` records the durable kernel
  lesson: helper-level `Ch`/`Maj` rewrites at the old abstraction boundary were
  poor trades; the kept wins came from kernel shape, denser local storage, and
  fused local kernels.
- `crates/ed25519-hss/docs/plans/optimization-v4.md` records the accepted
  Worker-path and wasm-isolate wins: transport trimming, prepared-session reuse,
  constant-pool reuse, staged-artifact handles, direct same-process hidden eval,
  and pair-wise round-core boolean helpers.
- New refactor-64 work should avoid repeating route-envelope cleanup,
  helper-level boolean rewrites, native-only fast paths, or browser-only payload
  shaping. Treat packed/arena representation and fused local kernels as the
  next non-duplicative direction.

## Current Read

Latest retained registration benchmark:

- scenarios: four smoke scenarios, five successful runs each
- baseline before finalize cache fast path: `20260608-030241Z`
- latest retained run after finalize cache fast path: `20260608-051326Z`
- latest instrumentation run: `20260608-053047Z`
- latest output-projector client-base run: `20260608-065437Z`
- latest mixed shared-mask output-projector run: `20260608-092157Z`
- latest A2B source/carry-core run: `20260609-162843Z`
- latest output-boundary paired transport run: native
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-output-transport-pair-native.json`,
  direct WASM `2026-06-09T16-43-10-136Z`, product smoke `20260609-164356Z`
- latest direct HSS artifact baseline after returning from refactor-61/62:
  `2026-06-10T02-49-09-370Z`
- latest registration smoke with product-side wallet-iframe confirmation
  readiness timing: `20260610-024516Z`
- latest retained stage-owned `CoreBitWordSide` sigma slice: native
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-sigma-native.json`,
  allocation probe
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-sigma-alloc.json`,
  direct WASM `2026-06-10T03-08-25-774Z`, product smoke
  `20260610-030916Z`
- latest retained message-schedule small-sigma `CoreBitWordSide` slice:
  native
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-small-sigma-native.json`,
  direct WASM `2026-06-10T03-35-11-130Z`, product smoke
  `20260610-033610Z`
- latest retained finalize seed-output prepared-session cache path: product
  smoke `20260610-035655Z`
- latest retained respond-delivery one-pass server-input bundle path: native
  release
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-respond-one-pass-native-release.json`,
  product smoke `20260610-041350Z`
- latest retained prepared OT branch-cache path: native release
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-prepared-ot-branches-native-release.json`,
  repeat
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-prepared-ot-branches-native-release-repeat.json`,
  product smoke `20260610-043955Z`
- latest retained-source product smoke after reverting the rejected direct
  output canonicalization shortcut and fixing the SDK rebuild blocker:
  `20260610-093753Z`; all four scenarios passed with five successful runs each.
  `ed25519EvaluationArtifactMs` p50 is `482/491/484/478ms`, SDK p50 is
  `1698/1717/1342/1359ms`, and browser-observed p50 is
  `2599/2388/1730/1751ms`.
- latest retained Phase 7B staged output boundary:
  - native hidden eval:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7b-staged-output-native.json`
    with `total_hidden_eval` p50 `129.757ms`, `round_core` p50 `82.188ms`,
    `output_projector` p50 `23.463ms`, and `message_schedule` p50
    `20.228ms`.
  - direct HSS WASM artifact run `2026-06-10T09-58-26-689Z`: browser
    worker-handle wall p50 `205.8ms`, browser hidden eval p50 `193.45ms`,
    browser round core p50 `119.9ms`, browser output projector p50
    `41.15ms`, and Node worker-handle wall p50 `457.773ms`.
  - product smoke `20260610-095927Z`: all four scenarios passed with five
    successful runs each; `ed25519EvaluationArtifactMs` p50 improved from
    `482/491/484/478ms` to `463/467/459/457ms`, SDK p50 improved to
    `1633/1650/1273/1295ms`, and browser-observed p50 improved to
    `2248/2266/1651/1672ms`.
- latest retained Phase 7C repeated-selector select batch:
  - native hidden eval:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7c-repeated-selector-native.json`
    with `total_hidden_eval` p50 `128.910ms`, `round_core` p50 `81.547ms`,
    `output_projector` p50 `23.726ms`, and `message_schedule` p50
    `20.051ms`.
  - native allocation:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7c-repeated-selector-alloc.json`
    reports `profile_hidden_eval_for_clear_input` p50 at about `4.916MB`
    across `5,123` allocation calls.
  - direct HSS WASM artifact run `2026-06-10T10-08-53-023Z`: browser
    worker-handle wall p50 `205.75ms`, browser hidden eval p50 `193.35ms`,
    browser round core p50 `119.65ms`, browser output projector p50
    `41.65ms`, and Node worker-handle wall p50 `466.002ms`.
  - product smoke `20260610-100938Z`: all four scenarios passed with five
    successful runs each; `ed25519EvaluationArtifactMs` p50 moved from Phase
    7B `463/467/459/457ms` to `460/460/455/457ms`, SDK p50 is
    `1654/1670/1269/1283ms`, and HSS worker `buildArtifactMs` p50 is
    `454/453/456/458ms`.
- latest retained Phase 7D carry-gate material-base reuse:
  - native hidden eval:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-material-base-reuse-native.json`
    with `total_hidden_eval` p50 `127.882ms`, `round_core` p50 `81.233ms`,
    `output_projector` p50 `23.708ms`, and `message_schedule` p50
    `19.640ms`.
  - direct HSS WASM artifact run `2026-06-10T10-23-17-523Z`: browser
    worker-handle wall p50 `200.75ms`, browser hidden eval p50 `188.6ms`,
    browser round core p50 `116.7ms`, browser output projector p50 `41.0ms`,
    and Node worker-handle wall p50 `459.574ms`.
  - product smoke `20260610-102403Z`: all four scenarios passed with five
    successful runs each; `ed25519EvaluationArtifactMs` p50 moved from Phase
    7C `460/460/455/457ms` to `459/459/453/455ms`, SDK p50 is
    `1656/1657/1265/1285ms`, and HSS worker `buildArtifactMs` p50 is
    `452/452/451/455ms`.
- latest retained Phase 7E borrow-path material-base reuse:
  - native hidden eval:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-material-base-borrow-native.json`
    with `total_hidden_eval` p50 `126.459ms`, `round_core` p50 `80.039ms`,
    `output_projector` p50 `23.318ms`, and `message_schedule` p50
    `19.654ms`.
  - direct HSS WASM artifact run `2026-06-10T10-31-55-959Z`: browser
    worker-handle wall p50 `201.2ms`, browser hidden eval p50 `188.65ms`,
    browser round core p50 `117.45ms`, browser output projector p50
    `40.5ms`, and Node worker-handle wall p50 `462.582ms`.
  - first product smoke `20260610-103247Z` was mixed: artifact p50 improved in
    three scenarios and regressed in one, so it was repeated before retention.
  - product smoke repeat `20260610-103434Z`: all four scenarios passed with
    five successful runs each; `ed25519EvaluationArtifactMs` p50 moved from
    Phase 7D `459/459/453/455ms` to `450/451/447/447ms`, SDK p50 is
    `1598/1638/1250/1290ms`, and HSS worker `buildArtifactMs` p50 is
    `443/445/449/450ms`.
  - `cargo hss-fv verus-check` passed after fixing a stale anti-drift fixture
    path to the current `packages/sdk-web` layout: Verus `96` verified,
    `0` errors, anti-drift `10` passed.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
    `102` passed, `4` ignored.
- latest retained Phase 7I public-multiple clamped scalar reduction:
  - native allocation:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7i-clamped-multiple-alloc.json`
    reports `profile_hidden_eval_for_clear_input` p50 at `4.161MB` /
    `5,031` allocation calls versus Phase 7E `4.916MB` / `5,123` calls.
  - native hidden eval:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7i-clamped-multiple-native-repeat.json`
    with `total_hidden_eval` p50 `118.039ms`, `round_core` p50 `79.370ms`,
    `output_projector` p50 `16.151ms`, and `message_schedule` p50
    `19.118ms`; reference match is `true`.
  - direct HSS WASM artifact run `2026-06-10T11-19-11-795Z`: browser
    worker-handle wall p50 `187.9ms`, browser hidden eval p50 `175.75ms`,
    browser round core p50 `115.1ms`, browser output projector p50 `30.25ms`,
    and browser reduce-a p50 `7.5ms`.
  - product smoke `20260610-112012Z`: all four scenarios passed with five
    successful runs each; `ed25519EvaluationArtifactMs` p50 moved from Phase
    7E `450/451/447/447ms` to `450/445/443/442ms`, SDK p50 is
    `1610/1639/1241/1260ms`, and HSS worker `buildArtifactMs` p50 is
    `441/438/441/442ms`.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
    `103` passed, `4` ignored.
  - `cargo hss-fv verus-check` passed: Verus `96` verified, `0` errors,
    anti-drift `10` passed.
- latest registration smoke with wallet-iframe transport diagnostics:
  `20260610-130323Z`; all four passkey scenarios passed. Wallet-iframe
  transport connect p50 is `99ms` Ed25519-only and `115ms` combined, with one
  handshake attempt. This makes transport secondary for SDK p50: passkey prompt
  decision wait is `674ms` / `663ms`, credential creation is `203ms` / `202ms`,
  and `ed25519EvaluationArtifactMs` remains `496ms` / `489ms`. Host-origin
  artifact p50 is `478ms` / `480ms`, so HSS client artifact construction stays
  the shared Passkey/OTP optimization target.
- latest registration smoke with post-prompt derived buckets:
  `20260610-135445Z`; all four passkey scenarios passed. Wallet-iframe
  `sdkMinusPasskeyPromptDecisionWaitMs` p50 is `1028ms` Ed25519-only and
  `1060ms` combined, while `authProofMinusPasskeyPromptDecisionWaitMs` p50 is
  `203ms` in both wallet-iframe scenarios. Full wallet-iframe SDK p50 is
  `1663ms` / `1703ms`, so the remaining gap to the `1500ms` full-SDK target is
  mostly passkey prompt decision wait. HSS artifact p50 is still large enough to
  optimize for margin: `ed25519EvaluationArtifactMs` is `471ms` / `468ms` in
  wallet iframe and `462ms` / `463ms` in host-origin scenarios.
- latest retained Phase 7E allocation profile:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7e-retained-alloc.json`
  reports `profile_hidden_eval_for_clear_input` p50 at `4.916MB` across
  `5,123` allocation calls with `1.402MB` peak live above start. The output
  projector checkpoint is the same `4.916MB` / `5,123` calls; round core is
  `2.677MB` / `4,847` calls, and message schedule is `1.140MB` / `2,773`
  calls.
- latest rejected post-Phase 7E micro-experiments:
  - Phase 7F select scratch reduction:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7f-select-scratch-native.json`;
    `total_hidden_eval` p50 regressed from Phase 7E `126.459ms` to
    `134.289ms`, `round_core` regressed to `85.625ms`, and
    `output_projector` regressed to `24.483ms`. Code was reverted.
  - Phase 7G validated local-word accessor:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7g-validated-local-word-native.json`
    and repeat
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-phase7g-validated-local-word-native-repeat.json`;
    first run was flat-to-negative at `126.745ms` total, and repeat regressed
    to `130.339ms`. Code was reverted.
- latest rejected client-artifact micro-experiments after the prepared OT
  branch-cache win:
  - fused A2B pack/native:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-pack-fused-native.json`;
    `round_core` p50 regressed `81.068ms -> 87.614ms`, and
    `total_hidden_eval` p50 regressed `131.835ms -> 142.134ms`
  - round-constant arithmetic precompute/native:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-round-constant-arith-precompute-native.json`;
    `temp1` improved `4.205ms -> 3.564ms`, but `round_core` p50 regressed
    `81.068ms -> 83.754ms`, and `total_hidden_eval` p50 regressed
    `131.835ms -> 136.777ms`
  - A2B zero-core carry seed/native:
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-zero-core-native.json`;
    `round_new_a_bits` and `round_new_e_bits` both regressed, with
    `round_core` p50 `81.068ms -> 83.632ms` and `total_hidden_eval` p50
    `131.835ms -> 135.810ms`
- rejected OT label-buffer experiment:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-ot-label-buffer-native-release.json`
  and repeat
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-ot-label-buffer-native-release-repeat.json`;
  native p50 regressed versus the retained one-pass baseline, so no code was
  kept from that micro-optimization
- rejected diagnostic stage-operation-count opt-out:
  native client-artifact p50 regressed to `148.854ms` and `147.873ms` across
  two transient runs versus the post-revert `145.156ms` reference, and product
  smoke `20260610-093125Z` regressed `ed25519EvaluationArtifactMs` p50 to
  `484/492/484/478ms`; no code was retained
- SDK registration total: `1250ms` to `1638ms` p50 across the latest smoke
  scenarios
- browser-observed total: `1623ms` to `2242ms` p50 across the latest smoke
  scenarios
- HSS client evaluation artifact: `447ms` to `451ms` p50 across the latest
  smoke scenarios
- `/wallets/register/start`: server route total is now roughly `1ms` p50 after
  consuming a prepared registration package; client-side start timing still
  includes authority verification and browser/Playwright noise
- `/wallets/register/prepare`: server total is roughly `378ms` to `383ms` p50,
  dominated by preauth HSS preparation
- prepare-route split: signing-root server-input derivation is roughly
  `372ms` to `375ms` p50 and server-session preparation is roughly `363ms` to
  `366ms` p50; they run in parallel, so both branches matter
- server-session preparation split: `prepare_prime_order_succinct_hss` still
  accounts for almost all preparation time; driver-state extraction, client
  offer creation, caching, and state encoding are each single-digit
  milliseconds
- `/wallets/register/hss/respond`: server total is now roughly `77ms` to
  `79ms` p50 after one-pass server-input delivery plus prepared OT branch
  caching; delivery preparation is `57ms` to `58ms` p50
- respond delivery split: OT open/join is the dominant product-path bucket at
  `49ms` p50, server-input sharing/open is `6ms` to `7ms`, sealing is roughly
  `2ms`, and delivery encoding remains roughly `6ms`
- `/wallets/register/finalize`: server total is roughly `44ms` to `46ms` p50
  after routing seed-output opening through the cached prepared session
- HSS finalize sub-buckets: serialized server-session materialization is now
  `0ms` p50 on the product path because the cached prepared server session is
  reused; seed-output opening is `1ms` to `2ms` p50, server-output opening is
  `15ms` to `16ms` p50, and artifact decode, report finalization, report
  encoding, key derivation, and key-store persistence are each single-digit
  milliseconds
- passkey auth proof is now split by confirmation bridge diagnostics.
  UserConfirm worker prewarm removes host-origin worker startup from the proof
- product-side wallet-iframe confirmation readiness is measured. Smoke run
  `20260610-024516Z` reports prompt host first-update and interactive p50 at
  about `1ms`, confirm-event p50 at `620ms` to `643ms`, and credential-create
  start p50 at `621ms` to `644ms` in iframe scenarios. The iframe prompt
  renderer is not the current product bottleneck; the benchmark still includes
  auto-confirm wait and WebAuthn time.
- current direct HSS artifact run `2026-06-10T10-31-55-959Z` reports:
  Node serialized-state wall p50 `530.704ms`, Node worker-handle wall p50
  `462.582ms`, and browser worker-handle wall p50 `201.2ms`. The browser
  worker-handle split is hidden eval `188.65ms`, round core `117.45ms`,
  message schedule `28.8ms`, and output projector `40.5ms`.
- the direct main-thread registration confirmation path removes the
  registration-only UserConfirm worker bounce. Host-origin `authProofMs` is now
  `203ms` p50, and wallet-iframe `authProofMs` is `824ms` to `828ms` p50. In
  wallet-iframe mode, the remaining benchmarked cost is the required visible
  click/prompt handoff plus WebAuthn credential creation, with
  `passkeyAuthWorkerRequestRoundTripMs` now `0ms`.

Latest fine-grained client-owned hidden-eval ranking:

- `hiddenEvalRoundCoreMs`: p50 roughly `233ms` to `236ms`
- `hiddenEvalOutputProjectorMs`: p50 roughly `149ms` to `153ms`
- `hiddenEvalMessageScheduleMs`: p50 roughly `32ms`
- inside round core:
  - `hiddenEvalRoundNewABitsMs`: about `23ms` to `24ms` p50
  - `hiddenEvalRoundNewEBitsMs`: about `23ms` to `24ms` p50
  - `hiddenEvalRoundMajMs`: about `32ms` p50
  - `hiddenEvalRoundChMs`: about `23ms` to `24ms` p50
  - `hiddenEvalRoundSigma0Ms`: about `6ms` to `7ms` p50
  - `hiddenEvalRoundSigma1Ms`: about `6ms` to `7ms` p50

Interpretation:

- worker transport, decode, materialization, and encode are now secondary for
  the retained browser-worker path
- standalone label-buffer cleanup is not a keep target after the
  output-projector label-reuse candidate regressed product host-origin client
  artifact p50 despite improving native allocation and direct artifact timings
- significant wins require attacking hidden-eval representation, hashing,
  allocation, A2B/carry conversion, output projection, or protocol shape
- the first A2B destination-reuse experiment improved native p50 but did not
  improve the browser/WASM HSS worker path, so no code from that candidate is
  retained
- the output-projector client-base candidate is retained; it computes
  `a + tau` once and derives client and relayer outputs from that shared base,
  removing one masked-path modular addition and one tau-doubling modular
  addition while preserving output values
- the output-projector mixed shared-mask candidate is retained; it computes
  `client_base + mask` directly from the shared mask bits instead of first
  materializing a split local mask word, reducing masked output-projector
  local-word materializations from `3072` to `2560`
- the Phase 7B staged output boundary is retained; it does not reduce logical
  materialization counters, but it makes output ownership and bundle emission
  explicit and moved product client-artifact p50 in the right direction
- the Phase 7C repeated-selector select batch is retained as the last small
  output-select allocation cleanup; it removes selector-vector cloning and
  improved or held product artifact p50 across the four smoke scenarios
- the Phase 7D carry-gate material-base reuse is retained; it moves public
  local-multiplication domain hasher setup out of fixed-width carry loops,
  improves browser worker-handle p50 by about `5ms`, and improves product
  artifact p50 by `1ms` to `2ms` without changing logical counters or
  transcript material
- the Phase 7E borrow-path material-base reuse is retained; it applies the same
  public-base reuse to fixed-modulus subtraction/borrow gates, deletes the old
  unused per-call wrappers, and improves product artifact p50 to
  `450/451/447/447ms` in the repeat smoke
- Phase 7F and Phase 7G show the current plateau for micro-kernel cleanup:
  output-select scratch and accessor-only changes can reduce apparent local
  work while making native timing worse. The next byte-equivalent attempt should
  be a larger output-projector scratch arena with `_into` helpers and allocation
  gates, or a reviewed backend-versioned A2B/scalar-reduction design.
- a direct Ed25519 HSS WASM artifact benchmark now exists at
  `benchmarks/ed25519-hss-wasm`; baseline run
  `2026-06-08T01-36-06-388Z` measured `node_client_artifact_worker_handle_wasm`
  at 690.641ms p50 and `browser_client_artifact_worker_handle_wasm` at
  339.650ms p50
- logical hidden-eval object counters now flow through the client artifact
  benchmark; smoke run `2026-06-08T01-58-13-255Z` reported 12,800 local-word
  materializations, 1,024 shared-word materializations, 1,536 transport-word
  materializations, 17,928 commitment materializations, 15,360 provenance digest
  materializations, and 57,128 logical label writes per artifact
- native allocation probe
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe.json` reports
  that `profile_hidden_eval_for_clear_input` allocates about `12.3MB` across
  `45,859` allocation calls per hidden-eval execution in native release; the
  same-process delivery path allocates about `14.9MB` across `48,630`
  allocation calls
- after the retained extra-material iterator candidate, the cumulative
  checkpoint allocation probe
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-allocation-probe-checkpoints.json`
  shows output projection as the largest remaining allocation source:
  `3.92MB` and `36.9k` allocation calls incremental over round core
- `hidden_eval_equivalence` now provides the representation-rewrite gate:
  production execution must match checkpoint-capturing trace execution for
  trusted-server and client-masked output projection, and the current
  materialization fixture pins the aggregate logical shape plus masked
  output-projector local-word materializations at `2560`
- the client-owned artifact path now uses a one-shot production hidden-eval
  helper that skips checkpoint digest retention; smoke run
  `2026-06-08T02-11-25-255Z` was mixed and should not be treated as a latency
  win by itself
- server-owned ceremony diagnostics now expose OT reconstruction, server input
  open/share/commitment/transcript, result assembly, and output sealing
  finalization buckets; finalize diagnostics expose artifact decode, serialized
  server-session materialization, report finalization, and report encoding
  buckets
- registration product-path diagnostics now include
  `wallets_register_hss_respond`; the normal registration flow uses the
  role-separated server-input-delivery path, while the server-owned ceremony
  buckets apply to same-process/server-owned artifact export paths
- the finalize fast path reuses the cached prepared server session when the
  staged artifact arrives as bytes; this removed about `241ms` to `244ms` p50
  from the product finalize route
- the next registration-path bottlenecks are client artifact construction,
  signing-root server-input derivation, and core HSS session preparation; HSS
  respond is useful to keep instrumented, but it is already relatively small
- treat the direct browser artifact benchmark as a per-artifact lower bound;
  use the future real-topology registration latency benchmark as the
  product-path confirmation. Refactor 88 retired the old
  `benchmark:registration-flow` runner with its managed-registration mock
  harness.
- native registration-path benchmark
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-native.json` now
  measures the crate-local registration-style flow without browser, worker,
  route, or WASM overhead. The first release run measured total p50 `359.445ms`,
  prepare-session p50 `98.852ms`, client-request p50 `14.825ms`,
  server-input-delivery p50 `25.258ms`, client-artifact p50 `220.099ms`, and
  finalize-report p50 `0.497ms`. Hidden eval inside client artifact was
  `212.261ms` p50, led by round core `125.912ms`, output projector
  `45.984ms`, and message schedule `38.091ms`.
- native CPU attribution captured with macOS `sample` at
  `crates/ed25519-hss/docs/benchmarks/refactor-64/profiles/ddh-hidden-eval-native-sample.txt`
  showed BLAKE3 compression as the dominant top-of-stack bucket, ahead of
  memcpy and curve25519 field arithmetic. The profile pointed to physical
  commitment/provenance hashing as the next useful target, rather than another
  allocation-only output-projector candidate.
- the retained local-multiplication provenance-fold candidates compute
  duplicated left/right provenance digests once for multiplication material,
  single raw multiplication output pairs, and raw batch multiplication output
  pairs while preserving labels, provenance inputs, commitments, protocol
  structs, wire structs, fixed public loops, and backend version. Native hidden
  eval p50 improved from `218.663ms` to `185.329ms`; direct browser WASM worker
  artifact p50 improved from `324.600ms` to `285.200ms`; product smoke HSS
  worker artifact p50 is now `517ms` to `528ms` across the four scenarios.
- physical hash counters now exist behind the diagnostic
  `hss-physical-counters` crate feature. The first counter run reported
  `584,220` derived-owner commitment hashes, `344,846` keyed digest
  derivations, and `31,232` multiplication-material hashes for one profiled
  hidden-eval execution. This confirms that remaining physical hash work is
  dominated by derived commitments and keyed digests. A derived-commitment
  prefix-hasher experiment was rejected after native hidden eval regressed from
  `185.329ms` to `192.030ms` p50.
- the keyed-digest domain counter run
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-keyed-domain-counters.json`
  accounted for all `344,846` keyed digest derivations with `other=0`. The
  largest domains are `eval_xor_local_word` at `164,286`,
  `eval_mul_local_material` at `93,696`, `eval_mul_local` at `43,008`,
  `phase_a_arith_share_to_bool` at `28,672`, and `eval_add_local` at `14,064`.
  This makes `eval_xor_local_word` the next keyed-digest audit target before
  another broad prefix-hasher or structured-label candidate.
- manual audit of `eval_xor_local_word` found no immediate byte-identical quick
  fold. `xor_local_word_pairs_public` already derives one provenance digest for
  both sides of a pair. The remaining single-side raw XOR cases use
  side-specific labels, so folding them would change transcript bytes under the
  current backend version.
- the derived-commitment domain counter run
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-derived-commitment-domain-counters.json`
  accounted for all `584,220` derived commitments with `other=0`. The largest
  domains are `eval_xor_local_word` at `275,324`,
  `eval_mul_local_material` at `187,392`, `eval_mul_local` at `62,464`,
  `phase_a_arith_share_to_bool` at `28,672`, and `eval_add_local` at `28,128`.
  This confirms that the largest remaining commitment work tracks the same XOR
  and multiplication-material families as the keyed-digest counters.
- manual audit of `eval_mul_local_material` and `eval_mul_local` found no
  remaining byte-identical quick fold. The retained multiplication provenance
  folds already derive shared left/right provenance once; the remaining
  commitments use distinct side labels and word bytes. Reducing this family now
  requires representation-level deferred/materialized commitments or a
  backend-versioned transcript change.
- the carry-core local adder candidate is retained. It keeps carry-chain
  intermediates as share/provenance cores, computes local multiplication
  material cores without triple commitments, and materializes commitments only
  for values that leave the carry-only path. Native hidden eval p50 improved
  from the previous retained `185.329ms` to `176.690ms`; direct browser worker
  artifact p50 improved from `285.200ms` to `263.500ms`; product smoke client
  artifact p50 is now `517ms`, `518ms`, `519ms`, and `507ms` across the four
  scenarios.
- the A2B source/carry-core candidate is retained. It applies the same
  deferred-materialization rule to cross-share arithmetic-to-boolean
  conversion: source bit words and carry-only products stay as
  share/provenance cores, while `xor_ab`, `sum`, and `a_xor_carry` remain
  materialized because their commitments are consumed or emitted. Native hidden
  eval p50 improved from the carry-core `176.690ms` to `144.601ms`; direct
  browser worker artifact p50 improved from `263.500ms` to `223.000ms`;
  product smoke client artifact p50 is now `477ms`, `474ms`, `466ms`, and
  `466ms` across the four scenarios.
- the output-boundary paired transport materialization candidate is retained.
  It builds the two `x_relayer_base` transport bundles from one canonical
  shared-word list and one bundle commitment, preserving emitted bundle bytes
  and transcript shape while avoiding duplicate canonicalization and
  commitment work. Native hidden eval p50 improved from the A2B source/core
  `144.601ms` to `138.394ms`; direct browser worker artifact p50 improved from
  `223.000ms` to `215.650ms`; product smoke client artifact p50 is now
  `467ms`, `466ms`, `455ms`, and `455ms` across the four scenarios. Product
  worker p50 improved in three scenarios and regressed by `3ms` in the first
  wallet-iframe scenario, while client artifact and hidden-eval p50 improved
  in all four scenarios.
- product smoke run `20260609-170907Z` added visible HSS worker
  `wasmInitWaitMs` columns to the registration report. Init wait is `0ms`
  p50/p95 for both `prepare_client_request` and
  `build_client_owned_staged_evaluator_artifact`, confirming that the remaining
  artifact bucket is WASM execution time rather than lazy HSS WASM startup.
- current protocol-level decision: defer backend-versioned protocol redesign.
  Runtime Path A has brought the client artifact under the near-term `500ms`
  target, and the remaining registration gap is better attacked through
  refactors 61/62 plus a larger stage-owned representation experiment.

## Constraints

HSS is cryptographic code. Every optimization must preserve:

- export-compatible Ed25519 seed semantics
- the hidden seed path `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`
- threshold-at-registration: neither client nor server learns plaintext `d` or
  plaintext `a`
- the server-blind deployed boundary where the server does not receive the
  client's recoverable secret or client output mask
- no secret-dependent branches
- no secret-dependent indexing
- no secret-dependent allocation sizes
- no variable-time arithmetic on secret-derived values
- fixed public loop bounds for SHA-512 words, rounds, and validated stage counts
- transcript label and gate schedule stability unless the backend version is
  deliberately changed
- route and persistence compatibility only at explicit boundaries

Diagnostics must remain observational and must never influence control flow.

Out of scope for this plan:

- non-exportable additive scalar-share bootstrap
- client-origin exportable seed split where the client materializes `d` and `a`
  before assigning a server share
- server-origin exportable seed split where the server materializes `d` and `a`
  before assigning a client share
- any protocol that makes either participant able to reconstruct the full
  export seed during registration

Those profiles can be discussed in optional-bootstrap planning only if their
trust model is explicitly different from HSS.

## Approach A: Measurement And Profiling First

Goal:

- replace aggregate timing with enough evidence to choose the right runtime or
  protocol change

Tasks:

- [x] add a native Rust HSS registration benchmark that bypasses browser/WASM
      and route overhead
- [x] add CPU attribution for native hidden eval that separates hashing,
      commitment derivation, provenance derivation, modular arithmetic, A2B
      carry conversion, output projection, and allocator overhead
- [x] add a WASM-only benchmark for
      `build_client_owned_staged_evaluator_artifact`
- [x] add logical object/materialization counters for hidden-eval execution
- [x] add counters for `DdhHssLocalWord`-shape materializations, commitments,
      provenance digest materializations, and logical label generation
- [x] add native allocator byte counters or heap-profiler instructions if
      logical counters make object churn the next limiting factor
- [x] add native flamegraph support for `crates/ed25519-hss`
- [x] add browser/WASM profiling instructions for Chrome Performance traces
      around `build_client_owned_staged_evaluator_artifact`, including whether
      time is in WASM compute, JS/WASM boundary calls, worker message handling,
      GC, or memory growth
- [x] capture peak memory and payload sizes for client prepare, respond,
      evaluate, and finalize
- [x] split server prepare/finalize timing into protocol sub-buckets
- [x] split registration start timing into server-input derivation and
      server-session preparation branch timings
- [x] record baseline results in `docs/benchmarks/registration-flow.md` or a new
      HSS-specific benchmark report

Keep rule:

- always keep profiling if it is diagnostics-only and does not change protocol
  behavior

Validation note:

- One-run host-origin benchmark `BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_host_origin
  BENCH_REGISTRATION_RUNS=1` passed after rebuilding the SDK prepare bundle.
  The scenario captured browser memory diagnostics, HSS worker evaluate payload
  bytes, HSS client prepare/respond bytes, and registration route payload bytes
  for `/wallets/register/prepare`, `/wallets/register/hss/respond`, and
  `/wallets/register/finalize`.

### Native Flamegraph Support

Run:

```bash
bash crates/ed25519-hss/scripts/profile_hidden_eval_flamegraph.sh
```

The script writes SVG flamegraphs to
`crates/ed25519-hss/docs/benchmarks/refactor-64/flamegraphs/` and profiles
`benchmark_ddh_hidden_eval` in release mode with debug symbols enabled via
`CARGO_PROFILE_RELEASE_DEBUG=true`.

Useful overrides:

```bash
SAMPLES=32 STAGE_WARMUP=2 bash crates/ed25519-hss/scripts/profile_hidden_eval_flamegraph.sh
bash crates/ed25519-hss/scripts/profile_hidden_eval_flamegraph.sh --fixture <fixture-name>
```

Interpretation target:

- identify whether the largest CPU stacks are hashing/commitment derivation,
  provenance derivation, modular arithmetic, A2B carry conversion, output
  projection, allocator/runtime overhead, or benchmark harness work
- use the flamegraph to choose between broader output-projector representation,
  A2B carry-gadget specialization, structured label/prefix-hasher work, or a
  true stage-owned arena representation
- do not treat allocation-only wins as sufficient if the CPU flamegraph shows
  arithmetic or hashing dominates

### Browser/WASM Trace Instructions

Use Chrome Performance traces on the direct artifact benchmark first, then
confirm promising changes with the future real-topology registration latency
benchmark.

Procedure:

1. Run the direct HSS WASM benchmark server/runner from
   `benchmarks/ed25519-hss-wasm`.
2. Open Chrome DevTools Performance for the benchmark page.
3. Enable allocation instrumentation, WebAssembly stacks, memory timeline, and
   worker profiling.
4. Record one warm run and one measured run for
   `browser_client_artifact_worker_handle_wasm`.
5. Inspect the worker thread around
   `build_client_owned_staged_evaluator_artifact`.
6. Classify the largest slices as WASM compute, JS/WASM boundary calls, worker
   message handling, GC, memory growth, or browser scheduling.
7. Save the trace summary beside the direct benchmark run under
   `crates/ed25519-hss/docs/benchmarks/refactor-64/`.

Keep evidence:

- wall p50/p95 from the direct artifact benchmark
- hidden-eval p50/p95 and sub-buckets
- top worker-thread CPU stacks
- GC and memory-growth events, if any
- worker message payload size and transfer behavior
- notes on whether the browser trace agrees with native flamegraph attribution

## Approach B: Production Representation Audit

Goal:

- identify which labels, commitments, provenance digests, and checkpoint data
  are required for production security versus testing, diagnostics, or protocol
  validation

Tasks:

- [x] classify every digest and commitment in hidden-eval execution as one of:
      security-critical, transcript-binding, validation-only, diagnostics-only,
      or redundant
- [x] identify which fields must be byte-identical for protocol compatibility
- [x] identify which fields can move behind a debug/profile build feature
- [x] identify which fields can be compacted without changing public protocol
      outputs
- [x] define a production execution profile and a validation execution profile
- [x] require explicit backend-version change for any transcript-affecting
      representation change

Potential win:

- moderate to large if provenance hashing and per-bit commitment construction
  dominate runtime

Risk:

- high. This can accidentally weaken transcript binding or remove useful
  validation evidence. No code change should land before the audit is explicit.

### Initial Audit Result

Classification rule:

- `protocol-critical`: required for current HSS security or party-to-party
  validation. Byte output must stay identical unless the backend version and
  protocol spec change.
- `transcript-binding`: included in a commitment, digest, run binding, AAD, or
  label domain. Bytes must stay identical unless the backend version changes.
- `validation-only`: needed to catch malformed local execution, test fixtures,
  continuation replay, or diagnostics, but not required on the production happy
  path after all remote inputs have already been validated.
- `diagnostics-only`: timing, probe, or benchmark data. It must remain
  observational.
- `compactable`: the representation may change if the public commitments,
  output bundles, and validation semantics stay byte-identical.

Current field matrix:

| Data                                                               | Current usage                                                                                                   | Classification                                                               | Compatibility rule                                                                                                                                                         | Optimization direction                                                                                      |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `DdhHssSharedWord.left_word` / `right_word`                        | Actual additive shares consumed by hidden eval and output projection.                                           | `protocol-critical`                                                          | Must preserve arithmetic value and word width.                                                                                                                             | Can move into packed fixed-width storage if accessors preserve value semantics.                             |
| `DdhHssLocalWord.share_word`                                       | Local share consumed by local DDH arithmetic helpers.                                                           | `protocol-critical`                                                          | Must preserve value, side, and width.                                                                                                                                      | Strong candidate for packed local-side arrays or arenas.                                                    |
| `DdhHssSharedWord.left_commitment` / `right_commitment`            | Inputs to `input_commitment_for_key`, stage digests, transport validation, and output commitments.              | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Can be stored compactly or recomputed at validation boundaries only if all transcript bytes stay identical. |
| `DdhHssLocalWord.share_commitment`                                 | Carried through local operations and used to derive downstream provenance/commitments.                          | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Can be represented as side arrays beside packed shares.                                                     |
| `DdhHssTransportWord.share_commitment` / `counterparty_commitment` | Validated by `validate_transport_word_pair_public` and included in `transport_bundle_commitment`.               | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical in transport messages.                                                                                                                            | Do not remove from wire format without a backend-version change.                                            |
| `provenance_digest` on shared/local/transport words                | Validates transport pairing, feeds `commit_word` for derived owners, and enters input/stage/bundle commitments. | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Can be compacted in memory; cannot move behind debug/profile in the current protocol.                       |
| `DdhHssInputShareBundle.commitment`                                | Bundle commitment used in combined input commitment and run binding.                                            | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Can be cached once per bundle; do not remove from persisted/wire boundary.                                  |
| `DdhHssTransportBundle.commitment`                                 | Validates left/right transport bundle agreement and reconstructed input commitment.                             | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Keep in transport boundary; internal packed form may carry one bundle-level commitment.                     |
| `client_input_commitment` / `server_input_commitment`              | Bound into `run_binding_for_key` with artifact digest, context binding, and candidate digest.                   | `protocol-critical`, `transcript-binding`                                    | Must stay byte-identical for current backend version.                                                                                                                      | Keep as run summary fields.                                                                                 |
| `DdhHiddenEvalCheckpointDigests`                                   | Stage-by-stage trace validation and continuation checks.                                                        | `validation-only`, partly `transcript-binding` for current continuation APIs | Continuation APIs must preserve byte-identical digests. Full one-shot production evaluation can avoid retaining all checkpoint digests if outputs are validated elsewhere. | Separate trace/continuation profile from one-shot production profile.                                       |
| `DdhHiddenEvalStageProfile` / `DdhHiddenEvalOperationCounts`       | Benchmark and profiling output.                                                                                 | `diagnostics-only`                                                           | Must never influence execution. Serialization shape can evolve as diagnostics.                                                                                             | Keep outside protocol structs and skip in production hot path where possible.                               |
| Human-readable labels passed to gates and bundle builders          | Domain separation for shares, provenance, commitments, OT payloads, and output bundles.                         | `transcript-binding`                                                         | Label bytes must stay byte-identical for current backend version.                                                                                                          | Replace `format!` with structured label writers only when resulting bytes match exactly.                    |
| Error strings and probe status values                              | Developer diagnostics.                                                                                          | `diagnostics-only`                                                           | No protocol compatibility requirement.                                                                                                                                     | Can change with diagnostics.                                                                                |

Production execution profile:

- validate remote transport bundles at request boundaries
- keep share values, word widths, side tags, commitments, provenance digests,
  labels, input commitments, transport commitments, and run binding bytes
  identical to the current backend version
- return only production outputs needed by the caller: canonical seed output,
  client output bundle, server transport bundles, run commitments, and necessary
  transport commitments
- skip `DdhHiddenEvalCheckpointDigests`, probes, timing profiles, logical
  counters, and stage-continuation materialization unless the caller requests a
  validation or continuation profile

Validation execution profile:

- retain checkpoint digests for add stage, message schedule, round core, and
  output projection
- retain continuation structs and staged materialization data
- retain timing and logical counter profiles for benchmark builds
- run negative tests for mismatched labels, provenance digests, output kind,
  replayed transport bundles, and backend-version downgrade attempts

Compaction decisions from this audit:

- Allowed without backend-version change: packed in-memory storage for local
  shares, commitments, and provenance digests; structured label writers that
  emit identical bytes; one-shot production APIs that avoid returning trace-only
  checkpoint digests.
- Requires backend-version change: removing or changing provenance digest bytes,
  changing commitment derivation domains, changing label bytes, changing bundle
  commitment inputs, changing transport wire fields, or changing run binding
  inputs.

## Approach C: Hot-Loop Local Optimizations

Goal:

- reduce cost in the already-measured hot loops without changing protocol shape

Candidates:

- A2B destination-writer helper for `new_a_bits` and `new_e_bits`
- A2B raw carry-gadget specialization for already-local arithmetic word pairs
- A2B carry-gadget specialization around `xor_ab`, `sum`, `a_xor_carry`,
  `carry`, and `next_carry`, with byte-identical labels and fixed public
  widths
- `maj` and `ch` destination-writing scratch reuse only as part of a fused
  round-core kernel or packed representation; standalone helper-level rewrites
  duplicate rejected/low-value historical work
- output-projector scratch reuse
- broader output-projector representation rewrite that reduces logical local
  word construction, commitment derivations, or provenance derivations instead
  of only reducing temporary allocation
- fewer temporary `DdhHssLocalWord` objects
- fewer intermediate `Vec` allocations in round state and schedule state
- pre-sized arena-backed storage for fixed-width words

Existing spec:

- `docs/refactor-55-hss-optimize-registration.md` Phase E1 already pins the
  labels, provenance, gate schedule, constant-time constraints, and validation
  gates for the first A2B/boolean-helper candidates

Implementation order:

1. A2B destination-writer candidate. Rejected after browser/WASM smoke.
2. Logical object-construction counters. Landed.
3. Production representation audit.
4. A2B raw carry-gadget candidate only if counters show object churn inside the
   carry conversion is material in browser/WASM.
5. output-projector client-base candidate. Landed and retained.
6. output-projector mixed shared-mask candidate. Landed and retained.
7. packed/arena representation harness before more helper-level boolean work.

Keep rule:

- keep only if protocol validation passes and benchmark results show a stable
  HSS p95 win with small complexity or clear p50/p95 improvement across smoke
  scenarios

## Approach D: Structured Labels And Prefix Hashers

Goal:

- remove hot-loop string formatting and repeated hasher setup without changing
  transcript bytes

Candidates:

- replace repeated `format!` and label string assembly with structured label
  writers
- precompute round label prefixes where labels are public and deterministic
- precompute child-label prefix hashers for repeated gate families
- derive labels from fixed public indices while preserving byte-equivalent label
  output
- add byte-equivalence tests for old and new labels

Potential win:

- small to moderate if label construction remains a meaningful slice after
  hot-loop scratch reuse

Risk:

- medium. Label bytes are transcript material. Require fixtures proving
  byte-equivalence before benchmarking.

## Approach E: Packed Or Arena-Backed Execution Representation

Goal:

- reduce object churn by moving from object-per-bit execution to fixed-width
  packed arrays or arena-backed records

Candidates:

- store 64-bit local bit words in contiguous left/right arrays
- store provenance digests in side arrays
- store commitments in side arrays
- use stable handles or indices into an arena instead of cloning full
  `DdhHssLocalWord` values
- specialize fixed-width SHA-512 word operations around public width `64`
- separate public shape metadata from secret share values

Potential win:

- large. This is the first approach likely to produce a major runtime reduction
  if object churn and hashing dominate.

Risk:

- high. This is a representation rewrite and must be split into small
  byte-equivalence-preserving steps.

Required gate:

- implement an equivalence harness before rewriting hot paths
- compare final hidden-eval outputs, checkpoint digests, and public artifacts
  against the current representation

### Candidate E1: Arena-Backed Local Bit-Side Storage

Decision:

- packed/arena representation work is justified. The native allocation probe
  shows hidden-eval still performs about `45.9k` allocation calls and allocates
  about `12.3MB` per profiled execution after the retained output-projector
  wins.
- a simple packed local metadata candidate was tried and rejected. It reduced
  `profile_hidden_eval_for_clear_input` allocation calls from `45,859` to
  `45,025`, but allocated bytes barely moved and the direct browser artifact
  path regressed by about `5ms-6ms`.
- a round-state scratch reuse candidate was tried and rejected. It reduced
  native hidden-eval allocation from `12,282,621` bytes to `10,985,757` bytes,
  but product `ed25519EvaluationArtifactMs` p50 regressed by `2ms-4ms` across
  all four registration-flow smoke scenarios.
- an extra-material iterator candidate was retained. It removed a temporary
  `Vec<&[u8]>` allocation in Boolean-to-arithmetic conversion, reduced native
  hidden-eval allocation from `12,282,621` bytes to `7,695,101` bytes, and
  improved product `ed25519EvaluationArtifactMs` p50 by `1ms-5ms` across all
  four registration-flow smoke scenarios.
- a standalone output-projector label-reuse candidate was rejected. It reduced
  native hidden-eval allocation to `6,419,990` bytes and `15,003` allocation
  calls, and the direct artifact benchmark improved, but product host-origin
  client-artifact p50 regressed by `22ms-24ms`.
- an output-projector select-stream candidate was rejected. It reduced native
  hidden-eval allocation to `6,658,481` bytes and `39,863` allocation calls,
  and direct artifact p50 improved, but product client-artifact p50 regressed
  by `15ms-30ms` across all registration-flow smoke scenarios.
- an A2B output recycling candidate was rejected before product smoke. It
  reduced native hidden-eval allocation to `6,398,237` bytes and `44,015`
  allocation calls, but direct artifact p50 regressed on Node and browser.

Starting scope:

- keep protocol structs, wire structs, bundle commitments, provenance digests,
  labels, and backend version unchanged
- target only internal `hidden_eval_executor` local bit-side storage first
- preserve the existing packed `share_blocks` representation for share bits
- reduce repeated allocation of side-vector storage for commitments and
  provenance digests in hot fixed-width helpers
- start with round-core and modular-add helpers where fixed public widths make
  arena sizing deterministic

Implementation shape:

- introduce a stage-local scratch/arena owner for `LocalBitWordSide` buffers
  with public fixed capacities
- make helpers write into borrowed scratch sides where the output does not need
  to outlive the stage
- materialize owned `SplitLocalBitWord` values only at stage boundaries,
  checkpoint boundaries, output bundles, and validation boundaries
- stream fixed public-shape extra material into digest builders without
  allocating temporary material vectors
- keep label generation and commitment/provenance derivation byte-identical
- keep all arena indexing by public stage shape and public bit index only
- avoid scratch designs that move owned state words through extra rotation
  traffic unless product client-artifact p50 improves
- avoid tiny output-side allocation fusions if direct artifact latency regresses
  on Node
- avoid A2B output recycling through SHA-512 state rotation unless a broader
  representation rewrite removes the observed direct artifact regression
- avoid standalone output-projector label-buffer reuse unless it is part of a
  representation change that improves product client-artifact p50
- avoid select-stream output-projector rewrites unless product smoke improves,
  even when native allocation and direct artifact timing improve

Keep gate:

- `hidden_eval_equivalence` must pass before benchmarking
- native allocation probe should show a meaningful reduction in
  `profile_hidden_eval_for_clear_input` allocation calls or bytes
- direct WASM artifact benchmark should show a clear `hiddenEvalRoundCoreMs` or
  total hidden-eval p50 win on the target browser path without a material Node
  regression
- product smoke should confirm the client artifact bucket moves in the same
  direction

### Candidate E2: Stage-Owned Core Arena Design

Status:

- design complete; first tiny core-input bridge rejected; larger
  `CoreBitWordSide` rewrite resumed after refactor-61/62 measurement showed
  wallet-iframe prompt rendering is not the bottleneck

Goal:

- move fixed-width hidden-eval internals toward stage-owned core values while
  keeping materialized commitments only at protocol, checkpoint, output, and
  validation boundaries

Representation direction:

- introduce a core bit-word side that mirrors `LocalBitWordSide` share storage
  and provenance digests without per-bit commitments
- keep bit indices, stage widths, and arena capacities public and fixed by the
  SHA-512/HSS program shape
- provide explicit materialization functions that take a provenance domain and
  emit `DdhHssLocalWord` or `SplitLocalBitWord` only when a caller proves the
  commitment is consumed or emitted
- preserve existing `SplitLocalBitWord` for boundary and validation APIs
- keep `DdhHssLocalWordCore` as the scalar/share-provenance record used by
  core helpers

First implementation slice:

- add `LocalBitWordSide::local_word_core(idx)` and use it in fixed-width adder
  helpers where the input commitment is only carried through to a helper that
  already has a core equivalent
- add core-input variants only where the provenance input set and output
  commitment bytes stay byte-identical
- keep `xor_ab`, `sum`, and `a_xor_carry` materialization rules unchanged until
  a caller-specific proof shows their commitments are unused before the next
  boundary
- avoid changing transport/shared input validation or output bundle shape
- benchmark this as a small bridge candidate before adding a larger
  `CoreBitWordSide` arena

First implementation result:

- rejected. The core-input bridge preserved byte-equivalence, but native hidden
  eval p50 regressed from `138.394ms` to `140.966ms`.
- code from the bridge was reverted.
- [x] choose the next product-latency step before a larger arena attempt:
      continue refactor-61/62 critical-path measurement.
- [x] revisit a larger stage-owned `CoreBitWordSide` representation after the
      registration warmup and remaining product-path bottlenecks are measured.
      Smoke run `20260610-024516Z` showed prompt host rendering at about `1ms`
      p50 and left client HSS artifact construction as the next product bucket.
- the next arena attempt should skip tiny local-word accessor bridges and move
  directly to a larger stage-owned `CoreBitWordSide` representation.

Expected signal:

- small if the slice only avoids local temporary words
- meaningful only if it also reduces physical commitment derivations,
  allocation calls, or direct artifact p50
- a flat or regressing result should push the next attempt directly to a larger
  stage-owned `CoreBitWordSide` representation

Validation:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml --features hss-physical-counters hidden_eval_equivalence`
- native hidden-eval benchmark
- direct WASM artifact benchmark
- product registration smoke before retention

### Phase E3: Larger Stage-Owned CoreBitWordSide Rewrite

Status:

- retained. This is the first real larger `CoreBitWordSide` attempt. Previous
  attempts were narrower: packed local metadata, round-state scratch reuse,
  output-side allocation rewrites, and the rejected E2 core-input bridge.

Architecture:

- Add `CoreBitWordSide` as stage-owned storage for fixed-width local bit words.
  It stores only public shape, packed share bits, and provenance digests.
- Keep commitments out of intermediate round scratch when the commitment is not
  consumed before the next materialization boundary.
- Materialize to `LocalBitWordSide` only when a downstream helper requires
  commitments, when stage/checkpoint digests are computed, or when output
  bundles are emitted.
- Keep all loop bounds, bit indices, scratch capacities, and arena indices
  derived from public SHA-512/HSS stage shape.
- Preserve label bytes, provenance input order, emitted commitments, protocol
  structs, wire structs, and backend version.
- Keep diagnostics observational. A benchmark result must decide whether code
  stays; diagnostics must not alter registration control flow.

First implementation slice:

- Convert round-stage `sigma0` and `sigma1` scratch words to core-backed
  storage.
- Compute `xor01` intermediates as core words and avoid deriving their
  commitments, because only their share/provenance pair feeds `xor012`.
- Materialize final `sigma0` and `sigma1` words exactly once before
  `add_two_local_bit_pairs_to_arithmetic_naive` or
  `add_five_local_bit_pairs_to_arithmetic_naive` consumes their commitments.
- Leave `choose`, `majority`, message-schedule small sigma, A2B, and output
  projection on existing materialized storage for this first slice.

Todo:

- [x] Add core raw XOR helpers that derive the same provenance as the
      materialized helpers without computing commitments.
- [x] Add `CoreBitWordSide` and a paired round-scratch type.
- [x] Materialize core round-sigma scratch into existing `LocalBitWordSide`
      boundary scratch before arithmetic conversion.
- [x] Run `hidden_eval_equivalence`.
- [x] Run native hidden-eval benchmark and record whether `round_core`,
      `total_hidden_eval`, and allocation counters improve.
- [x] Run direct HSS WASM artifact benchmark.
- [x] Run product registration smoke only if native and direct WASM move in the
      same direction.
- [x] Retain only if byte-equivalence passes and the product/client artifact
      bucket improves without a material Node or browser regression.

Result:

- kept. The slice preserves emitted protocol shape and moves the real product
  artifact bucket in the right direction.
- validation:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`
    passed: `3` passed, `98` filtered.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
    `97` passed, `4` ignored.
  - `cargo hss-fv verus-check` passed: Verus `96` verified, `0` errors, and
    `10` anti-drift tests passed.
- native hidden eval:
  - previous retained
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-output-transport-pair-native.json`
    to
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-sigma-native.json`
  - `round_core` p50: `84.740ms -> 81.380ms`
  - `total_hidden_eval` p50: `138.394ms -> 134.094ms`
  - allocation probe captured
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-sigma-alloc.json`;
    allocation was not the retained win. `profile_hidden_eval_for_clear_input`
    is `7.307MB` / `36,777` calls p50, and the timed
    `evaluate_for_clear_input_debug_timed` path is `9.965MB` / `39,548` calls
    p50.
- direct HSS WASM artifact:
  - baseline `2026-06-10T02-49-09-370Z` to run
    `2026-06-10T03-08-25-774Z`
  - browser worker-handle wall p50: `220.35ms -> 215.2ms`
  - browser hidden-eval p50: `207.6ms -> 202.55ms`
  - browser round-core p50: `124.6ms -> 120.95ms`
  - Node serialized-state wall p50: `542.319ms -> 530.613ms`
  - Node worker-handle wall p50: `471.816ms -> 452.168ms`
- product registration smoke:
  - baseline `20260610-024516Z` to run `20260610-030916Z`
  - `ed25519EvaluationArtifactMs` p50 by scenario:
    `466/471/466/466ms -> 464/466/459/458ms`
  - HSS worker artifact p50 by scenario:
    `465/470/465/464ms -> 461/465/458/461ms`
  - SDK total p50 by scenario:
    `1807/1869/1480/1511ms -> 1806/1867/1461/1508ms`
  - browser total p50 by scenario:
    `2480/2502/1852/1895ms -> 2436/2478/1830/1882ms`
  - logical hidden-eval counters stayed stable, including local word
    materializations `12,800` and commitment materializations `17,928`, which
    confirms this slice reduces transient physical work without changing the
    emitted logical shape.

Second implementation slice:

- Try message-schedule small-sigma side storage before `Ch`/`Maj`.
- Rationale: `Ch` and `Maj` transient XOR commitments feed the multiplication
  material digest, so deleting those commitments would change transcript bytes.
  Message-schedule small-sigma has the same safe pattern as the retained
  round-sigma slice: `xor01` is only an intermediate whose bit/provenance feed
  `xor012`, while the final `xor012` word is materialized before arithmetic
  conversion.
- Scope:
  - Add a single-side core XOR helper that derives the same provenance as
    `xor_local_bit_from_raw_public` without deriving the commitment.
  - Route `small_sigma0_local_bits` and `small_sigma1_local_bits` through
    `CoreBitWordSide`, then materialize the final side words once.
  - Leave `Ch`, `Maj`, A2B, output projection, and wire structs unchanged.
- Keep gate:
  - `hidden_eval_equivalence` must pass.
  - Native hidden eval should improve `message_schedule` or
    `total_hidden_eval` without a `round_core` regression.
  - Direct browser worker p50 decides whether to continue to product smoke.

Result:

- kept. The slice preserves hidden-eval byte equivalence and improves the
  registration artifact bucket across the product smoke scenarios.
- validation so far:
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml hidden_eval_equivalence`
    passed: `3` passed, `98` filtered.
  - `cargo test --manifest-path crates/ed25519-hss/Cargo.toml` passed:
    `97` passed, `4` ignored.
  - `cargo hss-fv verus-check` passed: Verus `96` verified, `0` errors, and
    `10` anti-drift tests passed.
- native hidden eval:
  - previous retained
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-sigma-native.json`
    to
    `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-core-bitword-small-sigma-native.json`
  - `message_schedule` p50: `24.640ms -> 23.116ms`
  - `round_core` p50: `81.380ms -> 81.068ms`
  - `total_hidden_eval` p50: `134.094ms -> 131.835ms`
- direct HSS WASM artifact:
  - baseline `2026-06-10T03-08-25-774Z` to run
    `2026-06-10T03-35-11-130Z`
  - browser worker-handle wall p50: `215.2ms -> 213.95ms`
  - browser hidden-eval p50: `202.55ms -> 201.5ms`
  - browser message-schedule p50: `37.15ms -> 34.05ms`
  - Node worker-handle wall p50: `452.168ms -> 450.608ms`
  - Node serialized-state wall p50 was noise-regressed:
    `530.613ms -> 532.467ms`; product and browser-worker p50 still improved.
- product registration smoke:
  - baseline `20260610-030916Z` to run `20260610-033610Z`
  - `ed25519EvaluationArtifactMs` p50 by scenario:
    `464/466/459/458ms -> 457/456/450/453ms`
  - HSS worker artifact p50 by scenario:
    `461/465/458/461ms -> 456/456/449/452ms`
  - SDK total p50 by scenario:
    `1806/1867/1461/1508ms -> 1791/1821/1440/1475ms`
  - browser total p50 by scenario:
    `2436/2478/1830/1882ms -> 2412/2442/1807/1842ms`
  - logical hidden-eval counters stayed stable, including local word
    materializations `12,800` and commitment materializations `17,928`.

Rejected follow-up micro-experiments:

- fused A2B pack/native:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-pack-fused-native.json`
  - tried to combine Boolean-share packing and right-share correction in
    `split_local_bit_pair_to_arithmetic_word_pair_naive`
  - `hidden_eval_equivalence` passed after preserving borrow order, but native
    p50 regressed:
    - `message_schedule`: `23.116ms -> 24.864ms`
    - `round_core`: `81.068ms -> 87.614ms`
    - `output_projector`: `24.444ms -> 26.071ms`
    - `total_hidden_eval`: `131.835ms -> 142.134ms`
  - result: reverted
- round-constant arithmetic precompute/native:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-round-constant-arith-precompute-native.json`
  - tried to precompute public SHA-512 round constants as arithmetic words for
    the `temp1/d` operand
  - `hidden_eval_equivalence` passed and `round_temp1` improved
    `4.205ms -> 3.564ms`, but the wider executor regressed:
    - `message_schedule`: `23.116ms -> 24.046ms`
    - `round_core`: `81.068ms -> 83.754ms`
    - `output_projector`: `24.444ms -> 25.398ms`
    - `total_hidden_eval`: `131.835ms -> 136.777ms`
  - result: reverted
- A2B zero-core carry seed/native:
  `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-a2b-zero-core-native.json`
  - tried to preserve the `{label}/zero` provenance digest while skipping
    unused zero-word commitment derivation in
    `arithmetic_word_pair_to_split_local_bits_secure`
  - `hidden_eval_equivalence` passed, but the target sub-buckets regressed:
    - `round_new_a_bits`: `14.373ms -> 15.065ms`
    - `round_new_e_bits`: `14.592ms -> 15.035ms`
    - `round_core`: `81.068ms -> 83.632ms`
    - `total_hidden_eval`: `131.835ms -> 135.810ms`
  - result: reverted

## Approach F: Binary And Compact Payloads

Goal:

- reduce serialization and transport overhead after core runtime costs are
  better understood

Candidates:

- binary worker messages for large one-shot artifacts
- transferable `ArrayBuffer` payloads
- compact evaluation result payloads
- compact staged artifact encoding
- route-level binary payloads only after browser worker payloads are proven
  useful

Current priority:

- lower than hidden-eval executor work for latency because latest diagnostics
  show worker decode, materialization, and encode are secondary on the retained
  worker-handle path

Potential win:

- small to moderate for browser registration
- useful for memory pressure and embedded transport even if runtime win is small

## Approach G: Native, SIMD, And Parallel Runtime Paths

Goal:

- make HSS faster on native and selected browser runtimes without changing the
  trust model

Candidates:

- native Rust benchmark and optimization profile separate from WASM
- Rust compiler profile tuning per target
- WebAssembly SIMD for fixed-width public-lane operations where safe
- native SIMD for digest/commitment or bit operations where library support is
  constant-time
- worker parallelism across independent public windows or gate batches
- server-side parallelism for prepare/finalize if transcript order remains
  deterministic

Constraints:

- parallel work must be partitioned by public indices only
- result assembly must be deterministic
- no scheduling decision can depend on secret share contents
- browser thread support must not become a correctness dependency

Potential win:

- moderate for SIMD
- moderate to large if server prepare/finalize can parallelize independent
  public batches

Risk:

- medium to high. Constant-time and deterministic transcript review required.

## Approach H: Protocol-Level Redesign

Goal:

- get a step-function improvement if representation and runtime work cannot
  make HSS fast enough, while preserving exportability and
  threshold-at-registration

Candidates:

- reduce the number of hidden-eval gates needed for registration
- change the output projection strategy
- precompute reusable public or server-side material safely
- use a different HSS primitive for the registration bootstrap only if it keeps
  `d` and `a` hidden from both parties
- split high-cost proof/validation material from the critical path
- introduce a backend-versioned compact HSS protocol

Required gate:

- write a separate protocol spec before implementation
- define threat model, transcript, replay protection, downgrade behavior, and
  compatibility boundary
- prove that neither party materializes the full export seed or signing scalar
  during registration
- add protocol-validation tests before any benchmark-driven keep decision

Potential win:

- large or 2x+

Risk:

- very high. Treat this as a protocol project, not a refactor.

## Approach I: Move Work Off The Critical Path

Goal:

- reduce user-visible registration latency while HSS remains expensive

Candidates:

- pre-auth HSS prepare
- registration ceremony precomputation
- post-auth finalize minimization
- background HSS readiness audit

Tasks:

- [x] route registration HSS respond diagnostics into the product-path benchmark
- [x] add a finalize fast path that reuses the cached prepared server session
      when the staged artifact arrives as bytes
- [x] validate the finalize fast path with `cargo check` for the server WASM
      export and relay-server TypeScript checks
- [x] benchmark the finalize fast path with `benchmark:registration-flow:smoke`
      and keep it only if the product-path finalize route improves
- [x] add finalize sub-buckets for server-output opening, seed-output opening,
      seed keypair derivation, relayer verifying-share derivation, and
      threshold key-store persistence so the remaining `registrationHssFinalizeMs`
      cost is observable
- [x] route registration seed-output opening through the live prepared-session
      cache handle while the ceremony is active, with serialized evaluator
      state remaining the request/persistence-boundary fallback
- [x] benchmark the seed-output cache path with `benchmark:registration-flow:smoke`
      and keep it only if `/wallets/register/finalize` or
      `registrationHssFinalizeOpenSeedOutputMs` improves without moving client
      artifact timing backward

Result:

- kept. Smoke run `20260610-035655Z` passed all four passkey scenarios.
- `walletRegisterFinalizeMs` p50 by scenario moved
  `213/215/211/215ms -> 52/55/51/52ms` versus `20260610-033610Z`.
- route `registrationHssFinalizeMs` p50 is now `45/46/44/44ms`.

Follow-up result:

- kept. Smoke run `20260610-041350Z` passed all four passkey scenarios after
  the one-pass server-input delivery patch.
- native release `server_input_delivery` p50 moved
  `25.258ms -> 21.418ms` versus
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-native.json`.
- route `registrationHssRespondMs` p50 by scenario moved
  `88/89/88/89ms -> 81/86/83/83ms` versus `20260610-035655Z`.
- route `registrationHssRespondPrepareDeliveryMs` p50 moved
  `70/70/69/69ms -> 64/66/64/64ms`.
- new respond sub-buckets show OT open/join as the remaining delivery
  bottleneck at `55ms` to `58ms` p50; server-input sharing/open is `6ms` to
  `7ms`, sealing is about `2ms`, and encoding is about `5ms`.
- new finalize sub-buckets show `registrationHssFinalizeOpenSeedOutputMs` at
  `1ms` to `2ms` p50 and `registrationHssFinalizeOpenServerOutputMs` at
  `15ms` to `16ms` p50.
- SDK total p50 moved `1791/1821/1440/1475ms -> 1615/1664/1274/1293ms`.
- client artifact p50 stayed compatible at `449/451/444/443ms`.

Prepared OT branch-cache follow-up:

- kept. Smoke run `20260610-043955Z` passed all four passkey scenarios after
  moving request-independent OT branch plaintext, AAD, and payload digests into
  prepared server-session materialization.
- native release `server_input_delivery` p50 moved
  `21.418ms -> 18.148ms` and repeated at `18.124ms` versus the retained
  one-pass server-input baseline. Native `prepare_session` p50 increased from
  `94.970ms` to roughly `102ms` to `104ms`, which is acceptable only while
  prepare remains preauth/off the post-auth critical path.
- route `registrationHssRespondMs` p50 by scenario moved
  `81/86/83/83ms -> 77/79/77/77ms` versus `20260610-041350Z`.
- route `registrationHssRespondPrepareDeliveryMs` p50 moved
  `64/66/64/64ms -> 58/58/57/57ms`.
- `registrationHssRespondDeliveryOtOpenJoinMs` p50 moved from `55ms` to `58ms`
  down to `49ms` in all four scenarios.
- `walletRegisterPrepareWaitMs` stayed `0ms` p50 in every scenario, preserving
  the refactor-62 critical-path assumption.
- the rejected OT label-buffer micro-experiment regressed native
  `server_input_delivery` p50 to `22.956ms` to `23.570ms`, so it remains
  documented evidence rather than retained code.

Ownership:

- this plan should record which HSS operations are movable
- route-shape and UX changes belong in dedicated registration-critical-path
  plans

Potential win:

- large for user-visible latency

Risk:

- medium to high. Scope binding, expiry, replay protection, and user-visible
  success semantics must be explicit.

## Recommended Order

1. Measurement and profiling.
2. Native flamegraph and CPU attribution across hashing, commitment derivation,
   provenance derivation, arithmetic, A2B carry conversion, output projection,
   and allocator overhead.
3. Browser/WASM Chrome Performance trace for the direct client artifact path.
4. Logical allocation and object-construction counters.
5. Production representation audit.
6. Native allocator or heap-profiler evidence if packed representation is still
   ambiguous.
7. Broader output-projector representation rewrite only where it reduces
   logical work or product client-artifact p50.
8. A2B carry-gadget specialization only where profiling shows carry conversion
   is material in browser/WASM.
9. Output-projector scratch candidates only where counters show browser/WASM
   object churn.
10. Packed/arena representation harness.
11. Structured label or prefix-hasher work only when folded into the new
    representation and guarded by byte-equivalence fixtures.
12. Native/SIMD/parallel runtime experiments.
13. Protocol-level redesign only if the above cannot meet targets.

Do not start with protocol redesign. First prove whether current HSS is slow
because of unavoidable cryptographic work or because the implementation carries
too much object, label, hashing, and diagnostics overhead in production.

## Targets

Near-term HSS targets:

- reduce client eval artifact p50 from about `677ms` to below `500ms`
- reduce client eval artifact p95 below `600ms`
- reduce HSS prepare and finalize p50 by at least `20%` each, or explain why the
  server path is protocol-bound

Stretch HSS targets:

- client eval artifact p50 below `300ms`
- total HSS critical path below `900ms`
- native HSS registration path fast enough for iOS-class devices
- embedded recommendation backed by measured runtime and memory numbers

Full registration target:

- HSS runtime work alone is unlikely to guarantee `1500ms max`
- reaching that user-visible target probably also requires moving prepare or
  finalize work off the post-auth critical path

## Validation Ladder

For instrumentation-only changes:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- targeted benchmark command
- `git diff --check`

For HSS Rust behavior changes:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`
- `pnpm -C sdk type-check`
- real-topology registration latency benchmark once the replacement exists

For protocol-shape changes:

- protocol spec update
- backend-version decision
- protocol-validation fixtures
- negative tests for mismatched labels, provenance, output kind, replay, and
  downgrade behavior
- full registration benchmark

## Next Optimization Task Queue

1. Native flamegraph support is in place via
   `crates/ed25519-hss/scripts/profile_hidden_eval_flamegraph.sh`.
2. Browser/WASM Chrome Performance trace instructions are in place for the
   direct client artifact path.
3. Native CPU attribution is captured. Browser trace capture remains useful for
   JS/WASM boundary, worker message, GC, and memory-growth confirmation, but the
   current hot path is physical DDH hash/provenance work.
4. Continue with narrowly scoped duplicate hash/provenance reductions before a
   broader output-projector or A2B representation rewrite.
5. Physical hash-invocation counters are available behind
   `hss-physical-counters`. Use them for diagnostic runs only; counter-enabled
   latency is not a keep/reject signal because the atomic increments add
   overhead.
6. Physical keyed-digest domain counters show `eval_xor_local_word` and
   `eval_mul_local_material` as the largest keyed-digest families. The
   `eval_xor_local_word` quick-fold audit did not find a byte-identical fold,
   so further XOR work should be representation-level or backend-versioned.
7. Physical derived-commitment domain counters also point to
   `eval_xor_local_word` and `eval_mul_local_material`. The narrow XOR and
   multiplication audits found no byte-identical quick fold, so move to
   representation-level commitment materialization work.
7a. Phase 9 boundary-graph audit selects `Maj` transient `xy`/`xz` plus gated
    product as the first multiplication/XOR root candidate after protocol
    approval. `Ch` gated select is second; local-add carry material is third.
    Do not implement another B2A-only root until the stronger B2A proof shape
    removes more logical work than the rejected core-sigma experiment.
7b. Phase 9A `Maj` root spec is drafted in `optimization-6.md`. The
    behaviorless typed scaffold and root digest builders have landed. The next
    executable behavior change is protocol approval of the root binding and a
    `Maj` helper swap under the physical-counter-first benchmark gate.
7c. Phase 9B/9C specs are drafted for `Ch` gated select and local-add carry.
    Keep the implementation order as `Maj`, then `Ch`, then local-add carry.
    Each slice must prove targeted physical-counter movement before native p50,
    direct browser/WASM, or product smoke work.
7d. Phase 9D approval/readiness checklist is drafted. The first code patches
    landed typed kernel/version/kind/boundary scaffolding, parser tests,
    committed-local root builders, and root sensitivity tests without helper
    behavior changes. The `Maj` helper swap and benchmarks come next.
7e. The first semantic `Maj` root helper experiment was rejected. It reduced
    `eval_xor_local_word` keyed digests and derived commitments by `20,480`
    each, but native total hidden-eval p50 regressed to `132.786ms` versus the
    `124.529ms` retained A2B-v2 reverted baseline and `118.436ms` best retained
    A2B BLAKE3-base run. Keep the root scaffold, but do not retry this exact
    three-root-per-bit `Maj` shape.
7f. A cheaper `Maj` pair-XOR fold is retained under
    `ddh_hss_backend_v3_a2b_maj_pair_xor`. It uses the existing pair helper for
    transient `xy` and `xz`, deleting the stale single-side raw XOR helper.
    Physical keyed digests drop `248,002 -> 237,762`, entirely from
    `eval_xor_local_word`; derived commitments remain flat. Native total
    hidden-eval p50 is `118.248ms`, improving over the latest reverted baseline
    `124.529ms` and matching the previous best retained A2B BLAKE3-base run.
    Direct browser/WASM reference-matched at `172.800ms` mean, which is flat to
    slightly slower than the retained A2B v2 direct-browser reference
    `170.5ms`; product smoke is deferred until direct-browser movement repeats
    or product-level validation is explicitly needed.
7g. Post-retention cheap-fold audit is complete. `Ch` already builds `yz`
    through the raw-public pair helper, and local-add carry already uses
    pair/core helpers for the obvious XOR and carry transitions. The next HSS
    runtime work in this lane is protocol-reviewed `Ch` root material or
    local-add carry-root material, rather than another helper-level fold.
7h. Phase 9B behaviorless `Ch` root scaffold is implemented. It adds typed
    `Ch` root inputs/digests and sensitivity tests for label, index,
    commitment, provenance, width, and share side. Runtime `Ch` helper behavior
    is unchanged until the root-bound gated-select protocol change is approved.
7i. Phase 9B root-bound `Ch` gated-select helper is retained under
    `ddh_hss_backend_v4_ch_gated_select_root`. Physical keyed digests drop
    `237,762 -> 222,402`; derived commitments drop `247,172 -> 195,972`;
    native total hidden-eval p50 improves `118.248ms -> 108.737ms`; native
    `round_ch` p50 improves `16.320ms -> 6.969ms`; direct browser/WASM
    reference-matched and improved `172.800ms -> 168.567ms`; product smoke
    `20260611-041314Z` passed all four scenarios with
    `ed25519EvaluationArtifactMs` p50 `430/431/422/420ms`. Full crate tests,
    wasm32 check, and `cargo hss-fv verus-check` passed; Verus reported
    `96 verified, 0 errors`, and anti-drift reported `10 passed`.
7j. Phase 9C local-add carry-root was implemented experimentally and rejected.
    It reduced physical derived commitments `195,972 -> 192,900`, but native
    p50 stayed in the `108.432-110.754ms` noise band against retained v4
    `108.737ms`, and the trimmed browser/WASM run regressed to `171.600ms`
    versus retained v4 `168.567ms`. The source is restored to the retained v4
    backend; keep the rejected v5 benchmark JSONs as evidence and do not retry
    this carry-root shape without a design that removes more logical work.
7k. A round-sigma B2A-boundary experiment was implemented and rejected. It
    routed `temp1`/`temp2` directly through `CoreBitWordPair` B2A conversion,
    preserving hidden-eval equivalence but leaving physical counters flat at
    keyed `222,402` and derived `195,972`. Native total hidden-eval p50
    regressed to `109.592ms` versus retained v4 `108.737ms`, and allocation
    calls increased from the retained `5,031` baseline to `5,081` while bytes
    only moved `4.160562MB -> 4.158085MB`. The source is restored to the
    retained v4 round-sigma materialization path; keep the exact-stage
    conversion check and the rejected benchmark JSONs as evidence.
8. The first two representation-level commitment materialization candidates
   are retained for the carry-chain adder and cross-share A2B converter.
   Continue with stage-owned cores only where callers can prove commitments are
   not consumed before materialization.
9. For output projection, target fewer logical local words, fewer commitment
   derivations, or fewer provenance derivations. Allocation-only wins are not a
   sufficient keep reason.
10. A2B source/carry-core specialization is retained. Future A2B work should
    target a larger stage-owned representation only if it preserves
    byte-identical labels, provenance inputs, commitments, and fixed public
    widths.
11. Output-boundary paired transport materialization is retained. Future output
    projection work should target a larger stage-owned representation or a
    proven reduction in logical materialization, since narrow bundle-boundary
    sharing is now exhausted.
12. The E2 core-input bridge is rejected. Avoid tiny accessor-only core bridges;
    they preserve bytes but do not reduce enough work to improve native latency.
13. Revisit structured labels and prefix hashers only after a domain-specific
    target is identified. Keep emitted transcript bytes identical unless the
    backend version changes deliberately.
14. Design the next true arena-backed representation as a stage-owned execution
    model with explicit lifetimes and materialization only at stage, checkpoint,
    output, and validation boundaries.
15. Retain a candidate only after `hidden_eval_equivalence`, native profiling,
    direct WASM artifact timing, and product registration smoke all move in a
    compatible direction.
16. Refactor-61 direct registration confirmation is retained as a product-path
    win. It is not an HSS runtime optimization, but it lowers wallet-iframe SDK
    p50 by about `41ms` to `43ms` and removes the registration-only
    UserConfirm worker bounce.
17. Current product-path bottleneck order is client HSS artifact construction,
    preauth HSS prepare, and wallet-iframe benchmark/user confirmation time.
    Finalize is now a secondary route bucket after the seed-output prepared
    session cache path. Wallet-iframe prompt host rendering is measured and is
    about `1ms` p50, so HSS-specific work should continue with the larger
    stage-owned `CoreBitWordSide` representation, keeping the product benchmark
    as the final keep gate.
18. Benchmark wallet-iframe auto-confirm diagnostics are retained. The latest
    smoke run shows the helper sees the confirm button at roughly `639ms` to
    `645ms` p50 and dispatches the click at roughly `843ms` to `849ms` p50.
    Treat browser-observed wallet-iframe p50 as partially benchmark-harness
    dependent; use SDK p50 and product-side diagnostics for keep/reject
    decisions.
19. Prepared OT branch caching is retained for the server respond route. Future
    respond-route work should target real OT open/join costs such as curve
    multiplication/key derivation/encryption batching, because branch payload
    derivation is now shifted into prepared session materialization.
20. The next optimization lane should return to client artifact construction:
    either a larger stage-owned `CoreBitWordSide` slice for round-core
    `Ch`/`Maj`/adder materialization, or a broader output-projector
    representation that reduces logical materializations in the browser worker.
21. Three bounded client-artifact micro-candidates after prepared OT branch
    caching were rejected after native benchmarks: fused A2B packing,
    round-constant arithmetic precompute, and A2B zero-core carry seed. Avoid
    repeating operation-count-only rewrites unless they reduce logical
    materialization or move direct browser worker p50.
22. The diagnostic stage-operation-count opt-out is rejected. It reduced no
    logical materialization, did not improve native p50, and regressed product
    smoke after a forced SDK rebuild.
23. Phase 7B staged output boundary is retained. It preserves current bundle
    bytes, commitments, labels, ownership, protocol structs, wire structs, and
    backend version, while product `ed25519EvaluationArtifactMs` p50 improved
    from `482/491/484/478ms` to `463/467/459/457ms`.
24. Phase 7C should try to feed staged output state earlier in the
    output-projector path only if it reduces output-side logical local words,
    commitment/provenance derivations, or product client-artifact p50.
25. Phase 7C repeated-selector select batch is retained as a small
    public-shape allocation slice. It removes selector-vector cloning in
    output-side select operations and improved or held product
    `ed25519EvaluationArtifactMs` p50 across all four smoke scenarios, but it
    does not reduce logical materialization counters.
26. The next HSS runtime candidate should be a larger representation or
    protocol-kernel change around the `round_new_a_bits` / `round_new_e_bits`
    A2B boundary, output-projector logical materialization, or a deliberate
    backend-versioned rewrite. Small local reshuffles have now produced
    consistent locality regressions in native hidden-eval.
27. The arena-backed executor lane now has a byte-equivalence signature harness
    before the next hot-path rewrite. The harness covers trusted-server and
    client-masked projection modes, compares output commitments, output
    projection digest, client output kind, input commitments, and logical
    operation shape between production and checkpoint-trace execution.
28. The arena-backed output-projector lane now also has targeted same-session
    byte-equivalence fixtures for scalar reduction and canonical modular
    addition. These fixtures compare exact local words and populated output
    digests for the two helper families most likely to receive `_into` /
    scratch-arena rewrites next.
29. Fresh arena precondition baselines are recorded under
    `crates/ed25519-hss/docs/benchmarks/refactor-64/optimization-5/arena-preconditions/`.
    The current allocation baseline is `4.158117MB` / `5,091` calls for
    `profile_hidden_eval_for_clear_input`; current native p50 is
    `114.320ms` total hidden-eval and `18.110ms` output-projector. Treat these
    as same-machine comparison points for the next candidate, not as a new
    retained-performance claim.
30. Do not spend the next slice on small select/accessor arena plumbing unless
    it removes logical materialization or improves browser/product p50. Phase
    7F and 7H already showed that allocation-only output-projector changes can
    regress latency.
31. Protocol B2A / multiplication-root work remains blocked on explicit
    approval of the stronger B2A replacement binding or the Phase 9D
    multiplication-root checklist in `optimization-6.md`. Do not implement a
    semantic root change until those boxes are checked.

## Current Checklist

- [x] Choose Path A for this plan: preserve current HSS trust model,
      exportability, and threshold-at-registration.
- [x] Capture native hidden-eval baseline for the current DDH executor.
- [x] Run Phase E1 A2B destination-reuse experiment.
- [x] Reject A2B destination-reuse candidate after browser/WASM smoke showed no
      HSS worker improvement.
- [x] Add native HSS registration benchmark.
- [x] Add native flamegraph support for `crates/ed25519-hss`.
- [x] Run native CPU attribution for hashing, commitment derivation, provenance
      derivation, modular arithmetic, A2B carry conversion, output projection,
      and allocator overhead.
- [x] Add browser/WASM Chrome Performance trace instructions for the direct
      client artifact path.
- [x] Add WASM-only HSS artifact benchmark.
- [x] Add hidden-eval logical allocation and object-construction counters.
- [x] Add native allocation probe for hidden-eval object churn.
- [x] Add cumulative checkpoint allocation probes for hidden-eval stage
      allocation attribution.
- [x] Add byte-equivalence harness before packed/arena representation work.
- [x] Add output-projector local-word materialization evidence for
      scratch/materialization keep-reject decisions.
- [x] Split one-shot client artifact evaluation from checkpoint-retaining trace
      evaluation.
- [x] Split server HSS prepare/finalize into protocol sub-buckets.
- [x] Complete production representation audit.
- [x] Benchmark A2B candidate against `20260607-152114Z`.
- [x] Split output-projector timing into core, reduction, tau, mask, client,
      relayer, and bundle-build sub-buckets.
- [x] Retain output-projector shared client-base candidate after direct artifact
      and registration-flow smoke benchmarks.
- [x] Retain output-projector mixed shared-mask candidate after
      byte-equivalence, direct artifact, and registration-flow smoke
      benchmarks.
- [x] Review historical `ed25519-hss` optimization notes for duplicate
      candidates before continuing refactor-64.
- [x] Avoid standalone `maj`/`ch` scratch candidates unless they are part of a
      fused round-core or packed-representation rewrite.
- [x] Design the first mixed local/shared output-projector kernel against the
      new equivalence harness.
- [x] Design the first packed round-core or arena-backed representation
      candidate against the equivalence harness.
- [x] Reject packed local metadata candidate after allocation and direct WASM
      benchmarks showed too little allocation reduction and a browser direct
      artifact regression.
- [x] Implement a real stage-local scratch/arena lifetime candidate that avoids
      temporary local side-vector allocation in fixed-width hot helpers.
- [x] Reject round-state scratch reuse candidate after native allocation
      improved but product client-artifact p50 regressed in registration-flow
      smoke.
- [x] Retain extra-material iterator candidate after byte-equivalence,
      allocation, direct artifact, and registration-flow smoke benchmarks.
- [x] Reject fused output canonicalization candidate after it saved only about
      `123KB` per hidden-eval profile and regressed Node direct artifact timing.
- [x] Reject standalone output-projector label-reuse candidate after it reduced
      native allocation and direct artifact p50 but regressed product
      host-origin client-artifact p50.
- [x] Decide whether structured labels/prefix hashers are still worth doing
      only after confirming they are part of a new representation shape rather
      than repeating retained label-buffer reuse.
- [x] Design an arithmetic-kernel representation candidate that reduces owned
      local word construction without adding state-rotation move traffic.
- [x] Reject output-projector select-stream candidate after it reduced native
      allocation and direct artifact p50 but regressed product client-artifact
      p50 by `15ms-30ms`.
- [x] Reject A2B output recycling candidate after native allocation improved
      but direct artifact p50 regressed on Node and browser.
- [x] Retain local multiplication provenance-fold candidate after
      byte-equivalence, native benchmark, direct WASM artifact, and product
      registration-flow smoke benchmarks.
- [x] Retain raw batch multiplication output provenance-fold candidate after
      byte-equivalence, native benchmark, direct WASM artifact, and product
      registration-flow smoke benchmarks.
- [x] Design the next representation-level candidate around a broader
      output-projector or A2B representation rewrite, with product
      client-artifact p50 as the keep gate.
- [x] Decide from CPU attribution that duplicate hash/provenance reductions
      should come before a broader output-projector or A2B representation
      rewrite.
- [x] Audit remaining physical hash invocations for more duplicated
      left/right provenance derivations that preserve byte-identical outputs.
- [x] Add physical hash-invocation counters if the next duplicated
      hash/provenance candidate is not obvious from code inspection.
- [x] Reject derived-commitment prefix-hasher candidate after native hidden eval
      p50 regressed despite byte-equivalence.
- [x] Add a physical keyed-digest domain breakdown before another keyed-digest
      optimization, so the next candidate can target a specific domain family.
- [x] Gate structured label and prefix-hasher work on profiling evidence that
      identifies a specific material domain.
- [x] Audit `eval_xor_local_word` for an immediate byte-identical fold; no quick
      fold found because paired provenance is already folded and raw side cases
      carry side-specific labels.
- [x] Add a physical derived-commitment domain breakdown; all derived
      commitments classified with `other=0`.
- [x] Audit `eval_mul_local_material` and `eval_mul_local` for any remaining
      byte-identical commitment/provenance folds.
- [x] Retain carry-core local adder candidate after byte-equivalence, native
      benchmark, direct WASM artifact, product registration-flow smoke, full
      crate tests, and WASM signer check.
- [x] Retain A2B source/carry-core candidate after byte-equivalence,
      counter-enabled equivalence, native benchmark, direct WASM artifact, and
      product registration-flow smoke.
- [x] Retain output-boundary paired transport materialization candidate after
      byte-equivalence, native benchmark, direct WASM artifact, and product
      registration-flow smoke.
- [x] Design the next true arena-backed execution model with stage-owned
      lifetimes and materialization only at stage, checkpoint, output, and
      validation boundaries.
- [x] Reject Candidate E2 core-input bridge after byte-equivalence passed but
      native hidden-eval p50 regressed.
- [x] Switch back temporarily to refactor 61/62 registration-critical-path work
      after the retained output-boundary paired transport and rejected E2
      core-input bridge experiments.
- [x] Decide whether to continue product-path work on wallet-iframe
      confirmation/finalize next or resume the larger stage-owned
      `CoreBitWordSide` HSS representation rewrite. Smoke run
      `20260610-024516Z` showed prompt host rendering at about `1ms` p50, so
      the next optimization lane resumes the larger stage-owned
      `CoreBitWordSide` HSS representation rewrite before another finalize
      pass.
- [x] Decide whether packed/arena representation is justified.
- [x] Defer protocol-level redesign until refactors 61/62 and stage-owned
      representation work fail to close the remaining latency gap.
- [x] Implement the first stage-owned `CoreBitWordSide` representation slice
      behind byte-equivalence checks, with stage widths and capacities derived
      only from public circuit shape.
- [x] Benchmark that slice with native hidden-eval, direct HSS WASM artifact,
      and product registration smoke before deciding whether to retain it.
- [x] Retain the first representation slice after byte-equivalence, native,
      direct WASM artifact, product registration smoke, full crate tests, and
      Verus anti-drift all passed.
- [x] If the next representation slice regresses direct artifact p50, reject it
      and use the direct bucket split to choose between round-core local side
      storage and message-schedule accumulation next. The chosen small-sigma
      slice improved and was retained, so no rejection was needed.
- [x] Pick the next stage-owned representation target from either
      `choose`/`majority` round scratch or message-schedule small-sigma
      accumulation, using direct browser worker p50 as the keep gate.
- [x] Pick message-schedule small-sigma as the next attempted slice after
      auditing `Ch`/`Maj` and finding their transient XOR commitments are
      protocol-bound through multiplication-material digests.
- [x] Implement the message-schedule small-sigma `CoreBitWordSide` slice.
- [x] Benchmark the small-sigma slice with hidden-eval equivalence and native
      hidden eval before deciding whether direct WASM is justified.
- [x] Benchmark the small-sigma slice with direct HSS WASM and product
      registration smoke after native hidden eval improved.
- [x] Retain the small-sigma slice after product artifact p50 improved in all
      four smoke scenarios.
- [x] Run full `ed25519-hss` tests and `cargo hss-fv verus-check` after the
      retained small-sigma slice.
- [x] Pick the next optimization lane from either protocol-bound `Ch`/`Maj`
      representation cleanup, A2B/output projector scratch reductions, or
      refactor-61/62 registration-prep critical path work.
- [x] Choose finalize cache/materialization as the next lane after the
      message-schedule small-sigma slice: `Ch`/`Maj` transient commitments are
      protocol-bound, refactor-62 prepare wait is already `0ms` p50/p95, and
      `/wallets/register/finalize` remains a visible route bucket around
      `205ms` to `218ms` p50.
- [x] Benchmark the finalize seed-output prepared-session cache experiment and
      update the keep/reject decision.
- [x] Choose the next optimization lane after the finalize cache win. Current
      live buckets were client artifact construction, wallet-iframe prompt/user
      confirmation time, HSS respond delivery, and preauth HSS prepare; choose
      HSS respond delivery because it was the smallest route-local retained
      win with clear diagnostics.
- [x] Implement one-pass role-separated server-input delivery so the respond
      path shares server input bundles once, seals from those same bundles, and
      preserves the existing public delivery packet/state shape.
- [x] Expose respond delivery sub-buckets for OT open/join, server-input
      open/share/commitment/transcript, sealing, and encoding.
- [x] Validate the one-pass respond path with `hidden_eval_equivalence`,
      `cargo check` for the server WASM export, relay-server type checks, SDK
      type checks, and product smoke.
- [x] Retain the one-pass respond path after native release and product smoke
      both improved the targeted delivery/respond buckets.
- [x] Choose the next optimization lane after the one-pass respond-delivery
      win. The live route-local target was OT open/join in server-input
      delivery, because it was the largest remaining respond-delivery
      sub-bucket.
- [x] Reject the OT label-buffer micro-experiment after native release
      `server_input_delivery` p50 regressed versus the retained one-pass
      baseline.
- [x] Implement prepared OT branch caching: prepare both branch plaintexts,
      AADs, and payload digests during server-session materialization while
      keeping request-dependent shared-point, key-derivation, and encryption
      work in the respond route.
- [x] Validate the prepared OT branch-cache path with
      `hidden_eval_equivalence`, server WASM export compile, relay-server type
      checks, SDK type checks, native release benchmark, repeat native release
      benchmark, and product smoke.
- [x] Retain prepared OT branch caching after native release and product smoke
      both improved the targeted respond-delivery/OT open-join buckets while
      `walletRegisterPrepareWaitMs` stayed `0ms` p50.
- [x] Choose the next optimization lane after the prepared OT branch-cache win.
      Chose client artifact construction because preauth HSS prepare remains
      hidden behind `walletRegisterPrepareWaitMs = 0ms` p50 and wallet-iframe
      prompt rendering is about `1ms` p50.
- [x] Reject fused A2B packing after `hidden_eval_equivalence` passed but
      native `round_core` and `total_hidden_eval` p50 regressed.
- [x] Reject round-constant arithmetic precompute after it improved
      `round_temp1` locally but regressed `round_core` and `total_hidden_eval`
      p50.
- [x] Reject A2B zero-core carry seed after it preserved byte-equivalence but
      regressed `round_new_a_bits`, `round_new_e_bits`, `round_core`, and
      `total_hidden_eval` p50.
- [x] Reject direct output canonicalization after product registration smoke
      regressed client-artifact p50. The candidate improved lower-level
      allocation and one direct browser repeat, but smoke runs
      `20260610-085232Z` and `20260610-085440Z` measured
      `ed25519EvaluationArtifactMs` p50 at `484/482/480/477ms` and
      `480/485/470/473ms`, versus the prior retained baseline around
      `449/451/444/443ms`.
- [x] Revert direct output canonicalization to the previous shared-vector
      canonicalization path and remove the shortcut-only focused test.
- [x] Validate the revert with `hidden_eval_equivalence`, materialization source
      guard, wasm32 library check, native registration-style benchmark, and
      direct browser/WASM benchmark. Native client artifact p50 improved from
      the rejected-candidate run `151.101ms` to `145.156ms`; direct browser
      hidden-eval mean is `203.6ms` with reference match `true`.
- [x] Run the full `ed25519-hss` suite after the revert: `101 passed`,
      `4 ignored`, `330.39s`.
- [x] Resolve the SDK TypeScript `Uint8Array<ArrayBufferLike>` / `BufferSource`
      rebuild errors with explicit owned-`ArrayBuffer` boundary conversions.
- [x] Re-run product registration smoke for the reverted Phase 7 state. Run
      `20260610-093753Z` passed all four scenarios and is the current
      retained-source product rebaseline.
- [x] Reject diagnostic stage-operation-count opt-out after native
      registration-style and product smoke both regressed.
- [x] Design the next larger client-artifact candidate around a real
      representation/protocol-kernel change instead of a local operation-count
      reduction.
- [x] Implement Phase 7B staged output boundary only after adding
      byte-equivalence fixtures for trusted-server and client-masked output
      bundles.
- [x] Benchmark Phase 7B with native hidden-eval / registration-style and
      direct browser/WASM before deciding whether product smoke is justified.
- [x] Run product smoke for Phase 7B and retain the staged output boundary
      after product client-artifact p50 improved.
- [x] Retain Phase 7C repeated-selector select batch after byte-equivalence,
      native/direct-WASM benchmarks, allocation probe, and product smoke.
- [x] Reject Phase 7F select scratch reduction after native hidden-eval p50
      regressed despite lower apparent scratch pressure.
- [x] Reject Phase 7G validated local-word accessor after the first native run
      was flat-to-negative and the repeat regressed `round_core`,
      `output_projector`, and `total_hidden_eval`.
- [x] Record the retained Phase 7E allocation baseline:
      `profile_hidden_eval_for_clear_input` and `probe_checkpoint_output_projector`
      both measured `4.916MB`, `5,123` allocation calls, and `1.402MB` peak
      live above start.
- [x] Reject Phase 7H.1 scalar-reduction scratch-buffer ping-pong after
      allocation improved to `4.522MB` / `5,051` calls but native p50 regressed:
      `total_hidden_eval` `126.459ms -> 127.959ms` and repeat `127.493ms`;
      `output_projector` `23.318ms -> 23.493ms` and repeat `23.566ms`.
- [x] Design the next deeper output-projector candidate as Phase 7I:
      clamped `scalar_a` public-multiple reduction with conditional subtracts
      of `4L`, `2L`, and `L`, gated as a protocol-kernel transcript change.
- [x] Implement and benchmark Phase 7I only if reference scalar correctness,
      hidden-eval equivalence, and native latency support keeping it.
- [x] Retain Phase 7I after scalar reference tests, hidden-eval equivalence,
      native hidden-eval/allocation, direct WASM artifact, product smoke, full
      crate tests, and formal verification all passed.
- [x] Design Phase 7J as the next narrow output-projector candidate:
      canonical-add material-base reuse across add and fixed-modulus subtract
      helpers.
- [x] Implement Phase 7J only if it preserves existing labels/provenance and
      passes hidden-eval equivalence.
- [x] Reject and revert Phase 7J after native timing regressed:
      `output_projector` p50 Phase 7I repeat `16.151ms` to `16.656ms`, and
      allocation stayed flat at `4.160562MB` / `5,031` calls.
- [x] Add an embedded-style native profile benchmark that emits stage/substage
      timing plus allocation and peak-live summaries in one report:
      `crates/ed25519-hss/docs/benchmarks/refactor-64/ddh-hidden-eval-embedded-profile-phase7i-baseline.json`.
- [x] Add an ARM64 Linux native runner for the embedded profile:
      `crates/ed25519-hss/scripts/run_embedded_profile_arm64_linux.sh`.
- [x] Add the iOS physical-device benchmark procedure:
      `crates/ed25519-hss/docs/ios-benchmark-procedure.md`.
- [x] Add the low-memory stress benchmark with configurable p95 allocation,
      allocation-call, and peak-live budgets:
      `benchmark_ddh_hidden_eval_memory_stress`.
- [x] Reject shifted sigma zero-normalization after hidden-eval equivalence
      passed but native message-schedule and total hidden-eval p50 regressed.
- [x] Add wallet-iframe transport diagnostics and use smoke run
      `20260610-130323Z` to rank transport against passkey prompt time and HSS
      artifact construction.
- [x] Decide that another output-projector micro-edit is not justified unless
      it removes canonical-add/A2B logical work, commitment/provenance
      derivation, or emitted transport work beyond Phase 7I/7J.
- [x] Design deeper output-projector and A2B protocol-kernel candidates.
      Phase 8A and Phase 8C specify paired output-projector and A2B v2
      candidates; Phase 8D keeps implementation gated on committed-root or
      equivalent-root binding plus typed backend versioning.
- [x] Implement a backend-versioned candidate only after protocol review
      approves root binding, transcript versioning, downgrade behavior, and
      negative tests.
- [x] Retain the cheaper `Maj` pair-XOR fold under
      `ddh_hss_backend_v3_a2b_maj_pair_xor` after physical counters, native
      hidden eval, direct browser/WASM, full crate tests, and wasm32 checks.
- [x] Audit `Ch` and local-add carry for another cheap helper-level fold; no
      low-risk fold remains because both paths already use pair/core helpers.
- [x] Add the Phase 9B behaviorless `Ch` root scaffold and focused
      sensitivity tests without changing runtime helper behavior.
- [x] Implement and retain the Phase 9B root-bound `Ch` gated-select helper
      after physical counters, native hidden eval, direct browser/WASM, product
      smoke, full crate tests, and wasm32 checks all passed.

## Open Questions

- How much runtime is spent in hashing versus arithmetic versus allocation?
- Can server prepare/finalize parallelize independent public batches safely?
- Does WASM SIMD help the actual hot loops, or are they object/hash-bound?
- What is the lowest embedded class that should be expected to run HSS?
- Should native HSS use the same artifact format as browser HSS?
- What benchmark threshold makes HSS acceptable as the default on iOS?

## Phase 8: Protocol-Kernel Candidate Selection

Status:

- A2B v2 committed-root is implemented and retained after native,
  direct-browser/WASM, and product-smoke validation. Output-projector paired
  root remains a rejected/design-only lane until a stronger proof shape removes
  real canonical-add work.

Current bottleneck read:

- Smoke run `20260610-130323Z` shows wallet-iframe transport is secondary:
  connect p50 is `99ms` / `115ms` for the two wallet-iframe scenarios.
- HSS artifact construction is shared across wallet-iframe, host-origin,
  Passkey, and OTP paths. Product `ed25519EvaluationArtifactMs` p50 is
  `496/489/478/480ms`.
- In the wallet-iframe Ed25519-only HSS worker, `buildArtifactMs` p50 is
  `483ms`, hidden eval p50 is `441ms`, round core p50 is `251ms`, output
  projector p50 is `150ms`, output-projector client-base p50 is `60ms`, and
  output-projector relayer-output p50 is `65ms`.
- Phase 7I already removed real scalar-reduction work. Phase 7J showed that
  canonical-add setup reuse does not move latency, and earlier output
  allocation-only candidates regressed product smoke.

Candidate lanes:

1. Backend-versioned canonical-add / output-projector v2.
   - Target the repeated canonical additions for `x_client_base` and
     `x_relayer_base`.
   - Specify whether a dual-output projector can share transcript material for
     `(a + tau) mod L` and `(a + 2*tau) mod L` while preserving the required
     emitted commitments for `client_output` and `x_relayer_base`.
   - Keep the current backend byte-equivalent. Add v2 only behind an explicit
     backend identifier if labels, provenance, or commitment shape changes.
2. Backend-versioned A2B v2.
   - Target `round_new_a_bits` and `round_new_e_bits`, currently about
     `24ms` to `26ms` each in product worker substeps.
   - Use the Phase 6 mini-spec as the starting point. Do not implement until
     the A2B word root, multiplication-material digest, retained commitments,
     and downgrade behavior are reviewed.
3. Larger round-core stage-owned storage.
   - Target `Ch`, `Maj`, and adder materialization only where the material
     graph proves commitments are not consumed before the new materialization
     boundary.
   - Avoid helper-only `Ch`/`Maj` rewrites; those were already rejected in the
     historical optimization plans.

Todo:

- [x] Write the canonical-add / output-projector v2 mini-spec, including
      backend identifier, transcript roots, retained commitments, removed
      commitments, and downgrade checks.
- [x] Add negative test requirements for mixed v1/v2 output-projector material,
      mismatched labels, wrong owner, wrong width, and altered output bundle
      commitments.
- [x] Estimate the expected p50 win from removing one canonical-add equivalent
      before implementation. Keep only candidates with a plausible product
      artifact improvement above benchmark noise.
- [x] Complete the first feasibility review against the current output
      commitments, projection-mode binding, and server-tau trust boundary.
- [x] Review the fallback order after the paired-projector feasibility pass:
      A2B v2 is the next protocol-kernel candidate, and larger round-core
      representation work stays limited to byte-equivalent slices until a
      backend-versioned proof shape is approved.
- [ ] Implement output-projector v2 only if protocol review approves a paired
      projector root that removes at least one full canonical addition or
      emitted transport pass.
- [x] After A2B v2 retention, choose B2A / multiplication-material root v2 as
      the next HSS protocol-runtime lane.
- [x] Draft the B2A / multiplication-material root v2 review package in
      `crates/ed25519-hss/docs/optimization-6.md`.

### Phase 8A Mini-Spec: Output-Projector Canonical-Add v2

Status:

- design candidate only. This is not approved for implementation until protocol
  review decides whether the retained commitments are sufficient.

Candidate backend identifier:

- `prime_order_ddh_hidden_eval_output_projector_v2`

Current v1 shape:

1. Compute `tau = (tau_client + tau_relayer) mod L`.
2. Compute `x_client_base = (a + tau) mod L`.
3. For client-masked export, compute `client_output = x_client_base + mask`.
   For trusted-server projection, `client_output = x_client_base`.
4. Compute `x_relayer_base = (x_client_base + tau) mod L`.
5. Emit:
   - `canonical_seed` client bundle
   - `client_output` client bundle
   - `x_relayer_base` left/right server transport bundles

The current client artifact product worker split shows `x_client_base` and
`x_relayer_base` canonical additions at about `60ms` and `65ms` p50. A
candidate that removes one full canonical-add equivalent could plausibly save
`50ms` to `65ms` p50 in product artifact construction before benchmark noise.

Candidate v2 shape:

1. Build one output-projector root:
   `{projector_label}/output_projector_v2/root`.
2. Bind the root to:
   - backend identifier
   - projection mode (`trusted_server` or `client_masked`)
   - scalar width (`256`)
   - modulus identifier (`ed25519_l`)
   - `reduced_a_bits` commitments/provenance
   - `tau_bits` commitments/provenance
   - optional client-output mask commitment/provenance
   - output labels: `canonical_seed`, client-output label, and
     `x_relayer_base`
3. Evaluate a fixed-width paired projection kernel:
   - raw `s1 = a + tau`
   - raw `s2 = s1 + tau`
   - canonical `x_client_base = s1 mod L`
   - canonical `x_relayer_base = s2 mod L`
4. The kernel may only be retained if it removes at least one current logical
   canonical-add equivalent. Acceptable removal examples:
   - avoid materializing selected `x_client_base` before deriving
     `x_relayer_base`
   - fuse the two canonicalization selectors under one root while preserving
     separate emitted output commitments
   - avoid one emitted transport/canonicalization pass without removing required
     `x_relayer_base` transport bundles
5. Emit the same public wire bundles as v1 unless the backend version explicitly
   changes artifact metadata and request/persistence boundaries.

Retained commitments:

- Output bundle commitments for `canonical_seed`, `client_output`, and
  `x_relayer_base`.
- Input commitments/provenance for `reduced_a_bits`, `tau_bits`, and optional
  client-output mask.
- A backend-version-bound projector root that commits to labels, projection
  mode, scalar width, and modulus identity.

Possible removed commitments, subject to review:

- Intermediate selected `x_client_base` material if it does not leave the
  projector boundary in client-masked mode.
- Per-step canonical-add intermediate commitments that are currently only used
  to prove the second add. The emitted output commitments must remain.

Rejected shortcut:

- Do not simply compute `x_relayer_base = (a + 2*tau) mod L` with two generic
  canonical reductions. That still performs two modular additions/reductions
  and may add an extra reduction path because `a + 2*tau < 3L`. It is only worth
  implementing if the paired kernel demonstrably removes a current full
  add/sub/select equivalent.

Negative test requirements:

- v1 artifact rejected by v2 backend and v2 artifact rejected by v1 backend.
- mixed v1/v2 projector roots rejected.
- wrong projection mode, owner, output label, scalar width, or modulus id
  rejected.
- altered `client_output` or `x_relayer_base` output bundle commitment rejected.
- replay with the same output values but different projector label rejected.
- client-masked mode rejected if mask binding is absent or uses the wrong owner.

Implementation gate:

- Protocol review must approve retained/removed commitment rules.
- Constant-time review must confirm only public loop indices, public projection
  mode, and public backend metadata control branches.
- Native and direct-WASM microbenchmarks must show a clear output-projector
  win before product smoke.
- Product `ed25519EvaluationArtifactMs` p50 must improve by more than expected
  smoke noise before retaining.

Feasibility review:

- The simple rewrite `x_relayer_base = (a + 2*tau) mod L` is not a useful
  current-backend candidate. Computing `2*tau mod L` plus `a` still performs
  two canonical additions, and reducing a raw `a + 2*tau` value is harder than
  the current second add because the value is below `3L`, not below `2L`.
- The current `x_relayer_base` proof consumes the committed
  `x_client_base` word. Skipping that materialization changes the proof shape
  and must be backend-versioned.
- Trusted-server projection emits `x_client_base` directly as client output, so
  that output commitment must remain.
- Client-masked projection does not emit raw `x_client_base`, but it still uses
  the canonical `x_client_base` as the input to client blinding, and it emits a
  mode-bound `client_output` commitment.
- The fast `right_shared_bits` helper cannot be used for server tau. A
  `DdhHssSharedWord` carries both shares; using that path for tau would expose
  hidden server input. It remains appropriate for client-provided mask material.
- The only plausible Phase 8A implementation is a paired projector root that
  keeps final output commitments while proving `x_client_base` and
  `x_relayer_base` together. Its expected win is lower than a naive `65ms`
  subtraction unless it actually removes a full canonical add/sub/select
  equivalent.

Decision:

- Do not implement Phase 8A as a byte-equivalent cleanup. It is a protocol
  change. Continue only after protocol review approves the paired-root proof
  shape; otherwise pivot to A2B v2 or larger round-core representation work.

## Phase 8B: Round-Core Representation Feasibility

Status:

- initial audit complete. No byte-equivalent code slice is approved yet.

Current bottleneck read:

- Product worker split in `20260610-130323Z` shows round core at `251ms` p50.
  The visible round sub-buckets are `Ch` `25ms`, `Maj` `34ms`,
  `new_a_bits` `24ms`, `new_e_bits` `24ms`, `temp1` `9ms`, `temp2` `4ms`,
  and sigma around `7ms` each.
- The retained `CoreBitWordSide` slices already cover round sigma and
  message-schedule small sigma where XOR intermediates could remain
  core/provenance-only until a known materialization boundary.

Audit result:

- `Ch` materializes `yz` and feeds it to
  `eval_mul_local_bit_pair_batch_raw_xor_base_public_into`; multiplication
  material binds the operand commitments.
- `Maj` feeds `x`, `y`, and `z` through
  `eval_maj_local_bit_pair_batch_raw_public_into`; the majority multiplication
  material binds operand commitments.
- `temp1`, `temp2`, and `state3` convert Boolean words through B2A material
  that hashes per-bit provenance and commitments.
- `new_a_bits` and `new_e_bits` cross the secure A2B boundary. The current
  A2B proof binds arithmetic share commitments, zero material, per-bit sum
  provenance, carry multiplication material, and serial carry order.

Decision:

- Do not implement another helper-level `Ch`, `Maj`, B2A, or A2B scratch
  rewrite under the current backend. The remaining meaningful round-core wins
  require either:
  - backend-versioned A2B v2 from the existing Phase 6 mini-spec, or
  - a backend-versioned B2A/multiplication-material root that explicitly changes
    retained commitments and downgrade behavior.

Next tasks:

- [x] Audit current round-core materialization consumers after Phase 7I.
- [x] Decide that helper-level `Ch`/`Maj` rewrites remain blocked by
      multiplication-material commitments.
- [x] Decide that `new_a_bits` / `new_e_bits` require A2B v2 for a meaningful
      latency win.
- [x] Write a protocol-review-ready A2B v2 package before implementation.
- [x] Record that A2B v2 is not implementation-ready with a digest-only root;
      require committed-root or equivalent-root binding before code changes.
- [x] Promote A2B v2 from design-only to implementation only after protocol
      review approves root binding, retained commitments, downgrade behavior,
      and negative tests.
- [x] Keep refactor-61/62 registration-path overlap as the fallback lane if
      post-cleanup A2B validation fails or further HSS-runtime work stalls.

## Phase 8C: A2B v2 Protocol Review Package

Status:

- review package drafted. No implementation is approved yet.

Target:

- `round_core/{round}/new_a_bits`
- `round_core/{round}/new_e_bits`

Measured opportunity:

- Product worker split in `20260610-130323Z` shows `new_a_bits` at `24ms` p50
  and `new_e_bits` at `24ms` p50 in wallet-iframe Ed25519-only. A full
  replacement cannot save the entire `48ms`, because output bits still need to
  be emitted and carry semantics still need to be proven. A plausible retained
  win needs to save enough of those two buckets to move product
  `ed25519EvaluationArtifactMs` beyond smoke noise.

Current v1 proof obligations:

- bind left/right arithmetic share commitments
- bind left/right arithmetic share provenance digests
- decompose each arithmetic share into ordered bits
- bind zero material to both arithmetic shares
- preserve serial carry order
- bind multiplication material for each carry gate
- emit committed Boolean output bits for the caller

Proposed v2 root:

- Root label: `{label}/a2b_v2/root`
- Root domain: `phase-a-arith-to-bool-v2-root`
- Root inputs:
  - backend identifier `prime_order_ddh_hidden_eval_a2b_v2`
  - caller label
  - word width
  - left/right arithmetic share commitments
  - left/right arithmetic share provenance digests
  - left/right arithmetic share-side tags
  - carry-order policy id
  - output commitment policy id

Proposed v2 carry material:

- Carry label: `{label}/a2b_v2/carry/{idx}`
- Carry material domain: `phase-a-arith-to-bool-v2-carry`
- Carry material inputs:
  - root digest
  - bit index
  - previous carry provenance digest
  - decomposed left/right bit provenance digests
  - `xor_ab` provenance digest
  - `a_xor_carry` provenance digest

Retained commitments:

- arithmetic input share commitments
- emitted Boolean output bit commitments
- optional root commitments, if review decides digest-only roots do not bind
  enough material

Candidate removed commitments:

- per-bit committed left/right decomposition words
- per-bit zero commitments
- intermediate committed `xor_ab`, `a_xor_carry`, `carry_gate`, and
  `next_carry` values that never leave the A2B boundary

Semantic equivalence:

- v2 output bits must decode to the same value as v1 for every tested
  arithmetic word.
- v2 must preserve fixed-width `mod 2^n` semantics for widths `1..=64`.
- v2 must preserve the existing public loop shape. Branches and indexes may
  depend on public width and bit index only.

Downgrade and negative tests:

- reject v2 material under a v1 backend identifier and v1 material under a v2
  backend identifier
- reject mixed v1/v2 A2B material inside one hidden-eval artifact
- reject wrong caller label
- reject wrong width
- reject swapped left/right share sides
- reject altered arithmetic share commitment
- reject altered arithmetic share provenance digest
- reject altered root digest
- reject skipped or reordered carry index
- reject altered emitted output bit commitment

Implementation sequence if approved:

1. Add a typed backend-version discriminator for hidden-eval kernels.
2. Add root/carry material builders for A2B v2.
3. Keep v1 byte-equivalent tests unchanged.
4. Add v2 semantic-equivalence tests against v1 decoded values.
5. Add v2 downgrade and negative tests.
6. Add native benchmark first. Continue only if `round_new_a_bits`,
   `round_new_e_bits`, `round_core`, and total hidden eval improve.
7. Add direct-WASM artifact benchmark.
8. Run product registration smoke.
9. Run full `ed25519-hss` tests and formal verification after retaining.

Open review questions:

- What exact committed-root or equivalent-root binding replaces the current
  per-bit operand commitments?
- Does carrying multiplication material from root/provenance without per-bit
  operand commitments preserve the intended transcript audit surface?
- Which intermediate values need commitments for downgrade resistance rather
  than semantic correctness?
- Should B2A receive a matching v2 root at the same backend version, or can A2B
  change independently?
- How should backend versioning appear in persisted/browser worker artifacts so
  stale v1/v2 material cannot mix?

## Phase 8D: A2B v2 Implementation Readiness

Status:

- implemented and retained as `ddh_hss_backend_v2_a2b_committed_root`.

Review decision:

- A digest-only A2B root is not sufficient for implementation. The current
  multiplication material path hashes operand commitments; removing per-bit
  operand commitments without replacing that binding changes more than the A2B
  representation.
- Protocol review selected committed root material per side. The implementation
  carries typed backend and A2B kernel versions through params, evaluation keys,
  artifacts, worker/session state, benchmark reports, and parser boundaries.

Constant-time review notes:

- The proposed v2 loop shape can be constant-time if branches and indexes
  depend only on public word width and public bit index.
- No implementation should introduce division, modulo, table lookup, allocation
  sizing, or early return based on arithmetic share values, decomposed bits, or
  carry bits.
- Carry order is public and fixed, but carry values are secret-derived; carry
  state may influence bit-masked arithmetic, not control flow.

Required implementation preconditions:

- [x] Pick and document committed-root or equivalent-root binding.
- [x] Add a typed hidden-eval kernel version before changing A2B semantics.
- [x] Add downgrade tests for v1/v2 mismatch at artifact, worker, and
      request/persistence boundaries.
- [x] Add v2 negative tests for root digest, carry order, emitted output
      commitments, width, label, and share-side mismatch.
- [x] Add constant-time review notes beside the implementation before native
      benchmark work.

Decision:

- Retain A2B v2 committed-root. Focused validation and narrow tamper coverage
  are complete; continue latency work in broader executor/protocol lanes.
- The next protocol-runtime lane is B2A / multiplication-material root v2.
  It targets the remaining round-core paths where the current proof shape still
  consumes per-bit commitments in B2A and local multiplication material.
- The `CoreBitWordStage` stage-identity guard slice is retained as
  type/validation hardening. It passed `hidden_eval_equivalence`, full
  `ed25519-hss` tests, `cargo hss-fv verus-check`, and direct browser/WASM
  reference matching. Native p50 after the guard was `122.902ms`, repeat
  `125.119ms`, versus the retained A2B v2 best report at `118.436ms`, so no
  product smoke was run for this guard-only slice.
- B2A root and multiplication-material root are now staged backend versions.
  The first B2A-only core-sigma experiment failed the native keep gate and was
  reverted. A second `ddh_hss_backend_v3_b2a_root` attempt needs a stronger
  B2A committed-root proof shape in
  `crates/ed25519-hss/docs/optimization-6.md`. `Ch`/`Maj`
  multiplication-material root work is now the next design target because it
  can address the larger remaining `eval_xor_local_word` and
  `eval_mul_local_material` buckets.
- Phase 9 boundary-graph audit is complete in
  `crates/ed25519-hss/docs/optimization-6.md`. The first implementation after
  protocol approval should target `Maj` transient `xy`/`xz` XORs plus the
  gated product, then `Ch` `yz` plus gated select, then local-add carry
  material. This ordering targets the largest remaining buckets while keeping
  output/transport commitments intact.
- Phase 9A first-slice spec is drafted for the `Maj` transient XOR/multiply
  root. It requires backend/kernel versioning, operation-kind and boundary-kind
  enums, root-bound `xy`/`xz` material, final committed majority output, and
  negative tests for version, kind, boundary, index, width, side, root, and
  operand tampering before benchmark work.
- Phase 9B and 9C specs are drafted for `Ch` gated-select and local-add carry
  roots. They extend the same root model only after the `Maj` slice proves the
  binding and counter movement, with final `choose` and `sum` outputs retained
  as committed local values.
- Phase 9D approval/readiness checklist is drafted. Rust implementation remains
  gated on accepting the Phase 9A `Maj` binding for root builders and helper
  behavior changes. The typed scaffold plus parser tests have landed with no
  helper behavior change.

June 11 binding decision:

- Use committed A2B root material per share side.
- Do not use a digest-only root. The root material is the committed replacement
  for the operand commitments that current multiplication material hashes.
- The root binds backend/kernel version, caller label, public width, arithmetic
  input commitments, arithmetic provenance digests, share-side tags,
  carry-order policy, and output commitment policy.
- The root does not bind actual emitted output commitments directly. That would
  be circular because carry material is needed before those output commitments
  exist. The final A2B boundary must bind the root digest and actual emitted
  output bit commitments together.
- Each carry-material derivation binds the root commitment, public bit index,
  previous carry provenance, decomposed bit provenance, `xor_ab` provenance,
  and `a_xor_carry` provenance.
- Implemented code step: typed A2B kernel-version scaffold, committed root/carry
  material, stale-backend downgrade rejection, and carry-index hardening.
- Validation step: A2B v2 now has focused negative coverage for altered
  arithmetic commitments/provenance, root labels/digests, carry index/order,
  width/share-side metadata, and emitted output bit commitments at the A2B
  boundary digest. Public artifact rejection for tampered emitted output is
  covered by `protocol_validation`.
- Semantic step: the A2B v2 conversion now round-trips decoded output bits
  against the pre-A2B Boolean reference for every width `1..=64`.
- Post-cleanup formal verification after deleting obsolete backend/A2B kernel
  variants passed: `cargo hss-fv verus-check` reported `96 verified, 0 errors`;
  anti-drift reported `10 passed`.

## Keep And Revert Rules

Keep an optimization only if:

- protocol validation passes
- constant-time review finds no new secret-dependent behavior
- benchmark results improve a measured target consistently
- complexity is proportional to the win
- transcript or backend-version impact is explicit

Revert or redesign if:

- labels or provenance drift unexpectedly
- a speedup only appears in one noisy scenario
- diagnostics start influencing execution
- object representation gets harder to validate without measurable gain
- protocol changes are made without a spec and backend-version decision
