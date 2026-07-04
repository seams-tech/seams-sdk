# HSS Optimize Registration

Date updated: June 8, 2026

Status: HSS client speed-profile optimization, scoped worker-resident client
HSS handles, two label-buffer executor cleanups, fine-grained hidden-eval worker
diagnostics, and the finalize cached-session fast path have been benchmarked and
kept.
Full registration benchmark results are tracked in
`docs/refactor-59-optimize.md`.

## Summary

This plan is for speeding up the active Ed25519 single-key HSS registration flow.

The rule for this work is simple:

- each optimization must be implemented in isolation
- each optimization must be measured before and after
- each optimization is only kept if it meaningfully improves registration speed
- if the speed win is weak, inconsistent, or comes with bad complexity or risk,
  revert it and move on

This is a performance plan, not a speculative redesign doc.

## Relationship To Refactor 59

`docs/refactor-59-optimize.md` owns the full registration benchmark:

- SDK call start through usable wallet state
- auth proof collection
- HSS registration ceremony
- optional ECDSA bootstrap
- NEAR account creation and key visibility
- relay persistence
- client IndexedDB/session persistence
- post-registration readiness checks

This plan owns the HSS slice of that benchmark. Resume this plan when
`refactor-59` can report the registration HSS buckets clearly enough to rank
them against the full flow.

`docs/refactor-64-hss-protocol-runtime-latency.md` owns deeper HSS runtime and
protocol performance work that is not registration-route-specific. Keep this
plan focused on registration measurements, route-level registration impact, and
the current Phase E1 candidate handoff.

Keep non-HSS work in `refactor-59` or a focused follow-up plan. Examples:

- account-exists preflight
- managed registration grant timing
- NEAR account creation and key visibility
- relay persistence outside HSS ceremony state
- client local persistence after HSS completes
- ECDSA registration bootstrap and storage

## Current State

Current code state:

- `wasm/hss_client_signer` now uses release `opt-level = 3` to prioritize
  registration and HSS active-path latency over bundle size.
- Server-side HSS ceremony handles are implemented for session and registration
  paths. Finalize no longer reposts the full prepared server session.
- Registration HSS routes currently use `/wallets/register/start`,
  `/wallets/register/hss/respond`, and `/wallets/register/finalize`.
- Server HSS prepare/respond/finalize timing logs exist for registration.
  Server-owned ceremony diagnostics now split prepare into OT reconstruction,
  server input, result assembly, and output sealing buckets, and split finalize
  into artifact decode, serialized server-session materialization, report
  finalization, and report encoding buckets.
- Client-side HSS worker calls now cache the materialized client session across
  `prepare_client_request` and `build_client_owned_staged_evaluator_artifact`
  with an ephemeral worker handle. The worker consumes the build handle after
  use, expires stale handles after five minutes, and falls back to serialized
  state for direct/script runtimes.
- Browser worker payloads still use base64url strings for the large
  one-shot artifacts. Binary worker payloads are not implemented.
- Browser registration benchmarking now captures sanitized HSS client timings,
  HSS worker-boundary diagnostics, and gated relay route diagnostics from the
  wallet-iframe path. The full prepared-SDK 5-run smoke baseline measured
  Ed25519-only wallet-iframe registration at:
  - full browser registration duration: p50 `3,812ms`, p95 `4,624ms`
  - SDK registration duration: p50 `2,435ms`, p95 `2,932ms`
  - HSS client `prepare`: p50 `380ms`, p95 `385ms`, `23,046` response bytes
  - HSS client `respond`: p50 `106ms`, p95 `117ms`, `419,361` response bytes
  - HSS worker `build_client_owned_staged_evaluator_artifact`: p50 `738ms`,
    p95 `748ms`, `464,999` request bytes, `154,567` response bytes
  - HSS worker `prepare_client_request`: p50 `126ms`, p95 `135ms`
  - relay `/wallets/register/start`: p50 `376ms`, p95 `544ms`, dominated by
    server `registrationHssPrepareMs`
  - relay `/wallets/register/finalize`: p50 `457ms`, p95 `467ms`, dominated by
    server `registrationHssFinalizeMs`
- Registration-start prepare pipelining is not implemented as a public route
  shape change. Treat it as a future optimization candidate only after a fresh
  baseline.
- The retained worker-handle benchmark (`20260607-142520Z`) measured
  `materializeSessionMs` p50/p95 at `0ms` across all four smoke scenarios.
  Staged-artifact build p50 moved `736ms -> 688ms` for wallet-iframe
  Ed25519-only, `736ms -> 718ms` for wallet-iframe Ed25519+ECDSA,
  `734ms -> 686ms` for host-origin Ed25519-only, and `736ms -> 686ms` for
  host-origin Ed25519+ECDSA versus the label-buffer baseline.
- A follow-up hidden-eval helper-label cleanup was retained after a forced
  SDK/WASM rebuild and two smoke runs (`20260607-144442Z` and
  `20260607-144642Z`). The repeat run improved `hiddenEvalTotalMs` p50/p95 in
  all four scenarios versus the worker-handle baseline while preserving label
  bytes and arithmetic shape. The largest repeat win was wallet-iframe
  Ed25519+ECDSA, where `hiddenEvalTotalMs` moved p50 `670ms -> 638ms` and p95
  `676ms -> 642ms`.
- The output-projector reduce/select label-buffer candidate was rejected after
  smoke run `20260607-150450Z`. It passed the HSS protocol suite, but benchmark
  results were weak and noisy, with regressions in the ECDSA scenarios. The
  candidate was reverted.
- Fine-grained hidden-eval worker diagnostics were exposed and benchmarked in
  smoke run `20260607-152114Z`. The run passed all four scenarios and ranked the
  remaining HSS client-owned hidden-eval cost as:
  - round core: p50 roughly `296ms` to `301ms`
  - output projector: p50 roughly `270ms` to `281ms`
  - message schedule: p50 roughly `58ms` to `59ms`
  - round-core A2B conversion for `new_a_bits` and `new_e_bits`: about
    `45ms` to `46ms` p50 each
  - round-core `maj`: about `38ms` to `39ms` p50
  - round-core `ch`: about `31ms` to `32ms` p50
- Binary worker payloads are now lower priority for latency because worker
  decode, materialization, and encode are near noise on the retained
  worker-handle path. Keep binary payloads as transport cleanup, and prioritize
  a spec-backed hidden-eval core patch for the next latency experiment.
- The finalize cached-session fast path was benchmarked and retained in
  registration smoke run `20260608-051326Z`, then remeasured with start-route
  branch diagnostics in `20260608-053047Z`. It reuses the cached prepared server
  session when finalize receives a staged artifact as bytes, while preserving
  the serialized-state fallback if the cache entry is gone. The retained result:
  - `registrationHssFinalizeSerializedSessionMaterializeMs` moved from about
    `241ms` to `244ms` p50 to `0ms` p50 in all four smoke scenarios
  - `/wallets/register/finalize` moved from about `455ms` to `462ms` p50 to
    `216ms` to `222ms` p50
  - SDK registration p50 improved by `266ms` to `484ms` versus the
    `20260608-030241Z` pre-finalize-cache baseline
  - latest retained SDK registration p50 is `1933ms` to `2134ms`; latest
    browser-observed p50 is `2816ms` to `3228ms`
- Start-route branch diagnostics from `20260608-053047Z` show
  `/wallets/register/start` remains `371ms` to `373ms` p50 because signing-root
  server-input derivation (`366ms` to `368ms` p50) and server-session
  preparation (`356ms` to `359ms` p50) run in parallel. Inside preparation,
  `prepare_prime_order_succinct_hss` accounts for `354ms` to `357ms` p50.
- The next HSS arithmetic change must be designed before implementation. The
  target is the round-core A2B/carry conversion path first, then the `maj`/`ch`
  boolean batch helpers. The spec needs to pin transcript labels, provenance
  digests, gate schedule, output equivalence, and constant-time constraints.

Historical full active-path test runs showed the Ed25519 HSS ceremony at roughly
`2.8s` to `3.3s` total. The main buckets are:

- server `prepare`: about `380ms` to `480ms`
- server `respond`: about `340ms` to `410ms`
- client `evaluate`: about `1.16s` to `1.34s`
- server `finalize`: about `540ms` to `650ms`
- client `complete`: about `170ms` to `210ms`

Native release profiling still points to the HSS hidden-eval core as the
dominant protocol cost, with the browser active path adding worker, WASM
boundary, serialization, and route overhead around it.

The older HSS-specific phase notes below are retained for context. The current
canonical registration checklist starts at
`Current Registration Optimization Plan`.

### Completed Phase 0: HSS Client Wasm Build Profile

Change:

- benchmarked `wasm/hss_client_signer` release `opt-level` values `"z"`, `"s"`,
  `2`, and `3`

Bundle-size impact:

- `opt-level = "z"`: `482,464` raw bytes, `217,929` gzipped bytes
- `opt-level = "s"`: `526,938` raw bytes, `232,814` gzipped bytes
- `opt-level = 2`: `712,241` raw bytes, `284,066` gzipped bytes
- `opt-level = 3`: `742,843` raw bytes, `289,496` gzipped bytes
- `opt-level = "s"` saves `215,905` raw bytes and `56,682` gzipped bytes
  versus `opt-level = 3`
- `opt-level = 2` saves `30,602` raw bytes and `5,430` gzipped bytes versus
  `opt-level = 3`

Latency impact from `pnpm -C tests test:threshold-ed25519:active-path`:

- `opt-level = "z"`: total mean `2,830.7ms`, client `evaluate` mean
  `1,151.7ms`, client `complete` mean `171.3ms`
- `opt-level = "s"`: total mean `2,485.8ms`, client `evaluate` mean
  `872.8ms`, client `complete` mean `155.5ms`
- `opt-level = 2`: total mean `2,296.8ms`, client `evaluate` mean `803.2ms`,
  client `complete` mean `96.2ms`
- `opt-level = 3`: total mean `2,227.5ms`, client `evaluate` mean `777.2ms`,
  client `complete` mean `93.5ms`
- `opt-level = "s"` is about `12.2%` faster than `"z"` by total ceremony mean
- `opt-level = 2` is about `18.9%` faster than `"z"` by total ceremony mean
- `opt-level = 3` is about `21.3%` faster than `"z"` by total ceremony mean
- `opt-level = "s"` gives back about `258.3ms` total ceremony mean versus
  `opt-level = 3`
- `opt-level = 2` gives back about `69.3ms` total ceremony mean versus
  `opt-level = 3`

Decision:

- June 7, 2026 update: use `opt-level = 3` as the active profile for now.
  Current-code benchmarking showed a stable HSS active-path win of about
  `231ms` median ceremony time, while adding about `78.7KB` gzipped WASM versus
  the previously tracked artifact.
- Revisit this if the full registration benchmark shows HSS is no longer a
  top-three registration latency bucket, or if bundle size becomes the dominant
  product constraint.

Current-code active-path comparison:

| Profile | Raw WASM | Gzipped WASM | Ceremony median | Ceremony mean | Ceremony p95 | Evaluate median | Complete median |
|---|---:|---:|---:|---:|---:|---:|---:|
| `opt-level = "s"` tracked baseline | `710,803` bytes | `301,937` bytes | `2,445.5ms` | `2,445.8ms` | `2,476ms` | `828.5ms` | `153ms` |
| `opt-level = 3` | `1,000,422` bytes | `380,674` bytes | `2,214.5ms` | `2,214.2ms` | `2,234ms` | `759ms` | `92ms` |
| Delta | `+289,619` bytes | `+78,737` bytes | `-231ms` (`-9.4%`) | `-231.6ms` (`-9.5%`) | `-242ms` | `-69.5ms` | `-61ms` |

### Historical Phase A: Add Evaluate Substage Instrumentation

Goal:

- make the browser `evaluateMs` bucket explain itself before changing runtime
  shape

Work:

- add worker-side timing fields around:
  - worker queue wait
  - WASM initialization
  - worker request and response payload byte counts
  - request payload normalization
  - base64 decode
  - bincode/state decode
  - evaluator runtime materialization
  - OT-selected client input reconstruction
  - server input delivery open
  - hidden-eval trace execution
  - staged artifact assembly and encode
- thread these timings through the worker response in a diagnostics-only field
  that cannot influence control flow
- log total request and response byte counts for the worker message

Current state:

- implemented browser HSS client worker-boundary diagnostics for queue wait,
  WASM initialization, WASM call duration, total duration, and request/response
  payload field sizes
- SDK type-check and the script-level HSS active-path suite pass with the
  diagnostics path present
- the script-level suite does not emit the browser-worker diagnostics because it
  exercises the script/direct worker path; capture from a browser-worker
  registration benchmark before choosing worker-resident handles or binary
  payloads

Keep rule:

- always keep if the instrumentation stays boundary-local and does not alter
  protocol semantics

Validation:

- `pnpm -C tests test:threshold-ed25519:active-path`

### Historical Phase B: Worker-Resident HSS Session Handles

Goal:

- avoid repeated state serialization, base64 decode, bincode decode, and runtime
  materialization across the HSS client worker calls

Target shape:

```ts
type HssClientWorkerSession =
  | { kind: 'prepared'; handle: HssClientSessionHandle }
  | { kind: 'client_request_prepared'; handle: HssClientSessionHandle }
  | { kind: 'evaluated'; handle: HssClientSessionHandle };
```

Work:

- [x] make `prepare_client_request` store the materialized runtime/session state
      behind a short-lived worker handle
- [x] make `build_client_owned_staged_evaluator_artifact` consume the handle on
      the browser-worker path
- [x] keep direct/script runtimes on the serialized-state branch through a
      discriminated client-request envelope
- [x] add handle expiry and build-time handle cleanup
- [ ] extend handle use to output opening only after a fresh benchmark shows the
      complete/open path is worth moving
- [ ] add explicit browser-worker tests for handle expiry and build-time cleanup
- keep durable and HTTP boundaries encoded as today; the worker-local path can
  use handles because it is process-local and ephemeral
- encode lifecycle with discriminated unions so call sites cannot evaluate with
  an unprepared or completed handle

Security constraints:

- client-owned evaluator state stays only in the client worker
- `clientOutputMaskB64u` remains required for client-owned staged artifact
  construction and client output opening
- diagnostics must never carry raw client input shares, raw mask material, or
  opened `xClientBaseB64u`

Expected effect:

- lower `evaluateMs` and `completeMs`
- lower worker message bytes
- lower browser GC pressure during the ceremony

Validation:

- worker type fixtures for invalid handle lifecycle transitions
- focused unit tests for cleanup on success, failure, and timeout
- `pnpm -C tests test:threshold-ed25519:active-path`
- `pnpm check:formal-verification` if boundary shapes change

### Historical Phase C: Binary Worker Payloads

Goal:

- remove base64 overhead from browser worker messages for process-local data

Work:

- replace worker-local HSS byte payload strings with `Uint8Array` where the data
  does not cross HTTP, persistence, or public SDK boundaries
- use transferables for large one-shot buffers
- keep HTTP payloads and persistent records in canonical encoded form unless a
  separate API migration changes those boundaries
- make boundary parsers normalize raw `ArrayBuffer`, `Uint8Array`, and encoded
  strings into narrow internal byte types at the worker edge

Candidate payloads:

- evaluator driver state
- evaluator OT state
- server input delivery after HTTP decode
- staged evaluator artifact before HTTP encode
- finalized client output packet after HTTP decode

Expected effect:

- lower worker transfer time
- lower encode/decode time
- lower allocation and GC pressure

Validation:

- static type fixtures rejecting raw string use inside core HSS worker logic
- active-path timing comparison before and after
- browser worker tests for transferable ownership behavior

### Historical Phase D: Wallet Registration Start Prepare Pipelining

Goal:

- remove one visible registration round trip by starting the HSS server prepare
  work during `/wallets/register/start`

Work:

- return the Ed25519 HSS prepared-session branch from
  `/wallets/register/start` after WebAuthn `create()` verification
- move registration-time HSS prepare ownership into the wallet registration
  ceremony service path
- delete the registration-specific client call to
  `/registration/threshold-ed25519/hss/prepare`
- keep session HSS prepare routes for existing-key flows such as
  reconstruction, repair, export, and warm-session work
- bind the prepared session to `registrationCeremonyId`,
  `walletId`, the canonical registration intent digest, the Ed25519
  signer spec, runtime policy scope, participant ids, and expiry

Expected effect:

- lower visible registration ceremony latency by roughly one `prepare` request
  when `/wallets/register/start` is already on the critical path

Validation:

- route tests proving wallet-registration prepared sessions cannot be reused
  across wallet, account, signing-root, intent digest, or participant
  changes
- active-path timing comparison before and after
- wallet registration ceremony grant tests

### Historical Phase E: Executor Core Cleanup

Goal:

- reduce the real hidden-eval cost after wrapper and route overhead are lower

Work:

- precompute stable labels and avoid per-round string formatting in the hot
  message schedule and round-core loops
- replace repeated `Vec` cloning in schedule and round continuations with
  fixed-size or reusable buffers where the stage shape is statically known
- keep round state in fixed arrays where possible
- reduce arithmetic-to-bit conversion frequency only when the algebra proof is
  clear and covered by tests or formal specs
- revisit output-projector additions after the worker/transport changes land,
  using the current `ClientMaskedProjection` algebra as the only production path

Expected effect:

- lower `round_core`, `message_schedule`, and `output_projector` timings
- smaller top-line impact than worker-resident state until the browser wrapper
  overhead is reduced

Validation:

- native release benchmark:
  `cargo run --release --bin benchmark_ddh_hidden_eval -- --primitive-warmup 0 --primitive-iterations 1 --stage-warmup 0 --stage-iterations 1 --samples 6`
- full active-path test:
  `pnpm -C tests test:threshold-ed25519:active-path`
- formal verification updates for any algebraic projector or carry conversion
  change

## HSS Protocol Todo

- [x] Capture a fresh active-path baseline with the size-optimized WASM profile.
- [x] Trial speed-optimized HSS client WASM and record size/latency impact.
- [x] Switch `wasm/hss_client_signer` release profile to `opt-level = 3` after
      current-code active-path benchmarking.
- [x] Implement relay-side HSS ceremony handles to reduce finalize payload size.
- [x] Add server-side HSS prepare/respond/finalize timing logs for registration.
- [x] Add HSS client worker-boundary diagnostics for queue/init/WASM-call time
      and payload sizes.
- [x] Capture sanitized HSS client prepare/respond timings from a browser
      wallet-iframe registration probe.
- [x] Capture HSS client worker-boundary diagnostics from a browser-worker
      registration benchmark.
- [x] Decide whether the browser registration path should emit worker-boundary
      diagnostics, or whether route-level HSS client timings are sufficient for
      the next optimization decision.
- [x] Add Rust/WASM internal evaluate substage instrumentation if browser-worker
      diagnostics show `wasmCallMs` dominates.
- [x] Keep the first tiny executor cleanup: replace per-bit local-addition
      `format!` allocations with reusable label buffers after protocol tests and
      the `refactor-59` smoke benchmark passed.
- [x] Implement scoped historical Phase B worker-resident client HSS handles for
      the registration staged-artifact build path.
- [x] Keep the second tiny executor cleanup: reuse child-label buffers in
      Boolean-to-arithmetic conversion helpers after protocol tests and two
      `refactor-59` smoke runs passed.
- [x] Reject the output-projector reduce/select label-buffer cleanup after the
      smoke benchmark showed weak/noisy results.
- [x] Expose fine-grained hidden-eval substage timings through worker
      diagnostics and benchmark smoke run `20260607-152114Z`.
- [x] Expose fine-grained server-owned HSS prepare/finalize sub-bucket
      diagnostics through the server ceremony WASM export.
- [x] Decide whether binary worker payloads should precede deeper executor
      work. They should not lead the latency path now; keep them as transport
      cleanup.
- [x] Write a focused round-core A2B/boolean-helper optimization spec before
      changing protocol arithmetic.
- [x] Implement and reject the first spec-backed round-core A2B destination
      reuse candidate. Native p50 improved, but browser/WASM smoke run
      `20260607-171754Z` showed no HSS worker improvement, so no code was
      retained.
- [ ] Implement historical Phase C binary worker payloads only if transport
      cleanup becomes product-relevant or a fresh benchmark makes payload
      transfer dominant again.
- [x] Re-benchmark the rejected A2B destination-reuse candidate against retained
      run `20260607-152114Z`.
- [x] Add direct Ed25519 HSS WASM artifact benchmark for faster candidate
      comparisons before full registration smoke runs.
- [x] Add logical hidden-eval object counters to the direct Ed25519 HSS WASM
      artifact benchmark.
- [ ] Pick any further Phase E executor cleanup after the logical counters,
      allocator evidence, or a representation audit identify browser/WASM
      object churn as the limiting factor.
- [ ] Update security and README language if any public timing or boundary claim
      changes.

## Current Registration Shape

The current registration flow does this:

1. validate account input and registration intent
2. complete the auth-method proof (`webauthn_registration` or Email OTP
   registration proof)
3. call `/wallets/register/start`
4. run Ed25519 single-key HSS through `/wallets/register/hss/respond`
5. call `/wallets/register/finalize`
6. create the NEAR account on-chain inside the relay registration path
7. run optimistic access-key visibility verification
8. persist relay-side authenticator, binding, session, and registration metadata
9. persist client-side wallet/session data
10. start background ECDSA provisioning and Ed25519 prewarm where configured

Recent timings show:

- HSS registration prepare is now in the low hundreds of milliseconds
- HSS registration finalize is around one second or less
- NEAR account creation plus optimistic key visibility is now one of the main
  fixed costs
- remaining avoidable latency is mostly wrapper overhead, request sequencing,
  serialization, and persistence ordering

## Success Criteria

An optimization counts as successful only if it satisfies all of these:

- improves median end-to-end registration time in local/dev benchmarking
- does not regress correctness or active single-key HSS behavior
- does not materially weaken security or scope binding
- does not add permanent legacy branches or duplicate code paths

Suggested threshold for “meaningful”:

- keep if median total registration time improves by at least `10%` or at least
  `500ms`
- otherwise revert unless the change is extremely small and obviously beneficial

## Benchmark Rules

Every phase below should use the same evaluation loop:

1. capture the current baseline
2. implement one isolated optimization
3. run the same registration benchmark several times
4. compare:
   - total registration time
   - Ed25519 HSS prepare/finalize time
   - atomic registration time
   - NEAR key visibility time
   - client local persistence time
5. keep only if the result is meaningfully better

Benchmark output should be logged in one place so we can compare phases without
guessing.

## Instrumentation First

Before changing behavior further, make the registration timing output complete
enough that every experiment can be judged quickly.

Needed timing buckets:

- client input validation
- client WebAuthn duration
- managed flow grant duration
- HSS client-input derivation duration
- HSS local prepare duration
- HSS relay prepare duration
- HSS local evaluate duration
- HSS relay finalize duration
- atomic registration request duration
- NEAR broadcast duration
- optimistic key-visibility duration
- relay persistence subtasks
- client local persistence subtasks
- total end-to-end duration

## Implementation Prep: Phase 0

Phase 0 is observability-only. It should preserve registration behavior and
produce one canonical timing summary for every registration attempt.

Primary files:

- `client/src/SeamsWeb/operations/registration/registration.ts`
- `client/src/SeamsWeb/operations/registration/createAccountRelayServer.ts`
- `client/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`

Current code already has a coarse summary in
`client/src/SeamsWeb/operations/registration/registration.ts`, but the existing
`thresholdEd25519PrepareMs` bucket covers most of the visible flow from start to
finalize. The first implementation pass should split that bucket into explicit
awaited boundaries:

- managed registration grant
- registration intent creation and digest check
- auth-method proof collection
- Email OTP enrollment material resolution
- Ed25519 HSS client material derivation
- `/wallets/register/start`
- Ed25519 client request preparation
- `/wallets/register/hss/respond`
- Ed25519 evaluation artifact build
- Email OTP recovery-code backup
- `/wallets/register/finalize`
- Ed25519 registration completion parsing
- local wallet/authenticator persistence
- threshold Ed25519 session persistence
- ECDSA registration finalization and signer-record persistence
- wallet-state activation
- immediate signing-lane assertion
- total end-to-end duration

Use a typed diagnostics shape instead of a loose `Record<string, number>`:

```ts
type RegistrationTimingSummary =
  | {
      kind: 'registration_timing_summary_v1';
      status: 'succeeded';
      authMethod: 'passkey' | 'email_otp';
      signerMode: 'ed25519_only' | 'ed25519_and_ecdsa';
      totalMs: number;
      timings: RegistrationTimingBuckets;
    }
  | {
      kind: 'registration_timing_summary_v1';
      status: 'failed';
      authMethod: 'passkey' | 'email_otp';
      signerMode: 'ed25519_only' | 'ed25519_and_ecdsa';
      totalMs: number;
      errorCode: string | null;
      timings: RegistrationTimingBuckets;
    };
```

`RegistrationTimingBuckets` should use required numeric fields for shared
phases. Auth-method-specific buckets should live in a discriminated nested
object so passkey and Email OTP timings cannot be mixed accidentally. Use
branch-specific summary builders for success and failure logs.

Phase 0 should log through one console line:

```text
[Registration] wallet timing summary
```

Keep existing server-side HSS timing logs as separate relay diagnostics for now.
After the client summary is stable, decide whether `/wallets/register/finalize`
should return structured relay subtask diagnostics. That is a second step
because it changes the route response surface.

Implementation checklist:

- [x] Map the current registration flow and existing timing logs.
- [x] Replace loose registration timing records with a typed summary builder.
- [x] Wrap the awaited registration boundaries listed above.
- [x] Emit success and failure summaries with the same top-level shape.
- [x] Keep diagnostics observational; they must not influence control flow.
- [x] Add or update focused tests around timing-summary shape if existing
      orchestration tests can observe console output cheaply.
- [x] Run `pnpm -C sdk type-check`.
- [x] Run a focused registration orchestration test if the timing summary is
      covered there.
- [ ] Run `pnpm -C tests test:threshold-ed25519:active-path` before keeping any
      behavior-changing optimization phase.
- [ ] Capture at least `5` local full-registration baseline runs and record
      median/p95 before Phase 1.

## Current Registration Optimization Plan

This is the canonical checklist for registration latency work. It replaces the
older HSS-only Phase A/B/C/D list for registration-flow decisions.

Before implementing any unchecked phase, capture a fresh baseline from the
current codebase. The historical May timings above are useful context, but they
are not sufficient to justify new behavior changes.

## HSS Resume Gate

Before changing HSS behavior again:

- [x] Finish the `refactor-59` registration timing summary enough to split
      Ed25519 HSS client and relay buckets.
- [x] Run the `refactor-59` smoke benchmark and record the HSS slice for
      passkey `ed25519_only` and passkey `ed25519_and_ecdsa`.
- [ ] Run `pnpm -C tests test:threshold-ed25519:active-path` as the HSS-only
      comparison baseline.
- [x] Decide whether HSS is still a top-three full-flow latency bucket by p50 or
      p95.
- [ ] If HSS is outside the top three, pause this plan and optimize the larger
      full-flow bucket first.

## Narrowed HSS Next Steps

Once the resume gate passes, proceed in this order:

1. Capture browser-worker HSS diagnostics from the full registration benchmark.
2. Add Rust/WASM internal evaluate substage diagnostics only if `wasmCallMs`
   dominates.
3. Re-run the full registration benchmark and HSS active-path benchmark.
4. Rank the measured HSS sub-buckets:
   - worker/WASM initialization
   - base64 and bincode decode
   - evaluator runtime materialization
   - hidden-eval execution
   - staged artifact assembly and encode
   - worker message transfer bytes
   - relay prepare/respond/finalize time
5. Pick exactly one HSS optimization from the largest stable bucket.
6. Re-benchmark before/after with the same scenarios.
7. Keep the change only if it clears the existing speed threshold or produces a
   clear p95 win with very small complexity.

Likely HSS optimization order after measurement:

- hidden-eval round-core A2B/carry conversion high: write the protocol-level
  optimization spec, then implement one candidate behind protocol validation and
  smoke benchmarking
- hidden-eval boolean batch helpers high: inspect `maj`/`ch` helper structure
  after the A2B candidate is measured
- worker transfer or encode/decode high in a fresh benchmark: move worker-local
  payloads to binary buffers and transferables
- relay prepare route sequencing high: prototype registration-start prepare
  pipelining
- finalize payload/transport high: investigate compact evaluation-result
  encoding or binary transport
- low-risk hidden-eval helper allocation high: retain only small label-buffer or
  recomputation cleanups that preserve transcript labels and gate shape

## Phase E1: Round-Core A2B And Boolean Helper Spec

Status: specced; implementation pending.

Measured basis:

- benchmark run `20260607-152114Z`
- top client-owned hidden-eval bucket: `hiddenEvalRoundCoreMs` p50 roughly
  `296ms` to `301ms`, p95 up to `308ms`
- largest visible round-core sub-buckets:
  - `hiddenEvalRoundNewABitsMs`: about `45ms` to `46ms` p50
  - `hiddenEvalRoundNewEBitsMs`: about `45ms` to `46ms` p50
  - `hiddenEvalRoundMajMs`: about `38ms` to `39ms` p50
  - `hiddenEvalRoundChMs`: about `31ms` to `32ms` p50

Implementation scope:

- `crates/ed25519-hss/src/ddh/hidden_eval_executor.rs`
  - `execute_round_stages`
  - `arithmetic_word_pair_to_split_local_bits_secure`
  - `ch_local_bits_into`
  - `maj_local_bits_into`
- `crates/ed25519-hss/src/ddh/ddh_hss.rs`
  - `eval_add_cross_share_local_arithmetic_word_bits_secure_public_into`
  - `eval_mul_local_bit_pair_batch_raw_xor_base_public_into`
  - `eval_maj_local_bit_pair_batch_raw_public_into`

Protocol invariants:

- Preserve all existing transcript label bytes unless the candidate explicitly
  changes `DDH_HSS_BACKEND_VERSION` and updates protocol fixtures.
- Preserve round labels generated by `set_round_label`:
  - `round_core/{round}/new_a_bits`
  - `round_core/{round}/new_e_bits`
  - `round_core/{round}/ch`
  - `round_core/{round}/maj`
- Preserve A2B child-label structure for each `new_a_bits` and `new_e_bits`
  conversion:
  - `{label}/zero`
  - `{label}/sum/left/{idx}`
  - `{label}/sum/right/{idx}`
  - `{label}/sum/xor_ab/{idx}`
  - `{label}/sum/sum/{idx}`
  - `{label}/sum/a_xor_carry/{idx}`
  - `{label}/sum/carry/{idx}`
  - `{label}/sum/next_carry/{idx}`
- Preserve `ch` labels:
  - `{label}/yz`
  - `{label}/gate/...`
  - `{label}/out/{idx}`
- Preserve `maj` labels:
  - `{label}/xy_left/{idx}`
  - `{label}/xy_right/{idx}`
  - `{label}/xz_left/{idx}`
  - `{label}/xz_right/{idx}`
  - `{label}/gate/{idx}`
  - `{label}/out/{idx}`
- Preserve provenance digest inputs, share commitments, output share sides, word
  widths, and carry chain order.
- Preserve the current gate schedule and number of local multiplication gates
  unless the candidate includes a formal protocol argument and a backend-version
  change.
- Diagnostics must remain observational. Timing fields cannot influence
  arithmetic, labels, branch selection, retries, or error handling.

Constant-time constraints:

- Loops must remain fixed by public widths: 64-bit SHA-512 words, 80 rounds, and
  stage/window counts validated at the boundary.
- No secret-dependent branches, secret-dependent indexing, or secret-dependent
  allocation sizes.
- No new variable-time arithmetic on secret-derived values. Reuse existing field
  and word helpers, or justify any replacement with a constant-time review.
- No early return based on secret share contents. Shape errors may still return
  at validation boundaries.

Candidate order:

1. A2B destination-writer candidate:
   - add an internal `arithmetic_word_pair_to_split_local_bits_secure_into`
     helper that writes into a caller-provided boolean word destination
   - keep the same `{label}/zero` and `{label}/sum/...` child labels
   - avoid per-call output-slice allocation where possible
   - reject the candidate if preserving owned `RoundKernelState` words forces
     equivalent allocation elsewhere
   - status: rejected after native and browser/WASM benchmarking; no code
     retained
2. A2B raw carry-gadget candidate:
   - specialize the secure A2B path for already-local arithmetic word pairs
   - reduce temporary `DdhHssLocalWord` construction only if provenance digest
     and commitment inputs remain byte-identical
   - require protocol validation before benchmarking
3. Boolean batch-helper candidate:
   - inspect `ch` and `maj` helpers after A2B is measured
   - prefer destination-writing or scratch reuse over algebra changes
   - preserve `gate` and `out` labels exactly

Required validation for each candidate:

- `cargo fmt --manifest-path crates/ed25519-hss/Cargo.toml`
- `cargo test --manifest-path crates/ed25519-hss/Cargo.toml`
- `CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang cargo check --manifest-path wasm/hss_client_signer/Cargo.toml --target wasm32-unknown-unknown`
- `pnpm -C sdk type-check`
- real-topology registration latency benchmark once the post-Refactor 88
  replacement exists

Benchmark comparison:

- compare against retained run `20260607-152114Z`
- inspect at least:
  - `hiddenEvalRoundCoreMs`
  - `hiddenEvalRoundNewABitsMs`
  - `hiddenEvalRoundNewEBitsMs`
  - `hiddenEvalRoundMajMs`
  - `hiddenEvalRoundChMs`
  - `hiddenEvalTotalMs`
  - SDK p50/p95
- keep the candidate only if it gives a stable HSS p95 win with small
  complexity or clears the broader `refactor-59` keep threshold
- revert if protocol validation fails, labels/provenance drift unexpectedly, or
  smoke results are weak/noisy

### Phase 0: Establish Baseline

Goal:

- produce a stable registration baseline before changing anything else

Work:

- add one canonical registration benchmark checklist
- run at least `5` full registrations in the same environment
- record median and p95 timings
- identify the largest stable buckets

Keep rule:

- always keep the improved instrumentation

### Phase 1: Remove Or Hide Preflight Latency

Candidate optimization:

- defer or eliminate the blocking account-exists pre-check
- fetch the managed `registration_v1` flow grant earlier, ideally while the
  user is completing WebAuthn

Hypothesis:

- this should shave off obvious pre-registration idle time without changing
  cryptographic behavior

Measurement:

- compare time-to-HSS-start
- compare total registration time

Keep only if:

- the early grant/preflight changes reduce median registration time
  meaningfully

### Phase 2: Shrink HSS Transport Overhead

Completed optimization:

- stop resending large HSS ceremony state on finalize
- replace full finalize payload state with a short-lived relay-side ceremony
  handle

Possible implementation direction:

- `prepare` stores server-side ceremony state keyed by a one-shot handle
- `finalize` sends only:
  - handle
  - evaluation result
  - minimal bound context

Measured:

- request payload size before/after
- HSS prepare/finalize client timing
- HSS total ceremony timing
- total registration time

Result:

- kept
- prepare still sends full ceremony state, so prepare size is unchanged
- finalize no longer reposts `preparedSession`; the relay stores a short-lived
  ceremony record keyed by a one-shot handle
- session HSS finalize request dropped from `315,263` bytes to `154,622` bytes
  (about `50.9%` smaller)
- registration HSS finalize request is now `154,693` bytes
- ceremony timings stayed roughly flat, so the direct latency win was weak, but
  the transport reduction is large and the design is cleaner and safer
- the remaining dominant finalize payload is now
  `evaluationResult.evaluationResultMessageB64u` at about `154.5KB`

### Phase 3: Reduce Blocking On-Chain Verification

Candidate optimization:

- relax or remove the blocking optimistic key-visibility gate from the user
  success path
- rely on background audit plus first-use tolerance instead

Hypothesis:

- this is likely one of the largest remaining registration wins

Measurement:

- compare registration total time before/after
- compare first-use success/failure immediately after registration
- compare rate of background audit completion

Keep only if:

- registration gets materially faster
- immediate post-registration signing remains reliable enough
- failure mode is still clean and understandable

If first-use reliability regresses, revert.

Spec clarification required before implementation:

- define whether UI success means account creation broadcast accepted, final key
  visibility confirmed, or background audit queued
- define first-use tolerance for immediate post-registration signing
- define the retry/error copy when key visibility is still pending
- keep this phase out of implementation until those acceptance criteria are
  written

### Phase 4: Parallelize Relay Persistence

Candidate optimization:

- parallelize independent relay-side post-transaction work:
  - authenticator persistence
  - credential binding persistence
  - Ed25519 session mint where safe

Hypothesis:

- this should reduce the tail of relay registration after the chain operation
  completes

Measurement:

- compare relay persistence subtasks
- compare total atomic registration time

Keep only if:

- the parallel version is measurably faster and preserves deterministic error
  behavior

Spec clarification required before implementation:

- list the exact relay writes that are independent
- define rollback/compensation behavior if one parallel write fails
- keep identity, authenticator, binding, and wallet publication ordering
  explicit

### Phase 5: Parallelize Client Local Persistence

Candidate optimization:

- parallelize:
  - `atomicStoreRegistrationData(...)`
  - `persistRegisteredThresholdEd25519Session(...)`

Hypothesis:

- this should reduce the post-success local storage tail on the client

Measurement:

- compare client local persistence time
- compare total registration time

Keep only if:

- there is a measurable user-visible reduction

Spec clarification required before implementation:

- list exact IndexedDB/session writes that can run in parallel
- define which writes must complete before resolving registration success
- keep recovery-code backup persistence ordering explicit for Email OTP accounts

### Phase 6: Reassess Background Work Placement

Candidate optimization:

- audit all remaining work that still runs before UI success
- move non-critical work to background if it is not needed for immediate
  correctness

Likely audit targets:

- any lingering local HSS warm-up
- any duplicated session/bootstrap work
- any non-critical relay metadata persistence

Keep only if:

- immediate registration correctness is unchanged
- total registration time gets meaningfully better

### Phase 7: Registration Start Prepare Pipelining

Candidate optimization:

- move Ed25519 HSS server prepare work earlier by returning the prepared branch
  from `/wallets/register/start`
- delete any separate registration-specific client prepare call if this route
  shape lands

Spec required before implementation:

- bind prepared sessions to `registrationCeremonyId`, wallet/account id,
  registration intent digest, signer spec, runtime policy scope, participant ids,
  and expiry
- prove prepared sessions cannot cross wallet, account, signing root, intent
  digest, or participant scope
- define cleanup for abandoned registration ceremonies

Keep only if:

- the route-shape change removes a visible round trip and produces a measurable
  registration win
- the scope-binding tests are strict enough to make invalid reuse
  unrepresentable

## Do Not Optimize Blindly

Do not keep an optimization just because it sounds cleaner.

Revert any change that:

- does not produce a real speed win
- weakens scope binding or request validation
- adds duplicate flows or temporary compatibility branches
- makes observability worse

## Plan Checklist

### Baseline

- [x] Add one canonical registration timing summary for all major client and
      relay substeps
- [x] Extract the Ed25519 HSS slice from the `refactor-59` full-flow benchmark
- [x] Capture baseline runs and record median/p95 registration timing
- [x] Capture an HSS-only script-level active-path baseline with
      `pnpm -C tests exec playwright test -c playwright.scripts.config.ts ./unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts ./unit/thresholdEd25519.separatedRoles.script.unit.test.ts --reporter=line`
- [ ] Restore the broad `pnpm -C tests test:threshold-ed25519:active-path`
      validation after updating stale relayer fixtures for the required
      WebAuthn `Origin`/`expected_origin` contract.

### Phase 1

- [ ] Prototype deferred or removed account-exists pre-check
- [ ] Prototype earlier managed flow grant fetch
- [ ] Benchmark both changes against baseline
- [ ] Keep only the changes that meaningfully improve speed

### Phase 2

- [x] Prototype relay-side HSS ceremony handle to reduce finalize payload size
- [x] Benchmark request size and total ceremony time before/after
- [x] Keep the handle-based finalize design

### Phase 3

- [ ] Prototype non-blocking or reduced blocking optimistic key-visibility gate
- [ ] Benchmark registration speed and immediate first-use reliability
- [ ] Keep only if speed improves without unacceptable reliability regression

### Phase 4

- [ ] Identify relay persistence steps that can safely run in parallel
- [ ] Implement relay-side parallel persistence
- [ ] Benchmark total atomic registration time before/after
- [ ] Keep only if the speed win is meaningful

### Phase 5

- [ ] Identify client local persistence steps that can safely run in parallel
- [ ] Implement client-side parallel persistence
- [ ] Benchmark local persistence and total registration time before/after
- [ ] Keep only if the speed win is meaningful

### Phase 6

- [ ] Audit remaining blocking work after registration success
- [ ] Move any non-critical work to background where safe
- [ ] Benchmark final registration flow again
- [ ] Keep only the background moves that produce a real speed improvement

### Phase 7

- [ ] Specify registration-start prepare pipelining scope bindings
- [ ] Prototype returning prepared HSS material from `/wallets/register/start`
- [ ] Add route and ceremony tests for invalid prepared-session reuse
- [ ] Benchmark against the current registration baseline
- [ ] Keep only if visible latency improves without weakening scope binding

### Final Decision

- [ ] Produce a final before/after summary of kept optimizations
- [ ] Revert experiments that did not materially improve speed
- [ ] Document the final optimized registration flow

## Next Target

The biggest remaining HSS transport cost is no longer `preparedSession`.

It is now:

- `evaluationResult.evaluationResultMessageB64u`

Current measured sizes:

- session HSS prepare request: `208,460` bytes
- session HSS finalize request: `154,622` bytes
- registration HSS prepare request: `208,491` bytes
- registration HSS finalize request: `154,693` bytes

That means the next real transport optimization is not another route-shape
cleanup. It is a protocol-level reduction of the evaluation result payload.

Candidate follow-up options:

- shrink the HSS evaluation message format itself
- move to a compact binary transport for the evaluation message
- add a server-assisted finalize design only if it avoids adding an extra round
  trip with negligible net win
