# HSS Optimize Registration

Date updated: May 23, 2026

## Summary

This plan is for speeding up the active Ed25519 single-key HSS registration flow.

The rule for this work is simple:

- each optimization must be implemented in isolation
- each optimization must be measured before and after
- each optimization is only kept if it meaningfully improves registration speed
- if the speed win is weak, inconsistent, or comes with bad complexity or risk,
  revert it and move on

This is a performance plan, not a speculative redesign doc.

## May 2026 Active-Path Plan

Recent full active-path test runs show the Ed25519 HSS ceremony at roughly
`2.8s` to `3.3s` total. The main buckets are:

- server `prepare`: about `380ms` to `480ms`
- server `respond`: about `340ms` to `410ms`
- client `evaluate`: about `1.16s` to `1.34s`
- server `finalize`: about `540ms` to `650ms`
- client `complete`: about `170ms` to `210ms`

Native release profiling still points to the HSS hidden-eval core as the
dominant protocol cost, with the browser active path adding worker, WASM
boundary, serialization, and route overhead around it.

The optimization work should proceed in this order.

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

- use `opt-level = "s"` as the default balanced profile; it keeps most of the
  bundle-size advantage of `"z"` while still cutting mean ceremony latency by
  about `345ms`
- use `opt-level = 3` only if registration latency becomes more important than
  the extra `56.7KB` gzipped WASM delta

### Phase A: Add Evaluate Substage Instrumentation

Goal:

- make the browser `evaluateMs` bucket explain itself before changing runtime
  shape

Work:

- add worker-side timing fields around:
  - worker queue wait
  - WASM initialization
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

Keep rule:

- always keep if the instrumentation stays boundary-local and does not alter
  protocol semantics

Validation:

- `pnpm -C tests test:threshold-ed25519:active-path`

### Phase B: Worker-Resident HSS Session Handles

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

- change `threshold_ed25519_hss_prepare_session` worker handling so the worker
  stores materialized runtime/session state behind a short-lived handle
- make `prepare_client_request`, `build_client_owned_staged_evaluator_artifact`,
  `open_client_output`, and seed export consume the handle where possible
- keep durable and HTTP boundaries encoded as today; the worker-local path can
  use handles because it is process-local and ephemeral
- add TTL cleanup and explicit cleanup on success, failure, cancellation, and
  worker reset
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

### Phase C: Binary Worker Payloads

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

### Phase D: Wallet Registration Start Prepare Pipelining

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

### Phase E: Executor Core Cleanup

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

## Current Todo

- [x] Capture a fresh active-path baseline with the size-optimized WASM profile.
- [x] Trial speed-optimized HSS client WASM and record size/latency impact.
- [ ] Implement Phase A instrumentation.
- [ ] Implement Phase B worker-resident HSS handles.
- [ ] Implement Phase C binary worker payloads.
- [ ] Implement Phase D wallet registration start prepare pipelining.
- [ ] Re-benchmark after each phase and keep only meaningful wins.
- [ ] Implement Phase E executor cleanup only after wrapper/transport overhead is
      quantified.
- [ ] Update security and README language if any public timing or boundary claim
      changes.

## Current Registration Shape

The current registration flow does this:

1. validate account input and run a best-effort account existence check
2. complete WebAuthn registration
3. run Ed25519 single-key HSS registration prepare/finalize
4. submit atomic relay registration
5. create the NEAR account on-chain
6. run optimistic access-key visibility verification
7. persist relay-side authenticator, binding, and warm-session data
8. persist client-side wallet/session data
9. start background ECDSA provisioning and Ed25519 prewarm

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

## Optimization Phases

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

Candidate optimization:

- stop resending large HSS ceremony state on finalize
- replace full finalize payload state with a short-lived relay-side ceremony
  handle

Possible implementation direction:

- `prepare` stores server-side ceremony state keyed by a one-shot handle
- `finalize` sends only:
  - handle
  - evaluation result
  - minimal bound context

Hypothesis:

- this should reduce JSON serialization cost, request bytes, and browser/relay
  overhead

Measurement:

- request payload size before/after
- HSS prepare/finalize client timing
- HSS total ceremony timing
- total registration time

Keep only if:

- the handle-based design gives a clear speed win and does not complicate scope
  binding in a risky way

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

## Do Not Optimize Blindly

Do not keep an optimization just because it sounds cleaner.

Revert any change that:

- does not produce a real speed win
- weakens scope binding or request validation
- adds duplicate flows or temporary compatibility branches
- makes observability worse

## Plan Checklist

### Baseline

- [ ] Add one canonical registration timing summary for all major client and
      relay substeps
- [ ] Capture baseline runs and record median/p95 registration timing

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
