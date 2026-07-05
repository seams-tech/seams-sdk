# Refactor 83B: Cloudflare HSS Durable Finalization

Date created: July 5, 2026
Updated: July 5, 2026 — corrected around the actual role-separated protocol:
the early server step must receive the add-stage request before the client
artifact build, durable advanced eval state is distinct from finalized report
idempotency, and execution-local handles are conditional only.

Status: in progress; Worker/WASM is the active Cloudflare path.

## Goal

Remove the multi-second Ed25519 HSS serialized replay from user-visible
registration without persisting WASM handles.

Success is measured on total registration elapsed time, with separate buckets
for:

- `walletRegisterHssRespondMs`;
- add-stage request build;
- client artifact build;
- early server eval advance;
- `/wallets/register/finalize`;
- total registration elapsed.

A fast `registrationHssFinalizeMs` is not success if the same work moved into
another visible wait.

## Current Problem

Refactor 83 removed the second Ed25519 HSS ceremony and enabled the
speed-oriented server HSS WASM build. The original Cloudflare D1/workerd
baseline showed multi-second server HSS finalization:

- passkey combined registration:
  - `registrationHssFinalizeMs` around `3,334ms`;
  - `registrationHssFinalizeReportMs` around `2,887ms`.
- Email OTP Ed25519-only registration:
  - `registrationHssFinalizeMs` around `3,232ms`;
  - `registrationHssFinalizeReportMs` around `2,798ms`.

The hot cost is `finalize_server_eval_state_from_add_stage_request()`, where
Rust advances server eval state through add-stage, message-schedule rounds,
round-core rounds, and output projection from serialized state.

Today the bridge calls server finalize with:

```ts
stagedEvaluatorArtifactHandle: '';
```

That made the live staged-artifact fast path unreachable and forced serialized
replay.

July 5 update: after the shared `ed25519-hss` pool fix was compiled into the
server WASM artifact, Worker-class server advance probes dropped to about
`325ms` median / `333ms` p95. Refactor 83C's native/container direction is
shelved; this plan remains the active Worker/WASM durable-advance path because
it provides overlap, durable retry, claim/lease protection, and provenance.

## Key Constraint

The server cannot produce the finalized report at `/hss/respond` in the current
role-separated flow, because the report requires the client-owned staged
artifact.

The server can, however, advance `ServerEvalState` before the full artifact is
built if the client submits the add-stage request early.

The client add-stage request is computed before the heavy artifact build from
data the client has immediately after respond:

- client request message;
- evaluator OT state;
- server input delivery.

Therefore the useful latency split is:

```text
/hss/respond returns
  -> client builds addStageRequestMessage immediately
  -> client POSTs addStageRequestMessage to /hss/advance-state
  -> server advances responded ServerEvalState to ready-for-output-projection
  -> client builds full staged evaluator artifact in parallel
  -> /wallets/register/finalize consumes durable advanced eval + artifact
     and runs the artifact-bound output projection
```

Submitting the full `evaluationResult` after artifact build is too late; it
starts the same server work at the same time the current finalize route starts
it.

## Durable Records

Two durable records are needed because the data becomes available at different
times.

```ts
type DurableEd25519HssAdvancedEvalRecord = {
  kind: 'ed25519_hss_advanced_eval_v1';
  ceremonyHandle: string;
  contextBindingB64u: string;
  addStageRequestDigestB64u: string;
  projectionMode: 'registration_seed_and_output' | 'registration_output_only';
  advancedServerEvalStateB64u: string;
  priorStageResponseMessageB64u: string;
  createdAtMs: number;
  expiresAtMs: number;
};

type DurableEd25519HssFinalizedReportRecord =
  | {
      kind: 'ed25519_hss_finalized_report_v1';
      ceremonyHandle: string;
      contextBindingB64u: string;
      addStageRequestDigestB64u: string;
      projectionMode: 'registration_seed_and_output';
      finalizedReport: {
        contextBindingB64u: string;
        clientOutputMessageB64u: string;
        serverOutputMessageB64u: string;
        seedOutputMessageB64u: string;
      };
      createdAtMs: number;
      expiresAtMs: number;
    }
  | {
      kind: 'ed25519_hss_finalized_report_v1';
      ceremonyHandle: string;
      contextBindingB64u: string;
      addStageRequestDigestB64u: string;
      projectionMode: 'registration_output_only';
      finalizedReport: {
        contextBindingB64u: string;
        clientOutputMessageB64u: string;
        serverOutputMessageB64u: string;
        seedOutputMessageB64u?: never;
      };
      createdAtMs: number;
      expiresAtMs: number;
    };
```

`advanced_eval` is created by the early add-stage route. It stops before output
projection because registration uses a client-masked projection whose mask
commitment is only known after the full client artifact is built.
`finalized_report` is created after the full artifact is available and is used
for HSS-level idempotent retries before route success. Whole-route idempotency
owns repeated finalize requests after a completed registration. Tests that
exercise `finalized_report` must use the same ceremony and add-stage digest
while bypassing the whole-route replay key.

`addStageRequestDigestB64u` is
`base64url(SHA-256(decoded addStageRequestMessageB64u bytes))`. Both the early
advance route and finalize route compute this digest at their boundary and
compare it with the durable record.

`advancedServerEvalStateB64u` is base64url-encoded MessagePack bytes for the
advanced `ServerEvalState`. The responded-state inputs stay on the existing
bincode state encoding, and `priorStageResponseMessageB64u` stays on the
existing `WireMessage` encoding. This split is intentional: the advanced eval
state uses serde data that needs a self-describing durable format, while the
existing request/response state blobs already round-trip through bincode.

No durable record stores `preparedSessionHandle` or
`stagedEvaluatorArtifactHandle`.

## Provenance

Every registration Ed25519 HSS finalize records provenance:

```ts
type Ed25519HssFinalizeSource =
  | 'durable_advanced_eval'
  | 'durable_finalized_report'
  | 'serialized_replay';
```

Tests assert on provenance. Timings are regression signals, not correctness
signals.

Local Miniflare/single-isolate runs may accidentally hit warm live state more
often than production. Benchmarks must record the advance/finalize timing
breakdown so warm runtime wins are not mistaken for production-safe durable
wins.

## Non-Goals

- Do not persist WASM handles.
- Do not remove production serialized replay from session-ceremony finalize;
  unlock/reconstruction keeps that path until a scoped migration replaces it.
- Do not optimize one timing bucket while total registration stays flat.
- Do not update `crates/ecdsa-hss` unless measurements show the same replay
  bottleneck on a user-visible ECDSA path.
- Do not make the registration ceremony store own live WASM runtime state.

## Phase 0: Baseline, Provenance, And Existing Cache Audit

- [x] Add route diagnostics for `Ed25519HssFinalizeSource`.
- [x] Record passkey and Email OTP p50/worst-case for total elapsed and the HSS
      buckets listed in the Goal.
- [x] Audit the existing `registrationFinalizeReplayLoadMs` /
      `registrationFinalizeReplayCacheMs` route cache and document what it
      already covers.
- [x] Add an intended structured provenance check for registration
      `source: 'serialized_replay'`; this is now promoted to a failing
      contract in Phase 7.
- [x] Add registration-scoped source guards for silent replay imports/calls.
- [x] Confirm unlock/session HSS still has a production replay path and is out
      of this guard scope.

Exit criteria:

- Every registration finalize has provenance.
- The existing idempotency cache is understood before new records are added.
- Baselines use total elapsed as the primary metric.

Audit note:

- `registrationFinalizeReplayLoadMs` / `registrationFinalizeReplayCacheMs`
  cover whole-route finalize idempotency keyed by registration ceremony id plus
  idempotency key. They do not prove which HSS finalization source was used and
  they do not provide a reusable HSS finalized-report record for the early
  advance-state path.
- The D1 source guard is scoped to `d1WalletRegistrationService.ts`. Session
  and recovery ceremonies still keep their serialized replay source in
  `ThresholdSigningService.ts` until their own migration replaces it.

Latest single-run smoke evidence, not a p50/worst-case baseline:

- `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line`
  passed on July 5, 2026.
- Email OTP Tempo+Arc registration: total `5,056ms`, advance-state
  `2,847ms`, client artifact `448ms`, finalize `624ms`, HSS finalize
  `594ms`, source `durable_advanced_eval`, overlapped/background `832ms`.
- Passkey registration: total `5,445ms`, advance-state `2,838ms`, client
  artifact `444ms`, finalize `593ms`, HSS finalize `571ms`, source
  `durable_advanced_eval`, overlapped/background `575ms`.

Historical p50/worst-case evidence, three samples per row, recorded July 5,
2026 with persisted intended traces before the rebuilt Worker WASM artifact
picked up the pool fix:

| Flow | Total | Respond | Add-stage | Artifact | Advance-state | Finalize | HSS finalize | Source |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Passkey | `5,558 / 5,562ms` | `238 / 255ms` | `29 / 29ms` | `451 / 452ms` | `2,858 / 2,882ms` | `600 / 620ms` | `575 / 590ms` | `durable_advanced_eval` |
| Email OTP, Ed25519-only | `4,996 / 5,072ms` | `216 / 222ms` | `29 / 29ms` | `449 / 451ms` | `2,871 / 2,875ms` | `602 / 637ms` | `577 / 608ms` | `durable_advanced_eval` |
| Email OTP, Tempo-only | `4,986 / 5,091ms` | `223 / 243ms` | `29 / 30ms` | `448 / 453ms` | `2,866 / 2,886ms` | `603 / 627ms` | `574 / 599ms` | `durable_advanced_eval` |
| Email OTP, Tempo+Arc | `5,026 / 5,121ms` | `232 / 255ms` | `29 / 30ms` | `450 / 450ms` | `2,880 / 2,881ms` | `609 / 631ms` | `581 / 602ms` | `durable_advanced_eval` |

The same traces recorded advance-state route diagnostics for every sample.
Representative historical p50 advance-state split:

- materialize serialized server state: `153-156ms`;
- message-schedule rounds: `1,227-1,231ms`;
- round-core rounds: `1,430-1,440ms`;
- full WASM advance: `2,838-2,857ms`.

Current advance-source probe after rebuilding Worker-class server WASM:

- `node ./benchmarks/ed25519-hss-advance-sources/src/runner.mjs --skip-optional --warmup 1 --iterations 10`
- run `2026-07-05T12-28-50-985Z`;
- `node_server_wasm_probe median_ms=334.674`, `p95_ms=347.254`;
- a broader source run with optional native service measured
  Worker-class WASM at `325.31ms` median and warm native at `266.679ms`
  median, before Worker-to-service hop costs.

Post-cleanup intended benchmark, recorded July 5, 2026 after removing native
startup/config:

- Command:
  `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line`.
- Result: `2 passed (30.8s)`.
- Email OTP Tempo+Arc registration:
  - total `2,766ms`;
  - advance-state `561ms`, route total `552ms`, WASM `536ms`;
  - advance source `durable_workerd_wasm`;
  - finalize `637ms`, HSS finalize `600ms`;
  - finalize source `durable_advanced_eval`;
  - harness violations `[]`.
- Passkey Tempo+Arc registration:
  - total `3,122ms`;
  - advance-state `542ms`, route total `533ms`, WASM `515ms`;
  - advance source `durable_workerd_wasm`;
  - finalize `590ms`, HSS finalize `568ms`;
  - finalize source `durable_advanced_eval`;
  - harness violations `[]`.
- Saved traces:
  `test-results/intended-lifecycle-traces/1783258261598-email_otp.registration-brisk-meadow-2vpm9x-intended-lifecycle-trace.json`
  and
  `test-results/intended-lifecycle-traces/1783258267070-passkey.registration-cedar-quartz-xvm5rb-intended-lifecycle-trace.json`.

## Phase 1: Durable Record Groundwork

- [x] Add typed parsers/builders for
      `DurableEd25519HssAdvancedEvalRecord`.
- [x] Add typed parsers/builders for
      `DurableEd25519HssFinalizedReportRecord`.
- [x] Make `DurableEd25519HssFinalizedReportRecord` projection-discriminated:
      seed output is required for `registration_seed_and_output` and rejected
      for `registration_output_only`.
- [x] Persist `finalized_report` after HSS report creation, before registration
      side effects complete, so partial-finalize retries can skip HSS replay
      while the ceremony still exists.
- [x] Validate context binding and add-stage request digest on read.
- [x] Add corruption tests for digest, context binding, and expiry.

Exit criteria:

- Durable records are represented by precise branch types.
- First-run latency is expected to remain mostly unchanged.

## Phase 2: Measure Advance Cost And Checkpointability

Complete this before choosing checkpoint/DO work. Durable advanced eval and
the registration replay policy can proceed once provenance guards are in
place; Phase 2 decides whether any remaining latency needs checkpointing or an
execution-local owner.

- [x] Split server advance timing into: - serialized decode/materialize; -
      add-stage response; - message-schedule rounds; - round-core rounds; -
      output projection; - report/finalized-state assembly.
- [x] Evaluate whether a distinct request-independent pool/checkpoint rebuild
      bucket exists inside materialization.
- [x] Determine whether a durable pool/checkpoint can make every isolate fast.
- [x] Determine whether a live warm session is the only fast path.
- [x] Record whether this applies to unlock material restore as well.

Exit criteria:

- The plan knows whether the `~2.9s` is checkpointable or fundamentally
  request-bound.
- The later DO decision has real data.

Measurement conclusion:

- No request-independent pool/checkpoint rebuild dominates registration
  advance. Serialized-state materialization is only `~153-156ms`.
- A durable checkpoint inside the current state shape would still run the
  request-bound message-schedule and round-core loops, which account for
  `~2.65s`.
- The remaining registration HSS latency requires execution-local ownership of
  live role-separated eval state if we want another large reduction.
- Unlock/session material restore remains outside the 83B evidence set. Keep
  its production serialized replay path available until a dedicated unlock
  measurement proves the same latency shape.

## Phase 3: Split Client Add-Stage From Artifact Build

- [x] In the client HSS WASM path, split the fused artifact builder into: -
      `prepareAddStageRequestMessage`; -
      `buildClientOwnedStagedEvaluatorArtifact`.
- [x] The add-stage builder must run immediately after `/hss/respond` and before
      the heavy artifact build.
- [x] The full artifact builder later verifies it uses the same add-stage
      request/projection mode.
- [x] Add client-side timing buckets for add-stage build and artifact build.
- [x] Add a regression test proving independently prepared add-stage requests
      differ because they carry a fresh client nonce, and that the prepared
      request validates against the artifact commitment.

Implementation note:

- Registration uses the split `prepared` add-stage branch and records
  `ed25519AddStageRequestMs` before `ed25519EvaluationArtifactMs`.
- The prepared add-stage request is the authority for the split flow. The
  artifact builder must receive that exact prepared request, validate it against
  the artifact's client input commitment, and return the prepared request in
  its result. It must not compare against a regenerated add-stage request.
- Recovery and session ceremonies still use the explicit `fused` branch until
  their scoped migrations replace that path.

Exit criteria:

- The SDK can produce add-stage request material without waiting for the full
  artifact.
- The old fused path is no longer required for registration.

## Phase 4: Ed25519 HSS Advance API

- [x] In `crates/ed25519-hss`, add a public API that advances a responded
      `ServerEvalState` plus add-stage request to ready-for-output-projection
      server eval state.
- [x] The crate API returns: - advanced `ServerEvalState`; - prior stage
      response message for output projection; - timing breakdown when called
      through the profiled variant.
- [x] The `wasm/near_signer` boundary returns the route-facing add-stage
      request digest, projection mode label, and timing breakdown.
- [x] It does not return finalized report payload; report creation still needs
      the full artifact and artifact-bound output projection.
- [x] Expose the API through `wasm/near_signer`.
- [x] Add crate tests for transcript/context binding, JSON serialization
      round-trip, and equivalence with current finalize replay.
- [x] Keep add-stage request digest binding at the TypeScript durable-record
      boundary with unit coverage.

Validation note:

- Default focused Rust check:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml durable_advanced_eval --test mod -- --nocapture`
- Full equivalence proof is available as an ignored debug-expensive test:
  `cargo test --manifest-path crates/ed25519-hss/Cargo.toml durable_advanced_eval_round_trip_matches_current_finalize_replay --test mod -- --ignored --nocapture`

Exit criteria:

- Advancing server eval state is a first-class runtime operation.
- The finalized report remains a separate operation.

## Phase 5: Early Advance-State Route With Claim

- [x] Add a narrow internal route, for example:

```text
POST /wallets/register/hss/advance-state
```

- [x] It accepts only ceremony identity and add-stage request message.
- [x] The route derives all authority/wallet/context data from the server-side
      ceremony record.
- [x] The route derives the registration projection label from the ceremony and
      never accepts a client-supplied cryptographic projection mode.
- [x] Add a typed durable claim record keyed by ceremony and add-stage digest so
      concurrent advance, finalize, or retry cannot start a second advance for
      the same digest.
- [x] Model claim state as a discriminated union:
      `in_flight -> fulfilled | failed`. The `in_flight` branch carries
      `claimId`, `leaseExpiresAtMs`, and attempt provenance. The `fulfilled`
      branch carries the advanced-eval record identity. The `failed` branch
      carries a structured failure code.
- [x] Store the `in_flight` claim before running the CPU-heavy advance and
      complete it only through typed state transitions.
- [x] Claim transitions use an atomic D1 compare-and-set shape. Stale leases
      move to `failed` before a new claim is allowed.
- [x] The route runs the Phase 4 API and persists
      `ed25519_hss_advanced_eval_v1`.
- [x] The SDK starts the advance-state request before starting the heavy
      artifact build and keeps it as an in-flight operation while the artifact
      build runs.
- [x] If `/wallets/register/finalize` arrives while advance is in flight, it
      performs a bounded wait/poll for the claim result. If the claim is still
      in flight, finalize returns a structured retryable response. It never
      starts a second replay for the same add-stage digest.

Exit criteria:

- Server advance begins before client artifact build.
- Duplicate advance is prevented by a typed claim/lease, not by timing.

## Phase 6: Finalize From Durable Advanced Eval

- [x] `/wallets/register/finalize` requires a matching
      `ed25519_hss_advanced_eval_v1` in intended/CI mode.
- [x] Finalize verifies the durable advanced record context and add-stage
      request digest at the TypeScript boundary, then verifies the artifact
      projection and add-stage binding inside the Rust finalizer.
- [x] Finalize runs only the artifact-bound output projection and report
      assembly from durable advanced state plus prior stage response, and
      reports `source: 'durable_advanced_eval'`.
- [x] After report creation, persist
      `ed25519_hss_finalized_report_v1` for idempotent retries.
- [x] HSS-level retry before route success reports
      `source: 'durable_finalized_report'` when a finalized-report record
      already exists for the same ceremony and add-stage digest.

Exit criteria:

- First-run registration finalize consumes durable advanced eval state.
- HSS-level partial-finalize retry consumes durable finalized report.
- Serialized replay is absent from intended registration.

## Phase 7: Registration Replay Policy

- [x] Intended/CI mode fails on registration `source: 'serialized_replay'`.
- [x] Serialized replay for registration exists only as an explicitly named
      diagnostic/test command. Normal registration finalize never chooses it
      automatically.
- [x] Production registration behavior is explicit: - durable advanced eval
      first; - in-flight claim wait/retry while advance is running; -
      structured diagnostic/restart when no durable advanced eval and no claim
      exists.
- [x] Keep session-ceremony serialized replay production-reachable for unlock.

Validation note:

- Registration intended/CI now parses `[Registration] wallet timing summary`
  JSON and fails on `wallets_register_finalize` HSS provenance of
  `serialized_replay` or missing Ed25519 finalize provenance.
- Session/recovery replay remains explicit outside registration:
  `ed25519HssFinalizeWithSession` passes
  `serverEvalSource: { kind: 'serialized_replay' }`, and email recovery
  registration-material finalization passes the same explicit source.

Exit criteria:

- Registration cannot silently fall through to serialized replay.
- Unlock/session HSS remains unaffected.

## Phase 8: Pool Or Checkpoint Optimization

Use Phase 2 results to decide whether to reduce the advance cost itself.

- [x] Evaluate the request-independent pool/checkpoint option and skip durable
      checkpoint work because rebuild/materialization does not dominate.
- [x] If live warm state is the only fast path, leave checkpointing out and use
      Phase 9 as the measured follow-up.
- [x] Record before/after for server advance wait and total registration
      elapsed.

Exit criteria:

- Any adopted checkpoint improves total elapsed, not just a sub-bucket.

Decision:

- No durable checkpoint format is added in Phase 8. The measured hot work is
  request-bound HSS evaluation, so checkpointing the current durable state
  would not materially change total elapsed.
- Durable advance reduced user-visible finalize from `~3.2-3.3s` to
  `~0.57-0.61s` HSS finalize, while total registration remains about
  `5.0-5.6s` because `~2.85s` moved to early advance-state work and overlaps
  only `~0.45s` of client artifact build plus route latency.
- Phase 9 remains the next latency lever.

## Phase 9: Execution-Local DO Decision Gate

Add an execution-local DO only if Phases 0-8 leave meaningful latency on the
table and the role-separated protocol exposes valid live state for the DO to
own.

Proceed only if:

- durable advanced eval works;
- serialized replay is absent from intended registration;
- total registration elapsed is still blocked by decode/materialize or live
  runtime locality;
- local benchmark provenance is not relying on Miniflare-only warmth.

Gate result:

- Proceed with Phase 9 as the next optimization if 83B continues past durable
  finalization. Durable records are working, serialized replay is absent from
  intended registration, and every benchmark sample reports
  `source: 'durable_advanced_eval'`. Remaining latency is the live-eval loop
  rather than durable decode/materialize.

If implemented:

- add `ED25519_HSS_EXECUTION` binding in Cloudflare types, wrangler config, and
  intended harness config;
- server-mint `hssExecutionId` and never accept it from the client;
- re-verify ceremony context binding on every command;
- keep live handles in memory only;
- use ceremony records as the durable source of truth;
- degrade live-state miss to durable advanced eval/finalized report where
  available;
- add alarm cleanup and Rust release calls.

Exit criteria:

- Simulated eviction degrades to durable records.
- No durable storage contains WASM handles.

## Phase 10: Tests And Intended Contracts

- [x] Unit test durable advanced eval and finalized report parsing.
- [x] Unit test add-stage digest/projection mismatch rejection.
- [x] Unit test prepared add-stage request nonce/commitment validation.
- [x] Unit test claim/lease duplicate-advance prevention.
- [x] Unit test finalize from durable advanced eval.
- [x] Unit test retry from durable finalized report.
- [x] Route test passkey registration end to end.
- [x] Route test Email OTP registration end to end.
- [x] Intended benchmark passkey registration.
- [x] Intended benchmark Email OTP registration, Ed25519-only.
- [x] Intended benchmark Email OTP registration, Tempo-only.
- [x] Intended benchmark Email OTP registration, Tempo+Arc.
- [x] Intended suite fails on registration `source: 'serialized_replay'` after
      Phase 7.

Validation note:

- Trace-enabled smoke command:
  `SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_SKIP_BUILD=1 pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts e2e/intended-behaviours/email-otp.registration.benchmark.test.ts --reporter=line`
- Result: `2 passed (32.4s)`.
- Saved traces:
  `test-results/intended-lifecycle-traces/1783232761233-email_otp.registration-opal-orchid-rsqpbh-intended-lifecycle-trace.json`
  and
  `test-results/intended-lifecycle-traces/1783232768791-passkey.registration-violet-raven-btr9yj-intended-lifecycle-trace.json`.

Exit criteria:

- Every intended registration benchmark uses durable advanced eval or finalized
  report.
- Provenance markers appear in every finalize trace.
- Total registration latency improvement is recorded.

## Phase 11: ECDSA HSS Assessment

Do not update `crates/ecdsa-hss` as part of this Ed25519 registration fix
unless measurements show the same replay pattern on a user-visible ECDSA path.

- [x] Audit ECDSA HSS registration/sign/export paths for durable replay costs.
- [x] Record that no matching ECDSA durable replay bottleneck exists in the
      current role-local paths.
- [x] Keep Ed25519 and ECDSA persisted record shapes separate unless a shared
      abstraction removes real duplication without hiding curve-specific state.

Audit note:

- ECDSA registration is role-local. The browser/Email OTP worker prepares an
  `ecdsa_role_local_pending_state_blob_v1`, the server derives the relayer
  role-local share and writes a `threshold_ecdsa_hss_role_local_v2` key record,
  and the browser finalizes the client bootstrap from the pending state plus
  relayer public identity. There is no server-side registration finalize replay
  equivalent to Ed25519's durable `ServerEvalState`.
- ECDSA signing goes through Router A/B presign/finalize routes and the active
  crate profile keeps the heavy sign bridge in the tens-of-milliseconds band.
  Existing benchmarks record WASM sign finalize around `~1 ms`, total core WASM
  around `~120-121 ms`, and native role-local bootstrap/export as
  sub-millisecond.
- ECDSA explicit export requests a relayer export share and builds the export
  artifact client-side from the role-local ready state. It does not replay a
  persisted hidden-eval server state.

Decision:

- No ECDSA HSS durable-advance/finalized-report phase is added to 83B.
- If future measurements find an ECDSA replay-shaped bottleneck, write a
  separate ECDSA phase with ECDSA-specific records and tests instead of sharing
  Ed25519's persisted state types.

Exit criteria:

- ECDSA is either explicitly out of scope with evidence or has its own scoped
  follow-up.

## Files Likely Touched

- `crates/ed25519-hss/src/*`
- `crates/ed25519-hss/tests/*`
- `wasm/near_signer/src/threshold/threshold_hss.rs`
- `wasm/hss_client_signer/src/*`
- `packages/sdk-server-ts/src/core/ThresholdService/ed25519HssWasm.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
- `packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/*`
- `packages/sdk-web/src/SeamsWeb/operations/registration/*`
- `tests/e2e/intended-behaviours/*registration*.benchmark.test.ts`
- `tests/scripts/check-*hss*`

Conditional DO files:

- `packages/sdk-server-ts/src/router/cloudflare/cloudflare.types.ts`
- `packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter.ts`
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/*`
- wrangler / Miniflare intended harness config

## Completion Criteria

- Client add-stage request is submitted before full artifact build.
- The prepared add-stage request is the single binding authority for the split
  client flow; regenerated add-stage requests cannot be used to prove equality.
- Server advance starts before artifact build and is claim-protected.
- Registration finalize uses `source: 'durable_advanced_eval'` on first run.
- HSS-level partial-finalize retry uses `source: 'durable_finalized_report'`;
  completed registration retry remains owned by whole-route replay.
- Registration never silently runs serialized replay.
- End-to-end registration latency improves versus Phase 0, or the plan records
  evidence that no useful overlap/checkpoint remains and stops before DO
  complexity.
- Unlock/session HSS production replay remains available until a scoped unlock
  migration replaces it.
- No durable record stores WASM handles.
