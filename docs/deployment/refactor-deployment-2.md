# Deployment Refactor 2: Email OTP Registration Latency

Date created: July 23, 2026

Status: planned

## Objective

Reduce the post-authentication `Creating...` latency for Email OTP wallet
registration while preserving the existing signer identities, cryptographic
checks, worker custody boundaries, and atomic finalization.

The production targets are:

- warm mixed-wallet Email OTP registration p50 below 5 seconds;
- cold mixed-wallet Email OTP registration p95 below 8 seconds;
- at least a 35% reduction from the measured production baseline when either
  target is already satisfied;
- timing coverage for at least 90% of wall-clock registration time;
- no regression in passkey, Ed25519-only, or ECDSA-only registration.

Latency is measured from the user's create action after authentication through
the successful registration result. Google authentication and time spent
entering an OTP are outside this budget.

## Classification and Current Finding

Classification: `production_regression`.

The live `seams.sh` bundle matches the current source. A Gateway deployment
alone cannot change this behavior.

The earlier registration optimization applied to a now-retired derivation
implementation. That path is historical context and is not part of the
current registration design. Current ECDSA uses strict Router A/B
threshold-PRF derivation followed by additive secp256k1 client and server share
construction.
Ed25519 uses Streaming Yao.

The Router A/B Yao lifecycle introduced afterward created a new Email OTP
critical path. In mixed-wallet registration, the current flow awaits all Email
OTP Ed25519 Yao work before starting Router A/B ECDSA derivation:

```text
wallet registration start
    -> wait for Email OTP enrollment material
    -> create Email OTP worker
    -> initialize Yao WASM
    -> Router Yao admission
    -> Router Yao execution
    -> complete Yao Client state
    -> Router A/B ECDSA threshold-PRF derivation
    -> registration finalize
    -> durable and local commit
```

Passkey mixed-wallet registration starts Yao as a background task and overlaps
it with ECDSA derivation. Email OTP currently awaits
`startEmailOtpRegistrationYaoWork(...)`, so its two signer branches run
serially.

The Ed25519-only Email OTP path has no ECDSA branch to overlap. Its improvement
comes from accurate measurement, early enrollment work, targeted worker/WASM
prewarming, and any later route optimization justified by measurements.

## Required Invariants

The implementation must preserve these invariants:

1. Registration finalization starts only after every selected signer branch has
   produced a verified pending result.
2. A mixed registration succeeds only when Ed25519 Yao and ECDSA identities
   match the finalized server response.
3. Durable server state, local signer records, and active worker capabilities
   remain one logical commit. The UI cannot report success early.
4. An ECDSA, Yao, finalization, persistence, or identity-validation failure
   disposes every uncommitted Yao capability and cancels the active
   registration intent.
5. Email OTP factors and active Yao material remain inside the Email OTP worker.
   Prewarming never requires an identity, factor, OTP, JWT, or registration
   grant.
6. Timing diagnostics contain durations, relative spans, branch kinds, and
   route names only. They cannot contain wallet IDs, account IDs, emails,
   credential IDs, tokens, OTPs, key material, or public-key fingerprints.
7. ECDSA-only and Ed25519-only registrations cannot enter mixed-branch states.

## Target Flow

Mixed Email OTP registration should use structured concurrency:

```text
wallet registration start
    |
    +-- Email OTP Ed25519 Yao ------------------+
    |                                          |
    +-- ECDSA threshold-PRF derivation --------+--> verified join
                                                   -> finalize
                                                   -> persist and activate
```

The two branches may start only after the registration-start response provides
their ceremony inputs. Finalization remains the join point.

## Phase 0: Establish a Reproducible Baseline

- [ ] Enable privacy-safe registration benchmark diagnostics in staging and for
      a bounded production measurement session.
- [ ] Record at least 10 cold and 20 warm Email OTP mixed-wallet registrations.
- [ ] Record at least 5 cold and 10 warm passkey mixed-wallet registrations as
      the comparison group.
- [ ] Record Ed25519-only and ECDSA-only Email OTP samples separately.
- [ ] Tag each sample with the exact source SHA, release-set ID, target, auth
      kind, signer-set kind, and cold/warm classification.
- [ ] Define a cold run as a fresh page with no live wallet worker or compiled
      Yao module in that document. Define a warm run as a subsequent
      registration in the same loaded SDK runtime.
- [ ] Preserve the raw timing summaries in an operator-owned benchmark artifact
      with no identity or authentication data.

Acceptance:

- The baseline reproduces the reported delay.
- Results distinguish mixed, Ed25519-only, and ECDSA-only signer sets.
- Each result identifies whether Yao and ECDSA were serialized or overlapped.

## Phase 1: Make Yao Time Visible

Replace the incomplete Ed25519 diagnostic branch with required, branch-specific
timing data. Record:

- Yao task start and completion offsets relative to registration start;
- Email OTP enrollment-material wait;
- Email OTP worker readiness;
- Yao WASM initialization;
- Router admission round trip;
- Client activation setup;
- Router execution round trip;
- Client completion and pending-capability creation;
- total Yao task duration;
- Yao cleanup or commit duration where applicable.

Record ECDSA branch start and completion offsets as well. Relative spans are
required to prove concurrency; aggregate durations alone cannot distinguish
overlap from serialization.

Implementation requirements:

- [ ] Return validated timing details through the worker response boundary.
      Worker internals must not mutate the registration recorder directly.
- [ ] Model Ed25519 diagnostics as a discriminated union with required fields
      for the enabled branch and `never` fields for the disabled branch.
- [ ] Replace `registration_timing_summary_v1` if the wire shape changes and
      remove the old producer and parser in the same change. Do not retain dual
      diagnostic schemas.
- [ ] Calculate measured coverage from the union of recorded time spans.
      Summing overlapping task durations must not hide unattributed gaps.
- [ ] Keep diagnostics opt-in and privacy-safe.
- [ ] Remove or replace literal source-guard assertions that merely duplicate
      the timing field list. Behavioral and type-level assertions own the new
      schema.

Acceptance:

- Yao no longer appears primarily as `unattributedElapsedMs`.
- The timing summary proves whether Yao and ECDSA overlap.
- Span-union coverage accounts for at least 90% of a successful registration.
- Invalid enabled/disabled diagnostic combinations fail type checking.

## Phase 2: Remove Email OTP Mixed-Branch Serialization

Refactor `RegistrationYaoWork` so passkey and Email OTP use one precise
asynchronous lifecycle:

```ts
type RegistrationYaoWorkState =
  | { kind: 'disabled' }
  | { kind: 'running'; completion: Promise<RegistrationYaoPendingResult> }
  | { kind: 'pending'; pending: ProductEd25519YaoPendingRegistrationPortV1 }
  | { kind: 'failed'; failure: RegistrationYaoFailure }
  | { kind: 'committed' }
  | { kind: 'disposed' };
```

The exact result and failure types should use the existing project `Result`
pattern. A running task must absorb rejection into its owned state so a
concurrent branch cannot produce an unhandled rejection.

Implementation steps:

- [ ] Make the Email OTP Yao starter return a running
      `RegistrationYaoWork` immediately after registration start.
- [ ] Keep enrollment material and recovery-code backup work starting as early
      as they do today.
- [ ] Start the strict Router A/B ECDSA threshold-PRF derivation ceremony
      (`runStrictEcdsaFamilyCeremony(...)`) immediately after the Email OTP Yao
      task is created.
- [ ] Join Yao and ECDSA before building the finalize request.
- [ ] Keep Yao activation references and ECDSA expected key handles in the same
      finalize request.
- [ ] Generalize `dispose()` across passkey and Email OTP running states. It
      must settle or cancel owned work and dispose a produced pending
      capability exactly once.
- [ ] Preserve fail-closed behavior when either branch fails. Finalization must
      remain unreachable.
- [ ] Use the same task lifecycle in Ed25519-only Email OTP registration even
      though that path has no ECDSA overlap.
- [ ] Remove the obsolete synchronous Email OTP Yao construction path after the
      new lifecycle is in place.

Acceptance:

- A deferred Yao test observes ECDSA start before Yao resolves.
- A deferred ECDSA test observes Yao admission/execute before ECDSA resolves.
- Finalization is not called until both branches resolve successfully.
- Failure in either ordering disposes Yao state exactly once and never
  finalizes.
- Successful registration commits Yao only after finalized identities and
  persistence inputs have been validated.

## Phase 3: Prewarm Email OTP Yao Resources

Add a dedicated registration-resource warmup request. Existing-account warmup
and pre-registration warmup represent different states and should remain
separate APIs.

The registration warmup input should be a discriminated union keyed by auth
method and signer set. An Email OTP request that includes Ed25519 should:

1. load the Email OTP worker module;
2. initialize the worker transport;
3. fetch and compile the Yao WASM module;
4. retain reusable module state within the current worker/runtime lifetime.

Implementation requirements:

- [ ] Start this prewarm as soon as the Google registration offer and selected
      signer set are known, while the wallet-name UI is visible.
- [ ] Run generic signer, confirmation-UI, Email OTP worker, and Yao module
      prewarming concurrently.
- [ ] Keep prewarm idempotent and best effort. A prewarm failure must be
      measured and retried by the real operation.
- [ ] Do not create factor roots, pending registrations, Router admissions, or
      durable records during prewarm.
- [ ] Include Email OTP worker and Yao WASM prewarm durations in registration
      diagnostics.
- [ ] Avoid prewarming Yao for ECDSA-only registration.

Acceptance:

- A cold Email OTP Ed25519 registration reuses the prewarmed worker and compiled
  module.
- Prewarm performs no authenticated request and writes no wallet state.
- ECDSA-only registration does not download or initialize Yao.
- A failed prewarm cannot change the registration result.

## Phase 4: Tests and Contract Coverage

Classify failures before changing tests. The concurrency defect is a
`production_regression`. Existing atomicity and identity assertions remain
authoritative. A source guard that requires the old timing field list is a
lower-authority fixture and should be replaced with behavioral or type-level
coverage.

Add or update:

- [ ] `tests/unit/addWalletSigner.orchestration.unit.test.ts`
      - Email OTP mixed Yao/ECDSA overlap;
      - finalize join ordering;
      - both branch-failure orderings;
      - exact-once Yao disposal;
      - Ed25519-only atomicity remains unchanged.
- [ ] `tests/unit/walletRegistrationYaoClientContracts.unit.test.ts`
      - worker timing boundary validation;
      - pending, failed, committed, and disposed transitions.
- [ ] registration timing unit coverage
      - required Ed25519 timing fields;
      - span-union coverage;
      - no identity-bearing diagnostic properties.
- [ ] a type fixture for invalid `RegistrationYaoWorkState` and Ed25519 timing
      combinations.
- [ ] intended-behaviour contracts for Email OTP mixed registration success,
      failure before finalize, and immediate post-registration signing.
- [ ] a staging browser benchmark that captures real cold and warm timing
      summaries without asserting fragile millisecond thresholds in ordinary
      CI.

Narrow validation commands:

```text
pnpm -C tests exec playwright test -c playwright.config.ts \
  ./unit/addWalletSigner.orchestration.unit.test.ts \
  ./unit/walletRegistrationYaoClientContracts.unit.test.ts \
  --reporter=line

pnpm test:intended
```

Run `pnpm check` because this change touches shared lifecycle types, worker
protocols, auth-sensitive registration, and public registration behavior.

## Phase 5: Stage, Measure, and Deploy

The concurrency and prewarm changes live in browser SDK, wallet iframe, worker,
and static WASM artifacts. They require the selected SDK/site artifact surfaces
to be deployed from one accepted exact-SHA release set.

A Gateway deployment is outside the core fix. Router A/B deployment is required
only if later measurement justifies server-side route changes.

- [ ] Build and publish the exact-SHA SDK/site release artifacts.
- [ ] Verify worker JS, Yao WASM, wallet iframe, and site assets all report the
      same release-set identity.
- [ ] Deploy to staging.
- [ ] Run the full Phase 0 sample matrix on staging.
- [ ] Confirm diagnostics show mixed-branch overlap and at least 90% timing
      coverage.
- [ ] Run one fresh Email OTP mixed-wallet registration through immediate NEAR
      and EVM-family signing.
- [ ] Promote the accepted release set to production without rebuilding.
- [ ] Repeat at least 5 cold and 10 warm production measurements.
- [ ] Disable the bounded production diagnostic collection after evidence is
      recorded.

Production acceptance:

- Warm p50 and cold p95 meet the objective or improve by at least 35% from the
  baseline.
- No registration timing sample shows OTP Yao fully preceding ECDSA in a mixed
  registration.
- Registration finalization occurs once per successful attempt.
- Post-registration NEAR and EVM-family signing use the expected identities.
- Production logs and diagnostics contain no OTP, JWT, email, credential, or
  key material.

## Rollback

This refactor requires no D1 migration and no durable schema change.

Rollback reactivates the previous accepted SDK/site artifact set. Preserve the
new benchmark evidence and classify any rollback-triggering failure before
further changes. If only prewarming causes a production problem, ship a new
accepted release that removes the faulty prewarm implementation while keeping
the structured-concurrency fix and timing coverage.

## Expected File Scope

Primary implementation:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519YaoWorkerClient.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/yaoClient.ts`
- `packages/sdk-web/src/core/signingEngine/assembly/warmup.ts`
- `packages/sdk-web/src/SeamsWeb/signingSurface/ports.ts`
- `packages/sdk-web/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`

Validation and documentation:

- `tests/unit/addWalletSigner.orchestration.unit.test.ts`
- `tests/unit/walletRegistrationYaoClientContracts.unit.test.ts`
- `tests/typecheck/`
- `tests/e2e/intended-behaviours/`
- `tests/scripts/check-registration-capability-subjects.mjs`
- `docs/refactor-patch-3-production-demo-readiness.md`

## Commit Boundaries

Keep the implementation reviewable:

1. timing schema, span coverage, and focused tests;
2. structured Yao/ECDSA concurrency and failure-ordering tests;
3. targeted Email OTP/Yao prewarm and cold-path tests;
4. staging measurements, corrected production-readiness documentation, and
   release evidence.

Do not reintroduce retired terminology or implementation paths. Do not combine
Gateway, delegate-signing, faucet, or OTP-delivery changes with this latency
refactor.
