# Deployment Refactor 2: Email OTP Registration Latency

Date created: July 23, 2026

Status: Phase 5 implementation complete; staging remains blocked on release validation

Implementation status: Phase 5 now covers offer-time selective Email OTP Yao
prewarm, the three registration variants, single-flight worker initialization,
failure-ordering cleanup, and result-style prewarm diagnostics. Focused browser
unit coverage passes. Phase 0 benchmark collection and Phase 6 artifact
deployment remain operational follow-up work.

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

- [x] Return validated timing details through the worker response boundary.
      Worker internals must not mutate the registration recorder directly.
- [x] Model Ed25519 diagnostics as a discriminated union with required fields
      for the enabled branch and `never` fields for the disabled branch.
- [x] Replace `registration_timing_summary_v1` if the wire shape changes and
      remove the old producer and parser in the same change. Do not retain dual
      diagnostic schemas.
- [x] Calculate measured coverage from the union of recorded time spans.
      Summing overlapping task durations must not hide unattributed gaps.
- [x] Keep diagnostics opt-in and privacy-safe.
- [x] Remove or replace literal source-guard assertions that merely duplicate
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

- [x] Make the Email OTP Yao starter return a running
      `RegistrationYaoWork` immediately after registration start.
- [x] Keep enrollment material and recovery-code backup work starting as early
      as they do today.
- [x] Start the strict Router A/B ECDSA threshold-PRF derivation ceremony
      (`runStrictEcdsaFamilyCeremony(...)`) immediately after the Email OTP Yao
      task is created.
- [x] Join Yao and ECDSA before building the finalize request.
- [x] Keep Yao activation references and ECDSA expected key handles in the same
      finalize request.
- [x] Generalize `dispose()` across passkey and Email OTP running states. It
      must settle or cancel owned work and dispose a produced pending
      capability exactly once.
- [x] Preserve fail-closed behavior when either branch fails. Finalization must
      remain unreachable.
- [x] Use the same task lifecycle in Ed25519-only Email OTP registration even
      though that path has no ECDSA overlap.
- [x] Remove the obsolete synchronous Email OTP Yao construction path after the
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
- [x] Run generic signer, confirmation-UI, Email OTP worker, and Yao module
      prewarming concurrently.
- [ ] Keep prewarm idempotent and best effort. A prewarm failure must be
      measured and retried by the real operation.
- [x] Do not create factor roots, pending registrations, Router admissions, or
      durable records during prewarm.
- [ ] Include successful and failed Email OTP worker and Yao WASM prewarm
      durations in registration diagnostics.
- [x] Avoid prewarming Yao for ECDSA-only registration.

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
      - current coverage proves Email OTP mixed Yao/ECDSA overlap and
        exact-once Yao disposal for deferred ECDSA failure;
      - add successful finalize join ordering;
      - add both branch-failure orderings with branch-specific fixtures;
      - preserve Ed25519-only atomicity and ECDSA-only isolation.
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

## Phase 5: Resolve Implementation-Review Release Blockers

The implementation must model three registration variants explicitly:

1. `ecdsa_only`;
2. `ed25519_only`;
3. `ecdsa_and_ed25519`.

Use discriminated unions and branch-specific builders throughout this phase.
Do not represent the variants with independent optional fields or boolean
flags.

### Phase 5A: Move Selective Prewarm to Registration-Offer Time

- [x] Add a required registration-prewarm dependency to the Google Email OTP
      registration flow.
- [x] Start prewarm after the registration offer and signer selection are
      resolved, before the wallet-name prompt is presented.
- [x] Wire the same prewarm lifecycle through direct browser and wallet-iframe
      registration paths.
- [x] Keep the prewarm handle with the active registration flow and reuse it
      when the user selects another offered wallet name.
- [x] Remove the pre-authentication wait on registration warmup. The real Yao
      operation must reuse an in-flight or completed worker initialization.
- [x] Select prewarm behavior by registration variant:
      - `ecdsa_only`: return `not_requested` and never initialize Yao;
      - `ed25519_only`: prewarm the Email OTP worker and Yao WASM;
      - `ecdsa_and_ed25519`: prewarm the same Yao resources while preserving
        concurrent ECDSA registration.

Acceptance:

- The worker/Yao prewarm request begins while the wallet-name UI is visible.
- Clicking Create does not wait for a separate pre-authentication warmup gate.
- ECDSA-only registration performs no Yao worker request or Yao WASM
  initialization.
- Wallet-name reroll does not create duplicate prewarm work.
- Prewarm remains unauthenticated and writes no wallet or factor state.

### Phase 5B: Restore Variant-Specific Success and Failure Coverage

- [x] Replace the shared ECDSA fixture that always throws with branch-specific
      successful, deferred-success, and deferred-failure builders.
- [x] Ensure all registration fixtures implement the current signing-surface
      contract, including preparation-modal cleanup and strict `chainTargets`
      response shapes.
- [x] Add one successful unit test for each registration variant:
      - ECDSA-only completes without starting or prewarming Yao;
      - Ed25519-only completes without starting an ECDSA ceremony;
      - mixed registration overlaps Yao and ECDSA, joins both branches, and
        finalizes exactly once.
- [x] In the successful mixed test, assert Yao commits exactly once after
      finalized identities and persistence inputs are validated.
- [x] Add mixed failure tests for Yao-first and ECDSA-first completion orderings.
      Each must dispose pending Yao state exactly once and must not finalize.
- [x] Add intended-behaviour coverage for successful mixed registration
      followed immediately by NEAR and EVM-family signing.

Acceptance:

- Existing ECDSA-only and Email OTP registration success tests pass.
- The new mixed success test returns `success: true`; failure tests cannot
  satisfy the success contract.
- The three variants cannot invoke work owned by a disabled signer branch.
- Finalization occurs exactly once only after every enabled branch succeeds.

### Phase 5C: Preserve Failed-Prewarm Diagnostics

- [x] Replace zero-value failure recovery with a result-style prewarm outcome:
      `not_requested`, `succeeded`, or `failed`.
- [x] Require branch-specific fields and use `never` fields to reject invalid
      combinations.
- [x] Record elapsed time and a bounded failure stage for failed prewarm
      without retaining raw errors or identity-bearing values.
- [x] Merge prewarm diagnostics without overwriting a measured duration with
      zero.
- [x] Preserve retry semantics by clearing failed worker initialization state
      so the real registration operation can initialize Yao again.
- [x] Add tests for successful, skipped, and failed prewarm outcomes, including
      a failed prewarm followed by a successful retry and registration.

Acceptance:

- Every attempted prewarm reports a non-negative elapsed duration.
- Failed prewarm is visible in diagnostics and cannot change the registration
  result.
- A real Ed25519 registration retries after prewarm failure.
- Diagnostic payloads contain no email, wallet identifier, JWT, OTP,
  credential, or key material.

Phase 5 validation:

```text
pnpm -C tests exec playwright test -c playwright.config.ts \
  ./unit/addWalletSigner.orchestration.unit.test.ts \
  ./unit/walletRegistrationYaoClientContracts.unit.test.ts \
  --reporter=line

pnpm test:intended
pnpm check
```

Local validation completed for the focused registration and worker-transport
tests, TypeScript type-check, diff check, and the WASM/SDK build. The complete
source-guard chain still stops at the existing Cloudflare D1 guard because the
repository lacks `packages/console-server-ts/wrangler.d1-staging-router-api.toml`
while the guard requires that path in `.gitignore`; this is unrelated to the
Phase 5 changes.

Phase 6 remains blocked until every Phase 5 acceptance condition passes.

## Phase 6: Stage, Measure, and Deploy

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

Rollback redeploys the previous accepted SDK/site artifact set through the
environment-specific Cloudflare stack workflow. This restores code and Pages
assets without reverting D1, Durable Object, secret, or other environment
state. Preserve the new benchmark evidence and classify any rollback-triggering
failure before further changes. If only prewarming causes a production problem,
ship a new accepted release that removes the faulty prewarm implementation
while keeping the structured-concurrency fix and timing coverage.

## Expected File Scope

Primary implementation:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`
- `packages/sdk-web/src/SeamsWeb/SeamsWeb.ts`
- `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/emailOtp.ts`
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
4. offer-time prewarm lifecycle and three-variant success fixtures;
5. failed-prewarm diagnostics and retry coverage;
6. staging measurements, corrected production-readiness documentation, and
   release evidence.

Do not reintroduce retired terminology or implementation paths. Do not combine
Gateway, delegate-signing, faucet, or OTP-delivery changes with this latency
refactor.
