# Refactor 83: Registration And Unlock Critical Path Cleanup

Date created: July 2, 2026
Updated: July 4, 2026 — aligned with the Refactor 82B authority/material type
decisions, the Refactor 90 reorganization, and the Email OTP unlock latency
extension; sequencing gates recorded below.

Status: implementation complete, residual HSS locality work deferred.

Sequencing gates:

- Phases 1 and 6 can start now.
- Phases 2-5 and 7 are gated on Refactor 82B Phases 6-7 exiting (Ed25519
  material-state unions and committed-lane loose-shape deletion complete),
  because Phases 3-5 edit `records.ts`, `sealedSessionStore.ts`, and
  `thresholdWarmSessionBootstrap.ts`, which 82B owns until that exit.
- Phase 7B can start after Refactor 82B Phase 10C exits and the manual Email OTP
  registration/unlock/sign/export flows pass. It shares warm-session files with
  Phases 3-5, so implementation must coordinate fact-write/current-commit
  boundaries instead of reintroducing generic upsert cleanup.
- Phase 1 baselines are captured after Refactor 84b's finalize payload trim
  lands, so measurements are not dominated by a payload that is about to
  shrink.
- Refactor 88 now provides both local and CI-managed intended lifecycle
  commands. Any 83 change touching registration, auth, warm sessions, signing
  lanes, export, or wallet iframe routing runs `pnpm test:intended` as the
  pre-merge lifecycle gate; use `pnpm test:intended:ci` when a fresh local
  startup/reset is needed.

Dated progress entries and validation evidence go to a companion journal file
(`refactor-83-journal.md`, created on first entry), not this plan.

## Goal

Remove redundant registration work from the current D1/DO signer-set flow while
preserving the security boundaries that matter:

- one registration intent
- one authority proof
- one Ed25519 registration ceremony
- one ECDSA registration bootstrap per requested ECDSA signer capability
- one local persistence transaction for the wallet state the SDK needs
- one authoritative post-registration wallet runtime state

Phase 7B extends the same measure-then-cut discipline to Email OTP wallet
unlock, which shares the warm-session, sealed-restore, and persistence
surfaces with the registration phases.

This plan is about simplifying and shortening the registration path. It is not a
new HSS protocol optimization plan and it is not a compatibility plan.

Scope extension: Email OTP wallet unlock has the same user-visible latency
problem class as registration when it reconstructs or restores warm signing
material. Phase 7B owns measuring and shortening that unlock activation path
without changing authentication semantics. Registration and unlock measurements
stay separate.

## Non-Goals

- Do not add legacy `mode: "ed25519_and_ecdsa"` handling.
- Do not add fallback registration routes.
- Do not hide missing material behind retry/fallback rehydration.
- Do not change HSS cryptographic transcript rules unless a separate HSS plan
  proves the change.
- Do not keep runtime postcondition scans as production control flow.
- Do not make Email OTP unlock reuse registration-only artifacts. Unlock consumes
  durable wallet/session state and produces current warm capability state.

## Related Plans

- `docs/refactor-55-hss-optimize-registration.md`: historical HSS runtime and
  hidden-eval optimization notes.
- `docs/refactor-61-registration-prep-parallelism.md`: earlier registration
  preparation overlap work.
- `docs/refactor-62-hss-prepare-preauth.md`: earlier pre-auth HSS prepare work.
- `docs/refactor-64-optimize-registration-2.md`: historical auth-agnostic
  precompute baseline.
- `docs/refactor-79-exact-signing-lane.md`: exact lane identity and runtime
  material modeling. This plan must reuse those types instead of introducing a
  parallel registration-only lane model.
- `docs/refactor-82-cloudflare-D1-migration.md`: D1/DO registration ceremony and
  signer-set backend ownership.
- `docs/refactor-82B.md`: authority typing cleanup. This plan consumes 82B's
  types — verified registration authority / `AuthFactorIdentity` at prepare,
  `WalletAuthMethodId` bindings, `ActiveWalletSession`, and the
  `Ed25519WorkerMaterialState` union. Phases 2-5 and 7 are gated on 82B
  Phases 6-7 exiting. Phase 7B consumes 82B Phase 10C's fact-write and
  current-session-commit split.
- `docs/refactor-84a-iframe-walletId.md`: visible registration is wallet-bound
  before WebAuthn. Phase 6 treats the registration draft wallet ID as part of
  precompute scope, with reroll as a named scope-invalidation case.
- `docs/refactor-84b-trim-hss.md`: finalize payload trim on the same route
  Phase 3 may touch. 84b lands before Phase 1 baselines; finalize contract
  changes are coordinated, not landed independently by both plans.
- `docs/refactor-85-indexedDB.md`: IndexedDB minimization. Phase 4's single
  persistence commit feeds 85's Phase 7 schema shrink.
- `docs/refactor-90-modular-auth-capabilities-plan.md`: Phase B6 promotes the
  signer-set request into capability provisioning. Prepared-branch identities
  in this plan must stay stable so B6 can map them to capability provisioning
  identities.

## Current Suspected Redundant Work

These are hypotheses to measure and either remove or explicitly keep.

- [x] Registration precompute can be started twice: once by UI prewarm and again
      inside `registerWalletInternal()` when the precompute handle is absent,
      stale, or scoped differently.
      Completed July 4, 2026: registration now models precompute as an explicit
      `start_inside_register_wallet` or `use_started_precompute` branch.
      Google Email OTP visible registration starts one scoped handle and
      completes through `registerWalletWithStartedPrecompute()`; scope mismatch
      fails closed before work is reused.
- [x] Router A/B keyset prefetch was running for every signer-set registration
      precompute. It is now branch-gated to the signer branches that need it.
      Completed July 4, 2026: Ed25519-only registration precompute now skips the
      Router A/B keyset fetch; combined Ed25519+ECDSA registration still
      prefetches it.
- [x] The client recomputes and rechecks registration intent digest after the
      server already returned the intent digest. The local digest check is useful
      at the boundary, but it should not become repeated core flow work.
      Completed July 4, 2026: the digest comparison is intentionally retained
      as the client boundary check for the server-returned challenge digest, but
      it lives only in `verifyWalletRegistrationIntentResponse()`. A Refactor 83
      guard rejects reintroducing `computeRegistrationIntentDigest()` outside
      that boundary helper.
- [x] D1 registration start reparses signer branches, runtime policy scope, and
      ECDSA chain targets after prepare already parsed equivalent state. The DO
      should store a normalized prepared registration package so later routes do
      not rederive the same branch shape repeatedly. Partial July 4, 2026:
      stored preparations and ceremonies now carry a normalized `signerPlan`,
      and start/respond/finalize consume that stored plan for branch selection.
      Completed July 4, 2026: stored preparations and ceremonies also carry the
      prepared runtime/signing-root/ECDSA context, and finalize reads runtime
      policy from that prepared context.
- [x] Passkey Ed25519 registration previously completed the registration HSS
      ceremony, persists the returned warm session, then immediately runs another
      Ed25519 HSS warm-session reconstruction ceremony to produce local worker
      material. Completed July 4, 2026: passkey registration now persists
      worker material directly from the registration HSS material and keeps
      reconstruction for login/recovery/sync.
- [x] Local wallet persistence is split across Ed25519 account data, Ed25519
      session data, optional ECDSA session data, optional ECDSA signer records,
      wallet activation, and immediate lane assertion. These should collapse
      into one typed persistence plan and one commit where IndexedDB allows it.
      Completed July 4, 2026: registration now builds a typed
      `RegistrationPersistencePlan` and commits it through one orchestrator
      function; literal IndexedDB row construction still lives inside the
      existing IndexedDB boundary APIs.
- [x] `immediateSigningLaneAssertionMs` does runtime inventory scans after
      registration. The production path should construct active runtime state
      from the persisted registration result. Tests can assert the same invariant
      without a user-visible runtime scan. Completed July 4, 2026: production
      registration now constructs `registration_active_runtime_state_v1` from
      the persistence plan, and the timing bucket remains zero.
- [x] Email OTP registration may prepare/reconstruct material and backup recovery
      codes serially where the work is independent.
      Completed July 4, 2026: Email OTP registration now starts enrollment
      material preparation immediately after OTP authority proof, lets the
      ECDSA-only `/start` request proceed while that material is preparing, and
      starts recovery-code backup as soon as enrollment material resolves.
- [x] Email OTP wallet unlock may serially restore Ed25519 material, restore or
      bootstrap ECDSA material, apply server seals, write sealed/current session
      records, and rebuild active runtime state. Measure before moving work.
      Completed July 4, 2026: the current combined Email OTP unlock traces show
      Ed25519 material restore dominates the activation path. Local persistence
      is small enough that collapsing it is not justified in this refactor
      slice.

## Target Shape

Registration should become a small state machine with one produced artifact per
stage. These sketches reuse the Refactor 82B and Refactor 79 types by name;
this plan must not mint parallel registration-only authority, lane, or
material types.

One prepared package shape, not a per-mode union. Ed25519-only registration is
a one-branch signer set on the same machinery (Phase 0A); a
`near_ed25519_prepared` vs `signer_set_prepared` split would re-introduce the
deleted mode-enum thinking. Branch identities stay stable so Refactor 90 B6
can map them to capability provisioning identities.

```ts
type PreparedRegistrationBranch =
  | {
      kind: 'near_ed25519';
      branchId: RegistrationSignerBranchId;
      prepared: PreparedNearEd25519Registration;
    }
  | {
      kind: 'evm_family_ecdsa';
      branchId: RegistrationSignerBranchId;
      prepared: PreparedEvmFamilyEcdsaRegistration;
    };

type RegistrationPreparedPackage = {
  intent: NormalizedRegistrationIntent;
  // Verified once at prepare and stored with the preparation (82B Phase 3);
  // never re-derived by later routes.
  authority: VerifiedRegistrationAuthority;
  branches: readonly PreparedRegistrationBranch[];
};
```

Runtime material reuses the 82B material-state unions. Do not mint a
method-kinded material type (`passkey_runtime_material` /
`email_otp_runtime_material`) — the branches would be structurally parallel,
which the 82B typing constraints forbid. The real discriminant is material
state; the authority's factor branch implies which state is expected (passkey
registration produces `loaded_material`, Email OTP produces
`sealed_material`), and that rule is enforced in the single commit builder.

```ts
type FinalizedRegistrationRuntimeMaterial = {
  ed25519: Extract<
    Ed25519WorkerMaterialState,
    { kind: 'loaded_material' | 'sealed_material' }
  >;
  ecdsa: readonly EcdsaRegistrationMaterialState[]; // same rule via the ECDSA material-state union
};

type RegistrationPersistencePlan = {
  wallet: RegisteredWalletBinding;
  authMethodBinding: WalletAuthMethodId; // 82B stable binding id
  signers: RegisteredSignerSet;
  runtimeMaterial: FinalizedRegistrationRuntimeMaterial;
  activeSession: ActiveWalletSession; // 82B type; minted at finalize
};
```

Email OTP unlock uses the same strict material/session vocabulary, but it is a
different lifecycle. It starts from durable wallet-bound authority and sealed
material, then produces current warm capabilities. It must not pass generic
persisted records into signing; all current records cross the 82B Phase 10C
commit boundary first.

```ts
type EmailOtpUnlockActivationPlan = {
  activeSession: ActiveWalletSession;
  ed25519: OperationUsableThresholdEd25519SessionRecord;
  ecdsa: readonly OperationUsableThresholdEcdsaSessionRecord[];
  runtimeState: ActiveWalletRuntimeState;
};
```

## Phase 1: Measurement And Trace Cleanup

- [x] Capture one clean local registration trace for:
      passkey `near_ed25519` only, passkey `near_ed25519 + evm_family_ecdsa`,
      Google Email OTP `near_ed25519` only, and Google Email OTP combined.
      Completed tooling July 4, 2026: the intended E2E page and harness now
      accept `passkeyEcdsaTargetProfile` /
      `SEAMS_INTENDED_PASSKEY_ECDSA_TARGET_PROFILE` and
      `emailOtpEcdsaTargetProfile` /
      `SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE` with `none`, `tempo`, and
      `tempo_arc` branches, so Ed25519-only, Tempo-only, and combined samples
      are representable. Updated July 5, 2026: passkey `near_ed25519` only now has a
      clean trace at
      `test-results/intended-lifecycle-traces/1783185253604-passkey.registration-verdant-harvest-8hzspp-intended-lifecycle-trace.json`
      with total registration 5,193ms, `walletRegisterFinalizeMs` 3,311ms,
      route `registrationHssFinalizeMs` 3,293ms,
      `registrationHssFinalizeReportMs` 2,858ms, and
      `ed25519EvaluationArtifactMs` 456ms.
      Updated July 5, 2026: Google Email OTP `near_ed25519` only now has a
      clean trace at
      `test-results/intended-lifecycle-traces/1783189388294-email_otp.registration-harbor-tempo-gtun6n-intended-lifecycle-trace.json`
      with total registration 5,256ms, `walletRegisterFinalizeMs` 3,257ms,
      route `registrationHssFinalizeMs` 3,232ms,
      `registrationHssFinalizeReportMs` 2,798ms,
      `ed25519EvaluationArtifactMs` 456ms, and
      `thresholdEd25519SessionPersistenceMs` 443ms.
      Updated July 5, 2026: passkey `near_ed25519 + evm_family_ecdsa`
      now has a clean `tempo_arc` trace at
      `test-results/intended-lifecycle-traces/1783189753190-passkey.registration-harbor-vermillion-qpgbcr-intended-lifecycle-trace.json`
      with total registration 5,740ms, `walletRegisterFinalizeMs` 3,232ms,
      route `registrationHssFinalizeMs` 3,214ms,
      `registrationHssFinalizeReportMs` 2,779ms,
      `ecdsaRegistrationPersistenceMs` 550ms, and
      `ed25519EvaluationArtifactMs` 458ms.
      Updated July 5, 2026: the Google Email OTP combined `tempo_arc`
      benchmark exposed an Email OTP ECDSA registration-root handle bug: one
      single-use worker handle was issued for the whole EVM-family branch, then
      reused for the second chain target. Registration material now carries
      target-scoped `{ chainTarget, evmFamilySigningKeySlotId }` handles.
      Updated July 5, 2026: Google Email OTP combined `tempo_arc` now has a
      clean trace at
      `test-results/intended-lifecycle-traces/1783192113778-email_otp.registration-polar-summit-wzneye-intended-lifecycle-trace.json`
      with total registration 5,145ms, `walletRegisterFinalizeMs` 3,201ms,
      route `registrationHssFinalizeMs` 3,182ms,
      `registrationHssFinalizeReportMs` 2,753ms,
      `ed25519EvaluationArtifactMs` 447ms,
      `ed25519ClientMaterialMs` 373ms,
      `emailOtpEnrollmentMaterialMs` 356ms,
      `thresholdEd25519SessionPersistenceMs` 442ms, and
      `ecdsaRegistrationPersistenceMs` 21ms.
- [x] Add or tighten timing buckets for the current suspicious tail:
      `thresholdEd25519SessionPersistenceMs`,
      `threshold_ed25519_warm_material_reconstruction_started`,
      `ecdsaRegistrationPersistenceMs`,
      `walletStateActivationMs`, and `immediateSigningLaneAssertionMs`.
      Completed July 4, 2026: registration timing summaries retain the
      Ed25519 session persistence, ECDSA persistence, wallet activation, and
      immediate-lane assertion buckets as observational fields in the critical
      path summary. The deleted second Ed25519 warm-material reconstruction no
      longer emits `threshold_ed25519_warm_material_reconstruction_started`,
      and the Refactor 83 guard rejects reintroducing that registration event.
      Updated July 4, 2026: the Ed25519 session-persistence wrapper now records
      sub-buckets for key-material persistence, session normalization,
      warm-material validation, warm-capability persistence, worker-material
      persistence, signing-session hydration, and sealed-session persistence.
      The critical-path ranking uses the sub-buckets so the old wrapper no
      longer hides the actual slow stage.
      Updated July 5, 2026: intended traces now enable registration route
      diagnostics and D1 finalize attaches
      `wallet_registration_route_diagnostics_v1`, so
      `walletRegisterFinalizeMs` has a server-side breakdown.
- [x] Add a registration critical-path summary that distinguishes elapsed time
      from background work. Diagnostics must stay observational.
      Completed July 4, 2026: timing summaries now include
      `registration_critical_path_summary_v1` with elapsed time, measured work,
      overlapped/background work, and the top measured buckets. The summary is
      also emitted as a JSON line so `intended-lifecycle-trace.json` can be used
      as a parseable baseline source.
- [x] Record baseline p50 and one cold-run worst case in this document before
      removing code.
      Current benchmark captured July 4, 2026 after the Refactor 83 timing
      instrumentation landed, because no clean pre-83 baseline was recorded
      before implementation began. `SEAMS_INTENDED_PERSIST_TRACE=1 pnpm -C
      tests exec playwright test -c playwright.intended.ci.config.ts
      e2e/intended-behaviours/email-otp.registration.contract.test.ts
      --reporter=line` passed 1/1 and wrote
      `test-results/intended-lifecycle-traces/1783173093265-email_otp.registration-indigo-bloom-294f55-intended-lifecycle-trace.json`.
      Current Email OTP combined registration elapsed time is 14,072ms. The
      top critical-path buckets are
      `thresholdEd25519SessionPersistenceMs` 6,913ms,
      `walletRegisterFinalizeMs` 5,411ms,
      `ed25519EvaluationArtifactMs` 470ms,
      `ed25519ClientMaterialMs` 382ms, and `walletRegisterPrepareMs` 375ms.
      A second registration captured during the unlock contract setup measured
      14,264ms with the same top two buckets. A fresh post-change green unlock
      contract trace added a third combined registration sample at 13,912ms in
      `test-results/intended-lifecycle-traces/1783175459504-email_otp.unlock-crimson-raven-vkxvzk-intended-lifecycle-trace.json`.
      Current combined Email OTP registration samples are 13,912ms, 14,072ms,
      and 14,264ms, so the current observed p50 is 14,072ms and the cold-run
      worst case is 14,264ms. Treat these as current post-instrumentation
      baselines, not a pre-refactor comparison.
      Updated July 5, 2026: a fresh post-84b intended registration trace passed
      1/1 and wrote
      `test-results/intended-lifecycle-traces/1783178970696-email_otp.registration-golden-ember-e4bdkp-intended-lifecycle-trace.json`.
      Email OTP combined registration elapsed time was 13,954ms. The top
      critical-path buckets were `thresholdEd25519WorkerMaterialPersistenceMs`
      6,578ms, `walletRegisterFinalizeMs` 5,345ms,
      `ed25519EvaluationArtifactMs` 462ms, `walletRegisterPrepareMs` 378ms,
      and `ed25519ClientMaterialMs` 376ms. The old
      `thresholdEd25519SessionPersistenceMs` wrapper was 6,874ms, with
      key-material persistence 1ms, warm-capability persistence 1ms,
      signing-session hydration 294ms, sealed-session persistence 0ms, and
      worker-material persistence 6,578ms. Route diagnostics showed
      `walletRegisterFinalizeMs` was dominated by `registrationHssFinalizeMs`
      5,319ms; route persistence was 5ms and session mint was 1ms.
      Updated July 5, 2026: the first clean Email OTP Ed25519-only benchmark
      passed 1/1 and wrote
      `test-results/intended-lifecycle-traces/1783189388294-email_otp.registration-harbor-tempo-gtun6n-intended-lifecycle-trace.json`.
      Total registration was 5,256ms. Top buckets were
      `walletRegisterFinalizeMs` 3,257ms, `ed25519EvaluationArtifactMs` 456ms,
      `ed25519ClientMaterialMs` 397ms, `emailOtpEnrollmentMaterialMs` 378ms,
      and `walletRegisterPrepareMs` 303ms. The server route reported
      `registrationHssFinalizeMs` 3,232ms with
      `registrationHssFinalizeSerializedSessionMaterializeMs` 151ms,
      `registrationHssFinalizeReportMs` 2,798ms,
      `registrationHssFinalizeOpenServerOutputMs` 161ms, and
      `registrationHssFinalizeOpenSeedOutputMs` 98ms.
- [x] Capture baselines after the Refactor 84b finalize payload trim lands, and
      note the 84b state next to the recorded numbers so the two changes are
      not conflated. Completed July 5, 2026: the post-84b trace above shows the
      slow stages are HSS finalize and Email OTP Ed25519 worker-material
      persistence. The 84b transport trim is therefore not the observed source
      of the 6-7s `thresholdEd25519SessionPersistenceMs` tail.
- [x] Capture baselines before Refactor 86 Phase 3 flips local wallet-asset
      serving to the static wallet origin, or record the serving topology
      beside the numbers; a topology change mid-measurement contaminates the
      comparison. The July 4, 2026 benchmark used the current local intended
      topology before the Refactor 86 Phase 3 static wallet-origin flip.
      Completed July 5, 2026: the Phase 1 registration matrix is recorded
      under the same current local intended topology, before the static
      wallet-origin flip.

Exit criteria:

- [x] We can point to the top three registration costs from a trace.
      Completed July 5, 2026: current combined Email OTP registration traces
      point to `thresholdEd25519WorkerMaterialPersistenceMs`,
      `walletRegisterFinalizeMs` / route `registrationHssFinalizeMs`, and
      `ed25519EvaluationArtifactMs` as the top measured registration costs.
- [x] We know whether the second Ed25519 HSS ceremony is on the critical path.
      Completed July 4, 2026: the second passkey registration Ed25519 HSS
      ceremony no longer exists on the registration path. Passkey registration
      persists worker material directly from the registration HSS output, and
      reconstruction remains scoped to login/recovery/sync flows.

## Phase 2: Single Prepared Registration Package

Refactor 82B already landed the seed of this package: registration prepare
verifies authority, stores it with the preparation, and prepared start
consumes only `registrationPreparationId`. This phase extends that stored
preparation rather than building a parallel one.

- [x] Extend the stored preparation into the normalized prepared registration
      package at the D1/DO boundary: already-parsed intent, the verified
      registration authority (never re-derived by later routes), prepared
      signer branches with stable branch identities, runtime policy scope,
      signing-root scope, and normalized ECDSA chain targets.
- [x] Persist the normalized registration `signerPlan` in stored preparation and
      ceremony records, validate it against the stored intent at the
      persistence boundary, and bind it into the atomic
      `consumeRegistrationIntentForPreparation()` check.
- [x] Update `/wallets/register/prepare`, `/start`, `/hss/respond`, and
      `/finalize` to consume the prepared package instead of reparsing the same
      raw shapes in each route.
- [x] Update `/start`, `/hss/respond`, and `/finalize` to consume the stored
      signer plan for registration branch selection. Runtime-policy scope and
      normalized ECDSA targets are carried through the stored prepared context
      instead of being re-parsed in the post-prepare core path.
- [x] Keep raw request parsing only in route parsers and D1/DO persistence
      boundary parsers.
      Completed July 4, 2026: `/prepare` and `/start` still parse request
      intent at the request/DO boundary; `/hss/respond` and `/finalize` consume
      stored ceremony `signerPlan`/prepared context. The Refactor 83 guard now
      rejects reintroducing raw intent parsing in post-prepare route handlers.
- [x] Delete duplicate private signer-selection parser calls from
      `respondWalletRegistrationHss()` and `finalizeWalletRegistration()` by
      reading branch facts from `ceremony.signerPlan`.
- [x] Delete duplicate runtime-scope and ECDSA-target parser calls from the
      registration start/respond/finalize core path.
- [x] Add type fixtures rejecting raw registration intent branches in post-prepare
      core functions.

Exit criteria:

- [x] After prepare, core registration route code accepts only normalized
      prepared package types.
- [x] Start/respond/finalize no longer rederive ECDSA chain targets or Ed25519
      prepare scope from raw intent objects.

## Phase 3: Eliminate Duplicate Ed25519 Worker-Material Reconstruction

- [x] Inventory exactly what material the Ed25519 registration HSS ceremony
      already produces in `completeRegisteredThresholdEd25519Registration()`.
- [x] Compare that output with what
      `reconstructThresholdEd25519SigningMaterialFromWarmSession()` produces for
      a new registration.
- [x] If the registration ceremony already has enough information to construct
      `LoadedEd25519WorkerMaterial`, route that material directly into
      persistence.
- [x] If the registration ceremony lacks one required field, change the finalize
      response or local completion type so the missing field is produced once at
      finalize time. Do not add a second ceremony. Updated July 5, 2026: the
      finalize response now returns a narrow
      `threshold_ed25519_registration_worker_material_report_v1` containing the
      registration HSS context binding and client output message. It does not
      expose seed output. Registration persistence combines that report with
      the original prepared session, client output-mask handle, and auth-method
      seal authorization to store worker material directly.
- [x] Coordinate any finalize request/response shape change with Refactor 84b,
      which owns the staged-artifact transport trim on the same route. One
      finalize contract change per landing — two plans must not edit the
      payload independently. Updated July 5, 2026: Refactor 84b trimmed the
      client-sent staged artifact. This Phase 3 correction adds only the
      registration worker-material report to the finalize response, because the
      client otherwise has to run a second warm-session HSS ceremony to obtain
      the client output needed by the sealed worker-material store.
- [x] Delete the immediate passkey registration call to
      `reconstructThresholdEd25519SigningMaterialFromWarmSession()`.
- [x] Keep warm-session reconstruction for login, recovery, and sync flows only
      where registration material is unavailable.
- [x] Add a guard that fails if passkey registration calls
      `reconstructThresholdEd25519SigningMaterialFromWarmSession()` after
      finalize. Updated July 5, 2026: the guard also rejects registration
      worker-material helpers calling
      `runThresholdEd25519HssCeremonyWithMaterialHandle`; those helpers must
      store from the finalized registration HSS report.

Exit criteria:

- [x] Passkey and Email OTP registration perform one Ed25519 HSS ceremony total.
- [x] The persisted Ed25519 session is immediately signable after registration.
- [x] Login/recovery reconstruction remains covered by its own tests.

## Phase 4: Collapse Local Persistence Into A Registration Commit

- [x] Build a typed `RegistrationPersistencePlan` before writing IndexedDB.
- [x] Include wallet profile rows, auth method rows, signer activation rows,
      key-material rows, Ed25519 runtime session rows, ECDSA runtime session
      rows, and selected-wallet state in the plan.
      Completed July 4, 2026: `RegistrationPersistencePlan` now carries
      `registration_persistence_write_subjects_v1`, built by
      `buildRegistrationPersistencePlan()` from the same auth, Ed25519, and
      ECDSA branches the commit consumes. The subject inventory names wallet
      profile rows, auth-method rows, signer activations, key-material rows,
      runtime-session rows, and the selected-wallet/activation branch.
- [x] Replace ad hoc sequential persistence calls in
      `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
      with one commit function that accepts only `RegistrationPersistencePlan`.
- [x] Keep persistence compatibility handling inside IndexedDB boundary parsers.
      Completed July 4, 2026: registration core now builds
      `RegistrationPersistencePlan`/write-subjects and commits through signing
      and account persistence ports. Compatibility and malformed persisted
      record handling remain in account lifecycle, session-record,
      sealed-session, and platform persistence boundaries.
- [x] Remove post-write reads that only verify data the commit function just
      wrote. Replace them with targeted tests on the commit function.
- [x] Keep post-write checks only where they verify external state, such as
      on-chain NEAR account readiness.
      Completed July 4, 2026: production registration no longer re-reads local
      lane/profile inventory as a success postcondition; the retained
      post-registration check is the external sponsored NEAR account readiness
      probe.

Exit criteria:

- [x] Successful registration performs one logical local persistence commit.
- [x] The registration path no longer reads profile/account mappings solely to
      prove its own IndexedDB write.

## Phase 5: Replace Runtime Lane Assertion With Constructed Active State

- [x] Replace `assertImmediateRegistrationSigningLanes()` in the production
      success path with active wallet runtime state built from the finalized
      registration result and persistence plan.
- [x] Move lane inventory assertions into unit/integration tests. The
      combined-registration fixture now asserts
      `registration_active_runtime_state_constructed`, and the Refactor 83
      guard rejects reintroducing `readPersistedAvailableSigningLanes` or
      `assertImmediateRegistrationSigningLanes` in the production registration
      path.
- [x] Ensure exact-lane state after registration uses the same canonical types as
      Refactor 79. The constructed active runtime state now carries
      `ExactEd25519SigningLaneIdentity` and a non-empty list of
      `ExactEcdsaSigningLaneIdentity` values built through the canonical
      Refactor 79 builders.
- [x] Delete registration-only lane availability predicates that duplicate exact
      lane selectors.

Exit criteria:

- [x] Production registration no longer scans runtime lane inventory as a
      postcondition.
- [x] Newly registered wallets can sign NEAR and EVM using the constructed
      active state.
      Completed July 4, 2026: production registration no longer performs the
      persisted-lane inventory scan, and manual testing reported newly
      registered passkey and Email OTP wallets signing NEAR plus EVM-family
      transactions successfully.

## Phase 6: Precompute Ownership And Scope Cleanup

- [x] Make the UI-started precompute handle the single precompute owner for
      registration surfaces that can start precompute before click completion.
      Completed July 4, 2026: Google Email OTP registration starts one local
      precompute handle and completes through
      `registerWalletWithStartedPrecompute()` when the main-window registration
      domain owns the work. The wallet-iframe domain intentionally reports
      precompute unavailable and routes registration through the iframe. The
      remaining direct `registerWallet()` path is the explicit non-prewarmed
      public/API branch.
- [x] Make `registerWalletInternal()` require either a valid precompute handle or
      an explicit `start_inside_register_wallet` branch for non-prewarmed callers.
- [x] Add exact scope mismatch diagnostics, then fail closed instead of silently
      starting another expensive precompute for the same click path.
      Completed July 4, 2026: `registerWalletWithStartedPrecompute()` rejects
      stale handles before `read()` and reports the mismatched scope fields.
- [x] Treat the Refactor 84a registration draft as the precompute scope owner
      for visible flows: precompute scope includes the draft wallet ID, and a
      wallet reroll replaces the draft and invalidates the precompute handle as
      a named scope change — never a silent re-precompute.
- [x] Branch-gate Router A/B keyset prefetch.
      Completed July 4, 2026: `startWalletRegistrationPrecomputeReady()` starts
      keyset prefetch only when the normalized signer plan includes an
      EVM-family ECDSA branch.
- [x] Branch-gate ECDSA bootstrap preparation.
      Completed July 4, 2026: Ed25519-only registration has a focused test
      assertion that no ECDSA client bootstrap is prepared.
- [x] Delete duplicate precompute lifecycle helpers that exist only to support
      stale UI flows.
      Completed July 4, 2026: no second UI lifecycle helper remains for
      main-window Google Email OTP registration; started handles are disposed by
      the flow that owns them, and the Refactor 83 guard records the explicit
      precompute branch split.

Exit criteria:

- [x] One user registration attempt maps to one precompute handle.
      Completed July 4, 2026: Google Email OTP registration creates exactly one
      local handle for the selected candidate wallet, reroll disposes it before
      creating the next flow, and scope mismatch is a hard registration error.
- [x] A scope mismatch is visible as a registration error, not as duplicate work.

## Phase 7: Email OTP Tail Parallelism

- [x] Identify which Email OTP work depends on verified OTP authority and which
      work depends only on the registration intent.
- [x] Run recovery-code backup, enrollment material preparation, and ECDSA
      bootstrap work in parallel where their inputs are already available.
      Completed July 4, 2026: OTP proof starts enrollment material work;
      ECDSA bootstrap and Ed25519 material consume that single promise at their
      typed boundaries, and recovery-code backup starts from the same material
      promise.
- [x] Keep backup acknowledgement single-use and tied to finalize.
      Completed July 4, 2026: backup runs in the background but the
      `emailOtpBackupAck` is still created only by the finalize path.
- [x] Delete stale Email OTP registration fixtures that encode old serialized
      tail work.
      Completed July 4, 2026: the registration orchestration fixture now
      asserts `/wallets/register/start` proceeds before Email OTP enrollment
      material resolves, while `/hss/respond` and `/finalize` remain gated on
      enrollment material and backup acknowledgement.

Exit criteria:

- [x] Email OTP registration keeps the same authority and backup semantics with a
      shorter post-OTP tail.
      Completed July 4, 2026: focused tests cover the overlapped ECDSA-only
      Email OTP registration path and verify the strict finalize
      `emailOtpEnrollment`/`emailOtpBackupAck` payload shape.

Phase 7B is this phase's unlock sibling: build the post-OTP parallelism
helpers once and share them across both flows.

## Phase 7B: Email OTP Unlock Critical Path

Status: complete. Manual Refactor 82B validation shows Email OTP main flows
work, and the benchmark matrix now measures unlock as its own lifecycle. The
remaining latency is Ed25519 material restore/server-HSS behavior, which belongs
to the deferred HSS locality work rather than more registration/unlock
persistence cleanup.

Do:

- [x] Capture one clean local Email OTP unlock trace for a wallet with:
      Ed25519 only, Ed25519 plus Tempo, and Ed25519 plus Tempo plus Arc/EVM.
      Completed tooling July 4, 2026: the strict intended harness target-profile
      parameter from Phase 1 is available for the Ed25519-only and Tempo-only
      samples. Updated July 5, 2026: the Ed25519-only unlock route now uses a private
      wallet-iframe RPC so session reconstruction runs in the wallet-service
      origin where Email OTP signer rows are persisted. The first intended
      Ed25519-only benchmark attempt was blocked by an expired local intended
      Google `id_token`; the July 5 matrix below supersedes that failure.
      Completed July 5, 2026: all three benchmark profiles passed against the
      same intended-services stack after refreshing the token and regenerating
      SDK/WASM artifacts:
      `1783195830676-email_otp.unlock-violet-quartz-psqmbh-intended-lifecycle-trace.json`
      for Ed25519-only,
      `1783195852065-email_otp.unlock-frost-summit-vx64pk-intended-lifecycle-trace.json`
      for Ed25519 plus Tempo, and
      `1783195871904-email_otp.unlock-cobalt-voyage-pfprt6-intended-lifecycle-trace.json`
      for Ed25519 plus Tempo plus Arc/EVM.
- [x] Add or tighten unlock timing buckets for:
      `emailOtpProofVerificationMs`, `appSessionExchangeMs`,
      `ed25519MaterialRestoreMs`, `ecdsaMaterialRestoreMs`,
      `signingSessionSealApplyMs`, `warmCapabilityPersistenceMs`,
      `activeRuntimeConstructionMs`, and wallet-iframe round trip time.
      Completed July 4, 2026: Google Email OTP app-session exchange success
      events include `appSessionExchangeMs`; local Email OTP unlock emits
      `email_otp_unlock_timing_summary_v1` with top buckets for reconstruction
      plan resolution, OTP proof verification, Ed25519 material restore, ECDSA
      material restore, server seal application, warm-capability persistence,
      wallet-state activation, active runtime construction, and wallet-iframe
      round-trip time. The Ed25519-only and combined ECDSA unlock helpers now
      return typed timing records, and the Refactor 83 guard rejects collapsing
      them back into a single coarse worker span. The summary is also emitted
      as a JSON line for intended trace baseline extraction.
- [x] Record unlock baseline p50 and one cold-run worst case in this document
      before removing code, under the same 84b and Refactor 86 serving-topology
      annotations as the Phase 1 registration baselines.
      Current single-run unlock activation baseline captured July 4, 2026 in
      `test-results/intended-lifecycle-traces/1783173252521-email_otp.unlock-frost-ember-s6y62s-intended-lifecycle-trace.json`.
      The core `email_otp_unlock_timing_summary_v1` succeeded with
      `prewarm.kind = not_prewarmed` and total elapsed time 8,011ms. Top
      buckets were `workerUnlockAndSessionBootstrapMs` 8,002ms,
      `ed25519MaterialRestoreMs` 6,957ms, `signingSessionSealApplyMs` 562ms,
      `emailOtpProofVerificationMs` 388ms, and `ecdsaMaterialRestoreMs` 80ms.
      A fresh green post-change unlock contract captured
      `test-results/intended-lifecycle-traces/1783175459504-email_otp.unlock-crimson-raven-vkxvzk-intended-lifecycle-trace.json`.
      Its core unlock activation elapsed time was 7,993ms with
      `workerUnlockAndSessionBootstrapMs` 7,985ms,
      `ed25519MaterialRestoreMs` 6,938ms, `signingSessionSealApplyMs` 562ms,
      `emailOtpProofVerificationMs` 387ms, and `ecdsaMaterialRestoreMs` 83ms.
      The current usable combined unlock samples are 7,993ms and 8,011ms; using
      nearest-rank p50 for the small sample gives 7,993ms, and the observed
      worst case is 8,011ms. This is a current post-change combined-flow
      baseline before the 83B unlock durable-advance follow-up. Updated July
      5, 2026: the shared HSS pool fix reduced unlock without unlock-specific
      work: `ed25519MaterialRestoreMs` improved from 6,957ms to 2,391ms and
      `workerUnlockAndSessionBootstrapMs` improved from 8,002ms to 3,487ms.
      The remaining restore cost was the old full-replay session ceremony, so
      unlock/session HSS now uses `/router-ab/ed25519/hss/advance` and
      requires durable advanced eval before finalize.
      baseline. Updated July 5, 2026: the benchmark matrix captured fresh
      not-prewarmed core activation samples for Ed25519-only, Tempo-only, and
      Tempo+Arc. Ed25519-only completed in 5,001ms with
      `ed25519MaterialRestoreMs` 4,622ms and `emailOtpProofVerificationMs`
      374ms. Tempo-only completed in 5,295ms with
      `ed25519MaterialRestoreMs` 4,592ms, `signingSessionSealApplyMs` 270ms,
      and `ecdsaMaterialRestoreMs` 48ms. Tempo+Arc completed in 5,651ms with
      `ed25519MaterialRestoreMs` 4,629ms, `signingSessionSealApplyMs` 547ms,
      and `ecdsaMaterialRestoreMs` 75ms. The duplicated host-side summary logs
      only `walletIframeRoundTripMs`; the core not-prewarmed summary is the
      optimization baseline.
- [x] Distinguish cold worker/WASM startup from steady-state unlock. Cold-start
      cost can be pre-warmed before unlock begins; steady-state duplicate work
      should be removed.
      Completed July 4, 2026: `email_otp_unlock_timing_summary_v1` now carries
      a typed prewarm snapshot with `not_prewarmed` versus
      `prewarm_attempted`, status, age, scope, and wallet match. Email OTP worker
      responses do not expose worker-level WASM init diagnostics, so the trace
      distinction is prewarm-state based; steady-state optimization decisions
      still require runs after `prewarm({ iframe: true })` or
      `prewarm({ workers: true })`.
- [x] Hold the Refactor 88 unlock contract as a hard constraint: unlock must
      not report success before all default lanes are usable, so readiness can
      never be deferred past the success signal. Wins come from parallelizing
      and eliminating work inside the unlock window, or pre-warming before it —
      never from moving lane readiness after success.
      Completed July 4, 2026: local Email OTP unlock constructs
      `email_otp_unlock_activation_plan_v1` after runtime postconditions and
      before success events. The plan now carries `ActiveWalletSession` and
      rejects ECDSA sibling records whose authority or bearer JWT diverges from
      the Ed25519 current session. Iframe unlock awaits the wallet-iframe
      router result before the host emits success, and the source guard pins
      both ordering rules.
- [x] Inventory Ed25519 unlock material reconstruction and compare it with the
      material state already available from sealed session restore.
      Completed July 4, 2026: Email OTP Ed25519 unlock currently performs one
      fresh reconstruction from the OTP worker's recovery-code material via
      `unlockEmailOtpWalletForEd25519Session()` and
      `reconstructEmailOtpEd25519Session()`. Email OTP sealed Ed25519 restore is
      wired through `EmailOtpSealedRestoreOrchestrator` for signing/status
      restoration and writes restored records as facts; it does not commit a
      wallet-unlock current session. This keeps the 82B Phase 10C split intact:
      unlock/reconstruction commits current sessions, durable restore stays
      fact-write only.
- [x] Implement a sealed-material-first Ed25519 unlock path only after the
      Phase 7B trace proves reconstruction dominates steady-state unlock and the
      replacement can still build `email_otp_unlock_activation_plan_v1` before
      success. The boundary must use a typed unlock activation builder instead
      of passing restored facts directly to signing.
      Completed July 4, 2026: Email OTP Ed25519 unlock now selects an exact
      operation-usable Email OTP Ed25519 record for the wallet-bound authority,
      prepares a recovery-code unseal authorization, restores the sealed worker
      material through the existing Router A/B Ed25519 readiness boundary, and
      returns the same typed provisioning result used by reconstruction. The
      path canonicalizes candidate facts before activation and falls back to HSS
      reconstruction only when no exact sealed record is available.
      Updated July 6, 2026: the combined Email OTP ECDSA unlock path now uses
      the same sealed Ed25519 activation helper before falling back to HSS
      reconstruction when `ed25519ReconstructionMode` is `await`. This reduces
      reconstruction frequency for Tempo/Arc unlocks that already have an
      exact restorable Ed25519 session record. Validation:
      `pnpm -C packages/sdk-web exec tsc -p tsconfig.build.json --noEmit` and
      `node tests/scripts/check-registration-capability-subjects.mjs`.
- [x] Inventory ECDSA unlock activation and verify it restores one wallet-key
      role-local material record for EVM-family targets instead of doing
      per-chain duplicate material work.
      Completed July 4, 2026: the Email OTP ECDSA unlock path restores one
      worker handle through `bootstrapEmailOtpEcdsaSessionsFromWorkerHandle()`
      and publishes all configured `publicationChainTargets` from that result.
      The shared role-local material identity remains enforced by the ECDSA
      role-local record boundary from Refactor 82B/90.
- [x] Build a typed `EmailOtpUnlockActivationPlan` before unlock success is
      reported. It must carry wallet-bound authority, active wallet session,
      operation-usable Ed25519/ECDSA current records, and constructed runtime
      state together.
      Completed July 4, 2026: Email OTP Ed25519 provisioning now returns the
      operation-usable current Ed25519 record it committed, and SeamsWeb builds
      `email_otp_unlock_activation_plan_v1` from an `ActiveWalletSession`,
      current Ed25519/ECDSA records, and runtime postcondition inventory before
      unlock success events are emitted. The builder rejects ECDSA sibling
      records whose authority or bearer JWT diverges from the Ed25519 current
      session. A Refactor 83 guard enforces the boundary.
- [x] Route Ed25519 and ECDSA unlocked session records through the 82B Phase 10C
      current-session commit commands. Restore/rehydration writes stay
      fact-write only.
      Completed July 4, 2026: Ed25519 warm capability persistence builds an
      operation-usable current record before `commitCurrentThresholdEd25519Session`;
      ECDSA bootstrap persistence builds an operation-usable current record
      before `commitCurrentThresholdEcdsaSession`; sealed restore hydration
      remains on fact-write APIs. ECDSA sealed-session persistence remains a
      durable seal/read-back write after the current session commit, and it
      does not upsert generic ECDSA facts. A Refactor 83 guard enforces this
      split.
- [x] Parallelize independent post-OTP work only after measurement proves the
      dependency boundary: server seal application, sealed material reads, ECDSA
      restore, and local persistence can overlap only when they do not depend on
      each other's output.
      Completed July 4, 2026: current combined unlock traces do not justify a
      parallelism slice here. Ed25519 material restore is the dominant bucket,
      while ECDSA restore is about 80ms and warm capability persistence is about
      13ms. The next meaningful optimization target is the Ed25519 restore/HSS
      finalization path, not overlapping small persistence writes.
- [x] Delete stale unlock fixtures that encode serial duplicate material restore
      as intended behavior.
      Completed July 4, 2026: source/test sweep found no remaining unlock
      fixture that treats duplicate Ed25519 sealed restore plus reconstruction
      as intended behavior. Current guards assert the commit/fact-write split
      and typed activation-plan boundary instead.

Exit criteria:

- [x] We can point to the top three Email OTP unlock costs from a trace.
      Completed July 4, 2026: the current unlock activation trace shows
      `ed25519MaterialRestoreMs` 6,957ms, `signingSessionSealApplyMs` 562ms,
      and `emailOtpProofVerificationMs` 388ms as the top named buckets after
      the aggregate `workerUnlockAndSessionBootstrapMs` span.
- [x] Email OTP unlock produces a single typed activation plan before success.
      Completed July 4, 2026: local Ed25519 and combined ECDSA unlock paths
      construct `email_otp_unlock_activation_plan_v1` before success events.
      Iframe unlock awaits the iframe router lifecycle result before the host
      reports success.
- [x] Collapse Email OTP unlock local persistence into one logical commit where
      IndexedDB allows it, only after a Phase 7B trace shows persistence is a
      top cost. Current behavior intentionally commits each produced current
      session through the 82B Phase 10C command boundary and keeps durable
      sealed-session writes separate from generic session fact writes.
      Completed July 4, 2026: the green combined unlock trace reports
      `warmCapabilityPersistenceMs` at 13ms, so persistence is not a top cost.
      The current 82B Phase 10C current-session commit boundary is retained.
- [x] Unlock does not run duplicate Ed25519 reconstruction when sealed restored
      material is sufficient.
      Completed July 4, 2026: `EmailOtpEd25519Warmup` attempts
      sealed-material activation before `reconstructSession()`, and the Refactor
      83 guard pins that ordering. The July 5 unlock benchmark matrix provides
      the post-change timing rerun.
- [x] Unlock does not perform per-chain ECDSA material restore for shared
      EVM-family material.
      Completed July 4, 2026: Email OTP ECDSA unlock uses one
      `bootstrapEmailOtpEcdsaSessionsFromWorkerHandle()` restore and publishes
      all configured EVM-family targets from the shared role-local result.
- [x] OTP registration, unlock, NEAR/Tempo/Arc signing, step-up signing, and
      Ed25519/ECDSA key export still pass manual validation.
      Completed July 4, 2026: manual testing reported OTP registration, wallet
      unlock, NEAR/Tempo/Arc transaction signing, repeated step-up signing, and
      both Ed25519/ECDSA key exports passing after the 82B current-session
      commit fixes.

## Phase 8: Cleanup And Line Count Closure

- [x] Use `rg` and a targeted manual review to find duplicate registration
      helpers after Phases 2-7B land.
      Completed July 4, 2026: the Phase 8 sweep found no remaining
      registration production references to `assertImmediateRegistrationSigningLanes`,
      `readPersistedAvailableSigningLanes`, the deleted
      `threshold_ed25519_warm_material_reconstruction_started` event, or
      registration-time `reconstructThresholdEd25519SigningMaterialFromWarmSession()`.
      The remaining precompute and digest helpers are active request/response
      boundary code.
- [x] Delete old precompute, reconstruction, parser, and lane assertion helpers
      that no longer have callers.
      Completed July 4, 2026: no obsolete registration helper with no caller
      remained in the sweep. The retained helpers are the public precompute API,
      the started-precompute scope boundary, the digest response boundary, and
      stored prepared-package parsers.
- [x] Delete stale tests instead of preserving deprecated behavior.
      Completed July 4, 2026: stale registration assertions for post-write lane
      inventory and serialized Email OTP tail work were already removed or
      rewritten to assert current behavior. The unlock-specific fixture cleanup
      remains tracked in Phase 7B.
- [x] Record before/after non-doc line counts for this refactor.
      Completed July 4, 2026: current 83-owned non-doc diff against `HEAD`
      records 2,820 additions and 884 deletions across the tracked server,
      SDK, and focused unit-test files touched by this plan, plus the new
      432-line `registrationCapabilitySubjects.guard.unit.test.ts` source
      guard. Net observed non-doc growth is +2,368 lines in the shared dirty
      worktree. Generated SDK `dist` output is excluded.
- [x] Update this plan with retained benchmark numbers and deleted-code totals.
      Completed July 4, 2026: Phase 1 and Phase 7B carry the current
      registration/unlock baseline artifacts and top buckets, and Phase 8
      records the current 83-owned non-doc diff and retained growth rationale.

Exit criteria:

- [x] Net non-doc line growth is zero or explicitly justified by stricter domain
      types replacing ad hoc runtime checks.
      Completed July 4, 2026: net growth is intentionally retained for
      normalized prepared-package state, registration persistence subjects,
      active runtime-state construction, Email OTP unlock timing/activation
      types, and source guards that keep stale runtime scans and fact/current
      session collapse from returning.
- [x] All temporary guards added for this refactor are listed in
      `docs/refactor-89-clean-source-guards.md`.
      Completed July 4, 2026: Refactor 89 now splits
      `tests/unit/registrationCapabilitySubjects.guard.unit.test.ts` into
      role-local ECDSA handle, wallet-scoped unlock subject, visible iframe
      passkey registration, registration active-state/persistence subjects,
      Email OTP current-session commit, and Email OTP unlock activation-plan
      ledger rows with cleanup triggers.

## Phase 9: Server HSS Finalize Latency

Root cause note, July 5, 2026: the two dominant Phase 1 baseline buckets are
the same server-side cost paid twice. `registrationHssFinalizeMs` (~5.3s
inside `walletRegisterFinalizeMs` per the route diagnostics: 5,319ms of the
5,333ms route total, with ceremony load, keygen, session mint, and D1
persistence under 10ms combined) and the warm-session ceremony finalize fetch
(~5.2s inside `thresholdEd25519SessionPersistenceMs`) both run
`threshold_ed25519_hss_finalize_report` on the D1 router cold path:

- The D1/Durable Object ceremony store persists only serialized state and
  cannot carry in-memory WASM handles (`CloudflareDurableObjectStore` rejects
  `stagedEvaluatorArtifactHandle`; the TypeScript bridge passes an empty
  handle in `ed25519HssWasm.ts`). The prepared-session and staged-artifact
  caches behind the Refactor 63 finalize fast path (~45ms route p50 on the
  Node router; 0.5ms `finalize_report` in the native benchmark) never hit, so
  finalize rematerializes sessions from serialized state and replays the full
  hidden evaluation (add stage, message schedule rounds, round core rounds,
  output projection) in
  `finalize_server_eval_state_from_add_stage_request`.
- The persisted server eval state is not `Finalized` at respond time, so the
  existing `status == Finalized` short-circuit in that function never fires.
- Before Phase 9, the server HSS WASM was built for size, not speed:
  `wasm/near_signer` pinned `opt-level = "z"` and the server bundle built with `--release --no-opt`
  (`packages/sdk-web/scripts/build/build-wasm.sh` `build_near_signer`,
  `pkg-server` output), while the client `hss_client_signer` builds at
  `opt-level = 3`. The same class of hidden-eval work measures ~145ms native
  (`benchmark_prime_order_registration` full-flow p50 287.7ms, re-run
  July 5, 2026, consistent with the recorded
  `crates/ed25519-hss/docs/benchmarks/refactor-64/prime-order-registration-respond-one-pass-native-release.json`
  at 270ms), ~450ms in the opt-level-3 client WASM
  (`ed25519EvaluationArtifactMs`), and ~5.3s in the size-optimized server
  WASM.

Post speed-build benchmark, July 5, 2026: passkey registration with the
Tempo+Arc EVM-family profile passed under
`SEAMS_INTENDED_PERSIST_TRACE=1 SEAMS_INTENDED_PASSKEY_ECDSA_TARGET_PROFILE=tempo_arc pnpm -C tests exec playwright test -c playwright.intended.benchmark.ci.config.ts e2e/intended-behaviours/passkey.registration.benchmark.test.ts --reporter=line`.
Persisted trace:
`test-results/intended-lifecycle-traces/1783184493610-passkey.registration-polar-orchid-2ugkxc-intended-lifecycle-trace.json`.
The route diagnostics now report `walletRegisterFinalizeMs` 3,354ms,
`registrationHssFinalizeMs` 3,334ms,
`registrationHssFinalizeSerializedSessionMaterializeMs` 155ms,
`registrationHssFinalizeReportMs` 2,887ms, and `registerFinalizeTotalMs`
3,343ms. The total passkey registration flow was 6,025ms. Compared with the
July 4 baseline (`registerFinalizeTotalMs` ~5,333ms,
`registrationHssFinalizeReportMs` 4,707ms), the server speed build removes
about 2.0s from the finalize route, but the HSS replay remains the top
registration bucket.

Refactor 84b is ruled out as the cause: it trimmed finalize transport bytes
only, and the cost is server compute, not transport.

Tasks:

- [x] Add the finalize sub-timings the bridge already returns
      (`decodeArtifactMs`, `serializedSessionMaterializeMs`,
      `finalizeReportMs`, `encodeReportMs`) to the D1 router finalize log
      lines so the materialize/replay split is visible in intended traces.
- [x] Build the server HSS WASM for speed: a dedicated server build at
      `opt-level = 3` with `wasm-opt` enabled, keeping the browser bundles
      size-optimized. Record the Worker bundle-size cost against Cloudflare
      deploy limits next to the before/after `registrationHssFinalizeMs`.
      Implemented by overriding `CARGO_PROFILE_RELEASE_OPT_LEVEL=3` only for
      `wasm/near_signer/pkg-server` and removing `--no-opt`; local
      `pnpm -C packages/sdk-web run build:wasm` passes. The generated server
      WASM is 2.0M versus the previously observed 1.6M size/no-opt artifact.
- [x] Reject respond-time finalized-state persistence for the current
      role-separated client-owned flow. The server can advance to
      `Finalized` only with the add-stage request, and that request depends on
      client-local evaluator OT state. `/wallets/register/hss/respond`
      deliberately accepts only `clientRequestMessageB64u` and rejects
      `evaluatorOtStateB64u`, `yClientB64u`, `tauClientB64u`, and output-mask
      fields, so moving this work to respond would cross the HSS privacy
      boundary. A `waitUntil` after respond has the same missing input.
      Handles stay prohibited in durable ceremony state.
- [x] Evaluate routing respond and finalize for one ceremony to the same
      Durable Object instance to restore in-memory session-cache locality.
      This requires a dedicated HSS execution-local DO path; the current
      registration ceremony DO is a durable key-value facade and must not grow
      stored WASM handles.
      Evaluated July 5, 2026: this is the remaining architectural optimization,
      but it is outside Refactor 83's registration/unlock cleanup scope. The
      current D1 registration ceremony DO remains a durable record owner, and
      any execution-local HSS DO must be designed as a separate HSS latency plan
      with explicit in-memory handle ownership and failure semantics.
- [x] Investigate eliminating the second server finalize on the Email OTP
      registration path. Current code already mirrors the Phase 3 passkey
      approach: `persistEmailOtpRegisteredThresholdEd25519WorkerMaterial`
      stores worker material through
      `storeThresholdEd25519WorkerMaterialFromFinalizedHssReport` with
      recovery-code seal authorization, and the guard test rejects
      `runThresholdEd25519HssCeremonyWithMaterialHandle` in both passkey and
      Email OTP registration stores.
- [x] Re-run the Phase 1 passkey intended registration benchmark and record the
      new `walletRegisterFinalizeMs` and server HSS finalize baselines next to
      the July 4, 2026 numbers.
      Completed July 5, 2026: `walletRegisterFinalizeMs` 3,354ms,
      `registrationHssFinalizeMs` 3,334ms, and
      `registrationHssFinalizeReportMs` 2,887ms in
      `1783184493610-passkey.registration-polar-orchid-2ugkxc-intended-lifecycle-trace.json`.
- [x] Re-run the Email OTP intended registration benchmark after fixing the
      Ed25519-only material boundary and intended startup blockers.
      Completed July 5, 2026: refreshed the intended Google token and
      `SEAMS_INTENDED_PERSIST_TRACE=1
      SEAMS_INTENDED_EMAIL_OTP_ECDSA_TARGET_PROFILE=none pnpm -C tests exec
      playwright test -c playwright.intended.benchmark.ci.config.ts
      e2e/intended-behaviours/email-otp.registration.benchmark.test.ts
      --reporter=line` passed 1/1. Trace:
      `test-results/intended-lifecycle-traces/1783189388294-email_otp.registration-harbor-tempo-gtun6n-intended-lifecycle-trace.json`.
      The earlier Vite module-graph failures were not reproduced after the SDK
      build artifacts were regenerated. The separate concurrent-build race was
      fixed by holding a shared WASM package-output lock across full SDK builds,
      standalone WASM builds, and standalone SDK builds.

Exit criteria:

- [x] The `registrationHssFinalizeMs` cost is explained by recorded
      sub-timings, and it is no longer one of the top two registration
      buckets — or the residual cost is explicitly accepted and documented.
      Current July 5 status: sub-timings explain the cost, but the residual
      server HSS finalize remains the top registration bucket: 3,334ms in the
      passkey combined benchmark and 3,232ms in the Email OTP Ed25519-only
      benchmark.
      Accepted July 5, 2026: the residual replay is explicitly deferred to a
      separate HSS execution-local DO/locality design. Refactor 83 exits with
      server-HSS sub-timings visible, speed-oriented server WASM enabled, and no
      second registration warm-session server replay on the critical path.
- [x] Registration pays the full hidden-evaluation replay at most once on the
      user-visible critical path.
      Completed July 5, 2026: the current Email OTP and passkey registration
      traces show one route-level `registrationHssFinalizeMs` replay, while
      `thresholdEd25519SessionPersistenceMs` is now local worker-material
      persistence and signing-session hydration in the 441-450ms range rather
      than a second ~5s server HSS finalize.

## Initial File Inventory

Client registration orchestration:

- `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
- `packages/sdk-web/src/SeamsWeb/operations/registration/registrationSignerSet.ts`
- `packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`
- `packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/prewarmedRegistrationMaterial.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`

Client persistence and runtime material:

- `packages/sdk-web/src/core/signingEngine/flows/registration/accountLifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/session.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `packages/sdk-web/src/core/indexedDB/seamsWalletDB/repositories.ts`

Client Email OTP unlock activation:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/authMethods/emailOtp/googleEmailOtpWalletAuthFlow.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`

Server D1/DO registration:

- `packages/sdk-server-ts/src/router/walletRegistrationRoutes.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/walletRegistration.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1WalletRegistrationService.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyDo.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1EvmFamilyEcdsaRegistrationBranch.ts`
- `packages/sdk-server-ts/src/router/cloudflare/d1RegistrationIntentService.ts`

Primary test inventory:

- Refactor 88 lifecycle contract gate: `pnpm test:intended`.
- `tests/unit/registrationIntentAllocation.unit.test.ts`
- `tests/unit/registrationSignerSetNormalization.unit.test.ts`
- `tests/unit/registrationWalletPersistence.unit.test.ts`
- `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts`
- `tests/unit/walletRegistrationEcdsaRouterAbBootstrap.unit.test.ts`
- `tests/unit/cloudflareD1RouterApiAuthService.unit.test.ts`
- `tests/unit/googleEmailOtpWalletAuthFlow.unit.test.ts`
- `tests/unit/sealedSessionStore.unit.test.ts`
- `tests/e2e/intended-behaviours/email-otp.unlock.contract.test.ts`
- `tests/wallet-iframe/router.registrationActivation.test.ts`

## Open Questions

- [x] Can the Ed25519 registration finalize output directly produce the same
      worker material identity currently produced by warm-session
      reconstruction? Resolved during Phase 3: passkey registration persists
      worker material directly from registration HSS material plus the
      registration credential; no second ceremony is needed.
- [x] Does ECDSA registration need per-chain local session material at
      registration time? Resolved by Refactor 90 Phase 0F: role-local material
      handles are chain-agnostic, so one wallet-key material record hydrates
      all requested EVM-family targets. Chain enforcement lives in exact lanes
      and session records and is checked before worker material opens.
- [x] Which registration UI surfaces still call `registerWallet()` without a
      started precompute handle? Resolved July 4, 2026: Google Email OTP uses
      `registerWalletWithStartedPrecompute()` when local precompute is
      available; the remaining direct `registerWallet()` path is the explicit
      non-prewarmed public/API branch plus wallet-iframe registration where the
      local precompute handle cannot be shared across the iframe boundary.
- [x] Which post-registration checks verify external state and must stay in the
      user-visible path? Resolved for the current code slice: profile/account
      mapping and lane inventory scans verified local writes and were removed
      from production; sponsored NEAR account readiness remains external state.
- [x] What are the top three Email OTP unlock costs after 82B Phase 10C, and is
      the dominant cost Ed25519 material restore, ECDSA material restore, server
      seal application, local persistence, or wallet-iframe orchestration?
      Answered July 4, 2026: for the core combined unlock path, the dominant
      cost is Ed25519 material restore. The top measured core buckets are
      `ed25519MaterialRestoreMs`, `signingSessionSealApplyMs`, and
      `emailOtpProofVerificationMs`. The host-side iframe round trip mirrors
      the core elapsed time and is observational, not a separate product
      bottleneck.
