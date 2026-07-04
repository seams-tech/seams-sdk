# Refactor 83: Registration Critical Path Cleanup

Date created: July 2, 2026
Updated: July 3, 2026 — aligned with the Refactor 82B authority/material type
decisions and the Refactor 90 reorganization; sequencing gates recorded below.

Status: planned, partially gated.

Sequencing gates:

- Phases 1 and 6 can start now.
- Phases 2-5 and 7 are gated on Refactor 82B Phases 6-7 exiting (Ed25519
  material-state unions and committed-lane loose-shape deletion complete),
  because Phases 3-5 edit `records.ts`, `sealedSessionStore.ts`, and
  `thresholdWarmSessionBootstrap.ts`, which 82B owns until that exit.
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

This plan is about simplifying and shortening the registration path. It is not a
new HSS protocol optimization plan and it is not a compatibility plan.

## Non-Goals

- Do not add legacy `mode: "ed25519_and_ecdsa"` handling.
- Do not add fallback registration routes.
- Do not hide missing material behind retry/fallback rehydration.
- Do not change HSS cryptographic transcript rules unless a separate HSS plan
  proves the change.
- Do not keep runtime postcondition scans as production control flow.

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
  Phases 6-7 exiting.
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

- [ ] Registration precompute can be started twice: once by UI prewarm and again
      inside `registerWalletInternal()` when the precompute handle is absent,
      stale, or scoped differently.
- [ ] Router A/B keyset prefetch currently runs for every signer-set registration
      precompute. It should be branch-gated to the signer branches that need it.
- [ ] The client recomputes and rechecks registration intent digest after the
      server already returned the intent digest. The local digest check is useful
      at the boundary, but it should not become repeated core flow work.
- [ ] D1 registration start reparses signer branches, runtime policy scope, and
      ECDSA chain targets after prepare already parsed equivalent state. The DO
      should store a normalized prepared registration package so later routes do
      not rederive the same branch shape repeatedly.
- [ ] Passkey Ed25519 registration currently completes the registration HSS
      ceremony, persists the returned warm session, then immediately runs another
      Ed25519 HSS warm-session reconstruction ceremony to produce local worker
      material. This is the largest suspicious duplicate.
- [ ] Local wallet persistence is split across Ed25519 account data, Ed25519
      session data, optional ECDSA session data, optional ECDSA signer records,
      wallet activation, and immediate lane assertion. These should collapse
      into one typed persistence plan and one commit where IndexedDB allows it.
- [ ] `immediateSigningLaneAssertionMs` does runtime inventory scans after
      registration. The production path should construct active runtime state
      from the persisted registration result. Tests can assert the same invariant
      without a user-visible runtime scan.
- [ ] Email OTP registration may prepare/reconstruct material and backup recovery
      codes serially where the work is independent.

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

## Phase 1: Measurement And Trace Cleanup

- [ ] Capture one clean local registration trace for:
      passkey `near_ed25519` only, passkey `near_ed25519 + evm_family_ecdsa`,
      Google Email OTP `near_ed25519` only, and Google Email OTP combined.
- [ ] Add or tighten timing buckets for the current suspicious tail:
      `thresholdEd25519SessionPersistenceMs`,
      `threshold_ed25519_warm_material_reconstruction_started`,
      `ecdsaRegistrationPersistenceMs`,
      `walletStateActivationMs`, and `immediateSigningLaneAssertionMs`.
- [ ] Add a registration critical-path summary that distinguishes elapsed time
      from background work. Diagnostics must stay observational.
- [ ] Record baseline p50 and one cold-run worst case in this document before
      removing code.
- [ ] Capture baselines after the Refactor 84b finalize payload trim lands, and
      note the 84b state next to the recorded numbers so the two changes are
      not conflated.
- [ ] Capture baselines before Refactor 86 Phase 3 flips local wallet-asset
      serving to the static wallet origin, or record the serving topology
      beside the numbers; a topology change mid-measurement contaminates the
      comparison.

Exit criteria:

- [ ] We can point to the top three registration costs from a trace.
- [ ] We know whether the second Ed25519 HSS ceremony is on the critical path.

## Phase 2: Single Prepared Registration Package

Refactor 82B already landed the seed of this package: registration prepare
verifies authority, stores it with the preparation, and prepared start
consumes only `registrationPreparationId`. This phase extends that stored
preparation rather than building a parallel one.

- [ ] Extend the stored preparation into the normalized prepared registration
      package at the D1/DO boundary: already-parsed intent, the verified
      registration authority (never re-derived by later routes), prepared
      signer branches with stable branch identities, runtime policy scope,
      signing-root scope, and normalized ECDSA chain targets.
- [ ] Update `/wallets/register/prepare`, `/start`, `/hss/respond`, and
      `/finalize` to consume the prepared package instead of reparsing the same
      raw shapes in each route.
- [ ] Keep raw request parsing only in route parsers and D1/DO persistence
      boundary parsers.
- [ ] Delete duplicate private signer-selection and runtime-scope parser calls
      from the registration start/respond/finalize core path.
- [ ] Add type fixtures rejecting raw registration intent branches in post-prepare
      core functions.

Exit criteria:

- [ ] After prepare, core registration route code accepts only normalized
      prepared package types.
- [ ] Start/respond/finalize no longer rederive ECDSA chain targets or Ed25519
      prepare scope from raw intent objects.

## Phase 3: Eliminate Duplicate Ed25519 Worker-Material Reconstruction

- [ ] Inventory exactly what material the Ed25519 registration HSS ceremony
      already produces in `completeRegisteredThresholdEd25519Registration()`.
- [ ] Compare that output with what
      `reconstructThresholdEd25519SigningMaterialFromWarmSession()` produces for
      a new registration.
- [ ] If the registration ceremony already has enough information to construct
      `LoadedEd25519WorkerMaterial`, route that material directly into
      persistence.
- [ ] If the registration ceremony lacks one required field, change the finalize
      response or local completion type so the missing field is produced once at
      finalize time. Do not add a second ceremony.
- [ ] Coordinate any finalize request/response shape change with Refactor 84b,
      which owns the staged-artifact transport trim on the same route. One
      finalize contract change per landing — two plans must not edit the
      payload independently.
- [ ] Delete the immediate passkey registration call to
      `reconstructThresholdEd25519SigningMaterialFromWarmSession()`.
- [ ] Keep warm-session reconstruction for login, recovery, and sync flows only
      where registration material is unavailable.
- [ ] Add a guard that fails if passkey registration calls
      `runThresholdEd25519HssCeremonyWithMaterialHandle()` after finalize.

Exit criteria:

- [ ] Passkey registration performs one Ed25519 HSS ceremony total.
- [ ] The persisted Ed25519 session is immediately signable after registration.
- [ ] Login/recovery reconstruction remains covered by its own tests.

## Phase 4: Collapse Local Persistence Into A Registration Commit

- [ ] Build a typed `RegistrationPersistencePlan` before writing IndexedDB.
- [ ] Include wallet profile rows, auth method rows, signer activation rows,
      key-material rows, Ed25519 runtime session rows, ECDSA runtime session
      rows, and selected-wallet state in the plan.
- [ ] Replace ad hoc sequential persistence calls in
      `packages/sdk-web/src/SeamsWeb/operations/registration/registration.ts`
      with one commit function that accepts only `RegistrationPersistencePlan`.
- [ ] Keep persistence compatibility handling inside IndexedDB boundary parsers.
- [ ] Remove post-write reads that only verify data the commit function just
      wrote. Replace them with targeted tests on the commit function.
- [ ] Keep post-write checks only where they verify external state, such as
      on-chain NEAR account readiness.

Exit criteria:

- [ ] Successful registration performs one logical local persistence commit.
- [ ] The registration path no longer reads profile/account mappings solely to
      prove its own IndexedDB write.

## Phase 5: Replace Runtime Lane Assertion With Constructed Active State

- [ ] Replace `assertImmediateRegistrationSigningLanes()` in the production
      success path with active wallet runtime state built from the finalized
      registration result and persistence plan.
- [ ] Move lane inventory assertions into unit/integration tests.
- [ ] Ensure exact-lane state after registration uses the same canonical types as
      Refactor 79.
- [ ] Delete registration-only lane availability predicates that duplicate exact
      lane selectors.

Exit criteria:

- [ ] Production registration no longer scans runtime lane inventory as a
      postcondition.
- [ ] Newly registered wallets can sign NEAR and EVM using the constructed
      active state.

## Phase 6: Precompute Ownership And Scope Cleanup

- [ ] Make the UI-started precompute handle the single precompute owner for
      registration surfaces that can start precompute before click completion.
- [ ] Make `registerWalletInternal()` require either a valid precompute handle or
      an explicit `start_inside_register_wallet` branch for non-prewarmed callers.
- [ ] Add exact scope mismatch diagnostics, then fail closed instead of silently
      starting another expensive precompute for the same click path.
- [ ] Treat the Refactor 84a registration draft as the precompute scope owner
      for visible flows: precompute scope includes the draft wallet ID, and a
      wallet reroll replaces the draft and invalidates the precompute handle as
      a named scope change — never a silent re-precompute.
- [ ] Branch-gate Router A/B keyset prefetch and ECDSA bootstrap preparation.
- [ ] Delete duplicate precompute lifecycle helpers that exist only to support
      stale UI flows.

Exit criteria:

- [ ] One user registration attempt maps to one precompute handle.
- [ ] A scope mismatch is visible as a registration error, not as duplicate work.

## Phase 7: Email OTP Tail Parallelism

- [ ] Identify which Email OTP work depends on verified OTP authority and which
      work depends only on the registration intent.
- [ ] Run recovery-code backup, enrollment material preparation, and ECDSA
      bootstrap work in parallel where their inputs are already available.
- [ ] Keep backup acknowledgement single-use and tied to finalize.
- [ ] Delete stale Email OTP registration fixtures that encode old serialized
      tail work.

Exit criteria:

- [ ] Email OTP registration keeps the same authority and backup semantics with a
      shorter post-OTP tail.

## Phase 8: Cleanup And Line Count Closure

- [ ] Use `rg` and a targeted manual review to find duplicate registration
      helpers after Phases 2-7 land.
- [ ] Delete old precompute, reconstruction, parser, and lane assertion helpers
      that no longer have callers.
- [ ] Delete stale tests instead of preserving deprecated behavior.
- [ ] Record before/after non-doc line counts for this refactor.
- [ ] Update this plan with retained benchmark numbers and deleted-code totals.

Exit criteria:

- [ ] Net non-doc line growth is zero or explicitly justified by stricter domain
      types replacing ad hoc runtime checks.
- [ ] All temporary guards added for this refactor are listed in
      `docs/refactor-89-clean-source-guards.md`.

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
- `tests/wallet-iframe/router.registrationActivation.test.ts`

## Open Questions

- [ ] Can the Ed25519 registration finalize output directly produce the same
      worker material identity currently produced by warm-session
      reconstruction? Resolve during the Phase 3 inventory.
- [x] Does ECDSA registration need per-chain local session material at
      registration time? Resolved by Refactor 90 Phase 0F: role-local material
      handles are chain-agnostic, so one wallet-key material record hydrates
      all requested EVM-family targets. Chain enforcement lives in exact lanes
      and session records and is checked before worker material opens.
- [ ] Which registration UI surfaces still call `registerWallet()` without a
      started precompute handle? Resolve before Phase 6 lands.
- [ ] Which post-registration checks verify external state and must stay in the
      user-visible path? Resolve during Phase 4.
