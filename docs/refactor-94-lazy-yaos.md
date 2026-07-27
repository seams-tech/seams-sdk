# Refactor 94 — Non-Blocking Ed25519 Yao Provisioning

## Status

Phase 1 (demo OTP export UX) and Phase 9 (demo chain order) are implemented.
Phases 2–8 and 10 are unstarted.

The design changed on 2026-07-27, after measurement. The original plan was
*on-demand lazy provisioning*: registration mints ECDSA only, and the Ed25519
signer is provisioned later when the user first wants NEAR. The adopted design
is *non-blocking provisioning*: the Ed25519 Yao ceremony still runs during
registration, but registration success no longer waits for it. On-demand
provisioning is preserved as a follow-on in Phase 11.

Latency is owned by
[refactor-94A-performance-regression.md](./refactor-94A-performance-regression.md),
which is `in progress`. This document owns only the product lifecycle change.

## Premise correction

The original goal cited a "2–3 second Yao branch" on the registration critical
path. That is not what the code does, and no longer what it costs.

The baseline in
[refactor-94A-performance-regression.md](./refactor-94A-performance-regression.md)
records ECDSA at 4.734 s and Ed25519 Yao at 3.544 s running *concurrently*,
with ECDSA determining when finalization begins. Removing the shorter
concurrent branch does not shorten the critical path.

That baseline is also pre-optimization. Phases 4–6 of the performance refactor
have since landed (`25cf4c3a0`, `d0de9311a`, `1e8c16f3a`). A measured **local**
release-profile passkey registration on 2026-07-27 recorded:

| Measure                              |   Observed |
| ------------------------------------ | ---------: |
| Total registration                   |   1,695 ms |
| ECDSA registration ceremony          |     234 ms |
| authProof (Touch ID, user-controlled) |     334 ms |
| Unattributed                         |   1,026 ms |

The Yao execute call returned 3 ms *before* finalize started. **Locally**,
Ed25519 is not on the critical path, and registration is already inside the
2–3 s target.

This has not been confirmed in production, and there is evidence it does not
hold there: a production Yao interval of 2,348 ms is under active
investigation. Local workerd collapses the Gateway/Router/Deriver network
boundaries that dominate production, so the local result is a lower bound on
the Yao branch, not a prediction of it.

Server-side instrumentation for this exists but is not yet deployed. The
registration execute response now emits a `Server-Timing` header on
`/router-ab/ed25519/yao/registration/execute` with `yao_credential_digest`,
`yao_request_digest`, `yao_d1_claim`, `yao_router_execution`,
`yao_result_reconstruction`, `yao_d1_terminal_commit`,
`yao_router_prepare_pair`, `yao_router_verify_readiness`,
`yao_router_role_execution`, and `yao_router_signing_worker_delivery`. One
production registration after deployment will locate the 2.35 s in D1, A/B
preparation, role execution, or SigningWorker delivery.

Two silent windows account for the unattributed 1,026 ms: 613 ms between
`finalize_response_received` and the SeamsWalletDB batch, and 291 ms after
`transaction_committed`. Both contain zero console output and zero network
requests. Attributing them is Phase 2.

## Goal

Registration success must not depend on an MPC ceremony completing.

Registration will:

1. create the wallet identity;
2. provision the shared ECDSA key used by Tempo and Arc;
3. persist an ECDSA-ready wallet and return success;
4. let the already-in-flight Ed25519 Yao ceremony finish afterwards and commit
   the NEAR signer when it does.

Tempo and Arc are usable at step 3. NEAR shows a provisioning state until step
4 completes.

## What this design does and does not buy

Buys:

- **Robustness.** A slow, failed, or burned Yao ceremony no longer fails
  registration or blocks Tempo and Arc.
- **A prerequisite.** The persistence split and the "Ed25519 absent" schema work
  are required by Phase 11 as well, so none of it is throwaway.

Does not buy:

- **Cost.** The Ed25519 key and the relayer-funded NEAR account are still
  created for every registration, including users who never use NEAR. Only
  Phase 11 removes that.

Undetermined:

- **Latency.** Locally, approximately zero — Yao already finishes before
  finalize. In production the Yao interval is under investigation at 2,348 ms;
  if that is real and on the critical path, detaching the join converts
  directly into saved wall time. Phase 2 settles this on both sides before
  Phases 3–8 are justified on latency grounds.

No phase in this document may be justified by a latency claim that has not been
measured on the environment it claims to improve.

## Architectural decisions

### 1. Registration success means ECDSA-ready

Registration success no longer implies an active Ed25519 signer or a NEAR
account. `docs/intended-behaviours.md:55-63` and `:86-93` currently promise
"NEAR projection in one finalize path" and an immediate NEAR warm signing lane;
both statements change, for passkey and Email OTP alike.

Wallet readiness becomes a discriminated union. Raw optional signer fields must
not represent lifecycle state:

```ts
type WalletSignerReadiness =
  | { kind: 'ecdsa_ready'; walletId: WalletId; ecdsaInventory: ActiveEcdsaInventory }
  | { kind: 'near_provisioning'; walletId: WalletId; ecdsaInventory: ActiveEcdsaInventory }
  | {
      kind: 'near_ready';
      walletId: WalletId;
      ecdsaInventory: ActiveEcdsaInventory;
      nearSigner: ActiveNearEd25519Signer;
    };
```

`ReadyWalletSessionReadiness` (`useCases/lifecycle.ts:165-170`) currently
requires a non-empty Ed25519 lane array, and `registerWallet.ts:107-112` types
ECDSA provisioning as consuming a `ReadyEd25519Lane`. Both must stop making
Ed25519 a precondition of ECDSA.

### 2. No new ceremony, no new grant, no extra prompt

This is the decision that separates this design from the original plan.

The Yao ceremony already starts during registration (`registration.ts:3663`)
and already runs concurrently with ECDSA. Registration waits for it at exactly
one join point, `claimRegistrationYao` (`registration.ts:3720`). This refactor
detaches that join. The ceremony continues with the authorization material
already in scope for the registration that started it.

Therefore this design does **not** introduce:

- an `initial_ed25519_provisioning` ceremony purpose;
- a short-lived initial-provisioning grant returned from registration;
- a second authentication prompt;
- a per-wallet D1 compare-and-set claim.

The existing registration admission, lifecycle ID, and one-use Yao execution
remain exactly as they are. The change is which promise registration success
awaits, not how the ceremony is authorized.

### 3. Client authorization material is not retained beyond its ceremony

Passkey PRF material is held as `prfFirstB64u`, an immutable JS string that
cannot be zeroized (`registrationAuthority.ts:87`). It is already held for the
duration of the registration flow.

Detaching the join extends that lifetime only until the in-flight ceremony
settles. It must not be persisted, re-derived for a later ceremony, or handed
to any new grant. If the page closes first, the wallet remains valid and
ECDSA-ready, and recovery is Phase 11's on-demand path — not a retained secret.

Email OTP material is already correctly shaped: a worker-owned secret behind an
opaque handle with a 5-minute TTL (`email-otp.worker.ts:263`).

### 4. Failure is non-fatal and visible

A failed, burned, or abandoned Ed25519 ceremony leaves a healthy `ecdsa_ready`
wallet. It must never roll back registration, invalidate the ECDSA inventory,
or block Tempo and Arc. The NEAR surface shows a retryable failure state.

### 5. Convergence is same-tab only

Same-tab callers join the owned in-flight promise, using the existing
single-flight pattern (`provisionEcdsaSession.ts:112` is the closest
precedent). Cross-tab convergence is explicitly out of scope: the SDK has no
`BroadcastChannel`, no `navigator.locks`, and no leader election anywhere, and
adding one is a separate project. A second tab observes durable state only.

### 6. Refactor 93 remains authoritative for Yao

Every Yao execution continues to use one admitted Router command, pair-bound
request and transcript identity, role-local A/B Durable Object lifecycle
authority, one-use fail-closed execution, exact completed-output redelivery,
and SigningWorker receipt validation. After activation, normal NEAR signing
makes zero Yao activation calls.

## Phase 1 — Finish demo OTP export UX

- [x] Preserve the typed `EmailOtpChallengeDelivery` through key-export
      challenge creation and resend.
- [x] Emit `key_export.auth.email_otp.input.required` through the existing
      key-export progress channel.
- [x] Include `demoOtpCode` only for `demo_code_response` and
      `provider_and_demo_code`.
- [x] Keep provider-only delivery structurally unable to expose an OTP.
- [x] Forward key-export events through `AccountMenuButton`.
- [x] Reuse `showCopiedDemoEmailOtpToast` in seams-site.
- [x] Show the formatted code in one replacing toast.
- [x] Copy the raw six-digit code to the clipboard.
- [x] Leave the code visible when clipboard access is unavailable.
- [x] Dismiss the OTP toast when verification begins, export completes, export
      fails, or the user cancels.
- [x] Verify OTP values are absent from logs, analytics, URLs, and persistence.

This behavior is restricted to the configured demo-code delivery branches.
Export has no dedicated `verify.started` phase; dismissal uses
`STEP_03_MATERIAL_PREPARE_STARTED`, which fires at the same point.

## Phase 2 — Attribute the unattributed time

This phase runs first because it may reduce registration more than every other
phase in this document combined, and because it establishes whether detaching
Ed25519 reclaims anything.

Two independent halves:

**Server side (implemented, not deployed).** The `Server-Timing` breakdown on
`/router-ab/ed25519/yao/registration/execute` listed under Premise correction.

- [ ] Deploy the Yao `Server-Timing` instrumentation.
- [ ] Record one production registration and locate the 2,348 ms Yao interval.
- [ ] Confirm whether the production Yao branch is on the critical path.

**Client side (the local 1,026 ms).** Root-caused 2026-07-27 by code reading;
spans still needed to confirm the split.

The 613 ms window is `finalizeRegistrationEcdsaSessions`
(`registration.ts:3313` → `ecdsaRegistrationSessions.ts:343`), which loops
**once per ECDSA chain target** and, inside warm-session hydration:

1. lazily constructs a nested Shamir 3-pass worker and instantiates a 422 KB
   WASM module (`shamir3pass/runtime.ts:145-149`, `shamir3pass.worker.ts:127-138`).
   This is the only worker in the registration path that is **not** prewarmed —
   `prewarmWorkers()` covers `SIGNER_WORKER_KINDS` only, and `prewarmUiConfirmUi`
   warms the touch-confirm worker but not its nested child. Estimated 200–400 ms;
2. issues a relayer `apply-server-seal` fetch **from inside that worker**
   (`passkey-confirm.worker.ts:730`), once per target. Worker-initiated
   requests do not appear in main-thread resource timing, which is why the
   window looked network-free;
3. runs Shamir keygen plus two modexps, once per target.

`assertMixedRegistrationSharedSigningBudget` (`registration.ts:2370`) is pure
synchronous JS and is **not** a contributor.

The 291 ms window is `activateAuthenticatedWalletState`
(`registration.ts:3427`, including a NEAR RPC prefetch at
`accountLifecycle.ts:657`), then `persistPasskeyEd25519YaoSessionForRefresh`
(`registration.ts:3441`) — a **second full seal cycle** — plus
`persistPasskeyEd25519YaoLocalMaterialV1` (WASM seal + IndexedDB,
`registration.ts:3023`). The Ed25519 activation itself
(`activateVerifiedNearEd25519YaoSigningCapability`) is an in-memory registry
write and is sub-millisecond.

Consequence for this refactor: detaching Ed25519 removes the second seal cycle
and the WASM material seal from the critical path, but not the activation.

- [ ] **Prewarm the Shamir 3-pass worker and its WASM.** Largest single lever
      found, no architectural change, independent of every other phase here.
- [ ] Consider firing the NEAR RPC prefetch (`accountLifecycle.ts:657`)
      fire-and-forget; it is a UX prefetch on the critical path.
- [ ] Add timing spans covering `finalize_response_received` →
      SeamsWalletDB `batch_started` (the 613 ms window). Wrapping
      `finalizeRegistrationEcdsaSessions` at `registration.ts:3313` is the
      single highest-value span: the inner buckets already exist and `record`
      is additive.
- [ ] Thread diagnostics through `ed25519YaoSealedSession.ts:55,62`, which
      currently pass none, so the Ed25519 seal cycle is invisible.
- [ ] Add timing spans covering `transaction_committed` → timing summary
      emission (the 291 ms window).
- [ ] Attribute `assertMixedRegistrationSharedSigningBudget`
      (`registration.ts:2370`) separately from persistence.
- [ ] Attribute Ed25519 SigningWorker activation
      (`activateVerifiedNearEd25519YaoSigningCapability`) separately.
- [ ] Record the post-instrumentation measurement in this document.
- [ ] Re-decide Phases 3–8 against that measurement before implementing them.

## Phase 3 — Make "no Ed25519 signer yet" representable

This is the prerequisite for every later phase, and the largest piece of work.
It ships with no behaviour change: every wallet still receives both signers.

- [x] Write the WebAuthn credential binding for wallets with no Ed25519 signer.
      `d1WalletRegistrationCommitStore.ts` wrote it only inside
      `if (ed25519Signer)`, so an ECDSA-only passkey wallet got no binding and
      the next login failed `unknown_credential`. The binding is now always
      written; Ed25519 facts are spread in only when that signer exists.
- [x] Make `nearAccountId`, `nearEd25519SigningKeyId`, `signerSlot`, and
      `publicKey` optional on `WebAuthnCredentialBindingRecord`, as an
      all-or-nothing set — a partial Ed25519 identity is still rejected.
- [x] Relax `CHECK (signer_slot >= 1)` to
      `CHECK (signer_slot IS NULL OR signer_slot >= 1)` and make the column
      nullable, via `migrations/d1-signer/0016_signer_webauthn_optional_ed25519.sql`
      (table rebuild, following the `0010` pattern). The store's inline
      `ensureSchema` DDL is kept in sync.
- [x] Replace the HTTP 500 at `routes/syncAccount.ts` with a typed
      `ed25519_not_provisioned` state mapped to 409, modelled on the existing
      `'email_otp_no_ed25519_session'` shape.
- [x] Stop mapping "signer absent" to `unknown_capability` / HTTP 404. The
      capability lookup is gated behind `result.thresholdEd25519`, which the
      new early return in `verifyWebAuthnSyncAccountWithStores` short-circuits,
      so an unprovisioned wallet no longer reaches that branch.
- [x] Remove the `loginState.nearAccountId!` non-null assertion and widen
      `AccountMenuButtonProps.nearAccountId` to `string | null`.
- [ ] Add type fixtures rejecting mixed readiness states and direct invalid
      construction.

Note: there are **two** credential-binding record types and **two** parsers —
`core/WebAuthnCredentialBindingStore.ts` (carries `version`) and
`router/cloudflare/d1WebAuthnRecords.ts` (does not). Both had to be relaxed.
Consolidating them is out of scope here but is a live source of drift.

## Phase 4 — Split the atomic dual-signer commit

**Phase 4 must land together with Phase 5.** Every change below is reachable
only when something defers the Ed25519 commit, and nothing does until Phase 5.
Landing Phase 4 alone would add an always-false branch, which
`refactor-94A-performance-regression.md` decision 12 and Phase 5 below both
forbid. Treat 4 and 5 as one change set with two review boundaries.

Three corrections from mapping the persistence layer (2026-07-28):

**No new composition variant is needed.** A complete ECDSA-only persistence
path already exists and already runs through one transaction:
`finalizeWalletEcdsaRegistration` (`accountLifecycle.ts:1737-1810`) and
`storeWalletEmailOtpEcdsaRegistrationData` (`:1812-1868`), reached from
`registerEvmWallet`. Adding an `ecdsa_only` member to
`StoreWalletRegistrationComposition` (`:193-201`) would instead make the
Ed25519 preamble (`:922-1009`) and the `signerActivations[1]` decode (`:1094`)
dead-but-reachable. Route the deferred path at the caller
(`persistAndActivateMixedRegistration`) rather than inside the composition.

**The guard is split, not removed.** `'Mixed wallet registration persisted an
incomplete signer set'` asserts two independent things: one ECDSA signer per
planned wallet key, and the Ed25519 signer landing at the router-assigned slot.
The ECDSA half stays on commit #1. The Ed25519 half moves to commit #2, where
an equivalent already exists — `'Wallet add-signer persisted a different
Ed25519 signer slot'`. Reuse that message rather than adding a third.

**`activateAuthenticatedWalletState` is split, not weakened.** Its three throws
are the exact post-condition of the Ed25519 commit and must stay strict. All
five fields it requires are Ed25519-specific, and it calls
`initializeNearAccessKey`, which is meaningless without a NEAR operational key.
Add a second, ECDSA-shaped activation instead.

- [ ] Persist ECDSA through the existing ECDSA-only path, adding
      `lastProfileState: { profileId: walletId, activeSignerSlot: 1 }` so the
      wallet is selectable before any Ed25519 signer exists.
- [ ] Commit the deferred Ed25519 signer through
      `finalizeWalletEd25519SignerRegistration` (`accountLifecycle.ts:1345`),
      which already upserts the NEAR profile, creates the
      `nearAccountProjections` row, writes `lastProfileState`, and — unlike
      `persistWalletRegistrationFinalize` — returns a `rollbackReceipt`.
- [ ] Parameterize its hardcoded `SIGNER_AUTH_METHODS.passkey` /
      `passkeyRegistration` (`:1401-1402`, `:1420-1421`); otherwise an
      Email OTP wallet gets a passkey-typed Ed25519 signer, contradicting the
      metadata written at `:1209-1210`.
- [ ] Make its `activationPolicy` retry-tolerant; `fail_if_occupied`
      (`:1405`, `:1424`) hard-fails instead of converging when a retry already
      landed.
- [ ] Split the incomplete-signer-set guard across the two commits as above.
- [ ] Add an ECDSA-only activation variant: resolve by `walletId` profile and
      `signerKind === thresholdEcdsa`, do `setLastProfileStateForProfile` +
      `setCurrentWallet` + `reloadUserSettings`, and omit both
      `initializeNearAccessKey` and the NEAR prefetch.
- [ ] Keep each commit individually atomic and read-back verified. Verified
      safe: slot planning is scoped to `(chainIdKey, accountAddress)` so
      Ed25519 (`wallet`/`near:*`) cannot collide with ECDSA (`evm:*`), and
      `assertSignerKeyMaterialPairsInTransaction` merges already-stored
      material, so commit #1's ECDSA rows still validate during commit #2.
- [ ] Keep the NEAR projection write with the Ed25519 commit. It is already
      implicit: `shouldWriteNearAccountProjection` fires only for
      `accountModel === 'near-native'`, which no ECDSA activation uses.
- [ ] Update the three batch-shape assertions in
      `tests/unit/registrationWalletPersistence.unit.test.ts` — the fixture at
      `:116-119` throws on any `persistWalletSignerFinalize`, and `:492`,
      `:689` assert exactly one finalize batch. Keep them for the non-deferred
      path; add deferred-path cases.
- [ ] Do not use the identifiers `registrationContinuation` /
      `registration_continuation`; they are banned by
      `tests/scripts/check-passkey-registration-rollback-boundaries.mjs:131-135`.

## Phase 5 — Detach the Yao join from registration success

### Server shape: split registration finalize, do not reuse add-signer

Decided 2026-07-28 after mapping the server.

NEAR account creation lives inside `executeWalletRegistrationFinalize`
(`d1WalletRegistrationService.ts:2776-2790`) and is driven by
`accountProvisioning`, supporting both implicit and sponsored-named. Deferring
the Ed25519 commit therefore needs a second server operation. Three candidates
were considered:

1. **Reuse add-signer finalize as-is.** Rejected: it hardcodes implicit
   accounts (`d1WalletAddSignerService.ts:1437`), so `nearAccountId` would stop
   equalling `walletId`, become unknown until Yao settles, and break the
   public result shape.
2. **Extend add-signer to support sponsored-named accounts.** Rejected.
   `ThresholdEd25519AddSignerSpec.mode`
   (`shared-ts/src/utils/registrationIntent.ts:339`) is bound into the
   **add-signer intent digest**, which the client recomputes and compares
   (`registration.ts:5171-5174`). Adding a variant changes an authorization
   digest preimage. It also routes the deferred commit through a *different*
   ceremony with a different authorization, contradicting decision §2 above.
3. **Split registration finalize into an ECDSA finalize and an Ed25519
   finalize.** Chosen. The second call is authorized by the same registration
   ceremony that is already open, so it introduces no new grant, no new
   ceremony purpose, and no digest change — exactly what §2 requires. It also
   reuses the existing sponsored-named path, so `nearAccountId` stays equal to
   `walletId` and no public result type changes.

Consequence: Phase 5 owns a server change to the registration ceremony state
machine, not a client-only change. The ceremony record must stay resumable
between the two finalizes, and the Ed25519 finalize must be idempotent under
retry.


- [ ] Remove the `claimRegistrationYao` await from the registration completion
      path (`registration.ts:3720`).
- [ ] Return the ECDSA-ready result once the ECDSA commit is durable.
- [ ] Keep the Yao promise owned by the page, outside the registration
      completion promise.
- [ ] Commit the Ed25519 signer, NEAR account facts, and `near_ready` state
      when the ceremony settles.
- [ ] Move NEAR account creation out of ECDSA finalize; it needs the Yao public
      key (`d1WalletRegistrationService.ts:2774-2776`).
- [ ] Join duplicate same-tab requests to the in-flight promise.
- [ ] Leave the wallet `ecdsa_ready` on any terminal failure.
- [ ] Do not introduce a feature flag or compatibility branch.

Passkey and Email OTP registration follow the same product lifecycle.

## Phase 6 — Provisioning UI

- [ ] Surface `ecdsa_ready | near_provisioning | near_ready` to the host app.
- [ ] Show a `Provisioning` state on the NEAR sign control and account menu.
- [ ] Show a retryable failure state distinct from provisioning.
- [ ] Never block Tempo or Arc controls on NEAR readiness.
- [ ] Selecting the NEAR tab must not prompt for authorization.

## Phase 7 — Unlock, recovery, refresh, and export

- [ ] Unlock and recovery preserve `ecdsa_ready` when Ed25519 is absent.
- [ ] ECDSA inventory remains usable and recoverable independently.
- [ ] Page refresh rehydrates readiness without creating new authority.
- [ ] Ed25519 recovery runs only for `near_ready`.
- [ ] ECDSA export remains available for `ecdsa_ready`.
- [ ] Ed25519 export returns typed `ed25519_not_provisioned` for
      `ecdsa_ready`; it must not silently create a signer.
- [ ] Active Ed25519 export keeps its existing fresh authorization requirement.
- [ ] Restate "registration and unlock produce equivalent runtime lanes"
      (`docs/intended-behaviours.md:386`) as equivalence against the durable
      signer inventory actually present.

## Phase 8 — Contract and documentation updates

- [ ] Update `docs/intended-behaviours.md:55-63` and `:86-93` so registration
      success means ECDSA-ready.
- [ ] Update the verification rows at `docs/intended-behaviours.md:387-388`.
- [ ] Update `email-otp.registration.contract.test.ts`, which currently exports
      Ed25519 and signs NEAR immediately after registration with no
      intervening step.
- [ ] Update `passkey.ed25519-yao-local.contract.test.ts` to await the
      provisioning state before asserting NEAR signing.
- [ ] `harness.ts:1014` asserts no Yao registration routes during
      `signNearTransaction`; keep it, since this design provisions during
      registration and not at signing time.

## Phase 9 — Demo order and eager chain effects

- [x] Reorder `DemoPage` chains to Tempo, Arc, NEAR.
- [x] Set the initial selected chain to Tempo.
- [x] Update any tab-order/default-selection tests.
- [x] Stop mounting eager NEAR RPC work while Tempo or Arc is selected.
- [x] Gate NEAR greeting reads, funding checks, and access-key polling behind
      NEAR selection.
- [x] Keep generic three-tab styling unchanged.

Gating covered all three chains, not only NEAR: `useDemoEip1559FeeCaps` polled
both Tempo and Arc on an interval while logged out.

## Phase 10 — Validation

- [ ] Passkey registration returns before the Yao ceremony completes.
- [ ] Email OTP registration returns before the Yao ceremony completes.
- [ ] Tempo and Arc sign immediately after registration returns.
- [ ] NEAR shows `Provisioning`, then becomes signable with no further prompt.
- [ ] A forced Yao failure leaves a usable ECDSA wallet and a retryable NEAR
      state.
- [ ] Closing the tab mid-ceremony leaves a usable ECDSA wallet.
- [ ] Refresh rehydrates `ecdsa_ready`, `near_provisioning`, and `near_ready`.
- [ ] ECDSA export works before Ed25519 is provisioned.
- [ ] Ed25519 export is typed-unavailable before provisioning.
- [ ] Ordinary NEAR signing after provisioning makes zero Yao activation calls.
- [ ] Registration is manually verified locally, in staging, and on seams.sh.
- [ ] Post-change registration timing is recorded against the 1,695 ms
      baseline in this document.

## Phase 11 — On-demand provisioning (deferred)

Not in scope. Recorded so the cost argument is not lost.

Phases 3, 4, 6, and 7 are shared prerequisites. What remains is: register with
an ECDSA-only signer set (`registrationSignerSet.ts:21-59` currently forces
`near_ed25519` first), and provision through the existing, contract-tested
`registration.addWalletSigner({ mode: 'ed25519' })` at slot 1 when the user
first wants NEAR.

This is the only variant that removes the per-registration cost of a
relayer-funded NEAR account (`createAccount + transfer + addKey`,
`nearRelayerAccountProvisioning.ts:185`) for users who never use NEAR. It
requires one extra authentication prompt, and — for Email OTP — a new
add-signer branch, since `registration.ts:5100-5142` is passkey-only.

## Implementation order

```text
Phase 2 measurement
  → Phase 3 representability
  → Phase 4 persistence split
  → Phase 5 detach the join
  → Phase 6 UI
  → Phase 7 lifecycle convergence
  → Phase 8 contracts
  → Phase 10 validation
```

Phase 3 ships behind no flag and changes no behaviour, so it can land alone.
Phase 5 must not land before Phases 3 and 4.

## Deletion checklist

- [ ] Delete the registration-time Yao join and its blocking timing branches.
- [ ] Delete the combined Ed25519 + ECDSA persistence batch.
- [ ] Delete the incomplete-signer-set guard.
- [ ] Delete assumptions that every wallet has a NEAR projection.
- [x] Delete default-NEAR demo selection.
- [x] Delete eager chain polling when another chain is selected.
- [ ] Delete compatibility flags and dual blocking/non-blocking paths.

## Completion definition

Complete when registration durably returns an ECDSA-ready wallet without
waiting for Yao, Tempo and Arc work immediately, the Ed25519 signer converges
in the background with no second prompt, a failed ceremony leaves a healthy
ECDSA-ready wallet, all Refactor 93 custody and one-use guarantees remain
intact, and the post-change registration timing is recorded against the
1,695 ms baseline.
