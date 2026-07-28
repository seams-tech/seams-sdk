# Refactor 94 — Non-Blocking Ed25519 Yao Provisioning

## Status

Phases 1, 3, 5, and 9 are complete. Phase 2 is closed on production evidence
(see below) rather than implemented. Phase 4's split persistence and its
convergence tests landed through `d83a906ca`; the ECDSA-only activation variant
remains open. The public host API has landed, while the UI consumers remain
open in Phase 6.
Phases 6–8 and the remaining Phase 10 validation must land before deployment
so `ecdsa_ready`, `near_provisioning`, and `near_ready` are represented
correctly in UI, unlock, recovery, and export.

The two workstreams are complementary and neither substitutes for the other:
94B addresses the 3–5 s cold ECDSA penalty; Phases 4+5 remove the ~2 s warm
Yao wait.

The design changed on 2026-07-27, after measurement. The original plan was
_on-demand lazy provisioning_: registration mints ECDSA only, and the Ed25519
signer is provisioned later when the user first wants NEAR. The adopted design
is _non-blocking provisioning_: the Ed25519 Yao ceremony still runs during
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
records ECDSA at 4.734 s and Ed25519 Yao at 3.544 s running _concurrently_,
with ECDSA determining when finalization begins. Removing the shorter
concurrent branch does not shorten the critical path.

That baseline is also pre-optimization. Phases 4–6 of the performance refactor
have since landed (`25cf4c3a0`, `d0de9311a`, `1e8c16f3a`). A measured **local**
release-profile passkey registration on 2026-07-27 recorded:

| Measure                               | Observed |
| ------------------------------------- | -------: |
| Total registration                    | 1,695 ms |
| ECDSA registration ceremony           |   234 ms |
| authProof (Touch ID, user-controlled) |   334 ms |
| Unattributed                          | 1,026 ms |

The Yao execute call returned 3 ms _before_ finalize started. **Locally**,
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

Also buys, resolved 2026-07-28 in production:

- **Latency, ~1.07 s on a warm registration.** See below. The earlier "removing
  Yao saves approximately zero" finding held only for local workerd, which
  collapses the network boundaries that dominate a deployed environment.

### Production evidence (seams.sh, Email OTP, 2 runs)

| Measure            | Run 1 (cold) | Run 2 (warm) |
| ------------------ | -----------: | -----------: |
| Total              |     6,350 ms | **3,439 ms** |
| ECDSA total        |     5,154 ms |     1,097 ms |
| ECDSA ends at      |     5,783 ms | **1,776 ms** |
| Yao total          |     4,089 ms |     2,171 ms |
| Yao ends at        |     4,718 ms | **2,850 ms** |
| Finalize starts at |     5,783 ms | **2,850 ms** |

The branches invert. Cold, ECDSA determines finalization. **Warm, Yao does**:
finalize begins exactly when Yao ends, 1,074 ms after ECDSA already finished.
Detaching the join takes the warm run from 3,439 ms to roughly 2,365 ms — a 31%
reduction that lands inside the 2–3 s target.

The warm run is the case to design against; cold-start variance dwarfs
everything else (Gateway respond/activate went 2,508/2,514 ms cold to
915/165 ms warm), so no single sample is decisive on its own.

These runs came from production `seams.sh` on the previously deployed frontend,
not from the staging revision. That build predates the new Yao buckets, which
is why none appear.

### Second production pair, on the instrumented frontend (2026-07-28)

Two further Email OTP registrations after the frontend deploy, now with the
dedicated buckets:

| Measure                     | Run 3 (cold) | Run 4 (warm) |
| --------------------------- | -----------: | -----------: |
| Total                       |     4,685 ms | **3,963 ms** |
| ECDSA total                 |     3,420 ms |       627 ms |
| ECDSA ends at               |     4,013 ms | **1,340 ms** |
| Yao total                   |     2,895 ms |     2,626 ms |
| Yao ends at                 |     3,487 ms | **3,339 ms** |
| Finalize starts at          |     4,013 ms | **3,339 ms** |
| **`yaoClientCompletionMs`** |         0 ms | **2,000 ms** |

Run 4 measures the payoff directly rather than inferring it from span offsets:
registration idles **2,000 ms** after ECDSA completes, waiting on Yao. Detaching
the join lands it near 1.96 s — roughly a **50% reduction**, and inside the
2–3 s target. Run 3 is the cold shape, where ECDSA again dominates.

All ten `yaoServer*Ms` buckets read 0 in both runs. The client half is
provably live — `yaoBranchTotalMs`, `yaoClientSessionCreateMs` and the
worker-sourced `clientTimings` all populate — so the missing piece is the
`Server-Timing` header itself. The header emission and its
`Access-Control-Expose-Headers` live in the same backend commit, and the
deploy runs referenced staging, so **production is serving an older backend**.
An unauthenticated probe cannot distinguish the builds, because the expose
header is conditional on `Server-Timing` being present and both gateways
return 400 without it. Deploying the production backend and re-running is the
decisive test.

Caveats: Email OTP only. Passkey has still not been measured in production.

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

- [x] Deploy the Yao `Server-Timing` instrumentation. Frontend is live in
      production; the **backend is not** — see below.
- [ ] Record one production registration and locate the 2,348 ms Yao interval.
      Blocked on the production backend deploy.
- [x] **Confirm whether the production Yao branch is on the critical path.
      Yes.** Four production Email OTP registrations, two before and two after
      the frontend deploy, all show finalize beginning exactly when the Yao
      branch ends once ECDSA is warm.

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

- [x] **Prewarm the Shamir 3-pass worker and its WASM.** Landed. It is the
      only worker on the passkey registration path without a prewarm, paying a
      nested worker spawn plus a 422 KB WASM instantiate inside the
      post-finalize window. Chained onto `prewarmUiConfirmUi`, best-effort,
      every failure swallowed. Scope note: production Email OTP runs report
      `registrationWarmupUiConfirmPrewarmMs: 0` and every
      `ecdsaRegistrationWarmSession*` bucket at 0, confirming this is a
      passkey-path change that costs Email OTP nothing.
- [x] Fire the NEAR RPC prefetch (`accountLifecycle.ts:657`) fire-and-forget.
      It was awaited on the critical path despite its own comment describing it
      as non-fatal UX warm-up.
      The remaining client-side span work was **dropped as unnecessary**, on
      evidence. The 613 ms and 291 ms windows were local-workerd artifacts, not a
      production cost:

- production span coverage is already 94.7–96.7% with only 154–210 ms
  unattributed, against 39% locally;
- `ecdsaRegistrationSessionFinalizeMs` — the wrapper that was to be the
  "single highest-value span" — is already instrumented and reads **12–15 ms**
  in production;
- every `ecdsaRegistrationWarmSession*` bucket reads **0** on production Email
  OTP, so the Shamir seal cycle that dominated the local window does not run
  on that path at all.

Adding spans to attribute ~180 ms of production time, in the file that Phases
4–5 are about to restructure, is not worth the churn. Revisit only if a
passkey production run shows a large unattributed remainder.

- [x] ~~Add timing spans covering `finalize_response_received` →
      SeamsWalletDB `batch_started`~~ — dropped, see above.
- [ ] Thread diagnostics through `ed25519YaoSealedSession.ts:55,62`, which
      currently pass none, so the Ed25519 seal cycle is invisible. Keep: this
      is the passkey path, still unmeasured in production.
- [x] ~~Add timing spans covering `transaction_committed` → timing summary
      emission~~ — dropped, see above.
- [x] ~~Attribute `assertMixedRegistrationSharedSigningBudget`~~ — dropped; it
      is synchronous pure JS and costs nanoseconds.
- [x] ~~Attribute Ed25519 SigningWorker activation separately~~ — dropped; it
      is an in-memory registry write and is sub-millisecond.
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
- [x] Add type fixtures rejecting mixed readiness states and direct invalid
      construction — `core/WebAuthnCredentialBindingStore.typecheck.ts`. Five
      `@ts-expect-error` cases cover each single fact alone, three-of-four, and
      an explicitly `undefined` fact. They are live: `sdk-server-ts` compiles
      `src/**/*`, and an unsatisfied `@ts-expect-error` is itself an error.

**Phase 3 is complete.**

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

- [x] Persist ECDSA through the existing ECDSA-only path, adding
      `lastProfileState: { profileId: walletId, activeSignerSlot: 1 }` so the
      wallet is selectable before any Ed25519 signer exists.
- [x] Commit the deferred Ed25519 signer through
      `finalizeWalletEd25519SignerRegistration` (`accountLifecycle.ts:1345`),
      which already upserts the NEAR profile, creates the
      `nearAccountProjections` row, writes `lastProfileState`, and — unlike
      `persistWalletRegistrationFinalize` — returns a `rollbackReceipt`.
- [x] ~~Parameterize its hardcoded `SIGNER_AUTH_METHODS.passkey` /~~
      `passkeyRegistration` (`:1401-1402`, `:1420-1421`); otherwise an
      Email OTP wallet gets a passkey-typed Ed25519 signer, contradicting the
      metadata written at `:1209-1210`.
      Closed as superseded after mapping the actual persistence path. This
      premise was wrong:
      registration never reaches `finalizeWalletEd25519SignerRegistration`.
      That is the add-signer surface, and `RegistrationPersistencePlan` has no
      `ed25519` member. Registration persists its Ed25519 signer through
      `persistWarmSessionEd25519Capability`, which already takes the auth
      method as an argument, so no Email OTP wallet could get a passkey-typed
      signer from this path. The finalizer was parameterized, found unreachable
      from registration, and collapsed back to a single explicit `passkey`
      branch rather than retaining an unreachable Email OTP branch.
- [x] Split the incomplete-signer-set guard across the two commits as above.
- [ ] Add an ECDSA-only activation variant: resolve by `walletId` profile and
      `signerKind === thresholdEcdsa`, do `setLastProfileStateForProfile` +
      `setCurrentWallet` + `reloadUserSettings`, and omit both
      `initializeNearAccessKey` and the NEAR prefetch.
- [x] Keep each commit individually atomic and read-back verified. Verified
      safe: slot planning is scoped to `(chainIdKey, accountAddress)` so
      Ed25519 (`wallet`/`near:*`) cannot collide with ECDSA (`evm:*`), and
      `assertSignerKeyMaterialPairsInTransaction` merges already-stored
      material, so commit #1's ECDSA rows still validate during commit #2.
- [x] Keep the NEAR projection write with the Ed25519 commit. It is already
      implicit: `shouldWriteNearAccountProjection` fires only for
      `accountModel === 'near-native'`, which no ECDSA activation uses.
- [x] Update the three batch-shape assertions in
      `tests/unit/registrationWalletPersistence.unit.test.ts` — the fixture at
      `:116-119` throws on any `persistWalletSignerFinalize`, and `:492`,
      `:689` assert exactly one finalize batch. Keep them for the non-deferred
      path; deferred-path cases now cover the split commits.
- [x] Do not use the identifiers `registrationContinuation` /
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
   digest preimage. It also routes the deferred commit through a _different_
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

### Server map, verified 2026-07-28

Mapped against `04c044efb`. Three assumptions above needed correcting.

**Correction 1 — NEAR account creation is already Ed25519-local.** The
checklist item below said to move it out of ECDSA finalize, citing
`d1WalletRegistrationService.ts:2774-2776`. That anchor is the Email-OTP
enrollment _prepare_ (pure validation, no write). The only NEAR
account-creation call is `this.createSponsoredNamedNearAccount(...)` at
`:2870-2879`, already inside the Ed25519 sub-block (`:2789-3010`), gated by
`sponsoredNamedRegistrationAccountId(requestedNearEd25519.accountProvisioning)`
at `:2867`. The split inherits correct placement for free, and the Ed25519
finalize keeps `accountProvisioning` handling verbatim — including the
sponsored-named path, which is exactly why option 3 was chosen over reusing
add-signer.

**Correction 2 — finalize does no CAS today, so the resumable state is new
work, not an extension.** `executeWalletRegistrationFinalize` (`:2626-3201`)
reads the ceremony with unversioned `getCeremony` (`:2670`), never calls
`updateCeremony` / `claimEcdsa*` / `commitEcdsaClaim`, and ends with an
**unconditional `deleteCeremony`** (`:3185`). The ECDSA finalize must stop that
delete from firing when an Ed25519 branch is still pending; otherwise the
second finalize has no ceremony to resume. The claim/commit CAS primitives it
needs already exist for the respond/activate routes
(`d1RegistrationCeremonyStore.ts:183`, `:202`, `:217`, funnelling through
private `claimEcdsaBranch` at `:529`) and are the model to follow.

**Correction 3 — there are already three idempotency mechanisms, and the
second call needs no new one.** An earlier revision of this section called for
a new route, a new server operation, and a new side-effect key. That was
wrong, and in an expensive direction. The mechanisms are:

1. Outer: `runRouterAbEd25519YaoRegistrationSideEffectV1` (`:2570`), keyed on
   `sha256("wallet-registration-finalize-v1\0{ceremonyId}\0{idempotencyKey}")`
   (`:2565-2569`). `idempotencyKey` is **client-supplied per call**, so two
   finalize calls already get two distinct effect keys. No new operation
   member is needed in
   `routerAbEd25519YaoRegistrationSideEffectBoundary.ts:6-10`.
2. Inner: the ceremony store's `getFinalizeReplay`/`putFinalizeReplay` pair
   (`:2645`, `:3170`) — a plain response cache keyed the same way, so it also
   separates the two calls for free.
3. Yao-local: `yaoRuntime.consumeActivated(...)` (`:2828`), one-shot via its
   `activation_consumed` failure code. Already belongs to the Ed25519 half and
   moves with it unchanged.

**Correction 4 — no new route and no second service method. The existing
finalize already has the right internal shape.** Both halves of
`executeWalletRegistrationFinalize` are _already_ independently gated and
independently build their own records:

- the ECDSA half (`:2718-2765`) gated on `requestedEvmFamilyEcdsa`, producing
  `ecdsaWalletKeys`;
- the Ed25519 half (`:2794-3010`) gated on `requestedNearEd25519`, producing
  `ed25519SignerRecord`, `resolvedNearAccount`, and the capability install;
- the commit (`:3012-3060`) assembling whatever those two produced;
- the response builder (`:3084-3164`) already covering all three kinds off the
  same two booleans.

Both booleans come from the **plan**. Deriving them from the **request kind**
instead is what splits the operation — the rest of the function already works
per-half. That is the whole server change, and it is on the order of a hundred
lines, not a new subsystem.

**Shape of the split.** The request discriminator already distinguishes the
three cases (`registrationContracts.ts:563-578`):

| plan               | finalize calls                                               |
| ------------------ | ------------------------------------------------------------ |
| `evm_family_ecdsa` | one call, `evm_family_ecdsa`; deletes the ceremony as today  |
| `near_ed25519`     | one call, `near_ed25519`                                     |
| mixed              | `evm_family_ecdsa`, ceremony stays open, then `near_ed25519` |

Only the mixed plan changes. The single atomic commit batch
(`d1WalletRegistrationCommitStore.ts:209-242`) becomes two batches for it,
which Phase 4 already requires, and both batches are safe: every statement is
an upsert, and `prepareAuthorityStatements` (`:84-166`) already writes the
credential binding with Ed25519 facts only when an Ed25519 signer is present.
Commit #2 passing just the Ed25519 signer therefore performs the Phase 3
convergence with no further change. Email-OTP statements must not run twice —
they belong to commit #1.

**Consequence: the combined kind becomes unreachable and must be deleted.**
For a mixed plan the client now receives `evm_family_ecdsa` then
`near_ed25519`, so `near_ed25519_and_evm_family_ecdsa` disappears from both
the request and response unions. Decision 12 (no compatibility branches)
requires removing it in the same change set. Measured blast radius: 52
references across 8 source files —

`core/registrationContracts.ts`, `core/registrationRequests.typecheck.ts`,
`router/walletRegistrationRoutes.ts`,
`router/cloudflare/d1WalletRegistrationService.ts`,
`router/cloudflare/d1RegistrationCeremonyRecords.ts`,
`sdk-web/core/rpcClients/relayer/walletRegistration.ts`,
`sdk-web/core/signingEngine/flows/registration/accountLifecycle.ts`,
`sdk-web/SeamsWeb/operations/registration/registration.ts`

— plus `tests/unit/walletRegistrationYaoFinalizeContracts.domain.guard.unit.test.ts`,
`tests/unit/walletRegistrationYaoClientContracts.unit.test.ts`, and
`tests/unit/addWalletSigner.orchestration.unit.test.ts`. Most are one case in a
three-case switch.

### Phase 4+5 server checklist, corrected

- [x] Derive the two half-gates from `request.kind`, not from the plan.
- [x] Replace `finalizeSignerWorkMatchesPlan` (`:875-888`) with a check that
      the requested kind is a subset of the plan **and** legal for the current
      branch progress: `evm_family_ecdsa` requires the ECDSA branch
      `activated`; `near_ed25519` on a mixed plan requires it `finalized`.
- [x] Add an `evm_family_ecdsa_finalized` branch kind
      (`RegistrationCeremonyStore.ts:343-378`), extend
      `findStoredWalletRegistrationEvmFamilyEcdsaBranch` (`:423-438`), and
      commit the transition through the existing `commitEcdsaClaim` CAS.
- [x] Make `deleteCeremony` (`:3185`) conditional on no planned branch
      remaining un-finalized.
- [x] Keep Email-OTP enrollment persistence on commit #1 only.
- [x] Delete the combined request and response kind across all 11 files.

Open question for implementation: commit #2 re-puts the credential binding
with `createdAtMs: input.now` (`d1WalletRegistrationCommitStore.ts:134`),
which would reset the original creation time. Check whether the put preserves
`created_at` on conflict; if not, thread the ceremony's original timestamp.

- [x] Remove the `claimRegistrationYao` await from the registration completion
      path (`registration.ts:3720`).
- [x] Return the ECDSA-ready result once the ECDSA commit is durable.
- [x] Keep the Yao promise owned by the page, outside the registration
      completion promise.
- [x] Commit the Ed25519 signer, NEAR account facts, and `near_ready` state
      when the ceremony settles.
- [x] Add a ceremony state representing "ECDSA committed, Ed25519 pending",
      and suppress the unconditional `deleteCeremony` while it holds.
- [x] Give the Ed25519 finalize its own side-effect operation and effect key.
- [x] Join duplicate same-tab requests to the in-flight promise.
- [x] Leave the wallet `ecdsa_ready` on any terminal failure.
- [x] Do not introduce a feature flag or compatibility branch.

Passkey and Email OTP registration follow the same product lifecycle.

## Phase 6 — Provisioning UI

- [x] Surface `ecdsa_ready | near_provisioning | near_ready` to the host app.
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
- [x] Restate "registration and unlock produce equivalent runtime lanes"
      (`docs/intended-behaviours.md:386`) as equivalence against the durable
      signer inventory actually present.

## Phase 8 — Contract and documentation updates

- [x] Update `docs/intended-behaviours.md:55-63` and `:86-93` so registration
      success means ECDSA-ready.
- [x] Update the verification rows at `docs/intended-behaviours.md:387-388`.
- [x] Update `email-otp.registration.contract.test.ts`, which currently exports
      Ed25519 and signs NEAR immediately after registration with no
      intervening step.
- [x] Update the mixed passkey registration contract to sign Tempo while NEAR
      remains pending, then await `near_ready` before NEAR signing.
- [x] Keep the harness assertion that NEAR signing does not invoke Yao
      registration routes, since this design provisions during registration
      and not at signing time.

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

- [x] Passkey registration returns before the Yao ceremony completes. Covered
      with Yao held unresolved and one Touch ID prompt in `d83a906ca`.
- [x] Email OTP registration returns before the Yao ceremony completes. Covered
      with the Email OTP Yao promise held unresolved in `d83a906ca`.
- [ ] Tempo and Arc sign immediately after registration returns.
- [ ] NEAR shows `Provisioning`, then becomes signable with no further prompt.
- [x] A forced Yao finalize or seal failure leaves the durable ECDSA wallet
      intact and publishes `near_failed_retryable`.
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
