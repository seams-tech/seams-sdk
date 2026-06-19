# Refactor 74: Normal Wallet Operations Without Ed25519 HSS

Date created: June 19, 2026

Status: proposed

Primary source of truth:

- [refactor-68-wallet-session-v2.md](./refactor-68-wallet-session-v2.md)
- [refactor-69C-cleanup-reduce-bloat.md](./refactor-69C-cleanup-reduce-bloat.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Goal

Make wallet unlock and ordinary Ed25519 transaction signing run without any
Ed25519 HSS key-derivation ceremony.

Warm signing session means:

- Wallet Session JWT exists.
- Wallet signing session id exists.
- Threshold session id exists.
- Expiry and budget are active.
- PRF claim or recoverable PRF budget exists for warm-session spending or
  step-up.
- Signing root, lane, and worker scope are persisted.

Ed25519 client signing material is a separate lifecycle. The HSS ceremony should
run only when a flow intentionally derives or exports key material:

- registration material setup
- add-signer or device-sync material setup
- explicit key export

Normal wallet unlock, warm-session restore, and daily transaction signing should
never invoke HSS. Those flows should use an existing client MPC share held by the
signer-core/WASM worker or restored from a worker-owned sealed artifact.

## Current Problem

`SeamsWeb.login().unlock()` currently does more than unlock the wallet. With the
default signing session policy, it also tries to make signing lanes immediately
ready.

The current critical path is:

```text
unlock()
  -> mint or restore Wallet Session
  -> warm threshold signing sessions
  -> prewarmThresholdEd25519ClientBaseFromCredential()
  -> run Ed25519 HSS material-handle reconstruction
  -> assert ready signing lanes
  -> return unlock success
```

This makes wallet unlock pay the Ed25519 HSS cost even when the caller only
needs an authenticated wallet session.

The same architectural problem exists in the first normal signing operation
after a worker restart. Current transaction signing can treat an Ed25519 warm
session as sign-plannable while material is pending, then call
`ensureThresholdEd25519HssSigningMaterial()` to reconstruct material through HSS
before Router A/B normal signing. That is the fallback this refactor removes
from normal signing.

Key files:

- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`

## Verified Current Code Shape

The current code already separates authorization from material enough to skip
HSS during unlock. It does not yet satisfy the stronger target that daily
signing never invokes HSS.

Verified unlock-side callchain:

```text
login.ts
  -> warmThresholdSigningSessions()
  -> primeThresholdLoginWarmSigners()
  -> signingEngine.connectEd25519Session()
  -> provisionThresholdEd25519Session()
  -> threshold/ed25519/connectSession.connectEd25519Session()
  -> mintEd25519WalletSession()
  -> persistWarmSessionEd25519Capability()
  -> cacheSigningSessionPrfFirst()
```

This callchain mints the Wallet Session JWT, persists the warm Ed25519 record,
and caches PRF.first for later material repair. It does not need Ed25519 HSS.
The HSS ceremony enters only through the extra unlock-side call to
`prewarmThresholdEd25519ClientBaseFromCredential()`.

Verified transaction-signing callchain:

```text
signTransactions()
  -> resolveNearSigningSessionAuthContext()
  -> deriveEd25519CapabilityState()
  -> material_pending is treated as ready for passkey warm-session planning
  -> requireNearStepUpAuth()
  -> buildNearEd25519StepUpAuthorization()
  -> classifyRouterAbEd25519PersistedSigningRecord()
  -> pending_material branch
  -> claimPrfFirstByThresholdSessionId()
  -> ensureThresholdEd25519HssSigningMaterial()
  -> persistStoredThresholdEd25519SessionMaterialHandle()
  -> resolveRouterAbEd25519WalletSessionStateFromRecord()
  -> requireRouterAbEd25519NormalSigningReadyState()
  -> Router A/B Ed25519 normal-signing prepare/finalize
```

That means the transaction path can hydrate material after unlock and before any
signature is produced. Today that hydration can invoke HSS. The target refactor
must replace that fallback with signer-core material restore or a clear
`material_restore_required` failure. `requireRouterAbEd25519NormalSigningReadyState()`
still correctly requires a material handle, binding digest, client verifier,
Wallet Session JWT, signing-root scope, and SigningWorker scope before Router
A/B signing starts.

Verified registration persistence gap:

```text
registration.ts
  -> prepareThresholdEd25519RegistrationHssClientMaterialFromPrfFirst()
  -> startWalletRegistration()
  -> prepareThresholdEd25519RegistrationHssClientRequest()
  -> respondWalletRegistrationHss()
  -> buildThresholdEd25519RegistrationHssClientOwnedArtifact()
  -> finalizeWalletRegistration()
  -> storeWalletEd25519RegistrationData()
  -> keyMaterialForSignerActivation()
```

The registration path uses HSS and obtains the Ed25519 key material, then the
local persistence layer stores threshold public metadata such as public key,
relayer key id, key version, and participant ids. It does not persist a
signer-core-owned client MPC share artifact that the normal signing worker can
restore later. That is why normal signing currently has to reconstruct client
material when the worker handle is missing.

### Verified No-HSS Cases

The current code can avoid an HSS ceremony in these cases:

- Unlock: after removing `prewarmThresholdEd25519ClientBaseFromCredential()`,
  the unlock path mints/restores authorization only.
- Signing with a loaded material handle:
  `ensureThresholdEd25519HssSigningMaterial()` first calls
  `validateThresholdEd25519HssMaterialHandleWasm()` when the record already has
  handle metadata. If that worker handle validates, no HSS ceremony runs.

The current code does not provide a no-HSS first-sign path from a plain
`material_pending` record. That is the core implementation gap.
`ensureThresholdEd25519HssSigningMaterial()` has an `existingMaterialCache` API
that accepts raw `xClientBaseB64u`, but that is the wrong direction for this
refactor. Raw client-base material should stay inside signer-core/WASM worker
memory or a worker-owned sealed restore artifact. TypeScript should route opaque
handles and metadata only.

## Signer-Core Crypto Boundary

Cryptographic operations and cryptographic material belong in the Rust
`signer-core` crate and the browser WASM workers that wrap it.

TypeScript may own:

- lifecycle state
- domain parsing at SDK/persistence/request boundaries
- Wallet Session JWT transport
- policy, budget, lane, and signing-root metadata
- opaque material handles
- binding digests and public verifier facts
- worker command orchestration

TypeScript must not own:

- raw Ed25519 client base material
- HSS private/evaluator material
- PRF-derived signing material
- signing-share generation
- Ed25519 signing key reconstruction
- material cache validation implemented in JavaScript

Normal signing after a worker restart requires a signer-core-owned restore path
instead of passing `xClientBaseB64u` through SDK TypeScript. The target shape is
an opaque worker restore command:

```ts
type Ed25519MaterialRestoreRequest = {
  kind: 'ed25519_material_restore_request';
  materialHandle: string;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterial: string;
};
```

The worker validates and opens the sealed artifact internally, loads material
into signer-core memory, and returns only the same handle metadata TypeScript
already uses. If no valid worker-owned restore artifact exists, normal signing
must fail with a recoverable material-restore error. It should not run HSS as a
hidden daily-operation fallback.

## Target Model

Split the lifecycle into two explicit states:

```ts
type WarmEd25519SigningSessionAuthorization = {
  kind: 'warm_ed25519_signing_session_authorized';
  curve: 'ed25519';
  nearAccountId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  thresholdSessionKind: 'jwt';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  walletSessionJwt: string;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  signingWorkerId: string;
  remainingUses: number;
  expiresAtMs: number;
  prfClaim: WarmPrfClaimReady;
  materialState: 'material_pending';
  ed25519HssMaterialHandle?: never;
  ed25519HssMaterialBindingDigest?: never;
  clientVerifyingShareB64u?: never;
};

type WarmPrfClaimReady =
  | {
      kind: 'hot_prf_claim';
      remainingUses: number;
      expiresAtMs: number;
    }
  | {
      kind: 'sealed_prf_claim_restore_available';
      remainingUses: number;
      expiresAtMs: number;
    };
```

Ed25519 signing readiness remains stricter:

```ts
type Ed25519SigningMaterialReady = {
  kind: 'ed25519_signing_material_ready';
  thresholdSessionId: string;
  walletSigningSessionId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  signingWorkerId: string;
  materialHandle: string;
  bindingDigest: string;
  clientVerifyingShareB64u: string;
  sealedWorkerMaterialRef: string;
  xClientBaseB64u?: never;
};
```

Unlock returns after `warm_ed25519_signing_session_authorized`. Signing requires
`ed25519_signing_material_ready`, materializing it lazily when needed.

## No-HSS Unlock Spec

Unlock should do exactly this for Ed25519:

1. Build the Wallet Session policy with `buildEd25519SessionPolicy()`.
2. Collect or reuse the authorization proof for that policy.
3. Mint the Wallet Session through `mintEd25519WalletSession()`.
4. Persist the warm capability with `persistWarmSessionEd25519Capability()`.
5. Cache PRF.first with `cacheSigningSessionPrfFirst()`.
6. Assert the authorization record and PRF claim are active.
7. Return unlock success.

Unlock should skip:

- `prewarmThresholdEd25519ClientBaseFromCredential()`
- `reconstructThresholdEd25519SigningMaterialFromWarmSession()`
- `runThresholdEd25519HssCeremonyWithMaterialHandle()`
- signing-lane postconditions that require `ed25519HssMaterialHandle`

The unlock postcondition should read the persisted Ed25519 record and warm PRF
claim directly. It should validate:

- record exists for the selected account and signer slot
- auth method matches the unlock route
- `thresholdSessionKind === 'jwt'`
- `thresholdSessionId` is non-empty
- `walletSigningSessionId` is non-empty
- `walletSessionJwt` is non-empty
- `runtimePolicyScope` exists
- signing root id and version resolve from `runtimePolicyScope`
- `routerAbNormalSigning.signingWorkerId` is non-empty
- `remainingUses > 0`
- `expiresAtMs > now`
- PRF claim has enough remaining uses or sealed restore is available

It should not inspect `ed25519HssMaterialHandle`,
`ed25519HssMaterialBindingDigest`, `clientVerifyingShareB64u`, or
`xClientBaseB64u`.

## No-HSS Transaction Signing Spec

The first transaction after unlock should use this shape:

1. `resolveNearSigningSessionAuthContext()` reads the warm Ed25519 capability.
2. `deriveEd25519CapabilityState()` returns `material_pending` when auth and
   budget are present but the material handle is missing.
3. `resolvePlannerReadinessForEd25519()` treats passkey `material_pending` as
   ready only when remaining uses cover the transaction signature count.
4. The confirmation flow chooses `warm_session`.
5. `signTransactions()` classifies the stored record with
   `classifyRouterAbEd25519PersistedSigningRecord()`.
6. For `signable`, it validates the loaded worker material handle before Router
   A/B normal signing.
7. For `pending_material`, it calls a signer-core/WASM restore command with
   only opaque restore metadata and public binding facts.
8. The worker opens the sealed client MPC share internally, loads it into worker
   memory, validates the binding digest and client verifier, and returns
   material handle metadata.
9. If the worker cannot restore the share, signing returns
   `material_restore_required` and does not produce a signature.
10. The record is updated through
   `persistStoredThresholdEd25519SessionMaterialHandle()`.
11. `resolveRouterAbEd25519WalletSessionStateFromRecord()` must now parse a
    signable record.
12. `requireRouterAbEd25519NormalSigningReadyState()` validates all Router A/B
    signing prerequisites.
13. Router A/B normal signing prepare/finalize can run.

The above chain guarantees that transaction signing has material before
producing a signature and never invokes HSS during a normal signing operation.
Raw client-base cache reuse in TypeScript is out of scope for the target design.

## Registration Output Spec

Registration is allowed to run HSS because it is a key-material setup flow. Its
completion must leave the client with durable signer-core-owned material for
normal signing:

1. Registration runs the Ed25519 HSS derivation ceremony.
2. signer-core/WASM stores the resulting client MPC share in worker memory.
3. signer-core/WASM emits:
   - opaque material handle
   - binding digest
   - client verifying share
   - sealed worker material artifact or restore reference
4. TypeScript persists only the opaque restore artifact/reference, handle
   metadata, public verifier facts, Wallet Session metadata, and lane scope.
5. TypeScript never receives raw `xClientBaseB64u` or signing shares.
6. Daily unlock restores authorization only.
7. Daily signing validates or restores the worker material handle without HSS.

## Invariants

- Wallet unlock never runs Ed25519 HSS material reconstruction by default.
- Wallet unlock may return an Ed25519 warm session in `material_pending`.
- A `material_pending` Ed25519 warm session is usable for auth planning and
  budget admission.
- A signing operation cannot produce an Ed25519 signature until material
  handle validation succeeds.
- Reusing an already loaded worker material handle still skips HSS.
- Reusing a valid signer-core-owned sealed material restore artifact should
  skip relay HSS after the worker restore path exists.
- Normal transaction signing must not call
  `ensureThresholdEd25519HssSigningMaterial()`,
  `runThresholdEd25519HssCeremonyWithMaterialHandle()`, or any HSS route.
- TypeScript must not persist, deserialize, validate, or pass raw
  `xClientBaseB64u` as a signing material cache.
- Registration and key export keep their existing HSS requirements.
- Compatibility handling stays at persistence and request boundaries only.

## Non-Goals

- Redesign the Ed25519 HSS protocol.
- Persist raw Ed25519 client signing material outside the worker boundary.
- Treat diagnostics or log state as control flow.
- Add legacy flags for old unlock behavior.
- Keep a permanent eager-HSS unlock path.

## Phase 1: Rename The Unlock Contract

- [ ] Introduce an internal `WarmEd25519SigningSessionAuthorization` domain
      type.
- [ ] Make the type carry required identity, budget, auth, lane, and scope
      fields.
- [ ] Keep Ed25519 material handle fields out of the authorization type.
- [ ] Add type fixtures rejecting authorization objects that include material
      fields.
- [ ] Add type fixtures rejecting signing-material-ready objects without a
      material handle, binding digest, and client verifying share.

## Phase 1B: Persist Worker-Owned Client MPC Share At Setup

- [ ] Add signer-core/WASM APIs that seal and restore Ed25519 client MPC share
      material without exposing raw material to TypeScript.
- [ ] Update registration finalization to persist an opaque worker-owned
      material restore artifact/reference alongside public metadata.
- [ ] Update add-signer and device-sync setup flows to produce the same restore
      artifact/reference.
- [ ] Delete or quarantine TypeScript persistence fields that carry raw
      `xClientBaseB64u`.
- [ ] Add type fixtures rejecting any registration persistence object that
      includes raw client signing material.

## Phase 2: Remove Ed25519 HSS From Unlock

- [ ] Delete the `prewarmEd25519MaterialForWarmup()` call from both unlock
      branches in `login.ts`.
- [ ] Delete the helper and remove the
      `prewarmThresholdEd25519ClientBaseFromCredential` import from `login.ts`
      if there is no remaining caller.
- [ ] Keep `primeThresholdLoginWarmSigners()` responsible for minting or
      restoring Wallet Session authorization.
- [ ] Preserve ECDSA warm-session bootstrap behavior only where it is required
      to mint the selected ECDSA session.
- [ ] Update unlock events so `STEP_05_ED25519_SIGNING_SESSION_READY` means
      authorization ready. Rename the event if callers need visible distinction
      between authorization and material readiness.

## Phase 3: Replace Unlock Postconditions

- [ ] Split `assertPasskeyUnlockRuntimePostconditions()` into an unlock
      authorization postcondition and a signing-material postcondition.
- [ ] Make unlock validate active session id, wallet signing session id,
      Wallet Session auth, expiry, budget, auth method, and lane scope.
- [ ] Allow Ed25519 `material_pending` during unlock.
- [ ] Keep registration and explicit signing checks strict about material
      readiness.
- [ ] Stop using `readPersistedAvailableSigningLanes()` as the Ed25519 unlock
      postcondition because it currently models sign-ready lanes.
- [ ] Add unit coverage for Ed25519 unlock success with `material_pending`.
- [ ] Add unit coverage proving Ed25519 signing still materializes or rejects
      before any signature is produced.

## Phase 4: Keep Lazy Materialization In The Sign Path

- [x] Transaction planning already treats passkey Ed25519 `material_pending` as
      sign-plannable when the warm session has enough remaining uses.
- [ ] Replace the transaction `pending_material` HSS repair branch with a
      signer-core material restore branch.
- [ ] Remove daily-signing calls to `claimPrfFirstByThresholdSessionId()` that
      exist only to feed Ed25519 HSS reconstruction.
- [ ] Remove daily-signing calls to `ensureThresholdEd25519HssSigningMaterial()`.
- [x] Reuse an already loaded worker handle when
      `validateThresholdEd25519HssMaterialHandleWasm()` succeeds.
- [ ] Delete the TypeScript raw-client-base cache path from the target signing
      flow instead of wiring it into transaction repair.
- [ ] Add a signer-core-owned sealed material restore command and route only
      opaque restore artifacts through TypeScript.
- [ ] Keep stale raw-client-base pruning, or replace it with deletion of raw
      client-base persistence fields after worker-owned restore lands.
- [ ] Persist the restored material handle after worker restore.
- [ ] Refresh the sealed record after worker restore in the transaction path.
- [ ] Add pending-material pre-repair parity for NEP-413 and delegate-action
      signing before broadening this refactor beyond transactions.

## Phase 5: Optional Background Worker Restore

Default unlock behavior should stay fast. Background worker restore is an
optional follow-up for apps that want immediate signing readiness after unlock.
It must validate or restore a signer-core-owned material handle without HSS.

- [ ] Add an explicit public option only if product wants this behavior.
- [ ] Model the option as a narrow discriminated union, for example:

```ts
type UnlockSigningMaterialRestorePolicy =
  | { kind: 'lazy'; background?: never }
  | { kind: 'background'; background: true };
```

- [ ] Keep the default as `lazy`.
- [ ] Emit background worker-restore events separately from unlock success.
- [ ] Ensure background restore failures do not flip a successful unlock into a
      failed unlock.
- [ ] Add a source guard proving background restore cannot call Ed25519 HSS
      reconstruction or HSS routes.

## Phase 6: Tests And Guards

- [ ] Add a source guard proving `unlock()` does not call
      `prewarmThresholdEd25519ClientBaseFromCredential()`.
- [ ] Add a source guard proving unlock postconditions do not require
      `ed25519HssMaterialHandle`.
- [ ] Add unit tests for:
      - Ed25519 unlock with active budget and missing material handle.
      - Ed25519 unlock failure when Wallet Session auth is missing.
      - Ed25519 unlock failure when budget is expired or exhausted.
      - Registration persists an opaque worker-owned material restore artifact.
      - First NEAR sign restores a pending material session without HSS.
      - First NEAR sign fails before signing when PRF claim is unavailable.
      - Worker handle reuse skips HSS.
      - Worker-owned material restore skips relay HSS after that restore path
        lands.
- [ ] Add a transaction-flow test proving `material_pending` reaches
      `persistStoredThresholdEd25519SessionMaterialHandle()` before Router A/B
      normal signing.
- [ ] Add a source guard proving daily signing code cannot call Ed25519 HSS
      reconstruction or HSS routes.
- [ ] Add a source guard rejecting new TypeScript code that reads or writes raw
      `xClientBaseB64u` outside a persistence-boundary deletion path.
- [ ] Run the focused SDK web type check.
- [ ] Run focused warm-session, runtime-postcondition, and NEAR signing tests.

## Validation Commands

Use the cheapest checks that cover this behavior:

```bash
pnpm -C packages/sdk-web type-check
pnpm -C tests exec playwright test \
  ./unit/runtimePostconditions.unit.test.ts \
  ./unit/warmSessionReadModel.unit.test.ts \
  ./unit/warmSessionStore.transitions.unit.test.ts \
  --reporter=line
```

Add or replace test targets as the implementation creates focused coverage.

## Migration Notes

This is an internal lifecycle cleanup during development. Breaking changes are
allowed.

Delete obsolete eager-HSS unlock assumptions instead of preserving compatibility
paths. If any persisted records encode old material-ready expectations, parse
them once at the persistence boundary into the new authorization/material state
split, then remove the obsolete branch after the replacement is complete.

## Completion Criteria

- `unlock()` succeeds for Ed25519 warm sessions without running Ed25519 HSS.
- Unlock latency no longer includes Ed25519 HSS material reconstruction.
- First Ed25519 signing operation validates or restores signer-core material
  before producing a signature, without invoking HSS.
- Logs no longer show Ed25519 HSS material-handle ceremony timings during
  ordinary wallet unlock or normal transaction signing.
- Tests cover `material_pending` unlock and lazy signing materialization.
- TypeScript carries opaque material handles and public binding facts only;
  signer-core/WASM owns crypto operations and raw material.
