# Refactor 75: Simplify Runtime Signing Material State

Date created: June 20, 2026

Status: in progress

Primary source of truth:

- [refactor-74-login-no-hss.md](./refactor-74-login-no-hss.md)
- [refactor-70-server-budget.md](./refactor-70-server-budget.md)
- [router-a-b-cleanup.md](./router-a-b-cleanup.md)

## Goal

Make Router A/B signing state easier to reason about by separating raw
persistence records from strict domain states, then shrinking duplicated identity
fields in active signing material. Ed25519 is the primary target. ECDSA-HSS gets
a focused parity phase for the same persisted-hint versus worker-validation
boundary.

The customer-facing behavior should stay simple:

- wallet unlock succeeds when Wallet Session authorization is ready
- normal signing restores or validates worker-owned material before producing a
  signature
- final signing consumes validated worker material only
- no HSS/raw-material fallback appears in unlock or normal signing

This refactor is internal SDK cleanup. It should not change public app concepts
or require customers to understand material handles, binding digests, session
bindings, or Router A/B SigningWorker ids.

## Current Problem

`RouterAbEd25519SigningMaterialReady` currently carries many flat identity
fields:

```ts
type RouterAbEd25519SigningMaterialReady = {
  kind: 'router_ab_ed25519_signing_material_ready_v1';
  materialHandle: Ed25519WorkerMaterialHandle;
  bindingDigest: string;
  thresholdSessionId: string;
  signingGrantId: string;
  signingRootId: string;
  signingRootVersion: string;
  expiresAtMs: number;
  nearAccountId: string;
  relayerKeyId: string;
  participantIds: number[];
  signingWorkerId: string;
  clientVerifyingShareB64u: string;
  materialBinding: ThresholdEd25519WorkerMaterialBinding;
  sessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  xClientBaseB64u?: never;
};
```

Those fields exist for good security reasons. They bind the worker material to:

- the material identity loaded in the browser worker
- the Wallet Session and signing grant
- the signing root and account
- the Router A/B SigningWorker
- the public client verifying share

The problem is representation, not the security model. Several flat fields are
duplicated by `materialBinding` and `sessionBinding`, which makes the type
large, easy to copy incorrectly, and hard to audit.

`ThresholdEd25519SessionRecord` also uses optional material fields:

```ts
clientVerifyingShareB64u?: string;
ed25519WorkerMaterialHandle?: string;
ed25519WorkerMaterialBindingDigest?: string;
sealedWorkerMaterialRef?: string;
sealedWorkerMaterialB64u?: string;
materialFormatVersion?: string;
materialKeyId?: string;
materialCreatedAtMs?: number;
signerSlot?: number;
keyVersion?: string;
```

Some optionality is legitimate at the persistence boundary because persisted
records can represent pending, restorable, unvalidated material-hint, and stale
states. That same optional shape should not leak into core signing logic.

## Current Code Baseline

The implementation already has partial versions of the target model:

- `RouterAbEd25519PersistedSigningRecordState` and
  `classifyRouterAbEd25519PersistedSigningRecord` classify persisted Ed25519
  records.
- `classifyRouterAbEcdsaHssPersistedSigningRecord` exists, but it still treats
  a parsed persisted ECDSA record as signable.
- Ed25519 worker-material validation currently uses a process-local marker set.
  That marker must be replaced with a typed, non-secret validation key.
- Active Ed25519 persistence fields already use `ed25519WorkerMaterialHandle`
  and `ed25519WorkerMaterialBindingDigest`.
- Stale HSS naming remains in `RouterAbEd25519SigningMaterialRef.kind` and file
  names such as `hssMaterialBinding.ts`.

This refactor replaces and tightens the existing model. It should not add a
parallel classifier or a second readiness system.

## Target Model

Keep raw optionals at the boundary. Convert immediately into a strict
discriminated union.

```ts
type Ed25519PersistedSigningRecordState =
  | {
      kind: 'auth_ready_material_pending';
      record: Ed25519AuthReadyRecord;
      reason:
        | 'missing_material_handle'
        | 'missing_material_binding_digest'
        | 'missing_client_verifying_share';
      material?: never;
    }
  | {
      kind: 'restore_available';
      record: Ed25519RestoreAvailableRecord;
      sealedMaterial: Ed25519SealedWorkerMaterialRef;
      materialHint: Ed25519SigningMaterialPersistedHint;
      reason: 'loaded_material_missing';
    }
  | {
      kind: 'material_hint_unvalidated';
      record: Ed25519MaterialHintRecord;
      materialHint: Ed25519SigningMaterialPersistedHint;
      sealedMaterial?: never;
    }
  | {
      kind: 'non_signing';
      record: Ed25519NonSigningRecord;
      reason: 'cookie_session';
    }
  | {
      kind: 'invalid';
      record: ThresholdEd25519SessionRecord | null;
      reason: RouterAbSigningWalletSessionParseFailureReason;
    };
```

Only the runtime-validated state can enter final signing:

```ts
type RouterAbEd25519RuntimeValidatedMaterial = {
  kind: 'router_ab_ed25519_runtime_validated_material_v1';
  materialRef: RouterAbEd25519SigningMaterialRef;
  materialBinding: ThresholdEd25519WorkerMaterialBinding;
  sessionBinding: ThresholdEd25519WorkerMaterialSessionBinding;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  expiresAtMs: number;
  xClientBaseB64u?: never;
};
```

The runtime-validated state should expose derived accessors only where route
builders or WASM-boundary calls need flat values. Prefer deriving from
`materialBinding` and `sessionBinding` over storing duplicate flat fields.

Final signing receives a separate budget/admission value:

```ts
type RouterAbEd25519FinalSigningInput = {
  material: RouterAbEd25519RuntimeValidatedMaterial;
  credential: RouterAbWalletSessionCredential;
  budgetAdmission: RouterAbWalletSessionBudgetAdmission;
};
```

Worker-material validation proves that the worker owns material for the current
binding. Budget admission proves the current operation is allowed. Keep those
as separate states.

## Non-Goals

- Do not change Router A/B cryptographic binding semantics.
- Do not remove signing root, SigningWorker, Wallet Session, grant, participant,
  or verifier binding checks.
- Do not add compatibility aliases for old field names.
- Do not change server budget semantics.
- Do not expose these internal state concepts to customer-facing SDK APIs.
- Do not fold final `clientOutputMaskB64u` cleanup into this refactor. That
  remains owned by Refactor 74.

## Resolved Spec Details

Use these names and boundaries consistently across Ed25519 and ECDSA-HSS.

Persisted records can only describe durable facts and restore hints:

- `auth_ready_material_pending`: Wallet Session auth is present, but signing
  material is missing or not restorable from durable worker material.
- `restore_available`: durable sealed worker material or role-local restore
  material exists, but the current worker has not validated it.
- `material_hint_unvalidated`: persisted fields are complete enough to attempt
  worker validation, but this is still not sign-ready.
- `non_signing`: the record is intentionally not a Router A/B bearer Wallet
  Session signing record.
- `invalid`: the record is malformed, stale, mismatched, expired, or missing
  required Router A/B identity.

Only volatile runtime state can be sign-ready:

- `runtime_validated`: the current worker has validated the material handle and
  binding for the current Wallet Session, signing grant, threshold session,
  signing root, runtime policy scope, Router A/B SigningWorker, verifier facts,
  and curve-specific active state.

No persisted field may assert `runtime_validated`. Page reloads, worker restarts,
Wallet Session remints, signing grant changes, signing root changes, Router A/B
activation changes, and verifier changes all invalidate worker-material
validation. Budget expiry invalidates per-operation admission.

Final signing has one valid input shape: runtime-validated worker-owned material
plus current Wallet Session budget/auth. It must not claim PRF output, run HSS
setup, restore sealed material, read raw persistence optionals, or fall back to
legacy material paths. Restore and validation happen before final signing.

Warm-session and lane readers may report auth or budget readiness from persisted
records. They may report sign-ready only from runtime-validated material plus a
current budget admission. When material is not validated, they must surface
`restore_available`, `material_hint_unvalidated`, or
`auth_ready_material_pending` with a concrete reason.

Storage-ref-only Ed25519 sealed records are valid restore records when the record
contains `sealedWorkerMaterialRef`, worker material binding digest, client
verifier, material format version, material key id, signer slot, key version, and
session identity. Inline `sealedWorkerMaterialB64u` is a transport optimization.
The restore boundary resolves either `storage_ref` or `inline_sealed_blob`.

## Phase 1: Inventory And Invariant Lock

- [x] Inventory all Ed25519 material/session state types and constructors:
      `RouterAbEd25519SigningMaterialReady`,
      `RouterAbEd25519SigningMaterialRef`,
      `ThresholdEd25519SessionRecord`,
      `RouterAbEd25519SigningWalletSession`,
      `ResolvedRouterAbEd25519WalletSessionState`,
      sealed restore metadata, and presign-pool scope types.
- [x] Document which fields belong to material identity, session identity,
      server/Router identity, and public verifier identity.
- [x] Confirm `ThresholdEd25519WorkerMaterialBinding` contains stable material
      identity: account id, signer slot, signing root id/version, relayer key id,
      key version, participant ids, client verifying share, material key id, and
      created-at timestamp.
- [x] Confirm `ThresholdEd25519WorkerMaterialSessionBinding` contains session
      identity: material binding digest, account id, signer slot, threshold
      session id, signing grant id, signing root id/version, runtime policy
      scope, relayer key id, key version, participant ids, SigningWorker id, and
      expiry.
- [x] Add source comments or doc notes for any required identity value missing
      from those two binding structs before shrinking flat fields. No missing
      required identity values were found in the current binding structs.
- [x] Confirm there are no persisted fields or durable records that claim
      worker-material validation.
- [x] Superseded: behavior changes started directly in the Phase 2/3
      classifier/readiness implementation.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] Focused source guard inventory test was not added; covered by the existing
      Router A/B source guards and focused classifier tests in Phase 3.

## Phase 2: Introduce Strict Internal State Types

- [x] Add strict Ed25519 persistence state types in a small module near
      `routerAbSigningWalletSession.ts`.
- [x] Superseded: standalone branch-builder functions were skipped. The existing
      classifier now emits exact branch-specific union values directly, which
      avoids extra wrapper ceremony while keeping invalid branches
      unrepresentable.
- [x] Add `never` fields so branch combinations cannot carry impossible material
      data.
- [x] Keep `ThresholdEd25519SessionRecord` as the raw normalized persistence shape
      until all callers are migrated.
- [ ] Add `.typecheck.ts` fixtures rejecting:
      direct runtime-validated construction without `materialHandle`,
      restore branch without sealed material,
      material-hint branch with sealed material,
      pending branch with material fields,
      non-signing branch with Wallet Session signing material,
      broad object-spread construction into runtime-validated state.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [ ] focused type fixtures for Ed25519 state branches

## Phase 3: Isolate Raw Persistence Optionals

- [x] Move optional material fields behind one boundary parser:
      `classifyEd25519PersistedSigningRecord`.
- [x] Update active readers to consume only the strict classified union.
- [x] Keep stale raw-material rejection in the boundary parser only.
- [x] Classify storage-ref-only sealed Ed25519 records as `restore_available`
      when all required worker material metadata is present. Inline sealed blobs
      remain optional restore transport data.
- [x] Replace direct reads of `record.ed25519WorkerMaterialHandle`,
      `record.ed25519WorkerMaterialBindingDigest`, and
      `record.clientVerifyingShareB64u` in core signing/readiness code with
      branch-specific accessors. Restore and persistence boundaries still read
      raw record fields by design.
- [x] Add a source guard that active final signing and readiness files cannot
      read raw optional material fields directly.
- [ ] Keep persistence writes branch-specific:
      auth-ready-material-pending writer, restore-available writer, and
      material-hint-unvalidated writer.
- [ ] Remove any helper that accepts a partial bag of optional material fields
      from core logic.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts --reporter=line`
- [x] Refactor 74/Router A/B focused source guard coverage:
      `thresholdEd25519.nearSigningQueue.guard.unit.test.ts` and
      `routerAbNormalSigningSdk.guard.unit.test.ts`.

## Phase 4: Worker Material Validation Boundary

- [x] Rename worker-material validation concepts away from persisted sign-ready
      wording.
      Use `material_hint_unvalidated` for persisted material and
      `runtime_validated` for current worker material.
- [ ] Replace the current worker-material validation marker set with a typed
      `Ed25519WorkerMaterialValidationKey` builder.
- [ ] Bind worker-material validation to:
      material handle, material binding digest, session binding digest, threshold
      session id, signing grant id, non-secret Wallet Session credential
      fingerprint, client verifier, signing root id/version, runtime policy
      scope, and SigningWorker id.
- [ ] Add `RouterAbEd25519FinalSigningInput` so final signing receives
      `material`, `credential`, and `budgetAdmission` as separate required
      fields.
- [x] Make lane readiness return `auth_ready_material_pending` or
      `restore_available` when current worker validation is absent.
- [x] Ensure final signing accepts only runtime-validated Ed25519 state.
- [ ] Make worker validation return a typed result with explicit failure reasons:
      `worker_material_missing`, `binding_digest_mismatch`,
      `session_binding_mismatch`, `signing_root_mismatch`,
      `signing_worker_mismatch`, `verifier_mismatch`, `expired`, and
      `credential_mismatch`.
- [ ] Ensure validation state is held in a volatile runtime store keyed by the
      typed validation key. Do not persist that store or include raw Wallet
      Session JWTs in its keys.
- [ ] Add tests for:
      worker restart invalidates worker-material validation,
      stale handle with same threshold session id fails,
      restored handle becomes runtime validated,
      refreshed Wallet Session with old material hint classifies as
      `restore_available` or `auth_ready_material_pending`.
      Current focused coverage includes restored-handle and remint
      classification, but worker restart and stale-handle mismatch still need
      explicit cases.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [ ] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`

## Phase 5: Shrink Active Ready State

- [ ] Replace `RouterAbEd25519SigningMaterialReady` with
      `RouterAbEd25519RuntimeValidatedMaterial` or a narrower equivalent.
- [ ] Remove flat fields that are derivable from `materialBinding` or
      `sessionBinding`.
- [ ] Keep flat fields only when they remove repeated parsing and are not
      duplicated in binding structs.
- [ ] Provide named accessors for route-builder and WASM-boundary needs:
      `ed25519ReadyThresholdSessionId`,
      `ed25519ReadySigningGrantId`,
      `ed25519ReadySigningWorkerId`, material handle, material binding,
      session binding, and verifier checks only if call sites genuinely need
      them.
- [ ] Update presign-pool scope to use material binding digest as the material
      identity input.
- [ ] Update final signing call sites in NEAR transaction, NEP-413, delegate, and
      presign-pool flows.
- [ ] Add a source guard proving final signing payloads do not carry raw
      `xClientBaseB64u` or raw optional persistence fields.

Validation:

- [ ] `pnpm -C packages/sdk-web type-check`
- [ ] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEd25519.presignPool.unit.test.ts unit/routerAbEd25519.walletSessionState.unit.test.ts --reporter=line`
- [ ] Router A/B normal-signing SDK source guard

## Phase 6: Naming Cleanup

- [x] Verify active persistence and core signing types use
      `ed25519WorkerMaterialHandle` and `ed25519WorkerMaterialBindingDigest`.
- [x] Keep any HSS naming that still refers to the actual setup ceremony until
      Refactor 74 removes or isolates that ceremony surface.
- [ ] Rename stale HSS references in active normal-signing names, including
      `RouterAbEd25519SigningMaterialRef.kind` and file names such as
      `hssMaterialBinding.ts`, after the HSS setup surface is isolated.
- [ ] Delete stale helper aliases after callers move.
- [ ] Add source guards preventing old HSS-named fields from returning to active
      normal signing state.

Validation:

- [ ] `pnpm -C packages/sdk-web type-check`
- [ ] focused source guards
- [ ] `git diff --check`

## Phase 7: Evidence And Release Criteria

- [ ] Refactor 70 budget evidence harness still proves:
      `remainingUses 3 -> 2 -> 1 -> 0`,
      no TouchID before exhaustion,
      exactly one step-up after exhaustion.
- [ ] Fresh passkey registration produces Ed25519 state that classifies as either
      runtime validated or explicitly restorable before first signing.
- [ ] Browser worker restart produces `restore_available` or
      `auth_ready_material_pending`, then restores before signature creation.
- [ ] No normal signing flow invokes HSS reconstruction.
- [ ] No normal signing flow reads raw `xClientBaseB64u`.
- [ ] Source guards prove raw optional persistence fields are isolated to
      parser/write boundaries.

Validation:

- [ ] `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`
- [ ] `pnpm -C packages/sdk-web type-check`
- [ ] targeted Router A/B and Refactor 74 source guards

## Phase 8: ECDSA-HSS Worker Material Parity

ECDSA-HSS has the same persisted-hint versus worker-validation boundary as
Ed25519, with a narrower material surface. The active risk is
`role_local_ready_state_blob` and record-backed policy being treated as
sign-ready before the current worker proves the role-local material handle.

- [ ] Inventory ECDSA-HSS material/session state types and constructors:
      `RouterAbEcdsaHssSigningWalletSession`,
      `RouterAbEcdsaHssSigningMaterialRef`,
      `ThresholdEcdsaSessionRecord`,
      `ThresholdEcdsaSecp256k1KeyRef`,
      `ReadyEcdsaSignerSession`,
      `ReadyEvmFamilyEcdsaMaterial`,
      `EvmFamilySharedEcdsaReadyState`, and role-local ready records.
- [ ] Document which ECDSA fields belong to active Router A/B state, stable key
      identity, session/grant identity, chain target identity, worker material
      identity, and public verifier identity.
- [ ] Define `EcdsaHssRuntimeMaterialValidationKey` with:
      material handle, binding digest, threshold session id, signing grant id,
      non-secret Wallet Session credential fingerprint, Router A/B active-state
      session id, ECDSA threshold key id, signing root id/version, activation
      epoch, key handle, chain target, participant ids, client/server/threshold
      verifier keys, and SigningWorker id.
- [ ] Split persisted ECDSA role-local state into strict branches:
      `auth_ready_material_pending`,
      `restore_available`,
      `material_hint_unvalidated`,
      `non_signing`, and `invalid`.
- [ ] Keep ECDSA `record_policy` and budget status as auth/budget readiness only.
      They must not imply worker material readiness.
- [ ] Treat `role_local_ready_state_blob` as restore material only. It must not
      classify a lane as sign-ready until the worker stores or validates the
      derived `role_local_worker_share` handle for the current binding.
- [ ] Require runtime worker validation before
      `classifyRouterAbEcdsaHssPersistedSigningRecord` can return a signable
      state.
- [ ] Move ECDSA role-local restore out of final signing and into an explicit
      readiness/restore boundary that returns runtime-validated material.
- [ ] Make ECDSA worker-material validation fail closed when the Wallet Session was
      reminted, the shared signing grant changed, the Router A/B activation epoch
      changed, or the persisted role-local blob does not match current public
      identity.
- [ ] Ensure final Tempo/EVM signing accepts only runtime-validated ECDSA-HSS
      material and one-use presignature state.
- [ ] Keep raw `clientSigningShare32` and additive-share bytes inside worker or
      worker-boundary code. Route orchestration and lane selection must consume
      handles, digests, public facts, and strict state only.
- [ ] Update warm-session status and persisted lane readers so record-backed
      policy can report auth/budget readiness, while sign-ready lanes require
      validated worker material.
- [ ] Keep Email OTP ECDSA worker-share claims as a worker-boundary exception:
      TypeScript may receive the one-use returned bytes only inside the existing
      worker bridge that immediately initializes the presign session and
      zeroizes the bytes.
- [ ] Add source guards preventing active ECDSA final signing and readiness files
      from treating `role_local_ready_state_blob`, `stateBlob`, or
      `clientSigningShare32` as sign-ready material.
- [ ] Add tests for:
      worker restart invalidates ECDSA sign-ready state,
      role-local blob classifies as `restore_available`,
      restore produces runtime-validated worker material,
      stale handle or binding mismatch fails closed,
      Tempo and EVM share the same validated material/budget state.

Validation:

- [ ] `pnpm -C packages/sdk-web type-check`
- [ ] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts unit/warmSessionStore.reconnect.unit.test.ts --reporter=line`
- [ ] focused ECDSA-HSS source guard
- [ ] Refactor 70 budget evidence harness still passes after ECDSA changes

## Completion Criteria

- Active Ed25519 final signing accepts only runtime-validated worker material.
- Active ECDSA-HSS final signing accepts only runtime-validated worker material.
- Optional material fields exist only in raw persistence/request boundary types.
- Persisted material handles are named and modeled as hints.
- `restore_available`, `auth_ready_material_pending`, and `runtime_validated`
  are distinct states.
- Flat ID duplication in active ready state is reduced to fields that cannot be
  derived from `materialBinding` or `sessionBinding`.
- Customer-facing APIs remain unchanged.
