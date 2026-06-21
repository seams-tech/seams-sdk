# Refactor 75: Simplify Runtime Signing Material State

Date created: June 20, 2026

Status: complete through Phase 10; live Refactor 70 evidence remains separate

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
- Active Ed25519 worker-material naming now uses worker-material terminology in
  the material-ref discriminator and module filenames.

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
- [x] Add `.typecheck.ts` fixtures rejecting current invalid branch
      combinations:
      runtime-validated state without parsed signing value, runtime-validated
      state with a failure reason, restore/material-hint/pending/non-signing
      branches carrying signable values, material-hint branch carrying sealed
      material, and Ed25519 signing value construction without material handle.
- [x] Add exact-type hardening for broad object-spread construction into
      runtime-validated state. Plain `satisfies` checks do not reliably reject
      spread extras.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] focused type fixtures for Ed25519 state branches

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
- [x] Keep persistence writes branch-specific:
      auth-ready-material-pending writer, restore-available writer, and
      material-hint-unvalidated writer.
- [x] Remove any helper that accepts a partial bag of optional material fields
      from core logic. The broad `upsertStoredThresholdEd25519SessionRecord`
      remains a persistence boundary normalizer only.

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
- [x] Replace the current worker-material validation marker set with a typed
      `Ed25519WorkerMaterialValidationKey` builder.
- [x] Bind worker-material validation to:
      material handle, material binding digest, session binding digest, threshold
      session id, signing grant id, non-secret Wallet Session credential
      fingerprint, client verifier, signing root id/version, runtime policy
      scope, and SigningWorker id.
- [x] Superseded: a separate `RouterAbEd25519FinalSigningInput` wrapper was not
      added. Final signing now receives runtime-validated worker material, and
      budget admission remains explicit in the signing state machine plus
      server-authoritative Router A/B normal-signing routes.
- [x] Make lane readiness return `auth_ready_material_pending` or
      `restore_available` when current worker validation is absent.
- [x] Ensure final signing accepts only runtime-validated Ed25519 state.
- [x] Make worker validation return a typed result with explicit failure reasons:
      `worker_material_missing`, `binding_digest_mismatch`,
      `session_binding_mismatch`, `signing_root_mismatch`,
      `signing_worker_mismatch`, `verifier_mismatch`, `expired`, and
      `credential_mismatch`.
- [x] Ensure validation state is held in a volatile runtime store keyed by the
      typed validation key. Do not persist that store or include raw Wallet
      Session JWTs in its keys.
- [x] Add tests for:
      worker restart invalidates worker-material validation,
      stale handle with same threshold session id fails,
      restored handle becomes runtime validated,
      refreshed Wallet Session with old material hint classifies as
      `restore_available` or `auth_ready_material_pending`.
      Focused coverage now includes worker restart, stale handle, restored
      handle, remint, and material-pending classification.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEd25519.walletSessionState.unit.test.ts unit/warmSessionStore.transitions.unit.test.ts --reporter=line`

## Phase 5: Shrink Active Ready State

- [x] Replace `RouterAbEd25519SigningMaterialReady` with
      `RouterAbEd25519RuntimeValidatedMaterial` or a narrower equivalent.
- [x] Remove flat fields that are derivable from `materialBinding` or
      `sessionBinding`.
- [x] Keep flat fields only when they remove repeated parsing and are not
      duplicated in binding structs.
- [x] Provide named accessors for route-builder and WASM-boundary needs:
      `ed25519ReadyThresholdSessionId`,
      `ed25519ReadySigningGrantId`,
      `ed25519ReadySigningWorkerId`, material handle, material binding,
      session binding, and verifier checks only if call sites genuinely need
      them.
- [x] Update presign-pool scope to use material binding digest as the material
      identity input.
- [x] Update final signing call sites in NEAR transaction, NEP-413, delegate, and
      presign-pool flows.
- [x] Add a source guard proving final signing payloads do not carry raw
      `xClientBaseB64u` or raw optional persistence fields.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/thresholdEd25519.presignPool.unit.test.ts unit/routerAbEd25519.walletSessionState.unit.test.ts --reporter=line`
- [x] Router A/B normal-signing SDK source guard

## Phase 6: Naming Cleanup

- [x] Verify active persistence and core signing types use
      `ed25519WorkerMaterialHandle` and `ed25519WorkerMaterialBindingDigest`.
- [x] Keep any HSS naming that still refers to the actual setup ceremony until
      Refactor 74 removes or isolates that ceremony surface.
- [x] Rename stale active normal-signing material kind:
      `RouterAbEd25519SigningMaterialRef.kind` now uses
      `router_ab_ed25519_worker_material_ref_v1`.
- [x] Rename stale HSS module/file references such as `hssMaterialBinding.ts`
      after the HSS setup surface is isolated and Refactor 76 branded-key work
      settles. The active module is now `workerMaterialBinding.ts`.
- [x] Delete stale helper aliases after callers move. No compatibility import path
      or alias for `hssMaterialBinding.ts` remains.
- [x] Add source guards preventing old raw-HSS material fields and HSS
      reconstruction helpers from returning to active normal signing state.
      Covered by the Router A/B normal-signing and Refactor 74 source guards.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] focused source guards
- [x] `git diff --check`

## Phase 7: Evidence And Release Criteria

- [x] Refactor 70 budget evidence harness still proves:
      `remainingUses 3 -> 2 -> 1 -> 0`,
      no TouchID before exhaustion,
      exactly one step-up after exhaustion.
- [x] Fresh passkey registration produces Ed25519 state that classifies as either
      runtime validated or explicitly restorable before first signing.
- [x] Browser worker restart produces `restore_available` or
      `auth_ready_material_pending`, then restores before signature creation.
      Covered by the budget evidence harness cold Ed25519 material case, which
      removes the material-handle hint, resets the signer worker, and verifies a
      single worker-material restore before signing.
- [x] No normal signing flow invokes HSS reconstruction.
- [x] No normal signing flow reads raw `xClientBaseB64u`.
- [x] Source guards prove raw optional persistence fields are isolated to
      parser/write boundaries.

Validation:

- [x] `RUN_ROUTER_AB_BUDGET_EVIDENCE=1 pnpm -C tests exec playwright test --reporter=line e2e/routerAb.serverBudgetEvidence.walletIframe.test.ts`
- [x] `pnpm -C packages/sdk-web type-check`
- [x] targeted Router A/B and Refactor 74 source guards

## Phase 8: ECDSA-HSS Worker Material Parity

ECDSA-HSS has the same persisted-hint versus worker-validation boundary as
Ed25519, with a narrower material surface. The active risk is
`role_local_ready_state_blob` and record-backed policy being treated as
sign-ready before the current worker proves the role-local material handle.

- [x] Inventory ECDSA-HSS material/session state types and constructors:
      `RouterAbEcdsaHssSigningWalletSession`,
      `RouterAbEcdsaHssSigningMaterialRef`,
      `ThresholdEcdsaSessionRecord`,
      `ThresholdEcdsaSecp256k1KeyRef`,
      `ReadyEcdsaSignerSession`,
      `ReadyEvmFamilyEcdsaMaterial`,
      `EvmFamilySharedEcdsaReadyState`, and role-local ready records.
- [x] Document which ECDSA fields belong to active Router A/B state, stable key
      identity, session/grant identity, chain target identity, worker material
      identity, and public verifier identity.
- [x] Define `EcdsaHssRuntimeMaterialValidationKey` with:
      material handle, binding digest, threshold session id, signing grant id,
      non-secret Wallet Session credential fingerprint, Router A/B active-state
      session id, ECDSA threshold key id, signing root id/version, activation
      epoch, key handle, chain target, participant ids, client/server/threshold
      verifier keys, and SigningWorker id.
- [x] Split persisted ECDSA role-local state into strict branches:
      `auth_ready_material_pending`,
      `restore_available`,
      `material_hint_unvalidated`,
      `non_signing`, and `invalid`.
- [x] Keep ECDSA `record_policy` and budget status as auth/budget readiness only.
      They must not imply worker material readiness.
- [x] Treat `role_local_ready_state_blob` as restore material only. It must not
      classify a lane as sign-ready until the worker stores or validates the
      derived `role_local_worker_share` handle for the current binding.
- [x] Require runtime worker validation before
      `classifyRouterAbEcdsaHssPersistedSigningRecord` can return a signable
      state.
- [x] Move ECDSA role-local restore out of final signing and into an explicit
      readiness/restore boundary that returns runtime-validated material.
- [x] Make ECDSA worker-material validation fail closed when the Wallet Session was
      reminted, the shared signing grant changed, the Router A/B activation epoch
      changed, or the persisted role-local blob does not match current public
      identity.
- [x] Ensure final Tempo/EVM signing accepts only runtime-validated ECDSA-HSS
      material and one-use presignature state.
- [x] Keep raw `clientSigningShare32` and additive-share bytes inside worker or
      worker-boundary code. Route orchestration and lane selection must consume
      handles, digests, public facts, and strict state only.
- [x] Update warm-session status and persisted lane readers so record-backed
      policy can report auth/budget readiness, while sign-ready lanes require
      validated worker material.
- [x] Keep Email OTP ECDSA worker-share claims as a worker-boundary exception:
      TypeScript may receive the one-use returned bytes only inside the existing
      worker bridge that immediately initializes the presign session and
      zeroizes the bytes.
- [x] Add source guards preventing active ECDSA final signing and readiness files
      from treating `role_local_ready_state_blob`, `stateBlob`, or
      `clientSigningShare32` as sign-ready material.
- [x] Add tests for:
      worker restart invalidates ECDSA sign-ready state,
      role-local blob classifies as `restore_available`,
      restore produces runtime-validated worker material,
      stale handle or binding mismatch fails closed,
      Tempo and EVM share the same validated material/budget state.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] `pnpm -C tests exec playwright test -c playwright.unit.config.ts unit/routerAbEcdsaHssNormalSigning.unit.test.ts unit/warmSessionStore.reconnect.unit.test.ts --reporter=line`
- [x] focused ECDSA-HSS source guard
- [x] Refactor 70 budget evidence harness still passes after ECDSA changes

## Phase 9: Fail-Closed Budget Admission And Activation Payload Boundaries

Refactor 70 made server-side Wallet Session budget authoritative. Persisted
records may still provide restore facts and display hints, but they must not
become signing-admission authority when a server budget read is absent,
rejected, stale, or ambiguous.

The active weak pattern is `record_policy` consumption falling back from a
missing `SigningSessionStatus` to persisted `record.remainingUses` and
`record.expiresAtMs`. That shape is hard to audit because optional chaining and
`??` make a missing server fact look equivalent to a current server fact.

Target shape:

```ts
function invalidRecordPolicyBudgetStatus(message: string): WarmSessionStatusResult {
  return {
    ok: false,
    code: 'budget_status_required',
    message,
  };
}

function admitActiveRecordPolicyLaneFromTrustedStatus(args: {
  status: SigningSessionStatus & { status: 'active' };
  uses: number;
  nowMs: number;
}): WarmSessionStatusResult {
  if (!Number.isSafeInteger(args.status.expiresAtMs)) {
    return invalidRecordPolicyBudgetStatus(
      'active server budget status is missing expiresAtMs',
    );
  }

  if (!Number.isSafeInteger(args.status.remainingUses)) {
    return invalidRecordPolicyBudgetStatus(
      'active server budget status is missing remainingUses',
    );
  }

  const availableUses = availableUsesForBudgetAdmission(args.status);

  if (args.status.expiresAtMs <= args.nowMs) {
    return {
      ok: false,
      code: 'expired',
      message: 'record-policy signing session expired',
    };
  }

  if (availableUses < args.uses) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'record-policy signing session exhausted',
    };
  }

  return {
    ok: true,
    remainingUses: availableUses - args.uses,
    expiresAtMs: args.status.expiresAtMs,
  };
}

function admitRecordPolicyLaneFromTrustedStatus(args: {
  lane: DiscoveredSigningSessionLane;
  uses: number;
  nowMs: number;
  trustedBudgetStatus: SigningSessionStatus | null;
}): WarmSessionStatusResult {
  const status = args.trustedBudgetStatus;

  if (!status) {
    return invalidRecordPolicyBudgetStatus(
      'server budget status is required for record-policy signing session',
    );
  }

  switch (status.status) {
    case 'active':
      return admitActiveRecordPolicyLaneFromTrustedStatus({
        status,
        uses: args.uses,
        nowMs: args.nowMs,
      });
    case 'expired':
      return {
        ok: false,
        code: 'expired',
        message: 'record-policy signing session expired',
      };
    case 'exhausted':
      return {
        ok: false,
        code: 'exhausted',
        message: 'record-policy signing session exhausted',
      };
    case 'not_found':
    case 'unavailable':
    case 'budget_unknown':
      return invalidRecordPolicyBudgetStatus(
        'current server budget status is required for record-policy signing session',
      );
    default:
      return assertNever(status);
  }
}
```

Implementation rules:

- [x] Rename `consumeRecordPolicyLane` to
      `admitRecordPolicyLaneFromTrustedStatus` or an equivalent admission-focused
      name, then replace the optional-chain / `??` logic with an exhaustive
      `switch (status.status)`.
- [x] Add or reuse a typed fail-closed code for missing server status, such as
      `budget_status_required` or the existing Wallet Session budget-unavailable
      domain error.
- [x] Explicitly fail closed for `not_found`, `unavailable`, and
      `budget_unknown`. These branches must never read persisted record budget
      fields.
- [x] Validate `active` status before admission. `remainingUses` and
      `expiresAtMs` are optional in the public `SigningSessionStatus` shape, so
      malformed active status must fail closed instead of flowing into `NaN` or
      zero-coercion behavior.
- [x] Use `availableUsesForBudgetAdmission(status)` for admission and returned
      remaining-use projection. Do not admit against raw `remainingUses` when
      server-reported `availableUses` is lower.
- [x] Keep persisted `remainingUses` and `expiresAtMs` as UI/display hints only.
      They may appear in available-lane summaries, reconnect diagnostics, and
      persistence-boundary parsing, but not as the authority for successful
      signing admission.
- [x] Tighten budget-status auth handling in `budgetStatusReader.ts`: when the
      caller provides trusted auth and that auth is rejected, return that
      rejection. Do not retry with record-derived auth after a caller-provided
      auth rejection.
- [x] Restrict record-derived budget auth to unauthenticated status checks that
      explicitly request record derivation. The derived record must match the
      signing grant and target threshold session exactly.
- [x] Add shared payload parsers for wallet-iframe registration activation
      `READY` and `STARTED` messages. `READY` must reject malformed payloads
      instead of using `event.payload?.expiresAtMs ?? previousExpiresAtMs`.
- [x] Keep switch/case branch handling for domain unions where the branch value
      drives control flow. Avoid `if`/`else` cascades with nullable coercions in
      budget, restore, and activation-message state machines.

Inventory:

- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts`
  - `consumeRecordPolicyLane`
  - `resolveStatusAfterConsume`
  - `assertThresholdSigningSessionReady`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
  - `readTrustedWalletSigningBudgetStatus`
  - `resolveWalletSigningBudgetStatusAuth`
  - `candidates[0]` fallback
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
  - persisted record display hints
  - `claim?.remainingUses ?? args.record.remainingUses`
  - `claim?.expiresAtMs ?? args.record.expiresAtMs`
- `packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
  - persisted lane summaries and UI-only record policy display data
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
  - audit live-status checks that skip restore for runtime-ready lanes
- `packages/sdk-web/src/SeamsWeb/walletIframe/shared/messages.ts`
  - shared activation message payload parsers
- `packages/sdk-web/src/SeamsWeb/walletIframe/client/router.ts`
  - registration activation `READY` and `STARTED` handling
- `packages/sdk-web/src/SeamsWeb/walletIframe/host/handlers/near.ts`
  - registration activation payload construction and parser use in tests

Grep checklist:

```bash
rg -n "basisStatus\\?\\.remainingUses \\?\\?|basisStatus\\?\\.expiresAtMs \\?\\?|trustedBudgetStatus\\?\\.remainingUses \\?\\?|trustedBudgetStatus\\?\\.expiresAtMs \\?\\?" \
  packages/sdk-web/src/core/signingEngine/session/availability

rg -n "fallbackAuth|recordDerivedAuth|candidates\\[0\\] \\|\\| null" \
  packages/sdk-web/src/core/signingEngine/session/budget

rg -n "event\\.payload\\?\\.|PM_REGISTRATION_ACTIVATION_READY|PM_REGISTRATION_ACTIVATION_STARTED" \
  packages/sdk-web/src/SeamsWeb/walletIframe
```

Tests and guards:

- [x] Add a unit test proving `record_policy` consumption with
      `trustedBudgetStatus: null` fails closed and does not use persisted
      `record.remainingUses` or `record.expiresAtMs`.
- [x] Add a unit test proving `status: 'not_found'`, `status: 'expired'`, and
      `status: 'exhausted'` never return `ok: true`.
- [x] Add a unit test proving `status: 'unavailable'` and
      `status: 'budget_unknown'` never return `ok: true`.
- [x] Add malformed-active-status tests for missing `remainingUses`, missing
      `expiresAtMs`, and lower `availableUses`.
- [x] Add a unit test proving `status: 'active'` is the only branch that can
      return successful record-policy consumption, and only while unexpired with
      enough server-admissible uses from `availableUsesForBudgetAdmission`.
- [x] Add a guard rejecting the exact fallback patterns:
      `basisStatus?.remainingUses ??`, `basisStatus?.expiresAtMs ??`, and
      `candidates[0] || null` in signing-budget authority code. The guard must
      not reject `record.remainingUses` or `record.expiresAtMs` in display,
      diagnostics, restore discovery, or persistence parsing.
- [x] Add or update wallet-iframe activation tests for malformed `READY` payloads
      and malformed `STARTED` states.
- [x] Keep any persisted-record fallback tests only when the fallback is display,
      diagnostics, restore discovery, or request/persistence boundary parsing.

Done criteria:

- `record_policy` signing admission is impossible without current server budget
  status.
- Persisted budget fields are never used to produce successful signing
  admission.
- Budget-status auth resolution cannot silently swap from the caller-provided
  threshold session to an unrelated persisted lane.
- Wallet-iframe activation message handling uses shared parsers and rejects
  malformed payloads.

## Phase 10: Strict Fallback State Modeling

Phase 9 removes the known fail-open record-policy behavior. Phase 10 removes the
remaining fallback-shaped control flow from signing and budget readiness. The
goal is not just renaming. Each current fallback must become an explicit domain
state with a boundary parser, required fields, and exhaustive handling.

Phase boundary:

- Phase 9 fixes fail-open behavior directly: record-policy admission cannot
  succeed without server budget status, caller-provided budget auth cannot
  silently retry through another lane, and malformed activation messages are
  rejected.
- Phase 10 makes those fixes structurally hard to regress: caller intent,
  record-derived auth, runtime material readiness, budget admission, and pending
  material states become explicit unions with exhaustive handling.

Problem statement:

- A persisted Ed25519 or ECDSA material handle is a hint until the current
  runtime worker validates it for the current Wallet Session, signing grant,
  threshold session, signing root, runtime policy scope, SigningWorker id,
  verifier, and material binding digest.
- Budget status auth must not silently swap from caller-provided auth to a
  different persisted lane after a server rejection.
- ECDSA signing flow must not describe runtime-validated record-backed material
  as fallback material.
- Warm-session status readers must not duplicate raw material-field checks when a
  strict classifier already owns the state transition.

Implementation passes:

- [x] Budget auth resolution: model caller intent first, then resolution output.
- [x] ECDSA material plan: separate runtime material readiness from server-backed
      budget admission.
- [x] Ed25519 warm-status conversion: switch directly on the existing
      persisted-state classifier. Avoid a second parallel status model unless it
      removes real duplication.

Strict budget-auth modeling:

- [x] Add a strict budget-status auth request union. Record-derived auth must be
      reachable only from the explicit `derive_from_record` branch:

      ```ts
      type BudgetStatusAuthRequest =
        | {
            kind: 'use_provided_auth';
            auth: ThresholdScopedBudgetStatusAuth;
          }
        | {
            kind: 'derive_from_record';
            owner: WalletBudgetOwner;
            signingGrantId: SigningGrantId;
            targetThresholdSessionIds: NonEmptyReadonlyArray<ThresholdSessionId>;
            ecdsaLaneCheck:
              | EcdsaLaneBudgetStatusCheck
              | AuthenticatedEcdsaLaneBudgetStatusCheck
              | null;
          }
        | {
            kind: 'no_auth_available';
            reason: 'missing_auth' | 'missing_record' | 'binding_mismatch';
          };
      ```

- [x] Add a strict budget-status auth resolution union:

      ```ts
      type BudgetStatusAuthResolution =
        | {
            kind: 'provided_auth';
            auth: ThresholdScopedBudgetStatusAuth;
          }
        | {
            kind: 'record_derived_auth';
            auth: ThresholdScopedBudgetStatusAuth;
          }
        | {
            kind: 'unavailable';
            reason: 'missing_auth' | 'missing_record' | 'binding_mismatch';
          };
      ```

- [x] Update `readTrustedWalletSigningBudgetStatus` so it accepts a
      `BudgetStatusAuthRequest` or an equivalent strict input. The function must
      switch on caller intent before resolving auth.
- [x] Update `readTrustedWalletSigningBudgetStatus` so provided auth is used as
      the sole authority when present. If provided auth is rejected, return the
      rejection. Do not retry with record-derived auth after a provided-auth
      rejection.
- [x] Allow record-derived budget auth only when the caller explicitly chooses
      `derive_from_record`. Derivation must bind wallet id, signing grant id,
      target threshold session ids, and ECDSA chain target when applicable.
- [x] Parse target threshold session ids into a non-empty branded/list type
      before budget auth resolution. Empty lists must produce `unavailable` with
      `binding_mismatch` or a narrower exact reason instead of falling back to an
      account-level candidate.
- [x] Delete `material_fallback` naming in `SigningSessionCoordinator`. Replace
      it with `record_derived_auth` or remove the status-source field if it no
      longer drives behavior.
- [x] Add tests for:
      provided auth rejected by server does not retry with a persisted lane,
      record-derived auth succeeds only for the exact lane/session binding, and
      missing records produce `unavailable` rather than a nullable fallback.

ECDSA signing-material and budget-admission model:

- [x] Replace `fallbackReadySecp256k1Material`,
      `buildFallbackReadySecp256k1SigningMaterial`, and
      `fallbackThresholdEcdsaRecord` with an explicit signing-material plan:

      ```ts
      type EcdsaSigningMaterialPlan =
        | {
            kind: 'material_from_step_up';
            material: ReadySecp256k1SigningMaterial;
          }
        | {
            kind: 'material_from_runtime_validated_record';
            material: ReadySecp256k1SigningMaterial;
          }
        | {
            kind: 'reconnect_required';
            runtime: EvmFamilyThresholdEcdsaStepUpRuntime;
          }
        | {
            kind: 'unavailable';
            reason:
              | 'missing_record'
              | 'not_runtime_validated'
              | 'rp_id_mismatch'
              | 'chain_mismatch'
              | 'single_use_email_otp_consumed';
          };
      ```

- [x] Add a narrowed final-signer material union. Final signing code may accept
      only this type, so `reconnect_required` and `unavailable` cannot cross the
      orchestration boundary:

      ```ts
      type ReadyEcdsaSigningMaterialSource =
        | {
            kind: 'material_from_step_up';
            material: ReadySecp256k1SigningMaterial;
          }
        | {
            kind: 'material_from_runtime_validated_record';
            material: ReadySecp256k1SigningMaterial;
          };
      ```

- [x] Move record-to-ready-material conversion behind one boundary resolver,
      such as `resolveEcdsaSigningMaterialPlan(...)`. The resolver may build a
      `material_from_runtime_validated_record` branch only after
      `classifyRouterAbEcdsaHssPersistedSigningRecord(record).kind ===
      'runtime_validated'`.
- [x] Keep ECDSA material readiness separate from budget admission. A
      `material_from_runtime_validated_record` branch proves only worker-material
      readiness. Final signing also requires server-backed budget admission from
      Refactor 70 before the private SigningWorker call proceeds.
- [x] Stop treating persisted `remainingUses` and `expiresAtMs` as signing
      authority when building ready ECDSA signer sessions. They may populate
      display/session-policy hints, but budget gating must come from the
      server-backed admission path.
- [x] Update `signingFlow.ts` to switch on `EcdsaSigningMaterialPlan`. Final
      signing may consume only `ReadyEcdsaSigningMaterialSource` after the
      operation has server budget admission.
- [x] Make final signing function inputs require
      `ReadyEcdsaSigningMaterialSource` and `BudgetAdmitted` operation state.
      Orchestration code must narrow to those types before calling final
      signing.
- [x] Keep reconnect orchestration outside final signing. A `reconnect_required`
      branch may drive pre-signing auth/restore flow, then it must produce a new
      `material_from_step_up` or `material_from_runtime_validated_record`
      branch before signing.
- [x] Add focused tests and guards for branch handling, including valid public
      identity with non-runtime-validated worker material returning
      `not_runtime_validated`.

Ed25519 warm-status model:

- [x] Replace raw material checks in
      `warmCapabilities/statusReader.ts` with
      `classifyRouterAbEd25519PersistedSigningRecord(record)`.
- [x] Switch directly on `RouterAbEd25519PersistedSigningRecordState`.
      `runtime_validated` is the only branch that may produce an active, ready
      warm-session status. `restore_available`,
      `material_hint_unvalidated`, and `auth_ready_material_pending` must map to
      pending/not-ready status.
- [x] Add a local derived union only if the direct classifier switch would force
      duplicated branching in more than one active reader. If added, the derived
      union must wrap the exact classifier branch rather than use loose
      `reason: string` fields.
- [x] Preserve expired and exhausted reporting only when it is backed by a
      current server budget status or an explicitly non-signing display state.
      Persisted record budget fields remain display hints.
- [x] Add tests proving records with `ed25519WorkerMaterialHandle`,
      `ed25519WorkerMaterialBindingDigest`, and `clientVerifyingShareB64u` still
      classify as pending until the runtime validation marker is present.

Source guards:

- [x] Reject these fallback names in active signing and readiness code:
      `fallbackReadySecp256k1Material`,
      `buildFallbackReadySecp256k1SigningMaterial`,
      `fallbackThresholdEcdsaRecord`, and `material_fallback`.
- [x] Reject direct readiness checks for
      `record.ed25519WorkerMaterialHandle`,
      `record.ed25519WorkerMaterialBindingDigest`, and
      `record.clientVerifyingShareB64u` outside the persistence boundary,
      worker-material boundary, and strict classifier module.
- [x] Keep UI/display fallback names allowed only in UI rendering code, CSS
      loading code, transaction display rendering, and diagnostics. They must
      not influence signing, restore, budget, or lane readiness control flow.

Validation:

- [x] `pnpm -C packages/sdk-web type-check`
- [x] Focused unit tests for budget auth resolution, ECDSA material plan
      branches, and Ed25519 material status conversion.
- [x] Router A/B normal-signing SDK source guard.
- [x] Refactor 70 budget evidence harness remains green after the cleanup.

Done criteria:

- No active signing or readiness path contains fallback-shaped control flow for
  budget auth, ECDSA material, or Ed25519 worker material.
- Caller-provided budget auth is never replaced after server rejection.
- ECDSA record-backed signing material is explicitly modeled as
  `material_from_runtime_validated_record`.
- Ed25519 persisted material facts do not become ready status without runtime
  validation.
- All recovery paths have named lifecycle branches and exhaustive handling.

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
