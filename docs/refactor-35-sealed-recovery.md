# Refactor 35: Unified Sealed Session Recovery

Date created: 2026-05-08
Status: complete

## Purpose

Unify passkey and Email OTP sealed-session recovery under
`client/src/core/signingEngine/session`.

The current code has two recovery architectures:

- `session/warmCapabilities/*` owns the passkey-origin warm-session and PRF recovery
  path.
- `sessionEmailOtp/*` owns a separate Email OTP lifecycle coordinator that also
  performs Shamir3Pass sealing, sealed restore, companion-session attachment,
  export PRF recovery, and warm-session status coordination.

The target architecture deletes the external `sessionEmailOtp/` folder. Generic
sealed recovery lives under `session/sealedRecovery/*`; auth-method-specific
recovery lives under `session/passkey/*` and `session/emailOtp/*`.
The refactor also cleans up session folder names so storage, restore,
operation-state, and warm-capability responsibilities are visible from the
folder tree.

## Goals

1. Make sealed recovery one session-domain concept with method-specific
   implementations.
2. Remove the historical split where passkey recovery is embedded in
   `session/warmCapabilities/*` while Email OTP recovery is isolated in
   `sessionEmailOtp/*`.
3. Keep generic session domains auth-method-neutral:
   `identity`, `availability`, `planning`, `budget`, `persistence`,
   `sealedRecovery`, `operationState`, and `warmCapabilities`.
4. Keep `session/persistence/*` as the storage boundary.
5. Move restore orchestration into `session/sealedRecovery/restoreCoordinator.ts`.
6. Keep method-specific crypto recovery details in method folders.
7. Delete `client/src/core/signingEngine/sessionEmailOtp/` after its
   responsibilities move.
8. Preserve strict lifecycle state types. Generic sealed recovery should accept
   normalized sealed records and exact method-specific restore contexts, never
   raw strings or partial lifecycle objects.

## Target Structure

```text
client/src/core/signingEngine/session/
  SigningSessionCoordinator.ts

  sealedRecovery/
    README.md
    types.ts
    policy.ts
    exactRecordLookup.ts
    companionSessions.ts
    restoreCoordinator.ts
    readback.ts

  passkey/
    README.md
    sealedRecovery.ts
    prfClaim.ts
    ecdsaRecovery.ts
    ed25519Recovery.ts
    ports.ts

  emailOtp/
    README.md
    sealedRecovery.ts
    workerRequests.ts
    ecdsaRecovery.ts
    ed25519Recovery.ts
    companionSessions.ts
    provisioning.ts
    status.ts
    exportRecovery.ts
    ports.ts

  identity/
  availability/
  persistence/
  planning/
  budget/
  operationState/
  warmCapabilities/
```

End state:

```text
client/src/core/signingEngine/sessionEmailOtp/          deleted
client/src/core/signingEngine/session/restore/          deleted
client/src/core/signingEngine/session/signingSession/   renamed to session/operationState/
client/src/core/signingEngine/session/warmCapabilities/      renamed/refactored to session/warmCapabilities/
```

`session/persistence/*` remains the storage and normalized-record boundary.
`session/sealedRecovery/restoreCoordinator.ts` owns restore orchestration over
persisted records. `session/operationState/*` owns per-operation signing state:
lanes, prepared operations, transaction state, trace events, and post-sign
policy state. `session/warmCapabilities/*` owns only the generic warm-material
read model, readiness checks, transitions, cleanup, and public facade. Passkey
PRF claim handling, passkey rehydration, and method-specific provisioning move
to `session/passkey/*`; Email OTP equivalents move to `session/emailOtp/*`.
`session/SigningSessionCoordinator.ts` remains as the thin session facade that
signing flows import. It orchestrates planning, status/readiness, restore,
budget reservation/finalization, and warm-capability reads by delegating to the
child session domains. It does not own method-specific recovery, persistence
mechanics, budget queue internals, or warm-material implementation details.

## Call Graph

```mermaid
flowchart TD
  FLOW["flows/*"] --> COORD["session/SigningSessionCoordinator.ts"]
  COORD --> RECOVERY["session/sealedRecovery/*"]
  COORD --> WARM["session/warmCapabilities/*"]
  COORD --> BUDGET["session/budget/*"]
  COORD --> PLAN["session/planning/*"]
  COORD --> STATE["session/operationState/*"]
  RECOVERY --> PASSKEY["session/passkey/*"]
  RECOVERY --> EMAIL["session/emailOtp/*"]

  RECOVERY --> PERSIST["session/persistence/*"]
  RECOVERY --> IDENTITY["session/identity/*"]
  RECOVERY --> AVAIL["session/availability/*"]

  PASSKEY --> UI["uiConfirm warm-session ports"]
  EMAIL --> WORKERS["workerManager emailOtp worker"]
  EMAIL --> THRESHOLD["threshold/*"]
```

Generic recovery owns shared mechanics. Method folders own method-specific
proof material and worker/protocol details.

## Ownership Contract

| Folder | Owns | May import | Forbidden imports |
| --- | --- | --- | --- |
| `session/SigningSessionCoordinator.ts` | Thin session facade for flows: delegates planning, status/readiness, restore, budget reservation/finalization, and warm-capability reads to child session domains | `session/planning/*`, `session/availability/*`, `session/budget/*`, `session/sealedRecovery/*`, `session/warmCapabilities/*`, `session/operationState/*`, primitive interfaces/types | `flows/*`, `SigningEngine.ts`, method-specific recovery/provisioning implementation, persistence record normalization/write internals |
| `session/sealedRecovery/*` | Exact sealed-record recovery mechanics, generic restore policies, readback verification, companion-session coordination contracts | `session/persistence/*`, `session/identity/*`, `session/availability/*`, `interfaces/*`, primitive SDK/shared types | `flows/*`, `SigningEngine.ts`, `assembly/*`, `stepUpConfirmation/*`, concrete method folders |
| `session/passkey/*` | Passkey PRF claim, passkey-origin sealed recovery, passkey ECDSA/Ed25519 rehydration adapters | `session/sealedRecovery/*`, `session/persistence/*`, `session/warmCapabilities/*`, `uiConfirm` warm-session ports, `threshold/*`, `interfaces/*` | `flows/*`, `SigningEngine.ts`, `assembly/*`, `stepUpConfirmation/*`, `session/emailOtp/*` |
| `session/emailOtp/*` | Email OTP sealed recovery, Email OTP worker restore/seal requests, Email OTP provisioning/status/export recovery currently in `sessionEmailOtp/*` | `session/sealedRecovery/*`, `session/persistence/*`, `threshold/*`, `workerManager/*`, `interfaces/*`, `uiConfirm` status ports | `flows/*`, `SigningEngine.ts`, `assembly/*`, `stepUpConfirmation/*`, `session/passkey/*` |
| `session/persistence/*` | Sealed store and normalized persistence records | Primitive types and validation helpers | Method-specific lifecycle logic |
| `session/operationState/*` | Per-operation signing state: lanes, prepared operation state, transaction state, trace events, post-sign policy state | `session/identity/*`, `session/planning/*`, `session/budget/*`, primitive chain/signing types | `flows/*`, `SigningEngine.ts`, `assembly/*`, method recovery folders |
| `session/warmCapabilities/*` | Generic warm-material read model, readiness/status readers, transitions, cleanup, public facade | `session/operationState/*`, `session/persistence/*`, primitive session interfaces, narrow injected ports | `flows/*`, `SigningEngine.ts`, `assembly/*`, `stepUpConfirmation/*`, UI prompt construction, method-specific recovery/provisioning implementation |

## Canonical Data Shapes

Generic sealed recovery should use explicit discriminated states.

```ts
type SealedRecoveryMethod = 'passkey' | 'email_otp';

type SealedRecoveryCurve = 'ecdsa' | 'ed25519';

type SealedRecoveryRecord =
  | {
      method: 'passkey';
      curve: SealedRecoveryCurve;
      sealedRecord: SigningSessionSealedStoreRecord;
      restoreContext: PasskeySealedRecoveryContext;
    }
  | {
      method: 'email_otp';
      curve: SealedRecoveryCurve;
      sealedRecord: SigningSessionSealedStoreRecord;
      restoreContext: EmailOtpSealedRecoveryContext;
    };
```

Method-specific recovery should return monotonic states:

```ts
type SealedRecoveryResult =
  | {
      kind: 'ecdsa_recovered';
      method: SealedRecoveryMethod;
      recovered: RecoveredEcdsaSigningSession;
      companion?: RecoveredEd25519SigningSession;
    }
  | {
      kind: 'ed25519_recovered';
      method: SealedRecoveryMethod;
      recovered: RecoveredEd25519SigningSession;
    };
```

Avoid optional lifecycle fields in recovery inputs. If a restore branch requires
`thresholdSessionId`, `walletSigningSessionId`, `chainTarget`,
`shamirPrimeB64u`, `thresholdSessionAuthToken`, or `participantIds`, the branch
type should require those fields.

## What Moves

From `sessionEmailOtp/EmailOtpThresholdSessionCoordinator.ts`:

- Email OTP sealed ECDSA seal persistence moves to
  `session/emailOtp/sealedRecovery.ts` or `session/emailOtp/ecdsaRecovery.ts`.
- Email OTP sealed ECDSA rehydrate logic moves to
  `session/emailOtp/ecdsaRecovery.ts`.
- Email OTP Ed25519 companion attachment moves to
  `session/emailOtp/companionSessions.ts`, using generic companion contracts
  from `session/sealedRecovery/companionSessions.ts`.
- Email OTP Ed25519 export PRF recovery moves to
  `session/emailOtp/exportRecovery.ts`.
- Email OTP status/readiness helpers move to `session/emailOtp/status.ts`.
- Email OTP provisioning and registration helpers move to
  `session/emailOtp/provisioning.ts`.

From `session/warmCapabilities/*`:

- Passkey PRF claim logic moves to `session/passkey/prfClaim.ts`.
- Passkey sealed recovery and rehydration adapters move to
  `session/passkey/sealedRecovery.ts`, `session/passkey/ecdsaRecovery.ts`, and
  `session/passkey/ed25519Recovery.ts`.
- Generic warm-session read model, readiness/status readers, transitions,
  cleanup, and public facade move to `session/warmCapabilities/*`.
- Method-specific provisioning moves to `session/passkey/*` or
  `session/emailOtp/*`; `session/warmCapabilities/*` receives method entrypoints
  through narrow typed ports.

From `session/restore/*`:

- Restore orchestration moves to
  `session/sealedRecovery/restoreCoordinator.ts`.
- Restore input/output lifecycle types move to `session/sealedRecovery/types.ts`
  when they describe sealed recovery requests or results.
- `session/restore/*` is deleted after callers import from
  `session/sealedRecovery/*`.

From `session/signingSession/*`:

- Per-operation lane, prepared-operation, transaction-state, trace, and
  post-sign policy files move to `session/operationState/*`.
- Imports are updated directly to `session/operationState/*`.
- No compatibility re-export path is kept.

From `session/persistence/*`:

- Sealed-store read/write primitives remain in `session/persistence/*`.
- Generic exact-record lookup helpers that combine persistence access with
  recovery policy move to `session/sealedRecovery/exactRecordLookup.ts`.

## `warmCapabilities` Refactor

`session/warmCapabilities/*` should become a small read/status facade over warm
material and threshold-session capability records. It should expose normalized
capability state to operation flows and method folders, while method folders own
the work needed to create or restore that state.

Target contents:

```text
session/warmCapabilities/
  README.md
  types.ts
  store.ts
  readModel.ts
  capabilityReader.ts
  capabilityReaderCore.ts
  statusReader.ts
  thresholdSigningSessionReadiness.ts
  ecdsaCapabilityReadiness.ts
  materialCache.ts
  transitions.ts
  cleanup.ts
  public.ts
```

Files that should move out:

- `prfCache.ts` becomes `warmCapabilities/materialCache.ts` if it only writes,
  clears, or claims generic warm material through a narrow port.
- `runtime.ts` splits:
  - generic claim/read error handling moves to `warmCapabilities/materialCache.ts`
    or `warmCapabilities/claim.ts`;
  - ECDSA seal persistence moves to `session/sealedRecovery/*` or
    `session/passkey/ecdsaRecovery.ts`, depending on whether the logic is
    method-neutral.
- `ecdsaBootstrap*.ts`, `ecdsaProvisioner.ts`,
  `ecdsaSessionProvision.ts`, `ecdsaWarmCapabilityBootstrap.ts`, and
  `ecdsaLoginPrefill.ts` move to `session/passkey/*` when they depend on
  passkey/WebAuthn PRF material or passkey-origin provisioning.
- `ed25519Provisioner.ts` and `ed25519SessionProvision.ts` move to
  `session/passkey/*`.
- `persistence.ts` should be split. Pure record normalization/write helpers move
  to `session/persistence/*`; method-specific write policy stays with
  `session/passkey/*` or `session/emailOtp/*`.
- `postSignPolicyAdapter.ts` should move to `session/operationState/*` if it
  adapts operation policy state, or stay in `warmCapabilities/*` only if it
  reads warm capability state without mutating operation state.

Import rule:

- `warmCapabilities/*` may depend on persistence records and primitive session
  types.
- `warmCapabilities/*` receives material-store access and method operations as
  typed ports.
- `warmCapabilities/*` does not construct passkey prompts, call Email OTP
  workers, perform threshold activation, or perform method-specific sealed
  recovery.

## Phased Todo List

### Phase 0: Inventory Exact Recovery Paths

- [x] List every `sessionEmailOtp/*` method that seals, reads, rehydrates, or
      attaches sealed recovery material.
- [x] List every `session/warmCapabilities/*` method that claims PRF material,
      persists seals, reconnects, or rehydrates passkey-origin sessions.
- [x] Identify which code is generic recovery mechanics and which code is
      method-specific passkey or Email OTP behavior.
- [x] List all current callers of `EmailOtpThresholdSessionCoordinator`.

Exit criteria:

- [x] Inventory maps each function to one target owner.
- [x] No implementation changes in this phase.

This inventory was completed retrospectively during the folder moves and owner
extraction work. It no longer represents pending execution work.

### Phase 1: Add Generic Sealed Recovery Contracts

- [x] Create `session/sealedRecovery/README.md`.
- [x] Create `session/sealedRecovery/types.ts` with strict recovery request and
      result unions.
- [x] Create generic helper for exact sealed-record lookup in
      `session/sealedRecovery/exactRecordLookup.ts`.
- [x] Create generic helper for companion session contracts in
      `session/sealedRecovery/companionSessions.ts`.
- [x] Create generic helper for readback verification in
      `session/sealedRecovery/readback.ts`.
- [x] Keep restore in-flight coordination in
      `session/sealedRecovery/restoreCoordinator.ts`.
- [x] Create generic helper for policy checks in
      `session/sealedRecovery/policy.ts`.
- [x] Add guard tests that prevent `session/sealedRecovery/*` from importing
      method folders, `flows/*`, `assembly/*`, or `SigningEngine.ts`.

Exit criteria:

- [x] Generic sealed recovery compiles without moving existing recovery paths.
- [x] No compatibility barrels are introduced.

### Phase 2: Move Passkey Recovery Behind `session/passkey/*`

- [x] Create `session/passkey/README.md`.
- [x] Move PRF claim helpers from `session/warmCapabilities/*` to
      `session/passkey/prfClaim.ts`.
- [x] Move passkey ECDSA sealed recovery/reconnect adapters to
      `session/passkey/ecdsaRecovery.ts`.
- [x] Move passkey Ed25519 sealed recovery adapters to
      `session/passkey/ed25519Recovery.ts`.
- [x] Keep `session/warmCapabilities/*` as a facade only where callers still need
      the warm-session read model.

Exit criteria:

- [x] Passkey-specific Shamir3Pass rehydration code is owned by
      `session/passkey/*`.
- [x] `session/warmCapabilities/*` no longer owns passkey-specific recovery logic.

### Phase 3: Move Email OTP Recovery Behind `session/emailOtp/*`

- [x] Create `session/emailOtp/README.md`.
- [x] Move Email OTP worker seal/rehydrate request construction to
      `session/emailOtp/workerRequests.ts`.
- [x] Move ECDSA Email OTP sealed recovery into
      `session/emailOtp/ecdsaRecovery.ts`.
- [x] Move Ed25519 Email OTP sealed recovery into
      `session/emailOtp/ed25519Recovery.ts`.
- [x] Move Email OTP companion session handling into
      `session/emailOtp/companionSessions.ts`.
- [x] Reuse generic recovery contracts from `session/sealedRecovery/*`.

Exit criteria:

- [x] Email OTP sealed recovery no longer lives in
      `sessionEmailOtp/EmailOtpThresholdSessionCoordinator.ts`.
- [x] Email OTP recovery uses the same generic sealed recovery orchestration
      boundary as passkey recovery, while reusing additional shared
      `session/sealedRecovery/*` helpers for policy, readback, and companion
      session handling.

### Phase 4: Move Remaining Email OTP Session Lifecycle

- [x] Move Email OTP session provisioning to `session/emailOtp/provisioning.ts`.
- [x] Move Email OTP warm-session status coordination to
      `session/emailOtp/status.ts`.
- [x] Move Email OTP export PRF recovery to `session/emailOtp/exportRecovery.ts`.
- [x] Move Email OTP app-session JWT caching to
      `session/emailOtp/appSessionJwtCache.ts`.
- [x] Move Email OTP route-plan helpers to `session/emailOtp/routePlan.ts`.
- [x] Replace direct `EmailOtpThresholdSessionCoordinator` construction with
      explicit `session/emailOtp/*` entrypoints.
- [x] Keep step-up prompt and auth-plan construction under
      `stepUpConfirmation/otpPrompt/*`.

Exit criteria:

- [x] `session/emailOtp/*` owns Email OTP session lifecycle.
- [x] `stepUpConfirmation/*` owns prompts and auth-plan orchestration only.
- [x] Operation flows import Email OTP session lifecycle through documented
      session entrypoints.

### Phase 5: Delete `sessionEmailOtp/`

- [x] Delete `client/src/core/signingEngine/sessionEmailOtp/`.
- [x] Update assembly ports and runtime construction to use
      `session/emailOtp/*`.
- [x] Update all imports from `sessionEmailOtp/*`.
- [x] Add deleted-path guard coverage for `sessionEmailOtp/`.
- [x] Update `client/src/core/signingEngine/README.md`,
      `session/README.md`, `docs/refactor-33.md`, and
      `docs/stepup-adaptor.md`.

Exit criteria:

- [x] `rg "sessionEmailOtp" client/src tests docs` returns only historical
      notes in completed plans or no results, depending on docs policy.
- [x] No compatibility re-export path exists.

### Phase 6: Tighten Recovery Types And Guards

- [x] Replace recovery inputs with method-specific required state branches.
- [x] Delete duplicate Email OTP/passkey recovery helper shapes.
- [x] Add guard tests:
      `session/passkey/*` cannot import `session/emailOtp/*`;
      `session/emailOtp/*` cannot import `session/passkey/*`;
      `session/sealedRecovery/*` cannot import either method folder.
- [x] Add tests that cover:
      passkey ECDSA recovery,
      Email OTP ECDSA recovery,
      Email OTP Ed25519 companion recovery,
      expired/exhausted sealed record rejection,
      mismatched wallet signing-session rejection.

Exit criteria:

- [x] `pnpm exec tsc -p client/tsconfig.json --noEmit --pretty false` passes.
- [x] Focused sealed recovery unit tests pass.
- [x] `pnpm build:sdk` passes.

### Phase 7: Thin Coordinator Phase

- [x] Keep `session/SigningSessionCoordinator.ts` as the only session
      coordinator imported by signing flows.
- [x] Limit the coordinator to orchestration and delegation:
      planning, status/readiness, restore, budget reservation/finalization,
      and warm-capability reads.
- [x] Move budget reservation state, projection checks, and queue ownership into
      `session/budget/*`.
- [x] Move restore cache and in-flight restore coordination into
      `session/sealedRecovery/restoreCoordinator.ts`.
- [x] Move operation-id binding state into `session/planning/*`.
- [x] Keep method-specific recovery/provisioning out of the coordinator.
- [x] Add guard tests so child session domains do not import
      `session/SigningSessionCoordinator.ts`.

Exit criteria:

- [x] Signing flows import only `session/SigningSessionCoordinator.ts` for
      session orchestration and do not sequence child session domains directly.
- [x] `session/SigningSessionCoordinator.ts` is a thin facade with no
      method-specific recovery/provisioning implementation.
- [x] Child session domains do not import `session/SigningSessionCoordinator.ts`.
- [x] No compatibility re-export path exists.
- [x] `pnpm exec tsc -p client/tsconfig.json --noEmit --pretty false` passes.
- [x] `pnpm build:sdk` passes.

### Phase 8: Rename Session Operation And Warm Capability Domains

- [x] Rename `session/signingSession/` to `session/operationState/`.
- [x] Update all imports from `session/signingSession/*` to
      `session/operationState/*`.
- [x] Rename `session/warmSigning/` to `session/warmCapabilities/`.
- [x] Move only generic warm-capability files into `session/warmCapabilities/*`:
      read model, capability readers, status/readiness readers, transitions,
      cleanup, public facade, runtime claim facade, and store types.
- [x] Move passkey-specific PRF, sealed recovery, and provisioning files into
      `session/passkey/*`.
      Started with `prfCache.ts`, `runtime.ts`, `ecdsaProvisioner.ts`,
      `ed25519Provisioner.ts`, `ecdsaBootstrap.ts`,
      `ecdsaWarmCapabilityBootstrap.ts`, `ecdsaSessionProvision.ts`,
      `ed25519SessionProvision.ts`, `ecdsaBootstrapRequest.ts`, and `public.ts`.
- [x] Move Email OTP-specific warm-session status/provisioning files into
      `session/emailOtp/*`.
      Started with `ecdsaBootstrapCommit.ts`, `ed25519LocalMetadata.ts`,
      `workerRequests.ts`, `status.ts`, `provisioning.ts`,
      `exportRecovery.ts`, and Email OTP ECDSA signing-share claim handling
      used by warm prefill.
- [x] Keep `session/persistence/*` unchanged as the storage and normalized-record
      boundary.
- [x] Add deleted-path guard coverage for `session/signingSession/*` and
      `session/warmSigning/*`.

Exit criteria:

- [x] `rg "session/signingSession/|session/warmSigning/" client/src tests/unit`
      returns only deleted-path guard coverage.
- [x] `session/operationState/*` contains operation-state files only.
- [x] `session/warmCapabilities/*` contains the generic warm-capability facade
      and no method-specific recovery/provisioning implementation.
- [x] Warm-session post-sign policy adaptation moved to
      `session/operationState/warmSessionPolicyAdapter.ts`.
- [x] `session/warmCapabilities/clearWarmSigningSessions.ts` no longer imports
      `session/passkey/prfCache` directly; passkey cleanup is injected by
      assembly.
- [x] No compatibility re-export path exists.
- [x] `pnpm exec tsc -p client/tsconfig.json --noEmit --pretty false` passes.
- [x] `pnpm build:sdk` passes.

### Phase 9: Fold Restore Into Sealed Recovery

- [x] Move `session/restore/restoreCoordinator.ts` to
      `session/sealedRecovery/restoreCoordinator.ts`.
- [x] Move restore request/result types into `session/sealedRecovery/types.ts`
      when they are shared by passkey and Email OTP recovery.
- [x] Update all imports from `session/restore/*` to
      `session/sealedRecovery/*`.
- [x] Delete `session/restore/`.
- [x] Add deleted-path guard coverage for `session/restore/*`.

Exit criteria:

- [x] `rg "session/restore" client/src tests` returns only deleted-path guard
      coverage or non-import text, with no production or test imports.
- [x] Restore orchestration imports `session/persistence/*` for storage access
      and method folders only through narrow typed ports.
- [x] `session/persistence/*` remains in place and does not import restore,
      sealed recovery orchestration, or method folders.
- [x] No compatibility re-export path exists.
- [x] `pnpm exec tsc -p client/tsconfig.json --noEmit --pretty false` passes.
- [x] `pnpm build:sdk` passes.

## Success Metrics

- `sessionEmailOtp/` is deleted.
- Passkey and Email OTP sealed recovery both pass through
  `session/sealedRecovery/*` contracts.
- Method-specific recovery lives in `session/passkey/*` and
  `session/emailOtp/*`.
- Generic session folders remain auth-method-neutral.
- `session/persistence/*` remains the storage boundary.
- Restore orchestration lives in `session/sealedRecovery/restoreCoordinator.ts`.
- Per-operation signing state lives in `session/operationState/*`.
- Generic warm-material readiness and facade code lives in
  `session/warmCapabilities/*`.
- `session/SigningSessionCoordinator.ts` remains as the thin facade imported by
  signing flows.
- No duplicate sealed-recovery structs remain between passkey and Email OTP.
- No broad internal barrels are added.

## Risks

- `EmailOtpThresholdSessionCoordinator.ts` currently owns multiple concerns.
  Splitting sealed recovery first reduces the blast radius.
- ECDSA and Ed25519 companion restore identity checks are fragile. Move them
  with focused tests before deleting old paths.
- Worker request payloads are method-specific. Keep them in method folders and
  pass normalized recovery results back to generic session code.
- Persistence schema changes are excluded from the first implementation pass.
  The plan should reuse existing sealed-store records until the recovery shape
  is stable.
