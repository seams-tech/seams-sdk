# session

## Owns

Signing-session identity, record normalization, lane selection, readiness,
planning, budget, sealed recovery, sealed persistence, and warm-session state.

## May Import

`workers/*` only from explicit worker/status boundaries, plus shared primitive
types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `stepUpConfirmation/*`, `chains/*`, or
chain operation modules.

## Entrypoints

`public.ts` owns the generic session-facing facade methods for mixed wallet /
NEAR restore, available-lane reads, and ECDSA session-record admin methods.

Current child owners are explicit folders:
`identity/*`, `availability/*`, `planning/*`, `budget/*`, `persistence/*`,
`sealedRecovery/*`, `operationState/*`, `warmCapabilities/*`, `passkey/*`, and
`emailOtp/*`.

## Child Domains

- Identity: `identity/laneIdentity.ts` and `identity/selectLane.ts` for
  selected-lane identity types, lane candidates, and canonical selected-lane
  construction.
- Availability: `availability/availableSigningLanes.ts`,
  `availability/persistedAvailableSigningLanes.ts`, and
  `availability/readiness.ts`.
- Planning: `planning/planner.ts`, `planning/operationFingerprint.ts`, and
  `planning/operationIdBinding.ts`.
- Budget: `budget/budget.ts`, `budget/budgetProjection.ts`,
  `budget/budgetFinalizer.ts`, and `budget/budgetStatusReader.ts`.
- Signing operation state: `operationState/types.ts`,
  `operationState/preparedOperation.ts`, `operationState/postSignPolicy.ts`,
  `operationState/transactionState.ts`, and `operationState/trace.ts`.
- Sealed recovery and persistence: `sealedRecovery/restoreCoordinator.ts`,
  `sealedRecovery/types.ts`, `sealedRecovery/exactRecordLookup.ts`,
  `sealedRecovery/readback.ts`,
  `persistence/sealedSessionStore.ts`, `persistence/records.ts`, and
  persistence-specific normalization.
- `sealedRecovery/*` owns only restore-boundary work:
  raw/current readback normalization into `SealedRecoveryRecord`,
  purpose-aware lookup/matching,
  restore orchestration,
  rejected-record reporting,
  and generic readback verification.
- `sealedRecovery/*` must not accept `SigningSessionSealedStoreRecord` or
  `BuildCurrentSealedSessionRecordBaseInput` except at the explicit raw
  normalization boundary.
- Method folders consume the same sealed-recovery orchestration boundary:
  passkey reconnect/restore-before-claim goes through
  `sealedRecovery/restoreCoordinator.ts`, while Email OTP reuses
  `sealedRecovery/readback.ts` and owns its companion-session persisted write
  assembly in `emailOtp/companionSessions.ts`.
- Warm capabilities: `warmCapabilities/*` for warm-session material,
  sealed-refresh parity, provisioning, runtime reads, status reads, capability
  state, and the warm-session public facade in `warmCapabilities/public.ts`.
- Passkey method helpers: `passkey/prfCache.ts`, `passkey/runtime.ts`,
  `passkey/ecdsaProvisioner.ts`, `passkey/ed25519Provisioner.ts`,
  `passkey/ecdsaBootstrap.ts`, `passkey/ecdsaWarmCapabilityBootstrap.ts`,
  `passkey/ecdsaSessionProvision.ts`, `passkey/ed25519SessionProvision.ts`,
  `passkey/ecdsaRecovery.ts`, and `passkey/ed25519Recovery.ts`.
- Email OTP method helpers: `emailOtp/EmailOtpThresholdSessionCoordinator.ts`,
  `emailOtp/companionSessions.ts`,
  `emailOtp/ecdsaRecovery.ts`, `emailOtp/ed25519Recovery.ts`,
  `emailOtp/ecdsaBootstrapCommit.ts`, `emailOtp/ed25519LocalMetadata.ts`,
  `emailOtp/exportRecovery.ts`, `emailOtp/provisioning.ts`,
  `emailOtp/status.ts`, and `emailOtp/workerRequests.ts`.

## Final ECDSA Path

- `SigningEngine.ts` owns the public/bootstrap boundary and wires strict ECDSA
  activation requests into warm-session services.
- `flows/signEvmFamily/*` owns operation selection, step-up authorization, and
  ECDSA provision-plan construction.
- `stepUpConfirmation/*` owns passkey and Email OTP confirmation payloads only.
- `passkey/ecdsaWarmCapabilityBootstrap.ts` owns the public
  `EcdsaBootstrapRequest` boundary and converts it into canonical bootstrap
  activation requests.
- `passkey/ecdsaProvisioner.ts` owns plan-driven warm-session reuse and strict
  reconnect or fresh activation branches. It must not accept raw bootstrap
  request shapes as lifecycle input.
- `passkey/ecdsaSessionProvision.ts` and `threshold/ecdsa/activation.ts` own
  the actual threshold-session activation and seal persistence boundary.

Selected-lane construction belongs to `identity/selectLane.ts` and
`identity/laneIdentity.ts`.
Persistence record normalization belongs to `persistence/records.ts` and
`persistence/sealedSessionStore.ts`.
