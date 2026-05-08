# session

## Owns

Signing-session identity, record normalization, lane selection, readiness,
planning, budget, restore, sealed persistence, and warm-session state.

## May Import

`workers/*` only from explicit worker/status boundaries, plus shared primitive
types.

## Must Not Import

`SigningEngine.ts`, `assembly/*`, `flows/*`, `stepUpConfirmation/*`, `chains/*`, or
chain operation modules.

## Entrypoints

`public.ts` owns the generic session-facing facade methods for account-wide
restore, available-lane reads, and ECDSA session-record admin methods.

Current child owners are explicit folders:
`identity/*`, `availability/*`, `planning/*`, `budget/*`, `persistence/*`,
`restore/*`, `signingSession/*`, and `warmSigning/*`.

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
- Signing operation state: `signingSession/types.ts`,
  `signingSession/preparedOperation.ts`, `signingSession/postSignPolicy.ts`,
  `signingSession/transactionState.ts`, and `signingSession/trace.ts`.
- Restore and persistence: `restore/restoreCoordinator.ts`,
  `persistence/sealedSessionStore.ts`, `persistence/records.ts`, and
  persistence-specific normalization.
- Warm signing: `warmSigning/*` for warm-session material, sealed-refresh
  parity, provisioning, runtime reads, status reads, capability state, and
  the warm-session public facade in `warmSigning/public.ts`.

Selected-lane construction belongs to `identity/selectLane.ts` and
`identity/laneIdentity.ts`.
Persistence record normalization belongs to `persistence/records.ts` and
`persistence/sealedSessionStore.ts`.
