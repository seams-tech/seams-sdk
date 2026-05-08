# Refactor 33 State Mapping

This note defines which existing lifecycle shapes may survive temporarily while
the first vertical slice moves. These shapes are compatibility inputs only; they
must not become operation identities in the target folders.

## Canonical Target Shapes

- `SelectedEd25519Lane`: complete NEAR Ed25519 signing identity.
- `SelectedEcdsaLane`: complete EVM/Tempo ECDSA signing identity.
- `PreparedOperation`: selected lane plus operation intent, readiness, auth
  plan, and availability generation.
- `BudgetAdmittedOperation`: prepared operation plus budget admission.
- `SignedOperation`: budget-admitted operation plus signed result.

## Temporary Raw Or Candidate Shapes

These may appear only at raw/candidate boundaries during the first slice:

- `SigningLaneContext`
- `EcdsaLaneIdentity`
- `ThresholdEcdsaRuntimeLane`
- `ThresholdEcdsaSessionLane`
- `ThresholdEd25519SessionLane`
- `NearEd25519TransactionLane`
- `EvmFamilyEcdsaTransactionLane`
- available signing lane candidates
- raw threshold session records

## Boundary-Owned Raw Shapes

Raw persistence and worker response structs stay in boundary modules until their
owning folders move:

- threshold persistence records stay in `api/thresholdLifecycle/*` until
  `session/persistence/records.ts` owns them.
- sealed-session persistence records stay in `session/persistence/sealedSessionStore.ts`
  until `session/sealedStore.ts` owns them.
- available signing lane candidate records stay in
  `session/availability/availableSigningLanes.ts`.
- worker request and response message structs stay in `workerManager/*` until
  `workers/*` owns them.
- relayer protocol response structs stay in `threshold/workflows/*` until
  `threshold/ed25519/*` and `threshold/ecdsa/*` own them.

## Rules

1. New operation modules must accept canonical selected lane or operation state.
2. Existing broad shapes may enter only through explicit raw/candidate
   conversion points.
3. Do not add converters between two target internal shapes. Delete one shape
   instead.
4. Do not add optional identity, auth, restore, budget, signing, or export
   fields to canonical operation state.
