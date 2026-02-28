# Nonce Lane Recovery Runbook

Last updated: 2026-02-28

## Goal

Provide deterministic recovery steps for EVM-family nonce lanes when lifecycle resolution is ambiguous.

## Trigger Signals

Treat the lane as degraded when any of these are observed:

1. signer error code `nonce_lane_blocked`,
2. repeated `nonce_conflict_retryable` on the same lane after reconcile,
3. reconcile result with `blocked: true`,
4. lifecycle metrics showing persistent `reconciled` + `lane_blocked` for the same lane.

Lane identity is:

1. `chain`,
2. `networkKey`,
3. `chainId`,
4. `sender`,
5. optional `nonceKey` (Tempo lanes).

## Recovery Procedure

### 1) Reconcile lane state

1. Call `reconcileNonceLane(...)` using the same `signedResult.managedNonce` lane context.
2. If `blocked: false`, resume normal signing flow.
3. If `blocked: true`, continue to step 2.

### 2) Classify stuck nonce

Use available broadcast and chain evidence:

1. known replacement tx at same nonce -> treat as `replaced`,
2. tx never propagated / evicted from mempool -> treat as `dropped`,
3. receipt eventually appears for tracked hash -> treat as `finalized`.

### 3) Apply lifecycle transition

1. For dropped tx:
   1. call `reportDroppedOrReplaced(... reason: 'dropped')`,
   2. call `reconcileNonceLane(...)`,
   3. retry signing (same nonce should become reusable).
2. For replaced tx:
   1. call `reportDroppedOrReplaced(... reason: 'replaced')` with replacement hash when known,
   2. continue finalization tracking on replacement hash.
3. For finalized tx:
   1. call `reportFinalized(...)`,
   2. resume signing on next nonce.

### 4) Escalate if still blocked

If lane remains blocked after explicit dropped/replaced/finalized transition:

1. stop automatic retries for that lane,
2. surface typed guidance to user (`nonce_lane_blocked`),
3. capture lane details + recent lifecycle metrics for investigation.

## UX Contract

When blocked:

1. do not keep spinner-only “waiting for finalization” forever,
2. show explicit recoverable error state,
3. offer deterministic retry action after reconcile/transition calls.

## Telemetry Checks

Track these for every incident:

1. lane tags (`chain`, `networkKey`, `chainId`, `sender`, `nonceKey?`),
2. lifecycle sequence (`broadcast_accepted`, `broadcast_rejected`, `finalized`, `dropped|replaced`, `reconciled`, `lane_blocked`),
3. time from first `broadcast_accepted` to resolution.

## Exit Criteria

Incident is closed when:

1. reconcile returns `blocked: false`,
2. next signing attempt succeeds without nonce conflict,
3. lifecycle metrics show terminal resolution (`finalized` or explicit `dropped|replaced`) for the affected nonce.
