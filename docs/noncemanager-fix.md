# Nonce Manager + Finalization Fix Plan

Last updated: 2026-02-28

## Goal

Fix stuck Tempo/EVM finalization by correcting nonce lifecycle semantics in core signing code.

This plan intentionally avoids UI-level timeout hacks as the primary solution.

## Problem Summary

Original buggy behavior treated successful `eth_sendRawTransaction` as enough to permanently advance local nonce state (`reportBroadcastResult(... status: 'success')` -> nonce commit).  
That assumption is wrong on real networks where a tx can be:

1. accepted by one RPC node but never propagated,
2. replaced,
3. dropped from mempool,
4. delayed in indexing/receipt availability.

When that happens, local nonce moves forward while chain nonce may not.  
The next signed tx can then be queued behind a missing nonce, which looks like "waiting for finalization forever" from the app perspective.

## Why Tempo Surfaces It More

The bug is chain-agnostic, but Tempo hits it more often because the current app flow stresses:

1. frequent sequential sends on the same signer lane,
2. hash-based confirmation assumptions,
3. aggressive optimistic nonce advance immediately after broadcast.

ARC is more forgiving in observed usage; Tempo exposes the same architecture flaw.

## Root Cause (Code)

Primary mismatch:

1. Nonce state transition was `reserved -> committed` at broadcast acceptance.
2. It should be `reserved -> in_flight -> finalized|replaced|dropped`.

Relevant files:

1. `client/src/core/signingEngine/api/evmSigning.ts`
2. `client/src/core/rpcClients/evm/nonceManager.ts`
3. `examples/tatchi-site/src/flows/demo/demoEvmHelpers.ts` (current hash-based confirmation logic in demo app)

## Design Principles for the Fix

1. Nonce ownership must live in core (`signingEngine` + nonce manager), not in demo/UI hooks.
2. Broadcast acceptance is not finalization.
3. Finalization must be modeled per lane: `(chain, networkKey, chainId, sender, nonceKey?)`.
4. All lane transitions must be explicit and auditable.
5. State-based observations (`greeting`, `userTokens`) are diagnostics only and never proof of tx finalization.
6. No duplicate legacy APIs once new lifecycle API lands.

## Proposed Architecture

### 1) Nonce Lane State Machine

Introduce explicit lane state in nonce manager:

1. `reserved` (nonce allocated for signing, not yet broadcast)
2. `in_flight` (broadcast accepted, awaiting chain resolution)
3. `finalized` (receipt success/revert finalized)
4. `replaced` (same nonce replaced by newer tx)
5. `dropped` (expired / evicted / never included)
6. `failed_pre_broadcast` (send failed before acceptance)

### 2) API Contract Changes (Breaking, clean)

Replace ambiguous `reportBroadcastResult(status: 'success' | 'failure')` semantics with lifecycle-first APIs:

1. `reportBroadcastAccepted(reservation, txHash)`
2. `reportBroadcastRejected(reservation, error)`
3. `reportFinalized(txHash, receiptStatus)`
4. `reportDroppedOrReplaced(nonceLane, nonce, reason)`
5. `reconcileLane(nonceLane)` (chain-driven reconciliation fallback)

Remove old success/failure broadcast API after migration.

### 3) Reconciliation Logic

`reconcileLane` should use chain data to resolve drift:

1. pending nonce (`eth_getTransactionCount(..., 'pending')`)
2. latest nonce (`eth_getTransactionCount(..., 'latest')`)
3. tracked in-flight tx hashes for unresolved nonces

Rules:

1. If chain pending advanced past nonce `n`, mark `n` resolved (finalized/replaced).
2. If nonce remains unresolved beyond policy window, mark lane `blocked` and require reprice/rebroadcast path.
3. Do not silently keep allocating nonces when first unresolved nonce is stale and unresolved.

### 4) Finalization Ownership

Move finalization tracking into SDK/core (or provide a core lifecycle module callable by app).  
UI should display lifecycle state, not own correctness logic.

## Migration Plan

### Phase 1: Core Lifecycle Types + Storage

1. Add `InFlightNonceRecord` model in nonce manager.
2. Add lane state transitions and invariant checks.
3. Add metrics/logging for transitions and reconciliation outcomes.

### Phase 2: Signing Engine Integration

1. On sign success: keep reservation.
2. On broadcast accept: transition to `in_flight` (not committed-final).
3. On broadcast reject: release/mark failed.
4. Wire lifecycle APIs through `TatchiPasskey.tempo` and iframe router.

### Phase 3: Reconciliation Worker/Calls

1. Add reconciliation on:
   1. next sign attempt for same lane,
   2. explicit lifecycle report calls,
   3. optional background cadence while app active.
2. Add stale-lane escalation error with deterministic error code.

### Phase 4: Delete Legacy Semantics

1. Remove old `status: 'success' | 'failure'` broadcast contract.
2. Delete UI-level assumptions tied to old contract.
3. Update docs/tests to lifecycle vocabulary only.

## Testing Plan

### Unit

1. reserve -> broadcast accepted -> finalized.
2. reserve -> broadcast accepted -> dropped -> reconcile -> nonce recovery.
3. reserve -> broadcast accepted -> replaced -> reconcile keeps lane in-flight until terminal resolution.
4. stalled unresolved nonce blocks unsafe next allocation.
5. tempo lane isolation by `nonceKey`.

### Integration

1. simulated RPC where first tx never finalizes but second is attempted.
2. replacement underpriced path with retry/reprice.
3. reconnection/app reload recovers lane state deterministically.

### E2E

1. Tempo sequential sends with injected dropped tx.
2. ARC parity scenarios (same failure model, same behavior).
3. unresolved nonce-gap is surfaced by reconcile and recovers after explicit dropped/replaced lifecycle transition.
4. no indefinite "waiting for finalization" state without explicit lifecycle error.

## Observability and SLO

Track per chain/lane:

1. time from `in_flight` to resolution,
2. dropped/replaced rate,
3. reconciliation recoveries,
4. stale blocked lane count,
5. nonce conflict retry rate.

## TODO

- [x] Add lifecycle state types and invariants in `evm/nonceManager.ts`.
- [x] Implement `in_flight` record store keyed by `(chain, networkKey, chainId, sender, nonceKey?)`.
- [x] Add `reportBroadcastAccepted` + `reportBroadcastRejected` APIs in signing engine.
- [x] Add `reportFinalized` + `reportDroppedOrReplaced` APIs.
- [x] Implement `reconcileLane` using pending/latest nonce + tracked tx hashes.
- [x] Add deterministic error code for blocked stale nonce lane.
- [x] Update `TatchiPasskey` public surface and iframe route handlers to new lifecycle API.
- [x] Remove old broadcast `status: 'success' | 'failure'` contract and call sites.
- [x] Refactor demo hooks to consume lifecycle status instead of owning correctness.
  - [x] Map accepted-broadcast + `nonce_lane_blocked` reconcile outcomes to explicit `reportDroppedOrReplaced(reason: 'dropped')`.
  - [x] Remove state-based fallback finalization (`greeting`/`userTokens`) and require receipt-based finalization for lifecycle transitions.
- [x] Add unit tests for dropped/replaced/reconcile flows.
- [x] Add e2e Tempo regression scenario for unresolved nonce gap.
- [x] Add ARC parity tests to ensure identical semantics.
- [x] Update docs:
  - [x] `docs/multichain-nonce-manager.md`
  - [x] `docs/signing-sessions.md`
  - [x] any API surface docs referencing old broadcast semantics.

## Next Steps

- [x] Emit lifecycle metrics (`accepted`, `rejected`, `finalized`, `dropped|replaced`, `reconcile`) to the SDK telemetry sink with lane tags.
- [x] Add wallet-iframe integration coverage for `nonce_lane_blocked` propagation and retry UX mapping.
- [x] Add an operator runbook for nonce-lane recovery paths (`dropped`, `replaced`, `blocked`) and expected app actions (`docs/nonce-lane-recovery-runbook.md`).
