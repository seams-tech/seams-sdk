# Multichain Nonce Manager Plan

Last updated: 2026-02-26

## 1. Goal

Introduce explicit nonce ownership in the signing engine for all nonce/counter-based chains:

1. Keep NEAR nonce management as-is (existing `NonceManager`).
2. Add EVM-family nonce management for:
   1. EVM `eip1559` (`nonce`).
   2. Tempo `tempoTransaction` (`nonceKey` + `nonce`).
3. Keep EVM-family manager chain-agnostic so newly added EVM networks/chains work without nonce-manager redesign.
4. Treat `evm` as family-level naming only; concrete network identity stays explicit (`arc-*`, `ethereum-*`, etc.).
5. Remove caller-level nonce bookkeeping from app/demo flows once engine-owned paths are in place.

## 2. Problem Statement

Current state:

1. NEAR has a dedicated manager with reservation/release semantics.
2. EVM and Tempo require caller-supplied nonce fields in `signTempo` requests.
3. UI code can hardcode or race nonce values, which causes pending/stuck transactions and brittle retries.

Required outcome:

1. Nonce lifecycle must be owned by signing/orchestration.
2. UI/API callers should not manually fetch and inject nonces for standard sends.
3. Competing requests from the same account/runtime must not reuse nonce values.

## 3. Scope

In scope:

1. New EVM-family nonce manager in SDK core.
2. Integration with signing orchestration for both EVM and Tempo signing.
3. Runtime memory reservation and commit/release lifecycle.
4. Docs/tests migration off hardcoded nonces.

Out of scope (phase 1):

1. Cross-device/global nonce coordination (server-side locking).
2. Guaranteed replacement/cancel transaction strategy.
3. Historical nonce analytics storage.

## 4. Design Principles

1. One authority per chain family at runtime.
2. Reserve before signing, commit after broadcast, release on failure/cancel.
3. Chain RPC is source of truth; local state is a short-lived acceleration/cache layer.
4. Fail closed when nonce cannot be resolved deterministically.
5. No legacy parallel paths; replace old caller-managed nonce flow as rollout completes.
6. UX-first confirmation sequencing for EVM/Tempo: mount the confirmer immediately and fetch/reserve nonce in parallel.
7. While nonce is pending, confirmer primary action must stay disabled with a loading indicator.
8. Avoid hardcoded chain branches; support any configured EVM chain (`evm:*`) via generic keying and RPC resolution.

## 5. Target Architecture

### 5.1 Managers

1. `NearNonceManager` (existing): unchanged semantics.
2. `EvmNonceManager` (new): owns nonce for both:
   1. `chain='evm'` keyed by `(network, chainId, sender)`.
   2. `chain='tempo'` keyed by `(network, chainId, sender, nonceKey)`.

### 5.2 Placement

1. New file: `client/src/core/rpcClients/evm/nonceManager.ts`.
2. Inject through signing bootstrap:
   1. `client/src/core/signingEngine/bootstrap/managerAssembly.ts`.
   2. `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`.
3. Used by tempo/evm signing orchestration (not adapters and not UI components).

### 5.3 Interface

```ts
type ReserveNonceInput = {
  chain: 'evm' | 'tempo';
  networkKey: string; // e.g. "evm:11155111", "tempo:42431"
  chainId: bigint;
  sender: `0x${string}`;
  nonceKey?: bigint; // required for tempo
};

interface EvmNonceManager {
  reserveNextNonce(input: ReserveNonceInput): Promise<bigint>;
  commitBroadcast(
    input: ReserveNonceInput & { nonce: bigint; txHash?: `0x${string}` },
  ): Promise<void>;
  releaseReservation(input: ReserveNonceInput & { nonce: bigint }): void;
  refreshFromChain(input: ReserveNonceInput): Promise<bigint>;
  clearForAccount(nearAccountId: string): void;
}
```

## 6. Data Model

In-memory map keyed by canonical reservation key:

1. `key = ${chain}|${networkKey}|${normalizedChainId}|${normalizedSender}|${nonceKey || 0}`
2. Per-key state:
   1. `chainNonce` (latest observed from RPC).
   2. `nextCandidate` (next assignable local nonce).
   3. `reserved` set.
   4. `lastRefreshMs`.
   5. `inflightRefresh` promise for coalescing.

No IndexedDB persistence in phase 1.

## 7. Execution Flow

### 7.1 Signing

1. Resolve sender/counterparty account context.
2. Start nonce reservation (`reserveNextNonce(...)`) and mount confirmer UI concurrently.
3. Keep confirmer primary action in `loading`/disabled state while nonce is pending.
4. Build request with reserved nonce after reservation completes.
5. Rehydrate confirmation model/challenge with finalized intent and enable confirmer primary action.
6. Sign intent.
7. If signing fails/cancelled: `releaseReservation(...)`.

### 7.2 Broadcast

1. On successful broadcast: `commitBroadcast(...)`.
2. On broadcast failure: `releaseReservation(...)`.
3. On nonce-related RPC error (`nonce too low`, `already known`, etc.): `refreshFromChain(...)` and fail with typed retry guidance.

## 8. API Evolution

Phase-in API change:

1. Add higher-level send helpers where nonce is engine-managed.
2. Keep low-level `signTempo` request shape for advanced/manual callers.
3. Mark caller-supplied nonce path as advanced/explicit in docs.
4. Migrate examples and product UI paths to managed send helpers.

## 9. Rollout Plan

### Phase 1: Core Manager + Wiring

1. Implement `EvmNonceManager`.
2. Wire into signing engine dependency graph.
3. Add unit tests for reservation/commit/release/refresh behavior.

### Phase 2: Signing Orchestration Integration

1. Reserve nonce before signing for EVM/Tempo paths.
2. Ensure cancellation/error paths release reservations.
3. Return structured errors for nonce drift/conflict.

### Phase 3: Broadcast Integration

1. Integrate commit/release hooks at broadcast call sites.
2. Add retry-safe refresh behavior on nonce conflicts.
3. Add telemetry fields (reservation key, reserved nonce, conflict type).

### Phase 4: Cleanup

1. Remove hardcoded nonce examples in docs/tests that model production flows.
2. Remove duplicate UI-side nonce-fetch logic from demo/app paths once engine-managed paths exist.
3. Update docs to make manager-owned nonce flow the default guidance.

## 10. TODO Checklist

Use this list as the implementation tracker and mark items complete in PRs.

### Phase 1: Core Manager + Wiring

- [x] Create `client/src/core/rpcClients/evm/nonceManager.ts`.
- [x] Implement in-memory reservation state keyed by `(chain, networkKey, chainId, sender, nonceKey?)`.
- [x] Keep manager logic chain-agnostic for EVM networks (no hardcoded per-network branching).
- [x] Implement `reserveNextNonce`.
- [x] Implement `refreshFromChain` with inflight call coalescing.
- [x] Implement `releaseReservation`.
- [x] Implement `commitBroadcast`.
- [x] Inject manager in `managerAssembly.ts`.
- [x] Thread manager through `orchestrationDependencyFactory.ts`.
- [x] Add unit tests for reservation/commit/release/refresh.

### Phase 2: Signing Orchestration Integration

- [x] Reserve nonce inside EVM signing orchestration before signing.
- [x] Reserve nonce inside Tempo signing orchestration before signing.
- [x] Mount confirmer before nonce reservation completes (no pre-modal nonce wait).
- [x] Keep confirmer primary action loading/disabled until nonce reservation resolves.
- [x] Populate signed request nonce fields from reserved nonce.
- [x] Release reservation on sign cancellation.
- [x] Release reservation on sign failure.
- [x] Add typed nonce-conflict/retryable error mapping.
- [x] Add integration tests for concurrent same-account signs.

### Phase 3: Broadcast Integration

- [x] Define engine-level broadcast hooks/API contract for nonce commit/release.
- [x] Call `commitBroadcast` on successful broadcast.
- [x] Call `releaseReservation` on broadcast failure.
- [x] Refresh nonce state on nonce-conflict RPC errors.
- [x] Add telemetry fields for nonce lifecycle events.
- [x] Add integration tests for broadcast failure + retry paths.

### Phase 4: Cleanup

- [x] Remove hardcoded EVM/Tempo nonces from production-facing examples.
- [x] Remove UI-local nonce-fetch logic from default/demo send paths.
- [x] Update docs to make engine-managed nonce path the default.
- [x] Keep low-level manual nonce path documented as advanced-only.
- [x] Add e2e coverage for back-to-back finalized sends with managed nonces.

## 11. Testing Plan

Unit tests:

1. Reserve monotonic sequence per key.
2. Parallel reserve calls never duplicate nonce.
3. Release makes nonce reusable only when safe.
4. Refresh coalesces inflight RPC calls.

Integration tests:

1. Concurrent EVM signs from same account/runtime.
2. Concurrent Tempo signs with same `nonceKey`.
3. Mixed EVM + Tempo signs do not interfere.
4. Broadcast failure path releases reservation.
5. Nonce-too-low path refreshes and reports retryable error.
6. Confirmer renders before nonce resolution and keeps confirm CTA loading/disabled until reservation completes.
7. Same sender signing on two distinct EVM chain IDs does not share or collide nonce state.

E2E tests:

1. No indefinite wait modal due to nonce mismanagement.
2. Back-to-back sends finalize without manual nonce input.

## 12. Open Decisions

1. Whether Tempo nonces are strictly shared with EVM or fully isolated by `nonceKey` per protocol guarantees.
2. Whether to maintain a small persisted watermark (sessionStorage) for tab reload recovery.
3. Whether broadcast should move into SDK-managed send APIs for strict commit semantics.

## 13. Acceptance Criteria

1. No app/demo path requires hardcoded nonce values for standard EVM/Tempo sends.
2. Same-runtime parallel sends on the same chain/account do not collide on nonce.
3. Nonce-related broadcast errors surface typed actionable messages.
4. Legacy duplicate nonce paths are removed from default docs/examples.
