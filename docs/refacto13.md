# Refactor 13: Concurrent Tx Confirmers + Serialized Threshold Commit

Status: Completed  
Severity: High (UX regression + signing race risk)  
Last updated: 2026-02-21

## 1. Problem Statement

Current threshold secp256k1 request queueing wraps the full signing flow, including UI confirmation.

Observed behavior:

1. The second Tempo/EVM request is blocked from showing a tx confirmer until the first request fully signs.
2. Users perceive this as stuck/lagging UX.
3. Queue timeout can occur before a user is even shown the second confirmer.

At the same time, full end-to-end concurrency is unsafe for threshold commit operations because PRF/session usage and relayer sign handshakes are stateful.

## 2. Scope and Decisions

1. Adopt a two-phase pipeline for threshold secp256k1 requests:
   - Phase A (concurrent): prepare intent + open tx confirmer + collect approval/auth artifact.
   - Phase B (serialized per account): commit/sign path (`authorize` + PRF dispense + presign/sign finalize).
2. Keep serialization only for same-account threshold commit; do not serialize confirmer UI.
3. Keep cross-account concurrency unchanged.
4. Clean switch only: remove full-flow queueing behavior; no legacy path, no feature flag.
5. Rename queue errors to commit-specific names (breaking change accepted):
   - `commit_queue_overflow`
   - `commit_queue_timeout`
   - `cancelled`
6. Commit order is deterministic by commit-queue enqueue order (confirmation completion time).

## 3. Invariants

- Multiple tx confirmers can be visible/open concurrently.
- Same-account threshold commit never runs concurrently.
- No new secret material is exposed to caller-facing responses.
- Cancellation before commit start removes queued commit request.
- Errors remain typed and actionable for reconnect/retry.

## 4. Target UX

When a user rapidly triggers Tempo and EVM signing for the same account:

1. Both tx confirmers can appear immediately (not blocked by prior signing).
2. User can approve/reject each independently.
3. If both are approved, one commit runs and the other waits in queued state.
4. Queued request progresses automatically once prior commit finishes.

## 5. Implementation Plan

## Phase 0: Types/Interfaces + Naming

- [x] Introduce commit-queue types/interfaces (`ThresholdEcdsaCommitQueue*`) and retire sign-in-flight naming.
- [x] Add commit-queue typed error codes (`commit_queue_overflow`, `commit_queue_timeout`, `cancelled`).
- [x] Update canonical boundary error mapping for wallet-iframe/router.

Files:

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`
- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/WalletIframe/client/router.ts`

## Phase 1: Split the Flow (Concurrent Confirm, Serialized Commit)

- [x] Refactor `signEvmFamily` into explicit stages:
  - `prepareAndConfirm` (concurrent),
  - `commitThresholdSignature` (serialized).
- [x] Move queue boundary so it wraps only commit stage, not confirmer stage.
- [x] Keep session readiness checks before confirmation and re-check before commit start.
- [x] Ensure `shouldAbort` is honored pre-confirm and pre-commit dequeue.

Files:

- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/signingEngine/api/tempoSigning.ts`
- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
- `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`

## Phase 2: Commit Queue Module + Lifecycle

- [x] Replace current full-flow queue helper with commit-only queue helper.
- [x] Preserve per-account FIFO semantics for commit stage.
- [x] Ensure queue clear/cancel behavior still runs on logout/destroy.
- [x] Remove old full-flow queue symbols from runtime codepaths.

Files:

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`
- `client/src/core/signingEngine/SigningEngine.ts`

## Phase 3: Progress + UI Behavior

- [x] Emit explicit queued/start commit progress phases (e.g., `commit-queued`, `commit-started`).
- [x] Keep stacked confirmer behavior for concurrent prompts.
- [x] Ensure overlay lifecycle does not close one request’s UI because another request completed.

Files:

- `client/src/core/signingEngine/touchConfirm/handlers/flows/signing.ts`
- `client/src/core/signingEngine/touchConfirm/ui/confirm-ui.ts`
- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`

## Phase 4: Tests + Anti-Regression Guards

- [x] Unit: second same-account request shows tx confirmer without waiting for first commit completion.
- [x] Unit: same-account commit stage remains serialized FIFO after approvals.
- [x] Unit: different-account commit stages can run concurrently.
- [x] Unit: queued-after-confirm cancellation prevents commit execution.
- [x] Unit: commit queue overflow/timeout produce new typed codes.
- [x] Integration: wallet-iframe concurrent confirmers keep overlay behavior correct.
- [x] Guard test: prevent reintroduction of full-flow queueing symbols/error codes.

Suggested tests/files:

- `tests/unit/thresholdEcdsa.commitQueue.unit.test.ts` (replaced from sign-in-flight semantics)
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/unit/walletIframeHost.signTempoCancel.unit.test.ts`
- `tests/wallet-iframe/router.behavior.concurrent.test.ts`
- `tests/wallet-iframe/router.behavior.sticky.test.ts`
- `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`
- `tests/unit/thresholdEcdsa.noLegacySurface.guard.unit.test.ts`

## 6. Risks and Mitigations

1. Confirmation succeeds but commit later fails due expired/missing warm session.  
   Mitigation: pre-commit re-check + clear typed reconnect error.

2. Completion order may differ from click order.  
   Mitigation: document commit-order rule (queue enqueue time) and emit clear queued progress phases.

3. Overlay race with multiple concurrent requests.  
   Mitigation: strengthen sticky/visibility tests for parallel confirmations.

4. Retry path complexity (deploy/presign/sign) under queued commit.  
   Mitigation: keep existing fail-closed behavior and add queue-aware integration coverage.

## 7. Done Criteria

- [x] Same-account second request can show confirmer immediately while first request is still in progress.
- [x] Same-account threshold commit stage is serialized and deterministic.
- [x] Cross-account concurrency remains unchanged.
- [x] Old full-flow queue behavior is removed from runtime codepaths.
- [x] Wallet-iframe overlay behavior is stable under concurrent confirmations.
- [x] Typed commit queue errors are surfaced and mapped consistently.
- [x] Regression tests cover concurrency, queueing, cancellation, and lifecycle edges.

## 8. Phased TODO List

## Immediate

- [x] Land phase-0 naming/type changes.
- [x] Implement phase-1 flow split with commit-only queue boundary.

## Next

- [x] Wire progress/UI lifecycle updates.
- [x] Update router error code mapping and host pass-through behavior.

## Finalize

- [x] Update/replace queue tests with split-phase semantics.
- [x] Add anti-regression guard for removed full-flow queue behavior.
- [x] Run focused + lite suites and close checklist.
