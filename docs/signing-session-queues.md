# Signing Session Queues Reference

Status: current consolidated reference from `refactor23` and `refactor24`.

## 1. Purpose
This document captures the final, intended behavior for:
1. Threshold signing session queueing and keying across ECDSA and Ed25519.
2. EVM/Tempo finalization reliability handling tied to nonce-lane recovery.

Use this as the canonical implementation reference when changing signing-session/queue behavior.

## 2. Core Outcomes
1. ECDSA commit queue keying is strict session-only: `session:${chain}:${thresholdSessionId}`.
2. Ed25519 threshold near-signing uses strict session-only keying: `session:ed25519:${thresholdSessionId}`.
3. ECDSA and Ed25519 queue wrappers share one queue primitive, but keep separate key domains.
4. Legacy fallback queue keys (`lane:*`, `account:*`) are removed and guarded against reintroduction.
5. EVM finalization paths are fail-closed and terminal: no indefinite loading states after broadcast.
6. Timeout outcomes explicitly trigger nonce-lane reconciliation.
7. Click-time fee-cap refresh is used for EIP-1559 request construction (with non-blocking fallback).

## 3. Queue Architecture (Refactor23)

### 3.1 Queue Identity
1. ECDSA resolver:
- `session:${chain}:${thresholdSessionId}` where `chain` is `tempo` or `evm`.
2. Ed25519 resolver:
- `session:ed25519:${thresholdSessionId}`.
3. Missing or empty `thresholdSessionId` is an invariant violation and throws before enqueue.

### 3.2 Queue Semantics
1. FIFO ordering per queue key.
2. Same key serializes; different keys can proceed concurrently.
3. Queue covers commit/sign stage, not full user flow.
4. Typed queue errors:
- `commit_queue_overflow`
- `commit_queue_timeout`
- `cancelled`

### 3.3 Shared Primitive + Curve Wrappers
1. Shared primitive:
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdCommitQueueShared.ts`
2. ECDSA wrapper:
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`
3. Ed25519 wrapper:
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519CommitQueue.ts`
4. Threshold Ed25519 signing uses the wrapper in threshold mode via:
- `client/src/core/signingEngine/api/nearSigning.ts`

### 3.4 Runtime Wiring
1. ECDSA commit queue is wired through:
- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`
2. Engine/dependency plumbing:
- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`

### 3.5 Guardrails
1. Never reintroduce fallback keying (`lane:` or `account:`) for commit queues.
2. Never couple Ed25519 and ECDSA queues into one key domain.
3. Shared implementation style is required; shared runtime lane is not.

## 4. Finalization Reliability (Refactor24)

### 4.1 Terminal Outcome Invariant
Any broadcasted EVM/Tempo attempt must resolve to a terminal outcome without spinner deadlock:
1. `success`
2. `dropped`
3. `replaced`
4. `underpriced`
5. `timeout`
6. `aborted`

### 4.2 Timeout and Recovery
1. Timeout branches are explicitly classified.
2. Timeout branches always invoke nonce-lane reconciliation.
3. Recovery runs deterministically, not via passive waiting.

### 4.3 Fee Freshness
1. EIP-1559 caps are refreshed at click/sign time.
2. Interval refresh remains for UX defaults.
3. Fee-fetch failures do not hard-block signing; fallback values are used.

### 4.4 Structured Finalization Telemetry
Finalization debug/reporting includes branch-level context to diagnose behavior:
1. `branch`
2. `reason`
3. `errorCode`
4. chain context fields (chain/chainId and tx-level identity fields where available)

Primary touchpoints:
1. `examples/tatchi-site/src/flows/demo/demoEvmHelpers.ts`
2. `examples/tatchi-site/src/flows/demo/hooks/demoEvmTransactionHandling.ts`
3. `examples/tatchi-site/src/flows/demo/hooks/reportTempoBroadcastFailure.ts`
4. `examples/tatchi-site/src/flows/demo/hooks/reportEvmFinalizationDebugEvent.ts`

## 5. Test/Validation Gates

### 5.1 Queue + Session Keying
1. `tests/unit/thresholdEcdsa.commitQueue.unit.test.ts`
2. `tests/unit/thresholdEd25519.commitQueue.unit.test.ts`
3. `tests/unit/thresholdCommitQueue.sharedPrimitive.guard.unit.test.ts`
4. `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`
5. `tests/unit/thresholdEcdsa.noLegacySurface.guard.unit.test.ts`
6. `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
7. `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts` (same-tab sealed refresh smoke)
8. `tests/e2e/thresholdEd25519.batchSigning.test.ts`

### 5.2 Finalization Reliability
1. `tests/unit/demoEvmTransactionHandling.unit.test.ts`
2. `tests/unit/reportTempoBroadcastFailure.unit.test.ts`
3. `tests/unit/evmPublicClient.waitForReceipt.unit.test.ts`
4. `tests/unit/demoEvmFinalizationDebugEvent.unit.test.ts`
5. `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
6. `tests/e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`

### 5.3 Build Gate
1. `pnpm -C sdk run build:check:fresh || pnpm -C sdk run build`

## 6. Residual Risks
1. Mempool/RPC divergence is external; client can classify terminal states but cannot force inclusion.
2. Nonce-lane reconciliation after terminal failures is intentionally off the UI critical path.

## 7. Change Rules for Future Refactors
1. Preserve strict session-only queue identity for both curves.
2. Preserve curve-specific key domains.
3. Keep queue logic in shared primitive + thin curve wrappers.
4. Keep timeout-to-reconcile behavior explicit in finalization flows.
5. Update this document and matching guard tests in the same change when queue/session contracts change.
