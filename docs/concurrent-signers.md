# Concurrent Signers: Canonical Lanes, PRF Seals, and Lane-Keyed Commit Queue

## Summary
This document consolidates `refactor21`, `refactor22`, and `refactor21-merge-notes` into one source of truth for concurrent threshold signing.

Outcome:
1. Tempo and ARC/EVM threshold signing lanes are isolated and can run concurrently when safe.
2. Warm-session persistence and rehydrate behavior are deterministic across refresh.
3. PRF sealed-refresh apply/remove operations are replay-safe under race and multi-instance conditions.
4. Startup config mismatches fail closed instead of silently degrading.

## Problem Statement
Previous behavior had two core issues:
1. ECDSA persisted-session identity and lookup were too coarse, causing cross-chain overwrite/mismatch and "session not ready" after refresh.
2. Commit queueing was keyed by `nearAccountId`, which serialized unrelated lanes and reduced throughput.

Observed regression to prevent:
1. User logs in.
2. EVM reuses warm session.
3. Tempo unexpectedly prompts TouchID due to missing/misresolved lane session.

## Final Architecture

## 1) Canonical ECDSA Session Identity and Persistence
1. Canonical ECDSA lane key is:
`encodeURIComponent(nearAccountId)|encodeURIComponent(chain)|encodeURIComponent(relayerKeyId)`.
2. ECDSA persisted records are keyed by this canonical lane key.
3. Reverse index is maintained as `thresholdSessionId -> canonicalLaneKey`.
4. ECDSA callsites are chain-strict:
- Tempo path resolves Tempo lane first.
- EVM path resolves EVM lane first.
5. A one-time migration moves legacy account-only records into canonical lane records with deterministic conflict resolution:
- highest `updatedAtMs`
- then highest `expiresAtMs`

Notes:
1. Ed25519 remains account-based for now.
2. No duplicate long-lived legacy stores are kept.

## 2) PRF Sealed Refresh: Shared Idempotency + Strict Parity

### Idempotency
1. In-process single-flight remains as a local optimization.
2. Shared idempotency backends support cross-instance replay-safe dedupe for `apply/remove`.
3. Idempotency key shape:
`prfseal:{op}:{userId}:{thresholdSessionId}:{keyVersion}:{ciphertextHash}`
4. Backend choice is explicit via `PRF_SESSION_SEAL_IDEMPOTENCY_KIND`:
- `in-memory`
- `upstash-redis-rest`
- `redis-tcp`
- `postgres`

Recommendation:
1. Use Redis modes for distributed deployments.
2. Use Postgres when Postgres is already your local relay backend.
3. Use in-memory only for single-node/dev test runs.

### Startup Parity Contract
1. Server publishes sealed-refresh capability metadata at:
`GET /.well-known/webauthn`
2. Field location:
`capabilities.signingSessionSeal`
3. Required parity fields:
- `mode` (expected `sealed_refresh_v1`)
- `keyVersion`
- `shamirPrimeB64u`
4. Client checks parity at startup and fails closed on mismatch with explicit field-level diagnostics.
5. Endpoint is public by design (well-known surface); client must fetch from the trusted relay origin.

## 3) Lane-Keyed Threshold ECDSA Commit Queue
Queue keying moved from account scope to lane scope.

Resolver:
1. `session:${chain}:${thresholdSessionId}` only.
2. Missing `thresholdSessionId` is a hard invariant error (no fallback queue key modes).

Queue invariants:
1. Same queue key always serializes.
2. Different queue keys do not block each other.
3. Key derivation is deterministic.
4. Missing session context fails closed before enqueue.
5. Chain-separated lanes never collapse into one key.

## 4) Cross-Curve Queue Style (Ed25519 + ECDSA)
Queue implementation style is unified via one shared primitive with curve-specific wrappers.

Resolver domains:
1. ECDSA: `session:${chain}:${thresholdSessionId}`.
2. Ed25519: `session:ed25519:${thresholdSessionId}`.

Notes:
1. Key domains remain separate to avoid cross-curve runtime coupling/blocking.
2. Ed25519 threshold near-signing now uses the same queueing pattern in threshold mode.

## Regression Controls
To avoid Tempo-only prompt regressions:
1. Canonical ECDSA store is authoritative for both Tempo and EVM.
2. Login/bootstrap must provision both lanes or guarantee deterministic no-prompt rehydrate from valid sealed state.
3. All ECDSA sign entrypoints use the same chain-strict resolver and readiness policy.
4. Rehydrate/transfer maintains canonical lane indexes and reverse-index integrity.
5. No merge without prompt-parity and cross-lane tests passing.

## Validation Snapshot
Full matrix (green):
1. lane store unit: `5 passed`
2. tempo high-level unit: `7 passed`
3. sealed-refresh parity unit: `4 passed`
4. relayer suites: `26 passed, 1 skipped`
5. tempo signing e2e: `7 passed`
6. sealed-refresh wallet-iframe e2e: `8 passed`
7. `pnpm -s type-check:relay-server`: passed

Short merge smoke (green):
1. commit queue unit: `10 passed`
2. tempo high-level unit: `7 passed`
3. wallet-iframe sealed-refresh smoke: `1 passed`
4. evm nonce prefetch unit: `1 passed`

Latest queue-focused verification (green):
1. `thresholdEcdsa.commitQueue.unit`: `10 passed`
2. `thresholdEcdsa.tempoHighLevel.unit`: `7 passed`
3. sealed-refresh wallet-iframe smoke: `1 passed`
4. `reportTempoBroadcastFailure + evmSigning.noncePrefetch` unit: `5 passed`
5. `thresholdEd25519.commitQueue.unit`: `5 passed`
6. `thresholdCommitQueue.sharedPrimitive.guard.unit`: `2 passed`
7. `thresholdEd25519.nearSigningQueue.guard.unit`: `1 passed`

## Operational Notes
1. `pnpm -C sdk run build:check:fresh` may report fresh while `sdk/dist/esm/*` artifacts are missing.
2. If browser-backed tests fail due to missing dist modules, run:
`pnpm -C sdk run build`
3. Dedicated `refactor22-matrix` CI job was removed by request; explicit local matrix command remains available for on-demand gating.

## Current Status
1. Refactor goals from 21 and 22 are implemented and validated.
2. No functional blockers are open in this scope.
3. Remaining cleanup is process-level.

## Follow-up
1. Remove one-time ECDSA session migration path once all active environments are confirmed on canonical lane keys.
2. Keep parity checks fail-closed; do not add silent fallback paths.
3. Reintroduce CI matrix gating later only if needed, using the explicit command chain already validated.
