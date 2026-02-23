# Refactor 18: Persistent Client ECDSA Presign Cache (Safe-by-Construction)

Status: Planned  
Severity: High (first-sign latency after login/logout)  
Last updated: 2026-02-23

## 1. Direct Answer

Yes, it can be safe enough for production UX, but only if we treat client presignatures as secret key material and enforce strict controls.

Not safe:

1. Persisting `kShare` / `sigmaShare` plaintext in IndexedDB.
2. Reusing a consumed presignature.
3. Keeping cache entries indefinitely.

Safe-by-construction target:

1. Encrypt presignatures at rest with a key derived from `PRF.first` (never persist the key).
2. Atomic single-use consume semantics.
3. TTL + compatibility binding + aggressive purge on mismatch/failure.
4. Cross-tab claim locking.

## 2. Problem Statement

Current behavior:

1. Server presign pool is persistent (Postgres), so relayer shares survive login/logout.
2. Client presign pool is in-memory-only (`Map`), so client shares are lost on reload/new runtime.
3. First sign after login often pays cold presign handshake (~6+ `/presign/step` calls), causing 10+ second UX outliers.

We need persistent client presign caching so first post-login sign can usually hit a warm presignature.

## 3. Scope and Decisions

1. Implement persistent client-side ECDSA presign cache in IndexedDB.
2. Keep no legacy dual-path architecture; persistent cache becomes canonical backing store for presign pool.
3. Keep existing protocol endpoints unchanged (`/presign/*`, `/sign/*`).
4. Keep fallback behavior: if cache fails/decrypt fails/mismatch occurs, run cold handshake and continue.
5. Keep existing manual prefill callback model; persistence complements prefill, not replaces it.

## 4. Security Invariants

1. `kShare` and `sigmaShare` must never be stored or logged plaintext outside short-lived runtime memory.
2. Persisted records must be encrypted with AEAD; integrity must be verified before use.
3. Cache key material (derived from `PRF.first`) must never be written to IndexedDB/localStorage/sessionStorage.
4. Every presignature is one-time use: claim/delete must be atomic.
5. Cache entry must be bound to pool identity (`relayerUrl`, `relayerKeyId`, `clientVerifyingShareB64u`, `participantIds`).
6. Expired or incompatible entries are purged before use.
7. Any decrypt/bigR mismatch marks entry invalid and removes it.

## 5. Target Architecture

## 5.1 Persistent Store

Add IndexedDB object store for encrypted presign entries (suggested name: `thresholdEcdsaPresignatures`).

Suggested record fields:

1. `recordId` (primary key; UUID)
2. `poolKey` (derived exactly like coordinator pool key)
3. `presignatureId`
4. `createdAtMs`
5. `expiresAtMs`
6. `ciphertextB64u`
7. `nonceB64u`
8. `saltB64u`
9. `aadVersion`
10. `encVersion`

The encrypted payload includes:

1. `bigRB64u`
2. `kShareB64u`
3. `sigmaShareB64u`
4. `presignatureId`
5. `poolKey`
6. timestamps

## 5.2 Encryption Key Strategy

1. Derive a cache KEK from `PRF.first` via HKDF-SHA256 and random per-record `salt`.
2. Encrypt payload with AES-GCM (or existing project-standard AEAD), include strict AAD binding (`poolKey`, `presignatureId`, `encVersion`).
3. Keep derived key only in memory for active runtime.
4. On fresh login, re-derive from new runtime access to `PRF.first` and decrypt existing records.

## 5.3 Claim/Consume Flow

1. `signThresholdEcdsaDigestWithPool` tries in-memory pool first.
2. If empty, atomically claim one persistent entry for `poolKey` (oldest-first), decrypt, validate, and use.
3. On successful claim, delete record immediately (single-use).
4. On failure (`pool_empty`, mismatch, decrypt failure), discard entry and fall back to cold presign handshake.

## 5.4 Cross-Tab Safety

1. Use IndexedDB transaction atomicity for claim+delete.
2. Use `navigator.locks` best-effort lock per `poolKey` to reduce duplicate concurrent claims.
3. If lock unsupported, rely on transaction-level atomic delete as correctness baseline.

## 6. Implementation Plan

## Phase 0: Baseline + Threat Model

- [ ] Document threat model and acceptable residual risk in `docs/presigning-pool.md` (link to this refactor).
- [ ] Define presign cache TTL policy (initial: 24h max, purge on every startup/login/sign path).
- [ ] Add explicit “no plaintext secret fields in logs” audit checklist.

## Phase 1: IndexedDB Schema + Types

- [ ] Bump `PasskeyClientDB` version and add `thresholdEcdsaPresignatures` store.
- [ ] Add indexes:
  - `poolKey_createdAtMs`
  - `poolKey_expiresAtMs`
  - `expiresAtMs`
- [ ] Add typed record definitions in `passkeyClientDB.types`.

Suggested files:

- `client/src/core/indexedDB/passkeyClientDB/schema.ts`
- `client/src/core/indexedDB/passkeyClientDB.types.ts`
- `client/src/core/indexedDB/passkeyClientDB/manager.ts`

## Phase 2: Crypto Envelope Module

- [ ] Add dedicated crypto helpers for encrypt/decrypt of presign payload records.
- [ ] Use versioned envelope format and strict AAD.
- [ ] Enforce payload shape + byte-length checks after decrypt.

Suggested files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaPresignCacheCrypto.ts` (new)
- `client/src/core/signingEngine/signers/wasm/ethSignerWasm.ts` (only if helper reuse is needed)

## Phase 3: Persistent Pool DAO

- [ ] Implement CRUD + claim helpers:
  - `putEncryptedPresignature`
  - `claimEncryptedPresignatureForPool`
  - `countAvailableForPool`
  - `purgeExpired`
  - `purgeIncompatibleForPool`
- [ ] Implement transactionally atomic claim-delete.
- [ ] Add background janitor hook (best-effort).

Suggested files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaPresignStore.ts` (new)
- `client/src/core/indexedDB/passkeyClientDB/manager.ts`

## Phase 4: Coordinator Integration

- [ ] Replace pure in-memory pool writes with write-through:
  - push to memory
  - persist encrypted copy
- [ ] Replace pool pop logic with two-tier retrieval:
  - memory pop
  - persistent claim/decrypt fallback
- [ ] Ensure `clearAllThresholdEcdsaClientPresignatures` clears both memory and persisted entries (or provide scoped clear API).

Suggested files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- `client/src/core/signingEngine/SigningEngine.ts`

## Phase 5: Lifecycle Wiring

- [ ] On login success, load/purge-expired cache metadata and keep ready for sign path.
- [ ] Keep logout behavior configurable by policy:
  - default: retain encrypted presign cache across logout
  - explicit full-clear path for “forget device/account”.
- [ ] Purge cache on key/session incompatibility (`relayerKeyId`, participants, verifying share drift).

Suggested files:

- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts`

## Phase 6: Observability

- [ ] Add structured events:
  - `persistent_cache_hit`
  - `persistent_cache_miss`
  - `persistent_cache_decrypt_fail`
  - `persistent_cache_entry_expired`
  - `persistent_cache_entry_consumed`
- [ ] Separate metrics for:
  - foreground sign latency
  - cold-handshake count
  - cache hit ratio

Suggested files:

- `client/src/core/signingEngine/api/evmSigning.ts`
- `docs/ecdsa_timings.md`

## Phase 7: Tests

- [ ] Unit: encrypt/decrypt round-trip with AAD mismatch failure.
- [ ] Unit: claim is single-use under concurrent callers.
- [ ] Unit: expired entries are not returned.
- [ ] Unit: pool identity mismatch causes discard.
- [ ] Integration: sign after logout/login uses persistent cache and skips cold presign when available.
- [ ] Guard: no plaintext `kShare`/`sigmaShare` fields persisted.

Suggested tests:

- `tests/unit/thresholdEcdsa.persistentPresignCache.crypto.unit.test.ts` (new)
- `tests/unit/thresholdEcdsa.persistentPresignCache.store.unit.test.ts` (new)
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`

## 7. Risks and Mitigations

1. XSS during active session can still request signing and memory-resident secrets.  
Mitigation: strict CSP, dependency hygiene, isolated signing runtime, no secret logging.

2. Persistent cache drift vs server pool state (`pool_empty`/mismatch).  
Mitigation: discard stale entry and cold-refill fallback.

3. Multi-tab duplicate work / race claims.  
Mitigation: lock per pool key + atomic claim/delete.

4. Local storage compromise at rest.  
Mitigation: encrypted payload only, no persisted key material, short TTL.

## 8. Done Criteria

- [ ] First sign after login/logout usually avoids cold presign when valid cache exists.
- [ ] No plaintext presign secret material at rest.
- [ ] Cache entries are single-use and atomically consumed.
- [ ] Purge/TTL rules prevent unbounded stale accumulation.
- [ ] Regression tests and latency metrics confirm improvement without security regressions.

