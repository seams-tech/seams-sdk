# PRF Session Persistence Plan (Refresh-Only)

Date updated: February 25, 2026

## Objective

Keep threshold signing unlocked across browser refresh in the same tab, without requiring a new TouchID/WebAuthn prompt, while keeping plaintext `PRF.first` out of persistent browser storage.

Scope for this plan:

- Persist across refresh.
- Do not persist across tab close.
- Wallet-iframe mode is the canonical runtime.
- Use `shamir-3-pass-rs`: https://github.com/peitalin/shamir-3-pass-rs

## Non-Goals

- XSS defense redesign (already handled separately via cross-origin wallet iframe + CSP hardening).
- Surviving browser restart.
- Long-term key escrow.

## Final Design (Target State)

1. `PRF.first` is obtained during login/auth and delivered to the passkey-confirm worker.
2. Worker uses `shamir-3-pass-rs` to produce a server-layer encrypted blob `enc_s(PRF.first)` without revealing plaintext to server.
3. Main thread stores only the sealed blob in wallet-origin `sessionStorage`.
4. After refresh, main thread reads sealed blob and sends it to worker.
5. Worker performs 3-pass unwrap with server and restores plaintext `PRF.first` into worker memory cache only.
6. Signing uses worker cache as today; no additional WebAuthn prompt unless sealed blob is missing/expired/invalid.

Plaintext `PRF.first` never lands in `sessionStorage`, `localStorage`, or IndexedDB.

## Protocol

Notation:

- `E_k(x)`: commutative encryption with key `k`.
- `D_k(x)`: corresponding decryption.
- `k_s`: server KEK.
- `k1`, `k2`: worker-ephemeral client keys from secure RNG.

### A. Seal for Storage (during login/bootstrap)

1. Worker receives plaintext `PRF.first`.
2. Worker computes `a = E_k1(PRF)`.
3. Worker calls authenticated server endpoint with `a`.
4. Server returns `b = E_ks(a)`.
5. Worker computes `sealed = D_k1(b) = E_ks(PRF)`.
6. Worker zeroizes `k1`, `a`, `b` buffers and asks main thread to persist `sealed`.

Server never sees plaintext `PRF`.

### B. Rehydrate after Refresh

1. Main thread reads `sealed = E_ks(PRF)` from `sessionStorage` and sends it to worker.
2. Worker computes `d = E_k2(sealed) = E_k2(E_ks(PRF))`.
3. Worker sends `d` to authenticated server endpoint.
4. Server returns `e = D_ks(d) = E_k2(PRF)`.
5. Worker computes `PRF = D_k2(e)` and repopulates in-memory PRF cache.
6. Worker zeroizes `k2`, `d`, `e` buffers.

Server still never sees plaintext `PRF`.

## Storage Model

Wallet-origin `sessionStorage` key:

- `tatchi:threshold-prf-sealed:v1:<thresholdSessionId>`

Value shape:

```json
{
  "v": 1,
  "alg": "shamir3pass-v1",
  "thresholdSessionId": "....",
  "sealedPrfFirstB64u": "....",
  "keyVersion": "kek-s-2026-02",
  "expiresAtMs": 0,
  "remainingUses": 0,
  "updatedAtMs": 0
}
```

Rules:

- TTL and remaining uses must be clamped to threshold-session policy.
- On logout, lock, session expiry, or account switch, remove this record.
- Never store raw `prfFirstB64u`.

## Auth Model for Worker -> Server

Either auth mode is supported:

1. `HttpOnly` cookie session (preferred when available):
   - Worker `fetch(..., { credentials: "include" })`.
   - Cross-origin CORS must allow credentials and exact wallet origin.
2. Bearer JWT:
   - Worker sets `Authorization: Bearer <token>`.

Both modes require server-side auth before any 3-pass operation.

## API Contract (Server)

Add dedicated authenticated endpoints:

1. `POST /threshold-ecdsa/prf-seal/apply-server-layer`
   - Input: `ciphertext` (`E_k1(PRF)`), `thresholdSessionId`, metadata/version.
   - Output: `ciphertext` (`E_ks(E_k1(PRF))`), `keyVersion`, `expiresAtMs`, `remainingUses`.
2. `POST /threshold-ecdsa/prf-seal/remove-server-layer`
   - Input: `ciphertext` (`E_k2(E_ks(PRF))`), `thresholdSessionId`, `keyVersion`.
   - Output: `ciphertext` (`E_k2(PRF)`), `expiresAtMs`, `remainingUses`.

Server requirements:

- Enforce authenticated principal matches `thresholdSessionId` ownership.
- Validate session not expired/exhausted.
- Rate-limit and audit both endpoints.
- Never log ciphertext payloads.

## Client/Worker Integration Plan

### 1. WASM integration in passkey-confirm worker

- Add a Rust/WASM module in worker runtime that wraps `shamir-3-pass-rs` operations needed for:
  - key generation,
  - `E_k`/`D_k` transforms,
  - strict input validation,
  - buffer zeroization.
- Keep protocol execution in worker; main thread only persists opaque blob.

### 2. Worker message surface

Extend user-confirm worker message types (no legacy duplicates):

- `THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST`
- `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE`
- `THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED`

Behavior:

- `SEAL_AND_PERSIST`: worker caches plaintext + returns sealed blob for storage.
- `REHYDRATE`: worker accepts sealed blob, runs 3-pass unwrap, restores in-memory cache.
- `DELETE_PERSISTED`: explicit cleanup path.

### 3. Main-thread persistence adapter

- Add a wallet-origin adapter responsible only for:
  - writing sealed blob into `sessionStorage`,
  - reading blob during init/reload,
  - deleting on logout/expiry/account change.
- No plaintext PRF fields cross this boundary.

### 4. Refresh bootstrap

- During SDK init in wallet iframe mode:
  1. hydrate canonical threshold session (`thresholdEcdsaSessionStore`),
  2. load sealed PRF blob from `sessionStorage`,
  3. call worker `REHYDRATE`,
  4. mark warm session active if worker returns `ok`.

If rehydrate fails, fail closed and request passkey auth.

## Cleanup Rules (No Legacy Paths)

When this ships:

- Remove any direct/persistent plaintext PRF storage path (if introduced during transition).
- Do not keep a fallback that writes raw `prfFirstB64u` to storage.
- Keep exactly one persistence format: sealed blob `v1`.
- Reject unknown/legacy blob versions explicitly.

## Rollout Phases

1. Protocol + server endpoints:
   - implement endpoints, auth binding, and audit/rate limit.
2. Worker cryptography integration:
   - wire `shamir-3-pass-rs` and worker fetch calls.
3. Storage adapter + refresh bootstrap:
   - write/read sealed blob and rehydrate worker cache.
4. Removal of temporary compatibility code:
   - delete any old persistence branches before final merge.

## Phased TODO List

### Phase 1: Contract and Config

- [ ] Add `prfSessionPersistence` opt-in config to SDK config types (`none` default).
- [ ] Define shared request/response DTOs for `apply-server-layer` and `remove-server-layer`.
- [ ] Add server-side feature gate flag (disabled by default in production until rollout).
- [ ] Document cookie/JWT auth mode selection for worker fetch calls.

Exit criteria:

- [ ] API contracts are type-checked end-to-end.
- [ ] Feature is disabled unless explicitly opted in.

### Phase 2: Server Endpoints

- [ ] Implement `POST /threshold-ecdsa/prf-seal/apply-server-layer`.
- [ ] Implement `POST /threshold-ecdsa/prf-seal/remove-server-layer`.
- [ ] Bind endpoint authorization to threshold session ownership.
- [ ] Enforce expiry/remaining-uses checks before processing.
- [ ] Add route-level rate limiting and structured audit events.
- [ ] Ensure ciphertext payloads are redacted from logs.

Exit criteria:

- [ ] Authenticated happy path works for both endpoints.
- [ ] Unauthorized and cross-account attempts are rejected with typed errors.

### Phase 3: Worker Crypto Runtime (Lazy Loaded)

- [ ] Add worker-only runtime module wrapping `shamir-3-pass-rs`.
- [ ] Implement lazy import in passkey-confirm worker so crypto runtime loads on demand.
- [ ] Add worker handlers for `SEAL_AND_PERSIST` and `REHYDRATE`.
- [ ] Ensure ephemeral keys/intermediates are zeroized on success and error paths.
- [ ] Add timeout/cancellation handling for worker -> server protocol requests.

Exit criteria:

- [ ] `shamir-3-pass-rs` code is not loaded when feature is off.
- [ ] Worker can seal and rehydrate deterministically under test.

### Phase 4: Storage and Bootstrap Integration

- [ ] Add wallet-origin `sessionStorage` adapter for sealed PRF blobs (`v1` only).
- [ ] Persist sealed blob after successful login/bootstrap.
- [ ] On refresh, load sealed blob and call worker `REHYDRATE`.
- [ ] On logout/lock/session-expiry/account-switch, remove sealed blob.
- [ ] Clamp persisted TTL/remaining-uses to threshold session policy.

Exit criteria:

- [ ] Login -> refresh -> sign works without TouchID re-prompt.
- [ ] Tab close -> new tab requires TouchID.

### Phase 5: Cleanup (No Legacy Paths)

- [ ] Remove any temporary plaintext PRF persistence code used during migration.
- [ ] Reject unknown blob versions and delete invalid blobs.
- [ ] Remove dead compatibility branches from worker/message handlers.
- [ ] Update architecture docs to reflect sealed-only persistence model.

Exit criteria:

- [ ] Exactly one persistence format exists (`sealed v1`).
- [ ] No plaintext PRF appears in persistent storage in integration tests.

### Phase 6: Verification and Rollout

- [ ] Add unit tests for storage parsing, versioning, and policy clamping.
- [ ] Add unit tests for 3-pass roundtrip and malformed payload handling.
- [ ] Add wallet-iframe integration tests for refresh success and expiry fallback.
- [ ] Add security regression tests for auth, session mismatch, and logging redaction.
- [ ] Roll out behind opt-in to internal environments first, then staged external enablement.

Exit criteria:

- [ ] All new tests pass in CI.
- [ ] Production rollout checklist signed off with metrics and rollback plan.

## Test Plan

1. Unit tests (worker/WASM):
   - 3-pass math roundtrip and malformed input handling.
   - zeroization/cleanup hooks are invoked on success/failure.
2. Unit tests (storage):
   - serialize/deserialize sealed blob v1.
   - TTL/remaining-uses enforcement.
3. Integration tests (wallet iframe):
   - login once -> refresh -> sign succeeds without TouchID.
   - tab close -> new tab requires TouchID.
   - expired/exhausted session forces re-auth.
4. Security regression tests:
   - server rejects unauthenticated unwrap.
   - cross-account/session mismatch rejected.
   - no plaintext PRF in logs or persisted storage snapshots.

## Planned Touchpoints

- `client/src/core/types/secure-confirm-worker.ts`
- `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts` (rehydrate trigger integration only)
- `server/src/router/express/routes/thresholdEcdsa.ts`
- `server/src/router/cloudflare/routes/thresholdEcdsa.ts`
- new worker-facing Rust/WASM module for `shamir-3-pass-rs` bindings
