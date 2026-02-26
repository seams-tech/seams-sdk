# PRF Session Persistence Plan (Sealed Refresh-Only)

Date updated: February 26, 2026

## Objective

Keep threshold signing unlocked across browser refresh in the same tab without requiring a new TouchID/WebAuthn prompt by implementing only:

- `signingSessionPersistenceMode: 'sealed_refresh_v1'` (opt-in)

This plan intentionally skips `plaintext_refresh_v1`.

## Scope

- Persist across refresh in the same tab.
- Do not persist across tab close.
- Wallet-iframe mode is the canonical runtime.
- Use `shamir-3-pass-rs`: https://github.com/peitalin/shamir-3-pass-rs

## Non-Goals

- XSS defense redesign (handled separately via cross-origin wallet iframe + CSP hardening).
- Surviving browser restart.
- Long-term key escrow.

## Target Design (`sealed_refresh_v1`)

1. `PRF.first` is obtained during login/auth and delivered to the passkey-confirm worker.
2. Worker runs 3-pass seal protocol and produces sealed blob `enc_s(PRF.first)` without revealing plaintext to server.
3. Main thread stores only sealed blob + metadata in wallet-origin `sessionStorage`.
4. After refresh, main thread reads sealed blob and sends it to worker.
5. Worker runs 3-pass unwrap with server and restores plaintext `PRF.first` into worker memory cache only.
6. Signing uses worker cache as today; no additional WebAuthn prompt unless record is missing/expired/invalid.

Plaintext `PRF.first` must never be persisted in `sessionStorage`, `localStorage`, or IndexedDB.

## 3-Pass Protocol

Notation:

- `E_k(x)`: commutative encryption with key `k`
- `D_k(x)`: corresponding decryption
- `k_s`: server KEK
- `k1`, `k2`: worker-ephemeral client keys from secure RNG

### A) Seal for Storage

1. Worker receives plaintext `PRF.first`.
2. Worker computes `a = E_k1(PRF)`.
3. Worker calls authenticated server endpoint with `a`.
4. Server returns `b = E_ks(a)`.
5. Worker computes `sealed = D_k1(b) = E_ks(PRF)`.
6. Worker zeroizes `k1`, `a`, `b` and asks main thread to persist `sealed`.

### B) Rehydrate After Refresh

1. Main thread reads `sealed = E_ks(PRF)` from `sessionStorage` and sends it to worker.
2. Worker computes `d = E_k2(sealed) = E_k2(E_ks(PRF))`.
3. Worker sends `d` to authenticated server endpoint.
4. Server returns `e = D_ks(d) = E_k2(PRF)`.
5. Worker computes `PRF = D_k2(e)` and repopulates in-memory PRF cache.
6. Worker zeroizes `k2`, `d`, `e`.

Server never sees plaintext `PRF`.

## Storage Model (Sealed Only)

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

- Clamp TTL and remaining uses to threshold-session policy.
- Delete on logout, lock, session expiry, account switch, exhaustion, unwrap failure, or shape/version mismatch.
- Reject unknown versions explicitly.

## Auth Model (Worker -> Server)

Either mode is supported:

1. `HttpOnly` cookie session (preferred):
   - Worker uses `fetch(..., { credentials: "include" })`.
   - CORS allows credentials and exact wallet origin.
2. Bearer JWT:
   - Worker sets `Authorization: Bearer <token>`.

Server authenticates before any 3-pass operation.

## API Contract (Server)

1. `POST /threshold-ecdsa/prf-seal/apply-server-seal`
   - Input: `ciphertext` (`E_k1(PRF)`), `thresholdSessionId`, metadata/version.
   - Output: `ciphertext` (`E_ks(E_k1(PRF))`), `keyVersion`, `expiresAtMs`, `remainingUses`.
2. `POST /threshold-ecdsa/prf-seal/remove-server-seal`
   - Input: `ciphertext` (`E_k2(E_ks(PRF))`), `thresholdSessionId`, `keyVersion`.
   - Output: `ciphertext` (`E_k2(PRF)`), `expiresAtMs`, `remainingUses`.

Server requirements:

- Enforce authenticated principal owns `thresholdSessionId`.
- Enforce session TTL/remainingUses.
- Rate-limit and audit both endpoints.
- Never log ciphertext payloads.

## Server Module Status (Completed)

- [x] Standalone server-SDK module for PRF seal/unlock routes.
- [x] Endpoints `apply-server-seal` and `remove-server-seal` with auth/session binding.
- [x] Router-option configuration surface for SDK consumers.
- [x] Service factory with pluggable session-policy adapter, cipher adapter, consume policy, guard/audit hooks.
- [x] ECDSA auth-session-store adapter for ownership + TTL/uses enforcement.
- [x] Helper builders for cipher adapter + route-options composition.
- [x] Rate-limit guard backends (in-memory/Upstash/Redis-TCP) wired.
- [x] Audit sink helper wired to structured logs/metrics.
- [x] Integration tests for owner mismatch, expired/exhausted session, status mapping, and audit redaction.

## Client/Worker Integration Plan (`sealed_refresh_v1`)

1. Config + gating:
   - support only `signingSessionPersistenceMode: 'none' | 'sealed_refresh_v1'` (default `none`),
   - enable sealed flow only when `sealed_refresh_v1` and wallet-iframe mode are active.
2. Worker runtime:
   - add worker-only lazy-loaded runtime wrapping `shamir-3-pass-rs`.
3. Worker message surface:
   - add `THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST`,
   - add `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE`,
   - add `THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED`.
4. Main-thread adapter:
   - add sealed storage adapter (`shamir3pass-v1`) persist/read/delete helpers.
5. TouchConfirm wiring:
   - seal on successful cache put/login bootstrap,
   - rehydrate on refresh from sealed record,
   - delete on clear/clear-all/logout/lock/switch/expiry/failure.
6. Failure behavior:
   - if sealed record missing/invalid/expired or unwrap fails, delete record and fail closed to passkey auth.

## Cleanup Rules (No Legacy Paths)

- Do not implement `plaintext_refresh_v1`.
- Remove/avoid any `plain-v1` storage paths and related worker message handling.
- Keep one steady-state persistence format: `shamir3pass-v1`.
- No hidden fallback that writes raw `prfFirstB64u`.

## Phased TODO List

### Phase 1 — Client Sealed Runtime + Wiring

- [ ] Add client opt-in config mode `sealed_refresh_v1` (`none` remains default).
- [ ] Add worker-only lazy-loaded `shamir-3-pass-rs` runtime.
- [ ] Implement worker seal/rehydrate handlers for 3-pass protocol.
- [ ] Add sealed storage adapter for `shamir3pass-v1`.
- [ ] Wire persist/rehydrate/delete flows in `TouchConfirmManager` and wallet bootstrap path.
- [ ] Enforce fail-closed invalidation behavior.

### Phase 2 — Legacy Removal + Contract Tightening

- [ ] Remove or block any `plain-v1` handling paths.
- [ ] Ensure config/type surfaces expose only `none` and `sealed_refresh_v1`.
- [ ] Reject unknown/legacy storage versions explicitly.

### Phase 3 — Tests + Rollout

- [ ] Worker/WASM tests for 3-pass roundtrip and malformed payload handling.
- [ ] Storage tests for sealed `v1` parse/serialize and TTL/remainingUses enforcement.
- [ ] Integration tests for login->refresh no TouchID, tab-close re-auth, session mismatch rejection.
- [ ] Security regression tests for auth rejection, cross-account mismatch, and no plaintext at-rest persistence.
- [ ] Verify runtime lazy-load behavior (loaded only when `sealed_refresh_v1` enabled).

Exit criteria:

- [ ] Login -> refresh -> sign succeeds without TouchID re-prompt.
- [ ] Tab close requires TouchID re-auth.
- [ ] No plaintext PRF persisted in steady state.
- [ ] `shamir-3-pass-rs` runtime only loads when `sealed_refresh_v1` is enabled.
- [ ] New tests pass in CI.

## Planned Touchpoints

- `client/src/core/types/secure-confirm-worker.ts`
- `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`
- `server/src/threshold/session/prfSessionSeal/`
- `server/src/router/relay.ts`
- `server/src/router/express/createRelayRouter.ts`
- `server/src/router/cloudflare/createCloudflareRouter.ts`
- `tests/relayer/prf-session-seal-router.test.ts`
- new worker-facing Rust/WASM module for `shamir-3-pass-rs` bindings
