# PRF Session Persistence Plan (Refresh-Only)

Date updated: February 26, 2026

## Objective

Keep threshold signing unlocked across browser refresh in the same tab, without requiring a new TouchID/WebAuthn prompt, using a two-phase rollout:

- Phase 1: plaintext `PRF.first` persisted in wallet-origin `sessionStorage` for fast delivery.
- Phase 2: replace plaintext persistence with `shamir-3-pass-rs` sealed persistence.

Scope for this plan:

- Persist across refresh.
- Do not persist across tab close.
- Wallet-iframe mode is the canonical runtime.
- Use `shamir-3-pass-rs`: https://github.com/peitalin/shamir-3-pass-rs

## Non-Goals

- XSS defense redesign (already handled separately via cross-origin wallet iframe + CSP hardening).
- Surviving browser restart.
- Long-term key escrow.

## Two-Phase Delivery Strategy

### Phase 1 (Interim): Plaintext Session Storage

- Store plaintext `prfFirstB64u` in wallet-origin `sessionStorage`.
- Rehydrate passkey-confirm worker cache from `sessionStorage` after refresh.
- Restrict to wallet-iframe runtime and tab lifetime only.
- Keep strict TTL/remaining-uses/cleanup semantics aligned with threshold session policy.

### Phase 2 (Target): Sealed Session Storage with `shamir-3-pass-rs`

- Replace plaintext record with sealed blob `enc_s(PRF.first)` in `sessionStorage`.
- Perform seal/rehydrate protocol in worker using `shamir-3-pass-rs`.
- Keep plaintext only in worker memory and remove Phase 1 plaintext path.

## Phase 1 Interim Design (Plaintext)

1. `PRF.first` is obtained during login/auth and delivered to the passkey-confirm worker.
2. Main thread persists `prfFirstB64u` plus session metadata in wallet-origin `sessionStorage`.
3. After refresh, main thread loads the record and asks worker to rehydrate in-memory cache.
4. Signing uses worker cache as today; no additional WebAuthn prompt unless record is missing/expired/invalid.

## Phase 2 Target Design (Sealed)

1. `PRF.first` is obtained during login/auth and delivered to the passkey-confirm worker.
2. Worker uses `shamir-3-pass-rs` to produce a server-layer encrypted blob `enc_s(PRF.first)` without revealing plaintext to server.
3. Main thread stores only the sealed blob in wallet-origin `sessionStorage`.
4. After refresh, main thread reads sealed blob and sends it to worker.
5. Worker performs 3-pass unwrap with server and restores plaintext `PRF.first` into worker memory cache only.
6. Signing uses worker cache as today; no additional WebAuthn prompt unless sealed blob is missing/expired/invalid.

In this target phase, plaintext `PRF.first` never lands in `sessionStorage`, `localStorage`, or IndexedDB.

## Phase 2 Protocol

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

### Phase 1 Key (Plaintext)

Wallet-origin `sessionStorage` key:

- `tatchi:threshold-prf-plain:v1:<thresholdSessionId>`

Value shape:

```json
{
  "v": 1,
  "alg": "plain-v1",
  "thresholdSessionId": "....",
  "prfFirstB64u": "....",
  "expiresAtMs": 0,
  "remainingUses": 0,
  "updatedAtMs": 0
}
```

### Phase 2 Key (Sealed)

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
- Phase 2 must never store raw `prfFirstB64u`.

## Auth Model for Worker -> Server (Phase 2)

Either auth mode is supported:

1. `HttpOnly` cookie session (preferred when available):
   - Worker `fetch(..., { credentials: "include" })`.
   - Cross-origin CORS must allow credentials and exact wallet origin.
2. Bearer JWT:
   - Worker sets `Authorization: Bearer <token>`.

Both modes require server-side auth before any 3-pass operation.

## API Contract (Server, Phase 2)

Add dedicated authenticated endpoints:

1. `POST /threshold-ecdsa/prf-seal/apply-server-seal`
   - Input: `ciphertext` (`E_k1(PRF)`), `thresholdSessionId`, metadata/version.
   - Output: `ciphertext` (`E_ks(E_k1(PRF))`), `keyVersion`, `expiresAtMs`, `remainingUses`.
2. `POST /threshold-ecdsa/prf-seal/remove-server-seal`
   - Input: `ciphertext` (`E_k2(E_ks(PRF))`), `thresholdSessionId`, `keyVersion`.
   - Output: `ciphertext` (`E_k2(PRF)`), `expiresAtMs`, `remainingUses`.

Server requirements:

- Enforce authenticated principal matches `thresholdSessionId` ownership.
- Validate session not expired/exhausted.
- Rate-limit and audit both endpoints.
- Never log ciphertext payloads.

## Server SDK Module Shape (Phase 2)

Server-side shamir3pass unlock routes must be implemented as a standalone module, not embedded directly inside existing threshold ECDSA route files.

Module requirements:

- Provide a dedicated server-SDK module (for example `server/src/threshold/session/prfSessionSeal/*`) with:
  - route handlers for `apply-server-seal` and `remove-server-seal`,
  - request/response validation,
  - auth/session ownership checks,
  - audit/rate-limit hooks,
  - pluggable cryptography adapter around `shamir-3-pass-rs` runtime.
- Export explicit registration helpers for both router stacks:
  - Express registration function,
  - Cloudflare handler/registration function.
- Expose configuration via server SDK/router options so apps can enable/disable and configure routes without patching core route files.
- Keep module loading opt-in and fail-closed when module or config is absent.

Integration requirements:

- `createRelayRouter(...)` and `createCloudflareRouter(...)` should call module registration only when the module is configured/enabled.
- Existing threshold ECDSA route modules should remain focused on core ECDSA flows; no duplicate unlock logic should be scattered across route files.

## Client/Worker Integration Plan

### Phase 1 Integration (Plaintext)

1. Worker message surface:
   - add `THRESHOLD_PRF_FIRST_CACHE_PERSIST_PLAINTEXT`,
   - add `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE_PLAINTEXT`,
   - add `THRESHOLD_PRF_FIRST_CACHE_DELETE_PLAINTEXT`.
2. Main-thread adapter:
   - persist/read/delete plaintext `sessionStorage` record (`plain-v1`) on wallet origin.
3. Refresh bootstrap:
   - hydrate canonical threshold session (`thresholdEcdsaSessionStore`),
   - load plaintext record from `sessionStorage`,
   - call worker plaintext rehydrate handler,
   - mark warm session active on success.
4. Failure behavior:
   - if missing/expired/invalid, fail closed and request passkey auth.

### Phase 2 Integration (Sealed with `shamir-3-pass-rs`)

1. WASM integration in passkey-confirm worker:
   - add a worker runtime module wrapping `shamir-3-pass-rs`,
   - keep protocol execution in worker; main thread persists opaque blob only.
2. Worker message surface:
   - add `THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST`,
   - add `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE`,
   - add `THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED`.
3. Main-thread adapter:
   - replace plaintext record handling with sealed record handling (`shamir3pass-v1`).
4. Refresh bootstrap:
   - same flow as Phase 1, but with sealed record + 3-pass unwrap.
5. Failure behavior:
   - if unwrap fails, delete sealed record and request passkey auth.

## Cleanup Rules (No Legacy Paths)

During rollout:

- Phase 1 explicitly allows plaintext `plain-v1` storage as an interim step.
- Phase 2 must remove `plain-v1` persistence and all related worker message paths.
- Do not keep a hidden fallback that writes raw `prfFirstB64u` once Phase 2 is enabled.
- Keep exactly one steady-state persistence format after Phase 2: sealed blob `v1`.
- Reject unknown/legacy blob versions explicitly.

## Rollout Phases

1. Phase 1: plaintext `sessionStorage` persistence in wallet iframe mode.
2. Phase 2: `shamir-3-pass-rs` sealed persistence replacing plaintext.

## Phased TODO List

### Phase 1: Plaintext Session Storage (Interim)

- [ ] Add client opt-in config mode `plaintext_refresh_v1` (`none` remains default).
- [ ] Add worker message handlers for plaintext persist/rehydrate/delete.
- [ ] Add wallet-origin `sessionStorage` adapter for `plain-v1` records.
- [ ] Persist plaintext PRF record after successful login/bootstrap.
- [ ] Rehydrate worker cache from `plain-v1` record on refresh.
- [ ] Clear `plain-v1` record on logout/lock/session-expiry/account-switch.
- [ ] Add integration tests for refresh success, tab-close re-auth, and fail-closed invalid record handling.

Exit criteria:

- [ ] Login -> refresh -> sign succeeds without TouchID re-prompt.
- [ ] Tab close requires TouchID re-auth.
- [ ] Feature is off unless explicitly opted in.

### Phase 2: `shamir-3-pass-rs` Sealed Storage (Target)

- [ ] Add client opt-in config mode `sealed_refresh_v1`.
- [x] Add server-SDK standalone module for PRF seal/unlock routes.
- [x] Add server endpoints `apply-server-seal` and `remove-server-seal` via that module with auth/session binding.
- [x] Add router-option configuration surface to enable/configure module from server SDK consumers.
- [x] Add server service factory with pluggable session-policy adapter, cipher adapter, consume policy, and guard/audit hooks.
- [x] Add ECDSA auth-session-store adapter for session ownership + TTL/uses enforcement in PRF seal routes.
- [x] Add server helper builders for cipher adapter and route-options composition.
- [ ] Add worker-only lazy-loaded runtime wrapping `shamir-3-pass-rs`.
- [ ] Implement worker seal/rehydrate handlers for 3-pass protocol.
- [ ] Replace `plain-v1` read/write paths with sealed `v1` read/write paths.
- [ ] Remove Phase 1 plaintext worker/storage code after Phase 2 stabilization.
- [ ] Add tests for 3-pass roundtrip, malformed payloads, auth rejection, and log redaction.

Next server-side implementation steps:

- [x] Implement `PrfSessionSealCipherAdapter` with `shamir-3-pass-rs` bindings.
- [x] Add reusable helper factories for server-side rate-limiter guard and audit sink.
- [x] Wire host-specific rate-limiter backend (in-memory/Upstash/Redis-TCP) through guard helper for both routes.
- [x] Wire audit sink helper to existing structured logs/metrics pipeline.
- [x] Add integration tests for owner mismatch, expired/exhausted session, route status mapping, and audit redaction.

Exit criteria:

- [ ] No plaintext PRF is persisted in steady state.
- [ ] `shamir-3-pass-rs` runtime is loaded only when `sealed_refresh_v1` is enabled.
- [ ] All new tests pass in CI.

## Test Plan

1. Phase 1 tests (plaintext path):
   - login once -> refresh -> sign succeeds without TouchID.
   - tab close -> new tab requires TouchID.
   - malformed/expired `plain-v1` record fails closed to re-auth.
2. Phase 2 worker/WASM tests (sealed path):
   - 3-pass math roundtrip and malformed payload handling.
   - zeroization/cleanup hooks are invoked on success/failure.
3. Phase 2 storage tests:
   - serialize/deserialize sealed blob `v1`.
   - TTL/remaining-uses enforcement and legacy record rejection.
4. Phase 2 security regression tests:
   - server rejects unauthenticated unwrap.
   - cross-account/session mismatch rejected.
   - no plaintext PRF in persistent storage snapshots in steady state.

## Planned Touchpoints

- `client/src/core/types/secure-confirm-worker.ts`
- `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts` (rehydrate trigger integration only)
- new server SDK module for shamir unlock routes (for example under `server/src/threshold/session/prfSessionSeal/`)
- `server/src/router/relay.ts` (router option surface for module config)
- `server/src/router/express/createRelayRouter.ts` (module registration wiring)
- `server/src/router/cloudflare/createCloudflareRouter.ts` (module registration wiring)
- `server/src/threshold/session/prfSessionSeal/service.ts` (session-guarded route service factory)
- `server/src/threshold/session/prfSessionSeal/guards/index.ts` (guard composition + rate-limit guard helpers)
- `server/src/threshold/session/prfSessionSeal/guards/backends.ts` (in-memory/Upstash/Redis-TCP limiter backends)
- `server/src/threshold/session/prfSessionSeal/observability/audit.ts` (audit sink helpers)
- `server/src/threshold/session/prfSessionSeal/routesOptions.ts` (module config composition)
- `server/src/threshold/session/prfSessionSeal/crypto/cipher.ts` (cipher adapters + shamir 3-pass runtime binding surface)
- `tests/relayer/prf-session-seal-router.test.ts` (server route integration tests)
- new worker-facing Rust/WASM module for `shamir-3-pass-rs` bindings
