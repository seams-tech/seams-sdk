# PRF Session Persistence Plan (`sealed_refresh_v1`)

Date updated: February 27, 2026

## Objective

Keep threshold signing unlocked across browser refresh in the same tab without requiring a new TouchID/WebAuthn prompt by implementing only:

- `signingSessionPersistenceMode: 'sealed_refresh_v1'` (opt-in)

This plan intentionally skips and removes plaintext persistence paths.

## Codebase Rescan Snapshot (Post-Refactor)

### Client state today

- `passkey-confirm.worker` currently stores PRF cache in memory only via:
  - `THRESHOLD_PRF_FIRST_CACHE_PUT`
  - `THRESHOLD_PRF_FIRST_CACHE_PEEK`
  - `THRESHOLD_PRF_FIRST_CACHE_DISPENSE`
  - `THRESHOLD_PRF_FIRST_CACHE_CLEAR`
  - `THRESHOLD_PRF_FIRST_CACHE_CLEAR_ALL`
  - files:
    - `client/src/core/types/secure-confirm-worker.ts`
    - `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
    - `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- Active signing session IDs are in-memory only (`Map`) in:
  - `client/src/core/signingEngine/api/session/signingSessionState.ts`
- Canonical threshold ECDSA session record is already persisted in `sessionStorage`:
  - `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`
- Login state in threshold mode currently requires an active warm session:
  - `client/src/core/TatchiPasskey/login.ts`
- There is no current config surface for PRF session persistence mode in:
  - `client/src/core/types/tatchi.ts`
  - `client/src/core/config/configBuilder.ts`
  - `client/src/core/config/defaultConfigs.ts`

### Server state today

`prfSessionSeal` server module is implemented and integrated:

- module: `server/src/threshold/session/prfSessionSeal/`
- route option: `server/src/router/relay.ts`
- router wiring:
  - `server/src/router/express/createRelayRouter.ts`
  - `server/src/router/cloudflare/createCloudflareRouter.ts`
- integration tests:
  - `tests/relayer/prf-session-seal-router.test.ts`

## Target Behavior

1. During login/bootstrap, worker seals `PRF.first` via 3-pass and main thread persists only sealed blob `enc_s(PRF.first)` in wallet-origin `sessionStorage`.
2. After refresh, client resolves canonical `thresholdSessionId`, restores active warm session pointer, and worker rehydrates plaintext PRF from sealed blob via 3-pass.
3. Signing continues without TouchID re-prompt unless sealed record/session is missing, expired, exhausted, or invalid.
4. Plaintext `PRF.first` is never persisted at rest.

## Protocol (Unchanged)

Notation:

- `E_k(x)`: commutative encryption with key `k`
- `D_k(x)`: corresponding decryption
- `k_s`: server KEK
- `k1`, `k2`: worker-ephemeral client keys

Seal:

1. Worker computes `a = E_k1(PRF)`.
2. Server returns `b = E_ks(a)`.
3. Worker computes `sealed = D_k1(b) = E_ks(PRF)`.
4. Persist `sealed` only.

Rehydrate:

1. Worker computes `d = E_k2(E_ks(PRF))`.
2. Server returns `e = D_ks(d) = E_k2(PRF)`.
3. Worker computes `PRF = D_k2(e)`.
4. Keep plaintext only in worker memory.

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

- Clamp TTL/remaining uses to threshold session policy.
- Delete on logout, lock, account switch, expiry, exhaustion, unwrap failure, or schema/version mismatch.
- Reject unknown versions.

## Implementation Plan (Refactored Codebase)

### Phase 1 — Config + Contracts

- [ ] Add config mode surface:
  - `TatchiConfigsInput.signingSessionPersistenceMode?: 'none' | 'sealed_refresh_v1'`
  - resolved config under signing domain (default `none`)
  - files:
    - `client/src/core/types/tatchi.ts`
    - `client/src/core/config/configBuilder.ts`
    - `client/src/core/config/defaultConfigs.ts`
- [ ] Thread mode into touchConfirm manager construction:
  - `client/src/core/signingEngine/bootstrap/managerAssembly.ts`
  - `client/src/core/types/secure-confirm-worker.ts`
  - `client/src/core/signingEngine/touchConfirm/types.ts`
  - `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`

### Phase 2 — Worker Sealed Runtime + Message Surface

- [ ] Add worker-only lazy-loaded `shamir-3-pass-rs` runtime wrapper.
- [ ] Add worker message types:
  - `THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST`
  - `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE`
  - `THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED`
- [ ] Implement handlers in:
  - `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- [ ] Keep existing `PUT/PEEK/DISPENSE/CLEAR` semantics as canonical cache operations (no duplicate legacy APIs).

### Phase 3 — Main-Thread Sealed Adapter + Session Restore

- [ ] Add sealed storage adapter module for `shamir3pass-v1` read/write/delete.
  - suggested location: `client/src/core/signingEngine/api/session/prfSessionSealedStore.ts`
- [ ] Integrate adapter into `TouchConfirmManager`:
  - seal+persist on successful PRF cache put/bootstrap
  - update persisted `remainingUses/expiresAtMs` after dispense
  - delete on clear/clearAll/failure paths
- [ ] Restore active session ID after refresh using canonical threshold session record:
  - read `thresholdSessionId` from `thresholdEcdsaSessionStore`
  - set active signing session ID before first threshold sign or warm-session status check
  - files:
    - `client/src/core/signingEngine/api/session/signingSessionState.ts`
    - `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
    - `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`
    - `client/src/core/TatchiPasskey/login.ts`

### Phase 4 — Build + Packaging for New WASM Runtime

- [ ] Add wasm runtime crate/package for `shamir-3-pass-rs` worker use.
- [ ] Wire SDK build scripts to compile and copy new wasm artifact(s):
  - `sdk/build-paths.ts`
  - `sdk/scripts/build/build-dev.sh`
  - `sdk/scripts/build/build-prod.sh`
- [ ] Ensure runtime is lazy-loaded only when `sealed_refresh_v1` is enabled.

### Phase 5 — Tests + Rollout

- [ ] Extend worker router/unit tests for new message routes:
  - `tests/unit/touchConfirm.workerRouter.unit.test.ts`
- [ ] Keep/extend server route tests:
  - `tests/relayer/prf-session-seal-router.test.ts`
- [ ] Add integration tests for:
  - login -> refresh -> sign without TouchID re-prompt
  - tab close -> TouchID required
  - malformed/expired/mismatched sealed record -> fail closed
  - no plaintext PRF in persistent storage snapshots
- [ ] Verify lazy-load gating for sealed runtime.

## Server Module Status (Already Done)

- [x] Standalone PRF seal module and route wiring.
- [x] Auth/session ownership checks.
- [x] Pluggable cipher/session policy/guard/audit composition.
- [x] Rate-limit and audit integrations.
- [x] Integration tests covering ownership/expiry/exhaustion/status mapping/redaction.

## Cleanup Rules (No Legacy Paths)

- No `plaintext_refresh_v1`.
- No `plain-v1` records.
- No fallback that writes raw `prfFirstB64u`.
- One steady-state format only: `shamir3pass-v1`.

## Exit Criteria

- [ ] `sealed_refresh_v1` works end-to-end in wallet-iframe mode.
- [ ] Refresh in same tab does not require TouchID re-prompt.
- [ ] Tab close still requires TouchID re-auth.
- [ ] Plaintext PRF is never persisted at rest.
- [ ] All new client/server tests pass in CI.
