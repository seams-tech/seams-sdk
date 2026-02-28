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
- Sealed refresh main-thread storage adapter is now present:
  - `client/src/core/signingEngine/api/session/prfSessionSealedStore.ts`
  - records are keyed by `thresholdSessionId` in wallet-origin `sessionStorage`
  - touchConfirm now wires best-effort persist/rehydrate hooks around `peek/dispense/clear`
- Active signing session IDs are in-memory only (`Map`) in:
  - `client/src/core/signingEngine/api/session/signingSessionState.ts`
  - now with canonical fallback restore via threshold session record lookup in:
    - `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
- Threshold Ed25519 auth session JWT is now persisted by `thresholdSessionId` in wallet-origin `sessionStorage`
  and reused after refresh:
  - `client/src/core/signingEngine/threshold/session/ed25519AuthSession.ts`
  - `client/src/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.ts`
- Canonical threshold ECDSA session record is already persisted in `sessionStorage`:
  - `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`
- Login state in threshold mode currently requires an active warm session:
  - `client/src/core/TatchiPasskey/login.ts`
- `signingSessionPersistenceMode` config surface is now wired (`none` | `sealed_refresh_v1`):
  - `client/src/core/types/tatchi.ts`
  - `client/src/core/config/configBuilder.ts`
  - `client/src/core/config/defaultConfigs.ts`
- Shamir runtime backend now uses dedicated Rust WASM wrapper crate:
  - `wasm/shamir3pass_runtime/`
  - lazy-loaded in worker via:
    - `client/src/core/signingEngine/workerManager/workers/shamir3pass/runtime.ts`
  - build/copy pipeline updated to emit:
    - `dist/workers/shamir3pass_runtime.js`
    - `dist/workers/shamir3pass_runtime_bg.wasm`

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

## Operational Bootstrap

Generate matching Shamir 3-pass key material for server + client env:

```bash
pnpm prf-seal:keygen
```

The command emits:

- server: `PRF_SESSION_SEAL_KEY_VERSION`, `SHAMIR_P_B64U`, `SHAMIR_E_S_B64U`, `SHAMIR_D_S_B64U`
- client: `VITE_SIGNING_SESSION_PERSISTENCE_MODE=sealed_refresh_v1`,
  `VITE_SIGNING_SESSION_SEAL_KEY_VERSION`, `VITE_SIGNING_SESSION_SHAMIR_P_B64U`

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

- [x] Add config mode surface:
  - `TatchiConfigsInput.signingSessionPersistenceMode?: 'none' | 'sealed_refresh_v1'`
  - `TatchiConfigsInput.signingSessionSeal?: { keyVersion?: string; shamirPrimeB64u?: string }`
  - resolved config under signing domain (default `none`)
  - files:
    - `client/src/core/types/tatchi.ts`
    - `client/src/core/config/configBuilder.ts`
    - `client/src/core/config/defaultConfigs.ts`
- [x] Thread mode into touchConfirm manager construction:
  - `client/src/core/signingEngine/bootstrap/managerAssembly.ts`
  - `client/src/core/types/secure-confirm-worker.ts`
  - `client/src/core/signingEngine/touchConfirm/types.ts`
  - `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`

### Phase 2 — Worker Sealed Runtime + Message Surface

- [x] Add worker-only lazy runtime wrapper for Shamir 3-pass operations.
- [x] Swap runtime backend to `shamir-3-pass-rs` WASM crate/package.
- [x] Add worker message types:
  - `THRESHOLD_PRF_FIRST_CACHE_SEAL_AND_PERSIST`
  - `THRESHOLD_PRF_FIRST_CACHE_REHYDRATE`
  - `THRESHOLD_PRF_FIRST_CACHE_DELETE_PERSISTED`
- [x] Implement full handlers in:
  - `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- [x] Add worker route fetch integration:
  - `POST /threshold-ecdsa/prf-seal/apply-server-seal`
  - `POST /threshold-ecdsa/prf-seal/remove-server-seal`
- [x] Keep existing `PUT/PEEK/DISPENSE/CLEAR` semantics as canonical cache operations (no duplicate legacy APIs).

### Phase 3 — Main-Thread Sealed Adapter + Session Restore

- [x] Add sealed storage adapter module for `shamir3pass-v1` read/write/delete.
  - suggested location: `client/src/core/signingEngine/api/session/prfSessionSealedStore.ts`
- [x] Integrate adapter plumbing into `TouchConfirmManager`:
  - best-effort seal-on-peek (when active cache exists)
  - rehydrate-on-peek miss from sealed record
  - update persisted `remainingUses/expiresAtMs` after dispense
  - delete on clear/clearAll/terminal failure paths
- [x] Finalize seal+rehydrate integration path (no worker placeholder path remains).
- [x] Restore active session ID after refresh for warm-session status checks:
  - read `thresholdSessionId` from `thresholdEcdsaSessionStore`
  - lazily set active signing session ID when `getWarmSigningSessionStatus(...)` runs
  - files:
    - `client/src/core/signingEngine/api/session/signingSessionState.ts`
    - `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`
    - `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSessionStore.ts`

### Phase 4 — Build + Packaging for New WASM Runtime

- [x] Add wasm runtime crate/package for `shamir-3-pass-rs` worker use (replace current BigInt runtime backend).
- [x] Wire SDK build scripts to compile and copy new wasm artifact(s):
  - `sdk/build-paths.ts`
  - `sdk/scripts/build/build-dev.sh`
  - `sdk/scripts/build/build-prod.sh`
- [x] Ensure runtime is lazy-loaded only when `sealed_refresh_v1` is enabled.

### Phase 5 — Tests + Rollout

- [x] Extend worker router/unit tests for new message routes:
  - `tests/unit/touchConfirm.workerRouter.unit.test.ts`
  - includes sealed rehydrate flow, non-sealed gating, and expired-record fail-closed coverage
- [x] Keep/extend server route tests:
  - `tests/relayer/prf-session-seal-router.test.ts`
  - includes out-of-range Shamir ciphertext rejection on `apply-server-seal`
- [ ] Add integration tests for:
  - [x] login -> refresh -> sign without TouchID re-prompt
  - [x] tab close -> TouchID required
  - [x] malformed/expired/mismatched sealed record -> fail closed (unit-level coverage in place)
  - [x] no plaintext PRF in persistent storage snapshots (unit-level coverage in place)
- [x] Verify lazy-load gating for sealed runtime.
  - `tests/unit/touchConfirm.workerRouter.unit.test.ts` covers `signingSessionPersistenceMode: 'none'` path with no rehydrate attempt

### Phase 6 — Opt-in Hardening + API Polish

- [x] Require explicit seal material when enabled:
  - fail fast if `signingSessionPersistenceMode === 'sealed_refresh_v1'` without `signingSessionSeal.shamirPrimeB64u`
  - reject non-base64url `shamirPrimeB64u`
  - file:
    - `client/src/core/config/configBuilder.ts`
- [x] Strip seal config when mode is disabled:
  - do not forward `signingSessionSeal` to wallet host when mode is `none`
  - file:
    - `client/src/core/WalletIframe/client/router.ts`
    - `client/src/core/TatchiPasskey/walletIframeCoordinator.ts`
    - `client/src/core/WalletIframe/TatchiPasskeyIframe.ts`
    - `client/src/core/WalletIframe/host/context.ts`
- [x] Hard-block sealed worker paths when mode is disabled:
  - `sealAndPersist` / `rehydrate` return `not_enabled` without posting worker messages
  - file:
    - `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- [x] Add tests for mode-gated behavior + fail-fast config:
  - `tests/unit/touchConfirm.workerRouter.unit.test.ts`
  - `tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts`
- [x] Scoped validation passes for sealed refresh + opt-in hardening:
  - `pnpm -C tests exec playwright test ./unit/touchConfirm.workerRouter.unit.test.ts ./unit/walletIframe.signerModeConfigPropagation.unit.test.ts ./e2e/thresholdEcdsa.sealedRefresh.walletIframe.test.ts`
  - `pnpm -C sdk build`

### Phase 7 — Consumer Integration Polish

- [x] Add SDK-facing sealed refresh integration guidance and config snippet:
  - `docs/signing-sessions.md`
- [x] Document explicit rollout + failure semantics:
  - same-tab refresh reuse, new-tab re-auth, fail-closed on invalid sealed state
  - `docs/signing-sessions.md`

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

- [x] `sealed_refresh_v1` works end-to-end in wallet-iframe mode.
- [x] Refresh in same tab does not require TouchID re-prompt.
- [x] Tab close still requires TouchID re-auth.
- [x] Plaintext PRF is never persisted at rest.
- [ ] All new client/server tests pass in CI.
