# Refactor 16: Post-Login Manual ECDSA Presign Prefill

Status: In progress  
Severity: High (first-transaction latency after login)  
Last updated: 2026-02-22

## 1. Problem Statement

Current threshold-ECDSA behavior still has a slow first transaction after login:

1. Login warm-up bootstraps a threshold ECDSA session, but does not prefill the client presign pool.
2. First sign often pays a full inline presign handshake (`/threshold-ecdsa/presign/init` + 6x `/presign/step`).
3. After sign success, post-sign refill runs, adding another ~5-6 seconds of presign traffic in logs.

Measured timing details are documented in:

- `docs/ecdsa_timings.md`

## 2. Scope and Decisions

1. Expose a manual callback to prefill ECDSA presignatures after successful threshold-signer login warm-up.
2. Keep login flow itself free of automatic prefill work.
3. Keep presign pool memory-only in this refactor (no IndexedDB persistence of presign shares).
4. Keep commit queue semantics unchanged (serialized commit, concurrent confirmers).
5. Use clean switch behavior (no legacy path, no feature flag).
6. Login prefill target should be conservative (`targetDepth=1`) to reduce relayer churn.
7. If prefill fails, login and subsequent sign flows remain functional via existing inline fallback.

## 3. Invariants

- No additional user prompts during prefill.
- No persistent storage of presign share material (`kShare`, `sigmaShare`) at rest.
- Same-account threshold commit serialization remains unchanged.
- Prefill scheduling remains deduped per pool key.
- Failure to prefill must not fail login.

## 4. Target Architecture

## 4.1 New Login Prefill Orchestrator

Add a dedicated client-side orchestration path to prefill one presignature after login warm-up:

1. Read canonical threshold ECDSA keyRef/session from existing login bootstrap result.
2. Verify warm session is active.
3. Dispense `PRF.first` once from threshold session cache.
4. Derive client secp256k1 signing share.
5. Trigger presign refill using existing coordinator primitives with conservative target depth.

## 4.2 Reuse Existing Components

Do not add duplicate protocol codepaths:

1. Reuse existing ECDSA share-derivation wasm helper.
2. Reuse existing presign refill scheduler/coordinator functions.
3. Reuse existing threshold session/keyRef sources established at login.

## 4.3 Runtime Behavior

1. Login only establishes the warm threshold session (no auto-prefill side effects).
2. App calls manual callback `auth.prefillThresholdEcdsaPresignPool(...)` after login when desired.
3. If user signs before callback or before prefill completion, existing inline presign fallback remains.
4. If callback prefill completes first, first user sign should typically skip inline presign.

## 5. Implementation Plan

## Phase 0: Baseline + Observability

- [x] Keep per-route timing logs on server (`durationMs`) for threshold ECDSA routes.
- [x] Document current latency profile and expected refill logs.

Files:

- `server/src/router/express/routes/thresholdEcdsa.ts`
- `docs/ecdsa_timings.md`

## Phase 1: Client Login Prefill API

- [x] Add a new signing-engine API entrypoint for login prefill (single-responsibility).
- [x] Validate required inputs (keyRef/session/prf cache state).
- [x] Reuse coordinator refill primitives instead of introducing new presign protocol code.
- [x] Return structured result: `scheduled | skipped | failed` with typed reason.

Suggested files:

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts` (new)
- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`

## Phase 2: Auth Callback Integration

- [x] Remove automatic login-triggered prefill from login flow.
- [x] Add manual callback `auth.prefillThresholdEcdsaPresignPool(...)` for explicit post-login warmup.
- [x] Keep callback best-effort with structured result (`scheduled | skipped | failed`).
- [x] Ensure callback works in both local and wallet-iframe mode.

Suggested files:

- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/types/sdkSentEvents.ts` (if new phases are added)

## Phase 3: Policy and Safety

- [x] Use conservative login prefill target depth (`1`) regardless of larger steady-state pool target.
- [x] Guard against low-remaining-uses sessions (skip prefill when budget too low).
- [x] Ensure duplicate login-triggered prefill requests are deduped by existing pool-key in-flight logic.

Suggested files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts` (if shared helper extraction is needed)

## Phase 4: Tests and Regression Guards

- [x] Unit: login threshold warm path does not auto-schedule prefill.
- [x] Unit: manual prefill callback forwards correctly in local and iframe mode.
- [ ] Unit: immediate first sign still succeeds if prefill races (fallback intact).
- [ ] Unit/Integration: when prefill completes first, first sign avoids inline `presign/init`.
- [ ] Guard: no IndexedDB writes for presign share material introduced by this refactor.

Suggested tests/files:

- `tests/unit/tatchiPasskey.loginThresholdWarm.unit.test.ts`
- `tests/unit/thresholdEcdsa.presignPoolRefill.unit.test.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/unit/thresholdEcdsa.noLegacySurface.guard.unit.test.ts`

## 6. Risks and Mitigations

1. Login prefill races with immediate user sign.  
Mitigation: keep existing inline presign fallback and commit-start guard behavior.

2. Prefill consumes session use budget unexpectedly.  
Mitigation: skip prefill when remaining uses are below a safe threshold.

3. Relayer load increase on high login volume.  
Mitigation: conservative login prefill depth (`1`) and per-pool dedupe.

4. Reintroducing duplicate presign orchestration logic.  
Mitigation: enforce reuse of coordinator/scheduler primitives and add guard tests.

## 7. Done Criteria

- [x] Threshold-signer login no longer auto-initiates ECDSA presign prefill.
- [x] Manual callback exists for explicit post-login prefill.
- [ ] First sign after login is usually warm when prefill has completed.
- [x] No IndexedDB persistence of presign shares is introduced.
- [ ] Existing sign correctness and queue invariants remain unchanged.
- [ ] Regression tests cover prefill scheduling, fallback, and non-fatal failure behavior.

## 8. Phased TODO List

## Immediate

- [x] Land Phase 1 prefill API and wiring in `SigningEngine`.
- [x] Land Phase 2 auth callback integration for explicit post-login scheduling.

## Next

- [ ] Land Phase 3 policy/safety guards (depth=1, low-use skip).
- [ ] Add structured login prefill diagnostics/events.

## Finalize

- [ ] Land Phase 4 tests + guardrails.
- [ ] Re-run targeted threshold ECDSA suites and compare first-sign latency before/after.
