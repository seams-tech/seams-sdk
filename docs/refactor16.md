# Refactor 16: Login-Time Background ECDSA Presign Prefill

Status: Planned  
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

1. Implement background presign prefill immediately after successful threshold-signer login warm-up.
2. Keep prefill non-blocking for login completion (best-effort).
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

1. On threshold-signer login success: schedule login prefill in background.
2. If user signs immediately and prefill is not done yet, existing inline presign fallback remains.
3. If prefill completes first, first user sign should typically skip inline presign.

## 5. Implementation Plan

## Phase 0: Baseline + Observability

- [x] Keep per-route timing logs on server (`durationMs`) for threshold ECDSA routes.
- [x] Document current latency profile and expected refill logs.

Files:

- `server/src/router/express/routes/thresholdEcdsa.ts`
- `docs/ecdsa_timings.md`

## Phase 1: Client Login Prefill API

- [ ] Add a new signing-engine API entrypoint for login prefill (single-responsibility).
- [ ] Validate required inputs (keyRef/session/prf cache state).
- [ ] Reuse coordinator refill primitives instead of introducing new presign protocol code.
- [ ] Return structured result: `scheduled | skipped | failed` with typed reason.

Suggested files:

- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts` (new)
- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts`

## Phase 2: Login Integration

- [ ] Trigger login prefill right after successful threshold ECDSA warm-up in login flow.
- [ ] Keep it best-effort and non-blocking for final login success response.
- [ ] Emit login progress diagnostics for prefill start/result (for debugging and telemetry).
- [ ] Ensure prefill is no-op when threshold warm mode is disabled.

Suggested files:

- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/types/sdkSentEvents.ts` (if new phases are added)

## Phase 3: Policy and Safety

- [ ] Use conservative login prefill target depth (`1`) regardless of larger steady-state pool target.
- [ ] Guard against low-remaining-uses sessions (skip prefill when budget too low).
- [ ] Ensure duplicate login-triggered prefill requests are deduped by existing pool-key in-flight logic.

Suggested files:

- `client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts` (if shared helper extraction is needed)

## Phase 4: Tests and Regression Guards

- [ ] Unit: login threshold warm path schedules prefill.
- [ ] Unit: prefill failure does not fail login.
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

- [ ] Threshold-signer login initiates background ECDSA presign prefill.
- [ ] Login success is not blocked by prefill completion.
- [ ] First sign after login is usually warm when prefill has completed.
- [ ] No IndexedDB persistence of presign shares is introduced.
- [ ] Existing sign correctness and queue invariants remain unchanged.
- [ ] Regression tests cover prefill scheduling, fallback, and non-fatal failure behavior.

## 8. Phased TODO List

## Immediate

- [ ] Land Phase 1 prefill API and wiring in `SigningEngine`.
- [ ] Land Phase 2 login integration with best-effort background scheduling.

## Next

- [ ] Land Phase 3 policy/safety guards (depth=1, low-use skip).
- [ ] Add structured login prefill diagnostics/events.

## Finalize

- [ ] Land Phase 4 tests + guardrails.
- [ ] Re-run targeted threshold ECDSA suites and compare first-sign latency before/after.
