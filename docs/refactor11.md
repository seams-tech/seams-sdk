# Refactor 11: Threshold ECDSA Session + KeyRef Ownership Hardening

Status: Proposed  
Severity: High (prompt-order regressions, stale-session signing failures, hidden fallback behavior)  
Last updated: 2026-02-21

## 1. Problem Statement

Recent regressions came from state ownership drift:

1. KeyRef/session state was resolved from multiple places (in-memory state, session storage, worker cache, returned login payload).
2. Bootstrap could happen outside the canonical login/provisioning path, causing extra TouchID prompts and session churn.
3. Signing code still had fallback branches that accepted stale/legacy keyRef/session shapes instead of failing fast.
4. Worker/session reset events (reload, iframe restart, worker restart) had no explicit re-hydration contract, so behavior depended on whatever stale keyRef was still around.
5. Rapid Tempo/EVM clicks hit a hard in-flight rejection instead of serializing safely per account.
6. Temporary debug trace logs were added across bootstrap/signing paths and must be removed after stabilization.

Observed failures matched this exactly:

- `[chains] threshold signingSession is not_found; reconnect threshold session before signing`
- Sign flow appearing stuck before useful UI/error feedback
- Extra TouchID prompts during login/provisioning

## 2. Decisions (Answers to the 5 Questions)

1. Reintroducing in-memory-first keyRef resolution  
Decision: **Yes, remove in-memory keyRef as an authority.**  
In-memory state can exist only as a UI mirror of canonical persisted state.

2. Multiple writers for keyRef/session  
Decision: **Yes, consolidate to a single writer + single read API.**  
No direct writes from feature/UI files.

3. Unconditional post-login bootstrap  
Decision: **Yes, remove it.**  
Bootstrap must occur only inside explicit provisioning paths (login/registration/manual reconnect), never as hidden post-login side effects.

4. Login refactor drifting from thresholdEcdsaKeyRef contract + reset edge cases  
Decision: **Enforce strict login contract + explicit session recovery state machine.**  
If threshold mode is required and login cannot return/store a valid threshold keyRef/session bundle, login fails.

5. Silent fallback to old keyRef/session fields  
Decision: **Yes, remove silent fallbacks.**  
Fail fast with typed errors and a single reprovision/reconnect path.

6. Rapid successive threshold sign requests (Tempo + EVM)  
Decision: **Implement a per-account FIFO queue in SDK path now.**  
Do not allow concurrent threshold ECDSA signing per account, but do serialize requests instead of rejecting with `signing_in_progress`.

7. Temporary debug logs added during incident triage  
Decision: **Remove them before final merge/release.**  
Keep only durable telemetry/typed errors; delete ad-hoc stage-level console traces.

## 3. Non-Negotiable Invariants

- Threshold ECDSA signing reads keyRef/session from one canonical store only.
- `signTempo`/`signTempoWithThresholdEcdsa` do not trigger hidden bootstrap.
- No legacy fallback for participant IDs, JWT, or session ID.
- In threshold-signer warm-session mode, successful login must produce a valid threshold ECDSA keyRef/session bundle.
- Worker reset results in deterministic typed status (`not_found`/`expired`/`exhausted`) and explicit reconnect guidance, never silent retry with stale state.
- Threshold ECDSA sign requests for the same account are serialized FIFO across Tempo and EVM in SDK path.
- No temporary `[threshold-trace]` console instrumentation remains in steady-state build.

## 4. Target Architecture

### 4.1 Canonical State

Introduce a single threshold ECDSA session/keyRef store in SDK domain (wallet origin), e.g.:

- `nearAccountId`
- `chain` (`tempo` / `evm`)
- `relayerUrl`, `relayerKeyId`
- `clientVerifyingShareB64u`
- `participantIds` (required)
- `thresholdSessionKind`, `thresholdSessionId`, `thresholdSessionJwt` (if JWT mode)
- `expiresAtMs`, `remainingUses`
- `updatedAtMs`, `source` (`login` | `registration` | `manual-bootstrap`)

### 4.2 Ownership

- Writers: login threshold warm-up, registration threshold provisioning, explicit manual reconnect flow.
- Readers: signing flows only.
- UI layer: read-only mirrors for display. No direct mutation of keyRef/session state.

### 4.3 Flow Boundaries

1. **Login/provisioning** mints threshold ECDSA session and writes canonical record.
2. **Signing** validates canonical record + worker cache status (`peekPrfFirstForThresholdSession`) before confirmation orchestration.
3. If invalid/missing, return typed error and route user to explicit reconnect/provision action.

### 4.4 Per-Account Queueing Model (Tempo/EVM)

- Queue scope: `nearAccountId`.
- Queue domain: threshold ECDSA sign requests (`senderSignatureAlgorithm=secp256k1`) across both Tempo and EVM.
- Ordering: FIFO.
- Behavior: second click is queued (not rejected), and starts after previous request completes/fails/cancels.
- Cancellation: queued items can be cancelled before start via existing abort/cancel signal path.
- Guardrails:
  - bounded queue length (fail fast with typed `queue_overflow` if exceeded),
  - queue item timeout budget,
  - deterministic teardown on engine destroy/logout.

## 5. Implementation Plan

## Phase 0: Immediate Guardrails (fail-closed)

- [ ] Add strict assertions in login path:
  - If threshold warm-up is required, missing `thresholdEcdsaKeyRef` or missing session fields is a hard error.
- [ ] Remove hidden post-login bootstrap triggers from UI/demo flows.
- [ ] Ensure sign path fails before signing orchestration when canonical threshold session is missing/stale.

Files:

- `client/src/core/TatchiPasskey/login.ts`
- `examples/tatchi-site/src/components/PasskeyLoginMenu.tsx`
- `examples/tatchi-site/src/components/DemoPage.tsx`
- `examples/tatchi-site/src/utils/thresholdSigners.ts`

## Phase 0.5: SDK Per-Account Queue (implement now)

- [ ] Replace reject-only in-flight gate with queueing gate for threshold ECDSA sign requests.
- [ ] Serialize Tempo + EVM secp256k1 sign requests per `nearAccountId`.
- [ ] Preserve cancellation semantics for queued requests (drop before execution when cancelled).
- [ ] Add typed queue overflow/timeout errors.
- [ ] Ensure queue is cleared on logout/destroy.

Files:

- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaSignInFlightGate.ts`
- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/signingEngine/api/tempoSigning.ts`

## Phase 1: Single Source of Truth for Threshold ECDSA

- [ ] Add a dedicated threshold ECDSA state store module in SDK domain (wallet origin).
- [ ] Route all writes through one API (`upsertFromBootstrap` / `clearForAccount` / `getForSigning`).
- [ ] Remove ad-hoc keyRef persistence in feature components/util modules.

Files:

- `client/src/core/signingEngine/api/thresholdLifecycle/*` (new store + wiring)
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts`
- `client/src/core/signingEngine/orchestration/thresholdActivation.ts`
- `examples/tatchi-site/src/components/PasskeyLoginMenu.tsx`
- `examples/tatchi-site/src/utils/thresholdSigners.ts`

## Phase 2: Login/Bootstrap Contract Hardening

- [ ] Define a strict threshold login contract:
  - In threshold-signer warm mode, login success must include valid threshold keyRef/session.
- [ ] Remove ambiguity between optional login success and required threshold provisioning.
- [ ] Reject ambiguous combinations that reintroduce double-prompt behavior.

Files:

- `client/src/core/types/tatchi.ts`
- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/TatchiPasskey/authSessions.ts`
- `client/src/core/TatchiPasskey/interfaces.ts`

## Phase 3: Worker Reset and Rehydration Strategy

- [ ] Define explicit behavior for reload/worker restart:
  - Never silently reuse stale in-memory state.
  - Return typed recoverable errors when PRF cache/session is gone.
- [ ] Add one explicit reconnect/provision entrypoint used by UI.
- [ ] Keep PRF material memory-only; do not add silent persistent-secret fallback.

Files:

- `client/src/core/signingEngine/api/session/signingSessionState.ts`
- `client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts`
- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`

## Phase 4: Delete Legacy/Silent Fallback Logic

- [ ] Remove fallback participant ID assumptions (e.g. implicit `[1,2]`).
- [ ] Remove fallback to `keyRef.thresholdSessionJwt` when canonical session lookup fails.
- [ ] Remove fallback to stale `keyRef.thresholdSessionId` when cache/session record is missing.
- [ ] Require canonical session record match before authorize/sign.

Primary file:

- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`

## Phase 5: Anti-Regression Tests + CI Checks

- [ ] Unit: threshold-required login returns valid keyRef/session or fails.
- [ ] Unit: signing with missing canonical session fails with typed reconnect error.
- [ ] Unit: worker reset path surfaces recoverable error (no hidden fallback).
- [ ] Unit: rapid Tempo then EVM click sequence is queued and executed in order for one account.
- [ ] Unit: queue remains per-account (account A does not block account B).
- [ ] Unit: queued request cancellation exits cleanly without running signing flow.
- [ ] Integration: login -> sign tempo -> sign evm uses same canonical threshold session.
- [ ] Integration: no extra bootstrap prompt appears after successful login provisioning.
- [ ] Integration: rapid Tempo/EVM clicks do not emit `signing_in_progress`.
- [ ] Architecture check: temporary threshold-trace debug instrumentation is removed from signing/bootstrap hot paths.
- [ ] Architecture checks to forbid reintroduction of removed fallback patterns.

Suggested tests:

- `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts`
- `tests/unit/tempo.signingAuthMode.unit.test.ts`
- `tests/unit/walletIframe.*.unit.test.ts`
- `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`
- `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts`

## Phase 5.5: Debug Instrumentation Cleanup

- [ ] Remove temporary stage-level `logThresholdTrace(...)` calls added for bootstrap->sign triage.
- [ ] Keep only stable, intentional telemetry (typed errors + minimal structured events).
- [ ] Remove temporary debug-only console emissions in wallet router/host and signing flows.

Files:

- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
- `client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts`
- `client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts`
- `client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts`
- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`
- `client/src/core/signingEngine/debug/thresholdTrace.ts`

## 6. How This Can Break Again (and Preventive Controls)

1. Someone adds a new in-memory-first keyRef lookup path.  
Control: ban direct keyRef reads outside canonical store module via architecture check.

2. A new flow writes keyRef/session directly (duplicate writer).  
Control: expose one writer API and fail CI if direct writes appear in non-store modules.

3. A convenience refactor re-adds automatic post-login bootstrap.  
Control: test that login success does not trigger secondary bootstrap calls.

4. Login result type is loosened again (threshold fields optional under required mode).  
Control: type-level contract + unit tests for threshold-required login.

5. Silent fallback paths return stale JWT/sessionId from old keyRef.  
Control: explicit “no fallback” tests and string-pattern CI guardrails for removed branches.

## 7. Done Criteria

- [ ] Signing no longer depends on ad-hoc in-memory/sessionStorage keyRef resolution.
- [ ] Threshold ECDSA keyRef/session writes are consolidated to one SDK-owned module.
- [ ] No unconditional post-login bootstrap remains.
- [ ] Login contract in threshold-required mode is strict and test-enforced.
- [ ] Silent fallback logic is removed; failures are explicit and recoverable.
- [ ] Reload/worker-reset behavior is deterministic and documented.
- [ ] Rapid Tempo/EVM clicks serialize per account without user-facing concurrency errors.
- [ ] Temporary session-debug console traces are removed.

## 8. Phased TODO List

## Phase 0 (Guardrails)

- [ ] Enforce threshold-required login fail-closed checks.
- [ ] Remove hidden post-login bootstrap triggers.
- [ ] Fail sign flow early for missing/stale canonical session.

## Phase 0.5 (Per-Account Queue)

- [ ] Implement FIFO queue gate for threshold ECDSA sign requests by account.
- [ ] Add queue overflow/timeout typed errors.
- [ ] Wire queue cleanup on logout/destroy.
- [ ] Add queue unit/integration coverage for rapid Tempo/EVM clicks.

## Phase 1 (Single Source of Truth)

- [ ] Add canonical threshold ECDSA store module.
- [ ] Route all keyRef/session writes through store API.
- [ ] Remove direct feature-layer keyRef writes.

## Phase 2 (Contract Hardening)

- [ ] Tighten login return contract in threshold-required mode.
- [ ] Remove ambiguous optional paths for required provisioning.
- [ ] Add type + unit coverage for contract guarantees.

## Phase 3 (Reset/Rehydration)

- [ ] Define deterministic worker reset behavior.
- [ ] Add explicit reconnect/provision entrypoint.
- [ ] Remove implicit stale-state reuse.

## Phase 4 (Legacy/Fallback Deletion)

- [ ] Remove participant/JWT/session legacy fallback branches.
- [ ] Require canonical session match before authorize/sign.
- [ ] Add architecture checks to block fallback reintroduction.

## Phase 5 (Regression Gate)

- [ ] Complete full unit + e2e matrix.
- [ ] Ensure rapid-click serialization tests are green.
- [ ] Remove temporary threshold-trace debug logs from hot paths.
- [ ] Ship only after invariants and done criteria are all satisfied.
