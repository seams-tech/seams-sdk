# Refactor 11: Threshold ECDSA Session + KeyRef Ownership Hardening

Status: Completed  
Severity: High (prompt-order regressions, stale-session signing failures, hidden fallback behavior)  
Last updated: 2026-02-21

## 1. Problem Statement

Recent regressions came from state ownership drift:

1. KeyRef/session state was resolved from multiple places (in-memory state, session storage, worker cache, returned login payload).
2. Bootstrap could happen outside the canonical login/provisioning path, causing extra TouchID prompts and session churn.
3. Signing code still had fallback branches that accepted stale/legacy keyRef/session shapes instead of failing fast.
4. Worker/session reset events (reload, iframe restart, worker restart) had no explicit re-hydration interface, so behavior depended on whatever stale keyRef was still around.
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

4. Login refactor drifting from thresholdEcdsaKeyRef interface + reset edge cases  
Decision: **Enforce strict login interface + explicit session recovery state machine.**  
If threshold mode is required and login cannot return/store a valid threshold keyRef/session bundle, login fails.

5. Silent fallback to old keyRef/session fields  
Decision: **Yes, remove silent fallbacks.**  
Fail fast with typed errors and a single reprovision/reconnect path.

6. Rapid successive threshold sign requests (Tempo + EVM)  
Decision: **Implement a per-account FIFO commit queue in SDK path now.**  
Do not allow concurrent threshold ECDSA commit per account. Confirmation stays concurrent (refined further in Refactor 13).

7. Temporary debug logs added during incident triage  
Decision: **Remove them before final merge/release.**  
Keep only durable telemetry/typed errors; delete ad-hoc stage-level console traces.

## 3. Non-Negotiable Invariants

- Threshold ECDSA signing reads keyRef/session from one canonical store only.
- `signTempo` does not trigger hidden bootstrap.
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

### 4.4 Per-Account Commit Queue Model (Tempo/EVM)

- Queue scope: `nearAccountId`.
- Queue domain: threshold ECDSA commit stage (`senderSignatureAlgorithm=secp256k1`) across both Tempo and EVM.
- Ordering: FIFO.
- Behavior: second click is queued (not rejected), and starts after previous request completes/fails/cancels.
- Cancellation: queued items can be cancelled before start via existing abort/cancel signal path.
- Guardrails:
  - bounded queue length (fail fast with typed `commit_queue_overflow` if exceeded),
  - queue item timeout budget (typed `commit_queue_timeout`),
  - deterministic teardown on engine destroy/logout.

## 5. Implementation Plan

## Phase 0: Immediate Guardrails (fail-closed)

- [x] Add strict assertions in login path:
  - If threshold warm-up is required, missing `thresholdEcdsaKeyRef` or missing session fields is a hard error.
- [x] Remove hidden post-login bootstrap triggers from UI/demo flows.
- [x] Ensure sign path fails before signing orchestration when canonical threshold session is missing/stale.

Files:

- `client/src/core/TatchiPasskey/login.ts`
- `examples/tatchi-site/src/components/PasskeyLoginMenu.tsx`
- `examples/tatchi-site/src/components/DemoPage.tsx`
- `examples/tatchi-site/src/utils/thresholdSigners.ts`

## Phase 0.5: SDK Per-Account Queue (implement now)

- [x] Replace reject-only in-flight gate with commit-queue gate for threshold ECDSA sign requests.
- [x] Serialize Tempo + EVM secp256k1 sign requests per `nearAccountId`.
- [x] Preserve cancellation semantics for queued requests (drop before execution when cancelled).
- [x] Add typed commit-queue overflow/timeout errors.
- [x] Ensure queue is cleared on logout/destroy.

Files:

- `client/src/core/signingEngine/SigningEngine.ts`
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts`
- `client/src/core/signingEngine/api/evmSigning.ts`
- `client/src/core/signingEngine/api/tempoSigning.ts`

## Phase 1: Single Source of Truth for Threshold ECDSA

- [x] Add a dedicated threshold ECDSA state store module in SDK domain (wallet origin).
- [x] Route all writes through one API (`upsertFromBootstrap` / `clearForAccount` / `getForSigning`).
- [x] Remove ad-hoc keyRef persistence in feature components/util modules.

Files:

- `client/src/core/signingEngine/api/thresholdLifecycle/*` (new store + wiring)
- `client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts`
- `client/src/core/signingEngine/orchestration/thresholdActivation.ts`
- `examples/tatchi-site/src/components/PasskeyLoginMenu.tsx`
- `examples/tatchi-site/src/utils/thresholdSigners.ts`

## Phase 2: Login/Bootstrap Types + Interface Hardening

- [x] Define a strict threshold login interface:
  - In threshold-signer warm mode, login success must include valid threshold keyRef/session.
- [x] Remove ambiguity between optional login success and required threshold provisioning.
- [x] Reject ambiguous combinations that reintroduce double-prompt behavior.

Files:

- `client/src/core/types/tatchi.ts`
- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/TatchiPasskey/authSessions.ts`
- `client/src/core/TatchiPasskey/interfaces.ts`

## Phase 3: Worker Reset and Rehydration Strategy

- [x] Define explicit behavior for reload/worker restart:
  - Never silently reuse stale in-memory state.
  - Return typed recoverable errors when PRF cache/session is gone.
- [x] Add one explicit reconnect/provision entrypoint used by UI.
- [x] Keep PRF material memory-only; do not add silent persistent-secret fallback.

Files:

- `client/src/core/signingEngine/api/session/signingSessionState.ts`
- `client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts`
- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`

## Phase 4: Delete Legacy/Silent Fallback Logic

- [x] Remove fallback participant ID assumptions (e.g. implicit `[1,2]`).
- [x] Remove fallback to `keyRef.thresholdSessionJwt` when canonical session lookup fails.
- [x] Remove fallback to stale `keyRef.thresholdSessionId` when cache/session record is missing.
- [x] Require canonical session record match before authorize/sign.

Primary file:

- `client/src/core/signingEngine/signers/algorithms/secp256k1.ts`

## Phase 5: Anti-Regression Tests + CI Checks

- [x] Unit: threshold-required login returns a valid threshold session bundle or fails.
- [x] Unit: signing with missing canonical session fails with typed reconnect error.
- [x] Unit: worker reset path surfaces recoverable error (no hidden fallback).
- [x] Unit: rapid Tempo then EVM click sequence is queued and executed in order for one account.
- [x] Unit: queue remains per-account (account A does not block account B).
- [x] Unit: queued request cancellation exits cleanly without running signing flow.
- [x] Integration: login -> sign tempo -> sign evm uses same canonical threshold session.
- [x] Integration: no extra bootstrap prompt appears after successful login provisioning.
- [x] Integration: rapid Tempo/EVM clicks do not emit legacy in-flight blocker errors.
- [x] Architecture check: temporary threshold-trace debug instrumentation is removed from signing/bootstrap hot paths.
- [x] Architecture checks to forbid reintroduction of removed fallback patterns.

Suggested tests:

- `tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts`
- `tests/unit/tempo.signingAuthMode.unit.test.ts`
- `tests/unit/walletIframe.*.unit.test.ts`
- `tests/e2e/docs.thresholdSigningActions.smoke.test.ts`
- `tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts`

## Phase 5.5: Debug Instrumentation Cleanup

- [x] Remove temporary stage-level `logThresholdTrace(...)` calls added for bootstrap->sign triage.
- [x] Keep only stable, intentional telemetry (typed errors + minimal structured events).
- [x] Remove temporary debug-only console emissions in wallet router/host and signing flows.

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
Control: type-level interface guarantees + unit tests for threshold-required login.

5. Silent fallback paths return stale JWT/sessionId from old keyRef.  
Control: explicit “no fallback” tests and string-pattern CI guardrails for removed branches.

## 7. Done Criteria

- [x] Signing no longer depends on ad-hoc in-memory/sessionStorage keyRef resolution.
- [x] Threshold ECDSA keyRef/session writes are consolidated to one SDK-owned module.
- [x] No unconditional post-login bootstrap remains.
- [x] Login types/interface in threshold-required mode are strict and test-enforced.
- [x] Silent fallback logic is removed; failures are explicit and recoverable.
- [x] Reload/worker-reset behavior is deterministic and documented.
- [x] Rapid Tempo/EVM clicks serialize per account without user-facing concurrency errors.
- [x] Temporary session-debug console traces are removed.

## 8. Phased TODO List

## Phase 0 (Guardrails)

- [x] Enforce threshold-required login fail-closed checks.
- [x] Remove hidden post-login bootstrap triggers.
- [x] Fail sign flow early for missing/stale canonical session.

## Phase 0.5 (Per-Account Queue)

- [x] Implement FIFO commit queue gate for threshold ECDSA sign requests by account.
- [x] Add commit queue overflow/timeout typed errors.
- [x] Wire queue cleanup on logout/destroy.
- [x] Add queue unit/integration coverage for rapid Tempo/EVM clicks.

## Phase 1 (Single Source of Truth)

- [x] Add canonical threshold ECDSA store module.
- [x] Route all keyRef/session writes through store API.
- [x] Remove direct feature-layer keyRef writes.

## Phase 2 (Types + Interface Hardening)

- [x] Tighten login return types/interface in threshold-required mode.
- [x] Remove ambiguous optional paths for required provisioning.
- [x] Add type + unit coverage for interface guarantees.

## Phase 3 (Reset/Rehydration)

- [x] Define deterministic worker reset behavior.
- [x] Add explicit reconnect/provision entrypoint.
- [x] Remove implicit stale-state reuse.

## Phase 4 (Legacy/Fallback Deletion)

- [x] Remove participant/JWT/session legacy fallback branches.
- [x] Require canonical session match before authorize/sign.
- [x] Add architecture checks to block fallback reintroduction.

## Phase 5 (Regression Gate)

- [x] Complete full unit + e2e matrix.
- [x] Ensure rapid-click serialization tests are green.
- [x] Remove temporary threshold-trace debug logs from hot paths.
- [x] Ship only after invariants and done criteria are all satisfied.
