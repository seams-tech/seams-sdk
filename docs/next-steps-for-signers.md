# Next Steps For Signers

Last updated: 2026-02-18

## Current State (Baseline)

- Registration can complete with one TouchID prompt.
- After registration, NEAR + Tempo + EVM threshold signing can run without extra TouchID in the happy path.
- Login is currently one prompt.
- Wallet iframe freeze/overlay-stuck issues were fixed for Tempo signing completion.

## Working Assumptions

- We keep a clean path only (no legacy fallback flows).
- We prefer deterministic behavior over parallelism for signing UX.
- A user-visible "logged in" state must imply workers/sessions are actually ready to sign.

## Plan (Phased)

## Phase 0: Lock Contracts Before Implementation

Goal: remove ambiguity before code changes.

- [ ] Lock concurrency policy to one behavior: fail fast for second in-flight threshold ECDSA request per account.
  - Canonical code: `signing_in_progress`.
  - No hidden fallback queue mode in runtime behavior.
- [ ] Lock cancellation/timeout contract for request-scoped execution.
  - If a request is cancelled/times out before lock acquisition, it must never enter SecureConfirm/TouchID.
  - If cancellation arrives after acquisition, flow exits deterministically with cancellation error semantics.
- [ ] Lock canonical error mapping at wallet API boundary:
  - `signing_in_progress`
  - `session_not_ready`
  - `deployment_in_progress` / `deployment_failed`
  - `cancelled` / timeout class (single canonical naming choice)

Definition of done:

- Team can implement without interpreting "waits or fails fast".
- Cancellation semantics are explicit for queued vs active requests.

## Phase 1: Serialize Tempo/EVM Signing Per Account (With Cancellation Safety)

Goal: eliminate race conditions from rapid-click concurrent signing.

- [x] Add a per-account in-flight gate for threshold ECDSA signing entrypoints.
  - Scope: wallet-origin `signTempo` path (and any EVM alias path using same engine).
  - Behavior: second concurrent request fails fast with `signing_in_progress`.
- [x] Prevent overlapping signer confirm UIs for the same account.
  - Keep gating at API boundary, not only in UI.
- [x] Wire cancellation/timeout checks so stale requests cannot execute after caller timeout.
  - Ensure wallet iframe `PM_CANCEL` and client timeout paths stop pending sign work before SecureConfirm begins.
- [x] Keep overlay behavior request-scoped and deterministic under rejected concurrent execution.

Definition of done:

- [x] Rapid click on "Sign Tempo" + "Sign EVM" does not produce overlapping signing sessions.
- [x] No duplicate TouchID prompts due to concurrent requests.
- [x] No delayed TouchID prompt for a request that already timed out/cancelled on the caller side.
- [x] No stuck overlay after either request succeeds/fails.

Completion record (2026-02-18):

- Runtime behavior landed:
  - per-account in-flight gate with deterministic `signing_in_progress`
  - wallet-host cancellation guard before sign execution (`PM_CANCEL` path)
  - hidden preflight intent for `PM_START_DEVICE2_LINKING_FLOW` so QR start does not surface wallet iframe
- Regression coverage landed:
  - `tests/unit/thresholdEcdsa.signInFlightGate.unit.test.ts`
  - `tests/unit/walletIframeHost.signTempoCancel.unit.test.ts`
  - `tests/unit/tempo.signingAuthMode.unit.test.ts`
  - `tests/wallet-iframe/passkeyAuthMenu.qrButton.overlay.test.ts`
  - `tests/wallet-iframe/router.computeOverlayIntent.test.ts`
  - `tests/wallet-iframe/router.behavior.sticky.test.ts`
  - `tests/wallet-iframe/router.behavior.concurrent.test.ts`
  - `tests/e2e/signTransactions.concurrentSessions.walletIframe.test.ts`
- Canonical gate command:
  - `pnpm -C ../sdk run build:check:fresh || pnpm -C ../sdk run build`
  - `USE_RELAY_SERVER=0 pnpm -C tests exec playwright test ./unit/thresholdEcdsa.signInFlightGate.unit.test.ts ./unit/walletIframeHost.signTempoCancel.unit.test.ts ./unit/tempo.signingAuthMode.unit.test.ts ./wallet-iframe/passkeyAuthMenu.qrButton.overlay.test.ts ./wallet-iframe/router.computeOverlayIntent.test.ts ./wallet-iframe/router.behavior.sticky.test.ts ./wallet-iframe/router.behavior.concurrent.test.ts ./e2e/signTransactions.concurrentSessions.walletIframe.test.ts --reporter=line`

## Phase 2: Deduplicate Smart-Account Deployment Work (Correct Key Scope)

Goal: avoid concurrent first-send deployment races.

- [ ] Add deployment in-flight dedupe lock keyed by resolved deployment identity:
  - `(profileId, chainId, accountModel, accountAddress)`.
  - Resolve preferred chain account first, then derive lock key.
- [ ] Re-check deployed state after waiting on the lock holder before attempting deploy.
- [ ] Keep deploy retry policy unchanged, but ensure only one active deploy attempt per key.

Definition of done:

- Two concurrent first-send requests trigger at most one deploy transaction attempt.
- Follower request reuses post-deploy state and proceeds.
- Different smart-account addresses under the same profile/chain are not incorrectly blocked by each other.

## Phase 3: Make Logged-In State Depend On Ready Signing State

Goal: no "logged in" UI if workers/session caches are not sign-capable.

- [ ] Add a strict readiness gate before publishing `isLoggedIn=true` to UI:
  - active signing session id exists for account
  - secure-confirm worker has valid PRF cache entry for session
  - threshold session token/keyRef scope is usable
- [ ] If readiness gate fails, treat login as failed/incomplete (no best-effort success state).
- [ ] Add one explicit recovery action to re-bootstrap session, but do not silently mark logged in.
- [ ] Ensure all login-state publishers use the same readiness source of truth:
  - core login snapshot
  - app React context refreshers
  - wallet iframe login-status bridge

Definition of done:

- UI never shows logged-in menus unless signers are actually ready.
- First Tempo/EVM sign after login does not require unexpected TouchID re-bootstrap.

## Phase 4: Add Concurrency + Readiness Test Gates

Goal: lock behavior with regression tests.

- [ ] Add unit/integration tests for:
  - concurrent Tempo/EVM sign requests (same account) returns deterministic `signing_in_progress`
  - cancellation/timeout before execution never triggers late SecureConfirm/TouchID
  - deployment dedupe under concurrent requests using `(profileId, chainId, accountModel, accountAddress)`
  - login readiness gate with/without PRF cache/session
- [ ] Keep existing overlay progress tests and add one concurrency + cancellation-focused overlay test.

Definition of done:

- CI has deterministic coverage for the above failure classes.

## Phase 5: Docs + Operational Clarity

Goal: make runtime behavior explicit for contributors and integrators.

- [ ] Document signer concurrency model ("one signing pipeline per account").
- [ ] Document cancellation/timeout semantics for sign requests and wallet iframe transport.
- [ ] Document deployment dedupe key shape and why address is part of the lock identity.
- [ ] Document login readiness contract and required worker/session invariants.
- [ ] Document canonical error codes:
  - `signing_in_progress`
  - `session_not_ready`
  - `deployment_in_progress` / `deployment_failed`

Definition of done:

- Docs match runtime behavior; no ambiguity about queueing vs parallel signing.

## Relevant Files To Load Into Context

## Client: Entry Points / Orchestration

- `client/src/core/signing/api/WebAuthnManager.ts`
- `client/src/core/signing/api/tempoSigning.ts`
- `client/src/core/TatchiPasskey/index.ts`
- `client/src/core/TatchiPasskey/login.ts`
- `client/src/core/TatchiPasskey/registration.ts`

## Client: SecureConfirm / TouchID / Worker Cache

- `client/src/core/signing/secureConfirm/confirmTxFlow/flows/intentDigest.ts`
- `client/src/core/signing/secureConfirm/handlers/confirmAndPrepareSigningSession.ts`
- `client/src/core/signing/secureConfirm/ui/confirm-ui.ts`
- `client/src/core/signing/webauthn/prompt/touchIdPrompt.ts`
- `client/src/core/workers/passkey-confirm.worker.ts`

## Client: ECDSA Engine + Threshold Flow

- `client/src/core/signing/engines/secp256k1.ts`
- `client/src/core/signing/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts`
- `client/src/core/signing/threshold/workflows/thresholdEcdsaAuthorize.ts`
- `client/src/core/signing/threshold/workflows/thresholdEcdsaSigning.ts`
- `client/src/core/signing/threshold/session/thresholdEcdsaAuthSession.ts`

## Client: Deployment Gate

- `client/src/core/signing/orchestration/deployment/ensureSmartAccountDeployed.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB.types.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/schema.ts`
- `client/src/core/IndexedDBManager/passkeyClientDB/manager.ts`

## Client: Login State Publishers (Phase 3 Critical)

- `client/src/core/signing/api/signingSessionState.ts`
- `client/src/react/context/useTatchiContextValue.ts`
- `client/src/react/context/useWalletIframeLifecycle.ts`
- `client/src/react/context/useLoginStateRefresher.ts`

## Wallet Iframe Transport + Overlay

- `client/src/core/WalletIframe/client/router.ts`
- `client/src/core/WalletIframe/client/progress/on-events-progress-bus.ts`
- `client/src/core/WalletIframe/host/wallet-iframe-handlers.ts`
- `client/src/core/WalletIframe/host/index.ts`

## Server: Session + Authorization + Signing

- `server/src/core/ThresholdService/ThresholdSigningService.ts`
- `server/src/core/ThresholdService/stores/AuthSessionStore.ts`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`
- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`

## Demo/UI Harness

- `examples/tatchi-site/src/components/DemoPage.tsx`

## Existing Tests To Extend

- `tests/unit/progressBus.defaultPhaseHeuristics.test.ts`
- `tests/wallet-iframe/router.behavior.sticky.test.ts`
- `tests/wallet-iframe/router.computeOverlayIntent.test.ts`
- `tests/unit/thresholdEcdsa.tempoHighLevel.unit.test.ts`
- `tests/unit/smartAccount.deploymentGate.unit.test.ts`
- `tests/unit/tempo.signingAuthMode.unit.test.ts`
- `tests/e2e/signTransactions.concurrentSessions.walletIframe.test.ts`
