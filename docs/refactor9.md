# signingSession Simplification Plan

Status: Active  
Last updated: 2026-02-20

## 0. Ground Rules

- [x] Keep the term `signingSession` (no rename to `warmSession`).
- [x] Breaking changes are allowed; remove legacy APIs rather than keeping compatibility shims.
- [x] Keep PRF handling wallet-origin only; never persist PRF to IndexedDB/localStorage/server.
- [x] Do not reintroduce worker-to-worker `MessagePort` PRF handoff.

## 1. Problem Statement

- [ ] `signingSession` ownership is spread across multiple layers (`SigningEngine`, registration/login, orchestration deps).
- [x] Public mutators (`setActiveSigningSessionId`, `putPrfFirstForThresholdSession`) expose low-level internals to feature code.
- [x] Session ID lifecycle is not explicit: some paths create IDs eagerly, some hydrate from bootstrap.
- [ ] Current plumbing still reflects older architecture complexity that is no longer needed.

## 2. Target Model

- [x] One internal `signingSession` owner module orchestrates:
  - [x] account -> active `sessionId`
  - [x] policy resolution (`ttlMs`, `remainingUses`)
  - [x] status lookup (`active` / `expired` / `exhausted` / `not_found`)
  - [x] hydration from threshold bootstrap responses
  - [x] clear-by-account and clear-all
- [x] `SigningEngine` exposes only high-level session operations.
- [x] Feature flows (registration/login/orchestration) call high-level APIs, never direct PRF cache writes.

## 3. PRF Cache Decision

- [x] Keep PRF cache in `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`.
- [x] Keep cache in-memory only, scoped by `sessionId`, with TTL + remaining-uses enforcement.
- [x] Access cache only through `SecureConfirmWorkerManager` methods (`put/peek/dispense/clear`).
- [x] Explicitly document threat model:
  - [x] Safe against at-rest leakage (not persisted).
  - [x] Not safe against full runtime compromise/XSS in same origin.
  - [x] Mitigations remain CSP + wallet-origin isolation + aggressive logout/session clearing.

## 4. Refactor Steps

### 4.1 Consolidate Session Ownership

- [x] Refactor `api/session/signingSessionState.ts` into the single source of truth for lifecycle operations.
- [x] Move any session map mutations behind this module.
- [x] Remove ad-hoc account/session map mutations outside the session module.

### 4.2 Remove Low-Level Public Surface

- [x] Remove `SigningEngine.setActiveSigningSessionId(...)` from public API.
- [x] Remove `SigningEngine.putPrfFirstForThresholdSession(...)` from public API.
- [x] Add one high-level hydrate method for bootstrap/session-restore flows.
- [x] Update registration/login flows to use high-level APIs only.

### 4.3 Tighten Session-ID Lifecycle

- [x] Create/retain long-lived `sessionId` only where warm signing is actually intended.
- [x] Avoid creating durable `sessionId` on generic one-off sign calls when warm signing is not used.
- [x] Keep fallback behavior explicit when cache is expired/exhausted.

### 4.4 Keep Cross-Chain Behavior Consistent

- [x] Apply the same `signingSession` policy/status behavior to NEAR, EVM, and Tempo flows.
- [x] Ensure EVM/Tempo threshold signing relies on the same PRF cache policy semantics.

### 4.5 Delete Legacy Paths

- [x] Remove unused helpers that exist only for pre-refactor session injection patterns.
- [x] Remove duplicate wrappers after call sites are migrated.
- [x] Route PRF cache clear paths through `api/session/signingSessionState.ts` helpers.

## 5. Testing Plan

- [x] Add/adjust unit tests for:
  - [x] session hydration from bootstrap (ed25519 + ecdsa)
  - [x] status transitions (`active -> exhausted/expired/not_found`)
  - [x] clear-by-account and clear-all semantics
  - [x] no direct low-level session mutation from registration/login
- [ ] Verify existing signing flow coverage still passes for:
  - [ ] `tests/unit/signingPipeline.unified.unit.test.ts`
  - [ ] `tests/unit/tempo.signingAuthMode.unit.test.ts`
  - [ ] `tests/unit/modularity.lazySigners.unit.test.ts`

## 6. Verification Commands

- [x] `pnpm exec tsc --noEmit -p client/tsconfig.json`
- [ ] `pnpm exec eslint client/src/core/signingEngine client/src/core/TatchiPasskey`
- [x] `pnpm exec eslint client/src/core/signingEngine/SigningEngine.ts client/src/core/signingEngine/api/session/signingSessionState.ts client/src/core/signingEngine/orchestration/near/transactionsFlow.ts client/src/core/signingEngine/orchestration/near/delegateFlow.ts client/src/core/signingEngine/orchestration/near/nep413Flow.ts client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts`
- [x] `pnpm exec eslint client/src/core/signingEngine/api/nearSigning.ts client/src/core/signingEngine/SigningEngine.ts client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts client/src/core/signingEngine/api/session/signingSessionState.ts client/src/core/signingEngine/orchestration/shared/secureConfirmSigning.ts tests/unit/tempo.signingAuthMode.unit.test.ts tests/unit/signingSession.state.unit.test.ts tests/unit/signingPipeline.unified.unit.test.ts`
- [ ] `pnpm -C tests exec playwright test ./unit/signingPipeline.unified.unit.test.ts ./unit/tempo.signingAuthMode.unit.test.ts ./unit/modularity.lazySigners.unit.test.ts --reporter=line` (skipped by request)
- [ ] `pnpm -C tests exec playwright test ./unit/signingSession.state.unit.test.ts ./unit/tempo.signingAuthMode.unit.test.ts --reporter=line` (skipped by request)

Validation notes:
- `pnpm exec tsc --noEmit -p client/tsconfig.json` passes after PRF cache helper consolidation + NEAR intent wrapper cleanup.
- Targeted lint for refactor9-delivered files passes:
  - `pnpm exec eslint client/src/core/signingEngine/SigningEngine.ts client/src/core/signingEngine/api/session/signingSessionState.ts client/src/core/signingEngine/orchestration/near/transactionsFlow.ts client/src/core/signingEngine/orchestration/near/delegateFlow.ts client/src/core/signingEngine/orchestration/near/nep413Flow.ts client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts`
  - `pnpm exec eslint client/src/core/signingEngine/api/nearSigning.ts client/src/core/signingEngine/SigningEngine.ts client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts client/src/core/signingEngine/api/session/signingSessionState.ts client/src/core/signingEngine/orchestration/shared/secureConfirmSigning.ts tests/unit/tempo.signingAuthMode.unit.test.ts tests/unit/signingSession.state.unit.test.ts tests/unit/signingPipeline.unified.unit.test.ts`
- `pnpm exec eslint client/src/core/signingEngine client/src/core/TatchiPasskey` currently fails due pre-existing lint debt outside the signingSession refactor scope (secureConfirm UI + shared adapters).
- Browser-based Playwright verification is intentionally deferred per request to skip Chromium/Playwright download and browser test execution.

## 7. Done Criteria

- [x] `signingSession` naming is unchanged across public SDK surface.
- [x] PRF cache remains in `passkey-confirm.worker.ts` only.
- [x] No public low-level `sessionId` / PRF cache mutator APIs remain.
- [x] Registration/login/orchestration use one consolidated session lifecycle API.
- [x] Legacy session plumbing code paths are deleted, not left in parallel.
