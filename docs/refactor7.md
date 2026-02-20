# TouchConfirm Refactor TODO

Status: Active
Last updated: 2026-02-20

## 0. Ground Rules

- [ ] Rename `secureConfirm` -> `touchConfirm` as a hard rename (no parallel legacy module).
- [ ] Keep worker-initiated confirmation as canonical path.
- [ ] Remove deprecated/legacy wrappers as soon as each caller is migrated.

## 1. Folder Restructure (Functionality-First)

- [ ] Create `client/src/core/signingEngine/touchConfirm/`.
- [ ] Create `touchConfirm/workerBridge/`.
- [ ] Create `touchConfirm/flows/signing/`.
- [ ] Create `touchConfirm/flows/registration/`.
- [ ] Create `touchConfirm/flows/recovery/`.
- [ ] Create `touchConfirm/shared/`.
- [ ] Move existing UI files to `touchConfirm/ui/`.
- [ ] Delete old `secureConfirm/` tree after import migration.

## 2. Worker Bridge Consolidation

- [ ] Move `awaitSecureConfirmation.ts` to `touchConfirm/workerBridge/awaitTouchConfirmation.ts`.
- [ ] Move/rename `handleSecureConfirmRequest.ts` to `touchConfirm/workerBridge/handlePromptInMainThread.ts`.
- [ ] Add one long-lived message router with `requestId -> resolver` map.
- [ ] Guarantee resolver cleanup on success, error, abort, and timeout.
- [ ] Remove per-request ad-hoc worker listener wiring.

## 3. Signing Flow Refactor

- [ ] Split signing NEAR context logic into:
  - [ ] `fetchSigningContext` (fail-fast)
  - [ ] `fetchDisplayContext` (fallback allowed)
- [ ] Move transaction signing flow into `flows/signing/signTransaction.ts`.
- [ ] Move NEP-413 signing flow into `flows/signing/signNep413Message.ts`.
- [ ] Move intent-digest signing flow into `flows/signing/signIntentDigest.ts`.
- [ ] Ensure signing paths do not proceed with dummy transaction context.
- [ ] Route all side effects via injectable helpers (no direct ctx-bound hard wiring in flow body).

## 4. Registration and Recovery Flow Refactor

- [ ] Move registration flow to `flows/registration/registerAccount.ts`.
- [ ] Move link-device flow to `flows/registration/linkDevice.ts`.
- [ ] Decide and document registration fallback policy:
  - [ ] Keep fallback for registration only, or
  - [ ] make registration fail-fast like signing.
- [ ] Move decrypt-private-key-with-prf flow to `flows/recovery/decryptPrivateKeyWithPrf.ts`.
- [ ] Move export/show-private-key-ui flow to `flows/recovery/showSecurePrivateKeyUi.ts`.

## 5. Shared Utilities and Validation

- [ ] Move request validation to `shared/validateRequest.ts`.
- [ ] Move common request helpers to `shared/requestHelpers.ts`.
- [ ] Move `determineConfirmationConfig` to `shared/determineConfirmationConfig.ts`.
- [ ] Move postMessage sanitization to `shared/sanitizeForPostMessage.ts`.
- [ ] Create one shared intent-digest validator used by both host UI and wrapper UI.
- [ ] Make flow inputs immutable (no in-place mutation of request/config/summary).

## 6. Messaging Hardening

- [ ] Replace wildcard `postMessage(..., '*')` where feasible.
- [ ] Enforce strict `event.origin` validation for inbound message handlers.
- [ ] Enforce `event.source` checks for expected frame/window.
- [ ] Add channel token or `MessageChannel` for confirm/export messaging.

## 7. Determinism and Testability

- [ ] Introduce injected helpers for:
  - [ ] clock (`Date.now`)
  - [ ] id generation
  - [ ] randomness
  - [ ] scheduler (`setTimeout`, `requestAnimationFrame`)
- [ ] Remove hard-coded time/random calls from flow modules.
- [ ] Ensure each major flow can be unit-tested with mocked helpers.

## 8. Legacy Cleanup

- [ ] Remove `secureConfirmBridge.ts` once callers are migrated.
- [ ] Remove `handlers/` wrapper layer.
- [ ] Remove `confirmTxFlow/flows/index.ts` low-churn compatibility barrel.
- [ ] Remove legacy NEP-413 payload fields if unused (`contractId`, `nearRpcUrl`).
- [ ] Update imports across signing engine to `touchConfirm/*` only.

## 9. Verification

- [ ] `pnpm -C sdk build`
- [ ] `pnpm -C sdk type-check`
- [ ] `pnpm -C tests test:unit`
- [ ] `pnpm -C tests exec playwright test ./unit/confirmTxFlow.successPaths.test.ts --reporter=line`
- [ ] `pnpm -C tests exec playwright test ./unit/confirmTxFlow.defensivePaths.test.ts --reporter=line`
- [ ] Add/adjust focused tests for worker router cleanup and same-origin message validation.

## 10. Done Criteria

- [ ] No imports from `secureConfirm/*` remain.
- [ ] No duplicate legacy path exists in parallel with `touchConfirm/*`.
- [ ] Worker-initiated flow is the only confirmation entrypoint.
- [ ] Signing never uses fallback dummy transaction context.
- [ ] Message handlers are origin/source scoped and deterministic tests pass.

## 11. Cross-Chain Compatibility (NEAR, EVM, Tempo)

- [ ] Replace generic-flow `nearAccountId` usage with chain-neutral identity (`signerAccountId` or `accountScopeId`).
- [ ] Keep `nearAccountId` only in NEAR-specific flow modules.
- [ ] Split confirmation API into:
  - [ ] `confirmIntentForSigning(...)` (chain-agnostic)
  - [ ] `confirmAndPrepareNearTransactionSession(...)` (NEAR-only nonce/block context)
- [ ] Introduce chain-discriminated execution context:
  - [ ] `{ chain: 'near'; nearTxContext: ... }`
  - [ ] `{ chain: 'evm' }`
  - [ ] `{ chain: 'tempo' }`
- [ ] Ensure non-NEAR chains do not require/expect NEAR `transactionContext`.
- [ ] Organize signing flows by chain + common helpers:
  - [ ] `touchConfirm/flows/signing/near/*`
  - [ ] `touchConfirm/flows/signing/evm/*`
  - [ ] `touchConfirm/flows/signing/tempo/*`
  - [ ] `touchConfirm/flows/signing/common/*`
- [ ] Update orchestration dependency wiring so EVM/Tempo deps are not NEAR-shaped by default.
- [ ] Keep NEAR RPC/nonce managers only in NEAR-specific dependency bundles.
- [ ] Make confirmation summary schema chain-neutral with optional chain-specific detail payload:
  - [ ] common fields: `title`, `body`, `intentDigest`, `challenge`, `security`
  - [ ] optional `chainDetails` by discriminator.
