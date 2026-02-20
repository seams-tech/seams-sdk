# Refactor 10: Export Flow Security Hardening (Worker-Owned Confirmation)

Status: Urgent
Severity: High (private-key export flow boundary violation)
Last updated: 2026-02-20

## 1. Problem Statement

Current export flows still rely on JS-main-thread orchestration that should be worker-owned.

Observed shortcut points:

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts:80`
  - Reads `getContext().requestUserConfirmation` and drives confirmation from JS orchestration.
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts:126`
  - JS sends `DECRYPT_PRIVATE_KEY_WITH_PRF` confirmation request.
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts:149`
  - JS extracts PRF output from returned credential.
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts:197`
  - JS sends `SHOW_SECURE_PRIVATE_KEY_UI` directly.
- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts:297`
  - Same JS-driven shortcut in multi-key export path.
- `client/src/core/signingEngine/workerManager/nearKeyOps/exportNearKeypairUi.ts:101`
  - JS calls `requestUserConfirmation` again for export UI display.

This violates the intended design boundary: export intent should be initiated by worker logic, with confirmation handshake via `awaitUserConfirmationV2`, and sensitive derivation/decrypt steps remaining in worker/wasm execution context.

## 2. Security Invariants (Must Hold)

- Export flows must start from a worker RPC operation, not from JS-main-thread confirmation helpers.
- `awaitUserConfirmationV2` is the only confirmation initiation mechanism for export.
- Main thread must not parse PRF outputs from credentials in export flows.
- Main thread must not receive raw private keys as normal return payloads from orchestration APIs.
- `TouchConfirmManager` remains a bridge/router, not a business-flow orchestrator for export.
- No dual legacy path: old JS shortcut flow must be removed, not retained behind compatibility switches.

## 3. Target Architecture

### 3.1 High-level flow (export)

1. Main thread issues `ExportPrivateKeysWithUi` worker operation.
2. Worker initiates confirmation via `awaitUserConfirmationV2`.
3. Worker receives credential and performs decrypt/derive in worker/wasm scope.
4. Worker initiates `SHOW_SECURE_PRIVATE_KEY_UI` via `awaitUserConfirmationV2`.
5. Worker returns sanitized result (`ok`/`cancelled`/`error`) without secret material.

### 3.2 Boundary rule

- JS-main-thread code may request an export operation.
- JS-main-thread code may not orchestrate intermediate confirmation steps for export.
- JS-main-thread code may not inspect credential PRF outputs for export.

## 4. Implementation Plan

## Phase 0: Immediate Containment (same day)

- [ ] Add hard guardrails in `privateKeyExportRecovery.ts` that block direct export confirmation orchestration when worker-owned flow is not active.
- [ ] Add temporary fail-fast error for legacy export shortcut entrypoints (`requestUserConfirmation` helper in export module).
- [ ] Communicate release note that export flow is under security hardening and may fail fast instead of falling back.

Deliverable:
- No successful runtime path that performs JS-driven export confirmation orchestration.

## Phase 1: Protocol and Type Contracts

- [ ] Add dedicated export worker operation type(s) to signer worker request/response contracts:
  - Example shape: `WorkerRequestType.ExportPrivateKeysWithUi`.
- [ ] Define worker payload contract for export intent:
  - `nearAccountId`, requested schemes, UI variant/theme, optional request metadata.
- [ ] Define worker response contract without secret outputs:
  - `ok`, `cancelled`, `exportedSchemes`, optional non-sensitive metadata.
- [ ] Add explicit export confirmation request types if needed in `touchConfirm/shared/confirmTypes.ts`.

Deliverable:
- Export flow protocol is explicit, typed, and does not require main-thread secret handling.

## Phase 2: Worker Runtime Implementation

- [ ] Implement export orchestration inside worker runtime (near-signer worker path).
- [ ] Ensure worker can initiate confirmation via `awaitUserConfirmationV2`.
- [ ] Keep credential handling and PRF extraction inside worker scope.
- [ ] Run decrypt/derive key steps inside worker/wasm handlers.
- [ ] Initiate `SHOW_SECURE_PRIVATE_KEY_UI` from worker via `awaitUserConfirmationV2`.
- [ ] Zeroize/clear sensitive in-memory values as soon as practical after use.

Deliverable:
- End-to-end export flow executes with worker-owned confirmation and key derivation.

## Phase 3: JS Orchestration Cleanup (Delete Shortcuts)

- [ ] Refactor `api/recovery/privateKeyExportRecovery.ts` to invoke only the new worker export operation.
- [ ] Delete export-local `requestUserConfirmation` helper in `privateKeyExportRecovery.ts`.
- [ ] Remove any export path that calls `getContext().requestUserConfirmation` from JS business logic.
- [ ] Remove direct PRF extraction from credentials in JS export orchestration.
- [ ] Remove/deprecate `workerManager/nearKeyOps/exportNearKeypairUi.ts` confirmation responsibility (or replace with worker-op wrapper that has no confirmation orchestration).

Deliverable:
- No export business path in JS that calls confirmation directly.

## Phase 4: Enforcement and Anti-Regression

- [ ] Add CI/static checks to fail on prohibited patterns in export orchestration code:
  - `getContext().requestUserConfirmation` in `api/recovery/*`.
  - `getPrfResultsFromCredential` usage in `api/recovery/*`.
  - direct `SHOW_SECURE_PRIVATE_KEY_UI` request construction in main-thread export orchestration.
- [ ] Add architectural lint/test that export requests must enter via worker operation.
- [ ] Add docs comments in sensitive modules describing forbidden patterns.

Deliverable:
- Future regressions trigger CI failures.

## Phase 5: Verification Matrix

- [ ] Unit: worker export operation success (single key and multi-key).
- [ ] Unit: user cancel at first confirmation step.
- [ ] Unit: user cancel at final display step.
- [ ] Unit: timeout and abort handling across both confirmation steps.
- [ ] Unit: no PRF/private key leakage in worker response payloads.
- [ ] Unit: no main-thread helper path exists for export confirmation.
- [ ] Integration: end-to-end export flow in wallet origin.
- [ ] Integration: concurrent export/signing isolation behavior.

Security assertions to test explicitly:

- [ ] Main thread never receives PRF outputs as part of export orchestration API payloads.
- [ ] Main thread never parses PRF from `SecureConfirmDecision` in export flows.
- [ ] Export confirmation requests are initiated from worker runtime only.

## 5. Files to Change (Expected)

Primary:

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
- `client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
- `client/src/core/signingEngine/workerManager/nearKeyOps/exportNearKeypairUi.ts`
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
- `client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts` (if new export-specific confirmation types are required)
- `client/src/core/types/signer-worker.ts` (worker op contracts)

Secondary:

- `client/src/core/signingEngine/interfaces/runtime.ts`
- `client/src/core/signingEngine/bootstrap/*` wiring where needed
- `tests/unit/*` and `tests/e2e/*` for anti-regression coverage

## 6. Rollout Strategy

- [ ] Land Phase 0 guardrails first.
- [ ] Land worker operation protocol and implementation next.
- [ ] Land JS shortcut deletion in the same release cycle (no long-lived dual path).
- [ ] Run full signing/export regression suite before release.

Release gate:

- [ ] Do not ship export flow unless all security invariants in Section 2 are satisfied.

## 7. Done Criteria

- [ ] Export flow is worker-owned end-to-end.
- [ ] `awaitUserConfirmationV2` is the only export confirmation initiation path.
- [ ] No JS export orchestration code directly calls confirmation bridge methods.
- [ ] No JS export orchestration code extracts PRF from credential objects.
- [ ] CI protections exist to prevent architectural regression.
- [ ] Unit + integration coverage validates no secret leakage and no shortcut paths.
