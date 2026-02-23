# Refactor 10: Export Flow Security Hardening (Worker-Owned Confirmation)

Status: Urgent
Severity: High (private-key export flow boundary violation)
Last updated: 2026-02-21

## 1. Problem Statement

Historical issue (resolved by this refactor): export flows relied on JS-main-thread orchestration that should be worker-owned.

Current status: worker-owned export flow is implemented; remaining work is verification hygiene and release-gate evidence refresh.

Historical shortcut points (removed/guarded):

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
  - Previously read `getContext().requestUserConfirmation` and drove confirmation from JS orchestration.
  - Previously sent `DECRYPT_PRIVATE_KEY_WITH_PRF` / `SHOW_SECURE_PRIVATE_KEY_UI` requests directly from JS flow.
  - Previously extracted PRF output from returned credential in JS path.
- `client/src/core/signingEngine/workerManager/nearKeyOps/exportNearKeypairUi.ts`
  - Previously performed JS-side confirmation for export UI display.
  - File removed in Phase 3 cleanup.

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

1. Main thread issues `ExportPrivateKeysWithUi` to the `passkey-confirm` worker.
2. `passkey-confirm` worker initiates confirmation via `awaitUserConfirmationV2`.
3. `passkey-confirm` worker delegates decrypt/derive crypto stage to `near-signer` worker.
4. `near-signer` (or routed callback path) requests main-thread display of `ExportPrivateKeyDrawer` UI.
5. `passkey-confirm` worker returns sanitized result (`ok`/`cancelled`/`error`) without secret material.

### 3.2 Worker responsibility split (explicit decision)

- `passkey-confirm.worker.ts` owns confirmation orchestration (`awaitUserConfirmationV2`) and export flow state machine.
- `near-signer.worker.ts` (Rust/WASM-backed) owns decrypt/derive cryptographic execution.
- Main thread is callback/router only for UI mounting (`ExportPrivateKeyDrawer`), not export business orchestration.

### 3.3 Boundary rule

- JS-main-thread code may request an export operation.
- JS-main-thread code may not orchestrate intermediate confirmation steps for export.
- JS-main-thread code may not inspect credential PRF outputs for export.
- JS export APIs may not depend on `TouchConfirmManager` directly; they must call a worker-operation port.

## 4. Implementation Plan

## Phase 0: Immediate Containment (same day)

- [x] Add hard guardrails in `privateKeyExportRecovery.ts` that block direct export confirmation orchestration when worker-owned flow is not active.
- [x] Add explicit temporary disable for legacy export shortcut entrypoints with typed error code:
  - Example: `SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT`.
- [x] Add telemetry for every blocked legacy path (account/device/request context, no secrets):
  - Example event: `signer.export.legacy_shortcut_blocked`.
- [x] Communicate release note that export flow is under security hardening and fail-closed behavior is intentional.

Deliverable:
- No successful runtime path that performs JS-driven export confirmation orchestration.
- Failures are explicit, typed, and observable (telemetry), not silent breakage.

## Phase 1: Protocol and Type Contracts

- [x] Add dedicated export operation contract to `passkey-confirm` worker messages:
  - Example shape: `EXPORT_PRIVATE_KEYS_WITH_UI`.
- [x] Add explicit near-signer crypto-stage contract invoked by passkey worker:
  - request/response payloads for decrypt/derive inputs/outputs used only within worker runtime boundaries.
- [x] Add explicit callback contract for secure export UI display request from worker runtime to main-thread renderer.
- [x] Define worker payload contract for export intent:
  - `nearAccountId`, requested schemes, UI variant/theme, optional request metadata.
- [x] Define worker response contract without secret outputs:
  - `ok`, `cancelled`, `exportedSchemes`, optional non-sensitive metadata.
- [x] Add explicit export confirmation request types if needed in `touchConfirm/shared/confirmTypes.ts`.
  - No new enum values were required; existing explicit export types remain canonical:
    - `UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF`
    - `UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI`

Deliverable:
- Export flow protocol is explicit, typed, and does not require main-thread secret handling.

## Phase 2: Worker Runtime Implementation

- [x] Implement export orchestration state machine inside `passkey-confirm.worker.ts`.
- [x] Ensure only `passkey-confirm` initiates confirmation via `awaitUserConfirmationV2`.
- [x] Delegate crypto execution (decrypt/derive) to `near-signer` runtime handlers.
- [x] Keep credential handling and PRF extraction inside worker scope only.
- [x] Initiate secure export UI via worker callback/main-thread bridge for `ExportPrivateKeyDrawer`.
- [x] Zeroize/clear sensitive in-memory values as soon as practical after use.

Deliverable:
- End-to-end export flow executes with worker-owned confirmation and key derivation.

## Phase 3: JS Orchestration Cleanup (Delete Shortcuts)

- [x] Refactor `api/recovery/privateKeyExportRecovery.ts` to invoke only the new worker export operation.
- [x] Remove direct `touchConfirmManager` dependency from `privateKeyExportRecovery.ts`; consume a narrow worker-operation callback instead.
- [x] Delete export-local `requestUserConfirmation` helper in `privateKeyExportRecovery.ts`.
- [x] Remove any export path that calls `getContext().requestUserConfirmation` from JS business logic.
- [x] Remove direct PRF extraction from credentials in JS export orchestration.
- [x] Remove/deprecate `workerManager/nearKeyOps/exportNearKeypairUi.ts` confirmation responsibility (or replace with worker-op wrapper that has no confirmation orchestration).

Deliverable:
- No export business path in JS that calls confirmation directly.

## Phase 4: Enforcement and Anti-Regression

- [x] Add CI/static checks to fail on prohibited patterns in export orchestration code:
  - `getContext().requestUserConfirmation` in `api/recovery/*`.
  - `getPrfResultsFromCredential` usage in `api/recovery/*`.
  - direct `SHOW_SECURE_PRIVATE_KEY_UI` request construction in main-thread export orchestration.
- [x] Add architectural lint/test that export requests must enter via worker operation.
- [x] Add docs comments in sensitive modules describing forbidden patterns.

Deliverable:
- Future regressions trigger CI failures.

## Phase 5: Verification Matrix

- [x] Unit: worker export operation success (single key and multi-key).
- [x] Unit: user cancel at first confirmation step.
- [x] Unit: user cancel at final display step.
- [x] Unit: timeout and abort handling across both confirmation steps.
- [x] Unit: no PRF/private key leakage in worker response payloads.
- [x] Unit: no main-thread helper path exists for export confirmation.
- [x] Integration: end-to-end export flow in wallet origin.
- [x] Integration: concurrent export/signing isolation behavior.

Security assertions to test explicitly:

- [x] Main thread never receives PRF outputs as part of export orchestration API payloads.
- [x] Main thread never parses PRF from `SecureConfirmDecision` in export flows.
- [x] Export confirmation requests are initiated from worker runtime only.

## 5. Files to Change (Expected)

Primary:

- `client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts`
- `client/src/core/types/secure-confirm-worker.ts`
- `client/src/core/signingEngine/touchConfirm/TouchConfirmManager.ts`
- `client/src/core/signingEngine/workerManager/workers/passkey-confirm.worker.ts`
- `client/src/core/signingEngine/workerManager/workers/near-signer.worker.ts`
- `client/src/core/signingEngine/workerManager/nearKeyOps/exportNearKeypairUi.ts` (deleted in Phase 3)
- `client/src/core/signingEngine/workerManager/workerTypes.ts`
- `client/src/core/signingEngine/touchConfirm/shared/confirmTypes.ts` (if new export-specific confirmation types are required)
- `client/src/core/types/signer-worker.ts` (worker op contracts)
- `wasm/near_signer/src/types/worker_messages.rs`
- `wasm/near_signer/src/lib.rs`

Secondary:

- `client/src/core/signingEngine/interfaces/runtime.ts`
- `client/src/core/signingEngine/bootstrap/*` wiring where needed
- `wasm/near_signer/src/handlers/*` (export-specific handler wiring)
- `wasm/near_signer/pkg/*` (generated bindings/types; update via codegen step)
- `tests/unit/*` and `tests/e2e/*` for anti-regression coverage

## 5.1 Rust/WASM Codegen Step (explicit)

- [x] After Rust enum/handler changes, regenerate near-signer WASM bindings (`wasm/near_signer/pkg/*`) using the repo’s SDK build/codegen flow.
  - Example command: `pnpm -C sdk build`
- [x] Confirm generated TS enums/types include new/updated request-response variants.
- [x] Treat stale generated bindings as release blockers.

## 6. Rollout Strategy

- [x] Land Phase 0 guardrails first.
- [x] Land worker operation protocol and implementation next.
- [x] Land JS shortcut deletion in the same release cycle (no long-lived dual path).
- [x] Re-run full signing/export regression suite on final merge candidate before release.
  - 2026-02-20 snapshot:
    - `pnpm test:unit` (`221 passed`, `8 skipped`)
    - `pnpm test:wallet-iframe` (`13 passed`)
    - `pnpm check:signing-architecture` (pass)
    - `pnpm -C sdk type-check` (pass)
  - 2026-02-21 targeted refresh:
    - `pnpm check:signing-architecture` (pass)
    - `USE_RELAY_SERVER=0 pnpm -C tests exec playwright test ./unit/privateKeyExportRecovery.hardening.unit.test.ts ./unit/passkeyConfirm.exportFlow.unit.test.ts --reporter=line` (`7 passed`)
  - 2026-02-21 final merge-candidate rerun:
    - `pnpm test:unit` (`223 passed`, `8 skipped`)
    - `pnpm test:wallet-iframe` (`13 passed`)
    - `pnpm check:signing-architecture` (pass)
    - `pnpm -C sdk type-check` (pass)

Release note draft (security hardening communication):

- Export flow now fail-closes when legacy JS-main-thread shortcut paths are encountered.
- Error is explicit and typed: `SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT`.
- Blocked legacy-path attempts emit telemetry event `signer.export.legacy_shortcut_blocked`.
- This behavior is intentional during worker-owned export hardening and prevents silent fallback.

Release gate:

- [x] Do not ship export flow unless all security invariants in Section 2 are satisfied and final full regression rerun is green.

## 7. Done Criteria

- [x] Export flow is worker-owned end-to-end.
- [x] `awaitUserConfirmationV2` is the only export confirmation initiation path.
- [x] No JS export orchestration code directly calls confirmation bridge methods.
- [x] No JS export orchestration code extracts PRF from credential objects.
- [x] CI protections exist to prevent architectural regression.
- [x] Unit + integration coverage validates no secret leakage and no shortcut paths.
