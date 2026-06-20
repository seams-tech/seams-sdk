# Refactor 71 Inventory: ID Rename Surfaces

Date created: June 18, 2026

Status: old grant-name baseline, Agent A public threshold policy/bootstrap
surfaces, and public `sessionId` allowlist closed; Agent B semantic renames
remain.

## Scope

This inventory covers the naming cleanup:

| Current token               | Target token           | Replacement class                                                     |
| --------------------------- | ---------------------- | --------------------------------------------------------------------- |
| `walletSigningSessionId`    | `signingGrantId`       | Direct rename when it identifies the user-approved signing allowance. |
| `WalletSigningSessionId`    | `SigningGrantId`       | Branded type and parser rename.                                       |
| `wallet_signing_session_id` | `signing_grant_id`     | Persistence and wire-field rename at boundary schemas.                |
| `wallet-signing-session`    | `signing-grant`        | Fixtures, string labels, source-guard samples.                        |
| `sessionId`                 | `thresholdSessionId`   | Rename only when it identifies the concrete threshold/MPC session.    |
| `session_id`                | `threshold_session_id` | Rename only for threshold/MPC wire or persistence fields.             |

`sessionId` is overloaded across app sessions, worker sessions, recovery
sessions, request-local variables, and threshold sessions. Treat it as a
classification pass. A mechanical replacement is incorrect.

## Search Baseline

Run these from the repo root before and after implementation:

```sh
rg "WalletSigningSessionId|walletSigningSessionId|wallet_signing_session_id|wallet-signing-session" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests docs --glob '!**/target/**' --glob '!**/node_modules/**' --stats
rg "ThresholdSessionId|thresholdSessionId|threshold_session_id|threshold-session" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests docs --glob '!**/target/**' --glob '!**/node_modules/**' --stats
rg "\bsessionId\b" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests docs wasm crates apps voiceId --glob '!**/target/**' --glob '!**/node_modules/**'
rg "signingGrantId|SigningGrantId|signing_grant_id|signing-grant" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests docs --glob '!**/target/**' --glob '!**/node_modules/**'
```

Initial baseline:

- Old grant name: 3,764 matches across 311 files.
- Existing `thresholdSessionId` spelling: 5,103 matches across 348 files.
- Plain `sessionId`: 291 files across code, tests, docs, Wasm, Rust, and apps.
- Existing target `signingGrantId`: docs only before the grant-ID rename slice.

Current Agent C audit:

- Active package/test TS sources have no direct old grant-name hits:
  `WalletSigningSessionId`, `parseWalletSigningSessionId`,
  `walletSigningSessionId`, `wallet_signing_session_id`, or
  `wallet-signing-session`.
- Live-behavior docs are guarded for old grant-name identifiers and prose
  variants. Historical refactor documents may still mention old terms as
  background context.
- The current source guard also covers Router A/B local smoke Rust fixtures under
  `crates/router-ab-dev/src` and the SecureConfirm app docs page.
- Public/wire `sessionId` surfaces now have an explicit source-guard allowlist.
  The guard now scans exported type/interface shapes recursively, so nested
  response fields are included. Current targeted guards also cover Router A/B
  Wallet Session JWT claims.
  Owner-specific semantic renames remain assigned to Agent B slices; the budget
  projection internal state row, ECDSA registration prepare/client bootstrap row,
  public threshold policy/bootstrap row, and Router A/B route/budget helper
  structs are now closed.

Post-grant rename slice evidence:

- `pnpm -C packages/shared-ts type-check`
- `pnpm -C packages/sdk-server-ts type-check`
- `pnpm -C packages/sdk-web type-check`
- `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/domainIds.boundary.unit.test.ts ./unit/thresholdSessionClaims.unit.test.ts ./unit/signingBudgetStatus.parser.unit.test.ts ./unit/walletSessionBudgetReservation.store.unit.test.ts ./unit/routerAbEd25519BudgetRouteCore.unit.test.ts --reporter=line`
- `rg "WalletSigningSessionId|parseWalletSigningSessionId|walletSigningSessionId|wallet_signing_session_id|wallet-signing-session" packages/shared-ts/src packages/sdk-server-ts/src packages/sdk-web/src tests -g '*.ts'`

## Boundary Decisions

- JWT claims: new tokens should emit `thresholdSessionId` and
  `signingGrantId`. Any support for old claim fields belongs only inside the
  JWT parser, then immediately normalizes to the new internal type.
- HTTP request and response fields: route handlers should accept new names at
  the request boundary and return new names. Old request fields are only a
  temporary parser concern if the route version still needs them.
- IndexedDB and durable records: new writes should use
  `threshold_session_id` and `signing_grant_id`. Existing records should be
  migrated or normalized at the storage boundary.
- Core logic: use branded `ThresholdSessionId` and `SigningGrantId` through a
  verified Wallet Session object.
- Docs and tests: update active docs and current fixtures. Leave older refactor
  docs alone when they are clearly historical.

## Owner Inventory

### Shared IDs And Helpers

Replace the canonical type and parser names first:

- `packages/shared-ts/src/utils/domainIds.ts`
- `packages/shared-ts/src/utils/domainIds.typecheck.ts`
- `tests/unit/domainIds.boundary.unit.test.ts`

Shared protocol helpers carrying the old field:

- `packages/shared-ts/src/utils/signingSessionSeal.ts`
- `packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts`

Expected edits:

- `WalletSigningSessionId` to `SigningGrantId`.
- `parseWalletSigningSessionId` to `parseSigningGrantId`.
- Any `walletSigningSessionId` input field to `signingGrantId`.
- Add or update type fixtures that reject raw strings and invalid branch mixes.

### Server Claims, Admission, And Route Boundaries

Primary server boundary files:

- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
- `packages/sdk-server-ts/src/core/types.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.typecheck.ts`
- `packages/sdk-server-ts/src/router/emailOtpSessionRouteHelpers.ts`
- `packages/sdk-server-ts/src/router/relayWalletRegistration.ts`

Express and Cloudflare route files:

- `packages/sdk-server-ts/src/router/express/routes/sessions.ts`
- `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
- `packages/sdk-server-ts/src/router/cloudflare/createSelfHostedCloudflareSigningWorker.ts`

Related server stores and services:

- `packages/sdk-server-ts/src/core/AuthService.ts`
- `packages/sdk-server-ts/src/core/DeviceLinkingSessionStore.ts`
- `packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts`
- `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.typecheck.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/service.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts`

Expected edits:

- JWT claim `sessionId` to `thresholdSessionId`.
- JWT claim `walletSigningSessionId` to `signingGrantId`.
- Budget binding remains `signingGrantId + curve + thresholdSessionId`.
- Route handlers consume a normalized verified Wallet Session object instead of
  loose string bags.
- Storage key helpers that use `sessionId` for generic store rows may stay
  generic. Fields representing the threshold session should use the target name.

### SDK Web Persistence And IndexedDB

Persistence schema and record boundaries:

- `packages/sdk-web/src/core/indexedDB/schemaNames.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts`

Expected edits:

- Rename the persisted old grant column/index from
  `wallet_signing_session_id` to `signing_grant_id`.
- Keep `threshold_session_id`, `ed25519_threshold_session_id`, and
  `ecdsa_threshold_session_id` where they already mean threshold sessions.
- Normalize or migrate old records at the IndexedDB boundary.

### SDK Web Session, Budget, And Availability

Budget and spend state:

- `packages/sdk-web/src/core/signingEngine/session/budget/budget.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.ts`
  - Closed: internal projection state uses `signingGrantId`; `sessionId` remains
    only at the existing `SigningSessionStatus` boundary.
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.typecheck.ts`
  - Closed: type fixtures reject old internal `sessionId` object shapes.
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator.ts`

Session and lane availability:

- `packages/sdk-web/src/core/signingEngine/session/public.ts`
- `packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/lanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/lanes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/types.typecheck.ts`

Expected edits:

- Replace public and internal grant fields with `signingGrantId`.
- Keep `thresholdSessionId` for concrete threshold session references.
- Rename any status/result field called `sessionId` when it is the threshold
  session identifier exposed to callers.

### SDK Web Identity And Auth-Lane State

Identity files:

- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/subjectIdentityCleanup.typecheck.ts`

Step-up and confirmation files:

- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane.ts`
- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts`
- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/channel/webauthnChallenge.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/adapters/request.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts`

Watch for compound names:

- `authorizingWalletSigningSessionId` to `authorizingSigningGrantId`.
- `mintedWalletSigningSessionId` to `mintedSigningGrantId`.
- Test helper factories under `SigningSessionIds.walletSigningSession(...)`.

### SDK Web Email OTP, Passkey, And Warm Capabilities

Email OTP surfaces:

- `packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedRestoreOrchestrator.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedSigningSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache.typecheck.ts`

Passkey surfaces:

- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/runtime.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner.ts`

Warm capability surfaces:

- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaCapabilityReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistencePorts.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistencePorts.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/public.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts`

### SDK Web RPC, Threshold, Worker, And Use-Case Boundaries

Relayer RPC clients:

- `packages/sdk-web/src/core/rpcClients/relayer/ecdsaUseCaseClient.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.typecheck.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
  - Closed: ECDSA registration prepare/client bootstrap now uses
    `thresholdSessionId`.
  - Closed: nested Ed25519 registration session response now uses
    `thresholdSessionId`.

Threshold protocol surfaces:

- `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession.ts`

Worker and public type surfaces:

- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `packages/sdk-web/src/core/types/secure-confirm-worker.ts`
- `packages/sdk-web/src/core/platform/ports.ts`

Use-case and SeamsWeb surfaces:

- `packages/sdk-web/src/core/signingEngine/useCases/lifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/lifecycle.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`

### SDK Web Signing And Recovery Flows

NEAR signing:

- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbEd25519WalletSessionState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`

EVM-family signing:

- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/budgetSpending.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/emailOtpRefresh.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/provisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts`

Recovery and export:

- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts`
- `packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/near.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/signing.ts`

### Rust, Wasm, Apps, And Docs Outside SDK Packages

Current scans have no direct old grant-name hits in `crates`, `wasm`, `apps`, or
`voiceId`. Agent C follow-up removed stale Router A/B local smoke JWT claim names
from `crates/router-ab-dev/src/bin/router_ab_local_smoke.rs`.

Plain `sessionId` / `session_id` appears in these non-package files and is now
classified by `refactor71WalletSessionNaming.guard.unit.test.ts`:

| File                                                                                      | Classification                                                |
| ----------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| `apps/docs/src/concepts/security-model.md`                                                | keep: SecureConfirm worker session id.                        |
| `apps/web-client/src/flows/demo/hooks/useDemoSigningSession.ts`                           | rename-later: Agent B, mirrors SDK signing-session status.    |
| `crates/signer-core/src/commands/ecdsa_bootstrap.rs`                                      | keep: Email OTP worker session handle id.                     |
| `crates/signer-core/src/commands/ed25519_worker_material.rs`                              | rename-later: Agent B, worker material session binding.       |
| `wasm/near_signer/src/handlers/handle_sign_delegate_action.rs`                            | rename-later: Agent B, Wasm signer request contract.          |
| `wasm/near_signer/src/handlers/handle_sign_nep413_message.rs`                             | rename-later: Agent B, Wasm signer request contract.          |
| `wasm/near_signer/src/handlers/handle_sign_transactions_with_actions.rs`                  | rename-later: Agent B, Wasm signer request contract.          |
| `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_client_verifying_share.rs` | rename-later: Agent B, Wasm material-derive request contract. |
| `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs`      | rename-later: Agent B, Wasm material-derive request contract. |
| `wasm/near_signer/src/threshold/coordinator.rs`                                           | rename-later: Agent B, threshold protocol session plumbing.   |
| `wasm/near_signer/src/threshold/relayer_http.rs`                                          | rename-later: Agent B, threshold protocol route contract.     |
| `wasm/near_signer/src/threshold/signer_backend.rs`                                        | rename-later: Agent B, threshold protocol session plumbing.   |
| `wasm/near_signer/src/threshold/transport.rs`                                             | rename-later: Agent B, threshold protocol route contract.     |
| `wasm/near_signer/src/threshold/worker_material.rs`                                       | rename-later: Agent B, worker material session binding.       |
| `wasm/near_signer/src/types/signing.rs`                                                   | rename-later: Agent B, threshold signer config.               |

Do not rename the Agent B rows in this slice. The guard keeps them classified so
new ambiguous public/wire `sessionId` surfaces cannot appear silently while
Refactor 74 owns signer-core/WASM material restore and unlock/signing flow.

### Tests And Fixtures

Initial baseline representative test groups with direct old-name hits:

- `tests/helpers/thresholdEcdsaTempoFlow.ts`
- `tests/helpers/thresholdEcdsaSealedRefreshHarness.ts`
- `tests/helpers/emailOtpEcdsaTempoFlow.ts`
- `tests/helpers/signingBudgetStatus.ts`
- `tests/e2e/signing-session-regressions.walletIframe.test.ts`
- `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
- `tests/relayer/cloudflare-router.test.ts`
- `tests/relayer/email-otp.routes.test.ts`
- `tests/relayer/email-recovery.prepare.test.ts`
- `tests/relayer/express-router.test.ts`
- `tests/relayer/link-device.prepare.test.ts`
- `tests/relayer/signing-session-seal-router.test.ts`
- `tests/relayer/signingBudgetStatus.fixtures.ts`
- `tests/relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts`
- `tests/relayer/threshold-ecdsa.signature-harness.test.ts`
- `tests/relayer/threshold-ed25519.scheme-dispatch.test.ts`
- `tests/unit/sessionTokens.unit.test.ts`
- `tests/unit/signingBudgetStatus.parser.unit.test.ts`
- `tests/unit/thresholdSessionClaims.unit.test.ts`
- `tests/unit/thresholdSigningService.walletBudgetConsume.unit.test.ts`

Large unit-test families also reference the old grant name:

- Available-lane and readiness tests.
- Email OTP session and recovery tests.
- ECDSA identity, material, selection, export, and budget tests.
- Passkey recovery and warm-session tests.
- Sealed session and signing-session seal tests.
- Source guards and public-surface guards.
- Router A/B Wallet Session tests.

Expected edits:

- Update fixtures to new names.
- Delete fixtures that encode old names as current intended behavior.
- Add `@ts-expect-error` fixtures for invalid raw-string and branch-mixing
  constructions.
- Add source guards that fail on old public names after the refactor.

### Active Docs To Update

Update active docs that describe current behavior:

- `docs/refactor-71-rename-id.md`
- `apps/docs/src/concepts/secureconfirm-sessions.md`
- `docs/refactor-68-wallet-session-v2.md`
- `docs/router-a-b-cleanup.md`
- `docs/router-a-b-SPEC.md`
- `docs/refactor-74-login-no-hss.md`
- `docs/otp/email-otp.md`
- `docs/intended-behaviours.md`
- `docs/ml-dsa-threshold.md`
- `docs/signing-session-architecture/README.md`
- `docs/signing-session-architecture/sealed-refresh.md`
- `docs/threshold-ecdsa/ecdsa-hss-v2-integration.md`

Historical docs with old terms should usually stay historical unless they are
being promoted as active source of truth:

- `docs/refactor-27-nonce-coordinator.md`
- `docs/refactor-33.md`
- `docs/refactor-34-email-otp-coordinator.md`
- `docs/refactor-35-sealed-recovery.md`
- `docs/refactor-36.md`
- `docs/refactor-36a-reduce-near-account-id-usage.md`
- `docs/refactor-37.md`
- `docs/refactor-39.md`
- `docs/refactor-40.md`
- `docs/refactor-41.md`
- `docs/refactor-42-stricter-union-types.md`
- `docs/refactor-45-consolidate-indexeddb-tables.md`
- `docs/refactor-46-wallet-id.md`
- `docs/refactor-46d-bugs.md`
- `docs/refactor-49-stepup-budget.md`
- `docs/refactor-50-cross-platform-1.md`
- `docs/refactor-51-cross-platform-2.md`

## Initial Direct Old Grant-Name File List

The initial baseline found at least one of these old grant-name tokens in the
files below:
`WalletSigningSessionId`, `walletSigningSessionId`,
`wallet_signing_session_id`, or `wallet-signing-session`.

### Code

- `packages/shared-ts/src/utils/domainIds.ts`
- `packages/shared-ts/src/utils/domainIds.typecheck.ts`
- `packages/shared-ts/src/utils/signingSessionSeal.ts`
- `packages/shared-ts/src/threshold/ecdsaHssRoleLocalBootstrap.ts`
- `packages/sdk-server-ts/src/core/AuthService.ts`
- `packages/sdk-server-ts/src/core/DeviceLinkingSessionStore.ts`
- `packages/sdk-server-ts/src/core/EmailRecoveryPreparationStore.ts`
- `packages/sdk-server-ts/src/core/RegistrationCeremonyStore.typecheck.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/CloudflareDurableObjectStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/SessionStore.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/thresholdPrfWasm.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/walletSigningBudget.ts`
- `packages/sdk-server-ts/src/core/types.ts`
- `packages/sdk-server-ts/src/router/cloudflare/createSelfHostedCloudflareSigningWorker.ts`
- `packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/sessions.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/router/cloudflare/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
- `packages/sdk-server-ts/src/router/emailOtpSessionRouteHelpers.ts`
- `packages/sdk-server-ts/src/router/express/routes/sessions.ts`
- `packages/sdk-server-ts/src/router/express/routes/thresholdEcdsa.ts`
- `packages/sdk-server-ts/src/router/express/routes/thresholdEd25519.ts`
- `packages/sdk-server-ts/src/router/relayWalletRegistration.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.typecheck.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/policy/sessionPolicy.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/service.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/types.ts`
- `packages/sdk-web/src/SeamsWeb/operations/auth/login.ts`
- `packages/sdk-web/src/SeamsWeb/operations/devices/linkDevice.ts`
- `packages/sdk-web/src/SeamsWeb/operations/recovery/emailRecovery.ts`
- `packages/sdk-web/src/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.ts`
- `packages/sdk-web/src/core/indexedDB/schemaNames.ts`
- `packages/sdk-web/src/core/platform/ports.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/ecdsaUseCaseClient.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/thresholdEcdsa.typecheck.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
- `packages/sdk-web/src/core/signingEngine/assembly/ports/near.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportFlow.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaExportMaterial.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/ecdsaHssExport.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportKeypairOperation.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
- `packages/sdk-web/src/core/signingEngine/flows/recovery/nearEd25519ExportFlow.ts`
- `packages/sdk-web/src/core/signingEngine/flows/registration/services/ecdsaRegistrationSessions.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/budgetSpending.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaLanes.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaMaterialState.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaReadiness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/ecdsaSelection.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/emailOtpRefresh.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/provisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbEd25519WalletSessionState.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/signingSessionAuthMode.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signDelegate.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNear.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signNep413.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/signTransactions.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/near.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/operationDeps.ts`
- `packages/sdk-web/src/core/signingEngine/interfaces/signing.ts`
- `packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/BudgetCoordinator.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budget.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budget.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetFinalizer.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetProjection.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/appSessionJwtCache.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/companionSessions.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaBootstrapCommit.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaPublication.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/ed25519Warmup.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/exportRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/persistedSnapshot.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/provisioning.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedRestoreOrchestrator.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/sealedSigningSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/workerRequests.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/emailOtpHssIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/selectLane.ts`
- `packages/sdk-web/src/core/signingEngine/session/identity/subjectIdentityCleanup.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/lanes/laneWarmSessionBinding.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/lanes.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/lanes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/postSignPolicy.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/transactionState.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/operationState/types.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaBootstrap.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaRecovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaSessionProvision.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ecdsaWarmCapabilityBootstrap.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519Recovery.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/ed25519SessionProvision.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/runtime.ts`
- `packages/sdk-web/src/core/signingEngine/session/passkey/unlockEcdsaWarmupPlanner.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/records.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.ts`
- `packages/sdk-web/src/core/signingEngine/session/persistence/sealedSessionStore.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/postconditions/runtimePostconditions.ts`
- `packages/sdk-web/src/core/signingEngine/session/public.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/exactRecordLookup.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/recoveryRecord.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts`
- `packages/sdk-web/src/core/signingEngine/session/sealedRecovery/types.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/capabilityReaderCore.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaCapabilityReadiness.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/ecdsaProvisionPlan.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistence.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistencePorts.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/persistencePorts.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/public.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/readModel.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/routerAbEcdsaWalletSessionAuth.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/types.ts`
- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/channel/webauthnChallenge.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane.ts`
- `packages/sdk-web/src/core/signingEngine/stepUpConfirmation/types.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/activation.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/connectSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/presignPool.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/sessionPolicy.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/UiConfirmManager.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/adapters/request.ts`
- `packages/sdk-web/src/core/signingEngine/uiConfirm/handlers/flows/signing.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/lifecycle.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/lifecycle.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsa.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/useCases/provisionEcdsaSession.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.typecheck.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workers/email-otp.worker.ts`
- `packages/sdk-web/src/core/types/secure-confirm-worker.ts`

### Tests

- `tests/e2e/signing-session-regressions.walletIframe.test.ts`
- `tests/e2e/thresholdEcdsa.tempoSigning.test.ts`
- `tests/helpers/emailOtpEcdsaTempoFlow.ts`
- `tests/helpers/signingBudgetStatus.ts`
- `tests/helpers/thresholdEcdsaSealedRefreshHarness.ts`
- `tests/helpers/thresholdEcdsaTempoFlow.ts`
- `tests/relayer/cloudflare-router.test.ts`
- `tests/relayer/email-otp.routes.test.ts`
- `tests/relayer/email-recovery.prepare.test.ts`
- `tests/relayer/express-router.test.ts`
- `tests/relayer/link-device.prepare.test.ts`
- `tests/relayer/signing-session-seal-router.test.ts`
- `tests/relayer/signingBudgetStatus.fixtures.ts`
- `tests/relayer/threshold-ecdsa-role-local-passkey-bootstrap.test.ts`
- `tests/relayer/threshold-ecdsa.signature-harness.test.ts`
- `tests/relayer/threshold-ed25519.scheme-dispatch.test.ts`
- `tests/unit/activateSigningSessionUseCase.unit.test.ts`
- `tests/unit/addWalletSigner.orchestration.unit.test.ts`
- `tests/unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts`
- `tests/unit/availableSigningLanes.ed25519Duplicates.unit.test.ts`
- `tests/unit/cloudflareSelfHostedSigningWorker.script.unit.test.ts`
- `tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts`
- `tests/unit/domainIds.boundary.unit.test.ts`
- `tests/unit/ecdsaBootstrapWarmPersistence.unit.test.ts`
- `tests/unit/ecdsaExportMaterial.unit.test.ts`
- `tests/unit/ecdsaMaterialState.unit.test.ts`
- `tests/unit/ecdsaRoleLocalRecords.unit.test.ts`
- `tests/unit/ecdsaSelection.restorable.unit.test.ts`
- `tests/unit/emailOtpAppSessionJwtCache.unit.test.ts`
- `tests/unit/emailOtpAuthLane.unit.test.ts`
- `tests/unit/emailOtpEcdsaBranchIsolation.guard.unit.test.ts`
- `tests/unit/emailOtpEcdsaPublication.unit.test.ts`
- `tests/unit/emailOtpEcdsaSigningSessionAuth.unit.test.ts`
- `tests/unit/emailOtpWalletSessionCoordinator.unit.test.ts`
- `tests/unit/evmFamily.requestBoundary.unit.test.ts`
- `tests/unit/evmFamilyBudgetSpending.unit.test.ts`
- `tests/unit/evmFamilyEcdsaIdentity.unit.test.ts`
- `tests/unit/evmFamilyStepUpProvisionPlan.unit.test.ts`
- `tests/unit/evmSigning.thresholdReconnectEvents.unit.test.ts`
- `tests/unit/exportKeysUseCase.unit.test.ts`
- `tests/unit/exportLaneSelection.unit.test.ts`
- `tests/unit/helpers/availableSigningLanes.fixtures.ts`
- `tests/unit/helpers/warmSessionStore.fixtures.ts`
- `tests/unit/nearSigning.sessionSelection.unit.test.ts`
- `tests/unit/nonceCoordinator.durableArchitecture.guard.unit.test.ts`
- `tests/unit/nonceCoordinator.unit.test.ts`
- `tests/unit/passkeyEd25519Recovery.unit.test.ts`
- `tests/unit/persistedAvailableSigningLanes.emailOtpEd25519.unit.test.ts`
- `tests/unit/phase5UseCaseServices.unit.test.ts`
- `tests/unit/provisionEcdsaUseCase.unit.test.ts`
- `tests/unit/registrationCeremonyStore.unit.test.ts`
- `tests/unit/registrationIntentAllocation.unit.test.ts`
- `tests/unit/relayWalletRegistration.boundary.unit.test.ts`
- `tests/unit/requireEvmFamilyStepUpAuth.unit.test.ts`
- `tests/unit/requireNearStepUpAuth.unit.test.ts`
- `tests/unit/routerAbEd25519.walletSessionState.unit.test.ts`
- `tests/unit/runtimePostconditions.unit.test.ts`
- `tests/unit/sealedRecovery.methodAdapters.unit.test.ts`
- `tests/unit/sealedSessionStore.unit.test.ts`
- `tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts`
- `tests/unit/sessionTokens.unit.test.ts`
- `tests/unit/signingBudgetStatus.parser.unit.test.ts`
- `tests/unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts`
- `tests/unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts`
- `tests/unit/signingFlow.readySigner.unit.test.ts`
- `tests/unit/signingPostSignPolicy.unit.test.ts`
- `tests/unit/signingSession.state.unit.test.ts`
- `tests/unit/signingSessionBudgetFinalizer.unit.test.ts`
- `tests/unit/signingSessionCoordinator.ecdsaStepUp.unit.test.ts`
- `tests/unit/signingSessionFreshness.unit.test.ts`
- `tests/unit/signingSessionRestoreCoordinator.unit.test.ts`
- `tests/unit/signingSessionSeal.sessionPolicy.unit.test.ts`
- `tests/unit/signingSessionSeal.shared.unit.test.ts`
- `tests/unit/signingSessionTypes.unit.test.ts`
- `tests/unit/stepUpAuthorization.builders.unit.test.ts`
- `tests/unit/thresholdEcdsa.authorizationBootstrapVerifier.unit.test.ts`
- `tests/unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts`
- `tests/unit/thresholdEcdsa.hssBootstrapPolicy.unit.test.ts`
- `tests/unit/thresholdEcdsa.hssRoleLocalClientParser.unit.test.ts`
- `tests/unit/thresholdEcdsa.hssRoleLocalExportPolicy.unit.test.ts`
- `tests/unit/thresholdEcdsa.signingRootResolver.script.unit.test.ts`
- `tests/unit/thresholdEcdsaChainTarget.unit.test.ts`
- `tests/unit/thresholdEcdsaEmailOtpConsumption.unit.test.ts`
- `tests/unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts`
- `tests/unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts`
- `tests/unit/thresholdEd25519.presignPool.unit.test.ts`
- `tests/unit/thresholdEd25519.presignStore.unit.test.ts`
- `tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts`
- `tests/unit/thresholdEd25519.sessionPolicyDigest.unit.test.ts`
- `tests/unit/thresholdSessionClaims.unit.test.ts`
- `tests/unit/thresholdSigningService.walletBudgetConsume.unit.test.ts`
- `tests/unit/touchConfirm.orchestrationBridge.unit.test.ts`
- `tests/unit/touchConfirm.signingAuthPlanValidation.unit.test.ts`
- `tests/unit/touchConfirm.workerRouter.integration.test.ts`
- `tests/unit/unlockEcdsaWarmupPlanner.unit.test.ts`
- `tests/unit/warmSessionEcdsaProvisioning.unit.test.ts`
- `tests/unit/warmSessionStore.bootstrapResolution.unit.test.ts`
- `tests/unit/warmSessionStore.capabilityResolution.unit.test.ts`
- `tests/unit/warmSessionStore.concurrency.unit.test.ts`
- `tests/unit/warmSessionStore.errorNormalization.unit.test.ts`
- `tests/unit/warmSessionStore.invariants.unit.test.ts`
- `tests/unit/warmSessionStore.reconnect.unit.test.ts`
- `tests/unit/warmSessionStore.transitions.unit.test.ts`
- `tests/unit/warmSessionTransitions.unit.test.ts`

### Docs

- `docs/intended-behaviours.md`
- `docs/ml-dsa-threshold.md`
- `docs/otp/email-otp.md`
- `docs/refactor-27-nonce-coordinator.md`
- `docs/refactor-33.md`
- `docs/refactor-34-email-otp-coordinator.md`
- `docs/refactor-35-sealed-recovery.md`
- `docs/refactor-36.md`
- `docs/refactor-36a-reduce-near-account-id-usage.md`
- `docs/refactor-37.md`
- `docs/refactor-39.md`
- `docs/refactor-40.md`
- `docs/refactor-41.md`
- `docs/refactor-42-stricter-union-types.md`
- `docs/refactor-45-consolidate-indexeddb-tables.md`
- `docs/refactor-46-wallet-id.md`
- `docs/refactor-46d-bugs.md`
- `docs/refactor-49-stepup-budget.md`
- `docs/refactor-50-cross-platform-1.md`
- `docs/refactor-51-cross-platform-2.md`
- `docs/refactor-71-rename-id.md`
- `docs/router-a-b-cleanup.md`
- `docs/signing-session-architecture/README.md`
- `docs/signing-session-architecture/sealed-refresh.md`
- `docs/threshold-ecdsa/ecdsa-hss-v2-integration.md`

## SessionId Classification Checklist

Classify plain `sessionId` hits into these buckets before renaming:

- Rename to `thresholdSessionId`: JWT threshold claims, threshold route request
  fields, threshold bootstrap responses, wallet-session status responses, Router
  A/B Wallet Session credentials, threshold session policies, threshold session
  store records, signing budget status records, and threshold-specific test
  fixtures.
- Keep as `sessionId`: app/browser auth sessions, Email OTP worker sessions,
  recovery execution sessions, device-linking sessions, local generic store
  helper parameters, request-correlation ids, and generic map keys.
- Remove: unused Wasm request fields whose only role was carrying an old
  threshold session id through a derivation boundary.

High-risk `sessionId` files to inspect first:

- `packages/sdk-server-ts/src/router/commonRouterUtils.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/validation.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService.ts`
- `packages/sdk-server-ts/src/router/signingBudgetStatus.ts`
- `packages/sdk-server-ts/src/router/relayWalletRegistration.ts`
- `packages/sdk-web/src/core/rpcClients/relayer/walletRegistration.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts`
- `packages/sdk-web/src/core/signingEngine/threshold/ed25519/walletSession.ts`
- `packages/sdk-web/src/core/signingEngine/session/routerAbSigningWalletSession.ts`
- `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/routerAbWalletSessionCredential.ts`
- `packages/sdk-web/src/core/signingEngine/session/budget/budgetStatusReader.ts`
- `packages/sdk-web/src/core/signingEngine/session/availability/readiness.ts`
- `packages/sdk-web/src/core/signingEngine/session/emailOtp/routePlan.ts`
- `packages/sdk-web/src/core/signingEngine/session/warmCapabilities/statusReader.ts`
- `packages/sdk-web/src/core/signingEngine/workerManager/workerTypes.ts`
- `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_client_verifying_share.rs`
- `wasm/near_signer/src/handlers/handle_threshold_ed25519_derive_hss_client_inputs.rs`
- `apps/web-client/src/flows/demo/hooks/useDemoSigningSession.ts`
- `tests/unit/thresholdSessionClaims.unit.test.ts`
- `tests/unit/sessionTokens.unit.test.ts`
- `tests/unit/signingBudgetStatus.parser.unit.test.ts`

## Implementation Order

1. Rename shared branded IDs and parsers.
2. Rename server claim parsers and Wallet Session JWT emission.
3. Rename server budget/status and route-boundary DTOs.
4. Rename storage schemas and persistence boundary parsers.
5. Rename SDK public and internal state surfaces.
6. Rename worker/RPC DTOs.
7. Rename signing, recovery, and availability flows.
8. Rename tests and fixtures.
9. Update active docs.
10. Add source guards and run targeted type checks.

## Completion Guards

After implementation, these should return no current-code hits outside the
inventory, historical docs, or intentional boundary parsers:

```sh
rg "WalletSigningSessionId|walletSigningSessionId|wallet_signing_session_id|wallet-signing-session" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests docs --glob '!**/target/**' --glob '!**/node_modules/**'
rg "\bsessionId\b" packages/sdk-server-ts/src packages/sdk-web/src packages/shared-ts/src tests --glob '!**/target/**' --glob '!**/node_modules/**'
```

The second guard needs an allowlist because unrelated app/recovery/worker
session identifiers should remain `sessionId`.

The current source guard is:

```sh
pnpm -C tests exec playwright test -c playwright.config.ts unit/refactor71WalletSessionNaming.guard.unit.test.ts --reporter=line
```

It rejects old signing-grant names, Router A/B Wallet Session JWT payloads that
use `sessionId`, unclassified exported `sessionId` public surfaces, and
unclassified non-package boundary files containing `sessionId` / `session_id`.
