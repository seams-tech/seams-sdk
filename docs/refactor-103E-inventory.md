# Refactor 103E implementation inventory

Inventory baseline: R114 merge `a582aac1c` is in `dev` history. This ledger is
the ownership and deletion manifest for implementing `refactor-103E.md`.

Legend:

- **ADD** — new canonical code or coverage.
- **CHANGE** — retained file whose behavior or contract changes.
- **DELETE** — obsolete after its named replacement is working.
- **INSPECT** — shared file with linked-device consumers; edit only when import tracing proves it necessary.
- **PRESERVE** — similar vocabulary, different invariant; do not delete.

The broad legacy-symbol scan reaches 171 files. Many are import consumers. The
lists below identify the owning implementation areas and the import-trace set
that must be checked before cutover.

## 1. Foundation checkpoint

### Canonical authority and identity

- **ADD** `packages/shared-ts/src/authorization/walletAuthority.ts`
  - `WalletAuthorityV1`, lifecycle branches, principal, provenance.
  - `WalletSignerActivationSetV1` and family-specific activation members.
  - canonical activation-set and authority digest encoders.
  - branch-specific parsers and builders.
- **CHANGE** `packages/shared-ts/src/utils/domainIds.ts`
  - add only `WalletAuthorityId` and `parseWalletAuthorityId`.
- **CHANGE** `packages/shared-ts/src/utils/registrationIntent.ts`
  - v2 `WalletAuthMethodRecord` with required opaque method ID, authority ID,
    wallet ID, and exact pending/active/revoked lifecycle.
  - remove factor-derived canonical ID construction after boundary cutover.
- **CHANGE** `packages/shared-ts/src/authorization/delegatedAuthority.ts`
  - retain permission parsing, `FULL_OWNER_PERMISSIONS`, and attenuation.
  - delete the permission-only durable authority shape after all callers use
    `WalletAuthorityV1.permissions`.
- **CHANGE** `packages/shared-ts/src/authorization/capabilityKinds.ts`
  - use canonical `DeviceId`.
  - ordinary Wallet Session authorization carries authority ID, auth-method ID,
    authority digest, epoch, and exact subjects.
  - delete linked-device Wallet Session identity and grant branches after the
    ordinary authorization cutover.

### Device-link boundary contracts

- **CHANGE** `packages/shared-ts/src/device-linking/contracts.ts`
  - exact `LinkSessionStateV1`.
  - `VerifiedSourceAuthorityV1`, `VerifiedTargetFactorV1`,
    `VerifiedLinkInputV1`.
  - committed package, local installation receipt, activation and resolution
    result unions.
- **CHANGE** `packages/shared-ts/src/device-linking/parsers.ts`
  - parse raw wire IDs once into branded identities.
  - recompute package and authority digests.
  - keep legacy identity handling at the migration/request boundary only.
- **CHANGE** `packages/shared-ts/src/device-linking/digests.ts`
  - canonical domain-separated activation-set, authority, and package-set
    encoders.
- **CHANGE/DELETE** `packages/shared-ts/src/device-linking/delegatedActivationPlan.ts`
  - preserve `ExactAdministeredSignerManifestV1`.
  - delete `DelegatedDeviceActivationPlanV1`, its opaque proof/parser, and
    `ExactAdministeredSignerActivationSetV1` after callers migrate.
- **DELETE** `packages/shared-ts/src/device-linking/ownerAuthBinding.ts`
- **DELETE** `packages/shared-ts/src/device-linking/ownerAuthBinding.typecheck.ts`
- **CHANGE** shared barrel files under `packages/shared-ts/src/` after the new
  contract compiles and deleted exports have no consumers.

### Shared import-trace set

- **INSPECT** `packages/shared-ts/src/utils/walletAuthAuthority.ts` — factor
  evidence currently uses authority vocabulary; it cannot become a second
  durable authority model.
- **INSPECT** `packages/shared-ts/src/signing-lanes/{ids,records,recordParsers,execution,rotation,rotationLifecycle,rotationParsers}.ts`
  — remove linked R102 ownership and candidate paths while retaining generic
  lane protocol records.
- **INSPECT** `packages/shared-ts/src/passkey-custody/custodySecretBinding.ts`
  — preserve R114 recovery and factor-addition custody proofs; linking never
  receives a custody seed.
- **PRESERVE** `packages/shared-ts/src/device-linking/ed25519ExportRoot.ts`
  — one-use Ed25519 export-root transport, updated to canonical identities.

## 2. Server authority lifecycle and D1

### Authority and auth-method persistence

- **ADD** D1 `wallet_authorities` table, constraints, indexes, parser, store,
  and transaction helpers under
  `packages/wallet-server/src/router/cloudflare/d1/`.
- **CHANGE** `packages/wallet-server/src/core/d1WalletAuthMethodStore.ts`.
- **CHANGE** `packages/wallet-server/src/core/WalletAuthMethodStore.ts`.
- **CHANGE** `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodBoundary.ts`.
- **CHANGE** `packages/wallet-server/src/router/cloudflare/d1/wallet/d1WalletAuthMethodService.ts`.
- **CHANGE** `packages/wallet-server/src/router/cloudflare/d1/auth/d1RouterApiAuthService.ts`.
- **CHANGE** `packages/wallet-server/src/core/registrationContracts.ts`.
- **CHANGE** `packages/wallet-server/src/router/domains/walletRegistration/walletRegistrationRoutes.ts`
  — registration creates the founding active authority and first active method.

### Link-session and activation core

- **CHANGE** `packages/wallet-server/src/core/deviceLinking/linkedDeviceSession.ts`
  — exact linear states and pending-authority retry semantics.
- **CHANGE** `packages/wallet-server/src/core/deviceLinking/linkedDeviceManagement.ts`
  — inventory and revocation from exact authorities.
- **CHANGE** `packages/wallet-server/src/core/deviceLinking/linkedDeviceEmailOtpGrant.ts`
  — one-use verified target factor.
- **DELETE** `packages/wallet-server/src/core/deviceLinking/linkedOwnerEnrollmentAdmission.ts`.
- **DELETE** `packages/wallet-server/src/core/deviceLinking/linkedOwnerEnrollmentProvenance.ts`.
- **INSPECT** `packages/wallet-server/src/core/deviceLinking/requestProof.ts`.
- **PRESERVE/CHANGE** `packages/wallet-server/src/core/deviceLinking/linkedDeviceEd25519ExportRoot.ts`.

### D1 device-linking directory

All files are under
`packages/wallet-server/src/router/cloudflare/d1/deviceLinking/`.

- **CHANGE** `d1LinkedDeviceSessionRecords.ts`,
  `d1LinkedDeviceSessionStore.ts`, `d1LinkedDeviceSessionService.ts`.
- **CHANGE** `d1LinkedDeviceRouteService.ts` — commit pending authority,
  validate receipt, activate, finalize, and resume.
- **CHANGE** `d1LinkedDeviceOwnerAuthorizationProvider.ts` — verify exact active
  source authority, method, digest, epoch, manifest, and attenuation.
- **CHANGE** `d1LinkedDeviceTargetCredentialProvider.ts`,
  `d1LinkedDeviceTargetAuthenticatorStore.ts`,
  `d1LinkedDeviceEmailOtpTargetFactor.ts`,
  `d1LinkedDeviceEmailOtpGrantStore.ts`.
- **CHANGE** `d1LinkedDeviceManagementComposition.ts`,
  `d1LinkedDeviceManagementRouteService.ts`.
- **DELETE/REPLACE** `d1LinkedDeviceManagementStore.ts` projection reads with
  authority-table queries.
- **DELETE** `d1LinkedDeviceOwnerAuthBindingStore.ts`.
- **DELETE** `d1LinkedDeviceExecutionAdmissionResolver.ts`.
- **DELETE** `d1LinkedDeviceWalletSessionIssuer.ts`.
- **DELETE/REPLACE** `d1LinkedDeviceLocalStateInvalidation.ts` with ordinary
  authority/method revocation cleanup.
- **DELETE/REPLACE** `d1LinkedDeviceAggregateActivationVerifier.ts` and
  `d1LinkedDeviceCompletionAdapters.ts` with exact receipt activation.
- **CHANGE** `d1LinkedDeviceTargetPlanner.ts` to build the in-memory install
  plan and allocate fresh exact activation refs.
- **DELETE** `d1LinkedDeviceOwnerPlanningDeployment.ts`,
  `d1LinkedDeviceOwnerPlanningSnapshotStore.ts`,
  `d1LinkedDeviceOwnerPlanningSnapshotStoreParser.ts`,
  `d1LinkedDeviceOwnerPlanningSnapshotWriter.ts`,
  `d1LinkedDeviceLaneLifecycleAuthorization.ts`,
  `linkedDeviceR102ProvisioningExecution.ts`.
- **DELETE/REPLACE** `d1LinkedDeviceProvisioningProvider.ts`,
  `d1LinkedDeviceProvisioningVerifier.ts`,
  `d1LinkedDeviceSourceHandoffProvider.ts`, and
  `d1LinkedDeviceGatewayCompletionService.ts` after ordinary inactive worker
  reservations and authority activation work.
- **INSPECT** `d1LinkedDeviceTargetDeploymentDescriptorProvider.ts` and
  `d1LinkedDeviceTargetDeploymentDescriptorRuntime.ts`; retain only reusable
  worker reservation/package behavior.
- **PRESERVE/CHANGE** `d1LinkedDeviceRequestProofNonceStore.ts` and
  `d1LinkedDeviceEd25519ExportRootStore.ts`.
- **CHANGE** directory `index.ts` after import cutover.

### Ordinary authorization and admission

- **CHANGE** `packages/wallet-server/src/authorization/domain.ts`.
- **CHANGE** `packages/wallet-server/src/authorization/service.ts`.
- **CHANGE** `packages/wallet-server/src/router/cloudflare/d1/authorization/d1AuthorizationStore.ts`.
- **CHANGE** `packages/wallet-server/src/router/auth/verifiedWalletSessionAuth.ts`.
- **CHANGE** `packages/wallet-server/src/router/auth/commonRouterUtils.ts`.
- **CHANGE** `packages/wallet-server/src/router/framework/authServicePort.ts`.
- **CHANGE** `packages/wallet-server/src/router/domains/signingOperations/walletExecutionAdmission.ts`.
- **INSPECT** `packages/wallet-server/src/core/ThresholdService/validation.ts`.
- **DELETE** linked authorization, renewal, quota, local-presence, and
  linked-normal-signing branches after ordinary authority admission works.

### Route and wire cutover

- **CHANGE** `packages/wallet-server/src/router/transport/fetch/routes/deviceLinking.ts`.
- **CHANGE** `packages/wallet-server/src/router/transport/fetch/routes/deviceManagement.ts`.
- **CHANGE** `packages/wallet-server/src/router/transport/fetch/createFetchRouter.ts`.
- **DELETE/REPLACE** `deviceLinkingGateway.ts`, `deviceLinkingLaneGateway.ts`,
  and `deviceLinkingOwnerAuthorization.ts` R102/owner-lane branches.
- **DELETE** `linkedDeviceNormalSigning.ts`, `linkedDeviceEcdsaPresign.ts`, and
  `packages/wallet-server/src/router/domains/signingOperations/linkedDeviceNormalSigning.ts`.
- **INSPECT** ordinary `normalSigningRouterProxy.ts`, `sessions.ts`,
  `thresholdEd25519.ts`, and `thresholdEcdsa.ts` for linked authorization
  branches only.

## 3. D1 schema inventory

### Add or rebuild

- **ADD** `wallet_authorities` with lifecycle/provenance/digest/epoch checks and
  required indexes from R103E.
- **CHANGE** `wallet_auth_methods` to require opaque ID and authority FK.
- **CHANGE** console D1 table manifests in
  `packages/wallet-console-server-ts/src/router/cloudflare/d1LocalDevWorker.ts`
  and `d1RouterApiStagingWorker.ts`.

Historical migrations under
`packages/wallet-server/migrations/d1-signer/` remain history. Add a reset/new
migration for the chosen environment policy; do not turn compatibility into a
runtime framework.

### Delete after authority cutover

- `linked_device_owner_planning_snapshots`
- `linked_device_provisioning_records`
- `linked_device_source_handoffs`
- `linked_device_target_deployment_descriptors`
- `linked_device_wallet_session_authorizations`
- `linked_device_wallet_session_quotas`
- `linked_device_owner_auth_bindings`
- linked R102 lane/promotion rows and linked-only indexes.
- linked authorization identity/revoke/quota triggers and
  `authorized_operation_linked_grant_claim_atomic`.

### Retain as temporary boundary state

- `linked_device_request_proof_nonces`
- `linked_device_session_transcripts`
- `linked_device_sessions`
- `linked_device_session_cas_guard`
- `linked_device_target_commit_reservations`
- `linked_device_target_credentials`
- `linked_device_email_otp_grants`
- `linked_device_ed25519_export_root_transfers`

## 4. Browser and IndexedDB

- **CHANGE** `packages/wallet/src/core/indexedDB/schemaNames.ts` and
  `packages/wallet/src/core/indexedDB/seamsWalletDB/schema.ts`.
- **CHANGE** `packages/wallet/src/core/indexedDB/passkeyClientDB.types.ts`.
- **CHANGE** `packages/wallet/src/core/indexedDB/unifiedIndexedDBManager.ts`.
- **CHANGE** `packages/wallet/src/core/indexedDB/seamsWalletDB/repositories.ts`
  — one authority-install transaction and exact readers.
- **CHANGE** `packages/wallet/src/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore.ts`.
- **DELETE** `packages/wallet/src/core/indexedDB/seamsWalletDB/linkedDeviceWalletSessionStore.ts`.
- **DELETE** `packages/wallet/src/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore.ts`.
- **CHANGE** `packages/wallet/src/core/indexedDB/index.ts`.
- **ADD** a `walletAuthorities` store only if no existing aggregate store can
  persist exact `WalletAuthorityV1` records.
- **DELETE** IndexedDB stores `linked_device_wallet_sessions` and
  `linked_device_execution_evidence` after the new transaction works.

### Exact reload, lock, and unlock

- **CHANGE** `packages/wallet/src/core/signingEngine/useCases/unlockWallet.ts`.
- **CHANGE** `packages/wallet/src/SeamsWeb/operations/auth/login.ts`.
- **INSPECT** persisted session, sealed-session, warm-capability, and restore
  modules under `packages/wallet/src/core/signingEngine/session/`.
- **DELETE** linked candidate scans, linked-session reads, R102 hydration, and
  repair-on-unlock paths.
- **ADD** durable monotonic lock generation and stale-result rejection.

## 5. Browser linking orchestration

All primary files are under
`packages/wallet/src/SeamsWeb/operations/devices/`.

- **CHANGE** `deviceLinkingPorts.ts`, `deviceLinkingComposition.ts`,
  `deviceLinkingHttpTransport.ts`, `deviceLinkingOwnerTransport.ts`,
  `deviceLinkingTargetCredential.ts`, `linkDevice.ts`, `scanDevice.ts`, and
  `qrLinkSession.ts`.
- **DELETE** `deviceLinkingLaneProvisioning.ts` and
  `deviceLinkingOwnerEnrollmentStart.ts`.
- **DELETE** `linkedDeviceSigningRuntime.ts`.
- **DELETE/REPLACE** `linkedDeviceLocalStateInvalidation.ts`.
- **CHANGE** `walletHostOwnerAuthority.ts` and `walletHostComposition.ts`.
- **DELETE** `walletHostSourceLanePorts.ts` after exact source-authority
  verification lands.
- **INSPECT** `deviceLinkingWorkerChannels.ts`; reuse ordinary family-specific
  material reservation APIs.
- **PRESERVE/CHANGE** `deviceLinkingEd25519ExportRoot.ts` and
  `deviceLinkingTargetEd25519ExportRoot.ts`.

Iframe/public integration:

- **CHANGE** `packages/wallet/src/SeamsWeb/walletIframe/host/handlers/deviceLink.ts`.
- **CHANGE** `packages/wallet/src/SeamsWeb/walletIframe/host/runtime-device-link.ts`.
- **CHANGE** iframe shared messages and exact session state only where their
  linked projection types are consumed.
- **CHANGE** `packages/wallet/src/SeamsWeb/publicApi/devices.ts` and
  `packages/wallet/src/core/types/linkDevice.ts`.
- **CHANGE** `packages/wallet/src/SeamsWeb/SeamsWeb.ts` and public barrels after
  old runtime/store imports disappear.
- **PRESERVE** linked-device UI and existing public route family.

## 6. Ordinary signing and export

- **CHANGE** `packages/wallet/src/SeamsWeb/signingSurface/BrowserSigningSurface.ts`.
- **CHANGE** `packages/wallet/src/SeamsWeb/assembly/browserSigningSurfaceAssembly.ts`.
- **CHANGE** `packages/wallet/src/core/signingEngine/flows/recovery/exportLaneSelection.ts`
  by moving exact ordinary resolution into the ordinary export flow and then
  removing the recovery-named linked selector.
- **INSPECT/CHANGE** ordinary Ed25519 and ECDSA export modules under
  `packages/wallet/src/core/signingEngine/flows/recovery/`.
- **DELETE** `packages/wallet/src/core/signingEngine/flows/signNear/shared/linkedDeviceEd25519NormalSigning.ts`.
- **DELETE** `packages/wallet/src/core/signingEngine/flows/signEvmFamily/shared/linkedDeviceEcdsaNormalSigning.ts`.
- **DELETE** `packages/wallet/src/core/signingEngine/flows/signEvmFamily/signers/linkedDeviceEcdsaSigningMaterialSource.ts`.
- **DELETE** linked execution bundle, linked Wallet Session credential, and
  linked hydration files under
  `packages/wallet/src/core/signingEngine/session/lanes/`.
- **CHANGE** available-lane and owner-scope modules only to remove linked
  candidate selection; ordinary generic lane behavior remains.
- **INSPECT** `packages/wallet/src/core/rpcClients/relayer/routerAbNormalSigning.ts`
  and ordinary server signing handlers for linked authorization branches.

R114 overlap requiring import-trace review:

- `packages/wallet-server/src/router/domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery.ts`
- `routerAbEd25519YaoRecoveryRequestScopedCloudflare.ts`
- `routerAbEd25519YaoRecoveryWalletSessionAuthorization.ts`

Remove direct linked-session warm-bootstrap/export branches. Preserve ordinary
R114 recovery, recovery-code, custody-finalization, and local continuity paths.

## 7. Registration cutover

- **CHANGE** server registration routes and D1 auth-method service listed in
  section 2.
- **CHANGE** `packages/wallet/src/core/signingEngine/flows/registration/accountLifecycle.ts`.
- **CHANGE** registration record construction in
  `packages/wallet/src/SeamsWeb/operations/auth/login.ts`.
- **INSPECT/CHANGE**
  `packages/wallet/src/SeamsWeb/operations/authMethods/passkey/localPasskeyProjection.ts`
  — delete linked-owner finalization while preserving R114 recovery continuity.
- **INSPECT** passkey and Email OTP factor-addition modules; R109A attaches a
  new method to an existing authority and must not create a linked authority.

## 8. Tests and fixtures

Read `tests/AGENTS.md` before editing any test. Classify each failure before
changing code or fixtures.

### Add/update: foundation

- **ADD** `tests/typecheck/wallet-authority.typecheck.ts`.
- **UPDATE** `packages/shared-ts/src/utils/domainIds.typecheck.ts`.
- **UPDATE** `packages/shared-ts/src/authorization/capabilityKinds.typecheck.ts`.
- **UPDATE** `packages/shared-ts/src/device-linking/contracts.typecheck.ts`.
- **UPDATE** `packages/shared-ts/src/utils/registrationIntent.typecheck.ts`.
- **UPDATE** `tests/typecheck/delegated-authority.typecheck.ts`.

### Add/update: server lifecycle

- `tests/unit/d1LinkedDeviceRouteService.unit.test.ts`
- `d1LinkedDeviceAuthorization.unit.test.ts`
- `d1LinkedDeviceManagementComposition.unit.test.ts`
- `d1LinkedDeviceOwnerAuthorizationProvider.unit.test.ts`
- `d1LinkedDeviceSessionStore.unit.test.ts`
- `deviceLinkingRoutes.unit.test.ts`
- `deviceManagementRoutes.unit.test.ts`
- `linkedDeviceManagement.unit.test.ts`
- `linkedDeviceEmailOtpTargetFactor.unit.test.ts`
- `walletAuthMethodStore.unit.test.ts`
- `cloudflareD1RouterApiWalletAuthMethods.unit.test.ts`
- ordinary authorization and Wallet Session provenance tests.

### Add/update: browser and orchestration

- `tests/unit/indexedDBConsolidation.unit.test.ts`
- `browserExactWalletAuthAuthority.unit.test.ts`
- `walletAuthLock.unit.test.ts`
- `walletAuthenticationRestoration.unit.test.ts`
- `deviceLinkContracts.unit.test.ts`
- `deviceLinkContractRoundTrip.unit.test.ts`
- `deviceLinkingComposition.unit.test.ts`
- `deviceLinkingHttpTransport.unit.test.ts`
- `linkDevice.flowEvents.unit.test.ts`
- `walletIframeDeviceLinkTargetFactor.unit.test.ts`
- `googleEmailOtpLinkedDeviceRouting.unit.test.ts`
- `deviceLinkingKeyWorker.unit.test.ts`
- `linkedDevicesModal.unit.test.ts`

### Add/update: ordinary operations and registration

- `tests/unit/walletExecutionAdmission.unit.test.ts`
- `signingLaneRecords.unit.test.ts`
- `availableSigningLanes.ownerScope.unit.test.ts`
- `walletHostOwnerAuthority.unit.test.ts`
- ordinary Ed25519/ECDSA export and step-up tests.
- registration persistence, commit, setup/respond/activate/finalize, signer-set,
  and custody-outcome tests.
- intended-behavior Passkey and Email OTP registration/unlock/sign/export
  contracts.

### Delete or rebuild as obsolete

- owner binding/planning tests:
  `d1LinkedDeviceOwnerAuthBindingStore`,
  `d1LinkedDeviceCanonicalOwnerMetadata`,
  `d1LinkedDeviceManagementStore`,
  `d1LinkedDeviceOwnerPlanningDeployment`,
  `d1LinkedDeviceOwnerPlanningSnapshotStore`,
  `d1LinkedDeviceOwnerPlanningSnapshotWriter`,
  `d1LinkedDeviceLaneGatewayRouteService`,
  `d1LinkedDeviceSourceHandoff`, and `d1LinkedDeviceTargetPlanner` unit tests.
- linked execution/session tests:
  `linkedDeviceExecutionBundle`, `linkedDeviceExecutionEvidenceStore`,
  `linkedDeviceWalletSessionStore`, `linkedDeviceWalletSessionClaims`,
  `linkedDeviceEd25519NormalSigning`, `linkedDeviceEcdsaNormalSigning`,
  `linkedDeviceNormalSigningRoutes`, and `linkedDeviceEcdsaScope` unit tests.
- linked-only helpers:
  `tests/unit/helpers/linkedOwnerAuthBinding.fixtures.ts`,
  `linkedDeviceWalletExecution.fixtures.ts`, and linked-only branches in
  `deviceLinkContracts.fixtures.ts`, `deviceLinkingServer.fixtures.ts`, and
  `walletSessionReadProjection.fixtures.ts`.

Target-deployment descriptor and gateway-completion tests are **INSPECT** until
ordinary worker reservation reuse is known. Preserve generic R102 wire vectors,
material-ref fixtures, sealed-session fixtures, recovery tests, and normal
signing vectors.

### Authoritative operating path

- **UPDATE** `tests/e2e/linked-device.operating-path.test.ts`.
- **PRESERVE/UPDATE** `tests/playwright.linked-device.config.ts`.
- Cover Passkey-to-Passkey and Email-OTP-to-Email-OTP across Ed25519-only,
  ECDSA-only, and both-family wallets.
- Cover signing, export with fresh step-up, inventory after LinkSession
  deletion, lock/reload/unlock, exact revocation, re-link identity, and all
  seven interruption points.
- Use real composed routes, stores, workers, activation, sessions, and ordinary
  operations. Stub external RPC/faucet/delivery only at network boundaries.

### Source guards to review after behavior is working

Inspect/update or retire only with replacement coverage:

- `check-auth-method-domain-boundaries.mjs`
- `check-indexeddb-consolidation-boundaries.mjs`
- `check-key-export-boundaries.mjs`
- `check-signing-engine-architecture-boundaries.mjs`
- `check-signing-engine-ecdsa-identity-boundaries.mjs`
- `check-wallet-capability-bindings-source-guard.mjs`
- `check-wallet-scoped-lookup-boundaries.mjs`
- `check-wallet-session-vocabulary-boundaries.mjs`
- `check-route-lifecycle-domain-boundaries.mjs`
- `check-router-ab-server-wallet-session-claim-boundaries.mjs`
- registration capability and rollback guards.
- Email OTP escrow, Ed25519 signing, public surface, and iframe boundary guards.

## 9. Verification commands

Foundation and package checks:

```bash
pnpm -C packages/shared-ts type-check
pnpm -C packages/wallet-server type-check
pnpm -C packages/wallet type-check
pnpm -C tests type-check:unit
```

Single focused unit file:

```bash
pnpm -C tests exec playwright test \
  -c playwright.unit.config.ts unit/<file>.unit.test.ts --reporter=line
```

Real linked-device path, against already-running services:

```bash
SEAMS_LINKED_DEVICE_E2E=1 pnpm -C tests exec playwright test \
  e2e/linked-device.operating-path.test.ts \
  -c playwright.linked-device.config.ts --reporter=line
```

Final checks:

```bash
pnpm test:intended
pnpm test:source-guards
pnpm check
git diff --check
```

The linked-device and intended suites are environment-gated. They require the
documented local services; Email OTP also requires configured Google-token
prerequisites.

## 10. Ownership and dependency order

1. **Foundation owner** — shared contract and type fixtures only.
2. **Server owner** — D1 authority/auth-method schema, pending commit,
   activation, ordinary session, inventory, revocation, registration cutover.
3. **Browser owner** — IndexedDB installation/finalization, exact reload/unlock,
   lock generation.
4. **Orchestration owner** — factor convergence and linear link composition.
5. **Ordinary-operations owner** — `BrowserSigningSurface`, signing/export
   resolver, assembly, and real operating path.
6. **Deletion owner** — each workstream deletes the path it replaced; shared
   obsolete symbols are deleted after every consumer has migrated.

Choke points with one owner at a time:

- `registrationIntent.ts`
- `capabilityKinds.ts`
- `d1WalletAuthMethodService.ts`
- `d1AuthorizationStore.ts`
- `repositories.ts`
- `walletSessionAuthorizationStore.ts`
- `deviceLinkingPorts.ts`
- `BrowserSigningSurface.ts`
- `browserSigningSurfaceAssembly.ts`
- shared device-linking test fixtures.

Implementation checkpoints:

1. Record baseline counts and land foundation types/parsers/fixtures.
2. Freeze the shared contract.
3. Implement successful server commit and activation.
4. Implement one browser installation/finalization transaction.
5. Compose Passkey and Email OTP through the same linear operation.
6. Switch ordinary readers and registration.
7. Add only the specified interruption behavior.
8. Delete the old model, obsolete fixtures, and temporary boundary migration.
9. Run the real operating path and final checks.

R103E has no direct Rust/wasm production change in the current inventory.
Rust/wire/vector files remain inspect-only unless an actual shared wire change
is demonstrated during implementation.
