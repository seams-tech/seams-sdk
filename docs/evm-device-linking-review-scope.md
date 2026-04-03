# EVM Device Linking / Recovery Review Scope

This file inventories the code touched for the EVM device-linking and multichain recovery work so the review pass can stay focused after commit.

## Review order

Review in this order:

1. docs and shared payload helpers
2. server canonical stores and orchestration
3. client link-device / recovery / deployment flows
4. background execution and observability
5. relayer/example wiring
6. tests

## In scope

### Docs

- [evm-device-linking.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/evm-device-linking.md)
- [smart-accounts-evm.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/smart-accounts-evm.md)
- [evm-smart-accounts.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/evm-smart-accounts.md)

### Shared recovery payload helpers

- [recoveryEmail.ts](/Users/pta/Dev/rust/simple-threshold-signer/shared/src/utils/recoveryEmail.ts)
- [index.ts](/Users/pta/Dev/rust/simple-threshold-signer/shared/src/utils/index.ts)

### Server: canonical stores and records

- [AuthService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/AuthService.ts)
- [DeviceLinkingSessionStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/DeviceLinkingSessionStore.ts)
- [AccountSignerStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/AccountSignerStore.ts)
- [RecoveryExecutionStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/RecoveryExecutionStore.ts)
- [RecoverySessionStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/RecoverySessionStore.ts)
- [SmartAccountRecoverySubjectStore.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/SmartAccountRecoverySubjectStore.ts)
- [recoveryExecutionRecords.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/recoveryExecutionRecords.ts)
- [recoverySessionRecords.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/recoverySessionRecords.ts)
- [smartAccountRegistrationRecords.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/smartAccountRegistrationRecords.ts)
- [smartAccountLinkDeviceRecords.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/smartAccountLinkDeviceRecords.ts)
- [smartAccountDeploymentManifest.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/smartAccountDeploymentManifest.ts)

### Server: recovery authority and sponsorship

- [recoveryAuthority.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/recoveryAuthority.ts)
- [recoveryAuthorityAuthorization.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/recoveryAuthorityAuthorization.ts)
- [recoveryAuthoritySponsorship.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/recoveryAuthoritySponsorship.ts)

### Server: email recovery pipeline

- [emailParsers.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/email-recovery/emailParsers.ts)
- [index.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/email-recovery/index.ts)
- [rpcCalls.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/email-recovery/rpcCalls.ts)
- [types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/email-recovery/types.ts)

### Server: router and execution wiring

- [index.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/index.ts)
- [postgres.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/storage/postgres.ts)
- [routeDefinitions.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/routeDefinitions.ts)
- [relay.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relay.ts)
- [relayRegistrationBootstrap.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/relayRegistrationBootstrap.ts)
- [recoveryExecutionTracking.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/recoveryExecutionTracking.ts)
- [recoveryAuthorityDispatch.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/recoveryAuthorityDispatch.ts)
- [recoveryAuthorityInterval.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/recoveryAuthorityInterval.ts)
- [recoveryAuthorityMonitoring.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/recoveryAuthorityMonitoring.ts)
- [recoveryAuthoritySponsorship.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/recoveryAuthoritySponsorship.ts)
- [smartAccountDeploymentManifest.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/smartAccountDeploymentManifest.ts)
- [smartAccountDeploymentRequest.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/smartAccountDeploymentRequest.ts)
- [smartAccountRecoverySubjectDeploymentSync.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/smartAccountRecoverySubjectDeploymentSync.ts)
- [createRelayRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/createRelayRouter.ts)
- [emailRecovery.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/emailRecovery.ts)
- [linkDevice.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/linkDevice.ts)
- [recoverEmail.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/recoverEmail.ts)
- [smartAccountDeployment.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/express/routes/smartAccountDeployment.ts)
- [createCloudflareRouter.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/createCloudflareRouter.ts)
- [cron.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/cron.ts)
- [email.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/email.ts)
- [emailRecovery.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/emailRecovery.ts)
- [linkDevice.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/linkDevice.ts)
- [recoverEmail.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/recoverEmail.ts)
- [smartAccountDeployment.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/router/cloudflare/routes/smartAccountDeployment.ts)

### Server: observability

- [adapters.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/adapters.ts)
- [index.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/index.ts)
- [policy.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/policy.ts)
- [types.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/console/observability/types.ts)

### Client: link-device and recovery flows

- [emailRecovery.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/near/emailRecovery.ts)
- [linkDevice.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/near/linkDevice.ts)
- [linkDeviceOwnerManagement.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/near/linkDeviceOwnerManagement.ts)
- [linkDevicePreparedEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/near/linkDevicePreparedEcdsa.ts)
- [linkDeviceThresholdEcdsa.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/near/linkDeviceThresholdEcdsa.ts)
- [thresholdEcdsaProvisioning.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/thresholdEcdsaProvisioning.ts)
- [registration.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/registration.ts)
- [scanDevice.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/TatchiPasskey/scanDevice.ts)
- [emailRecovery.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/types/emailRecovery.ts)

### Client: local persistence and deployment reconciliation

- [manager.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/passkeyClientDB/manager.ts)
- [unifiedIndexedDBManager.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/indexedDB/unifiedIndexedDBManager.ts)
- [evmSigning.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/api/evmSigning.ts)
- [ensureSmartAccountDeployed.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/ensureSmartAccountDeployed.ts)
- [reportSmartAccountDeploymentObservation.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/reportSmartAccountDeploymentObservation.ts)
- [smartAccountDeployment.ts](/Users/pta/Dev/rust/simple-threshold-signer/client/src/core/signingEngine/orchestration/smartAccountDeployment.ts)

### Example/runtime wiring

- [index.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-server/src/index.ts)
- [cronConfig.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-cloudflare-worker/src/cronConfig.ts)
- [cronFlags.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-cloudflare-worker/src/cronFlags.ts)
- [scheduledHandler.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-cloudflare-worker/src/scheduledHandler.ts)
- [worker.ts](/Users/pta/Dev/rust/simple-threshold-signer/examples/relay-cloudflare-worker/src/worker.ts)

### Tests: relayer

- [email-recovery.prepare.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/email-recovery.prepare.test.ts)
- [link-device.prepare.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/link-device.prepare.test.ts)
- [recover-email.execution-tracking.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/recover-email.execution-tracking.test.ts)
- [cloudflare-cron.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/cloudflare-cron.test.ts)
- [cloudflare-router.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/cloudflare-router.test.ts)
- [cloudflare-worker-scheduled.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/cloudflare-worker-scheduled.test.ts)
- [express-router.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/express-router.test.ts)
- [helpers.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/helpers.ts)
- [relay-api-keys.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/relayer/relay-api-keys.test.ts)

### Tests: unit

- [deviceRecoveryDomain.emailRecovery.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/deviceRecoveryDomain.emailRecovery.unit.test.ts)
- [emailRecoveryService.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/emailRecoveryService.test.ts)
- [emailSubjectParsing.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/emailSubjectParsing.test.ts)
- [recoverEmailRequestParse.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoverEmailRequestParse.test.ts)
- [linkDevice.device1PreparedEcdsa.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/linkDevice.device1PreparedEcdsa.unit.test.ts)
- [linkDevice.thresholdEcdsaPersistence.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/linkDevice.thresholdEcdsaPersistence.unit.test.ts)
- [recoveryAuthority.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryAuthority.unit.test.ts)
- [recoveryAuthorityAuthorization.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryAuthorityAuthorization.unit.test.ts)
- [recoveryAuthorityInterval.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryAuthorityInterval.unit.test.ts)
- [recoveryAuthorityMonitoring.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryAuthorityMonitoring.unit.test.ts)
- [recoveryExecutionStore.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryExecutionStore.unit.test.ts)
- [recoveryExecutionTracking.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoveryExecutionTracking.unit.test.ts)
- [recoverySessionStore.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/recoverySessionStore.unit.test.ts)
- [signerMutationSagas.pendingBehavior.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/signerMutationSagas.pendingBehavior.unit.test.ts)
- [smartAccount.deploymentGate.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccount.deploymentGate.unit.test.ts)
- [smartAccountDeploymentManifest.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccountDeploymentManifest.unit.test.ts)
- [smartAccountDeploymentRequest.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccountDeploymentRequest.unit.test.ts)
- [smartAccountLinkDeviceRecords.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccountLinkDeviceRecords.unit.test.ts)
- [smartAccountRegistrationRecords.unit.test.ts](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/smartAccountRegistrationRecords.unit.test.ts)

## Currently dirty but out of scope for this review

These files are modified or untracked in the worktree, but they are not part of the EVM device-linking / multichain recovery review scope.

### Docs

- [auth-gating-routes.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/auth-gating-routes.md)
- [formal-verification.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/formal-verification.md)
- [hss-export-key.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/hss-export-key.md)
- [load-testing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/load-testing.md)

### Example site

- [Navbar.css](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/components/Navbar/Navbar.css)
- [NavbarStatic.tsx](/Users/pta/Dev/rust/simple-threshold-signer/examples/tatchi-site/src/components/Navbar/NavbarStatic.tsx)
