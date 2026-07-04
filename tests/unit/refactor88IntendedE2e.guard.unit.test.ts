import { expect, test } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const intendedRoot = 'tests/e2e/intended-behaviours';
const intendedHarnessPath = path.join(repoRoot, intendedRoot, 'harness.ts');
const mutationSelfCheckManifestPath = path.join(
  repoRoot,
  intendedRoot,
  'mutation-self-check.manifest.json',
);
const intendedConfigPath = path.join(repoRoot, 'tests/playwright.intended.config.ts');
const intendedCiConfigPath = path.join(repoRoot, 'tests/playwright.intended.ci.config.ts');
const genericPlaywrightConfigPath = path.join(repoRoot, 'tests/playwright.config.ts');
const intendedCiStartupPath = path.join(repoRoot, 'tests/scripts/start-intended-services.mjs');
const seamsSiteConfigPath = path.join(repoRoot, 'apps/seams-site/src/config.ts');
const seamsSiteAppPath = path.join(repoRoot, 'apps/seams-site/src/app/App.tsx');
const intendedMutationSelfCheckScriptPath = path.join(
  repoRoot,
  'tests/scripts/check-intended-mutation-self-check.mjs',
);
const intendedGoogleOidcEnvModulePath = path.join(
  repoRoot,
  'tests/scripts/intended-google-oidc-env.mjs',
);
const intendedGoogleOidcSetupScriptPath = path.join(
  repoRoot,
  'tests/scripts/setup-intended-google-oidc.mjs',
);
const intendedGoogleTokenRefreshScriptPath = path.join(
  repoRoot,
  'tests/scripts/refresh-intended-google-token.mjs',
);
const intendedGoogleTokenEnsureScriptPath = path.join(
  repoRoot,
  'tests/scripts/ensure-intended-google-token.mjs',
);
const intendedLocalConsoleSeedScriptPath = path.join(
  repoRoot,
  'tests/scripts/seed-intended-local-console.mjs',
);
const warmSessionTestServicesFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/warmSessionTestServices.fixtures.ts',
);
const signingSessionRecordFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/signingSessionRecord.fixtures.ts',
);
const warmSessionUiConfirmFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/warmSessionUiConfirm.fixtures.ts',
);
const ecdsaChainTargetFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/ecdsaChainTarget.fixtures.ts',
);
const ecdsaBootstrapFixturePath = path.join(
  repoRoot,
  'tests/unit/helpers/ecdsaBootstrap.fixtures.ts',
);
const rootPackageJsonPath = path.join(repoRoot, 'package.json');
const testsPackageJsonPath = path.join(repoRoot, 'tests/package.json');
const testsReadmePath = path.join(repoRoot, 'tests/README.md');
const walletServiceHeadersTestPath = path.join(
  repoRoot,
  'tests/e2e/wallet-service-headers.test.ts',
);
const refactor88PlanPath = path.join(repoRoot, 'docs/refactor-88-intended-behaviour-e2e.md');
const refactor53PlanPath = path.join(repoRoot, 'docs/refactor-53-cleanup-tests.md');
const evmFamilyEcdsaIdentityTestPath = path.join(
  repoRoot,
  'tests/unit/evmFamilyEcdsaIdentity.unit.test.ts',
);
const registrationFlowBenchmarkReportPath = path.join(
  repoRoot,
  'docs/benchmarks/registration-flow.md',
);
const refactor89PlanPath = path.join(repoRoot, 'docs/refactor-89-clean-source-guards.md');
const siblingLifecycleGateDocs = [
  {
    relativePath: 'docs/refactor-82B.md',
    requiredTokens: [
      'Deferred Refactor 88 intended lifecycle gate:',
      'pnpm test:intended',
      'Run the Refactor 88 pre-merge lifecycle gate',
    ],
  },
  {
    relativePath: 'docs/refactor-83-registration.md',
    requiredTokens: [
      'Refactor 88 now provides both local and CI-managed intended lifecycle',
      'pnpm test:intended',
      'pre-merge lifecycle gate',
    ],
  },
  {
    relativePath: 'docs/refactor-90-modular-auth-capabilities-plan.md',
    requiredTokens: [
      'Refactor 88 lifecycle contract gate:',
      'pnpm test:intended',
      'auth, session exchange, signing, export, wallet iframe',
    ],
  },
] as const;

const expectedContractFiles = [
  'email-otp.registration.contract.test.ts',
  'email-otp.unlock.contract.test.ts',
  'passkey.registration.contract.test.ts',
  'passkey.unlock.contract.test.ts',
] as const;

const expectedContractActionSequences = {
  'email-otp.registration.contract.test.ts': [
    'registerEmailOtpWallet()',
    "signNearTransaction('post_registration')",
    "signTempoTransaction('post_registration')",
    "signArcEvmTransaction('post_registration')",
    'exhaustSigningBudget()',
    "signNearTransaction('after_step_up')",
    "signTempoTransaction('after_step_up')",
    'exportEd25519Key()',
    'exportEcdsaKey()',
  ],
  'email-otp.unlock.contract.test.ts': [
    'registerEmailOtpWallet()',
    'unlockEmailOtpWallet()',
    "signNearTransaction('post_unlock')",
    "signTempoTransaction('post_unlock')",
    "signArcEvmTransaction('post_unlock')",
    'exhaustSigningBudget()',
    "signNearTransaction('after_step_up')",
    "signTempoTransaction('after_step_up')",
    'exportEd25519Key()',
    'exportEcdsaKey()',
  ],
  'passkey.registration.contract.test.ts': [
    'registerPasskeyWallet()',
    "signNearTransaction('post_registration')",
    "signTempoTransaction('post_registration')",
    "signArcEvmTransaction('post_registration')",
    'exhaustSigningBudget()',
    "signNearTransaction('after_step_up')",
    "signTempoTransaction('after_step_up')",
    'exportEd25519Key()',
    'exportEcdsaKey()',
  ],
  'passkey.unlock.contract.test.ts': [
    'registerPasskeyWallet()',
    'unlockPasskeyWallet()',
    "signNearTransaction('post_unlock')",
    "signTempoTransaction('post_unlock')",
    "signArcEvmTransaction('post_unlock')",
    'exhaustSigningBudget()',
    "signNearTransaction('after_step_up')",
    "signTempoTransaction('after_step_up')",
    'exportEd25519Key()',
    'exportEcdsaKey()',
  ],
} as const satisfies Record<(typeof expectedContractFiles)[number], readonly string[]>;

const expectedMutationSelfCheckIds = [
  'cross_chain_ecdsa_material_reuse',
  'email_otp_reroll_bootstrap_token_request_mismatch',
  'export_provider_user_mismatch_after_app_session_refresh',
  'first_post_step_up_transaction_failure',
] as const;

const expectedMutationProofStatuses = {
  cross_chain_ecdsa_material_reuse: 'blocked_product_identity',
  email_otp_reroll_bootstrap_token_request_mismatch: 'detected',
  export_provider_user_mismatch_after_app_session_refresh: 'detected',
  first_post_step_up_transaction_failure: 'detected',
} as const satisfies Record<(typeof expectedMutationSelfCheckIds)[number], string>;

const expectedMutationUnblockRequirements = {
  cross_chain_ecdsa_material_reuse:
    'Provision target-specific Tempo and Arc/EVM ECDSA owner/public-key facts so wrong-material reuse produces a recovered-signer mismatch, then run the passkey intended contracts and update this row to detected.',
} as const satisfies Partial<Record<(typeof expectedMutationSelfCheckIds)[number], string>>;

const expectedMutationDetectedProofEvidence = {
  email_otp_reroll_bootstrap_token_request_mismatch: {
    observedAt: '2026-07-04',
    observedFailureCommand:
      'pnpm -C tests run ensure:intended-google-token && SEAMS_INTENDED_SIGNING_SESSION_DEBUG=1 pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line',
    restoredValidationCommand:
      'pnpm -C tests run ensure:intended-google-token && SEAMS_INTENDED_SIGNING_SESSION_DEBUG=1 pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line',
  },
  export_provider_user_mismatch_after_app_session_refresh: {
    observedAt: '2026-07-04',
    observedFailureCommand:
      'pnpm -C tests run ensure:intended-google-token && SEAMS_INTENDED_SIGNING_SESSION_DEBUG=1 pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line',
    restoredValidationCommand:
      'pnpm -C tests run ensure:intended-google-token && SEAMS_INTENDED_SIGNING_SESSION_DEBUG=1 pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/email-otp.registration.contract.test.ts --reporter=line',
  },
  first_post_step_up_transaction_failure: {
    observedAt: '2026-07-04',
    observedFailureCommand:
      'pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/passkey.registration.contract.test.ts e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line',
    restoredValidationCommand:
      'pnpm -C tests exec playwright test -c playwright.intended.config.ts e2e/intended-behaviours/passkey.registration.contract.test.ts e2e/intended-behaviours/passkey.unlock.contract.test.ts --reporter=line',
  },
} as const satisfies Partial<
  Record<
    (typeof expectedMutationSelfCheckIds)[number],
    {
      observedAt: string;
      observedFailureCommand: string;
      restoredValidationCommand: string;
    }
  >
>;

const expectedIntendedActionResultKinds = [
  'arc_evm_sign_success',
  'ecdsa_export_success',
  'ed25519_export_success',
  'email_otp_registration_success',
  'email_otp_unlock_success',
  'near_sign_success',
  'passkey_registration_success',
  'passkey_unlock_success',
  'tempo_sign_success',
] as const;

const expectedIntendedPageActionResultTypes = [
  'PasskeyRegistrationResultSummary',
  'EmailOtpRegistrationResultSummary',
  'NearSigningResultSummary',
  'PasskeyUnlockResultSummary',
  'EmailOtpUnlockResultSummary',
  'TempoSigningResultSummary',
  'ArcEvmSigningResultSummary',
  'Ed25519ExportResultSummary',
  'EcdsaExportResultSummary',
] as const;

const expectedHarnessActionResultTypes = [
  'PasskeyRegistrationResultSnapshot',
  'EmailOtpRegistrationResultSnapshot',
  'NearSigningResultSnapshot',
  'PasskeyUnlockResultSnapshot',
  'EmailOtpUnlockResultSnapshot',
  'TempoSigningResultSnapshot',
  'ArcEvmSigningResultSnapshot',
  'Ed25519ExportResultSnapshot',
  'EcdsaExportResultSnapshot',
] as const;

const expectedIntendedHarnessSetupTokens = [
  'export const intendedTest = base.extend',
  'installFailureCollectors',
  "this.page.on('console'",
  "this.page.on('requestfailed'",
  "this.page.on('response'",
  'installExternalNetworkStubs',
  "this.context.route('**/*'",
  'installWebAuthnVirtualAuthenticator',
  "client.send('WebAuthn.addVirtualAuthenticator'",
  'hasPrf: true',
  'resetBrowserStorage',
  'assertServicesReady',
  '`${this.config.routerUrl}/healthz`',
  '`${this.config.routerUrl}/readyz`',
  'runIntendedPageAction',
  'autoConfirmWalletIframeUntil',
  'fulfillExternalStub',
] as const;

const retiredMockedRuntimeFiles = [
  'benchmarks/registration-flow/playwright.config.ts',
  'benchmarks/registration-flow/src/report.mjs',
  'benchmarks/registration-flow/src/runner.mjs',
  'benchmarks/registration-flow/src/scenario-harness.ts',
  'benchmarks/registration-flow/src/scenarios.mjs',
  'tests/e2e/docs.thresholdRegisterAndSigning.integration.test.ts',
  'tests/e2e/docs.thresholdSigningActions.smoke.test.ts',
  'tests/setup/fixtures.ts',
  'tests/setup/flows.ts',
  'tests/setup/test-utils.ts',
  'tests/setup/webauthn-mocks.ts',
  'tests/unit/helpers/warmSessionStore.fixtures.ts',
  'tests/unit/passkeyLoginMenu.thresholdProvision.unit.test.ts',
  'tests/unit/seamsWeb.loginThresholdWarm.unit.test.ts',
] as const;

const retiredFakeRelayServerFiles = [
  'tests/scripts/provision-router-api-server.mjs',
  'tests/scripts/start-servers.mjs',
  'tests/scripts/test-router-api-server.mjs',
] as const;

const demoSurfaceFiles = [
  'apps/seams-site/src/flows/demo/DemoPage.tsx',
  'apps/seams-site/src/flows/demo/PasskeyLoginMenu.tsx',
] as const;

const setupSurfaceFiles = [
  'tests/setup/index.ts',
  'tests/setup/logging.ts',
] as const;

const activeSourceRootsForRetiredSetupImports = ['apps', 'packages', 'tests'] as const;

const allowedE2eLegacySetupBootstrapFiles = ['tests/e2e/cancel_overlay_specs.test.ts'] as const;
const allowedE2eLegacySetupBootstrapFileSet = new Set<string>(allowedE2eLegacySetupBootstrapFiles);

const fakeAuthServiceAllowedFiles = [
  'tests/unit/router.routerApiRouteSurface.unit.test.ts',
  'tests/unit/router.sponsoredEvmCallCloudflare.unit.test.ts',
] as const;

const fakeAuthServiceQuarantineTokens = [
  'makeFakeAuthService',
  'test-router-api-server.mjs',
] as const;

const fakeRelayServerScriptTokens = [
  'USE_RELAY_SERVER',
  'start-servers.mjs',
  'test-router-api-server.mjs',
  'provision-router-api-server.mjs',
] as const;

const retiredBrowserTestUtils = [
  'failureMocks',
  'rollbackVerification',
  'verifyAccountExists',
  'webAuthnUtils',
  'loginStatus',
  'testUtils',
  'createConsoleCapture',
] as const;

const retiredRegistrationFlowBenchmarkTokens = [
  'benchmark:registration-flow',
  'benchmarks/registration-flow/playwright.config.ts',
  'benchmarks/registration-flow/src/runner.mjs',
] as const;

const registrationFlowBenchmarkArchiveTokens = [
  'Status: archived historical report from the retired registration-flow benchmark.',
  'Commands embedded below are provenance only.',
  'Refactor 88 intended-behaviour topology',
] as const;

const retainedBoundaryAuditRows = [
  'tests/e2e/cancel_overlay_specs.test.ts',
  'tests/lit-components/coep.strict.all-elements.test.ts',
  'tests/lit-components/confirm-ui.handle.test.ts',
  'tests/lit-components/confirm-ui.host-and-inline.test.ts',
  'tests/lit-components/drawer.events.test.ts',
  'tests/lit-components/passkey-registration-btn.test.ts',
  'tests/unit/confirmTxFlow.common.helpers.test.ts',
  'tests/unit/confirmTxFlow.confirmSession.onMounted.unit.test.ts',
  'tests/unit/confirmTxFlow.defensivePaths.test.ts',
  'tests/unit/confirmTxFlow.determineConfirmationConfig.test.ts',
  'tests/unit/confirmTxFlow.nearAdapter.concurrency.test.ts',
  'tests/unit/confirmTxFlow.successPaths.test.ts',
  'tests/unit/accountKeyMaterial.generic.unit.test.ts',
  'tests/unit/awaitSecureConfirmationV2.test.ts',
  'tests/unit/chainFamily.naming.unit.test.ts',
  'tests/unit/confirmationReadinessRegistry.unit.test.ts',
  'tests/unit/credentialsHelpers.redaction.test.ts',
  'tests/unit/demoThresholdHooks.actions.unit.test.ts',
  'tests/unit/emailOtpDeviceEnrollmentEscrowStore.unit.test.ts',
  'tests/unit/emailOtpRecoveryCodeBackups.unit.test.ts',
  'tests/unit/evmClient.waitForReceipt.unit.test.ts',
  'tests/unit/evmNonceBackend.unit.test.ts',
  'tests/unit/evmNonceLifecycleMetrics.unit.test.ts',
  'tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts',
  'tests/unit/handleSecureConfirmRequest.test.ts',
  'tests/unit/indexedDBConsolidation.unit.test.ts',
  'tests/unit/localSignerReconciliation.unit.test.ts',
  'tests/unit/nearClient.sendTransaction.retryInvalidNonce.unit.test.ts',
  'tests/unit/nearThresholdKeyMaterial.persistence.unit.test.ts',
  'tests/unit/overlayController.test.ts',
  'tests/unit/passkeyAuthMenu.accountAvailability.unit.test.ts',
  'tests/unit/passkeyAuthMenu.fouc.unit.test.ts',
  'tests/unit/passkeyClientDB.deviceSelection.test.ts',
  'tests/unit/passkeyClientDB.repositories.unit.test.ts',
  'tests/unit/passkeyConfirm.exportFlow.unit.test.ts',
  'tests/unit/profileAccountProjection.generic.unit.test.ts',
  'tests/unit/progressBus.overlayIntentResolver.test.ts',
  'tests/unit/recoveryCodesModal.behavior.unit.test.ts',
  'tests/unit/routerAbEd25519.walletSessionState.unit.test.ts',
  'tests/unit/safari-fallbacks.test.ts',
  'tests/unit/sealedRefresh.parity.unit.test.ts',
  'tests/unit/sealedSessionStore.unit.test.ts',
  'tests/unit/seamsWeb.chainSigners.integration.test.ts',
  'tests/unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts',
  'tests/unit/seamsWeb.emailOtpIframe.unit.test.ts',
  'tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts',
  'tests/unit/seamsWeb.initWalletIframe.concurrent.unit.test.ts',
  'tests/unit/seamsWeb.namespacedSigningSurface.unit.test.ts',
  'tests/unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts',
  'tests/unit/seamsWeb.setTheme.unit.test.ts',
  'tests/unit/secureConfirm.warmSigning.test.ts',
  'tests/unit/signerMutationSagas.pendingBehavior.unit.test.ts',
  'tests/unit/tempo.feeTokenHelper.unit.test.ts',
  'tests/unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts',
  'tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts',
  'tests/unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts',
  'tests/unit/touchConfirm.workerRouter.integration.test.ts',
  'tests/unit/useAccountInput.clearPrefill.unit.test.ts',
  'tests/unit/userPreferences.indexeddb-disabled.test.ts',
  'tests/unit/walletFlowEvent.signing.unit.test.ts',
  'tests/unit/walletIframe.assetsBaseUrlNormalization.unit.test.ts',
  'tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts',
  'tests/wallet-iframe/csp.strict.violation-free.test.ts',
  'tests/wallet-iframe/export.flow.integration.test.ts',
  'tests/wallet-iframe/handshake.test.ts',
  'tests/wallet-iframe/passkeyAuthMenu.qrButton.overlay.test.ts',
  'tests/wallet-iframe/preferences.sync.test.ts',
  'tests/wallet-iframe/router.behavior.concurrent.test.ts',
  'tests/wallet-iframe/router.behavior.sticky.test.ts',
  'tests/wallet-iframe/router.behavior.test.ts',
  'tests/wallet-iframe/router.cancellationProgress.test.ts',
  'tests/wallet-iframe/router.computeOverlayIntent.test.ts',
  'tests/wallet-iframe/router.registrationActivation.test.ts',
  'tests/wallet-iframe/router.signingProgressForwarding.test.ts',
] as const;
const retainedBoundaryAuditRowSet = new Set<string>(retainedBoundaryAuditRows);

const retainedBoundaryAuditEvidenceTokens = {
  'tests/e2e/cancel_overlay_specs.test.ts': [
    'Wallet iframe overlay specs on cancel',
    'Overlay shows then hides on cancel across core routes',
    'router.cancelAll()',
  ],
  'tests/lit-components/coep.strict.all-elements.test.ts': [
    'COEP strict: all Lit elements define + upgrade without COEP/CORP violations',
    'cross-origin-embedder-policy',
    'window.crossOriginIsolated',
    '/__sdk-root',
  ],
  'tests/lit-components/confirm-ui.handle.test.ts': [
    'confirm-ui mountConfirmUI handle',
    'mounts from TxDisplayModel without txSigningRequests',
    'lazily enriches ABI hints in tx-tree rendering',
    'mountConfirmUI',
  ],
  'tests/lit-components/confirm-ui.host-and-inline.test.ts': [
    'confirm-ui inline confirmer',
    'modal confirm resolves with confirmed=true',
    'drawer cancel resolves with confirmed=false',
    'modal loading state still allows cancel button click',
  ],
  'tests/lit-components/drawer.events.test.ts': [
    'Lit component – drawer events',
    'emits open/close lifecycle events',
    'w3a:drawer-open-start',
    'w3a:drawer-close-end',
  ],
  'tests/lit-components/passkey-registration-btn.test.ts': [
    'seams-passkey-registration-btn',
    'emits activation once and mirrors hover, focus, busy, and disabled state',
    'uses the same rpID source for WebAuthn registration options',
    'rejects WebAuthn registration when username does not match wallet ID',
  ],
  'tests/unit/confirmTxFlow.common.helpers.test.ts': [
    'confirmTxFlow common helpers',
    'sanitizeForPostMessage strips functions and handle references',
    'sanitizeForPostMessage strips unexpected future function fields',
    'parseTransactionSummary parses JSON and falls back on invalid strings',
  ],
  'tests/unit/confirmTxFlow.confirmSession.onMounted.unit.test.ts': [
    'touchConfirm confirm session onMounted lifecycle',
    'promptUser exposes handle early enough for updateUI before decision resolution',
    'createConfirmSession',
    'onMounted?.(fakeHandle)',
  ],
  'tests/unit/confirmTxFlow.defensivePaths.test.ts': [
    'confirmTxFlow',
    'Signing flow: cancel releases reserved nonces',
    'Registration flow: cancel does not reserve access-key nonces',
    'Signing flow: missing PRF output surfaces error',
  ],
  'tests/unit/confirmTxFlow.determineConfirmationConfig.test.ts': [
    'determineConfirmationConfig',
    'warm-session transaction signing keeps the transaction confirmer enabled',
    'warm-session signing respects explicit transaction confirmation config',
    'DECRYPT_PRIVATE_KEY_WITH_PRF',
  ],
  'tests/unit/confirmTxFlow.nearAdapter.concurrency.test.ts': [
    'touchConfirm near adapter',
    'fetchNearContext returns an isolated transactionContext per call',
    'createConfirmTxFlowAdapters',
    'reserveNonces: true',
  ],
  'tests/unit/confirmTxFlow.successPaths.test.ts': [
    'confirmTxFlow',
    'LocalOnly: decryptPrivateKeyWithPrf skips intermediate confirm UI in wallet-iframe host mode',
    'Registration: collects registration credential without access-key nonce reservation',
    'Signing: collects assertion credential, reserves nonces, emits tx context',
  ],
  'tests/unit/accountKeyMaterial.generic.unit.test.ts': [
    'generic account key material helpers',
    'persists and reads non-NEAR key material rows through account refs',
    'rejects explicit key targets that conflict with mapped account refs',
  ],
  'tests/unit/awaitSecureConfirmationV2.test.ts': [
    'awaitUserConfirmationV2 - error handling',
    'preserves nonce leases across the worker confirmation bridge',
    'preserves Email OTP code and challenge id across the worker confirmation bridge',
    'ignores response with mismatched channel token',
  ],
  'tests/unit/chainFamily.naming.unit.test.ts': [
    'chain family naming',
    'maps concrete networks to canonical families and predicates',
    'explicit chain config is the authoritative active network set',
  ],
  'tests/unit/confirmationReadinessRegistry.unit.test.ts': [
    'confirmation readiness registry',
    'consume returns readiness once and clears the entry',
    'concurrent request ids do not consume each other',
  ],
  'tests/unit/credentialsHelpers.redaction.test.ts': [
    'credentialExtensions',
    'redactCredentialExtensionOutputs redacts entire clientExtensionResults',
  ],
  'tests/unit/demoThresholdHooks.actions.unit.test.ts': [
    'demo threshold action hooks',
    'ThresholdSignerSection displays the threshold owner address',
    'useDemoTempoFeeTokenActions signs and broadcasts setUserToken flow',
    'useDemoArcSigningActions signs and finalizes arc transaction via SDK lifecycle',
  ],
  'tests/unit/emailOtpDeviceEnrollmentEscrowStore.unit.test.ts': [
    'Email OTP device enrollment escrow store',
    'persists device-local enc_s(S) records without plaintext S or signing-session fields',
    'fails closed on malformed records and deletes by wallet/auth subject/enrollment scope',
    'write uses wallet DB disabled-mode protection without opening IndexedDB',
  ],
  'tests/unit/emailOtpRecoveryCodeBackups.unit.test.ts': [
    'Email OTP recovery-code backup repository',
    'retains stored codes across display and download metadata updates',
    'rejects raw recovery-code arrays and leaves mismatched enrollment seals intact',
    'explicit deletion removes plaintext rows without leaving tombstones',
  ],
  'tests/unit/evmClient.waitForReceipt.unit.test.ts': [
    'evm client waitForTransactionReceipt',
    'detects sustained underpriced pending tx via helper client',
    'classifies replaced when hash disappears and pending nonce moves ahead',
    'uses nonce hints to detect dropped tx when tx-by-hash is unavailable',
  ],
  'tests/unit/evmNonceBackend.unit.test.ts': [
    'EvmNonceBackend',
    'fetchChainNonce reads the pending chain nonce through the configured RPC',
    'routes duplicate chain ids by requested chain family and network key',
    'managed nonce snapshots fail closed on unknown chain families',
  ],
  'tests/unit/evmNonceLifecycleMetrics.unit.test.ts': [
    'evm nonce lifecycle metrics',
    'emits broadcast_accepted metric with lane tags',
    'emits lane_blocked metric when reconcile reports blocked lane',
  ],
  'tests/unit/googleEmailOtpWalletIframeHandles.unit.test.ts': [
    'Google Email OTP wallet iframe flow handles',
    'registration begin wire result exposes only display metadata',
    'rejects a handle used with the wrong wallet id',
    'strips recovery codes from iframe registration completion result',
    'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
  ],
  'tests/unit/handleSecureConfirmRequest.test.ts': [
    'handlePromptFromWorker - Orchestrator Unit Tests',
    'Unsupported type falls back to structured error',
    'Missing payload returns validation error',
    'Signing request with PRF or wrap key fields is rejected defensively',
  ],
  'tests/unit/indexedDBConsolidation.unit.test.ts': [
    'IndexedDB consolidation',
    'schema manifest defines every canonical store exactly once',
    'wallet signer rows mirror branch identity fields and ECDSA signers do not create NEAR projections',
    'wallet auth-method rows allow shared Email OTP identifiers and reject passkey duplicates plus scalar drift',
  ],
  'tests/unit/localSignerReconciliation.unit.test.ts': [
    'local signer reconciliation',
    'reports missing threshold material, orphaned material, and stale pending signers',
  ],
  'tests/unit/nearClient.sendTransaction.retryInvalidNonce.unit.test.ts': [
    'MinimalNearClient.sendTransaction',
    'retries after transient HTTP error, then can surface InvalidNonce',
  ],
  'tests/unit/nearThresholdKeyMaterial.persistence.unit.test.ts': [
    'NEAR threshold key material persistence',
    'threshold key writes persist the canonical single-key record shape',
    'threshold key reads synthesize canonical participants for incomplete threshold payloads',
  ],
  'tests/unit/overlayController.test.ts': [
    'OverlayController',
    'showFullscreen',
    'anchored positioning and sticky prevents hide',
    'forceHide clears sticky overlay lock and makes iframe inert',
  ],
  'tests/unit/passkeyAuthMenu.accountAvailability.unit.test.ts': [
    'Passkey auth account availability',
    'local saved credentials do not mark an unregistered account as existing',
    'register badge stays neutral for a locally saved account until it exists on-chain',
  ],
  'tests/unit/passkeyAuthMenu.fouc.unit.test.ts': [
    'PasskeyAuthMenu styles bootstrap',
    'login mode shows passkey, Google SSO Email OTP, and email recovery methods',
    'account dropdown renders auth labels instead of implicit NEAR account IDs',
    'Google SSO can hand off to the Email OTP unlock prompt',
  ],
  'tests/unit/passkeyClientDB.deviceSelection.test.ts': [
    'Seams wallet device selection',
    'getLastLoggedInSignerSlot does not fall back to another account',
    'activateAccountSigner same-signer retry is idempotent',
    'Email OTP threshold Ed25519 retry repairs missing key material after activation',
  ],
  'tests/unit/passkeyClientDB.repositories.unit.test.ts': [
    'Seams wallet repositories',
    'persists durable nonce leases and coordination locks in seams_wallet',
    'persists split NEAR Ed25519 wallet identity across wallet repositories',
    'stores scoped last-profile state through the unified repository',
  ],
  'tests/unit/passkeyConfirm.exportFlow.unit.test.ts': [
    'passkey-confirm export flow worker',
    'returns cancelled when user cancels at first confirmation step',
    'fails closed when seed does not match expected public key',
    'completes canonical ecdsa-hss EVM export without PRF.second',
  ],
  'tests/unit/profileAccountProjection.generic.unit.test.ts': [
    'generic profile/account projection helpers',
    'resolves mapped candidates and selects canonical signer slots',
    'returns the last selected profile state against generic chain candidates',
  ],
  'tests/unit/progressBus.overlayIntentResolver.test.ts': [
    'defaultOverlayIntentResolver',
    'returns show/hide/none from event interaction metadata',
    'tracks v2 flow, phase, and status stats',
  ],
  'tests/unit/recoveryCodesModal.behavior.unit.test.ts': [
    'RecoveryCodesModal behavior',
    'loads retained recovery codes from local wallet storage',
    'wallet iframe recovery-code command never sends recovery keys to the host',
    'PasskeyAuthMenu prompts rotation after recovery consumes a code',
  ],
  'tests/unit/routerAbEd25519.walletSessionState.unit.test.ts': [
    'Router A/B Ed25519 Wallet Session state',
    'resolves canonical Router A/B-ready state from the warm-session record',
    'accepts Router A/B Ed25519 signing when wallet and NEAR identities differ',
    'rejects persisted Ed25519 material without material identity',
  ],
  'tests/unit/safari-fallbacks.test.ts': [
    'Safari WebAuthn fallbacks - cancellation and timeout behavior',
    'create(): native fails then bridge cancel',
    'get(): native NotAllowedError cancel should not trigger bridge',
    'get(): clones challenge buffers before native and bridge attempts',
  ],
  'tests/unit/sealedRefresh.parity.unit.test.ts': [
    'sealed refresh startup parity',
    'passes when relayer well-known capabilities match client config',
    'fails closed with field-level mismatch diagnostics',
    'skips relayer fetch in app-origin wallet iframe mode',
  ],
  'tests/unit/sealedSessionStore.unit.test.ts': [
    'signing session sealed store',
    'writes shamir3pass records to IndexedDB without persisting plaintext secret or JWT auth',
    'drops chain-only ECDSA sealed records instead of inferring a concrete target',
    'rejects passkey Ed25519 signing-session seals without worker-material metadata',
  ],
  'tests/unit/seamsWeb.chainSigners.integration.test.ts': [
    'SeamsWeb chain signer modules',
    'createTempoSignerCapability',
    'afterCall',
    'onError',
    'reportBroadcastRejected',
    'reconcileTempoNonceLane',
  ],
  'tests/unit/seamsWeb.duplicateIframes.guardrails.unit.test.ts': [
    'Wallet iframe duplicate guardrails',
    'does not accumulate multiple wallet overlay iframes across multiple instances',
    'iframe.w3a-wallet-overlay',
    'PM_GET_WALLET_SESSION',
  ],
  'tests/unit/seamsWeb.emailOtpIframe.unit.test.ts': [
    'SeamsWeb Email OTP wallet iframe ownership',
    'routes Email OTP challenge, enrollment, and ECDSA bootstrap through the wallet iframe',
    'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION',
    'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
    'findForbidden',
  ],
  'tests/unit/seamsWeb.emailOtpRecoveryCodeBackup.unit.test.ts': [
    'SeamsWeb Email OTP recovery-code backup persistence',
    'stores recovery codes without showing a blocking registration modal',
    'download helper builds the recovery-code file without deleting storage',
    'email_otp_recovery_codes_backup',
  ],
  'tests/unit/seamsWeb.initWalletIframe.concurrent.unit.test.ts': [
    'SeamsWeb.initWalletIframe',
    'does not mount multiple wallet iframes on concurrent init',
    'iframe.w3a-wallet-overlay',
    'PM_SET_CONFIG',
  ],
  'tests/unit/seamsWeb.namespacedSigningSurface.unit.test.ts': [
    'SeamsWeb namespaced signing surface',
    'SeamsWeb exposes near/tempo/evm namespaces without flat root signing methods',
    'FLAT_ROOT_SIGNING_METHODS',
  ],
  'tests/unit/seamsWeb.passkeyIframe.flowEvents.unit.test.ts': [
    'SeamsWeb passkey wallet iframe flow events',
    'PM_REGISTER_WALLET',
    'forwards passkey registration and unlock sequences through onEvent',
    'registration.auth.passkey.create.started',
    'activation surface initializes and requires the wallet-scoped iframe router',
  ],
  'tests/unit/seamsWeb.setTheme.unit.test.ts': [
    'SeamsWeb.setTheme',
    'updates theme synchronously',
    'initializes theme from config appearance.theme',
    "seams.setTheme('light')",
  ],
  'tests/unit/secureConfirm.warmSigning.test.ts': [
    'SIGN_TRANSACTION warmSession skips TouchID and returns tx context',
    'TouchID prompt should not be called for warmSession',
    'threshold-session-warm',
  ],
  'tests/unit/signerMutationSagas.pendingBehavior.unit.test.ts': [
    'signer mutation saga pending behavior',
    'confirms undeployed add-signer operations without activating the signer locally',
    'confirms deployed add-signer operations after key material validation succeeds',
    'confirms deployed revoke-signer operations and deletes local key material',
  ],
  'tests/unit/tempo.feeTokenHelper.unit.test.ts': [
    'Tempo fee token helpers',
    'encodes setUserToken(address) calldata and default fee-manager call',
  ],
  'tests/unit/thresholdEcdsaSessionAuthMaterial.unit.test.ts': [
    'threshold ECDSA warm-session auth material',
    'resolves JWT only from explicit canonical ECDSA ownership',
  ],
  'tests/unit/thresholdEd25519.registrationWarmSession.unit.test.ts': [
    'threshold Ed25519 registration warm-session',
    'rejects returned warm-session identity that differs from expected registration binding',
    'awaits warm-session hydrate before registration persistence returns',
    'Email OTP registration persists sealed Ed25519 worker material before hydrate',
  ],
  'tests/unit/thresholdEd25519WalletSession.rehydrate.unit.test.ts': [
    'threshold Ed25519 Wallet Session rehydrate',
    'keeps canonical Ed25519 session records out of sessionStorage for wallet host mode',
  ],
  'tests/unit/touchConfirm.workerRouter.integration.test.ts': [
    'UserConfirm worker router',
    'routes concurrent responses by request id with one long-lived listener',
    'reads warm-session status snapshots in a single worker round trip',
    'sealed mode restores only through explicit signing restore command',
    'exportPrivateKeysWithUi strips secret fields from worker payload',
  ],
  'tests/unit/useAccountInput.clearPrefill.unit.test.ts': [
    'useAccountInput refresh prefill behavior',
    'refreshAccountData does not repopulate input after explicit clear',
  ],
  'tests/unit/userPreferences.indexeddb-disabled.test.ts': [
    'UserPreferences when IndexedDB is disabled',
    'wallet-iframe app-origin mode disables SDK IndexedDB persistence',
    'wallet-iframe app-origin mode does not create app-origin seams_wallet',
    'setCurrentWallet does not cause unhandledrejection',
  ],
  'tests/unit/walletFlowEvent.signing.unit.test.ts': [
    'wallet flow event invariants',
    'maps every numbered phase enum member to its declared step and message',
    'derives stable step numbers and canonical messages from signing phases',
    'key export viewer steps, messages, and overlay metadata',
  ],
  'tests/unit/walletIframe.assetsBaseUrlNormalization.unit.test.ts': [
    'Wallet iframe assetsBaseUrl normalization',
    'uses /sdk/ when sdkBasePath is an empty string',
  ],
  'tests/unit/walletIframe.signerModeConfigPropagation.unit.test.ts': [
    'forwards managed registration config in PM_SET_CONFIG',
    'fails fast when sealed refresh is enabled without shamirPrimeB64u',
    'forwards appearance theme/tokens in PM_SET_CONFIG for Lit confirmer theming',
    'PM_SET_CONFIG',
  ],
  'tests/wallet-iframe/csp.strict.violation-free.test.ts': [
    'wallet-service under strict CSP has no inline style tags or style attributes',
    'style-src-attr',
  ],
  'tests/wallet-iframe/export.flow.integration.test.ts': [
    'wallet-origin export flow integration',
    'export flow completes and overlay closes on key export progress',
    'export viewer ignores stale generic WALLET_UI_CLOSED from previous wallet UI',
    'concurrent export and signing remain isolated and do not cross-talk',
    'PM_EXPORT_KEYPAIR_UI',
  ],
  'tests/wallet-iframe/handshake.test.ts': [
    'resolves when the wallet host replies with READY',
    'rejects when READY never arrives within the timeout budget',
    'Wallet iframe READY timeout',
  ],
  'tests/wallet-iframe/passkeyAuthMenu.qrButton.overlay.test.ts': [
    'PasskeyAuthMenu QR button overlay regression',
    'clicking Scan and Link Device keeps wallet iframe overlay hidden',
    'PM_START_DEVICE2_LINKING_FLOW',
  ],
  'tests/wallet-iframe/preferences.sync.test.ts': [
    'PREFERENCES_CHANGED',
    'app-origin mirrors wallet-host confirmation config via PREFERENCES_CHANGED',
    'PM_SET_CONFIRMATION_CONFIG',
    'PM_SET_THEME',
  ],
  'tests/wallet-iframe/router.behavior.concurrent.test.ts': [
    'concurrent requests aggregate overlay visibility',
    'overlay stays visible while any request demands show',
    'PM_EXECUTE_ACTION',
  ],
  'tests/wallet-iframe/router.behavior.sticky.test.ts': [
    'sticky overlay lifecycle',
    'sticky requests keep overlay visible until explicit cancel',
    'sticky demand does not pin later PM_SIGN_TEMPO overlay visibility',
    'PM_EXPORT_KEYPAIR_UI',
  ],
  'tests/wallet-iframe/router.behavior.test.ts': [
    'overlay + timeout behavior',
    'executeAction shows overlay then hides it after request timeout',
    'Wallet request timeout for PM_EXECUTE_ACTION',
    'CAPTURED_PM_UNLOCK_PAYLOAD',
  ],
  'tests/wallet-iframe/router.cancellationProgress.test.ts': [
    'WalletIframeRouter cancellation progress',
    'forwards v2 cancelled terminal events for core request flows',
    'registration.cancelled',
    'unlock.cancelled',
    'signing.cancelled',
  ],
  'tests/wallet-iframe/router.computeOverlayIntent.test.ts': [
    'preflight fullscreen intent for activation-required requests',
    'PM_EXPORT_KEYPAIR_UI',
    'PM_GET_WALLET_SESSION',
  ],
  'tests/wallet-iframe/router.registrationActivation.test.ts': [
    'WalletIframeRouter registration activation surface',
    'ignores forged, malformed, and early activation button state messages',
    'PM_REGISTRATION_ACTIVATION_BUTTON_STATE',
    'overlayReleased',
  ],
  'tests/wallet-iframe/router.signingProgressForwarding.test.ts': [
    'WalletIframeRouter signing progress forwarding',
    'forwards v2 EVM threshold signing progress to app onEvent',
    'PM_SIGN_TEMPO',
    'Ignored wrong-flow progress',
  ],
} as const satisfies Record<(typeof retainedBoundaryAuditRows)[number], readonly string[]>;

const forbiddenIntendedHarnessPatterns = [
  {
    pattern: /from\s+['"]\.\.\/setup(?:\/|['"])/,
    message: 'imports legacy tests/setup barrel',
  },
  {
    pattern: /from\s+['"].*tests\/setup(?:\/|['"])/,
    message: 'imports legacy tests/setup helpers',
  },
  {
    pattern: /\bsetupBasicPasskeyTest\b/,
    message: 'uses legacy setupBasicPasskeyTest',
  },
  {
    pattern: /\bsetupRouterApiServerTest\b/,
    message: 'uses legacy fake Router API setup',
  },
  {
    pattern: /\bsetupTestUtilities\b/,
    message: 'installs window.testUtils',
  },
  {
    pattern: /\bwindow\.testUtils\b/,
    message: 'uses testUtils instead of public SDK/UI flow',
  },
  {
    pattern: /\b__testOverrides\b/,
    message: 'uses SDK internal test overrides',
  },
  {
    pattern: /\bsetupRouterApiMock\b/,
    message: 'mocks Router API responses',
  },
  {
    pattern: /\binstall(RouterApiProxy|WalletSdkCors)Shim\b/,
    message: 'installs legacy same-origin routing shims',
  },
  {
    pattern: /\bforceSameOrigin(SdkBase|Workers)\b/,
    message: 'uses legacy same-origin SDK or worker rewrites',
  },
  {
    pattern: /\b__W3A_WALLET_SDK_BASE__\b/,
    message: 'overrides wallet SDK asset origin',
  },
  {
    pattern: /\btest-router-api-server\.mjs\b/,
    message: 'depends on fake AuthService router server',
  },
] as const;

const forbiddenIntendedContractFlakePatterns = [
  {
    pattern: /\btest\.skip\b/,
    message: 'uses test.skip',
  },
  {
    pattern: /\btest\.fixme\b/,
    message: 'uses test.fixme',
  },
  {
    pattern: /\btest\.only\b/,
    message: 'uses test.only',
  },
  {
    pattern: /\btest\.describe\.skip\b/,
    message: 'uses test.describe.skip',
  },
  {
    pattern: /\btest\.describe\.only\b/,
    message: 'uses test.describe.only',
  },
  {
    pattern: /\btest\.describe\.configure\b/,
    message: 'overrides suite execution policy',
  },
  {
    pattern: /\.skip\s*\(/,
    message: 'uses a skip annotation',
  },
  {
    pattern: /\.only\s*\(/,
    message: 'uses a focused annotation',
  },
  {
    pattern: /\bretries\s*:/,
    message: 'overrides retry policy',
  },
] as const;

const forbiddenPrivateIntendedImportPatterns = [
  {
    pattern: /packages\/(?:sdk-web|sdk-server-ts)\//,
    message: 'imports SDK package source by filesystem path',
  },
  {
    pattern: /@\/core\/signingEngine(?:\/|$)/,
    message: 'imports private signing-engine internals',
  },
  {
    pattern: /@\/SeamsWeb(?:\/|$)/,
    message: 'imports private SeamsWeb operation internals',
  },
  {
    pattern: /@seams\/sdk\/(?:core|internal|src|dist)(?:\/|$)/,
    message: 'imports private SDK internals',
  },
  {
    pattern: /@seams-internal\//,
    message: 'imports internal SDK packages',
  },
  {
    pattern: /(?:^|\/)flows\/demo(?:\/|$)|^@\/flows\/demo(?:\/|$)/,
    message: 'imports demo app helpers',
  },
  {
    pattern: /(?:^|\/)signingEngine(?:\/|$)/,
    message: 'imports signing-engine internals',
  },
  {
    pattern: /(?:^|\/)ThresholdService(?:\/|$)/,
    message: 'imports server threshold service internals',
  },
  {
    pattern: /thresholdEd25519/i,
    message: 'imports legacy threshold Ed25519 test/runtime internals',
  },
  {
    pattern: /walletRegistrationRoutes/,
    message: 'imports Router wallet registration route internals',
  },
] as const;

test('Refactor 88 intended contracts expose exactly four lifecycle specs', () => {
  const files = listTypeScriptFiles(path.join(repoRoot, intendedRoot))
    .map((file) => path.basename(file))
    .filter((file) => file.endsWith('.contract.test.ts'))
    .sort();

  expect(files).toEqual([...expectedContractFiles].sort());
});

test('Refactor 88 intended contracts reject local flake escape hatches', () => {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, intendedRoot))) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const forbidden of forbiddenIntendedContractFlakePatterns) {
      if (!forbidden.pattern.test(source)) continue;
      violations.push(`${relativePath}: ${forbidden.message}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 lifecycle specs keep required public action sequence', () => {
  for (const [contractFile, expectedActions] of Object.entries(expectedContractActionSequences)) {
    const source = fs.readFileSync(path.join(repoRoot, intendedRoot, contractFile), 'utf8');
    assertTokensAppearInOrder(source, expectedActions, contractFile);
  }
});

test('Refactor 88 intended contract specs stay high-level harness scripts', () => {
  const violations: string[] = [];
  for (const contractFile of expectedContractFiles) {
    const source = fs.readFileSync(path.join(repoRoot, intendedRoot, contractFile), 'utf8');
    const imports = extractModuleSpecifiers(source);
    if (imports.length !== 1 || imports[0] !== './harness') {
      violations.push(`${contractFile}: imports ${imports.join(', ') || '<none>'}`);
    }
    for (const token of ['page.', 'context.', 'request.', 'expect(', '.route(', '.evaluate(']) {
      if (!source.includes(token)) continue;
      violations.push(`${contractFile}: uses ${token}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 intended contracts avoid mocked runtime setup helpers', () => {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, intendedRoot))) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const forbidden of forbiddenIntendedHarnessPatterns) {
      if (!forbidden.pattern.test(source)) continue;
      violations.push(`${relativePath}: ${forbidden.message}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 intended public flow files avoid private SDK runtime imports', () => {
  const checkedFiles = [
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    intendedHarnessPath,
  ];
  const violations: string[] = [];

  for (const filePath of checkedFiles) {
    const relativePath = path.relative(repoRoot, filePath).replaceAll(path.sep, '/');
    const source = fs.readFileSync(filePath, 'utf8');
    for (const specifier of extractModuleSpecifiers(source)) {
      for (const forbidden of forbiddenPrivateIntendedImportPatterns) {
        if (!forbidden.pattern.test(specifier)) continue;
        violations.push(`${relativePath}: ${specifier}: ${forbidden.message}`);
      }
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 intended harness owns setup primitives outside legacy setup', () => {
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  const imports = extractModuleSpecifiers(harnessSource);
  const violations: string[] = [];

  for (const token of expectedIntendedHarnessSetupTokens) {
    if (harnessSource.includes(token)) continue;
    violations.push(`missing intended setup token: ${token}`);
  }
  for (const specifier of imports) {
    if (!specifier.includes('tests/setup') && !specifier.includes('../setup')) continue;
    violations.push(`imports legacy setup helper: ${specifier}`);
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 intended action result discriminants stay aligned', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');

  expect(extractUnionMembers(pageSource, 'IntendedActionResult')).toEqual([
    ...expectedIntendedPageActionResultTypes,
  ]);
  expect(extractUnionMembers(harnessSource, 'IntendedActionResultSnapshot')).toEqual([
    ...expectedHarnessActionResultTypes,
  ]);
  expect(
    extractUniqueSwitchCases(
      extractDelimitedSource(
        harnessSource,
        'function parseIntendedActionResultSnapshot',
        'function parseEcdsaTargetKeys',
      ),
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
  expect(
    extractUniqueSwitchCases(
      extractDelimitedSource(
        pageSource,
        'function intendedActionResultWalletId',
        'function intendedActionResultNearAccountId',
      ),
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
  expect(
    extractUniqueSwitchCases(
      extractDelimitedSource(
        pageSource,
        'function intendedActionResultNearAccountId',
        'function readIntendedPageQuery',
      ),
    ),
  ).toEqual([...expectedIntendedActionResultKinds]);
});

test('Refactor 88 retired mocked runtime files stay deleted', () => {
  const presentFiles = retiredMockedRuntimeFiles.filter((relativePath) =>
    fs.existsSync(path.join(repoRoot, relativePath)),
  );

  expect(presentFiles, presentFiles.join('\n')).toEqual([]);
});

test('Refactor 88 fake relay server launcher files stay deleted', () => {
  const presentFiles = retiredFakeRelayServerFiles.filter((relativePath) =>
    fs.existsSync(path.join(repoRoot, relativePath)),
  );

  expect(presentFiles, presentFiles.join('\n')).toEqual([]);
});

test('Refactor 88 active source does not import retired setup wrapper files', () => {
  const retiredSetupTokens = [
    'tests/setup/fixtures',
    'tests/setup/flows',
    'tests/setup/test-utils',
  ];
  const violations: string[] = [];
  for (const relativePath of listSourceTextFiles(activeSourceRootsForRetiredSetupImports)) {
    if (relativePath === 'tests/unit/refactor88IntendedE2e.guard.unit.test.ts') continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of retiredSetupTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 retired browser mutation hooks stay out of active source', () => {
  const retiredBrowserMutationTokens = ['__testOverrides', 'window.testUtils'];
  const violations: string[] = [];
  for (const relativePath of listSourceTextFiles(activeSourceRootsForRetiredSetupImports)) {
    if (relativePath === 'tests/unit/refactor88IntendedE2e.guard.unit.test.ts') continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of retiredBrowserMutationTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 generic setup bootstrap stays out of lifecycle e2e tests', () => {
  const violations: string[] = [];
  const allowedMatches: string[] = [];
  for (const relativePath of allowedE2eLegacySetupBootstrapFiles) {
    if (retainedBoundaryAuditRowSet.has(relativePath)) continue;
    violations.push(`${relativePath}: setupBasicPasskeyTest allowlist must stay audited`);
  }
  for (const relativePath of listSourceTextFiles(['tests/e2e'])) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (allowedE2eLegacySetupBootstrapFileSet.has(relativePath)) {
      allowedMatches.push(relativePath);
      continue;
    }
    violations.push(`${relativePath}: setupBasicPasskeyTest`);
  }

  expect(allowedMatches.sort()).toEqual([...allowedE2eLegacySetupBootstrapFiles].sort());
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 remaining generic browser bootstrap consumers stay audited', () => {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, 'tests'))) {
    if (relativePath === 'tests/setup/index.ts') continue;
    if (relativePath === 'tests/unit/refactor88IntendedE2e.guard.unit.test.ts') continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (retainedBoundaryAuditRowSet.has(relativePath)) continue;
    violations.push(`${relativePath}: setupBasicPasskeyTest usage must have a retained audit row`);
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 fake AuthService helpers stay quarantined to router boundary tests', () => {
  const violations: string[] = [];
  for (const relativePath of listSourceTextFiles(['tests'])) {
    if (relativePath === 'tests/unit/refactor88IntendedE2e.guard.unit.test.ts') continue;
    if (allowsFakeAuthServiceSurface(relativePath)) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const token of fakeAuthServiceQuarantineTokens) {
      if (!source.includes(token)) continue;
      violations.push(`${relativePath}: ${token}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 retained boundary tests stay explicitly classified', () => {
  const planSource = fs.readFileSync(refactor88PlanPath, 'utf8');
  const violations: string[] = [];
  const retainedEvidenceRows = Object.keys(retainedBoundaryAuditEvidenceTokens).sort();
  const walletIframeAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    relativePath.startsWith('tests/wallet-iframe/'),
  );
  const walletIframeTestFiles = listTypeScriptFiles(
    path.join(repoRoot, 'tests/wallet-iframe'),
  ).filter((relativePath) => relativePath.endsWith('.test.ts'));

  expect(retainedEvidenceRows).toEqual([...retainedBoundaryAuditRows].sort());

  for (const relativePath of retainedBoundaryAuditRows) {
    const absolutePath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(absolutePath)) {
      violations.push(`${relativePath}: retained audit row points at a missing test file`);
      continue;
    }
    const source = fs.readFileSync(absolutePath, 'utf8');
    const missingEvidenceTokens = missingSourceTokens(
      source,
      retainedBoundaryAuditEvidenceTokens[relativePath],
    );
    for (const token of missingEvidenceTokens) {
      violations.push(`${relativePath}: missing retained-boundary evidence token: ${token}`);
    }
    const rowPrefix = `| \`${relativePath}\` | keep |`;
    if (planSource.includes(rowPrefix)) continue;
    violations.push(`${relativePath}: missing Refactor 88 keep classification row`);
  }

  expect(planSource).toContain('Initial audit:');
  expect(planSource).toContain('| Target | Classification | Reason |');
  expect([...walletIframeAuditRows].sort()).toEqual(walletIframeTestFiles);
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 retained Lit component browser tests stay explicitly classified', () => {
  const litComponentAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    relativePath.startsWith('tests/lit-components/'),
  );
  const litComponentTestFiles = listTypeScriptFiles(
    path.join(repoRoot, 'tests/lit-components'),
  ).filter((relativePath) => relativePath.endsWith('.test.ts'));

  expect([...litComponentAuditRows].sort()).toEqual(litComponentTestFiles);
});

test('Refactor 88 SeamsWeb browser setup unit tests stay explicitly classified', () => {
  const violations: string[] = [];
  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, 'tests/unit'))) {
    if (!path.basename(relativePath).startsWith('seamsWeb.')) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (retainedBoundaryAuditRowSet.has(relativePath)) continue;
    violations.push(`${relativePath}: setupBasicPasskeyTest usage must have a retained audit row`);
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 confirm-flow browser unit tests stay explicitly classified', () => {
  const confirmFlowAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    path.basename(relativePath).startsWith('confirmTxFlow.'),
  );
  const confirmFlowTestFiles = listTypeScriptFiles(path.join(repoRoot, 'tests/unit'))
    .filter((relativePath) => path.basename(relativePath).startsWith('confirmTxFlow.'))
    .filter((relativePath) => relativePath.endsWith('.test.ts'));

  expect([...confirmFlowAuditRows].sort()).toEqual(confirmFlowTestFiles);
});

test('Refactor 88 test README advertises intended contracts instead of retired lifecycle tests', () => {
  const source = fs.readFileSync(testsReadmePath, 'utf8');

  expect(source).toContain('e2e/intended-behaviours/*.contract.test.ts');
  expect(source).toContain('intended registration,');
  expect(source).toContain('unlock, signing, step-up, and export lifecycle contracts');
  expect(source).toContain('Intended Behaviour Contracts: registration, unlock, signing');
  expect(source).toContain('Registration, unlock,');
  expect(source).toContain('lifecycle authority belongs there');
  expect(source).toContain('for generic SDK/browser bootstrap');
  expect(source).toContain('only; do not use it as a lifecycle oracle');
  expect(source).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(source).toContain('pnpm test:intended:ci');
  expect(source).toContain('pnpm check:intended-mutation-self-check:complete');
  expect(source).toContain('The generic config excludes');
  expect(source).toContain('The generic Playwright config excludes those contracts');
  expect(source).toContain('on the intended runner');
  expect(source).toContain(
    '`test`, `test:lite`, and `test:inline` use the Vite-only browser setup',
  );
  expect(source).toContain(
    '`test:e2e` uses the same generic config and excludes intended contracts',
  );
  expect(source).toContain('The fake relay server launcher has been removed');
  expect(source).not.toContain('End‑to‑End: registration, login, actions');
  expect(source).not.toContain('orchestrates the 5 steps');
  expect(source).not.toContain('e2e/thresholdEd25519.*.test.ts');
  expect(source).not.toContain('tests/setup/fixtures.ts');
  expect(source).not.toContain('tests/setup/flows.ts');
  expect(source).not.toContain('tests/setup/test-utils.ts');
  expect(source).not.toContain('window.testUtils');
  expect(source).not.toContain('USE_RELAY_SERVER');
});

test('Refactor 88 cleanup docs advertise Vite-only integration signing scripts', () => {
  const source = fs.readFileSync(refactor53PlanPath, 'utf8');

  expect(source).toContain(
    '"test:integration:signing": "pnpm -C .. build:sdk-full && playwright test -c playwright.integration.config.ts --reporter=line"',
  );
  expect(source).not.toContain('USE_RELAY_SERVER');
});

test('Refactor 88 demo surfaces do not expose SDK test override hooks', () => {
  const violations = demoSurfaceFiles.filter((relativePath) => {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    return source.includes('__testOverrides');
  });

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 browser test utilities do not expose retired mock hooks', () => {
  const violations: string[] = [];
  for (const relativePath of setupSurfaceFiles) {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    for (const retiredField of retiredBrowserTestUtils) {
      if (!source.includes(retiredField)) continue;
      violations.push(`${relativePath}: ${retiredField}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 retired cleanup surfaces are recorded in Refactor 89 ledger', () => {
  const source = fs.readFileSync(refactor89PlanPath, 'utf8');
  const violations: string[] = [];

  for (const relativePath of retiredMockedRuntimeFiles) {
    if (source.includes(relativePath)) continue;
    violations.push(`missing retired file ledger row: ${relativePath}`);
  }
  for (const relativePath of retiredFakeRelayServerFiles) {
    if (source.includes(relativePath)) continue;
    violations.push(`missing retired fake relay server ledger row: ${relativePath}`);
  }
  for (const retiredField of retiredBrowserTestUtils) {
    const token = retiredField === 'testUtils' ? 'window.testUtils' : retiredField;
    if (source.includes(token)) continue;
    violations.push(`missing retired browser setup hook ledger token: ${token}`);
  }

  expect(source).toContain('## Retired Cleanup Ledger');
  expect(source).toContain('| Refactor 88 |');
  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 generic setup does not expose same-origin rewrite flags', () => {
  const setupIndexSource = fs.readFileSync(path.join(repoRoot, 'tests/setup/index.ts'), 'utf8');
  const setupBootstrapSource = fs.readFileSync(
    path.join(repoRoot, 'tests/setup/bootstrap.ts'),
    'utf8',
  );
  const setupTypesSource = fs.readFileSync(path.join(repoRoot, 'tests/setup/types.ts'), 'utf8');
  const combinedSource = `${setupIndexSource}\n${setupBootstrapSource}\n${setupTypesSource}`;

  expect(combinedSource).not.toContain('forceSameOrigin');
  expect(combinedSource).not.toContain('W3A_FORCE_SAME_ORIGIN_WORKERS');
  expect(combinedSource).not.toContain('useRelayer');
  expect(combinedSource).not.toContain('relayServerUrl');
  expect(combinedSource).not.toContain('5-step');
  expect(combinedSource).not.toContain('mocked Router server');
  expect(combinedSource).not.toContain('LackBalanceForState');
  expect(combinedSource).not.toContain('NotEnoughBalance');
  expect(combinedSource).not.toContain('Atomic registration failed');
  expect(combinedSource).not.toContain('EADDRINUSE');
  expect(combinedSource).not.toContain('On-chain access key mismatch');
});

test('Refactor 88 ECDSA chain target fixtures stay split from warm-session runtime fixtures', () => {
  const warmSessionTestServicesFixtureSource = fs.readFileSync(
    warmSessionTestServicesFixturePath,
    'utf8',
  );
  const signingSessionRecordFixtureSource = fs.readFileSync(
    signingSessionRecordFixturePath,
    'utf8',
  );
  const warmSessionUiConfirmFixtureSource = fs.readFileSync(
    warmSessionUiConfirmFixturePath,
    'utf8',
  );
  const chainTargetFixtureSource = fs.readFileSync(ecdsaChainTargetFixturePath, 'utf8');
  const bootstrapFixtureSource = fs.readFileSync(ecdsaBootstrapFixturePath, 'utf8');

  expect(warmSessionTestServicesFixtureSource).not.toMatch(
    /export function testEcdsaChain(Target|Id)\b/,
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createThresholdEcdsaBootstrapFixture',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createThresholdEcdsaStoreFixture',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function seedEd25519WarmSessionRecord',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function seedEcdsaWarmSessionRecord',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createWarmSessionStatusReader',
  );
  expect(warmSessionTestServicesFixtureSource).not.toContain(
    'export function createWarmSessionUiConfirmFixture',
  );
  expect(warmSessionTestServicesFixtureSource).toContain(
    'export function createWarmSessionTestServices',
  );
  expect(signingSessionRecordFixtureSource).toContain(
    'export function createThresholdEcdsaStoreFixture',
  );
  expect(signingSessionRecordFixtureSource).toContain(
    'export function seedEd25519WarmSessionRecord',
  );
  expect(signingSessionRecordFixtureSource).toContain('export function seedEcdsaWarmSessionRecord');
  expect(warmSessionUiConfirmFixtureSource).toContain(
    'export function createWarmSessionStatusReader',
  );
  expect(warmSessionUiConfirmFixtureSource).toContain(
    'export function createWarmSessionUiConfirmFixture',
  );
  expect(chainTargetFixtureSource).toContain('export function testEcdsaChainId');
  expect(chainTargetFixtureSource).toContain('export function testEcdsaChainTarget');
  expect(bootstrapFixtureSource).toContain('export function createThresholdEcdsaBootstrapFixture');
});

test('Refactor 88 intended command is wired as a named pre-merge gate', () => {
  const rootPackage = readJsonRecord(rootPackageJsonPath);
  const testsPackage = readJsonRecord(testsPackageJsonPath);

  expect(readScript(rootPackage, 'test:intended')).toBe('pnpm -C tests test:intended');
  expect(readScript(testsPackage, 'test:intended')).toBe(
    'pnpm run ensure:intended-google-token && playwright test -c playwright.intended.config.ts --reporter=line',
  );
  expect(readScript(rootPackage, 'test:intended:ci')).toBe('pnpm -C tests test:intended:ci');
  expect(readScript(testsPackage, 'test:intended:ci')).toBe(
    'pnpm run ensure:intended-google-token && playwright test -c playwright.intended.ci.config.ts --reporter=line',
  );
  expect(readScript(rootPackage, 'ensure:intended-google-token')).toBe(
    'pnpm -C tests ensure:intended-google-token',
  );
  expect(readScript(testsPackage, 'ensure:intended-google-token')).toBe(
    'node scripts/ensure-intended-google-token.mjs',
  );
  expect(readScript(rootPackage, 'setup:intended-google-oidc')).toBe(
    'pnpm -C tests setup:intended-google-oidc',
  );
  expect(readScript(testsPackage, 'setup:intended-google-oidc')).toBe(
    'node scripts/setup-intended-google-oidc.mjs',
  );
  expect(readScript(rootPackage, 'refresh:intended-google-token')).toBe(
    'pnpm -C tests refresh:intended-google-token',
  );
  expect(readScript(testsPackage, 'refresh:intended-google-token')).toBe(
    'node scripts/refresh-intended-google-token.mjs',
  );
  expect(readScript(rootPackage, 'seed:intended-local-console')).toBe(
    'pnpm -C tests seed:intended-local-console',
  );
  expect(readScript(testsPackage, 'seed:intended-local-console')).toBe(
    'node scripts/seed-intended-local-console.mjs',
  );
  expect(readScript(rootPackage, 'check:intended-mutation-self-check')).toBe(
    'pnpm -C tests check:intended-mutation-self-check',
  );
  expect(readScript(testsPackage, 'check:intended-mutation-self-check')).toBe(
    'node scripts/check-intended-mutation-self-check.mjs',
  );
  expect(readScript(rootPackage, 'check:intended-mutation-self-check:complete')).toBe(
    'pnpm -C tests check:intended-mutation-self-check:complete',
  );
  expect(readScript(testsPackage, 'check:intended-mutation-self-check:complete')).toBe(
    'node scripts/check-intended-mutation-self-check.mjs --require-detected',
  );
  expect(readScript(rootPackage, 'preflight:intended-mutation-self-check')).toBe(
    'pnpm -C tests preflight:intended-mutation-self-check',
  );
  expect(readScript(testsPackage, 'preflight:intended-mutation-self-check')).toBe(
    'pnpm run ensure:intended-google-token && node scripts/check-intended-mutation-self-check.mjs --preflight',
  );
  expect(readScript(rootPackage, 'preflight:intended-mutation-self-check:ci')).toBe(
    'pnpm -C tests preflight:intended-mutation-self-check:ci',
  );
  expect(readScript(testsPackage, 'preflight:intended-mutation-self-check:ci')).toBe(
    'pnpm run ensure:intended-google-token && node scripts/check-intended-mutation-self-check.mjs --preflight --ci',
  );
});

test('Refactor 88 intended Google OIDC helper uses service-account impersonation', () => {
  const envSource = fs.readFileSync(intendedGoogleOidcEnvModulePath, 'utf8');
  const setupSource = fs.readFileSync(intendedGoogleOidcSetupScriptPath, 'utf8');
  const refreshSource = fs.readFileSync(intendedGoogleTokenRefreshScriptPath, 'utf8');
  const ensureSource = fs.readFileSync(intendedGoogleTokenEnsureScriptPath, 'utf8');
  const seedSource = fs.readFileSync(intendedLocalConsoleSeedScriptPath, 'utf8');
  const intendedConfigSource = fs.readFileSync(intendedConfigPath, 'utf8');
  const preflightSource = fs.readFileSync(intendedMutationSelfCheckScriptPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');

  expect(envSource).toContain("export const defaultEnvFile = '.env.intended.local'");
  expect(envSource).toContain('export const defaultGoogleProjectId =');
  expect(envSource).toContain('export const defaultGoogleClientId =');
  expect(envSource).toContain('fs.chmodSync(envFilePath, 0o600)');
  expect(setupSource).toContain('iamcredentials.googleapis.com');
  expect(setupSource).toContain('roles/iam.serviceAccountTokenCreator');
  expect(setupSource).toContain('add-iam-policy-binding');
  expect(setupSource).toContain('SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT');
  expect(setupSource).toContain('GOOGLE_OIDC_CLIENT_ID');
  expect(setupSource).toContain('SEAMS_INTENDED_GOOGLE_CLIENT_SECRET');
  expect(setupSource).toContain('GOOGLE_OIDC_CLIENT_SECRET');
  expect(setupSource).toContain('--client-secret');
  expect(setupSource).toContain('refresh-intended-google-token.mjs');
  expect(refreshSource).toContain('--impersonate-service-account=');
  expect(refreshSource).toContain('--audiences=');
  expect(refreshSource).toContain('validateGoogleIdTokenClaims');
  expect(refreshSource).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(refreshSource).not.toContain('console.log(token');
  expect(ensureSource).toContain('refresh-intended-google-token.mjs');
  expect(ensureSource).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(ensureSource).toContain('SEAMS_INTENDED_GOOGLE_SERVICE_ACCOUNT');
  expect(ensureSource).toContain('minimumTtlSeconds');
  expect(ensureSource).not.toContain('console.log(token');
  expect(seedSource).toContain('ak_intended_local_publishable');
  expect(seedSource).toContain('hashApiKeySecret');
  expect(seedSource).toContain('SEAMS_INTENDED_PUBLISHABLE_KEY');
  expect(seedSource).toContain('SEAMS_INTENDED_PROJECT_ENVIRONMENT_ID');
  expect(intendedConfigSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local') })",
  );
  expect(preflightSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local') })",
  );
  expect(startupSource).toContain(
    "dotenv.config({ path: path.join(repoRoot, '.env.intended.local') })",
  );
  expect(startupSource).toContain("seed:intended-local-console");
});

test('Refactor 88 retired registration-flow benchmark commands stay absent', () => {
  const rootPackage = readJsonRecord(rootPackageJsonPath);
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const violations: string[] = [];

  collectRetiredScriptViolations('package.json', rootPackage, violations);
  collectRetiredScriptViolations('tests/package.json', testsPackage, violations);

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 generic Playwright config excludes intended contracts', () => {
  const source = fs.readFileSync(genericPlaywrightConfigPath, 'utf8');

  expect(source).toContain("'**/e2e/**/*.test.ts'");
  expect(source).toContain("testIgnore: ['**/e2e/intended-behaviours/**']");
});

test('Refactor 88 registration-flow benchmark report stays marked historical', () => {
  const source = fs.readFileSync(registrationFlowBenchmarkReportPath, 'utf8');
  const violations: string[] = [];

  if (
    !source.startsWith('# Registration Flow Benchmark Report\n\nStatus: archived historical report')
  ) {
    violations.push('docs/benchmarks/registration-flow.md: archive notice must stay at the top');
  }

  for (const token of registrationFlowBenchmarkArchiveTokens) {
    if (source.includes(token)) continue;
    violations.push(`docs/benchmarks/registration-flow.md: missing ${token}`);
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 signing integration suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const integrationScript = readScript(testsPackage, 'test:integration:signing');

  expect(integrationScript).toContain(
    'playwright test -c playwright.integration.config.ts --reporter=line',
  );
  assertScriptAvoidsFakeRelayServer('test:integration:signing', integrationScript);
});

test('Refactor 88 generic e2e script stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const e2eScript = readScript(testsPackage, 'test:e2e');

  expect(e2eScript).toContain('playwright test ./e2e --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:e2e', e2eScript);
});

test('Refactor 88 full generic suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const testScript = readScript(testsPackage, 'test');

  expect(testScript).toContain('playwright test --reporter=line');
  assertScriptAvoidsFakeRelayServer('test', testScript);
});

test('Refactor 88 lite suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const liteScript = readScript(testsPackage, 'test:lite');

  expect(liteScript).toContain('playwright test -c playwright.lite.config.ts --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:lite', liteScript);
});

test('Refactor 88 inline suite stays off the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const inlineScript = readScript(testsPackage, 'test:inline');

  expect(inlineScript).toContain('playwright test --reporter=line');
  assertScriptAvoidsFakeRelayServer('test:inline', inlineScript);
});

test('Refactor 88 package scripts never launch the fake relay server', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const scripts = readScriptsRecord(testsPackage);

  for (const [scriptName, script] of Object.entries(scripts)) {
    assertScriptAvoidsFakeRelayServer(scriptName, script);
  }
});

test('Refactor 88 source-script suite name no longer refers to Router API server scripts', () => {
  const testsPackage = readJsonRecord(testsPackageJsonPath);
  const scripts = readScriptsRecord(testsPackage);

  expect(scripts['test:unit:scripts']).toBe(
    'playwright test -c playwright.scripts.config.ts --reporter=line',
  );
  expect(Object.hasOwn(scripts, 'test:unit:router-api-server-scripts')).toBe(false);
});

test('Refactor 88 wallet-service e2e header smoke follows local wallet origin', () => {
  const source = fs.readFileSync(walletServiceHeadersTestPath, 'utf8');

  expect(source).toContain("const DEFAULT_LOCAL_WALLET_ORIGIN = 'https://localhost:8443'");
  expect(source).toContain('resolveExpectedWalletOrigin()');
  expect(source).toContain('buildPermissionsPolicy(walletOrigin)');
  expect(source).not.toContain("'https://wallet.example.localhost'");
});

test('Refactor 88 sibling plans name the intended lifecycle pre-merge gate', () => {
  const violations: string[] = [];
  for (const doc of siblingLifecycleGateDocs) {
    const source = fs.readFileSync(path.join(repoRoot, doc.relativePath), 'utf8');
    for (const token of doc.requiredTokens) {
      if (source.includes(token)) continue;
      violations.push(`${doc.relativePath}: missing ${token}`);
    }
  }

  expect(violations, violations.join('\n')).toEqual([]);
});

test('Refactor 88 intended config is serial Chromium with zero retries and a suite budget', () => {
  const source = fs.readFileSync(intendedConfigPath, 'utf8');
  expect(source).toContain('fullyParallel: false');
  expect(source).toContain('workers: 1');
  expect(source).toContain('retries: 0');
  expect(source).toContain('globalTimeout: 600_000');
  expect(source).toContain("name: 'chromium'");
  expect(source).toContain("devices['Desktop Chrome']");
  expect(source).not.toContain('webServer');
  expect(source).not.toContain('USE_RELAY_SERVER');
  expect(source).not.toContain('start-servers.mjs');
  expect(source).not.toContain('test-router-api-server.mjs');
});

test('Refactor 88 intended CI config owns service startup', () => {
  const configSource = fs.readFileSync(intendedCiConfigPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');

  expect(configSource).toContain("command: 'node ./scripts/start-intended-services.mjs'");
  expect(configSource).toContain("WEB_SERVER_READY_URL");
  expect(configSource).toContain("'http://127.0.0.1:37888/readyz'");
  expect(configSource).toContain('reuseExistingServer: false');
  expect(configSource).toContain("gracefulShutdown: { signal: 'SIGTERM', timeout: 30_000 }");
  expect(configSource).toContain('timeout: 240_000');
  expect(startupSource).toContain("spawnSync('pnpm'");
  expect(startupSource).toContain("runRequiredBuild('sdk', ['run', 'build:sdk-full'])");
  expect(startupSource).toContain("spawnManaged('site'");
  expect(startupSource).toContain("['-C', 'apps/seams-site', 'run', 'vite']");
  expect(startupSource).not.toContain("spawnManaged('site', ['run', 'site']");
  expect(startupSource).toContain("spawnManaged('router'");
  expect(startupSource).toContain("['run', 'router', '--', '--fresh']");
  expect(startupSource).toContain("removePath('.router-ab-local')");
  expect(startupSource).toContain("removePath('packages/sdk-server-ts/.wrangler/state/seams-d1')");
  expect(startupSource).toContain('VITE_SEAMS_PROJECT_ENVIRONMENT_ID: projectEnvironmentId');
  expect(startupSource).toContain('VITE_SEAMS_PUBLISHABLE_KEY: publishableKey');
  expect(startupSource).toContain("waitForHttpOk(`${routerUrl}/readyz`, 'router readyz'");
  expect(startupSource).toContain('function startWebServerReadyServer()');
  expect(startupSource).toContain('function handleWebServerReadyRequest(request, response)');
  expect(startupSource).toContain("request.url === '/readyz'");
  expect(startupSource).toContain("terminateManagedProcessLeaks('SIGTERM')");
  expect(startupSource).toContain("terminateManagedProcessLeaks('SIGKILL')");
  expect(startupSource).toContain('function isLocalWorkerdCommand(command)');
  assertTokensAppearInOrder(
    startupSource,
    [
      'const router = startRouter();',
      "await waitForHttpOk(`${routerUrl}/healthz`, 'router healthz', 180_000);",
      "await waitForHttpOk(`${routerUrl}/readyz`, 'router readyz', 180_000);",
      'const site = startSite();',
      "await waitForHttpOk(appUrl, 'site', 120_000);",
      "await waitForHttpOk(intendedPageSmokeUrl(), 'intended page', 60_000);",
      'await startWebServerReadyServer();',
    ],
    'intended CI service startup order',
  );
});

test('Refactor 88 intended route is gated to dev and explicit CI opt-in', () => {
  const configSource = fs.readFileSync(seamsSiteConfigPath, 'utf8');
  const appSource = fs.readFileSync(seamsSiteAppPath, 'utf8');
  const startupSource = fs.readFileSync(intendedCiStartupPath, 'utf8');

  expect(configSource).toContain('enableIntendedE2E');
  expect(configSource).toContain('env.VITE_ENABLE_INTENDED_E2E');
  expect(configSource).toContain('env.DEV === true');
  expect(appSource).toContain("case '/__intended-e2e':");
  expect(appSource).toContain('FRONTEND_CONFIG.enableIntendedE2E ? <IntendedBehaviourE2EPage />');
  expect(appSource).toContain(': <NotFoundPage />');
  expect(startupSource).toContain("VITE_ENABLE_INTENDED_E2E: '1'");
});

test('Refactor 88 intended harness fails fast when a public action click is inert', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  const startMethod = source.match(
    /private async waitForIntendedPageActionStarted[\s\S]*?\n  private async closeExportViewerIfOpen/,
  );
  expect(startMethod, 'waitForIntendedPageActionStarted method').not.toBeNull();
  expect(source).toContain('intendedPageActionStartedOrCompleted');
  expect(source).toContain('did not start after click');
  expect(source).toContain('tryReadIntendedPageSnapshot');
  expect(source).toContain('Page snapshot:');
  expect(startMethod?.[0]).not.toContain('.catch(() => undefined)');
});

test('Refactor 88 failure string tripwires are versioned harness matchers', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('LIFECYCLE_FAILURE_MATCHER_TABLE_VERSION');
  expect(source).toContain('LIFECYCLE_FAILURE_MATCHERS');
  expect(source).not.toContain('LIFECYCLE_FAILURE_PATTERNS');
  expect(source).toContain('remaining_spend_indeterminate_budget_unknown');
  expect(source).toContain('/budget_unknown/i');
  expect(source).toContain('exact_lane_selection_failure');
  expect(source).toContain('canonical_ecdsa_lane_ambiguous_material');
  expect(source).toContain('/ambiguous_material/i');
  expect(source).not.toContain('duplicate_exact_lane');
  expect(source).not.toContain('/duplicate exact lane/i');
  expect(source).toContain('wallet_runtime_postcondition');
  expect(source).toContain('captureFailedResponseBody');
  expect(source).toContain('recordViolationIfNeeded(bodySnippet)');
});

test('Refactor 88 NEAR signing contract verifies Ed25519 signatures cryptographically', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('verifyNearEd25519Signature');
  expect(source).toContain('ed25519.verifyAsync');
  expect(source).toContain('parseNearUnsignedTransactionSubject');
  expect(source).toContain('base58Decode');
  expect(source).toContain("createHash('sha256')");
});

test('Refactor 88 ECDSA contracts recover Tempo and Arc/EVM signer addresses', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('verifyTempoEcdsaSignature');
  expect(source).toContain('verifyArcEvmSignature');
  expect(source).toContain('recoverAddress');
  expect(source).toContain('recoverTransactionAddress');
  expect(source).toContain('decodeTempoSignedTransaction');
  expect(source).toContain('thresholdEcdsaEthereumAddress');
});

test('Refactor 88 signing contracts assert structured auth-path events', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('assertSigningAuthEvents');
  expect(source).toContain('signing.auth.warm_session.claimed');
  expect(source).toContain('signing.auth.passkey.prompt.started');
  expect(source).toContain('signing.auth.email_otp.challenge.sent');
  expect(source).toContain('did not claim a warm signing session');
});

test('Refactor 88 intended harness only stubs external identity and chain RPC hosts', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  const externalHosts = extractDelimitedSource(
    source,
    'const EXTERNAL_HOST_PATTERNS = [',
    '] as const;',
  );
  const routeHandler = extractDelimitedSource(
    source,
    'private async handleExternalRoute',
    'private handleConsoleMessage',
  );
  const fulfillStub = extractDelimitedSource(
    source,
    'async function fulfillExternalStub',
    'async function fulfillNearRpcStub',
  );

  expect(externalHosts).toContain('googleapis\\.com');
  expect(externalHosts).toContain('accounts\\.google\\.com');
  expect(externalHosts).toContain('near\\.org');
  expect(externalHosts).toContain('fastnear\\.com');
  expect(externalHosts).toContain('rpc\\.moderato\\.tempo\\.xyz');
  expect(externalHosts).toContain('rpc\\.testnet\\.arc\\.network');
  expect(externalHosts).not.toContain('localhost');
  expect(externalHosts).not.toContain('router');
  expect(externalHosts).not.toContain('wallet');
  assertTokensAppearInOrder(
    routeHandler,
    [
      'if (!isExternalStubHost(url.hostname))',
      'await route.continue();',
      'return;',
      'await fulfillExternalStub(route, this.config);',
    ],
    'intended harness external route boundary',
  );
  expect(fulfillStub).not.toContain('routerUrl');
  expect(fulfillStub).not.toContain('walletOrigin');
  expect(fulfillStub).not.toContain('/__intended-e2e');
});

test('Refactor 88 passkey unlock preserves storage while clearing page runtime', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('resetRuntimeOnlyState');
  expect(source).toContain("this.page.goto('about:blank')");
  expect(source).toContain('requirePasskeyUnlockResult');
  expect(source).toContain('passkey_unlock_success');
});

test('Refactor 88 passkey contracts use a PRF-capable virtual authenticator', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('WebAuthn.addVirtualAuthenticator');
  expect(source).toContain('hasPrf: true');
});

test('Refactor 88 Email OTP unlock uses public flow and dev outbox readback', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(pageSource).toContain('beginGoogleEmailOtpWalletAuth');
  expect(pageSource).toContain("mode: 'login'");
  expect(pageSource).toContain("mode: 'register'");
  expect(pageSource).toContain('googleEmailOtpLoginFlowChallengeId');
  expect(pageSource).toContain('/wallet/email-otp/dev/otp-outbox');
  expect(pageSource).toContain('__seamsIntendedE2EReadEmailOtpCode');
  expect(pageSource).toContain('email_otp_unlock_success');
  expect(harnessSource).toContain('fillWalletIframeEmailOtpIfAvailable');
  expect(harnessSource).toContain('readWalletIframeEmailOtpChallengeId');
  expect(harnessSource).toContain('otpFilled');
});

test('Refactor 88 remaining-spend exhaustion is driven by public signing', () => {
  const source = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(source).toContain('exhaustSigningBudget');
  expect(source).toContain('remaining_spend.exhaust');
  expect(source).toContain('MAX_BUDGET_EXHAUSTION_SIGNS');
  expect(source).toContain('minimumRemainingUse');
  expect(source).toContain('this.signNearTransaction(this.currentWarmSigningStage)');
  expect(source).toContain('NEAR remaining spend did not exhaust');
  expect(source).not.toContain('IntendedHarnessActionNotImplementedError');
});

test('Refactor 88 key export actions use public exact-lane export UI', () => {
  const pageSource = fs.readFileSync(
    path.join(repoRoot, 'apps/seams-site/src/pages/intended-e2e/page.tsx'),
    'utf8',
  );
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  expect(pageSource).toContain('resolveExactKeyExportLane');
  expect(pageSource).toContain('exportKeypairWithUI');
  expect(pageSource).toContain('ed25519_export_success');
  expect(pageSource).toContain('ecdsa_export_success');
  expect(harnessSource).toContain('requireEd25519ExportResult');
  expect(harnessSource).toContain('requireEcdsaExportResult');
  expect(harnessSource).toContain('assertKeyExportAuthEvents');
  expect(harnessSource).toContain('key_export.auth.passkey.prompt.started');
  expect(harnessSource).toContain('did not fill a fresh Email OTP export authorization');
  expect(harnessSource).not.toMatch(
    /this\.passkeyPromptCount \+= 1;\s+this\.recordService\(`ed25519 export/,
  );
});

test('Refactor 88 mutation self-check manifest covers known regression classes', () => {
  const harnessSource = fs.readFileSync(intendedHarnessPath, 'utf8');
  const mutationScriptSource = fs.readFileSync(intendedMutationSelfCheckScriptPath, 'utf8');
  const planSource = fs.readFileSync(refactor88PlanPath, 'utf8');
  const manifest = readJsonRecord(mutationSelfCheckManifestPath);
  const mutations = manifest.mutations;
  if (!Array.isArray(mutations)) {
    throw new Error('mutation self-check manifest must include a mutations array');
  }
  const instruction = requireStringField(manifest, 'instruction');
  expect(instruction).toContain('fresh SDK build');
  expect(instruction).toContain('restarted site/router services');
  expect(instruction).toContain('CI-managed intended startup');

  const ids = mutations.map((mutation) => requireStringField(mutation, 'id')).sort();
  expect(ids).toEqual([...expectedMutationSelfCheckIds].sort());

  const uncheckedMutationProofRows = expectedMutationSelfCheckIds.filter((id) =>
    planSource.includes(`- [ ] Run \`${id}\``),
  );
  if (uncheckedMutationProofRows.length > 0) {
    expect(planSource).not.toContain(
      'The Phase 3B mutation self-check has been run and every seeded regression',
    );
    expect(planSource).toContain('pnpm check:intended-mutation-self-check:complete');
    expect(planSource).toContain('must pass before this');
    expect(planSource).toContain('until every seeded regression row is `detected`');
  }

  const contractFiles = new Set(expectedContractFiles);
  for (const mutation of mutations) {
    const id = requireStringField(mutation, 'id');
    expect(requireStringField(mutation, 'seededRegression'), `${id} seededRegression`).toBeTruthy();
    expect(
      requireStringField(mutation, 'expectedFailureOracle'),
      `${id} expectedFailureOracle`,
    ).toBeTruthy();

    const targetedContracts = requireStringArrayField(mutation, 'contractFiles');
    expect(targetedContracts.length, `${id} contractFiles`).toBeGreaterThan(0);
    for (const contractFile of targetedContracts) {
      expect(contractFiles.has(contractFile as (typeof expectedContractFiles)[number])).toBe(true);
    }

    const evidenceTokens = requireStringArrayField(mutation, 'requiredHarnessEvidence');
    expect(evidenceTokens.length, `${id} requiredHarnessEvidence`).toBeGreaterThan(0);
    for (const evidenceToken of evidenceTokens) {
      expect(harnessSource, `${id} missing harness evidence ${evidenceToken}`).toContain(
        evidenceToken,
      );
    }

    const proof = requireRecordField(mutation, 'phase3bProof');
    const mutationId = id as (typeof expectedMutationSelfCheckIds)[number];
    expect(requireStringField(proof, 'status'), `${id} proof status`).toBe(
      expectedMutationProofStatuses[mutationId],
    );
    const expectedUnblockRequirement = expectedMutationUnblockRequirements[mutationId];
    if (expectedUnblockRequirement) {
      expect(requireStringField(proof, 'unblockRequirement'), `${id} unblockRequirement`).toBe(
        expectedUnblockRequirement,
      );
    } else {
      expect(proof.unblockRequirement, `${id} unblockRequirement`).toBeUndefined();
    }
    expect(proof.requiresFreshStartup, `${id} requiresFreshStartup`).toBe(true);
    expect(typeof proof.requiresEmailOtpGoogleIdToken, `${id} requiresEmailOtpGoogleIdToken`).toBe(
      'boolean',
    );
    if (id === 'cross_chain_ecdsa_material_reuse') {
      assertCrossChainBlockerStillBackedBySharedProductIdentity(proof);
    }
    if (id === 'first_post_step_up_transaction_failure') {
      expect(requireStringField(proof, 'observedFailureOracle')).toBe(
        'post-step-up transaction failed',
      );
    }
    const expectedDetectedEvidence = expectedMutationDetectedProofEvidence[mutationId];
    if (expectedDetectedEvidence) {
      expect(requireStringField(proof, 'observedAt'), `${id} observedAt`).toBe(
        expectedDetectedEvidence.observedAt,
      );
      expect(
        requireStringField(proof, 'observedFailureCommand'),
        `${id} observedFailureCommand`,
      ).toBe(expectedDetectedEvidence.observedFailureCommand);
      expect(
        requireStringField(proof, 'restoredValidationCommand'),
        `${id} restoredValidationCommand`,
      ).toBe(expectedDetectedEvidence.restoredValidationCommand);
    } else {
      expect(proof.observedAt, `${id} observedAt`).toBeUndefined();
      expect(proof.observedFailureCommand, `${id} observedFailureCommand`).toBeUndefined();
      expect(proof.restoredValidationCommand, `${id} restoredValidationCommand`).toBeUndefined();
    }
    const localCommand = requireStringField(proof, 'localCommand');
    const ciCommand = requireStringField(proof, 'ciCommand');
    expect(localCommand, `${id} localCommand`).toContain('playwright.intended.config.ts');
    expect(ciCommand, `${id} ciCommand`).toContain('playwright.intended.ci.config.ts');
    expect(localCommand, `${id} localCommand`).not.toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN=');
    expect(ciCommand, `${id} ciCommand`).not.toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN=');
    if (proof.requiresEmailOtpGoogleIdToken === true) {
      expect(localCommand, `${id} local token ensure`).toContain(
        'pnpm -C tests run ensure:intended-google-token',
      );
      expect(ciCommand, `${id} ci token ensure`).toContain(
        'pnpm -C tests run ensure:intended-google-token',
      );
    }
    expect(
      targetedContracts.some(
        (contractFile) => localCommand.includes(contractFile) || ciCommand.includes(contractFile),
      ),
      `${id} proof command target`,
    ).toBe(true);
  }

  expect(mutationScriptSource).toContain('fixedCiPorts');
  expect(mutationScriptSource).toContain('expectedManifestVersion');
  expect(mutationScriptSource).toContain('googleTokenEnsureCommand');
  expect(mutationScriptSource).toContain('expectedFailureOraclesByMutationId');
  expect(mutationScriptSource).toContain('printManifestCheckSummary');
  expect(mutationScriptSource).toContain('formatProofStatusCounts');
  expect(mutationScriptSource).toContain('proof status:');
  expect(mutationScriptSource).toContain('--require-detected');
  expect(mutationScriptSource).toContain('enforceDetectedProofRequirement');
  expect(mutationScriptSource).toContain('detectedProofRows');
  expect(mutationScriptSource).toContain('printDetectedProofRow');
  expect(mutationScriptSource).toContain('proof completion incomplete');
  expect(mutationScriptSource).toContain('observedAt=${row.observedAt}');
  expect(mutationScriptSource).toContain('restored: ${row.restoredValidationCommand}');
  expect(mutationScriptSource).toContain('Arc/EVM recovered signer mismatch');
  expect(mutationScriptSource).toContain('post-step-up transaction failed');
  expect(mutationScriptSource).toContain("await httpsOk(appUrl, 'site root')");
  expect(mutationScriptSource).toContain('intendedPageSmokeUrl');
  expect(mutationScriptSource).toContain("flow', 'passkey.registration'");
  expect(mutationScriptSource).toContain("walletId', 'intended-preflight-smoke'");
  expect(mutationScriptSource).toContain('SEAMS_INTENDED_GOOGLE_ID_TOKEN');
  expect(mutationScriptSource).toContain('validateGoogleIdTokenPreflight');
  expect(mutationScriptSource).toContain('isCompactJwtShape');
  expect(mutationScriptSource).toContain('local-google-id-token');
  expect(mutationScriptSource).toContain('must not inline a Google ID token');
  expect(mutationScriptSource).toContain('compact JWT: header.payload.signature');
  expect(mutationScriptSource).toContain('jwt-shaped');
  expect(mutationScriptSource).toContain('SEAMS_INTENDED_MUTATION_FRESH_STARTUP');
  expect(mutationScriptSource).toContain('knownProductBlocker');
  expect(mutationScriptSource).toContain('allowedPhase3bProofStatuses');
  expect(mutationScriptSource).toContain('validateProofStatusPolicy');
  expect(mutationScriptSource).toContain('validateDetectedProofEvidence');
  expect(mutationScriptSource).toContain('validateBlockedProofOmitsDetectedEvidence');
  expect(mutationScriptSource).toContain('observedFailureOracle');
  expect(mutationScriptSource).toContain('observedFailureCommand');
  expect(mutationScriptSource).toContain('restoredValidationCommand');
  expect(mutationScriptSource).toContain('unblockRequirement');
  expect(mutationScriptSource).toContain('blocked proof rows must explain');
  expect(mutationScriptSource).toContain('unblock: ${row.unblockRequirement}');
  expect(mutationScriptSource).toContain("const status = requireStringField(proof, 'status')");
  expect(mutationScriptSource).toContain('status,');
  expect(mutationScriptSource).toContain('status=${row.status}');
  expect(mutationScriptSource).toContain('validateKnownProductBlockerPolicy');
  expect(mutationScriptSource).toContain('validateProofTokenPolicy');
  expect(mutationScriptSource).toContain('validateProofCommandContractScope');
  expect(mutationScriptSource).toContain('phase3bProof');
  expect(mutationScriptSource).toContain('--preflight');
  expect(mutationScriptSource).toContain('--mutation');
  expect(mutationScriptSource).toContain('selectMutations');
  expect(mutationScriptSource).toContain('unknown mutation id(s)');
});

function assertCrossChainBlockerStillBackedBySharedProductIdentity(
  proof: Record<string, unknown>,
): void {
  const knownProductBlocker = requireStringField(proof, 'knownProductBlocker');
  expect(knownProductBlocker).toContain('target-specific ECDSA owner/public-key facts');
  expect(knownProductBlocker).toContain('shared evm-family key scope');

  const identityTestSource = fs.readFileSync(evmFamilyEcdsaIdentityTestPath, 'utf8');
  expect(identityTestSource).toContain(
    'derives one shared fingerprint across Tempo and Arc/EVM session lanes',
  );
  expect(identityTestSource).toContain('expect(evmKey.thresholdOwnerAddress).toBe');
  expect(identityTestSource).toContain('deriveEvmFamilyKeyFingerprint(evmKey)');
  expect(identityTestSource).toContain('deriveEvmFamilyKeyFingerprint(tempoKey)');
}

function allowsFakeAuthServiceSurface(relativePath: string): boolean {
  return (
    relativePath.startsWith('tests/relayer/') ||
    fakeAuthServiceAllowedFiles.includes(
      relativePath as (typeof fakeAuthServiceAllowedFiles)[number],
    )
  );
}

function assertTokensAppearInOrder(source: string, tokens: readonly string[], label: string): void {
  let offset = 0;
  for (const token of tokens) {
    const nextOffset = source.indexOf(token, offset);
    if (nextOffset < 0) {
      throw new Error(`${label} missing or reordered lifecycle action: ${token}`);
    }
    offset = nextOffset + token.length;
  }
}

function missingSourceTokens(source: string, tokens: readonly string[]): string[] {
  const missing: string[] = [];
  for (const token of tokens) {
    if (!source.includes(token)) missing.push(token);
  }
  return missing;
}

function extractModuleSpecifiers(source: string): string[] {
  const specifiers: string[] = [];
  const importFromPattern = /\bimport\s+(?:type\s+)?[\s\S]*?\s+from\s+['"]([^'"]+)['"]/g;
  const sideEffectImportPattern = /\bimport\s+['"]([^'"]+)['"]/g;
  const dynamicImportPattern = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
  collectModuleSpecifiers(source, importFromPattern, specifiers);
  collectModuleSpecifiers(source, sideEffectImportPattern, specifiers);
  collectModuleSpecifiers(source, dynamicImportPattern, specifiers);
  return [...new Set(specifiers)].sort();
}

function collectModuleSpecifiers(source: string, pattern: RegExp, specifiers: string[]): void {
  for (const match of source.matchAll(pattern)) {
    const specifier = match[1];
    if (specifier) specifiers.push(specifier);
  }
}

function extractUnionMembers(source: string, typeName: string): string[] {
  const unionSource = extractDelimitedSource(source, `type ${typeName} =`, ';');
  return [...unionSource.matchAll(/\|\s+([A-Za-z][A-Za-z0-9_]*)/g)].map((match) => match[1]);
}

function extractUniqueSwitchCases(source: string): string[] {
  const cases = [...source.matchAll(/case\s+'([^']+)'/g)].map((match) => match[1]);
  return [...new Set(cases)].sort();
}

function extractDelimitedSource(source: string, startToken: string, endToken: string): string {
  const start = source.indexOf(startToken);
  if (start < 0) {
    throw new Error(`source missing start token: ${startToken}`);
  }
  const end = source.indexOf(endToken, start + startToken.length);
  if (end < 0) {
    throw new Error(`source missing end token after ${startToken}: ${endToken}`);
  }
  return source.slice(start, end);
}

function listTypeScriptFiles(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
    }
  }
  return files.sort();
}

function listSourceTextFiles(relativeRoots: readonly string[]): string[] {
  return relativeRoots.flatMap(listSourceTextFilesInRoot).sort();
}

function listSourceTextFilesInRoot(relativeRoot: string): string[] {
  return listSourceTextFilesRecursive(path.join(repoRoot, relativeRoot));
}

function listSourceTextFilesRecursive(dir: string): string[] {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'out' || entry.name === 'dist') {
        continue;
      }
      files.push(...listSourceTextFilesRecursive(absolutePath));
      continue;
    }
    if (!entry.isFile() || !isSourceTextFile(entry.name)) continue;
    files.push(path.relative(repoRoot, absolutePath).replaceAll(path.sep, '/'));
  }
  return files;
}

function isSourceTextFile(fileName: string): boolean {
  return ['.ts', '.tsx', '.js', '.mjs', '.cjs'].some((extension) => fileName.endsWith(extension));
}

function readJsonRecord(filePath: string): Record<string, unknown> {
  const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!isRecord(parsed)) {
    throw new Error(`${filePath} must contain a JSON object`);
  }
  return parsed;
}

function readScript(packageJson: Record<string, unknown>, scriptName: string): string {
  const scripts = readScriptsRecord(packageJson);
  const script = scripts[scriptName];
  if (typeof script !== 'string') {
    throw new Error(`package.json script ${scriptName} must be a string`);
  }
  return script;
}

function readScriptsRecord(packageJson: Record<string, unknown>): Record<string, string> {
  const scripts = packageJson.scripts;
  if (!isRecord(scripts)) {
    throw new Error('package.json scripts must be an object');
  }
  const result: Record<string, string> = {};
  for (const [scriptName, script] of Object.entries(scripts)) {
    if (typeof script !== 'string') {
      throw new Error(`package.json script ${scriptName} must be a string`);
    }
    result[scriptName] = script;
  }
  return result;
}

function assertScriptAvoidsFakeRelayServer(scriptName: string, script: string): void {
  const violations: string[] = [];
  for (const token of fakeRelayServerScriptTokens) {
    if (!script.includes(token)) continue;
    violations.push(`${scriptName}: ${token}`);
  }
  expect(violations, violations.join('\n')).toEqual([]);
}

function collectRetiredScriptViolations(
  label: string,
  packageJson: Record<string, unknown>,
  violations: string[],
): void {
  const scripts = readScriptsRecord(packageJson);
  for (const [scriptName, scriptValue] of Object.entries(scripts)) {
    if (typeof scriptValue !== 'string') {
      violations.push(`${label}: script ${scriptName} must be a string`);
      continue;
    }
    for (const token of retiredRegistrationFlowBenchmarkTokens) {
      if (scriptName.includes(token) || scriptValue.includes(token)) {
        violations.push(`${label}: ${scriptName} references retired ${token}`);
      }
    }
  }
}

function requireStringField(value: unknown, fieldName: string): string {
  if (!isRecord(value)) {
    throw new Error(`mutation self-check row must be an object`);
  }
  const field = value[fieldName];
  if (typeof field !== 'string' || field.trim() === '') {
    throw new Error(`mutation self-check field ${fieldName} must be a non-empty string`);
  }
  return field;
}

function requireStringArrayField(value: unknown, fieldName: string): string[] {
  if (!isRecord(value)) {
    throw new Error(`mutation self-check row must be an object`);
  }
  const field = value[fieldName];
  if (!Array.isArray(field) || field.length === 0) {
    throw new Error(`mutation self-check field ${fieldName} must be a non-empty array`);
  }
  return field.map((entry) => {
    if (typeof entry !== 'string' || entry.trim() === '') {
      throw new Error(`mutation self-check field ${fieldName} entries must be strings`);
    }
    return entry;
  });
}

function requireRecordField(value: unknown, fieldName: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`mutation self-check row must be an object`);
  }
  const field = value[fieldName];
  if (!isRecord(field)) {
    throw new Error(`mutation self-check field ${fieldName} must be an object`);
  }
  return field;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}
