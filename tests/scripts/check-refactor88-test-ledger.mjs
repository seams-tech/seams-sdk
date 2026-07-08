#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(scriptDir, '../..');
const docPath = path.join(repoRoot, 'docs/refactor-88-intended-behaviour-e2e.md');

const scopeRoots = [
  'tests/unit',
  'tests/e2e',
  'tests/relayer',
  'tests/lit-components',
  'tests/wallet-iframe',
];

const args = new Set(process.argv.slice(2));
const listMissing = args.has('--list-missing');
const requireComplete = args.has('--require-complete');

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
    'tests/unit/seamsAuthMenu.accountAvailability.unit.test.ts',
    'tests/unit/seamsAuthMenu.fouc.unit.test.ts',
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
    'tests/wallet-iframe/seamsAuthMenu.qrButton.overlay.test.ts',
    'tests/wallet-iframe/preferences.sync.test.ts',
    'tests/wallet-iframe/router.behavior.concurrent.test.ts',
    'tests/wallet-iframe/router.behavior.sticky.test.ts',
    'tests/wallet-iframe/router.behavior.test.ts',
    'tests/wallet-iframe/router.cancellationProgress.test.ts',
    'tests/wallet-iframe/router.computeOverlayIntent.test.ts',
    'tests/wallet-iframe/router.registrationActivation.test.ts',
    'tests/wallet-iframe/router.signingProgressForwarding.test.ts',
    'tests/wallet-iframe/static-wallet-assets.browser.test.ts',
];
const retainedBoundaryAuditRowSet = new Set(retainedBoundaryAuditRows);
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
    'tests/unit/seamsAuthMenu.accountAvailability.unit.test.ts': [
        'Passkey auth account availability',
        'local saved credentials do not mark an unregistered account as existing',
        'register badge stays neutral for a locally saved account until it exists on-chain',
    ],
    'tests/unit/seamsAuthMenu.fouc.unit.test.ts': [
        'SeamsAuthMenu styles bootstrap',
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
        'SeamsAuthMenu prompts rotation after recovery consumes a code',
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
        'wallet-service default route does not emit legacy strict CSP',
        'content-security-policy',
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
    'tests/wallet-iframe/seamsAuthMenu.qrButton.overlay.test.ts': [
        'SeamsAuthMenu QR button overlay regression',
        'disabled Device2 linking keeps wallet iframe overlay hidden',
        'PM_START_DEVICE2_LINKING_FLOW',
    ],
    'tests/wallet-iframe/preferences.sync.test.ts': [
        'PREFERENCES_CHANGED',
        'app-origin mirrors wallet-host confirmation config via PREFERENCES_CHANGED',
        'PM_SET_CONFIRMATION_CONFIG',
        'PM_SET_CONFIG',
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
    'tests/wallet-iframe/static-wallet-assets.browser.test.ts': [
        'static wallet-service loads workers and worker WASM from dist/public',
        'WORKER_ROUTES',
        'WORKER_WASM_ROUTES',
        'WebAssembly.compile',
    ],
};

function toRepoPath(absolutePath) {
  return path.relative(repoRoot, absolutePath).split(path.sep).join('/');
}

function listFiles(directory) {
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const absolutePath = path.join(directory, entry.name);

    if (entry.isDirectory()) {
      files.push(...listFiles(absolutePath));
      continue;
    }

    if (entry.isFile()) {
      files.push(toRepoPath(absolutePath));
    }
  }

  return files;
}

function collectScopeFiles() {
  return new Set(
    scopeRoots.flatMap((root) => listFiles(path.join(repoRoot, root))).sort(),
  );
}

function pathInScope(candidate) {
  return scopeRoots.some((root) => candidate === root || candidate.startsWith(`${root}/`));
}

function collectLedgerPaths() {
  const source = fs.readFileSync(docPath, 'utf8');
  const lines = source.split(/\r?\n/);
  const ledgerPaths = new Set();
  let inLedgerTable = false;

  for (const line of lines) {
    if (line.startsWith('| Target | Classification | Reason |')) {
      inLedgerTable = true;
      continue;
    }

    if (inLedgerTable && line.startsWith('### Phase 6:')) {
      break;
    }

    if (!inLedgerTable || !line.startsWith('| `')) {
      continue;
    }

    for (const match of line.matchAll(/`([^`]+)`/g)) {
      if (pathInScope(match[1])) {
        ledgerPaths.add(match[1]);
      }
    }
  }

  return ledgerPaths;
}

const scopeFiles = collectScopeFiles();
const ledgerPaths = collectLedgerPaths();
const existingLedgerPaths = [...ledgerPaths].filter((ledgerPath) => scopeFiles.has(ledgerPath)).sort();
const deletedLedgerPaths = [...ledgerPaths].filter((ledgerPath) => !scopeFiles.has(ledgerPath)).sort();
const missingLedgerPaths = [...scopeFiles].filter((scopeFile) => !ledgerPaths.has(scopeFile)).sort();

console.log(
  `[refactor88-test-ledger] scope=${scopeFiles.size} ledger_existing=${existingLedgerPaths.length} ledger_deleted=${deletedLedgerPaths.length} missing=${missingLedgerPaths.length}`,
);

if (listMissing) {
  for (const missingPath of missingLedgerPaths) {
    console.log(missingPath);
  }
}

if (requireComplete && missingLedgerPaths.length > 0) {
  process.exitCode = 1;
}

assertRetainedBoundaryAuditComplete();

function assertRetainedBoundaryAuditComplete() {
  const planSource = fs.readFileSync(docPath, 'utf8');
  const violations = [];
  const retainedEvidenceRows = Object.keys(retainedBoundaryAuditEvidenceTokens).sort();
  const walletIframeAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    relativePath.startsWith('tests/wallet-iframe/'),
  );
  const walletIframeTestFiles = listTypeScriptFiles(path.join(repoRoot, 'tests/wallet-iframe')).filter(
    (relativePath) => relativePath.endsWith('.test.ts'),
  );

  assertSameStringList(retainedEvidenceRows, [...retainedBoundaryAuditRows].sort(), 'retained evidence rows');
  for (const relativePath of retainedBoundaryAuditRows) {
    const absolutePath = path.join(repoRoot, relativePath);
    if (!fs.existsSync(absolutePath)) {
      violations.push(relativePath + ': retained audit row points at a missing test file');
      continue;
    }
    const source = fs.readFileSync(absolutePath, 'utf8');
    const missingEvidenceTokens = missingSourceTokens(
      source,
      retainedBoundaryAuditEvidenceTokens[relativePath],
    );
    for (const token of missingEvidenceTokens) {
      violations.push(relativePath + ': missing retained-boundary evidence token: ' + token);
    }
    if (hasKeepClassification(planSource, relativePath)) continue;
    violations.push(relativePath + ': missing Refactor 88 keep classification row');
  }

  if (!planSource.includes('Initial audit:')) {
    violations.push('Refactor 88 plan is missing the Initial audit marker');
  }
  if (!planSource.includes('| Target | Classification | Reason |')) {
    violations.push('Refactor 88 plan is missing the Phase 5 ledger header');
  }
  assertSameStringList([...walletIframeAuditRows].sort(), walletIframeTestFiles, 'wallet iframe retained audit rows');

  const litComponentAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    relativePath.startsWith('tests/lit-components/'),
  );
  const litComponentTestFiles = listTypeScriptFiles(path.join(repoRoot, 'tests/lit-components')).filter(
    (relativePath) => relativePath.endsWith('.test.ts'),
  );
  assertSameStringList([...litComponentAuditRows].sort(), litComponentTestFiles, 'lit retained audit rows');

  const confirmFlowAuditRows = retainedBoundaryAuditRows.filter((relativePath) =>
    path.basename(relativePath).startsWith('confirmTxFlow.'),
  );
  const confirmFlowTestFiles = listTypeScriptFiles(path.join(repoRoot, 'tests/unit'))
    .filter((relativePath) => path.basename(relativePath).startsWith('confirmTxFlow.'))
    .filter((relativePath) => relativePath.endsWith('.test.ts'));
  assertSameStringList([...confirmFlowAuditRows].sort(), confirmFlowTestFiles, 'confirm-flow retained audit rows');

  for (const relativePath of listTypeScriptFiles(path.join(repoRoot, 'tests/unit'))) {
    if (!path.basename(relativePath).startsWith('seamsWeb.')) continue;
    const source = fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
    if (!source.includes('setupBasicPasskeyTest')) continue;
    if (retainedBoundaryAuditRowSet.has(relativePath)) continue;
    violations.push(relativePath + ': setupBasicPasskeyTest usage must have a retained audit row');
  }

  if (violations.length > 0) {
    for (const violation of violations) console.error('[refactor88-test-ledger] ' + violation);
    process.exitCode = 1;
  }
}

function hasKeepClassification(planSource, relativePath) {
  return planSource.includes('| `' + relativePath + '` | keep |');
}

function missingSourceTokens(source, tokens) {
  const missing = [];
  for (const token of tokens) {
    if (!source.includes(token)) missing.push(token);
  }
  return missing;
}

function listTypeScriptFiles(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absolutePath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listTypeScriptFiles(absolutePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith('.ts')) {
      files.push(toRepoPath(absolutePath));
    }
  }
  return files.sort();
}

function assertSameStringList(actual, expected, label) {
  if (JSON.stringify(actual) === JSON.stringify(expected)) return;
  console.error('[refactor88-test-ledger] ' + label + ' mismatch');
  console.error('[refactor88-test-ledger] actual: ' + JSON.stringify(actual));
  console.error('[refactor88-test-ledger] expected: ' + JSON.stringify(expected));
  process.exitCode = 1;
}
