import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const signingEngineRoot = path.join(repoRoot, 'client/src/core/signingEngine');

const targetTopLevelFolders = [
  'assembly',
  'flows',
  'session',
  'stepUpConfirmation',
  'threshold',
  'chains',
  'uiConfirm',
  'workers',
  'nonce',
  'webauthnAuth',
] as const;
const targetContractFolders = [
  'assembly',
  'flows',
  'chains',
  'stepUpConfirmation',
  'uiConfirm',
  'workers',
  'webauthnAuth',
] as const;

const signingEngineAllowedImportPrefixes = [
  './assembly/',
  './flows/',
  './interfaces/',
  './chains/',
  './stepUpConfirmation/',
  './threshold/ed25519/public',
  './threshold/ecdsa/activation',
  './threshold/ecdsa/commitQueue',
  './threshold/crypto/hssClientSignerWasm',
  './threshold/ed25519/commitQueue',
  './threshold/sessionPolicy',
  './session/public',
  './session/userPreferences',
  './session/budget/budgetStatusReader',
  './session/availability/persistedAvailableSigningLanes',
  './session/persistence/records',
  './session/identity/emailOtpHssIdentity',
  './session/identity/laneIdentity',
  './session/identity/evmFamilyEcdsaIdentity',
  './session/passkey/',
  './session/warmCapabilities/',
  './session/emailOtp/',
  './nonce/NonceCoordinator',
  './uiConfirm/',
  './webauthnAuth/',
  './workerManager/',
] as const;

const currentTopLevelImportContract: Record<string, readonly string[]> = {
  'SigningEngine.ts': [
    'chains',
    'stepUpConfirmation',
    'assembly',
    'interfaces',
    'nonce',
    'flows',
    'session',
    'threshold',
    'uiConfirm',
    'webauthnAuth',
    'workerManager',
  ],
  'index.ts': ['SigningEngine.ts', 'stepUpConfirmation', 'interfaces'],
  webauthnAuth: [],
  chains: ['interfaces', 'workerManager'],
  stepUpConfirmation: ['interfaces', 'webauthnAuth'],
  assembly: [
    'flows',
    'chains',
    'stepUpConfirmation',
    'interfaces',
    'nonce',
    'session',
    'threshold',
    'uiConfirm',
    'webauthnAuth',
    'workerManager',
  ],
  interfaces: ['stepUpConfirmation', 'nonce', 'session', 'threshold', 'uiConfirm', 'workerManager'],
  nonce: ['interfaces', 'session'],
  flows: [
    'chains',
    'stepUpConfirmation',
    'interfaces',
    'nonce',
    'session',
    'threshold',
    'uiConfirm',
    'webauthnAuth',
    'workerManager',
  ],
  session: [
    'stepUpConfirmation',
    'interfaces',
    'threshold',
    'uiConfirm',
    'webauthnAuth',
    'workerManager',
  ],
  threshold: ['chains', 'interfaces', 'session', 'webauthnAuth', 'workerManager'],
  uiConfirm: [
    'chains',
    'stepUpConfirmation',
    'interfaces',
    'nonce',
    'session',
    'threshold',
    'webauthnAuth',
    'workerManager',
  ],
  workerManager: [
    'chains',
    'stepUpConfirmation',
    'interfaces',
    'nonce',
    'session',
    'threshold',
    'uiConfirm',
    'webauthnAuth',
  ],
  workers: [],
} as const;

const existingIndexFiles = [
  'client/src/core/signingEngine/index.ts',
  'client/src/core/signingEngine/interfaces/index.ts',
  'client/src/core/signingEngine/uiConfirm/ui/lit-components/Drawer/index.ts',
  'client/src/core/signingEngine/uiConfirm/ui/lit-components/HaloBorder/index.ts',
  'client/src/core/signingEngine/uiConfirm/ui/lit-components/PasskeyHaloLoading/index.ts',
  'client/src/core/signingEngine/uiConfirm/ui/lit-components/TxTree/index.ts',
] as const;

const deletedSigningEngineFolders = [
  'client/src/core/signingEngine/api/evmFamily',
  'client/src/core/signingEngine/api/thresholdLifecycle',
  'client/src/core/signingEngine/api',
  'client/src/core/signingEngine/bootstrap',
  'client/src/core/signingEngine/chainAdaptors',
  'client/src/core/signingEngine/orchestration',
  'client/src/core/signingEngine/signers',
  'client/src/core/signingEngine/signers/algorithms',
  'client/src/core/signingEngine/signers/wasm',
  'client/src/core/signingEngine/signers/webauthn',
  'client/src/core/signingEngine/webauthnAuth/cose',
  'client/src/core/signingEngine/sessionEmailOtp',
  'client/src/core/signingEngine/sessionsEmailOtp',
  'client/src/core/signingEngine/flows/emailOtp',
  'client/src/core/signingEngine/flows/passkey',
  'client/src/core/signingEngine/sessionPasskey',
  'client/src/core/signingEngine/sessionMagicLink',
  'client/src/core/signingEngine/sessionAuthenticatorOtp',
  'client/src/core/signingEngine/sessionPassword',
  'client/src/core/signingEngine/session/restore',
  'client/src/core/signingEngine/session/signingSession',
  'client/src/core/signingEngine/session/warmSigning',
  'client/src/core/signingEngine/touchConfirm',
  'client/src/core/signingEngine/uiConfirm/shared',
  'client/src/core/signingEngine/walletAuth',
] as const;

const deletedSigningEnginePaths = [
  'client/src/core/signingEngine/api/thresholdLifecycle/normalization.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaLoginPrefill.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore.ts',
  'client/src/core/signingEngine/bootstrap/managerAssembly.ts',
  'client/src/core/signingEngine/bootstrap/orchestrationDependencyFactory.ts',
  'client/src/core/signingEngine/bootstrap/runtimeBootstrap.ts',
  'client/src/core/signingEngine/bootstrap/workerResourceWarmup.ts',
  'client/src/core/signingEngine/api/session/signingSessionState.ts',
  'client/src/core/signingEngine/api/index.ts',
  'client/src/core/signingEngine/api/evmSigning.ts',
  'client/src/core/signingEngine/api/evmFamily/accountAuth.ts',
  'client/src/core/signingEngine/api/evmFamily/addresses.ts',
  'client/src/core/signingEngine/api/evmFamily/authPlanning.ts',
  'client/src/core/signingEngine/api/evmFamily/budgetSpending.ts',
  'client/src/core/signingEngine/api/evmFamily/ecdsaLanes.ts',
  'client/src/core/signingEngine/api/evmFamily/ecdsaSelection.ts',
  'client/src/core/signingEngine/api/evmFamily/emailOtpRefresh.ts',
  'client/src/core/signingEngine/api/evmFamily/errors.ts',
  'client/src/core/signingEngine/api/evmFamily/events.ts',
  'client/src/core/signingEngine/api/evmFamily/evmNonceLifecycle.ts',
  'client/src/core/signingEngine/api/evmFamily/ecdsaReadiness.ts',
  'client/src/core/signingEngine/api/evmFamily/freshEmailOtpRetry.ts',
  'client/src/core/signingEngine/api/evmFamily/nonceLifecycleAdapter.ts',
  'client/src/core/signingEngine/api/evmFamily/nonceMetrics.ts',
  'client/src/core/signingEngine/api/evmFamily/nonceResolution.ts',
  'client/src/core/signingEngine/api/evmFamily/operationIds.ts',
  'client/src/core/signingEngine/api/evmFamily/postSignPolicy.ts',
  'client/src/core/signingEngine/api/evmFamily/preparedSigning.ts',
  'client/src/core/signingEngine/api/evmFamily/signingFlowRuntime.ts',
  'client/src/core/signingEngine/api/evmFamily/signerLoader.ts',
  'client/src/core/signingEngine/api/evmFamily/tempoNonceLifecycle.ts',
  'client/src/core/signingEngine/api/evmFamily/transactionExecutor.ts',
  'client/src/core/signingEngine/api/evmFamily/types.ts',
  'client/src/core/signingEngine/api/evmFamily/warmSessionServices.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdCommitQueueShared.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaCommitQueue.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519CommitQueue.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdEd25519Lifecycle.ts',
  'client/src/core/signingEngine/api/thresholdLifecycle/thresholdSessionActivation.ts',
  'client/src/core/signingEngine/uiConfirm/intentDigestPreparationRegistry.ts',
  'client/src/core/signingEngine/uiConfirm/shared/displayModel.ts',
  'client/src/core/signingEngine/uiConfirm/shared/confirmCommon.ts',
  'client/src/core/signingEngine/uiConfirm/shared/confirmTypes.ts',
  'client/src/core/signingEngine/uiConfirm/shared/forbiddenMainThreadSecrets.typecheck.ts',
  'client/src/core/signingEngine/uiConfirm/shared/normalization.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/calldata.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/evmTx.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/functionSelectors.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/gas.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/model.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/nearTx.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/normalization.ts',
  'client/src/core/signingEngine/stepUpConfirmation/display/tempoTx.ts',
  'client/src/core/signingEngine/api/nearSigning.ts',
  'client/src/core/signingEngine/api/tempoSigning.ts',
  'client/src/core/signingEngine/api/recovery/privateKeyExportRecovery.ts',
  'client/src/core/signingEngine/api/registration/registrationAccountLifecycle.ts',
  'client/src/core/signingEngine/api/registration/registrationSession.ts',
  'client/src/core/signingEngine/api/session/emailOtpDeviceEnrollmentEscrowStore.ts',
  'client/src/core/signingEngine/api/userPreferences.ts',
  'client/src/core/signingEngine/flows/signEvmFamily/runtimeCommandExecutor.ts',
  'client/src/core/signingEngine/chainAdaptors/near/index.ts',
  'client/src/core/signingEngine/chainAdaptors/near/nearAdapter.ts',
  'client/src/core/signingEngine/signers/algorithms/ed25519.ts',
  'client/src/core/signingEngine/otpSessions/authLane.ts',
  'client/src/core/signingEngine/otpSessions/EmailOtpThresholdSessionCoordinator.ts',
  'client/src/core/signingEngine/otpSessions/README.md',
  'client/src/core/signingEngine/sessionsEmailOtp/authLane.ts',
  'client/src/core/signingEngine/sessionsEmailOtp/EmailOtpThresholdSessionCoordinator.ts',
  'client/src/core/signingEngine/sessionsEmailOtp/README.md',
  'client/src/core/signingEngine/flows/emailOtp/ecdsaSigningSession.ts',
  'client/src/core/signingEngine/flows/emailOtp/ed25519LocalMetadata.ts',
  'client/src/core/signingEngine/stepUpConfirmation/warmSessionUiConfirm.ts',
  'client/src/core/signingEngine/stepUpConfirmation/passkeyPrompt/webauthnKeyRef.ts',
  'client/src/core/signingEngine/webauthnAuth/cose/coseP256.ts',
  'client/src/core/signingEngine/session/operationState/budget.ts',
  'client/src/core/signingEngine/session/operationState/budgetFinalizer.ts',
  'client/src/core/signingEngine/session/operationState/budgetProjection.ts',
  'client/src/core/signingEngine/session/operationState/budgetStatusReader.ts',
  'client/src/core/signingEngine/session/operationState/planner.ts',
  'client/src/core/signingEngine/session/operationState/operationFingerprint.ts',
  'client/src/core/signingEngine/session/operationState/operationIdBinding.ts',
  'client/src/core/signingEngine/chainAdaptors/evm/bytes.ts',
  'client/src/core/signingEngine/chainAdaptors/evm/evmAdapter.ts',
  'client/src/core/signingEngine/chainAdaptors/evm/index.ts',
  'client/src/core/signingEngine/chainAdaptors/evm/types.ts',
  'client/src/core/signingEngine/chainAdaptors/index.ts',
  'client/src/core/signingEngine/chainAdaptors/tempo/feeToken.ts',
  'client/src/core/signingEngine/chainAdaptors/tempo/index.ts',
  'client/src/core/signingEngine/chainAdaptors/tempo/tempoAdapter.ts',
  'client/src/core/signingEngine/chainAdaptors/tempo/types.ts',
  'client/src/core/signingEngine/orchestration/executeSigningIntent.ts',
  'client/src/core/signingEngine/orchestration/evm/evmSigningFlow.ts',
  'client/src/core/signingEngine/orchestration/evm/index.ts',
  'client/src/core/signingEngine/orchestration/near/delegateFlow.ts',
  'client/src/core/signingEngine/orchestration/near/index.ts',
  'client/src/core/signingEngine/orchestration/near/nearSigningFlow.ts',
  'client/src/core/signingEngine/orchestration/near/nep413Flow.ts',
  'client/src/core/signingEngine/orchestration/near/shared/ensureThresholdEd25519HssClientBase.ts',
  'client/src/core/signingEngine/orchestration/near/shared/repairThresholdEd25519MissingRelayerKey.ts',
  'client/src/core/signingEngine/orchestration/near/shared/signingMaterials.ts',
  'client/src/core/signingEngine/orchestration/near/shared/thresholdAuthMode.ts',
  'client/src/core/signingEngine/orchestration/near/shared/thresholdSessionAuth.ts',
  'client/src/core/signingEngine/orchestration/near/shared/workerRequestAssembly.ts',
  'client/src/core/signingEngine/orchestration/near/transactionsFlow.ts',
  'client/src/core/signingEngine/flows/signNear/shared/ensureThresholdEd25519HssClientBase.ts',
  'client/src/core/signingEngine/flows/signNear/shared/repairThresholdEd25519MissingRelayerKey.ts',
  'client/src/core/signingEngine/flows/signNear/shared/runNearSigningCommand.ts',
  'client/src/core/signingEngine/uiConfirm/shared/emailOtpPromptCopy.ts',
  'client/src/core/signingEngine/orchestration/shared/thresholdEcdsaTransactionAdmission.ts',
  'client/src/core/signingEngine/orchestration/shared/evmFamilySigningFlow.ts',
  'client/src/core/signingEngine/orchestration/shared/thresholdSigningSessionReadiness.ts',
  'client/src/core/signingEngine/orchestration/shared/touchConfirmSigning.ts',
  'client/src/core/signingEngine/flows/shared/touchConfirmSigning.ts',
  'client/src/core/signingEngine/orchestration/thresholdActivation.ts',
  'client/src/core/signingEngine/orchestration/tempo/index.ts',
  'client/src/core/signingEngine/orchestration/tempo/tempoSigningFlow.ts',
  'client/src/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator.ts',
  'client/src/core/signingEngine/orchestration/walletOrigin/webauthnKeyRef.ts',
  'client/src/core/signingEngine/session/operationState/execution.ts',
  'client/src/core/signingEngine/session/operationState/ecdsaChainTarget.ts',
  'client/src/core/signingEngine/session/operationState/readiness.ts',
  'client/src/core/signingEngine/session/identity.ts',
  'client/src/core/signingEngine/session/selectLane.ts',
  'client/src/core/signingEngine/session/availableSigningLanes.ts',
  'client/src/core/signingEngine/session/persistedAvailableSigningLanes.ts',
  'client/src/core/signingEngine/session/readiness.ts',
  'client/src/core/signingEngine/session/records.ts',
  'client/src/core/signingEngine/session/sealedSessionStore.ts',
  'client/src/core/signingEngine/session/restoreCoordinator.ts',
  'client/src/core/signingEngine/session/availability/availableSigningLanesReader.ts',
  'client/src/core/signingEngine/session/snapshot.ts',
  'client/src/core/signingEngine/session/snapshotReader.ts',
  'client/src/core/signingEngine/session/persistedSigningSessionSnapshot.ts',
  'client/src/core/signingEngine/signers/algorithms/index.ts',
  'client/src/core/signingEngine/signers/algorithms/secp256k1.ts',
  'client/src/core/signingEngine/signers/algorithms/webauthnP256.ts',
  'client/src/core/signingEngine/signers/index.ts',
  'client/src/core/signingEngine/signers/wasm/ethSignerWasm.ts',
  'client/src/core/signingEngine/signers/wasm/hssClientSignerWasm.ts',
  'client/src/core/signingEngine/signers/wasm/index.ts',
  'client/src/core/signingEngine/signers/wasm/nearSignerWasm.ts',
  'client/src/core/signingEngine/signers/wasm/tempoSignerWasm.ts',
  'client/src/core/signingEngine/signers/webauthn/cose/coseP256.ts',
  'client/src/core/signingEngine/signers/webauthn/cose/index.ts',
  'client/src/core/signingEngine/signers/webauthn/credentials/collectAuthenticationCredentialForChallengeB64u.ts',
  'client/src/core/signingEngine/signers/webauthn/credentials/credentialExtensions.ts',
  'client/src/core/signingEngine/signers/webauthn/credentials/helpers.ts',
  'client/src/core/signingEngine/signers/webauthn/credentials/index.ts',
  'client/src/core/signingEngine/signers/webauthn/device/signerSlot.ts',
  'client/src/core/signingEngine/signers/webauthn/device/index.ts',
  'client/src/core/signingEngine/signers/webauthn/fallbacks/safari-fallbacks.ts',
  'client/src/core/signingEngine/signers/webauthn/fallbacks/index.ts',
  'client/src/core/signingEngine/signers/webauthn/index.ts',
  'client/src/core/signingEngine/signers/webauthn/prompt/touchIdPrompt.ts',
  'client/src/core/signingEngine/signers/webauthn/prompt/index.ts',
  'client/src/core/signingEngine/threshold/session/ed25519AuthSession.ts',
  'client/src/core/signingEngine/threshold/session/ed25519RelayerHealth.ts',
  'client/src/core/signingEngine/threshold/session/ed25519SessionTypes.ts',
  'client/src/core/signingEngine/threshold/session/sessionPolicy.ts',
  'client/src/core/signingEngine/threshold/workflows/authorizeEcdsa.ts',
  'client/src/core/signingEngine/threshold/workflows/bootstrapEcdsaSession.ts',
  'client/src/core/signingEngine/threshold/workflows/connectEcdsaSession.ts',
  'client/src/core/signingEngine/threshold/workflows/connectEd25519Session.ts',
  'client/src/core/signingEngine/threshold/workflows/httpRequest.ts',
  'client/src/core/signingEngine/threshold/workflows/keygenEcdsa.ts',
  'client/src/core/signingEngine/threshold/workflows/signEcdsa.ts',
  'client/src/core/signingEngine/threshold/workflows/thresholdClientSecretSource.ts',
  'client/src/core/signingEngine/threshold/workflows/thresholdEcdsaHssTransport.ts',
  'client/src/core/signingEngine/threshold/ecdsa/sessionActivation.ts',
  'client/src/core/signingEngine/threshold/ed25519WrapKeySalt.ts',
  'client/src/core/signingEngine/threshold/prfSalts.ts',
  'client/src/core/signingEngine/threshold/webauthn.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/calldata.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/evmTx.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/functionSelectors.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/gas.ts',
  'client/src/core/signingEngine/uiConfirm/index.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/nearTx.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/normalization.ts',
  'client/src/core/signingEngine/uiConfirm/displayFormat/tempoTx.ts',
  'client/src/core/signingEngine/workerManager/index.ts',
  'client/src/core/signingEngine/workerManager/nearKeyOps/index.ts',
] as const;

function readRepoSource(relativePath: string): string {
  return fs.readFileSync(path.join(repoRoot, relativePath), 'utf8');
}

function extractMethodBlock(source: string, signatureFragment: string): string {
  const signatureIndex = source.indexOf(signatureFragment);
  expect(signatureIndex, `expected method signature: ${signatureFragment}`).toBeGreaterThanOrEqual(
    0,
  );

  const bodyStart = source.indexOf('{', signatureIndex);
  expect(bodyStart, `expected method body start: ${signatureFragment}`).toBeGreaterThanOrEqual(0);

  let depth = 0;
  for (let index = bodyStart; index < source.length; index += 1) {
    const char = source[index];
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) {
        return source.slice(signatureIndex, index + 1);
      }
    }
  }

  throw new Error(`Could not extract method block for signature: ${signatureFragment}`);
}

function listProductionTypeScriptFiles(dir: string): string[] {
  if (!fs.existsSync(dir)) return [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...listProductionTypeScriptFiles(fullPath));
      continue;
    }
    if (entry.isFile() && fullPath.endsWith('.ts')) {
      files.push(path.relative(repoRoot, fullPath));
    }
  }
  return files;
}

function isTypeFixture(relativePath: string): boolean {
  return relativePath.endsWith('.typecheck.ts');
}

function extractImportSpecifiers(source: string): string[] {
  return Array.from(
    source.matchAll(/\bfrom\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)/g),
  )
    .map((match) => match[1] || match[2])
    .filter(Boolean);
}

function resolveSigningEngineImport(fromRelativePath: string, specifier: string): string | null {
  if (specifier.startsWith('@/core/signingEngine/')) {
    return `client/src/core/signingEngine/${specifier.slice('@/core/signingEngine/'.length)}`;
  }
  if (specifier === '@/core/signingEngine') {
    return 'client/src/core/signingEngine';
  }
  if (!specifier.startsWith('.')) return null;

  const resolved = path.resolve(path.join(repoRoot, path.dirname(fromRelativePath)), specifier);
  const relative = path.relative(repoRoot, resolved).replaceAll(path.sep, '/');
  if (!relative.startsWith('client/src/core/signingEngine')) return null;
  return relative;
}

function signingEngineTopLevel(relativePath: string): string | null {
  const prefix = 'client/src/core/signingEngine/';
  if (!relativePath.startsWith(prefix)) return null;
  const first = relativePath.slice(prefix.length).split('/')[0] || null;
  if (first === 'SigningEngine') return 'SigningEngine.ts';
  if (first === 'index') return 'index.ts';
  return first;
}

function sliceTypeAlias(source: string, name: string): string {
  const start = source.indexOf(`export type ${name}`);
  if (start < 0) throw new Error(`missing exported type ${name}`);
  const next = source.indexOf('\nexport type ', start + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

function stripNeverOptionalGuards(source: string): string {
  return source.replace(/\b\w+\?:\s*never;?/g, '');
}

function sliceClassMethod(source: string, name: string): string {
  const match = new RegExp(`\\n  async ${name}(?:<[^>]+>)?\\(`).exec(source);
  const start = match?.index;
  if (start === undefined) throw new Error(`missing method ${name}`);
  const next = source.indexOf('\n  async ', start + 1);
  return source.slice(start, next < 0 ? source.length : next);
}

function compactSource(source: string): string {
  return source
    .replace(/\s+/g, ' ')
    .replace(/\s+([(),;])/g, '$1')
    .replace(/\(\s+/g, '(')
    .replace(/\s+\)/g, ')')
    .replace(/,\)/g, ')');
}

test.describe('Refactor 33 signing-engine guardrails', () => {
  test('root README documents the Refactor 33 architecture', () => {
    const source = readRepoSource('client/src/core/signingEngine/README.md');

    expect(source).toContain('Refactor 33 layout');
    expect(source).toContain('## Import Direction');
    expect(source).toContain('## Operation Pipeline');
    expect(source).toContain('SelectedLane');
    expect(source).toContain('flows/signEvmFamily/signEvmFamily.ts');
    expect(source).toContain('flows/signNear/signNear.ts');
  });

  test('public signing facade methods delegate directly to operation modules', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const signNear = sliceClassMethod(source, 'signNear');
    const signTempo = sliceClassMethod(source, 'signTempo');

    expect(signNear).toContain(
      'return await signNearOperation(this.enginePorts.nearSigningDeps, request);',
    );
    expect(signTempo).toContain(
      'return await signTempoOperation(this.enginePorts.tempoSigningDeps, args);',
    );
    for (const method of [signNear, signTempo]) {
      expect(method).not.toContain('ensureSealedRefreshStartupParityForTransactionSigning');
      expect(method).not.toContain('evmFamilySigningTargetFromExplicitTarget');
    }
  });

  test('registration facade methods delegate through flows registration public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);

    expect(source).toContain("from './flows/registration/public';");
    expect(source).toContain('this.registrationPublicDeps = {');
    expect(compact).toContain(
      'return registrationPublic.storeUserData(this.registrationPublicDeps, userData);',
    );
    expect(compact).toContain(
      'return registrationPublic.requestRegistrationCredentialConfirmation(this.registrationPublicDeps, params);',
    );
    expect(compact).toContain(
      'return registrationPublic.getAuthenticationCredentialsSerialized(this.registrationPublicDeps, args);',
    );
    expect(compact).toContain(
      'return registrationPublic.extractCosePublicKey(this.registrationPublicDeps, attestationObjectBase64url);',
    );
    expect(source).not.toContain('storeUserDataValue(');
    expect(source).not.toContain('requestRegistrationCredentialConfirmationPublicValue(');
    expect(source).not.toContain('getAuthenticationCredentialsSerializedValue(');
  });

  test('recovery facade methods delegate through flows recovery public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);

    expect(source).toContain('this.recoveryPublicDeps = createRecoveryPublicDeps({');
    expect(compact).toContain(
      'return await recoveryPublic.exportKeypairWithUI(this.recoveryPublicDeps, input);',
    );
    expect(compact).toContain(
      'return recoveryPublic.exportNearEd25519SeedArtifactWithUI(this.recoveryPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await recoveryPublic.exportThresholdEd25519SeedFromHssReport(this.recoveryPublicDeps, args);',
    );
    expect(source).not.toContain('const laneSelection: ExportLaneSelectionDeps');
    expect(source).not.toContain('const deps: ExportKeypairWithUIDeps');
  });

  test('warm-session facade assembly is bound through assembly ports', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const warmSigningAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/ports/warmSigning.ts',
    );

    expect(source).toContain('type WarmSigningPorts,');
    expect(source).toContain("from './assembly/ports/warmSigning';");
    expect(source).toContain('this.warmSigning = createWarmSigningPorts({');
    expect(source).toContain('this.passkeyPublicDeps = createPasskeyPublicDeps({');
    expect(source).toContain('private readonly passkeyPublicDeps: PasskeyPublicDeps;');
    expect(source).toContain(
      'this.warmCapabilitiesPublicDeps = createWarmCapabilitiesPublicDeps({',
    );
    expect(source).toContain(
      'private readonly warmCapabilitiesPublicDeps: WarmCapabilitiesPublicDeps;',
    );
    expect(source).not.toContain('createWarmSessionStatusOnlyUiConfirm(');
    expect(source).not.toContain('createWarmSessionCapabilityReader(');
    expect(source).not.toContain('createWarmSessionStatusReader(');

    expect(warmSigningAssembly).toContain('createWarmSessionStatusOnlyUiConfirm');
    expect(warmSigningAssembly).toContain('createWarmSessionCapabilityReader');
    expect(warmSigningAssembly).toContain('createWarmSessionStatusReader');
    expect(warmSigningAssembly).toContain('export function createPasskeyPublicDeps');
    expect(warmSigningAssembly).toContain('export function createWarmCapabilitiesPublicDeps');
  });

  test('warm-session public methods delegate through session warm-signing public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);
    const warmSigningPublic = readRepoSource(
      'client/src/core/signingEngine/session/warmCapabilities/public.ts',
    );
    const passkeyPublic = readRepoSource('client/src/core/signingEngine/session/passkey/public.ts');

    expect(source).toContain("from './session/warmCapabilities/public';");
    expect(source).toContain("from './session/passkey/public';");
    expect(compact).toContain(
      'return await passkeyPublic.connectEd25519Session(this.passkeyPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await passkeyPublic.bootstrapEcdsaSession(this.passkeyPublicDeps, args);',
    );
    expect(compact).toContain(
      'return warmCapabilitiesPublic.persistThresholdEcdsaBootstrapForWalletTarget(this.warmCapabilitiesPublicDeps, args);',
    );
    expect(compact).toContain(
      'return warmCapabilitiesPublic.getWarmThresholdEd25519SessionStatus(this.warmCapabilitiesPublicDeps, toAccountId(nearAccountId));',
    );
    expect(source).toContain('return warmCapabilitiesPublic.getWarmThresholdEcdsaSessionStatus(');
    expect(source).toContain(
      'return warmCapabilitiesPublic.listWarmThresholdEcdsaSessionStatuses(',
    );
    expect(compact).toContain(
      'return await warmCapabilitiesPublic.scheduleThresholdEcdsaLoginPresignPrefill(this.warmCapabilitiesPublicDeps, args);',
    );
    expect(compact).toContain(
      'await warmCapabilitiesPublic.hydrateSigningSession(this.warmCapabilitiesPublicDeps, args);',
    );
    expect(compact).toContain(
      'await warmCapabilitiesPublic.clearVolatileWarmSigningMaterial(this.warmCapabilitiesPublicDeps, walletId);',
    );
    expect(source).not.toContain('return await provisionWarmEd25519Capability(');
    expect(source).not.toContain('return await bootstrapWarmEcdsaCapability(');

    expect(warmSigningPublic).toContain('export type WarmCapabilitiesPublicDeps');
    expect(warmSigningPublic).not.toContain('export async function connectEd25519Session');
    expect(warmSigningPublic).toContain(
      'export async function scheduleThresholdEcdsaLoginPresignPrefill',
    );
    expect(passkeyPublic).toContain('export type PasskeyPublicDeps');
    expect(passkeyPublic).toContain('export async function connectEd25519Session');
    expect(passkeyPublic).toContain('export async function bootstrapEcdsaSession');
  });

  test('step-up runtime assembly is bound through assembly ports', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const runtimeAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/ports/stepUpRuntime.ts',
    );

    expect(source).toContain("from './assembly/ports/stepUpRuntime';");
    expect(source).toContain('const stepUpRuntime = createStepUpRuntime({');
    expect(source).toContain('this.emailOtpSessions = stepUpRuntime.emailOtpSessions;');
    expect(source).toContain('this.touchConfirm = stepUpRuntime.touchConfirm;');
    expect(source).not.toContain('new EmailOtpThresholdSessionCoordinator({');
    expect(source).not.toContain('createWarmSessionAwareUiConfirm({');

    expect(runtimeAssembly).toContain('export function createStepUpRuntime');
    expect(runtimeAssembly).toContain('new EmailOtpThresholdSessionCoordinator({');
    expect(runtimeAssembly).toContain('createWarmSessionAwareUiConfirm({');
  });

  test('recovery facade assembly is bound through recovery ports', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);
    const recoveryAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/ports/recovery.ts',
    );

    expect(source).toContain("from './flows/recovery/public';");
    expect(source).toContain(
      "import { createRecoveryPublicDeps } from './assembly/ports/recovery';",
    );
    expect(source).toContain('this.recoveryPublicDeps = createRecoveryPublicDeps({');
    expect(compact).toContain(
      'return await recoveryPublic.exportKeypairWithUI(this.recoveryPublicDeps, input);',
    );
    expect(recoveryAssembly).toContain('export function createRecoveryPublicDeps');
    expect(recoveryAssembly).toContain('readPersistedAvailableSigningLanes');
    expect(recoveryAssembly).toContain('readPersistedAvailableSigningLanesForTargets');
  });

  test('session facade methods delegate through session public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);
    const sessionAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/ports/session.ts',
    );

    expect(source).toContain('SessionPublicDeps,');
    expect(source).toContain("from './session/public';");
    expect(source).toContain("import { createSessionPublicDeps } from './assembly/ports/session';");
    expect(source).toContain('this.sessionPublicDeps = createSessionPublicDeps({');
    expect(source).toContain('private readonly sessionPublicDeps: SessionPublicDeps;');
    expect(compact).toContain(
      'return await sessionPublic.restorePersistedSessionsForWallet(this.sessionPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await sessionPublic.readPersistedAvailableSigningLanes(this.sessionPublicDeps, args);',
    );
    expect(source).not.toContain('this.emailOtpSessions.restorePersistedSessionsForWallet({');
    expect(source).not.toContain('this.touchConfirm.restorePersistedSessionsForWallet?.({');

    expect(sessionAssembly).toContain('export function createSessionPublicDeps');
    expect(sessionAssembly).toContain('configuredThresholdEcdsaChainTargets');
    expect(sessionAssembly).toContain('restorePersistedSessionsForWallet');
  });

  test('session ECDSA record admin facade methods delegate through session public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);
    const sessionPublic = readRepoSource('client/src/core/signingEngine/session/public.ts');
    const upsertMethod = extractMethodBlock(source, 'upsertThresholdEcdsaSessionFromBootstrap(');
    const keyRefMethod = extractMethodBlock(source, 'getThresholdEcdsaKeyRefForWalletTarget(');
    const listMethod = extractMethodBlock(
      source,
      'listThresholdEcdsaSessionRecordsForWalletTarget(',
    );
    const clearOneMethod = extractMethodBlock(source, 'clearThresholdEcdsaSessionRecordForWallet(');
    const clearAllMethod = extractMethodBlock(
      source,
      'clearAllThresholdEcdsaSessionRecords(): void',
    );

    expect(compact).toContain(
      'sessionPublic.upsertThresholdEcdsaSessionFromBootstrap(this.sessionPublicDeps, args);',
    );
    expect(compact).toContain(
      'return sessionPublic.getThresholdEcdsaKeyRefForWalletTarget(this.sessionPublicDeps, args);',
    );
    expect(compact).toContain(
      'return sessionPublic.listThresholdEcdsaSessionRecordsForWalletTarget(this.sessionPublicDeps, args);',
    );
    expect(compact).toContain(
      'sessionPublic.clearThresholdEcdsaSessionRecordForWallet(this.sessionPublicDeps, walletId);',
    );
    expect(source).toContain(
      'sessionPublic.clearAllThresholdEcdsaSessionRecords(this.sessionPublicDeps);',
    );
    expect(upsertMethod).not.toContain('upsertThresholdEcdsaSessionFromBootstrapValue(');
    expect(keyRefMethod).not.toContain('getThresholdEcdsaKeyRefByIdentityValue(');
    expect(listMethod).not.toContain('getThresholdEcdsaSessionRecordForTargetValue(');
    expect(clearOneMethod).not.toContain('clearThresholdEcdsaSessionRecordForWalletValue(');
    expect(clearAllMethod).not.toContain('clearAllThresholdEcdsaSessionRecordsValue(');

    expect(sessionPublic).toContain('export function upsertThresholdEcdsaSessionFromBootstrap');
    expect(sessionPublic).toContain('export function getThresholdEcdsaKeyRefForWalletTarget');
    expect(sessionPublic).toContain(
      'export function listThresholdEcdsaSessionRecordsForWalletTarget',
    );
    expect(sessionPublic).toContain('export function clearAllThresholdEcdsaSessionRecords');
  });

  test('Ed25519 HSS facade helpers delegate through threshold public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const thresholdPublic = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/public.ts',
    );

    expect(source).toContain("from './threshold/ed25519/public';");
    expect(source).toContain(
      'return thresholdEd25519Public.deriveThresholdEd25519ClientVerifyingShareFromCredential(',
    );
    expect(source).toContain(
      'return thresholdEd25519Public.prepareThresholdEd25519HssClientRequest(',
    );
    expect(source).toContain(
      'return thresholdEd25519Public.buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifact(',
    );
    expect(source).toContain(
      'return thresholdEd25519Public.buildThresholdEd25519SeedExportArtifactFromHssReport(',
    );
    expect(source).not.toContain("from './threshold/ed25519/hssLifecycle';");

    expect(thresholdPublic).toContain('export type ThresholdEd25519PublicDeps');
    expect(thresholdPublic).toContain('prepareThresholdEd25519HssClientRequestWasm');
    expect(thresholdPublic).toContain(
      'buildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactWasm',
    );
    expect(thresholdPublic).toContain('buildThresholdEd25519SeedExportArtifactFromHssReport');
  });

  test('Email OTP ECDSA facade helpers delegate through flow public entrypoints', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const compact = compactSource(source);
    const emailOtpPublic = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/emailOtpPublic.ts',
    );
    const emailOtpAssembly = readRepoSource(
      'client/src/core/signingEngine/assembly/ports/emailOtp.ts',
    );

    expect(source).toContain("from './flows/signEvmFamily/emailOtpPublic';");
    expect(source).not.toContain(
      "import { createEmailOtpPublicDeps } from './assembly/ports/emailOtp';",
    );
    expect(source).toContain('this.emailOtpPublicDeps = {');
    expect(source).toContain('private readonly emailOtpPublicDeps: EmailOtpPublicDeps;');
    expect(compact).toContain(
      'return await emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal(this.emailOtpPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await emailOtpPublic.requestEmailOtpSigningSessionChallenge(this.emailOtpPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await emailOtpPublic.refreshEmailOtpSigningSession(this.emailOtpPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await emailOtpPublic.enrollEmailOtpInternal(this.emailOtpPublicDeps, args);',
    );
    expect(compact).toContain(
      'return await emailOtpPublic.enrollAndLoginWithEmailOtpEcdsaCapabilityInternal(this.emailOtpPublicDeps, args);',
    );
    expect(source).not.toContain("from './flows/signEvmFamily/emailOtpSigningSession';");
    expect(source).not.toContain("from '../SeamsPasskey/emailOtp';");

    expect(emailOtpPublic).toContain('export type EmailOtpPublicDeps');
    expect(emailOtpPublic).toContain('requestEmailOtpSigningSessionChallengeValue');
    expect(emailOtpPublic).toContain('refreshEmailOtpSigningSessionValue');
    expect(emailOtpPublic).toContain('enrollEmailOtpWallet');
    expect(emailOtpAssembly).not.toContain('export function createEmailOtpPublicDeps');
  });

  test('folder ownership README template exists', () => {
    const source = readRepoSource('docs/refactor-33-folder-readme-template.md');

    for (const heading of ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints']) {
      expect(source).toContain(heading);
    }
  });

  test('session child domains declare ownership READMEs', () => {
    for (const relativePath of [
      'client/src/core/signingEngine/session/identity/README.md',
      'client/src/core/signingEngine/session/availability/README.md',
      'client/src/core/signingEngine/session/persistence/README.md',
      'client/src/core/signingEngine/session/sealedRecovery/README.md',
      'client/src/core/signingEngine/session/warmCapabilities/README.md',
      'client/src/core/signingEngine/session/passkey/README.md',
      'client/src/core/signingEngine/session/emailOtp/README.md',
      'client/src/core/signingEngine/session/operationState/README.md',
      'client/src/core/signingEngine/session/budget/README.md',
      'client/src/core/signingEngine/session/planning/README.md',
    ]) {
      const source = readRepoSource(relativePath);
      for (const heading of ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints']) {
        expect(source, relativePath).toContain(heading);
      }
    }
  });

  test('new target top-level folders must declare ownership before use', () => {
    for (const folder of targetTopLevelFolders) {
      const folderPath = path.join(signingEngineRoot, folder);
      if (!fs.existsSync(folderPath)) continue;

      const readmePath = path.join(folderPath, 'README.md');
      expect(fs.existsSync(readmePath), `${folder}/README.md`).toBe(true);
      const source = fs.readFileSync(readmePath, 'utf8');
      for (const heading of ['## Owns', '## May Import', '## Must Not Import', '## Entrypoints']) {
        expect(source, `${folder}/README.md`).toContain(heading);
      }
    }
  });

  test('no new signing-engine index barrels appear during the refactor', () => {
    const current = listProductionTypeScriptFiles(signingEngineRoot)
      .filter((relativePath) => relativePath.endsWith('/index.ts'))
      .sort();

    expect(current).toEqual([...existingIndexFiles].sort());
  });

  test('deleted signing-engine paths stay deleted', () => {
    for (const relativePath of deletedSigningEnginePaths) {
      expect(fs.existsSync(path.join(repoRoot, relativePath)), relativePath).toBe(false);
    }
    for (const relativePath of deletedSigningEngineFolders) {
      expect(fs.existsSync(path.join(repoRoot, relativePath)), relativePath).toBe(false);
    }

    const offenders: string[] = [];
    const deletedWithExtension: readonly string[] = deletedSigningEnginePaths;
    const deletedWithoutExtension: readonly string[] = deletedSigningEnginePaths.map(
      (relativePath) => relativePath.replace(/\.ts$/, ''),
    );
    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'client/src'))) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (
          resolved &&
          (deletedWithoutExtension.includes(resolved) ||
            deletedWithExtension.includes(`${resolved}.ts`))
        ) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    for (const configPath of ['sdk/rolldown.config.ts', 'sdk/build-paths.sh'] as const) {
      const configSource = readRepoSource(configPath);
      for (const relativePath of [...deletedSigningEngineFolders, ...deletedSigningEnginePaths]) {
        const buildRelativePath = relativePath.replace(/^client\/src\//, '../client/src/');
        expect(configSource, `${configPath} references ${relativePath}`).not.toContain(
          relativePath,
        );
        expect(configSource, `${configPath} references ${buildRelativePath}`).not.toContain(
          buildRelativePath,
        );
      }
    }

    expect(offenders).toEqual([]);
  });

  test('top-level folders do not exceed the documented current import contract', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const sourceTopLevel = signingEngineTopLevel(relativePath);
      if (!sourceTopLevel) continue;
      const allowed = currentTopLevelImportContract[sourceTopLevel];
      if (!allowed) {
        offenders.push(`${relativePath} has no import-contract row`);
        continue;
      }

      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) continue;
        const targetTopLevel = signingEngineTopLevel(resolved);
        if (!targetTopLevel || targetTopLevel === sourceTopLevel) continue;
        if (!allowed.includes(targetTopLevel)) {
          offenders.push(
            `${relativePath} -> ${specifier} (${sourceTopLevel} -> ${targetTopLevel})`,
          );
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('SigningEngine.ts imports stay within the documented facade-owned allowlist', () => {
    const source = readRepoSource('client/src/core/signingEngine/SigningEngine.ts');
    const offenders: string[] = [];

    for (const specifier of extractImportSpecifiers(source)) {
      if (!specifier.startsWith('./')) continue;
      if (
        !signingEngineAllowedImportPrefixes.some((allowedPrefix) =>
          specifier.startsWith(allowedPrefix),
        )
      ) {
        offenders.push(specifier);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('target child folders do not import target flows modules', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const sourceTopLevel = signingEngineTopLevel(relativePath);
      if (!sourceTopLevel || !targetTopLevelFolders.includes(sourceTopLevel as never)) continue;
      if (sourceTopLevel === 'assembly' || sourceTopLevel === 'flows') continue;

      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (resolved?.startsWith('client/src/core/signingEngine/flows')) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('session child domains avoid flow and assembly imports', () => {
    const domains = [
      'client/src/core/signingEngine/session/identity',
      'client/src/core/signingEngine/session/availability',
      'client/src/core/signingEngine/session/planning',
      'client/src/core/signingEngine/session/budget',
      'client/src/core/signingEngine/session/persistence',
      'client/src/core/signingEngine/session/sealedRecovery',
      'client/src/core/signingEngine/session/operationState',
      'client/src/core/signingEngine/session/warmCapabilities',
      'client/src/core/signingEngine/session/passkey',
      'client/src/core/signingEngine/session/emailOtp',
    ] as const;
    const forbiddenMarkers = [
      '/flows/',
      '/assembly/',
      "from './SigningEngine'",
      "from '../SigningEngine'",
      "from '@/core/signingEngine/SigningEngine'",
    ] as const;
    const offenders: string[] = [];

    for (const domain of domains) {
      for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, domain))) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenMarkers) {
          if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('sealedRecovery stays free of method folders, flows, assembly, and SigningEngine.ts', () => {
    const domainRoot = path.join(repoRoot, 'client/src/core/signingEngine/session/sealedRecovery');
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) continue;
        if (
          resolved.startsWith('client/src/core/signingEngine/session/passkey/') ||
          resolved.startsWith('client/src/core/signingEngine/session/emailOtp/') ||
          resolved.startsWith('client/src/core/signingEngine/flows/') ||
          resolved.startsWith('client/src/core/signingEngine/assembly/') ||
          resolved === 'client/src/core/signingEngine/SigningEngine'
        ) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('session child domains only use allowed sibling domains', () => {
    const allowedSiblingDomains: Record<string, readonly string[]> = {
      identity: ['availability', 'operationState', 'persistence'],
      availability: [
        'identity',
        'operationState',
        'persistence',
        'warmCapabilities',
        'budget',
        'planning',
        'sealedRecovery',
      ],
      planning: ['operationState'],
      budget: ['persistence', 'operationState', 'identity'],
      persistence: ['identity', 'sealedRecovery', 'operationState'],
      sealedRecovery: ['persistence'],
      operationState: ['identity', 'persistence', 'budget', 'planning', 'emailOtp'],
      warmCapabilities: ['availability', 'identity', 'persistence', 'operationState', 'budget'],
      passkey: ['identity', 'persistence', 'operationState', 'sealedRecovery', 'warmCapabilities'],
      emailOtp: [
        'availability',
        'budget',
        'identity',
        'operationState',
        'persistence',
        'sealedRecovery',
        'warmCapabilities',
      ],
    };
    const offenders: string[] = [];

    for (const [sourceDomain, allowedTargets] of Object.entries(allowedSiblingDomains)) {
      const domainRoot = path.join(
        repoRoot,
        `client/src/core/signingEngine/session/${sourceDomain}`,
      );

      for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
        if (isTypeFixture(relativePath)) continue;
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;

          const tail = resolved.slice('client/src/core/signingEngine/session/'.length);
          const targetDomain = tail.split('/')[0];
          if (!targetDomain || targetDomain === sourceDomain) continue;
          if (targetDomain === 'public.ts') continue;
          if (!allowedTargets.includes(targetDomain)) {
            offenders.push(`${relativePath} -> ${specifier} (${sourceDomain} -> ${targetDomain})`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('child session domains do not import session/SigningSessionCoordinator.ts', () => {
    const childDomains = [
      'identity',
      'availability',
      'planning',
      'budget',
      'persistence',
      'sealedRecovery',
      'operationState',
      'warmCapabilities',
      'passkey',
      'emailOtp',
    ] as const;
    const coordinatorPath = 'client/src/core/signingEngine/session/SigningSessionCoordinator.ts';
    const offenders: string[] = [];

    for (const domain of childDomains) {
      const domainRoot = path.join(repoRoot, `client/src/core/signingEngine/session/${domain}`);
      for (const relativePath of listProductionTypeScriptFiles(domainRoot)) {
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (resolved === coordinatorPath.replace(/\.ts$/, '')) {
            offenders.push(`${relativePath} -> ${specifier}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('SigningSessionCoordinator.ts stays free of method-specific session domains', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
    );
    const offenders: string[] = [];

    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(
        'client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
        specifier,
      );
      if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
      if (
        resolved.startsWith('client/src/core/signingEngine/session/passkey/') ||
        resolved.startsWith('client/src/core/signingEngine/session/emailOtp/')
      ) {
        offenders.push(`${specifier} -> ${resolved}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('SigningSessionCoordinator.ts only imports orchestration session domains', () => {
    const relativePath = 'client/src/core/signingEngine/session/SigningSessionCoordinator.ts';
    const source = readRepoSource(relativePath);
    const allowedSessionDomains = new Set([
      'planning',
      'availability',
      'budget',
      'persistence',
      'operationState',
      'warmCapabilities',
    ]);
    const offenders: string[] = [];

    for (const specifier of extractImportSpecifiers(source)) {
      const resolved = resolveSigningEngineImport(relativePath, specifier);
      if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
      const tail = resolved.slice('client/src/core/signingEngine/session/'.length);
      const targetDomain = tail.split('/')[0];
      if (!targetDomain || targetDomain === 'SigningSessionCoordinator.ts') continue;
      if (targetDomain === 'public.ts') continue;
      if (!allowedSessionDomains.has(targetDomain)) {
        offenders.push(`${specifier} -> ${resolved}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('signing flows only import session/SigningSessionCoordinator.ts as a session coordinator', () => {
    const offenders: string[] = [];
    const allowedCoordinatorPrefix =
      'client/src/core/signingEngine/session/SigningSessionCoordinator';

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved?.startsWith('client/src/core/signingEngine/session/')) continue;
        if (!resolved.includes('Coordinator')) continue;
        if (
          resolved !== allowedCoordinatorPrefix &&
          resolved !== `${allowedCoordinatorPrefix}.ts`
        ) {
          offenders.push(`${relativePath} -> ${specifier} -> ${resolved}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('shared signing state machine owns the signing operation runner', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/flows/shared/signingStateMachine.ts',
    );
    const ports = readRepoSource('client/src/core/signingEngine/flows/shared/operationPorts.ts');

    expect(source).toContain('export async function runSigningOperationSteps');
    expect(source).toContain('export async function runUnplannedSigningOperationCommandSequence');
    expect(source).toContain('export function buildSigningPostSignOperationSteps');
    expect(source).toContain('export type SigningOperationPlan');
    expect(source).toContain('preparedOperation: PreparedOperation | null;');
    expect(source).toContain('commands: SigningOperationCommandSequence;');
    expect(source).toContain("event: 'signing_operation_transition'");
    expect(source).toContain("ConnectThreshold: 'connectThreshold'");
    expect(source).toContain("PreparePayload: 'preparePayload'");
    expect(source).toContain("lane: SigningSessionPlan['lane'];");
    expect(source).toContain('lane: plan.lane');
    expect(source).toContain("from '../../session/operationState/types'");
    expect(source).toContain("from './operationPorts'");
    expect(ports).toContain('export type OperationCommandExecutor<TCommand>');
    expect(ports).toContain('export type OperationTransitionObserver<TTransitionEvent>');
    expect(source).not.toContain('plan?: SigningSessionPlan');
    expect(source).not.toContain('SigningExecution');
    expect(source).not.toContain('ReconnectThreshold');
    expect(source).not.toContain('PrepareNonce');
    expect(source).not.toContain('ThresholdReconnected');
    expect(source).not.toContain('NonceReady');
    expect(source).not.toContain('signing_execution_transition');
    expect(source).not.toMatch(/from ['"][.\/]+api\//);
    expect(source).not.toMatch(/from ['"][.\/]+orchestration\//);
    expect(source).not.toMatch(/from ['"][.\/]+chains\//);
  });

  test('EVM-family runtime command tracing uses the shared machine port directly', () => {
    const runtime = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlowRuntime.ts',
    );
    const uiConfirmFlow = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
    );
    const evmFamilyOperation = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmFamily.ts',
    );
    const stateMachine = readRepoSource(
      'client/src/core/signingEngine/flows/shared/signingStateMachine.ts',
    );

    expect(runtime).toContain('runSigningOperationCommandTrace');
    expect(runtime).toContain("from '../shared/signingStateMachine'");
    expect(uiConfirmFlow).toContain('runSharedSigningCommandSequence');
    expect(uiConfirmFlow).toContain('createSigningOperationPlan');
    expect(uiConfirmFlow).toContain('buildSigningOperationCommandSteps');
    expect(uiConfirmFlow).toContain('runSigningOperationCommandSteps');
    expect(uiConfirmFlow).toContain('runUnplannedSigningOperationCommandSequence');
    expect(uiConfirmFlow).toContain('SigningOperationCommandKind.ShowConfirmation');
    expect(uiConfirmFlow).toContain('SigningOperationCommandKind.PreparePayload');
    expect(uiConfirmFlow).toContain('SigningOperationCommandKind.ReserveBudget');
    expect(uiConfirmFlow).toContain('SigningOperationCommandKind.Sign');
    expect(evmFamilyOperation).toContain('signingOperation: createTransactionSigningOperation()');
    expect(evmFamilyOperation).toContain(
      'onSigningOperationTransition: emitEvmFamilySigningOperationTrace',
    );
    expect(runtime).not.toContain("from '../passkey/runtimeCommandExecutor'");
    expect(runtime).not.toContain('function executeEvmFamilyRuntimeCommand');
    expect(runtime).not.toContain('function wrapEmailOtpSigningWithRuntimeCommands');
    expect(uiConfirmFlow).not.toContain('for (const command of commands)');
    expect(stateMachine).toContain('export async function runSigningOperationCommandTrace');
    expect(stateMachine).toContain('export async function runSigningOperationCommandSteps');
    expect(stateMachine).toContain('export function buildSigningOperationCommandSteps');
    expect(stateMachine).toContain('createSigningOperationCommandTraceEvent');
    expect(stateMachine).not.toMatch(/from ['"][.\/]+api\//);
    expect(stateMachine).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('NEAR signing flows use shared machine command steps', () => {
    const transactionFlow = readRepoSource(
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const delegateFlow = readRepoSource(
      'client/src/core/signingEngine/flows/signNear/signDelegate.ts',
    );
    const nep413Flow = readRepoSource('client/src/core/signingEngine/flows/signNear/signNep413.ts');
    const commandRunner = readRepoSource(
      'client/src/core/signingEngine/flows/shared/signingStateMachine.ts',
    );
    const sharedConfirmation = readRepoSource(
      'client/src/core/signingEngine/flows/shared/signingConfirmation.ts',
    );
    const nearPayloads = readRepoSource('client/src/core/signingEngine/chains/near/payloads.ts');
    const nearDisplay = readRepoSource('client/src/core/signingEngine/chains/near/display.ts');

    expect(commandRunner).toContain('createSigningOperationPlan');
    expect(commandRunner).toContain('buildSigningOperationCommandSteps');
    expect(commandRunner).toContain('runSigningOperationCommandSteps');
    expect(commandRunner).toContain('export async function runSigningOperationCommand');
    expect(sharedConfirmation).toContain('export async function runSigningConfirmationCommand');
    expect(sharedConfirmation).toContain('SigningOperationCommandKind.ShowConfirmation');
    expect(nearPayloads).toContain('export function buildNearTransactionSigningPayloads');
    expect(nearPayloads).toContain('export function buildNearDelegateSigningPayloads');
    expect(nearDisplay).toContain('export function buildNearDisplayModel');
    expect(nearDisplay).toContain("from '@/core/signingEngine/interfaces/display'");
    for (const flow of [transactionFlow, delegateFlow, nep413Flow]) {
      expect(flow).toContain('runSigningOperationCommand');
      expect(flow).toContain('runSigningConfirmationCommand');
      expect(flow).not.toContain('runNearSigningOperationCommand');
      expect(flow).toContain('SigningOperationCommandKind.PreparePayload');
      expect(flow).toContain('SigningOperationCommandKind.Sign');
      expect(flow).not.toContain('SigningOperationCommandKind.ShowConfirmation');
      expect(flow).not.toContain('confirmSigningOperation(');
      expect(flow).not.toContain('stepUpConfirmation/confirmOperation');
      expect(flow).not.toMatch(/from ['"][.\/]+api\//);
      expect(flow).not.toMatch(/from ['"][.\/]+orchestration\//);
    }
    expect(transactionFlow).toContain('SigningOperationCommandKind.ReserveBudget');
    expect(transactionFlow).toContain('BudgetAdmittedOperation<SelectedEd25519Lane>');
    expect(transactionFlow).toContain("from '../../chains/near/payloads'");
    expect(delegateFlow).toContain("from '../../chains/near/payloads'");
    expect(transactionFlow).not.toContain('NearEd25519TransactionLane');
    expect(transactionFlow).not.toContain('validateActionArgsWasm');
    expect(delegateFlow).not.toContain('validateActionArgsWasm');
    expect(transactionFlow).not.toContain('buildNearDisplayModel');
    expect(delegateFlow).not.toContain('buildNearDisplayModel');
    for (const flow of [delegateFlow, nep413Flow]) {
      expect(flow.indexOf('await resolveNearThresholdSigningAuthContext')).toBeGreaterThanOrEqual(
        0,
      );
      expect(flow.indexOf('await resolveNearSigningMaterials')).toBeGreaterThan(
        flow.indexOf('await resolveNearThresholdSigningAuthContext'),
      );
    }
  });

  test('available signing lanes own signing-session availability terminology', () => {
    const forbiddenMarkers = [
      'SigningSessionSnapshot',
      'readSigningSessionSnapshot',
      'session/snapshot',
      'snapshotReader',
      'persistedSigningSessionSnapshot',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    const availableLanesSource = readRepoSource(
      'client/src/core/signingEngine/session/availability/availableSigningLanes.ts',
    );
    const persistedAvailableLanesSource = readRepoSource(
      'client/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
    );

    expect(offenders).toEqual([]);
    expect(availableLanesSource).toContain('export type AvailableSigningLanes');
    expect(availableLanesSource).toContain('export async function readAvailableSigningLanes');
    expect(persistedAvailableLanesSource).toContain(
      'export async function readPersistedAvailableSigningLanes',
    );
  });

  test('confirmation shared contracts are owned outside uiConfirm runtime internals', () => {
    const confirmationTypes = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/types.ts',
    );
    const confirmationChannelTypes = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/channel/confirmTypes.ts',
    );
    const signingConfirmation = readRepoSource(
      'client/src/core/signingEngine/flows/shared/signingConfirmation.ts',
    );
    const confirmOperation = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/confirmOperation.ts',
    );
    const promptText = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/promptText.ts',
    );
    const signingPrompt = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/signingPrompt.ts',
    );
    const exportAuthorization = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization.ts',
    );
    const displayModel = readRepoSource('client/src/core/signingEngine/interfaces/display.ts');
    const intentDigestPreparation = readRepoSource(
      'client/src/core/signingEngine/stepUpConfirmation/intentDigestPreparation.ts',
    );
    const emailOtpCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/emailOtp/EmailOtpThresholdSessionCoordinator.ts',
    );

    expect(confirmationTypes).toContain('export const SigningAuthPlanKind');
    expect(confirmationTypes).toContain('export type SigningAuthPlan');
    expect(confirmationTypes).toContain('export interface EmailOtpConfirmPrompt');
    expect(confirmationTypes).toContain('export interface UserConfirmProgressEvent');
    expect(confirmationTypes).toContain('signingAuthModeFromSigningAuthPlan');
    expect(confirmOperation).toContain('export async function confirmSigningOperation');
    expect(confirmOperation).toContain('export type ConfirmIntentDigestSigningOperationRequest');
    expect(confirmOperation).toContain('export type ConfirmTransactionSigningOperationRequest');
    expect(promptText).toContain('export function formatEmailOtpSentText');
    expect(signingPrompt).toContain('export async function prepareEmailOtpSigningPrompt');
    expect(exportAuthorization).toContain(
      'export async function requestEmailOtpExportAuthorization',
    );
    expect(displayModel).toContain('export interface TxDisplayModel');
    expect(intentDigestPreparation).toContain('export function registerIntentDigestPreparation');
    expect(confirmationChannelTypes).toContain("from '../types'");
    expect(confirmationChannelTypes).not.toContain('export const SigningAuthPlanKind');
    expect(confirmationChannelTypes).not.toContain('export type SigningAuthPlan');
    expect(signingConfirmation).toContain(
      'export function createSigningConfirmationCommandHandler',
    );
    expect(signingConfirmation).toContain('export async function runSigningConfirmationCommand');
    expect(signingConfirmation).not.toContain('formatEmailOtpSentText');
    expect(signingConfirmation).not.toContain('touchConfirm/shared/emailOtpPromptCopy');
    expect(emailOtpCoordinator).toContain('async requestExportChallenge');
    expect(emailOtpCoordinator).not.toContain('requestExportAuthorization');
    expect(emailOtpCoordinator).not.toContain('requestUserConfirmation');
    expect(emailOtpCoordinator).not.toContain('UserConfirmationType');
    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      const isSharedConfirmation = relativePath.endsWith('flows/shared/signingConfirmation.ts');
      expect(source, relativePath).not.toContain('stepUpConfirmation/channel/confirmTypes');
      expect(source, relativePath).not.toContain('touchConfirm/shared/displayModel');
      expect(source, relativePath).not.toContain('touchConfirm/handlers/flowOrchestrator');
      expect(source, relativePath).not.toContain('touchConfirm/intentDigestPreparationRegistry');
      expect(source, relativePath).not.toContain('.orchestrateSigningConfirmation(');
      if (!isSharedConfirmation) {
        expect(source, relativePath).not.toContain('stepUpConfirmation/confirmOperation');
        expect(source, relativePath).not.toContain('confirmSigningOperation(');
      }
      expect(source, relativePath).not.toContain('formatEmailOtpSentText');
      expect(source, relativePath).not.toContain('Enter email code to sign');
      expect(source, relativePath).not.toContain('emailOtpSigning.prepare()');
    }
  });

  test('EVM-family post-sign finalization commands live under flows', () => {
    const transactionExecutor = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );
    const postSignFinalization = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/postSignFinalization.ts',
    );

    expect(transactionExecutor).toContain("from './postSignFinalization'");
    expect(transactionExecutor).toContain('export type EvmFamilyExecutorThresholdEcdsaState');
    expect(transactionExecutor).toContain("kind: 'prepared'");
    expect(transactionExecutor).toContain('lane: SelectedEcdsaLane');
    expect(transactionExecutor).toContain('thresholdOwnerAddress: `0x${string}`;');
    expect(transactionExecutor).not.toContain('thresholdEcdsaRecord?:');
    expect(transactionExecutor).not.toContain('thresholdEcdsaKeyRef?:');
    expect(transactionExecutor).not.toContain('ThresholdEcdsaSessionRecord');
    expect(transactionExecutor).not.toContain('ThresholdEcdsaSecp256k1KeyRef');
    expect(transactionExecutor).not.toContain('warmRecord');
    expect(transactionExecutor).not.toContain('emailOtpReauthRecord');
    expect(transactionExecutor).not.toContain('warmKeyRef');
    expect(transactionExecutor).not.toContain(
      'async function runSuccessfulEvmFamilyPostSignCommands',
    );
    expect(postSignFinalization).toContain(
      'export async function runSuccessfulEvmFamilyPostSignCommands',
    );
    expect(postSignFinalization).toContain('createSigningPostSignOperationPlan');
    expect(postSignFinalization).toContain('buildSigningPostSignOperationSteps');
    expect(postSignFinalization).toContain('runSigningOperationSteps');
    expect(postSignFinalization).not.toMatch(/from ['"][.\/]+api\//);
    expect(postSignFinalization).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('EVM-family threshold admission lives under flows', () => {
    const admission = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/thresholdAdmission.ts',
    );

    expect(admission).toContain('export type EvmFamilyThresholdEcdsaAdmissionMode');
    expect(admission).toContain(
      'export async function completeEvmFamilyThresholdEcdsaAdmissionAfterConfirmation',
    );
    expect(admission).not.toMatch(/from ['"][.\/]+api\//);
    expect(admission).not.toMatch(/from ['"][.\/]+orchestration\//);
  });

  test('operation modules do not import SigningEngine or assembly construction', () => {
    const offenders: string[] = [];
    const operationsRoot = path.join(signingEngineRoot, 'flows');

    for (const relativePath of listProductionTypeScriptFiles(operationsRoot)) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (
          resolved === 'client/src/core/signingEngine' ||
          resolved === 'client/src/core/signingEngine/SigningEngine' ||
          resolved === 'client/src/core/signingEngine/SigningEngine.ts' ||
          resolved?.startsWith('client/src/core/signingEngine/assembly')
        ) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('assembly createPorts stays a thin typed aggregator', () => {
    const aggregator = readRepoSource('client/src/core/signingEngine/assembly/createPorts.ts');
    const requiredFactories = [
      './ports/emailOtp',
      './ports/evmFamily',
      './ports/near',
      './ports/recovery',
      './ports/registration',
      './ports/shared',
    ];
    const operationSpecificMarkers = [
      'resolveThresholdEd25519SessionId',
      'getEmailOtpThresholdEcdsaKeyRefForSigning',
      'requestExportPrivateKeysWithUi',
      'extractCosePublicKey',
      'resolveAccountAuthMethodForSigning',
    ];

    for (const importPath of requiredFactories) {
      expect(aggregator).toContain(importPath);
    }
    for (const marker of operationSpecificMarkers) {
      expect(aggregator).not.toContain(marker);
    }
  });

  test('WebAuthn P-256 COSE decoding stays behind the eth signer WASM boundary', () => {
    const offenders: string[] = [];
    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      if (source.includes('webauthnAuth/cose')) offenders.push(relativePath);
      if (source.includes('coseP256PublicKeyToXY')) offenders.push(relativePath);
    }

    const keyRef = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/webauthnP256KeyRef.ts',
    );
    const ethSigner = readRepoSource('client/src/core/signingEngine/chains/evm/ethSignerWasm.ts');

    expect(offenders).toEqual([]);
    expect(keyRef).toContain('decodeCoseP256PublicKeyWasm');
    expect(ethSigner).toContain('decodeCoseP256PublicKeyWasm');
  });

  test('new target folders follow the Refactor 33 import direction contract', () => {
    const offenders: string[] = [];
    const allowedBySourceTopLevel: Record<string, readonly string[]> = {
      assembly: [
        'flows',
        'session',
        'stepUpConfirmation',
        'threshold',
        'chains',
        'workers',
        'workerManager',
        'uiConfirm',
        'webauthnAuth',
        'interfaces',
        'nonce',
      ],
      flows: [
        'flows',
        'session',
        'stepUpConfirmation',
        'threshold',
        'chains',
        'workers',
        'nonce',
        'interfaces',
        'uiConfirm',
        'webauthnAuth',
        'workerManager',
      ],
      chains: ['workers', 'workerManager', 'session', 'signers', 'interfaces'],
      stepUpConfirmation: ['interfaces', 'webauthnAuth'],
      uiConfirm: [
        'chains',
        'stepUpConfirmation',
        'interfaces',
        'nonce',
        'session',
        'threshold',
        'webauthnAuth',
        'workerManager',
      ],
      webauthnAuth: [],
      workers: [],
    };

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const sourceTopLevel = signingEngineTopLevel(relativePath);
      if (!sourceTopLevel || !targetContractFolders.includes(sourceTopLevel as never)) continue;

      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved) continue;
        const targetTopLevel = signingEngineTopLevel(resolved);
        if (!targetTopLevel) continue;
        if (targetTopLevel === sourceTopLevel) continue;

        const allowed = allowedBySourceTopLevel[sourceTopLevel] || [];
        if (!allowed.includes(targetTopLevel)) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('auth prompt and UI runtime boundaries stay one-way', () => {
    const forbiddenByRoot: Record<string, readonly string[]> = {
      webauthnAuth: [
        'stepUpConfirmation',
        'uiConfirm',
        'session',
        'flows',
        'threshold',
        'chains',
        'nonce',
        'workerManager',
      ],
      stepUpConfirmation: [
        'uiConfirm',
        'session',
        'flows',
        'assembly',
        'threshold',
        'chains',
        'nonce',
        'workerManager',
      ],
      uiConfirm: ['flows', 'assembly', 'SigningEngine.ts'],
    };
    const offenders: string[] = [];

    for (const [root, forbiddenTargets] of Object.entries(forbiddenByRoot)) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, root),
      )) {
        const source = readRepoSource(relativePath);
        for (const specifier of extractImportSpecifiers(source)) {
          const resolved = resolveSigningEngineImport(relativePath, specifier);
          if (!resolved) continue;
          const targetTopLevel = signingEngineTopLevel(resolved);
          if (targetTopLevel && forbiddenTargets.includes(targetTopLevel)) {
            offenders.push(`${relativePath} -> ${specifier}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('operation flows use uiConfirm only through documented runtime ports', () => {
    const allowedUiConfirmImports = [
      'client/src/core/signingEngine/uiConfirm/types',
      'client/src/core/signingEngine/uiConfirm/ui/export-viewer-host',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      for (const specifier of extractImportSpecifiers(source)) {
        const resolved = resolveSigningEngineImport(relativePath, specifier);
        if (!resolved?.startsWith('client/src/core/signingEngine/uiConfirm')) continue;
        if (!allowedUiConfirmImports.includes(resolved as never)) {
          offenders.push(`${relativePath} -> ${specifier}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('auth-method prompt builders stay under stepUpConfirmation prompt folders', () => {
    const forbiddenPromptOwnerMarkers = [
      'export function formatEmailOtpSentText',
      'export async function prepareEmailOtpSigningPrompt',
      'export async function requestEmailOtpExportAuthorization',
      'Enter email code to sign',
    ] as const;
    const roots = ['flows', 'session'] as const;
    const offenders: string[] = [];

    for (const root of roots) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, root),
      )) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenPromptOwnerMarkers) {
          if (source.includes(marker)) offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('ECDSA chain target primitives live in interfaces', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'client/src'))) {
      const source = readRepoSource(relativePath);
      if (source.includes('signingEngine/session/operationState/ecdsaChainTarget')) {
        offenders.push(relativePath);
      }
    }

    const promptFiles = [
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/authLane.ts',
      'client/src/core/signingEngine/stepUpConfirmation/otpPrompt/exportAuthorization.ts',
    ] as const;

    expect(offenders).toEqual([]);
    expect(fs.existsSync(path.join(signingEngineRoot, 'interfaces/ecdsaChainTarget.ts'))).toBe(
      true,
    );
    for (const relativePath of promptFiles) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).toContain(
        "from '@/core/signingEngine/interfaces/ecdsaChainTarget'",
      );
    }
  });

  test('canonical selected lanes and operation states do not use optional lifecycle fields', () => {
    const identity = readRepoSource(
      'client/src/core/signingEngine/session/identity/laneIdentity.ts',
    );
    const signingLanes = readRepoSource(
      'client/src/core/signingEngine/session/operationState/lanes.ts',
    );
    const signingTypes = readRepoSource(
      'client/src/core/signingEngine/session/operationState/types.ts',
    );
    const signingBudget = readRepoSource('client/src/core/signingEngine/session/budget/budget.ts');
    const operationState = readRepoSource(
      'client/src/core/signingEngine/flows/shared/operationState.ts',
    );
    const planner = readRepoSource('client/src/core/signingEngine/session/planning/planner.ts');
    const restoreTypes = readRepoSource(
      'client/src/core/signingEngine/session/sealedRecovery/types.ts',
    );
    const restoreCoordinator = readRepoSource(
      'client/src/core/signingEngine/session/sealedRecovery/restoreCoordinator.ts',
    );

    for (const typeName of [
      'BaseSelectedLane',
      'BaseLaneCandidate',
      'Ed25519LaneCandidate',
      'EcdsaLaneCandidate',
      'SelectedEd25519Lane',
      'SelectedEcdsaLane',
      'SelectedLane',
    ]) {
      const alias = sliceTypeAlias(identity, typeName).replace(
        /\bresolvedKey\?:\s*ResolvedEvmFamilyEcdsaKey;?/g,
        '',
      );
      const normalizedAlias = alias.replace(/\bsourceChainTarget\?:\s*never;?/g, '');
      expect(stripNeverOptionalGuards(normalizedAlias), typeName).not.toMatch(/\w+\?:/);
    }

    for (const typeName of [
      'SigningReadyState',
      'ReadyLane',
      'ReauthRequired',
      'PreparedOperation',
    ]) {
      expect(
        stripNeverOptionalGuards(sliceTypeAlias(operationState, typeName)),
        typeName,
      ).not.toMatch(/\w+\?:/);
    }
    expect(operationState).not.toContain('BudgetAdmission');
    expect(operationState).not.toContain('BudgetAdmittedOperation');
    expect(operationState).not.toContain('SignedOperation');

    expect(signingLanes).toContain(
      'export type NearTransactionSigningLane = SelectedEd25519Lane & SelectedSigningSessionPlanningLane;',
    );
    expect(signingLanes).toContain(
      'export type EcdsaTransactionSigningLane = SelectedEcdsaLane & SelectedSigningSessionPlanningLane;',
    );
    expect(identity).toContain('export function selectedEd25519Lane');
    expect(identity).toContain('export function selectedEcdsaLane');
    expect(signingLanes).not.toContain("kind: 'selected_lane'");
    expect(signingLanes).not.toContain("chain: 'near'");
    expect(signingLanes).not.toContain('chain: input.chainTarget.kind');
    expect(signingLanes).not.toContain('): SigningSessionPlanningLane');
    expect(
      stripNeverOptionalGuards(
        sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput'),
      ),
    ).not.toMatch(/\w+\?:/);
    expect(sliceTypeAlias(restoreTypes, 'RestorePersistedSessionForSigningInput')).not.toContain(
      "reason: 'session_status'",
    );
    expect(restoreCoordinator).not.toContain('RestorePersistedSessionForSigningMaintenanceInput');
    expect(
      stripNeverOptionalGuards(sliceTypeAlias(planner, 'SigningSessionReadiness')),
    ).not.toMatch(/\w+\?:/);
    expect(sliceTypeAlias(planner, 'SigningSessionReadiness')).not.toContain(
      'backingMaterialSessionId',
    );
    expect(
      stripNeverOptionalGuards(sliceTypeAlias(signingTypes, 'PasskeyReconnectPlan')),
    ).not.toMatch(/\w+\?:/);
    expect(signingBudget).not.toContain('refs: {');
    expect(signingBudget).not.toContain('refs.thresholdSessionId');
    expect(signingBudget).not.toContain('refs.backingMaterialSessionId');

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'flows'),
    )) {
      const source = readRepoSource(relativePath);
      expect(source, relativePath).not.toContain('SelectedSigningSessionPlanningLane');
    }
  });

  test('selected-lane construction stays in session identity', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      if (isTypeFixture(relativePath)) continue;
      if (relativePath === 'client/src/core/signingEngine/session/identity/laneIdentity.ts')
        continue;
      const source = readRepoSource(relativePath);
      if (source.includes("kind: 'selected_lane'")) offenders.push(relativePath);
    }

    expect(offenders).toEqual([]);
  });

  test('signing execution boundaries do not receive lane candidates or raw records', () => {
    const executionFiles = [
      'client/src/core/signingEngine/interfaces/near.ts',
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
      'client/src/core/signingEngine/flows/signNear/signDelegate.ts',
      'client/src/core/signingEngine/flows/signNear/signNep413.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signEvmWithUiConfirm.ts',
      'client/src/core/signingEngine/flows/signEvmFamily/signTempoWithUiConfirm.ts',
    ] as const;
    const forbiddenMarkers = [
      'LaneCandidate',
      'AvailableSigningLanes',
      'availableLane',
      'selectedLaneCandidate',
      'ThresholdEd25519SessionRecord',
      'ThresholdEcdsaSessionRecord',
      'warmRecord',
      'emailOtpReauthRecord',
      'warmKeyRef',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of executionFiles) {
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    const nearTransactions = readRepoSource(
      'client/src/core/signingEngine/flows/signNear/signTransactions.ts',
    );
    const evmExecutor = readRepoSource(
      'client/src/core/signingEngine/flows/signEvmFamily/transactionExecutor.ts',
    );

    expect(nearTransactions).toContain('BudgetAdmittedOperation<SelectedEd25519Lane>');
    expect(nearTransactions).toContain('ResolvedThresholdEd25519SessionState');
    expect(evmExecutor).toContain('lane: SelectedEcdsaLane');
    expect(evmExecutor).toContain('thresholdOwnerAddress: `0x${string}`;');
    expect(offenders).toEqual([]);
  });

  test('deleted duplicate lane shape names stay out of production signing-engine code', () => {
    const removedDuplicateNames = [
      'ConcreteThresholdEcdsaSessionRecord',
      'EcdsaLaneIdentity',
      'ThresholdEcdsaRuntimeLane',
      'ThresholdEd25519SessionLane',
      'NearEd25519TransactionLane',
      'NearEd25519SelectedIdentity',
      'EvmFamilyEcdsaTransactionLane',
      'SigningLaneContext',
      'SelectedSigningLaneContext',
      'ReadyEcdsaLane',
      'Ed25519NearLaneIdentity',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(signingEngineRoot)) {
      const source = readRepoSource(relativePath);
      for (const removedName of removedDuplicateNames) {
        const exactName = new RegExp(`\\b${removedName}\\b`);
        if (exactName.test(source)) offenders.push(`${relativePath}: ${removedName}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  test('threshold session kind has one signing-engine owner', () => {
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(path.join(repoRoot, 'client/src'))) {
      const source = readRepoSource(relativePath);
      if (
        source.includes('Ed25519SessionKind') ||
        source.includes('EcdsaSessionKind') ||
        source.includes('ThresholdEcdsaSessionKind') ||
        source.includes('normalizeThresholdEcdsaSessionKind') ||
        source.includes('ed25519SessionTypes') ||
        source.includes('signingEngine/threshold/session/') ||
        source.includes('signingEngine/threshold/workflows/')
      ) {
        offenders.push(relativePath);
      }
    }

    expect(offenders).toEqual([]);
    expect(readRepoSource('client/src/core/signingEngine/threshold/sessionPolicy.ts')).toContain(
      "export type ThresholdSessionKind = 'jwt' | 'cookie';",
    );
  });

  test('threshold protocol entrypoints take protocol material instead of broad session shapes', () => {
    const protocolFiles = [
      'client/src/core/signingEngine/threshold/ecdsa/authorize.ts',
      'client/src/core/signingEngine/threshold/ecdsa/bootstrapSession.ts',
      'client/src/core/signingEngine/threshold/ecdsa/presignPool.ts',
      'client/src/core/signingEngine/threshold/ecdsa/sign.ts',
      'client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
    ] as const;
    const broadShapeMarkers = [
      'ThresholdEcdsaSessionRecord',
      'ThresholdEd25519SessionRecord',
      'SigningSessionPlanningLane',
      'SelectedSigningSessionPlanningLane',
      'AvailableSigningLanes',
      'snapshot',
    ] as const;

    for (const relativePath of protocolFiles) {
      const source = readRepoSource(relativePath);
      for (const marker of broadShapeMarkers) {
        expect(source, `${relativePath} must avoid ${marker}`).not.toContain(marker);
      }
    }
  });

  test('Ed25519 HSS client-base reconstruction receives resolved protocol material', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/hssClientBase.ts',
    );

    expect(source).toContain('existingXClientBaseB64u?: string');
    expect(source).toContain('signingRootId: string');
    expect(source).toContain('persistClientBase?:');
    expect(source).not.toContain('session/records');
    expect(source).not.toContain('getStoredThresholdEd25519SessionRecord');
  });

  test('Ed25519 HSS lifecycle leaves persistence to caller boundaries', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/hssLifecycle.ts',
    );

    expect(source).not.toContain('session/records');
    expect(source).not.toContain('persistStoredThresholdEd25519SessionClientBase');
    expect(source).not.toContain('persistToThresholdSessionId');
    expect(source).not.toContain('persistedThresholdSessionId');
  });

  test('threshold session identity types live outside persistence records', () => {
    const identity = readRepoSource(
      'client/src/core/signingEngine/session/identity/laneIdentity.ts',
    );
    const records = readRepoSource('client/src/core/signingEngine/session/persistence/records.ts');
    const activation = readRepoSource(
      'client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
    );

    expect(identity).toContain('export type ThresholdEcdsaSessionStoreSource');
    expect(identity).toContain('export type ThresholdEd25519SessionStoreSource');
    expect(identity).toContain('export type ThresholdEcdsaEmailOtpAuthContext');
    expect(records).not.toContain('export type ThresholdEcdsaSessionStoreSource');
    expect(records).not.toContain('export type ThresholdEd25519SessionStoreSource');
    expect(records).not.toContain('export type ThresholdEcdsaEmailOtpAuthContext');
    expect(activation).not.toContain('session/records');
  });

  test('Ed25519 auth session mint helper has no session lifecycle cache', () => {
    const source = readRepoSource('client/src/core/signingEngine/threshold/ed25519/authSession.ts');

    expect(source).not.toContain('session/records');
    expect(source).not.toContain('persistWarmSessionEd25519Capability');
    expect(source).not.toContain('buildAndCacheEd25519AuthSession');
    expect(source).not.toContain('resolveEd25519AuthSessionBySessionId');
    expect(source).not.toContain('authSessionCache');
  });

  test('Ed25519 connect-session protocol leaves warm-session persistence to callers', () => {
    const source = readRepoSource(
      'client/src/core/signingEngine/threshold/ed25519/connectSession.ts',
    );

    expect(source).not.toContain('persistWarmSessionEd25519Capability');
    expect(source).not.toContain('cacheSigningSessionPrfFirstBestEffort');
    expect(source).not.toContain('session/warmCapabilities');
  });

  test('threshold modules avoid session lifecycle imports', () => {
    const forbiddenMarkers = [
      'session/records',
      'session/warmCapabilities',
      'api/session/signingSessionState',
    ] as const;
    const offenders: string[] = [];

    for (const relativePath of listProductionTypeScriptFiles(
      path.join(signingEngineRoot, 'threshold'),
    )) {
      if (isTypeFixture(relativePath)) continue;
      const source = readRepoSource(relativePath);
      for (const marker of forbiddenMarkers) {
        if (source.includes(marker)) {
          offenders.push(`${relativePath} contains ${marker}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  test('threshold protocol modules do not write warm-session cache material', () => {
    const forbiddenMarkers = [
      'putWarmSessionMaterial',
      'prfFirstCache',
      'WarmSessionMaterial',
    ] as const;
    const offenders: string[] = [];

    for (const protocolFolder of ['ecdsa', 'ed25519'] as const) {
      for (const relativePath of listProductionTypeScriptFiles(
        path.join(signingEngineRoot, 'threshold', protocolFolder),
      )) {
        const source = readRepoSource(relativePath);
        for (const marker of forbiddenMarkers) {
          if (source.includes(marker)) {
            offenders.push(`${relativePath} contains ${marker}`);
          }
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
