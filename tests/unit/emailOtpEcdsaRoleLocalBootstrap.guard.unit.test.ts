import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { buildConfigsFromEnv } from '../../client/src/core/config/defaultConfigs';
import { emailOtpEcdsaPublicationChainTargets } from '../../client/src/core/signingEngine/session/emailOtp/ecdsaPublication';

const EMAIL_OTP_WORKER_URL = new URL(
  '../../client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
  import.meta.url,
);
const EMAIL_OTP_ECDSA_ENROLLMENT_URL = new URL(
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaEnrollment.ts',
  import.meta.url,
);
const EMAIL_OTP_ECDSA_LOGIN_URL = new URL(
  '../../client/src/core/signingEngine/session/emailOtp/ecdsaLogin.ts',
  import.meta.url,
);
const EMAIL_OTP_ECDSA_BOOTSTRAP_URL = new URL(
  '../../client/src/core/signingEngine/session/passkey/ecdsaBootstrap.ts',
  import.meta.url,
);
const ECDSA_SESSION_PROVISION_URL = new URL(
  '../../client/src/core/signingEngine/session/passkey/ecdsaSessionProvision.ts',
  import.meta.url,
);
const PERSISTED_AVAILABLE_LANES_URL = new URL(
  '../../client/src/core/signingEngine/session/availability/persistedAvailableSigningLanes.ts',
  import.meta.url,
);
const SESSION_READINESS_URL = new URL(
  '../../client/src/core/signingEngine/session/availability/readiness.ts',
  import.meta.url,
);
const EVM_FAMILY_PREPARED_SIGNING_URL = new URL(
  '../../client/src/core/signingEngine/flows/signEvmFamily/preparedSigning.ts',
  import.meta.url,
);
const EVM_FAMILY_SIGNING_FLOW_URL = new URL(
  '../../client/src/core/signingEngine/flows/signEvmFamily/signingFlow.ts',
  import.meta.url,
);
const EMAIL_OTP_PROVISIONING_URL = new URL(
  '../../client/src/core/signingEngine/session/emailOtp/provisioning.ts',
  import.meta.url,
);
const SIGNING_SESSION_COORDINATOR_URL = new URL(
  '../../client/src/core/signingEngine/session/SigningSessionCoordinator.ts',
  import.meta.url,
);
const WARM_CAPABILITY_STATUS_READER_URL = new URL(
  '../../client/src/core/signingEngine/session/warmCapabilities/statusReader.ts',
  import.meta.url,
);
const NEAR_THRESHOLD_AUTH_MODE_URL = new URL(
  '../../client/src/core/signingEngine/flows/signNear/shared/thresholdAuthMode.ts',
  import.meta.url,
);
const SIGNING_ENGINE_URL = new URL(
  '../../client/src/core/signingEngine/SigningEngine.ts',
  import.meta.url,
);
const SEAMS_PASSKEY_URL = new URL('../../client/src/core/SeamsPasskey/index.ts', import.meta.url);
const SEAMS_PASSKEY_INTERFACES_URL = new URL(
  '../../client/src/core/SeamsPasskey/interfaces.ts',
  import.meta.url,
);
const THRESHOLD_WARM_SESSION_BOOTSTRAP_URL = new URL(
  '../../client/src/core/SeamsPasskey/thresholdWarmSessionBootstrap.ts',
  import.meta.url,
);
const WALLET_IFRAME_MESSAGES_URL = new URL(
  '../../client/src/core/WalletIframe/shared/messages.ts',
  import.meta.url,
);
const DEMO_PASSKEY_LOGIN_MENU_URL = new URL(
  '../../examples/seams-site/src/flows/demo/PasskeyLoginMenu.tsx',
  import.meta.url,
);

test.describe('Email OTP ECDSA role-local bootstrap guard', () => {
  test('bootstrap uses role-local paths and rejects missing role-local identity', () => {
    const source = readFileSync(EMAIL_OTP_WORKER_URL, 'utf8');
    const functionStart = source.indexOf(
      'async function runThresholdEcdsaAuthorizationBootstrapFromClientRootShare',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf(
      'async function runEmailOtpEcdsaPublicationBootstrapsFromClientRootShare',
      functionStart,
    );
    expect(functionEnd).toBeGreaterThan(functionStart);
    const roleLocalBlock = source.slice(functionStart, functionEnd);

    expect(roleLocalBlock).toContain('exactSessionBootstrap && roleLocalRelayerKeyId');
    expect(roleLocalBlock).toContain("operation === 'email_otp_bootstrap'");
    expect(roleLocalBlock).toContain('!keyHandle');
    expect(roleLocalBlock).toContain('existingKeyRoleLocalIdentity');
    expect(roleLocalBlock).toContain('roleLocalKeyIdentity');
    expect(roleLocalBlock).toContain('computeEcdsaHssRoleLocalFirstBootstrapRootProofDigest32');
    expect(roleLocalBlock).toContain('sign_secp256k1_recoverable(proofDigest32');
    expect(roleLocalBlock).toContain('clientRootProof');
    expect(roleLocalBlock).toContain('threshold_ecdsa_hss_role_local_client_bootstrap');
    expect(roleLocalBlock).toContain('thresholdEcdsaHssRoleLocalBootstrap');
    expect(roleLocalBlock).toContain('readOptionalString(value.jwt)');
    expect(roleLocalBlock).toContain('base64UrlDecode(clientShare32B64u)');
    expect(roleLocalBlock).not.toContain('base64UrlDecode(mappedPrivateShare32B64u)');
    expect(roleLocalBlock).toContain('ecdsaHssRoleLocalClientState');
    expect(roleLocalBlock).toContain('requires concrete role-local key identity');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssPrepare(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssRespond(');
    expect(roleLocalBlock).not.toContain('thresholdEcdsaHssFinalize(');
  });

  test('enrollment derives runtime policy scope from app-session auth before worker bootstrap', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_ENROLLMENT_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function enrollAndLoginWithEmailOtpEcdsaCapability',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf(
      'const workerCtx = ports.getSignerWorkerContext',
      functionStart,
    );
    expect(functionEnd).toBeGreaterThan(functionStart);
    const enrollmentSetup = source.slice(functionStart, functionEnd);

    expect(enrollmentSetup).toContain(
      'parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt)',
    );
    expect(enrollmentSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt)');
    expect(source).toContain('resolveRequiredEmailOtpEcdsaRoleLocalKeyIdentity({');
    expect(source).toContain('runtimePolicyScope,');
  });

  test('enrollment does not run the legacy Ed25519 sidecar provisioning path', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_ENROLLMENT_URL, 'utf8');
    expect(source).not.toContain('provisionEd25519Capability');
    expect(source).not.toContain('ed25519ParticipantIds');
    expect(source).not.toContain('registration_ed25519_companion_provisioning');
  });

  test('enrollment keeps fresh registration on ECDSA role-local bootstrap only', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_ENROLLMENT_URL, 'utf8');
    expect(source).toContain("type: 'bootstrapEmailOtpEcdsaSessionsFromClientRootShare'");
    expect(source).toContain('commitEmailOtpEcdsaPublicationBootstraps');
    expect(source).not.toContain('/threshold-ed25519/hss/');
  });

  test('Email OTP ECDSA publication includes every configured EVM-family target during login-style registration', () => {
    const targets = emailOtpEcdsaPublicationChainTargets({
      configs: buildConfigsFromEnv({
        chains: [
          {
            network: 'near-testnet',
            rpcUrl: 'https://near.example.test',
            explorerUrl: 'https://near.explorer.test',
          },
          {
            network: 'tempo-testnet',
            chainId: 42431,
            rpcUrl: 'https://tempo.example.test',
            explorerUrl: 'https://tempo.explorer.test',
          },
          {
            network: 'arc-testnet',
            chainId: 5042002,
            rpcUrl: 'https://arc.example.test',
            explorerUrl: 'https://arc.explorer.test',
          },
        ],
        relayer: { url: 'https://relayer.example.test' },
      }),
      primaryChain: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'login',
        authMethod: 'email_otp',
        authSubjectId: 'google:subject',
      },
    });

    expect(targets).toEqual([
      { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-testnet' },
      { kind: 'evm', namespace: 'eip155', chainId: 5042002, networkSlug: 'arc-testnet' },
    ]);
  });

  test('Email OTP ECDSA bootstrap does not persist through the passkey touch-confirm material path', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_BOOTSTRAP_URL, 'utf8');
    const functionStart = source.indexOf('export async function bootstrapEcdsaSessionValue');
    expect(functionStart).toBeGreaterThan(-1);
    const functionBlock = source.slice(functionStart);

    const emailOtpBranch = functionBlock.indexOf(
      "normalizedRequest.kind === 'email_otp_ecdsa_bootstrap'",
    );
    const touchConfirmWrite = functionBlock.indexOf('deps.touchConfirm.putWarmSessionMaterial');
    const passkeyGuard = functionBlock.indexOf(
      "normalizedRequest.kind !== 'email_otp_ecdsa_bootstrap'",
    );

    expect(emailOtpBranch).toBeGreaterThan(-1);
    expect(passkeyGuard).toBeGreaterThan(emailOtpBranch);
    expect(touchConfirmWrite).toBeGreaterThan(passkeyGuard);
  });

  test('Email OTP ECDSA registration persistence does not use touch-confirm warm material writes', () => {
    const source = readFileSync(SIGNING_ENGINE_URL, 'utf8');
    const functionStart = source.indexOf(
      'async persistWalletRegistrationEcdsaBootstrapForWalletKeys',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('\n  }\n\n  extractCosePublicKey', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    const passkeyWriteGuard = functionBlock.indexOf("if (args.auth.kind === 'passkey')");
    const touchConfirmWrite = functionBlock.indexOf('touchConfirm.putWarmSessionMaterial');
    const emailOtpBranch = functionBlock.indexOf("args.auth.kind === 'email_otp'");

    expect(emailOtpBranch).toBeGreaterThan(-1);
    expect(passkeyWriteGuard).toBeGreaterThan(emailOtpBranch);
    expect(touchConfirmWrite).toBeGreaterThan(passkeyWriteGuard);
  });

  test('Email OTP ECDSA registration lanes derive readiness from inline HSS material', () => {
    const source = readFileSync(PERSISTED_AVAILABLE_LANES_URL, 'utf8');
    const functionStart = source.indexOf('readRuntimeEcdsaClaimsForRecords: async');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('readRuntimeClaimsForSessions: async', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    const emailOtpBranch = functionBlock.indexOf(
      'ecdsaRecord.source === SIGNER_AUTH_METHODS.emailOtp',
    );
    const inlineShareCheck = functionBlock.indexOf(
      'thresholdEcdsaRecordHasInlineRoleLocalSigningMaterial(ecdsaRecord)',
    );
    const policyClaim = functionBlock.indexOf('runtimeRecordPolicyClaim');
    const workerStatus = functionBlock.indexOf('getEmailOtpWarmSessionStatus');
    const passkeyStatus = functionBlock.indexOf('deps.statusReader');

    expect(emailOtpBranch).toBeGreaterThan(-1);
    expect(inlineShareCheck).toBeGreaterThan(emailOtpBranch);
    expect(policyClaim).toBeGreaterThan(inlineShareCheck);
    expect(workerStatus).toBeGreaterThan(policyClaim);
    expect(passkeyStatus).toBeGreaterThan(workerStatus);
  });

  test('Email OTP Ed25519 registration lanes derive readiness from cached client base material', () => {
    const source = readFileSync(PERSISTED_AVAILABLE_LANES_URL, 'utf8');
    const functionStart = source.indexOf('readRuntimeClaimsForSessions: async');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('const walletSigningSessionId', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    const ed25519Branch = functionBlock.indexOf(
      'ed25519Record?.source === SIGNER_AUTH_METHODS.emailOtp',
    );
    const sessionRetention = functionBlock.indexOf(
      "ed25519Record.emailOtpAuthContext?.retention === 'session'",
      ed25519Branch,
    );
    const clientBaseCheck = functionBlock.indexOf('ed25519Record.xClientBaseB64u', ed25519Branch);
    const policyClaim = functionBlock.indexOf('runtimeRecordPolicyClaim', ed25519Branch);
    const workerStatus = functionBlock.indexOf('getEmailOtpWarmSessionStatus', policyClaim);

    expect(ed25519Branch).toBeGreaterThan(-1);
    expect(sessionRetention).toBe(-1);
    expect(clientBaseCheck).toBeGreaterThan(ed25519Branch);
    expect(policyClaim).toBeGreaterThan(clientBaseCheck);
    expect(workerStatus).toBeGreaterThan(policyClaim);
  });

  test('Email OTP ECDSA bootstrap does not call passkey PRF seal persistence', () => {
    const source = readFileSync(ECDSA_SESSION_PROVISION_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function provisionThresholdEcdsaSessionFromBootstrapArgs',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf(
      'export async function provisionThresholdEcdsaSession',
      functionStart + 1,
    );
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    const emailOtpGuard = functionBlock.indexOf("request.kind !== 'email_otp_ecdsa_bootstrap'");
    const sealPersistCall = functionBlock.indexOf('ensureEcdsaPrfSealPersisted');

    expect(emailOtpGuard).toBeGreaterThan(-1);
    expect(sealPersistCall).toBeGreaterThan(emailOtpGuard);
  });

  test('registration postconditions check configured ECDSA targets, not only returned wallet keys', () => {
    const source = readFileSync(
      new URL('../../client/src/core/SeamsPasskey/registration.ts', import.meta.url),
      'utf8',
    );

    expect(source).toContain('expectedEcdsaChainTargetsFromRegistrationSpec');
    expect(source).toContain('thresholdEcdsaChainTargetFromRequest');
    expect(source).toContain('expectedEcdsaChainTargets: expectedEcdsaChainTargetsFromRegistrationSpec');
    expect(source).not.toContain('ecdsaWalletKeys: walletKeys');
  });

  test('EVM-family signing prep does not start from a passkey auth-method default', () => {
    const source = readFileSync(EVM_FAMILY_PREPARED_SIGNING_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function prepareEvmFamilyEcdsaSigningSession',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const firstPrepareStart = source.indexOf(
      'const preparedTransaction = await prepareTransactionSigningOperation',
      functionStart,
    );
    const lifecycleStart = source.indexOf('lifecycleAdapter:', firstPrepareStart);
    expect(firstPrepareStart).toBeGreaterThan(functionStart);
    expect(lifecycleStart).toBeGreaterThan(firstPrepareStart);
    const initialPrepare = source.slice(firstPrepareStart, lifecycleStart);

    expect(initialPrepare).toContain("authSelectionPolicy: { kind: 'any' }");
    expect(initialPrepare).not.toContain("authMethod: 'passkey'");
  });

  test('EVM-family signing prep resolves material before sealed restore', () => {
    const source = readFileSync(EVM_FAMILY_PREPARED_SIGNING_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function prepareEvmFamilyEcdsaSigningSession',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionBlock = source.slice(functionStart);
    const materialSelection = functionBlock.indexOf(
      'let selection = await resolveSelectedEcdsaMaterial()',
    );
    const restoreCall = functionBlock.indexOf('args.deps.restorePersistedSessionForSigning({');

    expect(materialSelection).toBeGreaterThan(-1);
    expect(restoreCall).toBeGreaterThan(materialSelection);
    expect(functionBlock).toContain('!hasSelectedHotMaterial');
    expect(functionBlock).not.toContain('getThresholdEcdsaSessionRecordByKey(transactionLane)');
  });

  test('Email OTP ECDSA readiness does not fall back to touch-confirm status', () => {
    const source = readFileSync(
      new URL(
        '../../client/src/core/signingEngine/flows/signEvmFamily/authPlanning.ts',
        import.meta.url,
      ),
      'utf8',
    );
    const branchStart = source.indexOf('if (materialIsEmailOtp)');
    expect(branchStart).toBeGreaterThan(-1);
    const branchEnd = source.indexOf('const trustedPasskeyReadiness', branchStart);
    expect(branchEnd).toBeGreaterThan(branchStart);
    const branch = source.slice(branchStart, branchEnd);

    const inlineShareCheck = branch.indexOf('inlineClientAdditiveShare32B64u');
    const inlinePolicyReturn = branch.indexOf('return buildBackingReadiness', inlineShareCheck);
    const workerSessionResolution = branch.indexOf('resolveEmailOtpEcdsaWorkerSessionId(record)');
    const workerStatusCheck = branch.indexOf('getEmailOtpWarmSessionStatus');

    expect(inlineShareCheck).toBeGreaterThan(-1);
    expect(inlinePolicyReturn).toBeGreaterThan(inlineShareCheck);
    expect(workerSessionResolution).toBeGreaterThan(inlinePolicyReturn);
    expect(workerStatusCheck).toBeGreaterThan(workerSessionResolution);
    expect(branch).toContain('getEmailOtpWarmSessionStatus');
    expect(branch).not.toContain('touchConfirm.getWarmSessionStatus');
  });

  test('Email OTP ECDSA worker session resolver never falls back to threshold session id', () => {
    const source = readFileSync(SESSION_READINESS_URL, 'utf8');
    const functionStart = source.indexOf('export function resolveEmailOtpEcdsaWorkerSessionId');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('\n}\n\nfunction ecdsaRecordHasInlineEmailOtpMaterial', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    expect(functionBlock).toContain(': string | null');
    expect(functionBlock).toContain("record.source !== 'email_otp'");
    expect(functionBlock).toContain("record.clientAdditiveShareHandle?.kind === 'email_otp_worker_session'");
    expect(functionBlock).toContain('return null');
    expect(functionBlock).not.toContain('return thresholdSessionId');
  });

  test('Email OTP ECDSA lane discovery separates inline record policy from worker backing', () => {
    const source = readFileSync(SESSION_READINESS_URL, 'utf8');
    const functionStart = source.indexOf('export function buildDiscoveredLaneForRecord');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('\n}\n\nexport function discoverLanesForWallet', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    expect(functionBlock).toContain("emailOtpWorkerSessionId");
    expect(functionBlock).toContain("'email_otp_worker'");
    expect(functionBlock).toContain('ecdsaRecordHasInlineEmailOtpMaterial(record)');
    expect(functionBlock).toContain("'record_policy'");
    expect(functionBlock).toContain('if (!ecdsaRecordHasInlineEmailOtpMaterial(record)) return null');
    expect(functionBlock).not.toContain('emailOtpWorkerSessionId || thresholdSessionId');
  });

  test('Email OTP ECDSA warm capability reads inline policy or worker status only', () => {
    const source = readFileSync(WARM_CAPABILITY_STATUS_READER_URL, 'utf8');
    const functionStart = source.indexOf('async function readEcdsaWarmSessionClaimForRecord');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('\n  async function readWalletScopedClaimsForRecords', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const functionBlock = source.slice(functionStart, functionEnd);

    const emailOtpBranch = functionBlock.indexOf("if (record.source === 'email_otp')");
    const inlinePolicyClaim = functionBlock.indexOf('warmClaimFromRecordPolicy', emailOtpBranch);
    const workerSessionId = functionBlock.indexOf('resolveEmailOtpEcdsaWorkerSessionId(record)', emailOtpBranch);
    const nullWithoutWorker = functionBlock.indexOf('if (!workerSessionId) return null', workerSessionId);
    const passkeyTouchConfirm = functionBlock.indexOf('readWarmSessionClaim(touchConfirm');

    expect(emailOtpBranch).toBeGreaterThan(-1);
    expect(inlinePolicyClaim).toBeGreaterThan(emailOtpBranch);
    expect(workerSessionId).toBeGreaterThan(inlinePolicyClaim);
    expect(nullWithoutWorker).toBeGreaterThan(workerSessionId);
    expect(passkeyTouchConfirm).toBeGreaterThan(nullWithoutWorker);
  });

  test('EVM-family signing admission reuses already-admitted ECDSA warm material', () => {
    const source = readFileSync(EVM_FAMILY_SIGNING_FLOW_URL, 'utf8');
    const admissionStart = source.indexOf('const admissionMode: EvmFamilyThresholdEcdsaAdmissionMode');
    expect(admissionStart).toBeGreaterThan(-1);
    const admissionEnd = source.indexOf('const admissionConfirmation', admissionStart);
    expect(admissionEnd).toBeGreaterThan(admissionStart);
    const admissionBlock = source.slice(admissionStart, admissionEnd);
    const alreadyAdmittedCheck = admissionBlock.indexOf(
      'activeThresholdEcdsaOperation && thresholdEcdsaSignerSession',
    );
    const thresholdReconnectCheck = admissionBlock.indexOf(
      'thresholdEcdsaStepUpRuntime?.thresholdReconnect',
    );

    expect(alreadyAdmittedCheck).toBeGreaterThan(-1);
    expect(thresholdReconnectCheck).toBeGreaterThan(alreadyAdmittedCheck);
  });

  test('login derives runtime policy scope from route auth before worker bootstrap', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_LOGIN_URL, 'utf8');
    const functionStart = source.indexOf('export async function loginWithEmailOtpEcdsaCapability');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('if (!workerCtx)', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const loginSetup = source.slice(functionStart, functionEnd);

    expect(loginSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt)');
    expect(loginSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt)');
    expect(source).toContain('resolveRequiredEmailOtpEcdsaRoleLocalKeyIdentity({');
    expect(source).toContain('runtimePolicyScope,');
  });

  test('login reconstructs existing Ed25519 sessions through session-auth path', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_LOGIN_URL, 'utf8');
    const reconstructionArgsStart = source.indexOf('const ed25519ReconstructionArgs');
    expect(reconstructionArgsStart).toBeGreaterThan(-1);
    const reconstructionArgsEnd = source.indexOf('};', reconstructionArgsStart);
    expect(reconstructionArgsEnd).toBeGreaterThan(reconstructionArgsStart);
    const reconstructionArgs = source.slice(reconstructionArgsStart, reconstructionArgsEnd);

    expect(reconstructionArgs).toContain("kind: 'session_ed25519_reconstruction'");
    expect(reconstructionArgs).toContain('routeAuth: reconstructionAuth');
    expect(reconstructionArgs).toContain(
      'runtimePolicyScope: resolvedEd25519Reconstruction.runtimePolicyScope',
    );
    expect(reconstructionArgs).toContain('ed25519Key: resolvedEd25519Reconstruction.ed25519Key');
    expect(source).toContain("ed25519ReconstructionPlan.reason === 'missing_runtime_policy_scope'");
    expect(source).toContain(
      'ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan',
    );
    expect(source).toContain('ed25519Reconstruction: EmailOtpEd25519ReconstructionResult');
    expect(source).toContain("ed25519ReconstructionMode: 'await' | 'skip'");
    expect(source).not.toContain('ed25519Reconstruction?:');
    expect(source).not.toContain('ed25519ReconstructionMode?:');
    expect(source).not.toContain('ed25519SessionMaterial?:');
    expect(source).not.toContain('ed25519SessionReconstruction?:');
    expect(source).not.toContain('ed25519SessionReconstruction?.runtimePolicyScope');
    expect(source).toContain('await ports.reconstructEd25519Session(');
    expect(source).toContain('ed25519ReconstructionArgs');
    expect(source).not.toContain('canUseRegistrationEd25519Provisioning');
  });

  test('stale Ed25519 sidecar registration provisioning path is deleted', () => {
    const source = readFileSync(EMAIL_OTP_PROVISIONING_URL, 'utf8');
    const reconstructionStart = source.indexOf(
      'export async function reconstructEmailOtpEd25519Session',
    );
    const helperStart = source.indexOf('function joinUrlPath', reconstructionStart);
    expect(source).not.toContain('registerEmailOtpEd25519Capability');
    expect(source).not.toContain('/threshold-ed25519/hss/prepare');
    expect(source).not.toContain('/threshold-ed25519/hss/respond');
    expect(source).not.toContain('/threshold-ed25519/hss/finalize');
    expect(source).not.toContain('completeThresholdEd25519HssClientCeremony({');
    expect(source).not.toContain('requestManagedRegistrationBootstrapGrant({');
    expect(reconstructionStart).toBeGreaterThan(-1);
    expect(helperStart).toBeGreaterThan(reconstructionStart);
    const reconstructionBlock = source.slice(reconstructionStart, helperStart);

    expect(reconstructionBlock).toContain('ReconstructEmailOtpEd25519SessionArgs');
    expect(reconstructionBlock).toContain('/threshold-ed25519/session');
  });

  test('Ed25519 sealed companion links are attached after reconstructed signer material is persisted', () => {
    const source = readFileSync(EMAIL_OTP_PROVISIONING_URL, 'utf8');
    const reconstructionStart = source.indexOf(
      'export async function reconstructEmailOtpEd25519Session',
    );
    const helperStart = source.indexOf('function joinUrlPath', reconstructionStart);
    const reconstructionBlock = source.slice(reconstructionStart, helperStart);

    const reconstructionReadyMaterial = reconstructionBlock.indexOf(
      'xClientBaseB64u: completed.clientOutput.xClientBaseB64u',
    );
    const reconstructionHss = reconstructionBlock.indexOf(
      'runThresholdEd25519HssCeremonyWithSessionValue({',
    );
    const reconstructionPersist = reconstructionBlock.indexOf(
      'persistWarmSessionEd25519Capability({',
    );
    const reconstructionHydrate = reconstructionBlock.indexOf('hydrateSigningSession({');
    const reconstructionAttach = reconstructionBlock.indexOf(
      'attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({',
    );

    expect(reconstructionHss).toBeGreaterThan(-1);
    expect(reconstructionPersist).toBeGreaterThan(reconstructionHss);
    expect(reconstructionReadyMaterial).toBeGreaterThan(-1);
    expect(reconstructionHydrate).toBeGreaterThan(reconstructionReadyMaterial);
    expect(reconstructionAttach).toBeGreaterThan(reconstructionReadyMaterial);
  });

  test('SDK boundary forwards stored Ed25519 key identity for Email OTP ECDSA reconstruction', () => {
    const sdkSource = readFileSync(SEAMS_PASSKEY_URL, 'utf8');
    const engineSource = readFileSync(SIGNING_ENGINE_URL, 'utf8');
    const helperStart = sdkSource.indexOf(
      'async function resolveEmailOtpEd25519SessionReconstruction',
    );
    expect(helperStart).toBeGreaterThan(-1);
    const helperEnd = sdkSource.indexOf('/**', helperStart);
    expect(helperEnd).toBeGreaterThan(helperStart);
    const reconstructionHelper = sdkSource.slice(helperStart, helperEnd);
    const loginStart = sdkSource.indexOf('async loginWithEmailOtpEcdsaCapability');
    expect(loginStart).toBeGreaterThan(-1);
    const loginEnd = sdkSource.indexOf(
      'async enrollAndLoginWithEmailOtpEcdsaCapability',
      loginStart,
    );
    expect(loginEnd).toBeGreaterThan(loginStart);
    const sdkLogin = sdkSource.slice(loginStart, loginEnd);
    const engineFunctionStart = engineSource.indexOf(
      'async loginWithEmailOtpEcdsaCapabilityInternal',
    );
    expect(engineFunctionStart).toBeGreaterThan(-1);
    const engineFunctionEnd = engineSource.indexOf(
      'async requestEmailOtpSigningSessionChallenge',
      engineFunctionStart,
    );
    expect(engineFunctionEnd).toBeGreaterThan(engineFunctionStart);
    const engineLoginBridge = engineSource.slice(engineFunctionStart, engineFunctionEnd);
    const compactEngineLoginBridge = engineLoginBridge
      .replace(/\s+/g, ' ')
      .replace(/\s+([(),;])/g, '$1')
      .replace(/\(\s+/g, '(')
      .replace(/\s+\)/g, ')')
      .replace(/,\)/g, ')');

    expect(reconstructionHelper).toContain('resolveEmailOtpEd25519KeyIdentity(walletId)');
    expect(sdkSource).toContain("source: 'wallet_profile_signer'");
    expect(sdkSource).toContain('listAccountSignersByProfile');
    expect(sdkSource).toContain('walletProfileSignerCount');
    expect(sdkSource).toContain('participantIdsFromEmailOtpEd25519SignerMetadata');
    expect(sdkSource).toContain('buildThresholdEd25519Participants2pV1');
    expect(reconstructionHelper).toContain('const ed25519Key = keyIdentity.ed25519Key');
    expect(sdkSource).toContain('const relayerKeyId = String(metadata.relayerKeyId');
    expect(sdkSource).toContain('const keyVersion = String(metadata.keyVersion');
    expect(reconstructionHelper).toContain('participantIds');
    expect(reconstructionHelper).toContain("'missing_runtime_policy_scope'");
    expect(reconstructionHelper).toContain('ed25519Key');
    expect(sdkLogin).toContain('await resolveEmailOtpEd25519SessionReconstruction(args)');
    expect(sdkSource).toContain('async function resolveEmailOtpEd25519KeyIdentity');
    expect(sdkSource).toContain('IndexedDBManager.listAccountSignersByProfile');
    expect(sdkSource).toContain("'wallet_profile_signer'");
    expect(sdkLogin).toContain("ed25519ReconstructionMode: 'await'");
    expect(sdkLogin).toContain('ed25519SessionReconstruction');
    expect(sdkLogin).toContain('initializeCurrentUser(toAccountId(walletId), this.nearClient)');
    expect(compactEngineLoginBridge).toContain(
      'return await emailOtpPublic.loginWithEmailOtpEcdsaCapabilityInternal(this.emailOtpPublicDeps, args);',
    );
  });

  test('SDK boundary preserves Google exchange runtime scope for Email OTP Ed25519 reconstruction', () => {
    const sdkSource = readFileSync(SEAMS_PASSKEY_URL, 'utf8');
    const interfacesSource = readFileSync(SEAMS_PASSKEY_INTERFACES_URL, 'utf8');
    const iframeMessagesSource = readFileSync(WALLET_IFRAME_MESSAGES_URL, 'utf8');
    const demoSource = readFileSync(DEMO_PASSKEY_LOGIN_MENU_URL, 'utf8');

    const helperStart = sdkSource.indexOf(
      'async function resolveEmailOtpEd25519SessionReconstruction',
    );
    expect(helperStart).toBeGreaterThan(-1);
    const helperEnd = sdkSource.indexOf('/**', helperStart);
    expect(helperEnd).toBeGreaterThan(helperStart);
    const reconstructionHelper = sdkSource.slice(helperStart, helperEnd);

    expect(interfacesSource).toContain('runtimePolicyScope?: ThresholdRuntimePolicyScope');
    expect(iframeMessagesSource).toContain('runtimePolicyScope?: ThresholdRuntimePolicyScope');
    expect(reconstructionHelper).toContain(
      'args.runtimePolicyScope || parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt)',
    );
    expect(demoSource).toContain('let runtimePolicyScope = exchange.session.runtimePolicyScope');
    expect(demoSource).toContain('runtimePolicyScope ? { runtimePolicyScope }');
  });

  test('Email OTP Ed25519 readiness remains reauthable when preflight budget status is unavailable', () => {
    const coordinatorSource = readFileSync(SIGNING_SESSION_COORDINATOR_URL, 'utf8');
    const applyStart = coordinatorSource.indexOf('private async applyWalletBudgetToReadiness');
    expect(applyStart).toBeGreaterThan(-1);
    const applyEnd = coordinatorSource.indexOf(
      'function hasWalletSigningSessionConsumeDeps',
      applyStart,
    );
    expect(applyEnd).toBeGreaterThan(applyStart);
    const applyBlock = coordinatorSource.slice(applyStart, applyEnd);

    expect(applyBlock).toContain("input.lane.authMethod === 'email_otp'");
    expect(applyBlock).toContain("input.lane.curve === 'ed25519'");
    expect(applyBlock).toContain("walletBudgetStatus?.status === 'budget_unknown'");
    expect(applyBlock).toContain("walletBudgetStatus?.status === 'unavailable'");
    expect(applyBlock).toContain("status: 'not_found' as const");
  });

  test('active Email OTP Ed25519 status is ready when enough signature uses remain', () => {
    const authModeSource = readFileSync(NEAR_THRESHOLD_AUTH_MODE_URL, 'utf8');
    const activeStart = authModeSource.indexOf("if (status?.status === 'active')");
    expect(activeStart).toBeGreaterThan(-1);
    const activeEnd = authModeSource.indexOf(
      "if (args.capability.state === 'missing')",
      activeStart,
    );
    expect(activeEnd).toBeGreaterThan(activeStart);
    const activeBlock = authModeSource.slice(activeStart, activeEnd);

    expect(activeBlock).not.toContain("isEmailOtpSession) {\n      return buildReadiness({ status: 'missing_session'");
    expect(activeBlock).toContain('normalizeRequiredSignatureUses(args.requiredSignatureUses)');
    expect(activeBlock).toContain("status: 'ready'");
  });

  test('demo Google Email OTP registration reroll reuses the current OTP challenge', () => {
    const demoSource = readFileSync(DEMO_PASSKEY_LOGIN_MENU_URL, 'utf8');
    const rerollStart = demoSource.indexOf('onRerollAccount: async () =>');
    expect(rerollStart).toBeGreaterThan(-1);
    const rerollEnd = demoSource.indexOf('const nextPromptCopy = buildOtpPromptCopy();', rerollStart);
    expect(rerollEnd).toBeGreaterThan(rerollStart);
    const rerollBlock = demoSource.slice(rerollStart, rerollEnd);

    expect(rerollBlock).not.toContain('requestCurrentOtpChallenge()');
    expect(demoSource).toContain("codeDelivery: 'reused'");
    expect(demoSource).toContain('Use the email code already sent');
  });

  test('demo Google Email OTP registration uses the unified wallet registration path', () => {
    const demoSource = readFileSync(DEMO_PASSKEY_LOGIN_MENU_URL, 'utf8');
    const enrollStart = demoSource.indexOf("if (otpFlow === 'enroll') {\n            if (!emailHint)");
    expect(enrollStart).toBeGreaterThan(-1);
    const loginStart = demoSource.indexOf('} else {', enrollStart);
    expect(loginStart).toBeGreaterThan(enrollStart);
    const enrollBlock = demoSource.slice(enrollStart, loginStart);

    expect(enrollBlock).toContain('seams.near.registerNearWallet');
    expect(enrollBlock).toContain("kind: 'email_otp'");
    expect(enrollBlock).not.toContain('enrollAndLoginWithEmailOtpEcdsaCapability');
  });

  test('Email OTP registration persists the Ed25519 warm session as an Email OTP lane', () => {
    const registrationSource = readFileSync(
      new URL('../../client/src/core/SeamsPasskey/registration.ts', import.meta.url),
      'utf8',
    );
    const bootstrapSource = readFileSync(THRESHOLD_WARM_SESSION_BOOTSTRAP_URL, 'utf8');
    expect(registrationSource).toContain("if (args.authMethod.kind === 'email_otp') {");
    expect(registrationSource).toContain("auth: {\n          kind: 'email_otp'");
    expect(registrationSource).toContain('emailOtpAuthContext: buildRegistrationEmailOtpAuthContext');
    expect(registrationSource).toContain('registrationHssClientMaterial: hssClientMaterial');
    expect(bootstrapSource).toContain("args.auth.kind === 'email_otp'");
    expect(bootstrapSource).toContain(
      'reconstructEmailOtpRegisteredThresholdEd25519ClientBase',
    );
    expect(bootstrapSource).toContain("kind: 'jwt_email_otp'");
    expect(bootstrapSource).toContain("source: 'email_otp'");
    expect(bootstrapSource).toContain('emailOtpAuthContext: args.auth.emailOtpAuthContext');
    expect(bootstrapSource).toContain('xClientBaseB64u');
  });
});
