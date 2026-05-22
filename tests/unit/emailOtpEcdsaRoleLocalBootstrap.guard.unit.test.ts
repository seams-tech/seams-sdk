import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

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
const EMAIL_OTP_PROVISIONING_URL = new URL(
  '../../client/src/core/signingEngine/session/emailOtp/provisioning.ts',
  import.meta.url,
);
const SIGNING_ENGINE_URL = new URL(
  '../../client/src/core/signingEngine/SigningEngine.ts',
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

    expect(enrollmentSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt)');
    expect(enrollmentSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt)');
    expect(source).toContain('resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle({');
    expect(source).toContain('...(runtimePolicyScope ? { runtimePolicyScope } : {})');
  });

  test('enrollment keeps ECDSA and Ed25519 participant sets separate', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_ENROLLMENT_URL, 'utf8');
    const provisioningStart = source.indexOf('await ports.provisionEd25519Capability({');
    expect(provisioningStart).toBeGreaterThan(-1);
    const provisioningEnd = source.indexOf('});', provisioningStart);
    expect(provisioningEnd).toBeGreaterThan(provisioningStart);
    const provisioningBlock = source.slice(provisioningStart, provisioningEnd);

    expect(source).toContain('ed25519ParticipantIds?: number[]');
    expect(provisioningBlock).toContain('args.ed25519ParticipantIds');
    expect(provisioningBlock).not.toContain('args.participantIds');
  });

  test('login derives runtime policy scope from route auth before worker bootstrap', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_LOGIN_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function loginWithEmailOtpEcdsaCapability',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('if (!workerCtx)', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const loginSetup = source.slice(functionStart, functionEnd);

    expect(loginSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(args.appSessionJwt)');
    expect(loginSetup).toContain('parseThresholdRuntimePolicyScopeFromJwt(routeAuth?.jwt)');
    expect(source).toContain('resolveEmailOtpEcdsaRoleLocalKeyIdentityForHandle({');
    expect(source).toContain('...(runtimePolicyScope ? { runtimePolicyScope } : {})');
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
      'runtimePolicyScope: ed25519ReconstructionPlan.runtimePolicyScope',
    );
    expect(source).toContain(
      'ed25519SessionReconstruction: EmailOtpEd25519SessionReconstructionPlan',
    );
    expect(source).not.toContain('ed25519SessionReconstruction?:');
    expect(source).not.toContain('ed25519SessionReconstruction?.runtimePolicyScope');
    expect(source).toContain('await ports.reconstructEd25519Session(');
    expect(source).toContain('ed25519ReconstructionArgs');
    expect(source).not.toContain('canUseRegistrationEd25519Provisioning');
  });

  test('Ed25519 registration and reconstruction paths are split', () => {
    const source = readFileSync(EMAIL_OTP_PROVISIONING_URL, 'utf8');
    const registrationStart = source.indexOf('export async function registerEmailOtpEd25519Capability');
    const reconstructionStart = source.indexOf(
      'export async function reconstructEmailOtpEd25519Session',
    );
    const helperStart = source.indexOf('function joinUrlPath', reconstructionStart);
    expect(registrationStart).toBeGreaterThan(-1);
    expect(reconstructionStart).toBeGreaterThan(registrationStart);
    expect(helperStart).toBeGreaterThan(reconstructionStart);
    const registrationBlock = source.slice(registrationStart, reconstructionStart);
    const reconstructionBlock = source.slice(reconstructionStart, helperStart);

    expect(registrationBlock).toContain("kind === 'registration_ed25519_companion_provisioning'");
    expect(registrationBlock).toContain('/registration/threshold-ed25519/hss/prepare');
    expect(registrationBlock).toContain('requestManagedRegistrationBootstrapGrant({');
    expect(reconstructionBlock).toContain('ReconstructEmailOtpEd25519SessionArgs');
    expect(reconstructionBlock).toContain('/threshold-ed25519/session');
    expect(reconstructionBlock).not.toContain('/registration/threshold-ed25519/hss/prepare');
    expect(reconstructionBlock).not.toContain('requestManagedRegistrationBootstrapGrant({');
  });

  test('Ed25519 sealed companion links are attached after signer material is persisted', () => {
    const source = readFileSync(EMAIL_OTP_PROVISIONING_URL, 'utf8');
    const registrationStart = source.indexOf('export async function registerEmailOtpEd25519Capability');
    const reconstructionStart = source.indexOf(
      'export async function reconstructEmailOtpEd25519Session',
    );
    const helperStart = source.indexOf('function joinUrlPath', reconstructionStart);
    const registrationBlock = source.slice(registrationStart, reconstructionStart);
    const reconstructionBlock = source.slice(reconstructionStart, helperStart);

    const registrationReadyMaterial = registrationBlock.indexOf(
      'xClientBaseB64u: completed.clientOutput.xClientBaseB64u',
    );
    const registrationAttach = registrationBlock.indexOf(
      'attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({',
    );
    const reconstructionReadyMaterial = reconstructionBlock.indexOf(
      'xClientBaseB64u: completed.clientOutput.xClientBaseB64u',
    );
    const reconstructionAttach = reconstructionBlock.indexOf(
      'attachEd25519SessionToEmailOtpSigningSessionSealBestEffort({',
    );

    expect(registrationReadyMaterial).toBeGreaterThan(-1);
    expect(registrationAttach).toBeGreaterThan(registrationReadyMaterial);
    expect(reconstructionReadyMaterial).toBeGreaterThan(-1);
    expect(reconstructionAttach).toBeGreaterThan(reconstructionReadyMaterial);
  });

  test('SDK Email OTP ECDSA login forwards stored Ed25519 key identity for reconstruction', () => {
    const source = readFileSync(SIGNING_ENGINE_URL, 'utf8');
    const functionStart = source.indexOf('async loginWithEmailOtpEcdsaCapabilityInternal');
    expect(functionStart).toBeGreaterThan(-1);
    const functionEnd = source.indexOf('async requestEmailOtpSigningSessionChallenge', functionStart);
    expect(functionEnd).toBeGreaterThan(functionStart);
    const loginBridge = source.slice(functionStart, functionEnd);

    expect(loginBridge).toContain('getLastLoggedInSignerSlot(walletId, IndexedDBManager.clientDB)');
    expect(loginBridge).toContain('getNearThresholdKeyMaterial(');
    expect(loginBridge).toContain('ed25519SessionReconstruction');
    expect(loginBridge).toContain('relayerKeyId: thresholdKeyMaterial.relayerKeyId');
    expect(loginBridge).toContain('keyVersion: thresholdKeyMaterial.keyVersion');
    expect(loginBridge).toContain('participantIds');
    expect(loginBridge).toContain("'missing_runtime_policy_scope'");
  });
});
