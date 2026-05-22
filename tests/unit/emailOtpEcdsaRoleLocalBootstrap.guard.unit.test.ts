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

  test('login forwards parsed runtime policy scope into companion Ed25519 provisioning', () => {
    const source = readFileSync(EMAIL_OTP_ECDSA_LOGIN_URL, 'utf8');
    const provisioningArgsStart = source.indexOf('const ed25519ProvisioningArgs');
    expect(provisioningArgsStart).toBeGreaterThan(-1);
    const provisioningArgsEnd = source.indexOf('};', provisioningArgsStart);
    expect(provisioningArgsEnd).toBeGreaterThan(provisioningArgsStart);
    const provisioningArgs = source.slice(provisioningArgsStart, provisioningArgsEnd);

    expect(provisioningArgs).toContain('...(runtimePolicyScope ? { runtimePolicyScope } : {})');
    expect(provisioningArgs).not.toContain(
      '...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {})',
    );
  });

  test('Ed25519 companion provisioning does not spend registration grants during unlock', () => {
    const source = readFileSync(EMAIL_OTP_PROVISIONING_URL, 'utf8');
    const functionStart = source.indexOf(
      'export async function provisionEmailOtpEd25519Capability',
    );
    expect(functionStart).toBeGreaterThan(-1);
    const grantRequestStart = source.indexOf(
      'requestManagedRegistrationBootstrapGrant({',
      functionStart,
    );
    expect(grantRequestStart).toBeGreaterThan(functionStart);
    const preGrantBlock = source.slice(functionStart, grantRequestStart);

    expect(preGrantBlock).toContain('parseThresholdRuntimePolicyScopeFromJwt(input.appSessionJwt)');
    expect(preGrantBlock).toContain('parseThresholdRuntimePolicyScopeFromJwt(input.routeAuth?.jwt)');
    expect(preGrantBlock).toContain(
      'const registrationGrantAdmission = resolveRegistrationGrantAdmission(input);',
    );
    expect(preGrantBlock).toContain(
      "registrationGrantAdmission.kind === 'registration_grant_admitted'",
    );
    expect(source).toContain(
      "if (registrationGrantAdmission.kind === 'registration_grant_forbidden')",
    );
    expect(source).toContain(
      'Email OTP threshold-ed25519 registration bootstrap requires a registration attempt',
    );
  });
});
