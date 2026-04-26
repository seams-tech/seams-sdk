import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_hosted_account_privacy_tests';
const RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project_hosted_account_privacy_tests',
  envId: 'dev',
  signingRootVersion: 'default',
} as const;

function makeService(): AuthService {
  process.env.ACCOUNT_ID_DERIVATION_SECRET ||= 'test-account-id-derivation-secret';
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });
}

async function seedNonHostedEmailOtpMapping(
  service: AuthService,
  input: {
    providerSubject: string;
    walletId: string;
  },
): Promise<void> {
  const identity = (service as any).getIdentityStore();
  const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
  await identity.linkSubjectToUserId({
    userId: input.walletId,
    subject: `wallet:${input.providerSubject}`,
    allowMoveIfSoleIdentity: false,
  });
  await enrollmentStore.put({
    version: 'email_otp_wallet_enrollment_v1',
    walletId: input.walletId,
    providerUserId: input.providerSubject,
    orgId: ORG_ID,
    verifiedEmail: 'active@example.com',
    enrollmentId: `email-otp-device-enrollment-v1:${input.walletId}:${input.providerSubject}`,
    enrollmentVersion: '1',
    enrollmentSealKeyVersion: 'email-key-v1',
    signingRootId: 'email_otp_default_signing_root',
    signingRootVersion: 'default',
    recoveryWrappedEnrollmentEscrowCount: 10,
    clientUnlockPublicKeyB64u: 'unlock-public',
    unlockKeyVersion: 'unlock-key-v1',
    thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
    createdAtMs: 1,
    updatedAtMs: 1,
  });
}

test.describe('hosted Google Email OTP account privacy', () => {
  test('registration does not reuse non-HMAC-readable email-derived wallet mappings', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-non-hmac-email-wallet';
    await seedNonHostedEmailOtpMapping(service, {
      providerSubject,
      walletId: 'alice-example-com-1776502017920.relayer.testnet',
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'alice@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });

    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('register_started');
    if (resolved.mode !== 'register_started') return;
    expect(resolved.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(resolved.walletId).not.toContain('alice');
    expect(resolved.walletId).not.toContain('example');
  });

  test('login does not accept non-HMAC-readable email-derived wallet mappings', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-non-hmac-login';
    await seedNonHostedEmailOtpMapping(service, {
      providerSubject,
      walletId: 'alice-example-com.relayer.testnet',
    });

    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject,
        email: 'alice@example.com',
        accountMode: 'login',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  test('registration discards non-HMAC-readable resumable attempts before allocating an HMAC-readable wallet', async () => {
    const service = makeService();
    const attemptStore = (service as any).getEmailOtpRegistrationAttemptStore();
    const providerSubject = 'google:subject-non-hmac-attempt';
    await attemptStore.put({
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: 'non-hmac-attempt',
      providerSubject,
      email: 'alice@example.com',
      walletId: 'alice-example-com-1776502017920.relayer.testnet',
      authProvider: 'google_oidc',
      accountIdSlugVersion: 'hmac_readable_v1',
      collisionCounter: 0,
      state: 'started',
      createdAtMs: Date.now(),
      updatedAtMs: Date.now(),
      expiresAtMs: Date.now() + 30 * 60 * 1000,
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'alice@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });

    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('register_started');
    if (resolved.mode !== 'register_started') return;
    expect(resolved.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(resolved.registrationAttemptId).not.toBe('non-hmac-attempt');

    await expect(attemptStore.get('non-hmac-attempt')).resolves.toMatchObject({
      state: 'failed',
      failureCode: 'non_hmac_readable_wallet_id',
    });
  });

  test('registration reroll retires the current attempt and allocates a different HMAC-readable wallet', async () => {
    const service = makeService();
    const attemptStore = (service as any).getEmailOtpRegistrationAttemptStore();
    const providerSubject = 'google:subject-reroll';

    const first = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.mode).toBe('register_started');
    if (first.mode !== 'register_started') return;

    const second = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll@example.com',
      accountMode: 'register',
      rerollRegistrationAttempt: true,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.mode).toBe('register_started');
    if (second.mode !== 'register_started') return;
    expect(second.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(second.walletId).not.toBe(first.walletId);
    expect(second.registrationAttemptId).not.toBe(first.registrationAttemptId);

    await expect(attemptStore.get(first.registrationAttemptId)).resolves.toMatchObject({
      state: 'failed',
      failureCode: 'rerolled_by_user',
    });
  });

  test('registration reroll can allocate a new wallet when the Google account already has an Email OTP wallet', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-reroll-existing';
    const first = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll-existing@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(first.ok).toBe(true);
    if (!first.ok || first.mode !== 'register_started') return;

    const identity = (service as any).getIdentityStore();
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    await identity.linkSubjectToUserId({
      userId: first.walletId,
      subject: `wallet:${providerSubject}`,
      allowMoveIfSoleIdentity: false,
    });
    await enrollmentStore.put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: first.walletId,
      providerUserId: providerSubject,
      orgId: ORG_ID,
      verifiedEmail: 'reroll-existing@example.com',
      enrollmentId: `email-otp-device-enrollment-v1:${first.walletId}:${providerSubject}`,
      enrollmentVersion: '1',
      enrollmentSealKeyVersion: 'email-key-v1',
      signingRootId: 'email_otp_default_signing_root',
      signingRootVersion: 'default',
      recoveryWrappedEnrollmentEscrowCount: 10,
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const existing = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll-existing@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(existing.ok).toBe(true);
    if (!existing.ok) return;
    expect(existing.mode).toBe('existing_wallet');
    expect(existing.walletId).toBe(first.walletId);

    const rerolled = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll-existing@example.com',
      accountMode: 'register',
      rerollRegistrationAttempt: true,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(rerolled.ok).toBe(true);
    if (!rerolled.ok) return;
    expect(rerolled.mode).toBe('register_started');
    if (rerolled.mode !== 'register_started') return;
    expect(rerolled.walletId).not.toBe(first.walletId);
    expect(rerolled.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
  });
});
