import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

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

async function seedLegacyEmailOtpMapping(service: AuthService, input: {
  providerSubject: string;
  walletId: string;
}): Promise<void> {
  const identity = (service as any).getIdentityStore();
  const enrollmentStore = (service as any).getEmailOtpEnrollmentStore();
  await identity.linkSubjectToUserId({
    userId: input.walletId,
    subject: `wallet:${input.providerSubject}`,
    allowMoveIfSoleIdentity: false,
  });
  await enrollmentStore.put({
    version: 'email_otp_enrollment_v1',
    walletId: input.walletId,
    userId: input.providerSubject,
    otpChannel: 'email_otp',
    emailOtpEscrowBlob: 'escrow',
    emailOtpKeyVersion: 'email-key-v1',
    unlockPublicKey: 'unlock-public',
    unlockKeyVersion: 'unlock-key-v1',
    createdAtMs: 1,
    updatedAtMs: 1,
  });
}

test.describe('hosted Google Email OTP account privacy', () => {
  test('registration does not reuse legacy email-derived wallet mappings', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-legacy-email-wallet';
    await seedLegacyEmailOtpMapping(service, {
      providerSubject,
      walletId: 'alice-example-com-1776502017920.relayer.testnet',
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'alice@example.com',
      accountMode: 'register',
    });

    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('register_started');
    expect(resolved.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(resolved.walletId).not.toContain('alice');
    expect(resolved.walletId).not.toContain('example');
  });

  test('login does not accept legacy email-derived wallet mappings', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-legacy-login';
    await seedLegacyEmailOtpMapping(service, {
      providerSubject,
      walletId: 'alice-example-com.relayer.testnet',
    });

    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject,
        email: 'alice@example.com',
        accountMode: 'login',
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
    });
  });

  test('registration discards legacy resumable attempts before allocating an HMAC-readable wallet', async () => {
    const service = makeService();
    const attemptStore = (service as any).getEmailOtpRegistrationAttemptStore();
    const providerSubject = 'google:subject-legacy-attempt';
    await attemptStore.put({
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: 'legacy-attempt',
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
    });

    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('register_started');
    expect(resolved.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(resolved.registrationAttemptId).not.toBe('legacy-attempt');

    await expect(attemptStore.get('legacy-attempt')).resolves.toMatchObject({
      state: 'failed',
      failureCode: 'legacy_email_derived_wallet_id',
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
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(first.mode).toBe('register_started');

    const second = await service.resolveGoogleEmailOtpSession({
      providerSubject,
      email: 'reroll@example.com',
      accountMode: 'register',
      rerollRegistrationAttempt: true,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.mode).toBe('register_started');
    expect(second.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(second.walletId).not.toBe(first.walletId);
    expect(second.registrationAttemptId).not.toBe(first.registrationAttemptId);

    await expect(attemptStore.get(first.registrationAttemptId)).resolves.toMatchObject({
      state: 'failed',
      failureCode: 'rerolled_by_user',
    });
  });
});
