import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import {
  WALLET_EMAIL_OTP_ACTIONS,
  WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
  WALLET_EMAIL_OTP_UNLOCK_OPERATION,
} from '@shared/utils/emailOtpDomain';
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

function directRegistrationChallengeProof(input: {
  providerSubject: string;
  proofEmail: string;
  challengeId: string;
  finalWalletId: string;
  appSessionVersion: string;
}) {
  return {
    kind: 'direct_proof_email',
    providerSubject: input.providerSubject,
    challengeSubjectId: input.providerSubject,
    proofEmail: input.proofEmail,
    challengeId: input.challengeId,
    finalWalletId: input.finalWalletId,
    orgId: ORG_ID,
    appSessionVersion: input.appSessionVersion,
  };
}

test.describe('hosted Google Email OTP account privacy', () => {
  test('registration fails closed on non-HMAC-readable email-derived wallet mappings', async () => {
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

    expect(resolved).toMatchObject({
      ok: false,
      mode: 'stale_identity_mapping',
      code: 'stale_identity_mapping',
      walletId: 'alice-example-com-1776502017920.relayer.testnet',
      providerSubject,
    });
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
      code: 'stale_identity_mapping',
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
      walletIdDerivationNonce: 'seededNonceA0123456789',
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

    const failedFirstAttempt = await attemptStore.get(first.registrationAttemptId);
    const secondAttempt = await attemptStore.get(second.registrationAttemptId);
    expect(failedFirstAttempt).toMatchObject({
      state: 'failed',
      failureCode: 'rerolled_by_user',
    });
    expect(secondAttempt).toMatchObject({
      walletId: second.walletId,
      walletIdDerivationNonce: expect.any(String),
      collisionCounter: 0,
    });
    if (!failedFirstAttempt || !secondAttempt) return;
    expect(secondAttempt.walletIdDerivationNonce).not.toBe(
      failedFirstAttempt.walletIdDerivationNonce,
    );
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
    await expect(
      (service as any).getEmailOtpRegistrationAttemptStore().get(rerolled.registrationAttemptId),
    ).resolves.toMatchObject({
      walletId: rerolled.walletId,
      walletIdDerivationNonce: expect.any(String),
      collisionCounter: 0,
    });
  });

  test('registration OTP challenge survives wallet id reroll for the same Google email', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-otp',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-Otp@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);
    expect(challengeRecord).toMatchObject({
      challengeSubjectId: 'google:subject-registration-reroll-otp',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      email: 'reroll-otp@example.com',
    });

    const verified = await (service as any).verifyEmailOtpChallengeCode({
      challengeSubjectId: 'google:subject-registration-reroll-otp',
      registrationChallengeProof: directRegistrationChallengeProof({
        providerSubject: 'google:subject-registration-reroll-otp',
        proofEmail: 'reroll-otp@example.com',
        challengeId: challenge.challenge.challengeId,
        finalWalletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        appSessionVersion: 'google-app-session-v1',
      }),
      walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      orgId: ORG_ID,
      challengeId: challenge.challenge.challengeId,
      otpCode: challengeRecord.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'rerolled-registration-intent-digest',
      appSessionVersion: 'google-app-session-v1',
      expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
      expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
    });
    expect(verified).toMatchObject({
      ok: true,
      walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
      email: 'reroll-otp@example.com',
    });
  });

  test('register-mode reroll can reuse an existing-wallet login OTP for the same Google subject', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-registration-reroll-from-login';
    const existingWalletId = 'spruce-plain-cps1f80m3a.w3a-relayer.testnet';
    await seedNonHostedEmailOtpMapping(service, {
      providerSubject,
      walletId: existingWalletId,
    });

    const challenge = await service.createEmailOtpChallenge({
      userId: providerSubject,
      walletId: existingWalletId,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      sessionHash: 'existing-wallet-login-session-hash',
      appSessionVersion: 'google-app-session-v1',
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    expect(challenge.challenge).toMatchObject({
      action: WALLET_EMAIL_OTP_ACTIONS.login,
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: providerSubject,
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject,
          proofEmail: 'active@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        allowRegistrationChallengeReroll: true,
        walletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
      email: 'active@example.com',
    });
  });

  test('register-mode reroll rejects existing-wallet login OTP when reroll bridge is not allowed', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-registration-reroll-disallowed';
    const existingWalletId = 'spruce-plain-cps1f80m3a.w3a-relayer.testnet';
    await seedNonHostedEmailOtpMapping(service, {
      providerSubject,
      walletId: existingWalletId,
    });

    const challenge = await service.createEmailOtpChallenge({
      userId: providerSubject,
      walletId: existingWalletId,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      sessionHash: 'existing-wallet-login-session-hash',
      appSessionVersion: 'google-app-session-v1',
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: providerSubject,
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject,
          proofEmail: 'active@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        walletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'registration_reroll_disallowed',
    });
  });

  test('register-mode reroll rejects existing-wallet login OTP without matching proof email', async () => {
    const service = makeService();
    const providerSubject = 'google:subject-registration-reroll-from-login-email-mismatch';
    const existingWalletId = 'spruce-plain-cps1f80m3a.w3a-relayer.testnet';
    await seedNonHostedEmailOtpMapping(service, {
      providerSubject,
      walletId: existingWalletId,
    });

    const challenge = await service.createEmailOtpChallenge({
      userId: providerSubject,
      walletId: existingWalletId,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      sessionHash: 'existing-wallet-login-session-hash',
      appSessionVersion: 'google-app-session-v1',
      operation: WALLET_EMAIL_OTP_UNLOCK_OPERATION,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: providerSubject,
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject,
          proofEmail: 'other@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        allowRegistrationChallengeReroll: true,
        walletId: 'steady-lake-1p5it43hyd.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_email_mismatch',
    });
  });

  test('registration OTP reroll exemption follows the Google provider subject', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-otp-mismatch',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-Otp@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: 'google:subject-registration-reroll-otp-mismatch',
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject: 'google:subject-registration-reroll-otp-mismatch',
          proofEmail: 'reroll-otp@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        allowRegistrationChallengeReroll: true,
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
    });
  });

  test('registration OTP reroll exemption requires a registration challenge proof', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-no-proof',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-No-Proof@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: 'google:subject-registration-reroll-no-proof',
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
    });
  });

  test('registration OTP reroll exemption rejects proof challenge id mismatch', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-challenge-id',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-Otp@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: 'google:subject-registration-reroll-challenge-id',
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject: 'google:subject-registration-reroll-challenge-id',
          proofEmail: 'reroll-otp@example.com',
          challengeId: 'different-challenge-id',
          finalWalletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        allowRegistrationChallengeReroll: true,
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_id_mismatch',
    });
  });

  test('registration OTP reroll exemption rejects provider subject mismatch', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-otp-provider',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-Otp@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: 'google:different-subject',
        registrationChallengeProof: directRegistrationChallengeProof({
          providerSubject: 'google:different-subject',
          proofEmail: 'reroll-otp@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
          appSessionVersion: 'google-app-session-v1',
        }),
        allowRegistrationChallengeReroll: true,
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        orgId: ORG_ID,
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_subject_mismatch',
    });
  });

  test('registration OTP reroll exemption still rejects org mismatch', async () => {
    const service = makeService();
    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: 'google:subject-registration-reroll-explicit',
      walletId: 'spruce-plain-cps1f80m3a.w3a-relayer.testnet',
      orgId: ORG_ID,
      email: 'Reroll-Otp@Example.com',
      otpChannel: 'email_otp',
      sessionHash: 'initial-app-session-hash',
      appSessionVersion: 'google-app-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    const challengeRecord = await (service as any)
      .getEmailOtpChallengeStore()
      .get(challenge.challenge.challengeId);

    await expect(
      (service as any).verifyEmailOtpChallengeCode({
        challengeSubjectId: 'google:subject-registration-reroll-explicit',
        walletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
        orgId: 'org_other_tenant',
        challengeId: challenge.challenge.challengeId,
        otpCode: challengeRecord.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'rerolled-registration-intent-digest',
        appSessionVersion: 'google-app-session-v1',
        expectedAction: WALLET_EMAIL_OTP_ACTIONS.registration,
        expectedOperation: WALLET_EMAIL_OTP_REGISTRATION_OPERATION,
        registrationChallengeProof: {
          kind: 'direct_proof_email',
          providerSubject: 'google:subject-registration-reroll-explicit',
          challengeSubjectId: 'google:subject-registration-reroll-explicit',
          proofEmail: 'reroll-otp@example.com',
          challengeId: challenge.challenge.challengeId,
          finalWalletId: 'cobalt-meadow-35whhdqoua.w3a-relayer.testnet',
          orgId: 'org_other_tenant',
          appSessionVersion: 'google-app-session-v1',
        },
        allowRegistrationChallengeReroll: true,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_org_mismatch',
    });
  });
});
