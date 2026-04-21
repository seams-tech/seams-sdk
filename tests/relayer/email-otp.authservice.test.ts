import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import {
  createEmailOtpChallengeStore,
  createEmailOtpWalletEnrollmentStore,
  createEmailOtpGrantStore,
  createEmailOtpUnlockChallengeStore,
} from '@server/core/EmailOtpStores';
import { base64UrlEncode } from '@shared/utils/encoders';
import { ensurePostgresSchema, getPostgresPool } from '../../server/src/storage/postgres';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const EMAIL_OTP_KEY_VERSION = 'kek-s-email-otp-test';
const VALID_SECP256K1_PUBLIC_KEY_33_B64U = base64UrlEncode(
  Uint8Array.from(
    Buffer.from(
      '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      'hex',
    ),
  ),
);
const USER_ID = 'alice.testnet';
const WALLET_ID = 'alice.testnet';
const ORG_ID = 'org_email_otp_authservice';
const EMAIL = 'alice@example.com';
const SESSION_HASH = 'session-hash-v1';
const APP_SESSION_VERSION = 'app-session-v1';
const EMAIL_OTP_RATE_LIMIT_ENV_UNSET: Record<string, string | undefined> = {
  EMAIL_OTP_RATE_LIMITER_KIND: undefined,
  EMAIL_OTP_RATE_LIMIT_REDIS_URL: undefined,
  EMAIL_OTP_RATE_LIMIT_UPSTASH_URL: undefined,
  EMAIL_OTP_RATE_LIMIT_UPSTASH_TOKEN: undefined,
  EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX: undefined,
  EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS: undefined,
  EMAIL_OTP_VERIFY_RATE_LIMIT_MAX: undefined,
  EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS: undefined,
  EMAIL_OTP_GRANT_RATE_LIMIT_MAX: undefined,
  EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS: undefined,
  EMAIL_OTP_RATE_LIMIT_KEY_PREFIX: undefined,
  EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT: undefined,
};

function randPrefix(tag: string): string {
  return `test:${tag}:${Date.now()}:${Math.random().toString(16).slice(2)}:`;
}

function makeService(): AuthService {
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

function makeCapturingLogger(): {
  logger: {
    info: (...args: unknown[]) => void;
    warn: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
    debug: (...args: unknown[]) => void;
  };
  entries: Array<{ level: string; args: unknown[] }>;
} {
  const entries: Array<{ level: string; args: unknown[] }> = [];
  return {
    logger: {
      info: (...args: unknown[]) => entries.push({ level: 'info', args }),
      warn: (...args: unknown[]) => entries.push({ level: 'warn', args }),
      error: (...args: unknown[]) => entries.push({ level: 'error', args }),
      debug: (...args: unknown[]) => entries.push({ level: 'debug', args }),
    },
    entries,
  };
}

function makeServiceWithLogger(logger: {
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  debug: (...args: unknown[]) => void;
}): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger,
    thresholdStore: {
      SIGNING_SESSION_SEAL_KEY_VERSION: EMAIL_OTP_KEY_VERSION,
      SIGNING_SESSION_SHAMIR_P_B64U: base64UrlEncode(Uint8Array.from([0x01, 0x01])),
      SIGNING_SESSION_SEAL_E_S_B64U: base64UrlEncode(Uint8Array.from([0x03])),
      SIGNING_SESSION_SEAL_D_S_B64U: base64UrlEncode(Uint8Array.from([0xab])),
    },
  });
}

async function withEnv<T>(
  overrides: Record<string, string | undefined>,
  fn: () => Promise<T>,
): Promise<T> {
  const env = (globalThis as any)?.process?.env as Record<string, string | undefined>;
  const previous = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(overrides)) {
    previous.set(key, env[key]);
    if (value === undefined) delete env[key];
    else env[key] = value;
  }
  try {
    return await fn();
  } finally {
    for (const [key, value] of previous.entries()) {
      if (value === undefined) delete env[key];
      else env[key] = value;
    }
  }
}

async function createEmailOtpLoginChallenge(service: AuthService): Promise<{
  challengeId: string;
  otpCode: string;
  expiresAtMs: number;
}> {
  await seedEmailOtpEnrollment(service);
  const challenge = await service.createEmailOtpChallenge({
    userId: USER_ID,
    walletId: WALLET_ID,
    orgId: ORG_ID,
    email: EMAIL,
    otpChannel: 'email_otp',
    sessionHash: SESSION_HASH,
    appSessionVersion: APP_SESSION_VERSION,
  });
  expect(challenge.ok).toBe(true);
  const challengeId = challenge.ok ? challenge.challenge.challengeId : '';
  const outbox = await service.readEmailOtpOutboxEntry({
    challengeId,
    userId: USER_ID,
    walletId: WALLET_ID,
  });
  expect(outbox.ok).toBe(true);
  return {
    challengeId,
    otpCode: outbox.ok ? outbox.otpCode : '',
    expiresAtMs: outbox.ok ? outbox.expiresAtMs : 0,
  };
}

async function seedEmailOtpEnrollment(service: AuthService): Promise<void> {
  const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
  const existing = await enrollmentStore.get(WALLET_ID);
  if (existing) return;
  const nowMs = Date.now();
  await enrollmentStore.put({
    version: 'email_otp_wallet_enrollment_v1',
    walletId: WALLET_ID,
    providerUserId: USER_ID,
    orgId: ORG_ID,
    verifiedEmail: EMAIL,
    enrollmentEscrowCiphertextB64u: 'recovery-escrow-blob',
    enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
    clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
    unlockKeyVersion: 'email-otp-unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
  });
}

async function consumeEmailOtpChallengeRateLimit(service: AuthService, clientIp: string) {
  return (service as any).consumeEmailOtpRateLimit({
    scope: 'challenge',
    action: 'wallet_email_otp_login',
    userId: USER_ID,
    walletId: WALLET_ID,
    clientIp,
  });
}

async function enrollRecoveryWallet(service: AuthService): Promise<void> {
  const challenge = await service.createEmailOtpEnrollmentChallenge({
    userId: USER_ID,
    walletId: WALLET_ID,
    orgId: ORG_ID,
    email: EMAIL,
    otpChannel: 'email_otp',
    sessionHash: SESSION_HASH,
    appSessionVersion: APP_SESSION_VERSION,
  });
  expect(challenge.ok).toBe(true);
  const challengeId = challenge.ok ? challenge.challenge.challengeId : '';
  const outbox = await service.readEmailOtpOutboxEntry({
    challengeId,
    userId: USER_ID,
    walletId: WALLET_ID,
  });
  expect(outbox.ok).toBe(true);
  const verified = await service.verifyEmailOtpEnrollment({
    userId: USER_ID,
    walletId: WALLET_ID,
    orgId: ORG_ID,
    challengeId,
    otpCode: outbox.ok ? outbox.otpCode : '',
    otpChannel: 'email_otp',
    sessionHash: SESSION_HASH,
    appSessionVersion: APP_SESSION_VERSION,
    enrollmentEscrowCiphertextB64u: 'recovery-escrow-blob',
    enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
    clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
    unlockKeyVersion: 'email-otp-unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
  });
  expect(verified.ok).toBe(true);
}

async function withMockedNow<T>(startMs: number, fn: (setNowMs: (nextMs: number) => void) => Promise<T>): Promise<T> {
  const originalDateNow = Date.now;
  let nowMs = startMs;
  Date.now = () => nowMs;
  try {
    return await fn((nextMs) => {
      nowMs = nextMs;
    });
  } finally {
    Date.now = originalDateNow;
  }
}

test.describe('AuthService Email OTP policy', () => {
  test('Email OTP login challenge requires a completed enrollment', async () => {
    const service = makeService();
    const missingEnrollmentChallenge = await service.createEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: EMAIL,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(missingEnrollmentChallenge.ok).toBe(false);
    if (missingEnrollmentChallenge.ok) return;
    expect(missingEnrollmentChallenge.code).toBe('not_found');

    const missingEnrollmentVerify = await service.verifyEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      challengeId: 'missing-challenge',
      otpCode: '123456',
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(missingEnrollmentVerify.ok).toBe(false);
    if (missingEnrollmentVerify.ok) return;
    expect(missingEnrollmentVerify.code).toBe('not_found');

    await seedEmailOtpEnrollment(service);
    const enrolledChallenge = await service.createEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: EMAIL,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(enrolledChallenge.ok).toBe(true);
  });

  test('Email OTP enrollment reads require tenant scope', async () => {
    const service = makeService();
    await seedEmailOtpEnrollment(service);

    const missingOrg = await service.readEmailOtpEnrollment({ walletId: WALLET_ID } as any);
    expect(missingOrg.ok).toBe(false);
    expect(missingOrg.ok ? '' : missingOrg.code).toBe('invalid_body');
    expect(missingOrg.ok ? '' : missingOrg.message).toBe('Missing orgId');

    const wrongOrg = await service.readEmailOtpEnrollment({
      walletId: WALLET_ID,
      orgId: 'org_other',
    });
    expect(wrongOrg.ok).toBe(false);
    expect(wrongOrg.ok ? '' : wrongOrg.code).toBe('tenant_scope_mismatch');

    const activeMissingOrg = await service.readActiveEmailOtpEnrollment({
      walletId: WALLET_ID,
    } as any);
    expect(activeMissingOrg.ok).toBe(false);
    expect(activeMissingOrg.ok ? '' : activeMissingOrg.code).toBe('invalid_body');

    const active = await service.readActiveEmailOtpEnrollment({
      walletId: WALLET_ID,
      orgId: ORG_ID,
      providerUserId: USER_ID,
    });
    expect(active.ok).toBe(true);
  });

  test('Email OTP login challenges bind export_key operation through verification', async () => {
    const service = makeService();
    await seedEmailOtpEnrollment(service);
    const challenge = await service.createEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: EMAIL,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
      operation: 'export_key',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) return;
    expect(challenge.challenge.operation).toBe('export_key');

    const outbox = await service.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: USER_ID,
      walletId: WALLET_ID,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) return;

    const wrongOperation = await service.verifyEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
      operation: 'transaction_sign',
    });
    expect(wrongOperation.ok).toBe(false);
    if (wrongOperation.ok) return;
    expect(wrongOperation.code).toBe('challenge_binding_mismatch');

    const verified = await service.verifyEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
      operation: 'export_key',
    });
    expect(verified.ok).toBe(true);
  });

  test('Email OTP enrollment rejects missing verified email and login never repairs it', async () => {
    const service = makeService();
    const nowMs = Date.now();
    await expect((service as any).getEmailOtpWalletEnrollmentStore().put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: WALLET_ID,
      providerUserId: USER_ID,
      orgId: ORG_ID,
      verifiedEmail: '',
      enrollmentEscrowCiphertextB64u: 'invalid-recovery-escrow-blob',
      enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
      clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
    })).rejects.toThrow('Invalid Email OTP wallet enrollment record');

    const challenge = await service.createEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: EMAIL,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(challenge.ok).toBe(false);
    expect(challenge.ok ? '' : challenge.code).toBe('not_found');

    await (service as any).getEmailOtpChallengeStore().put({
      version: 'email_otp_challenge_v1',
      challengeId: 'login-challenge-with-email',
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      otpChannel: 'email_otp',
      email: EMAIL,
      otpCode: '123456',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
      createdAtMs: nowMs,
      expiresAtMs: nowMs + 60_000,
      attemptCount: 0,
      maxAttempts: 3,
    });

    const verified = await service.verifyEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      challengeId: 'login-challenge-with-email',
      otpCode: '123456',
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(verified.ok).toBe(false);
    expect(verified.ok ? '' : verified.code).toBe('not_found');

    const enrollment = await service.readEmailOtpEnrollment({ walletId: WALLET_ID, orgId: ORG_ID });
    expect(enrollment.ok).toBe(false);
  });

  test('Email OTP login challenge ignores app-session email after enrollment has a verified mailbox', async () => {
    const service = makeService();
    await seedEmailOtpEnrollment(service);
    const changedEmailChallenge = await service.createEmailOtpChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: 'changed@example.com',
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(changedEmailChallenge.ok).toBe(true);
    if (!changedEmailChallenge.ok) return;
    expect(
      (service as any).emailOtpMemoryOutbox.get(changedEmailChallenge.challenge.challengeId)?.email,
    ).toBe(EMAIL);
    const unchangedEnrollment = await service.readEmailOtpEnrollment({
      walletId: WALLET_ID,
      orgId: ORG_ID,
    });
    expect(unchangedEnrollment.ok).toBe(true);
    expect(unchangedEnrollment.ok && unchangedEnrollment.enrollment.verifiedEmail).toBe(EMAIL);
  });

  test('Email OTP resend accepts any active matching code for the same context', async () => {
    const service = makeService();
    await withMockedNow(800_000, async () => {
      const first = await createEmailOtpLoginChallenge(service);
      const second = await createEmailOtpLoginChallenge(service);

      const verifiedFirstViaLatestChallenge = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: first.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verifiedFirstViaLatestChallenge.ok).toBe(true);
      if (!verifiedFirstViaLatestChallenge.ok) return;
      expect(verifiedFirstViaLatestChallenge.challengeId).toBe(first.challengeId);

      const verifiedSecond = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: second.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verifiedSecond.ok).toBe(true);
      if (!verifiedSecond.ok) return;
      expect(verifiedSecond.challengeId).toBe(second.challengeId);
    });
  });

  test('Email OTP resend does not accept expired older codes while newer code remains valid', async () => {
    const service = makeService();
    await withMockedNow(1_000_000, async (setNowMs) => {
      const first = await createEmailOtpLoginChallenge(service);
      setNowMs(first.expiresAtMs + 1);
      const second = await createEmailOtpLoginChallenge(service);

      const expiredOlderCode = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: first.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(expiredOlderCode.ok).toBe(false);

      const verifiedSecond = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: second.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verifiedSecond.ok).toBe(true);
    });
  });

  test('Email OTP resend cannot reuse an active code across app-session bindings', async () => {
    const service = makeService();
    await withMockedNow(850_000, async () => {
      const first = await createEmailOtpLoginChallenge(service);
      const second = await createEmailOtpLoginChallenge(service);

      const wrongSession = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: first.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: `${APP_SESSION_VERSION}:other`,
      });
      expect(wrongSession.ok).toBe(false);
      if (wrongSession.ok) return;
      expect(wrongSession.code).toBe('challenge_binding_mismatch');

      const verifiedFirst = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: second.challengeId,
        otpCode: first.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verifiedFirst.ok).toBe(true);
    });
  });

  test('Email OTP challenge creation prunes the oldest active challenge past the context cap', async () => {
    await withEnv(
      {
        EMAIL_OTP_MAX_ACTIVE_CHALLENGES_PER_CONTEXT: '2',
      },
      async () => {
        const service = makeService();
        await withMockedNow(900_000, async (setNowMs) => {
          const first = await createEmailOtpLoginChallenge(service);
          setNowMs(901_000);
          const second = await createEmailOtpLoginChallenge(service);
          setNowMs(902_000);
          const third = await createEmailOtpLoginChallenge(service);

          const prunedFirst = await service.verifyEmailOtpChallenge({
            userId: USER_ID,
            walletId: WALLET_ID,
            orgId: ORG_ID,
            challengeId: third.challengeId,
            otpCode: first.otpCode,
            otpChannel: 'email_otp',
            sessionHash: SESSION_HASH,
            appSessionVersion: APP_SESSION_VERSION,
          });
          expect(prunedFirst.ok).toBe(false);

          const verifiedSecond = await service.verifyEmailOtpChallenge({
            userId: USER_ID,
            walletId: WALLET_ID,
            orgId: ORG_ID,
            challengeId: third.challengeId,
            otpCode: second.otpCode,
            otpChannel: 'email_otp',
            sessionHash: SESSION_HASH,
            appSessionVersion: APP_SESSION_VERSION,
          });
          expect(verifiedSecond.ok).toBe(true);

          const verifiedThird = await service.verifyEmailOtpChallenge({
            userId: USER_ID,
            walletId: WALLET_ID,
            orgId: ORG_ID,
            challengeId: third.challengeId,
            otpCode: third.otpCode,
            otpChannel: 'email_otp',
            sessionHash: SESSION_HASH,
            appSessionVersion: APP_SESSION_VERSION,
          });
          expect(verifiedThird.ok).toBe(true);
        });
      },
    );
  });

  test.describe('Postgres durable stores', () => {
    const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
    const enabled = Boolean(postgresUrl);
    const emailOtpPrefix = randPrefix('email-otp:pg');

    test.beforeAll(async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      await ensurePostgresSchema({ postgresUrl, logger: console as any });
    });

    test.afterAll(async () => {
      if (!enabled) return;
      const pool = await getPostgresPool(postgresUrl);
      await pool.query('DELETE FROM email_otp_challenges WHERE namespace = $1', [emailOtpPrefix]);
      await pool.query('DELETE FROM email_otp_grants WHERE namespace = $1', [emailOtpPrefix]);
      await pool.query('DELETE FROM email_otp_wallet_enrollments WHERE namespace = $1', [
        emailOtpPrefix,
      ]);
      await pool.query('DELETE FROM email_otp_unlock_challenges WHERE namespace = $1', [
        emailOtpPrefix,
      ]);
    });

    test('persists challenge, grant, enrollment, and unlock state across store instances', async () => {
      test.skip(!enabled, 'POSTGRES_URL not set');
      const config = {
        kind: 'postgres',
        POSTGRES_URL: postgresUrl,
        EMAIL_OTP_PREFIX: emailOtpPrefix,
      } as any;
      const storeInput = { config, logger: console as any, isNode: true };
      const nowMs = Date.now();
      const expiresAtMs = nowMs + 60_000;

      const challengeWriter = createEmailOtpChallengeStore(storeInput);
      const challengeReader = createEmailOtpChallengeStore(storeInput);
      await challengeWriter.put({
        version: 'email_otp_challenge_v1',
        challengeId: 'challenge-pg',
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        otpChannel: 'email_otp',
        email: EMAIL,
        otpCode: '169670',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
        action: 'wallet_email_otp_registration',
        operation: 'registration',
        createdAtMs: nowMs,
        expiresAtMs,
        attemptCount: 0,
        maxAttempts: 5,
      });
      const persistedChallenge = await challengeReader.get('challenge-pg');
      expect(persistedChallenge?.otpCode).toBe('169670');
      await challengeReader.del('challenge-pg');
      expect(await challengeWriter.get('challenge-pg')).toBeNull();

      const grantWriter = createEmailOtpGrantStore(storeInput);
      const grantReader = createEmailOtpGrantStore(storeInput);
      await grantWriter.put({
        version: 'email_otp_grant_v1',
        grantToken: 'grant-pg',
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: 'challenge-pg',
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
        action: 'wallet_email_otp_unseal',
        issuedAtMs: nowMs,
        expiresAtMs,
      });
      expect((await grantReader.consume('grant-pg'))?.challengeId).toBe('challenge-pg');
      expect(await grantWriter.consume('grant-pg')).toBeNull();

      const enrollmentWriter = createEmailOtpWalletEnrollmentStore(storeInput);
      const enrollmentReader = createEmailOtpWalletEnrollmentStore(storeInput);
      await enrollmentWriter.put({
        version: 'email_otp_wallet_enrollment_v1',
        walletId: WALLET_ID,
        providerUserId: USER_ID,
        orgId: ORG_ID,
        verifiedEmail: EMAIL,
        enrollmentEscrowCiphertextB64u: 'escrow-blob',
        enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
        clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
        unlockKeyVersion: 'unlock-v1',
        thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
      });
      expect((await enrollmentReader.get(WALLET_ID))?.enrollmentEscrowCiphertextB64u).toBe('escrow-blob');
      await enrollmentReader.del(WALLET_ID);
      expect(await enrollmentWriter.get(WALLET_ID)).toBeNull();

      const unlockWriter = createEmailOtpUnlockChallengeStore(storeInput);
      const unlockReader = createEmailOtpUnlockChallengeStore(storeInput);
      await unlockWriter.put({
        version: 'email_otp_unlock_challenge_v1',
        challengeId: 'unlock-pg',
        walletId: WALLET_ID,
        userId: USER_ID,
        challengeB64u: base64UrlEncode(Uint8Array.from([1, 2, 3, 4])),
        createdAtMs: nowMs,
        expiresAtMs,
      });
      expect((await unlockReader.consume('unlock-pg'))?.walletId).toBe(WALLET_ID);
      expect(await unlockWriter.consume('unlock-pg')).toBeNull();
    });
  });

  test('Email OTP dev delivery logs plaintext OTP codes but never plaintext secret material', async () => {
    const { logger, entries } = makeCapturingLogger();
    await withEnv(
      {
        NODE_ENV: 'development',
        EMAIL_OTP_DELIVERY_MODE: 'log',
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'false',
      },
      async () => {
        const service = makeServiceWithLogger(logger);
        const originalCrypto = globalThis.crypto;
        Object.defineProperty(globalThis, 'crypto', {
          configurable: true,
          value: {
            ...originalCrypto,
            getRandomValues<T extends ArrayBufferView | null>(buffer: T): T {
              if (!buffer) return buffer;
              const bytes = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
              if (bytes.length === 16) {
                for (let i = 0; i < bytes.length; i += 1) bytes[i] = i + 1;
              } else if (bytes.length === 6) {
                bytes.set(Uint8Array.from([1, 2, 3, 4, 5, 6]));
              } else {
                for (let i = 0; i < bytes.length; i += 1) bytes[i] = 7;
              }
              return buffer;
            },
          },
        });
        try {
          const sensitiveEmailOtpEscrowBlob = 'email-otp-escrow-sensitive-marker';
          const challenge = await service.createEmailOtpEnrollmentChallenge({
            userId: USER_ID,
            walletId: WALLET_ID,
            orgId: ORG_ID,
            email: EMAIL,
            otpChannel: 'email_otp',
            sessionHash: SESSION_HASH,
            appSessionVersion: APP_SESSION_VERSION,
          });
          expect(challenge.ok).toBe(true);
          if (!challenge.ok) return;
          expect(challenge.delivery.mode).toBe('log');

          const verified = await service.verifyEmailOtpEnrollment({
            userId: USER_ID,
            walletId: WALLET_ID,
            orgId: ORG_ID,
            challengeId: challenge.challenge.challengeId,
            otpCode: '123456',
            otpChannel: 'email_otp',
            sessionHash: SESSION_HASH,
            appSessionVersion: APP_SESSION_VERSION,
            enrollmentEscrowCiphertextB64u: sensitiveEmailOtpEscrowBlob,
            enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
            clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
            unlockKeyVersion: 'email-otp-unlock-v1',
            thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          });
          expect(verified.ok).toBe(true);
        } finally {
          Object.defineProperty(globalThis, 'crypto', {
            configurable: true,
            value: originalCrypto,
          });
        }
      },
    );

    const serializedLogs = JSON.stringify(entries);
    expect(serializedLogs).toContain('123456');
    expect(serializedLogs).toContain('devOtpCode');
    expect(serializedLogs).not.toContain('email-otp-escrow-sensitive-marker');
    expect(serializedLogs).not.toContain('enrollmentEscrowCiphertextB64u');
    expect(serializedLogs).toContain('development OTP code');
  });

  test('Email OTP delivery mode selection enforces production guardrails', async () => {
    await withEnv(
      {
        NODE_ENV: 'development',
        EMAIL_OTP_DELIVERY_MODE: 'log',
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'true',
      },
      async () => {
        const service = makeService();
        const challenge = await service.createEmailOtpEnrollmentChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          email: EMAIL,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
        });
        expect(challenge.ok).toBe(true);
        if (!challenge.ok) return;
        expect(challenge.delivery.mode).toBe('log');
        const outbox = await service.readEmailOtpOutboxEntry({
          challengeId: challenge.challenge.challengeId,
          userId: USER_ID,
          walletId: WALLET_ID,
        });
        expect(outbox.ok).toBe(false);
        if (outbox.ok) return;
        expect(outbox.code).toBe('not_found');
      },
    );

    await withEnv(
      {
        NODE_ENV: 'production',
        EMAIL_OTP_DELIVERY_MODE: 'log',
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'true',
      },
      async () => {
        const service = makeService();
        const challenge = await service.createEmailOtpEnrollmentChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          email: EMAIL,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
        });
        expect(challenge.ok).toBe(false);
        if (challenge.ok) return;
        expect(challenge.code).toBe('email_otp_delivery_not_allowed');
      },
    );
  });

  test('Email OTP does not deliver a code before the challenge is durably persisted', async () => {
    const { logger, entries } = makeCapturingLogger();
    const service = makeServiceWithLogger(logger);
    (service as any).getEmailOtpChallengeStore = () => ({
      put: async () => {},
      get: async () => null,
      deleteExpired: async () => [],
      countActiveByContext: async () => 0,
      deleteOldestActiveByContext: async () => null,
      del: async () => {},
    });

    const challenge = await service.createEmailOtpEnrollmentChallenge({
      userId: USER_ID,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      email: EMAIL,
      otpChannel: 'email_otp',
      sessionHash: SESSION_HASH,
      appSessionVersion: APP_SESSION_VERSION,
    });
    expect(challenge.ok).toBe(false);
    if (challenge.ok) return;
    expect(challenge.code).toBe('internal');
    expect(challenge.message).toBe('Email OTP challenge could not be persisted');

    const serializedLogs = JSON.stringify(entries);
    expect(serializedLogs).not.toContain('development OTP code');
    expect(serializedLogs).not.toContain('devOtpCode');
  });

  test('Email OTP default memory delivery logs the development OTP code', async () => {
    const { logger, entries } = makeCapturingLogger();
    await withEnv(
      {
        NODE_ENV: 'development',
        EMAIL_OTP_DELIVERY_MODE: undefined,
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'true',
      },
      async () => {
        const service = makeServiceWithLogger(logger);
        const challenge = await service.createEmailOtpEnrollmentChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          email: EMAIL,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
        });
        expect(challenge.ok).toBe(true);
        if (!challenge.ok) return;
        expect(challenge.delivery.mode).toBe('memory');

        const outbox = await service.readEmailOtpOutboxEntry({
          challengeId: challenge.challenge.challengeId,
          userId: USER_ID,
          walletId: WALLET_ID,
        });
        expect(outbox.ok).toBe(true);
        if (!outbox.ok) return;

        const serializedLogs = JSON.stringify(entries);
        expect(serializedLogs).toContain('development OTP code');
        expect(serializedLogs).toContain('devOtpCode');
        expect(serializedLogs).toContain(outbox.otpCode);
      },
    );
  });

  test('Email OTP memory outbox is dev-only and enforces wallet binding plus expiry', async () => {
    await withEnv(
      {
        NODE_ENV: 'development',
        EMAIL_OTP_DELIVERY_MODE: 'memory',
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'true',
      },
      async () => {
        const service = makeService();
        await withMockedNow(900_000, async (setNowMs) => {
          const challenge = await createEmailOtpLoginChallenge(service);

          const wrongWallet = await service.readEmailOtpOutboxEntry({
            challengeId: challenge.challengeId,
            userId: USER_ID,
            walletId: 'bob.testnet',
          });
          expect(wrongWallet.ok).toBe(false);
          if (wrongWallet.ok) return;
          expect(wrongWallet.code).toBe('not_found');

          setNowMs(challenge.expiresAtMs + 1);
          const expired = await service.readEmailOtpOutboxEntry({
            challengeId: challenge.challengeId,
            userId: USER_ID,
            walletId: WALLET_ID,
          });
          expect(expired.ok).toBe(false);
          if (expired.ok) return;
          expect(expired.code).toBe('not_found');
        });
      },
    );

    await withEnv(
      {
        NODE_ENV: 'production',
        EMAIL_OTP_DELIVERY_MODE: 'memory',
        EMAIL_OTP_DEV_OUTBOX_ENABLED: 'true',
      },
      async () => {
        const service = makeService();
        const outbox = await service.readEmailOtpOutboxEntry({
          challengeId: 'missing',
          userId: USER_ID,
          walletId: WALLET_ID,
        });
        expect(outbox.ok).toBe(false);
        if (outbox.ok) return;
        expect(outbox.code).toBe('not_found');
      },
    );
  });

  test('Email OTP challenge expires and successful verify cannot be replayed', async () => {
    const service = makeService();
    await withMockedNow(1_000_000, async (setNowMs) => {
      const expiring = await createEmailOtpLoginChallenge(service);
      setNowMs(expiring.expiresAtMs + 1);
      const expired = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: expiring.challengeId,
        otpCode: expiring.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(expired.ok).toBe(false);
      if (expired.ok) return;
      expect(expired.code).toBe('challenge_expired_or_invalid');

      setNowMs(2_000_000);
      const replayable = await createEmailOtpLoginChallenge(service);
      const verified = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: replayable.challengeId,
        otpCode: replayable.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verified.ok).toBe(true);

      const replay = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: replayable.challengeId,
        otpCode: replayable.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(replay.ok).toBe(false);
      if (replay.ok) return;
      expect(replay.code).toBe('challenge_expired_or_invalid');
    });
  });

  test('wrong OTP lockout persists across challenges and a later successful verify resets the state', async () => {
    const service = makeService();
    await withMockedNow(3_000_000, async (setNowMs) => {
      await enrollRecoveryWallet(service);
      const challenge = await createEmailOtpLoginChallenge(service);

      let exhaustedCode: string | null = null;
      while (!exhaustedCode) {
        const invalid = await service.verifyEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          challengeId: challenge.challengeId,
          otpCode: '000000',
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
        });
        expect(invalid.ok).toBe(false);
        if (invalid.ok) continue;
        if (invalid.code === 'otp_attempts_exhausted') {
          exhaustedCode = invalid.code;
          expect(typeof invalid.lockedUntilMs).toBe('number');
          break;
        }
        expect(invalid.code).toBe('invalid_otp');
      }

      const lockedChallenge = await service.createEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        email: EMAIL,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(lockedChallenge.ok).toBe(false);
      if (lockedChallenge.ok) return;
      expect(lockedChallenge.code).toBe('otp_locked_out');

      const lockedState = await (service as any).getEmailOtpAuthStateStore().get(WALLET_ID);
      expect(lockedState?.otpFailureCount).toBeGreaterThan(0);
      expect(typeof lockedState?.otpLockedUntilMs).toBe('number');

      setNowMs((lockedState?.otpLockedUntilMs || 0) + 1);
      const resetChallenge = await createEmailOtpLoginChallenge(service);
      const resetVerify = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: resetChallenge.challengeId,
        otpCode: resetChallenge.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(resetVerify.ok).toBe(true);

      const resetState = await (service as any).getEmailOtpAuthStateStore().get(WALLET_ID);
      expect(resetState?.otpFailureCount).toBe(0);
      expect(resetState?.lastOtpFailureAtMs).toBeUndefined();
      expect(resetState?.otpLockedUntilMs).toBeUndefined();
    });
  });

  test('login grants are single-use and expire by TTL', async () => {
    const service = makeService();
    await withMockedNow(4_000_000, async (setNowMs) => {
      const singleUse = await createEmailOtpLoginChallenge(service);
      const verified = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: singleUse.challengeId,
        otpCode: singleUse.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(verified.ok).toBe(true);
      if (!verified.ok) return;

      const consume1 = await service.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(consume1.ok).toBe(true);

      const consume2 = await service.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(consume2.ok).toBe(false);
      if (consume2.ok) return;
      expect(consume2.code).toBe('login_grant_invalid_or_expired');

      setNowMs(5_000_000);
      const expiring = await createEmailOtpLoginChallenge(service);
      const expiringVerified = await service.verifyEmailOtpChallenge({
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        challengeId: expiring.challengeId,
        otpCode: expiring.otpCode,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(expiringVerified.ok).toBe(true);
      if (!expiringVerified.ok) return;

      setNowMs(expiringVerified.grantExpiresAtMs + 1);
      const expiredConsume = await service.consumeEmailOtpGrant({
        loginGrant: expiringVerified.loginGrant,
        userId: USER_ID,
        walletId: WALLET_ID,
        orgId: ORG_ID,
        otpChannel: 'email_otp',
        sessionHash: SESSION_HASH,
        appSessionVersion: APP_SESSION_VERSION,
      });
      expect(expiredConsume.ok).toBe(false);
      if (expiredConsume.ok) return;
      expect(expiredConsume.code).toBe('login_grant_invalid_or_expired');
    });
  });

  test('Email OTP default challenge limits are local-friendly and production-conservative', async () => {
    await withEnv(
      {
        ...EMAIL_OTP_RATE_LIMIT_ENV_UNSET,
        NODE_ENV: 'development',
        EMAIL_OTP_RATE_LIMITER_KIND: 'in-memory',
      },
      async () => {
        const service = makeService();
        for (let i = 0; i < 6; i += 1) {
          const consumed = await consumeEmailOtpChallengeRateLimit(service, '203.0.113.20');
          expect(consumed.ok).toBe(true);
        }
      },
    );

    await withEnv(
      {
        ...EMAIL_OTP_RATE_LIMIT_ENV_UNSET,
        NODE_ENV: 'production',
        EMAIL_OTP_RATE_LIMITER_KIND: 'in-memory',
      },
      async () => {
        const service = makeService();
        for (let i = 0; i < 5; i += 1) {
          const consumed = await consumeEmailOtpChallengeRateLimit(service, '203.0.113.21');
          expect(consumed.ok).toBe(true);
        }

        const limited = await consumeEmailOtpChallengeRateLimit(service, '203.0.113.21');
        expect(limited.ok).toBe(false);
        if (limited.ok) return;
        expect(limited.code).toBe('rate_limited');
      },
    );
  });

  test('Email OTP local default rate limiter does not inherit shared Redis without explicit opt-in', async () => {
    await withEnv(
      {
        ...EMAIL_OTP_RATE_LIMIT_ENV_UNSET,
        NODE_ENV: 'development',
        REDIS_URL: 'redis://127.0.0.1:1',
        EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX: '1',
        EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS: '60000',
      },
      async () => {
        const firstService = makeService();
        const firstConsume = await consumeEmailOtpChallengeRateLimit(firstService, '203.0.113.22');
        expect(firstConsume.ok).toBe(true);

        const firstLimited = await consumeEmailOtpChallengeRateLimit(
          firstService,
          '203.0.113.22',
        );
        expect(firstLimited.ok).toBe(false);
        if (firstLimited.ok) return;
        expect(firstLimited.code).toBe('rate_limited');

        const secondService = makeService();
        const secondConsume = await consumeEmailOtpChallengeRateLimit(
          secondService,
          '203.0.113.22',
        );
        expect(secondConsume.ok).toBe(true);
      },
    );
  });

  test('Email OTP rate limits challenge issuance, OTP verification, and grant redemption', async () => {
    await withEnv(
      {
        EMAIL_OTP_RATE_LIMITER_KIND: 'in-memory',
        EMAIL_OTP_CHALLENGE_RATE_LIMIT_MAX: '1',
        EMAIL_OTP_CHALLENGE_RATE_LIMIT_WINDOW_MS: '60000',
        EMAIL_OTP_VERIFY_RATE_LIMIT_MAX: '1',
        EMAIL_OTP_VERIFY_RATE_LIMIT_WINDOW_MS: '60000',
        EMAIL_OTP_GRANT_RATE_LIMIT_MAX: '1',
        EMAIL_OTP_GRANT_RATE_LIMIT_WINDOW_MS: '60000',
      },
      async () => {
        const service = makeService();
        await seedEmailOtpEnrollment(service);

        const challenge1 = await service.createEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          email: EMAIL,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.10',
        });
        expect(challenge1.ok).toBe(true);

        const challenge2 = await service.createEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          email: EMAIL,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.10',
        });
        expect(challenge2.ok).toBe(false);
        if (challenge2.ok) return;
        expect(challenge2.code).toBe('rate_limited');

        const verifyService = makeService();
        const verifyChallenge = await createEmailOtpLoginChallenge(verifyService);
        const verify1 = await verifyService.verifyEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          challengeId: verifyChallenge.challengeId,
          otpCode: '000000',
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.11',
        });
        expect(verify1.ok).toBe(false);
        if (verify1.ok) return;
        expect(verify1.code).toBe('invalid_otp');

        const verify2 = await verifyService.verifyEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          challengeId: verifyChallenge.challengeId,
          otpCode: '000000',
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.11',
        });
        expect(verify2.ok).toBe(false);
        if (verify2.ok) return;
        expect(verify2.code).toBe('rate_limited');

        const grantService = makeService();
        const grantChallenge = await createEmailOtpLoginChallenge(grantService);
        const verifiedGrant = await grantService.verifyEmailOtpChallenge({
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          challengeId: grantChallenge.challengeId,
          otpCode: grantChallenge.otpCode,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.12',
        });
        expect(verifiedGrant.ok).toBe(true);
        if (!verifiedGrant.ok) return;

        const consume1 = await grantService.consumeEmailOtpGrant({
          loginGrant: verifiedGrant.loginGrant,
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.12',
        });
        expect(consume1.ok).toBe(true);

        const consume2 = await grantService.consumeEmailOtpGrant({
          loginGrant: 'invalid-grant',
          userId: USER_ID,
          walletId: WALLET_ID,
          orgId: ORG_ID,
          otpChannel: 'email_otp',
          sessionHash: SESSION_HASH,
          appSessionVersion: APP_SESSION_VERSION,
          clientIp: '203.0.113.12',
        });
        expect(consume2.ok).toBe(false);
        if (consume2.ok) return;
        expect(consume2.code).toBe('rate_limited');
      },
    );
  });

  test('Email OTP strong-auth gate flips on Email OTP login and clears on fresh passkey auth', async () => {
    const service = makeService();
    await enrollRecoveryWallet(service);

    const initialGate = await service.isEmailOtpStrongAuthRequired({ walletId: WALLET_ID });
    expect(initialGate.ok).toBe(true);
    if (!initialGate.ok) return;
    expect(initialGate.required).toBe(false);

    const enrollment = await (service as any).getEmailOtpWalletEnrollmentStore().get(WALLET_ID);
    expect(enrollment).toBeTruthy();
    const emailOtpLoginAtMs = Date.now();
    await (service as any).getEmailOtpAuthStateStore().put({
      version: 'email_otp_auth_state_v1',
      walletId: WALLET_ID,
      providerUserId: USER_ID,
      orgId: ORG_ID,
      createdAtMs: emailOtpLoginAtMs,
      updatedAtMs: emailOtpLoginAtMs,
      lastEmailOtpLoginAtMs: emailOtpLoginAtMs,
    });

    const gated = await service.isEmailOtpStrongAuthRequired({ walletId: WALLET_ID });
    expect(gated.ok).toBe(true);
    if (!gated.ok) return;
    expect(gated.required).toBe(true);
    expect(gated.lastEmailOtpLoginAtMs).toBe(emailOtpLoginAtMs);

    const marked = await service.markEmailOtpStrongAuthSatisfied({ walletId: WALLET_ID });
    expect(marked.ok).toBe(true);
    if (!marked.ok) return;

    const cleared = await service.isEmailOtpStrongAuthRequired({ walletId: WALLET_ID });
    expect(cleared.ok).toBe(true);
    if (!cleared.ok) return;
    expect(cleared.required).toBe(false);
    expect(typeof cleared.lastStrongAuthAtMs).toBe('number');
  });
});
