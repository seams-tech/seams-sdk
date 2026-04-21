import { test, expect } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const ORG_ID = 'org_oidc_exchange_tests';
const RUNTIME_POLICY_SCOPE = {
  orgId: ORG_ID,
  projectId: 'project_oidc_exchange_tests',
  envId: 'env_oidc_exchange_tests',
} as const;

function b64u(input: Uint8Array | string): string {
  const bytes = typeof input === 'string' ? Buffer.from(input, 'utf8') : Buffer.from(input);
  return bytes
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

async function makeSignedJwt(input: {
  privateKey: CryptoKey;
  kid: string;
  payload: Record<string, unknown>;
}): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: input.kid };
  const headerB64u = b64u(JSON.stringify(header));
  const payloadB64u = b64u(JSON.stringify(input.payload));
  const data = new TextEncoder().encode(`${headerB64u}.${payloadB64u}`);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, input.privateKey, data),
  );
  return `${headerB64u}.${payloadB64u}.${b64u(sig)}`;
}

async function generateIssuerKeypair(kid: string): Promise<{
  kid: string;
  privateKey: CryptoKey;
  publicJwk: JsonWebKey;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const publicJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  return {
    kid,
    privateKey: keyPair.privateKey,
    publicJwk: {
      ...publicJwk,
      use: 'sig',
      alg: 'RS256',
    },
  };
}

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
    oidcExchange: {
      clockSkewSec: 0,
      issuers: [
        {
          issuer: 'https://issuer.example.com',
          audiences: ['wallet-app'],
          jwksUrl: 'https://issuer.example.com/.well-known/jwks.json',
        },
      ],
    },
  });
}

test.describe('AuthService OIDC exchange verification', () => {
  test('verifies a valid OIDC JWT exchange token and maps subject', async () => {
    const service = makeService();
    const key = await generateIssuerKeypair('kid-success');

    (service as any).getOidcJwksByUrl = async () => ({
      keysByKid: new Map([[key.kid, key.publicJwk]]),
      expiresAtMs: Date.now() + 60_000,
    });

    const now = Math.floor(Date.now() / 1000);
    const token = await makeSignedJwt({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        iat: now,
        exp: now + 300,
      },
    });

    const verified = await service.verifyOidcJwtExchange({ token });
    expect(verified.ok).toBe(true);
    expect(verified.verified).toBe(true);
    expect(verified.sub).toBe('subject-123');
    expect(verified.userId).toBe('oidc:https://issuer.example.com:subject-123');
  });

  test('rejects issuer mismatch before JWKS verify', async () => {
    const service = makeService();
    const now = Math.floor(Date.now() / 1000);

    const headerB64u = b64u(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'kid-x' }));
    const payloadB64u = b64u(
      JSON.stringify({
        iss: 'https://other-issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        iat: now,
        exp: now + 300,
      }),
    );
    const token = `${headerB64u}.${payloadB64u}.${b64u('sig')}`;

    const verified = await service.verifyOidcJwtExchange({ token });
    expect(verified.ok).toBe(false);
    expect(verified.code).toBe('invalid_issuer');
  });

  test('rejects expired token', async () => {
    const service = makeService();
    const key = await generateIssuerKeypair('kid-expired');

    (service as any).getOidcJwksByUrl = async () => ({
      keysByKid: new Map([[key.kid, key.publicJwk]]),
      expiresAtMs: Date.now() + 60_000,
    });

    const now = Math.floor(Date.now() / 1000);
    const token = await makeSignedJwt({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        iat: now - 500,
        exp: now - 1,
      },
    });

    const verified = await service.verifyOidcJwtExchange({ token });
    expect(verified.ok).toBe(false);
    expect(verified.code).toBe('expired');
  });

  test('rejects signature tampering', async () => {
    const service = makeService();
    const key = await generateIssuerKeypair('kid-tamper');

    (service as any).getOidcJwksByUrl = async () => ({
      keysByKid: new Map([[key.kid, key.publicJwk]]),
      expiresAtMs: Date.now() + 60_000,
    });

    const now = Math.floor(Date.now() / 1000);
    const token = await makeSignedJwt({
      privateKey: key.privateKey,
      kid: key.kid,
      payload: {
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-123',
        iat: now,
        exp: now + 300,
      },
    });

    const parts = token.split('.');
    const tamperedPayloadB64u = b64u(
      JSON.stringify({
        iss: 'https://issuer.example.com',
        aud: 'wallet-app',
        sub: 'subject-999',
        iat: now,
        exp: now + 300,
      }),
    );
    const tampered = `${parts[0]}.${tamperedPayloadB64u}.${parts[2]}`;

    const verified = await service.verifyOidcJwtExchange({ token: tampered });
    expect(verified.ok).toBe(false);
    expect(verified.code).toBe('invalid_signature');
  });

  test('Google Email OTP registration starts an attempt without binding identity', async () => {
    const service = makeService();

    const registered = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-1',
      email: 'Alice.Example+demo@Example.COM',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(registered.ok).toBe(true);
    if (!registered.ok) return;
    expect(registered.mode).toBe('register_started');
    if (registered.mode !== 'register_started') return;
    expect(registered.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(registered.walletId).not.toContain('alice');
    expect(registered.walletId).not.toContain('example');
    expect(registered.registrationAttemptId).toBeTruthy();
    const attempt = await (service as any)
      .getEmailOtpRegistrationAttemptStore()
      .get(registered.registrationAttemptId);
    expect(attempt).toMatchObject({
      walletId: registered.walletId,
      providerSubject: 'google:subject-1',
      email: 'alice.example+demo@example.com',
      authProvider: 'google_oidc',
      accountIdSlugVersion: 'hmac_readable_v1',
      collisionCounter: 0,
    });

    const identity = (service as any).getIdentityStore();
    await expect(identity.getUserIdBySubject('wallet:google:subject-1')).resolves.toBeNull();

    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject: 'google:subject-1',
        email: 'different@example.com',
        accountMode: 'login',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
      message: 'Email OTP enrollment not found',
    });
  });

  test('Google Email OTP registration resumes a live pending attempt', async () => {
    const service = makeService();

    const first = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-resume',
      email: 'resume@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    const second = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-resume',
      email: 'resume@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });

    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(first.mode).toBe('register_started');
    expect(second.mode).toBe('register_started');
    if (first.mode !== 'register_started' || second.mode !== 'register_started') return;
    expect(second.walletId).toBe(first.walletId);
    expect(second.registrationAttemptId).toBe(first.registrationAttemptId);
  });

  test('identity mapping is committed only after successful Google Email OTP finalization', async () => {
    const service = makeService();
    const registered = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-finalize',
      email: 'finalize@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(registered.ok).toBe(true);
    if (!registered.ok || registered.mode !== 'register_started') return;

    const identity = (service as any).getIdentityStore();
    await expect(identity.getUserIdBySubject('wallet:google:subject-finalize')).resolves.toBeNull();

    const completed = await service.completeGoogleEmailOtpRegistrationAttempt({
      registrationAttemptId: registered.registrationAttemptId,
      walletId: registered.walletId,
      finalizedPublicKey: 'ed25519:test-public-key',
    });
    expect(completed).toEqual({ ok: true });
    await expect(identity.getUserIdBySubject('wallet:google:subject-finalize')).resolves.toBe(
      registered.walletId,
    );
  });

  test('Google Email OTP register with existing active wallet switches to login resolution', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    await identity.linkSubjectToUserId({
      userId: 'existing-active-a1b2c3d4e5.relayer.testnet',
      subject: 'wallet:google:subject-existing-active',
      allowMoveIfSoleIdentity: false,
    });
    await enrollmentStore.put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: 'existing-active-a1b2c3d4e5.relayer.testnet',
      providerUserId: 'google:subject-existing-active',
      orgId: ORG_ID,
      verifiedEmail: 'existing-active@example.com',
      enrollmentEscrowCiphertextB64u: 'escrow',
      enrollmentSealKeyVersion: 'email-key-v1',
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-existing-active',
      email: 'existing@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('existing_wallet');
    expect(resolved.walletId).toBe('existing-active-a1b2c3d4e5.relayer.testnet');
  });

  test('Google Email OTP login never creates wallets', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject: 'google:subject-login-missing',
        email: 'missing@example.com',
        accountMode: 'login',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
      message: 'Email OTP enrollment not found',
    });
    await expect(
      identity.getUserIdBySubject('wallet:google:subject-login-missing'),
    ).resolves.toBeNull();
  });

  test('Google Email OTP register with stale failed wallet does not reuse stale wallet', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    await identity.linkSubjectToUserId({
      userId: 'stale-failed-c1d2e3f4g5.relayer.testnet',
      subject: 'wallet:google:subject-stale-failed',
      allowMoveIfSoleIdentity: false,
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-stale-failed',
      email: 'stale.failed@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(resolved.ok).toBe(false);
    if (resolved.ok) return;
    expect(resolved.mode).toBe('registration_incomplete');
    expect(resolved.walletId).toBe('stale-failed-c1d2e3f4g5.relayer.testnet');
  });

  test('completed Google Email OTP registration resolves through OIDC wallet helper only after finalization', async () => {
    const service = makeService();
    const registered = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-finalized-helper',
      email: 'finalized@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(registered.ok).toBe(true);
    if (!registered.ok || registered.mode !== 'register_started') return;
    await service.completeGoogleEmailOtpRegistrationAttempt({
      registrationAttemptId: registered.registrationAttemptId,
      walletId: registered.walletId,
    });
    await (service as any).getEmailOtpWalletEnrollmentStore().put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: registered.walletId,
      providerUserId: 'google:subject-finalized-helper',
      orgId: ORG_ID,
      verifiedEmail: 'finalized-helper@example.com',
      enrollmentEscrowCiphertextB64u: 'escrow',
      enrollmentSealKeyVersion: 'email-key-v1',
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const walletId = await service.resolveOidcWalletId({
      providerSubject: 'google:subject-finalized-helper',
      accountMode: 'login',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(walletId).toBe(registered.walletId);
  });

  test('Google Email OTP registration uses privacy-preserving HMAC account ids', async () => {
    const service = makeService();
    const registered = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-privacy',
      email: 'Alice.Example+demo@Example.COM',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(registered.ok).toBe(true);
    if (!registered.ok) return;
    expect(registered.mode).toBe('register_started');
    expect(registered.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
    expect(registered.walletId).not.toContain('alice');
    expect(registered.walletId).not.toContain('example');
    expect(registered.walletId).not.toContain('gmail');
    expect(registered.walletId).not.toContain('google');
  });

  test('Google Email OTP registration is deterministic for the same provider subject', async () => {
    const service = makeService();
    const first = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-deterministic',
      email: 'first@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    await (service as any)
      .getEmailOtpRegistrationAttemptStore()
      .deleteExpired(Date.now() + 31 * 60 * 1000);

    const second = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-deterministic',
      email: 'second@example.com',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(second.ok).toBe(true);
    if (!second.ok) return;
    expect(second.walletId).toBe(first.walletId);
  });

  test('Google Email OTP registration keeps existing active wallet login semantics', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    await identity.linkSubjectToUserId({
      userId: 'active-stable-b1c2d3e4f5.relayer.testnet',
      subject: 'wallet:google:subject-active-stable',
      allowMoveIfSoleIdentity: false,
    });
    await enrollmentStore.put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: 'active-stable-b1c2d3e4f5.relayer.testnet',
      providerUserId: 'google:subject-active-stable',
      orgId: ORG_ID,
      verifiedEmail: 'active-stable@example.com',
      enrollmentEscrowCiphertextB64u: 'escrow',
      enrollmentSealKeyVersion: 'email-key-v1',
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const resolved = await service.resolveGoogleEmailOtpSession({
      providerSubject: 'google:subject-active-stable',
      email: 'Dev.Active.Stable@Example.COM',
      accountMode: 'register',
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    });
    expect(resolved.ok).toBe(true);
    if (!resolved.ok) return;
    expect(resolved.mode).toBe('existing_wallet');
    expect(resolved.walletId).toBe('active-stable-b1c2d3e4f5.relayer.testnet');
  });

  test('dev cleanup removes expired attempts and orphaned Google wallet mappings', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    const attemptStore = (service as any).getEmailOtpRegistrationAttemptStore();
    await identity.linkSubjectToUserId({
      userId: 'orphaned.relayer.testnet',
      subject: 'wallet:google:subject-orphaned',
      allowMoveIfSoleIdentity: false,
    });
    await attemptStore.put({
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: 'expired-attempt',
      providerSubject: 'google:expired-subject',
      email: 'expired@example.com',
      walletId: 'expired.relayer.testnet',
      state: 'started',
      createdAtMs: 1,
      updatedAtMs: 1,
      expiresAtMs: 2,
    });

    const cleaned = await service.cleanupGoogleEmailOtpDevRegistrationState({
      providerSubject: 'google:subject-orphaned',
      nowMs: 3,
    });

    expect(cleaned).toMatchObject({
      ok: true,
      providerSubject: 'google:subject-orphaned',
      expiredRegistrationAttemptsDeleted: 1,
      linkedWalletId: 'orphaned.relayer.testnet',
      orphanedWalletMappingRemoved: true,
    });
    await expect(identity.getUserIdBySubject('wallet:google:subject-orphaned')).resolves.toBeNull();
    await expect(attemptStore.get('expired-attempt')).resolves.toBeNull();
  });

  test('dev cleanup keeps Google mappings with active Email OTP enrollment', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    await identity.linkSubjectToUserId({
      userId: 'active.relayer.testnet',
      subject: 'wallet:google:subject-active-cleanup',
      allowMoveIfSoleIdentity: false,
    });
    await enrollmentStore.put({
      version: 'email_otp_wallet_enrollment_v1',
      walletId: 'active.relayer.testnet',
      providerUserId: 'google:subject-active-cleanup',
      orgId: ORG_ID,
      verifiedEmail: 'active-cleanup@example.com',
      enrollmentEscrowCiphertextB64u: 'escrow',
      enrollmentSealKeyVersion: 'email-key-v1',
      clientUnlockPublicKeyB64u: 'unlock-public',
      unlockKeyVersion: 'unlock-key-v1',
      thresholdEcdsaClientVerifyingShareB64u: 'ecdsa-client-verifying-share',
      createdAtMs: 1,
      updatedAtMs: 1,
    });

    const cleaned = await service.cleanupGoogleEmailOtpDevRegistrationState({
      providerSubject: 'google:subject-active-cleanup',
    });

    expect(cleaned).toMatchObject({
      ok: true,
      linkedWalletId: 'active.relayer.testnet',
      orphanedWalletMappingRemoved: false,
      orphanedWalletMappingSkippedReason: 'active_email_otp_enrollment',
    });
    await expect(identity.getUserIdBySubject('wallet:google:subject-active-cleanup')).resolves.toBe(
      'active.relayer.testnet',
    );
  });

  test('derives HMAC-readable OIDC wallet id when no registration mapping exists', async () => {
    const service = makeService();
    const walletId = await service.resolveOidcWalletId({
      providerSubject: 'oidc:https://issuer.example.com:subject-no-registration',
      accountMode: 'login',
    });
    expect(walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
  });

  test('Google Email OTP login requires registration before resolving a wallet id', async () => {
    const service = makeService();
    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject: 'google:subject-no-registration',
        accountMode: 'login',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
      message: 'Email OTP enrollment not found',
    });
  });

  test('Google Email OTP registration moves stale top-level wallet mappings to relayer subaccounts', async () => {
    const service = makeService();
    const identity = (service as any).getIdentityStore();
    await identity.linkSubjectToUserId({
      userId: 'stale-google-wallet.testnet',
      subject: 'wallet:google:subject-stale-top-level',
      allowMoveIfSoleIdentity: false,
    });

    await expect(
      service.resolveGoogleEmailOtpSession({
        providerSubject: 'google:subject-stale-top-level',
        accountMode: 'login',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
      message: 'Email OTP enrollment not found',
    });

    const originalNow = Date.now;
    Date.now = () => 1_712_345_678_902;
    try {
      const registered = await service.resolveGoogleEmailOtpSession({
        providerSubject: 'google:subject-stale-top-level',
        email: 'stale@example.com',
        accountMode: 'register',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      });
      expect(registered.ok).toBe(true);
      if (!registered.ok) return;
      expect(registered.walletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relayer\.testnet$/);
      expect(registered.walletId).not.toContain('stale');
      expect(registered.walletId).not.toContain('example');
    } finally {
      Date.now = originalNow;
    }
  });

  test('rejects Email OTP registration wallet id resolution without email', async () => {
    const service = makeService();
    await expect(
      service.resolveOidcWalletId({
        providerSubject: 'google:subject-without-email',
        accountMode: 'register',
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      }),
    ).rejects.toThrow('Email is required to register a Google Email OTP wallet id');
  });

  test('returns invalid_session_version for stale app session version', async () => {
    const service = makeService();
    const userId = 'oidc:https://issuer.example.com:subject-stale-version';

    const first = await service.getOrCreateAppSessionVersion({ userId });
    expect(first.ok).toBe(true);
    if (!first.ok) return;

    const rotated = await service.rotateAppSessionVersion({ userId });
    expect(rotated.ok).toBe(true);

    const validated = await service.validateAppSessionVersion({
      userId,
      appSessionVersion: first.appSessionVersion,
    });
    expect(validated.ok).toBe(false);
    if (validated.ok) return;
    expect(validated.code).toBe('invalid_session_version');
  });
});
