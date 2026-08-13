import { expect, test } from '@playwright/test';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import {
  handleEmailOtpFactorReleaseRoute,
  handleEmailOtpSigningSessionChallengeRoute,
} from '@server/router/domains/emailOtp/emailOtpRouteHandlers';

const FACTOR_RELEASE_AAD_DOMAIN = 'seams/email-otp/factor-release/v1';

type CapturedEmailOtpCalls = {
  readActiveEnrollmentInput: Record<string, unknown> | null;
  createChallengeInput: Record<string, unknown> | null;
  consumeGrantInput: Record<string, unknown> | null;
  removeServerSealInput: Record<string, unknown> | null;
};

class EmailOtpFactorReleaseRouteService {
  constructor(
    private readonly captured: CapturedEmailOtpCalls,
    private readonly factorSecret32B64u: string,
  ) {}

  async readActiveEmailOtpEnrollment(input: Record<string, unknown>) {
    this.captured.readActiveEnrollmentInput = input;
    return {
      ok: true,
      enrollment: {
        walletId: 'wallet-a',
        orgId: 'org-a',
        providerUserId: 'google:provider-user',
        verifiedEmail: 'user@example.com',
        enrollmentId: 'email_otp:wallet-a:google:provider-user',
        enrollmentSealKeyVersion: 'seal-v1',
        serverSealedFactorCiphertextB64u: 'stored-server-sealed-factor',
      },
    };
  }

  async consumeEmailOtpGrant(input: Record<string, unknown>) {
    this.captured.consumeGrantInput = input;
    return {
      ok: true,
      challengeId: 'challenge-1',
      otpChannel: EMAIL_OTP_CHANNEL,
    };
  }

  async createEmailOtpChallenge(input: Record<string, unknown>) {
    this.captured.createChallengeInput = input;
    return {
      ok: true,
      challenge: {
        challengeId: 'challenge-1',
        issuedAtMs: 1,
        expiresAtMs: 2,
        userId: input.userId,
        walletId: input.walletId,
        orgId: input.orgId,
        sessionHash: input.sessionHash,
        appSessionVersion: input.appSessionVersion,
        otpChannel: EMAIL_OTP_CHANNEL,
        action: 'login',
        operation: input.operation,
      },
      delivery: { ok: true },
    };
  }

  async removeEmailOtpServerSeal(input: Record<string, unknown>) {
    this.captured.removeServerSealInput = input;
    return {
      ok: true,
      ciphertext: this.factorSecret32B64u,
      enrollmentSealKeyVersion: 'seal-v1',
    };
  }
}

async function ignoreEmailOtpWebhook(): Promise<void> {}

function factorReleaseAad(): Uint8Array {
  return new TextEncoder().encode(
    [
      FACTOR_RELEASE_AAD_DOMAIN,
      'wallet-a',
      'email_otp:wallet-a:google:provider-user',
      'seal-v1',
      'challenge-1',
    ].join('\0'),
  );
}

test('Email OTP factor release encrypts the stored factor to the requesting worker', async () => {
  const factorSecret32 = new Uint8Array(32).fill(7);
  const captured: CapturedEmailOtpCalls = {
    readActiveEnrollmentInput: null,
    createChallengeInput: null,
    consumeGrantInput: null,
    removeServerSealInput: null,
  };
  const service = new EmailOtpFactorReleaseRouteService(captured, base64UrlEncode(factorSecret32));
  const workerKeyPair = (await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  )) as CryptoKeyPair;
  const workerPublicKey65 = new Uint8Array(
    await crypto.subtle.exportKey('raw', workerKeyPair.publicKey),
  );

  const response = await handleEmailOtpFactorReleaseRoute({
    body: {
      walletId: 'wallet-a',
      loginGrant: 'login-grant-1',
      workerEphemeralPublicKey65B64u: base64UrlEncode(workerPublicKey65),
    },
    claims: {
      walletId: 'wallet-a',
      orgId: 'org-a',
      provider: 'oidc',
      oidcProvider: 'google',
      providerSubject: 'google:provider-user',
      authSource: {
        kind: 'oidc_provider',
        providerId: 'google_oidc',
        providerSubject: 'google:provider-user',
      },
    },
    userId: 'wallet-a',
    appSessionVersion: 'app-session-v1',
    service: service as any,
    emitWebhook: ignoreEmailOtpWebhook,
  });

  expect(response.status).toBe(200);
  expect(captured.removeServerSealInput).toEqual({
    wrappedCiphertext: 'stored-server-sealed-factor',
  });
  expect(captured.consumeGrantInput).toMatchObject({
    subject: {
      kind: 'provider_identity',
      orgId: 'org-a',
      providerSubject: 'google:provider-user',
      walletId: 'wallet-a',
    },
    loginGrant: 'login-grant-1',
  });

  const body = response.body as Record<string, unknown>;
  expect(body.kind).toBe('email_otp_factor_release_v1');
  expect(JSON.stringify(body)).not.toContain(base64UrlEncode(factorSecret32));
  const serverPublicKey = await crypto.subtle.importKey(
    'raw',
    base64UrlDecode(String(body.serverEphemeralPublicKey65B64u)),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: serverPublicKey },
    workerKeyPair.privateKey,
    256,
  );
  const decryptionKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'AES-GCM' },
    false,
    ['decrypt'],
  );
  const decrypted = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64UrlDecode(String(body.nonce12B64u)),
        additionalData: factorReleaseAad(),
        tagLength: 128,
      },
      decryptionKey,
      base64UrlDecode(String(body.ciphertextB64u)),
    ),
  );
  expect(decrypted).toEqual(factorSecret32);
});

test('Email OTP signing-session challenge resolves wallet identity from wallet-session claims', async () => {
  const captured: CapturedEmailOtpCalls = {
    readActiveEnrollmentInput: null,
    createChallengeInput: null,
    consumeGrantInput: null,
    removeServerSealInput: null,
  };
  const service = new EmailOtpFactorReleaseRouteService(
    captured,
    base64UrlEncode(new Uint8Array(32)),
  );

  const response = await handleEmailOtpSigningSessionChallengeRoute({
    body: {
      walletId: 'wallet-a',
      otpChannel: EMAIL_OTP_CHANNEL,
      operation: 'wallet_unlock',
    },
    claims: { walletId: 'wallet-a', orgId: 'org-a' },
    userId: 'near-account-subject',
    appSessionVersion: 'wallet-session-v1',
    sessionHash: 'wallet-session-hash',
    clientIp: '203.0.113.42',
    service: service as any,
    opts: {} as any,
    emitWebhook: ignoreEmailOtpWebhook,
  });

  expect(response.status).toBe(200);
  expect(captured.readActiveEnrollmentInput).toMatchObject({
    walletId: 'wallet-a',
    orgId: 'org-a',
  });
  expect(captured.createChallengeInput).toMatchObject({
    userId: 'google:provider-user',
    walletId: 'wallet-a',
    orgId: 'org-a',
    sessionHash: 'wallet-session-hash',
    appSessionVersion: 'wallet-session-v1',
    clientIp: '203.0.113.42',
    operation: 'wallet_unlock',
  });
});
