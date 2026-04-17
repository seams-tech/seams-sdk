import { test, expect } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

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

  test('resolves Google Email OTP registration to a timestamped email wallet id and reuses it on login', async () => {
    const service = makeService();
    const originalNow = Date.now;
    Date.now = () => 1_712_345_678_901;
    try {
      const registered = await service.resolveOidcWalletId({
        providerSubject: 'google:subject-1',
        email: 'Alice.Example+demo@Example.COM',
        accountMode: 'register',
      });
      expect(registered).toBe('alice-example-demo-example-com-1712345678901.testnet');

      const login = await service.resolveOidcWalletId({
        providerSubject: 'google:subject-1',
        email: 'different@example.com',
        accountMode: 'login',
      });
      expect(login).toBe(registered);
    } finally {
      Date.now = originalNow;
    }
  });

  test('falls back to hashed OIDC wallet id when no registration mapping exists', async () => {
    const service = makeService();
    const walletId = await service.resolveOidcWalletId({
      providerSubject: 'oidc:https://issuer.example.com:subject-no-registration',
      accountMode: 'login',
    });
    expect(walletId).toMatch(/^g-[a-f0-9]{32}\.testnet$/);
  });

  test('Google Email OTP login does not fall back to a hashed wallet id without registration', async () => {
    const service = makeService();
    await expect(
      service.resolveOidcWalletId({
        providerSubject: 'google:subject-no-registration',
        accountMode: 'login',
      }),
    ).rejects.toMatchObject({
      code: 'not_found',
      message: 'Email OTP enrollment not found',
    });
  });

  test('rejects Email OTP registration wallet id resolution without email', async () => {
    const service = makeService();
    await expect(
      service.resolveOidcWalletId({
        providerSubject: 'google:subject-without-email',
        accountMode: 'register',
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
