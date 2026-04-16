import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '@server/core/ThresholdService/ethSignerWasm';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createPrfSessionSealShamir3PassBigIntRuntime } from '@server/threshold/session/prfSessionSeal';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpUnlockAuthSeed,
} from '@shared/utils/emailOtpDerivation';
import {
  enrollEmailOtpWallet,
  loginWithEmailOtpAndUnlockWallet,
  loginWithEmailOtpAndBootstrapEcdsaCapability,
} from '@/core/TatchiPasskey/emailOtp';
import { callCf, makeCfCtx, makeSessionAdapter, startExpressRouter, fetchJson } from './helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const EMAIL_OTP_KEY_VERSION = 'kek-s-email-otp-test';
const SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
const CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(
  modInverse(5n, decodePositiveBigIntB64u(SHAMIR_PRIME_B64U) - 1n),
);

function decodePositiveBigIntB64u(value: string): bigint {
  const bytes = base64UrlDecode(value);
  let output = 0n;
  for (const byte of bytes) {
    output = (output << 8n) | BigInt(byte);
  }
  if (output <= 0n) throw new Error('value must decode to a positive bigint');
  return output;
}

function encodePositiveBigIntB64u(value: bigint): string {
  if (value <= 0n) throw new Error('value must be > 0');
  const bytesReversed: number[] = [];
  let cursor = value;
  while (cursor > 0n) {
    bytesReversed.push(Number(cursor & 255n));
    cursor >>= 8n;
  }
  bytesReversed.reverse();
  return base64UrlEncode(Uint8Array.from(bytesReversed));
}

function modInverse(value: bigint, modulus: bigint): bigint {
  let t = 0n;
  let newT = 1n;
  let r = modulus;
  let newR = value % modulus;
  while (newR !== 0n) {
    const quotient = r / newR;
    [t, newT] = [newT, t - quotient * newT];
    [r, newR] = [newR, r - quotient * newR];
  }
  if (r !== 1n) throw new Error('value is not invertible modulo modulus');
  return t < 0n ? t + modulus : t;
}

function makeClientSecret32B64u(seedByte: number): string {
  return base64UrlEncode(Uint8Array.from({ length: 32 }, () => seedByte & 255));
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
    thresholdEd25519KeyStore: {
      PRF_SESSION_SEAL_KEY_VERSION: EMAIL_OTP_KEY_VERSION,
      SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
      SHAMIR_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      SHAMIR_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
    },
  });
}

function makeAppSessionAdapter(appSessionVersion: string) {
  return makeSessionAdapter({
    parse: async () => ({
      ok: true,
      claims: {
        kind: 'app_session_v1',
        sub: 'alice.testnet',
        appSessionVersion,
        email: 'alice@example.com',
      },
    }),
  });
}

function makeTokenBoundAppSessionAdapter(
  claimsByToken: Record<string, Record<string, unknown> | (() => Record<string, unknown>)>,
) {
  return makeSessionAdapter({
    parse: async (headers) => {
      const rawHeader = headers.authorization ?? headers.Authorization;
      const header = Array.isArray(rawHeader) ? String(rawHeader[0] || '') : String(rawHeader || '');
      const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
      const entry = claimsByToken[token];
      const claims = typeof entry === 'function' ? entry() : entry;
      if (!claims) return { ok: false } as const;
      return { ok: true, claims: claims as any } as const;
    },
  });
}

function addClientSeal(ciphertextB64u: string): string {
  const runtime = createPrfSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function removeClientSeal(ciphertextB64u: string): string {
  const runtime = createPrfSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.removeServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function createHandleShamirRuntime() {
  return {
    createClientKeyHandle: async () => ({ keyHandle: 'kh-relayer' }),
    destroyClientKeyHandle: async () => undefined,
    addClientSealWithKeyHandle: async ({ ciphertextB64u }: { ciphertextB64u: string }) =>
      addClientSeal(ciphertextB64u),
    addClientSealBytesWithKeyHandle: async ({ ciphertext }: { ciphertext: Uint8Array }) =>
      addClientSeal(base64UrlEncode(ciphertext)),
    removeClientSealWithKeyHandle: async ({ ciphertextB64u }: { ciphertextB64u: string }) =>
      removeClientSeal(ciphertextB64u),
    removeClientSealWithKeyHandleToBytes: async ({ ciphertextB64u }: { ciphertextB64u: string }) =>
      base64UrlDecode(removeClientSeal(ciphertextB64u)),
  };
}

function addServerSeal(ciphertextB64u: string): string {
  const runtime = createPrfSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function normalizeHeaders(initHeaders?: HeadersInit): Record<string, string> {
  const headers = new Headers(initHeaders || {});
  const output: Record<string, string> = {};
  headers.forEach((value, key) => {
    output[key] = value;
  });
  return output;
}

function createCloudflareFetchImpl(
  handler: ReturnType<typeof createCloudflareRouter>,
  ctx = makeCfCtx(),
): typeof fetch {
  return (async (input, init) => {
    const url = new URL(typeof input === 'string' ? input : input.url || 'https://relay.test');
    const bodyText =
      init?.body == null
        ? undefined
        : typeof init.body === 'string'
          ? init.body
          : init.body instanceof URLSearchParams
            ? init.body.toString()
            : String(init.body);
    const response = await callCf(handler, {
      method: String(init?.method || 'GET').toUpperCase(),
      path: `${url.pathname}${url.search}`,
      headers: normalizeHeaders(init?.headers),
      ...(bodyText !== undefined ? { body: bodyText } : {}),
      ctx: ctx.ctx,
    });
    return new Response(response.text, {
      status: response.status,
      headers: response.headers,
    });
  }) as typeof fetch;
}

test.describe('Email OTP bootstrap integration', () => {
  test('Cloudflare adapter preserves helper-driven Email OTP enrollment and bootstrap flows', async () => {
    const service = makeService();
    const enrollVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(enrollVersion.ok).toBe(true);
    let recoveryAppSessionVersion = '';
    const handler = createCloudflareRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session-enroll': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: (enrollVersion as { appSessionVersion: string }).appSessionVersion,
          email: 'alice@example.com',
          deviceId: 'cf-device-enroll',
        },
        'app-session-recover': () => ({
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: recoveryAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'cf-device-recover',
        }),
      }),
    });
    const cf = makeCfCtx();
    const cfFetch = createCloudflareFetchImpl(handler, cf);
    const relayUrl = 'https://relay.test';

    const plaintextSecretB64u = makeClientSecret32B64u(73);
    const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u: plaintextSecretB64u,
      walletId: 'alice.testnet',
      userId: 'alice.testnet',
    });

    let latestEnrollOtpCode = '';
    const enrollFetchImpl: typeof fetch = async (input, init) => {
      const url = String(typeof input === 'string' ? input : input.url || '');
      const nextInit = { ...(init || {}) };
      if (
        url.endsWith('/wallet/email-otp/enroll/verify') &&
        nextInit.body &&
        typeof nextInit.body === 'string' &&
        latestEnrollOtpCode
      ) {
        const body = JSON.parse(nextInit.body);
        nextInit.body = JSON.stringify({ ...body, otpCode: latestEnrollOtpCode });
      }
      const response = await cfFetch(input, nextInit);
      if (!url.endsWith('/wallet/email-otp/enroll/challenge')) return response;
      const text = await response.text();
      const json = text ? JSON.parse(text) : null;
      const challengeId = String(json?.challenge?.challengeId || '');
      if (challengeId) {
        const enrollOutbox = await service.readEmailOtpOutboxEntry({
          challengeId,
          userId: 'alice.testnet',
          walletId: 'alice.testnet',
        });
        if (enrollOutbox.ok) latestEnrollOtpCode = enrollOutbox.otpCode;
      }
      return new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    };

    const enrolled = await enrollEmailOtpWallet({
      relayUrl,
      walletId: 'alice.testnet',
      otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
      appSessionJwt: 'app-session-enroll',
      clientSecretB64u: plaintextSecretB64u,
      fetchImpl: enrollFetchImpl,
      shamirRuntime: createHandleShamirRuntime(),
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            return (
              await secp256k1PrivateKey32ToPublicKey33(
                new Uint8Array(request.payload.privateKey32),
              )
            ).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
    });

    const rotatedVersion = await service.rotateAppSessionVersion({ userId: 'alice.testnet' });
    expect(rotatedVersion.ok).toBe(true);
    recoveryAppSessionVersion = (rotatedVersion as { appSessionVersion: string }).appSessionVersion;

    let latestRecoveryOtpCode = '';
    const recoveryFetchImpl: typeof fetch = async (input, init) => {
      const url = String(typeof input === 'string' ? input : input.url || '');
      const nextInit = { ...(init || {}) };
      if (
        url.endsWith('/wallet/email-otp/verify') &&
        nextInit.body &&
        typeof nextInit.body === 'string' &&
        latestRecoveryOtpCode
      ) {
        const body = JSON.parse(nextInit.body);
        nextInit.body = JSON.stringify({ ...body, otpCode: latestRecoveryOtpCode });
      }
      const response = await cfFetch(input, nextInit);
      if (!url.endsWith('/wallet/email-otp/challenge')) return response;
      const text = await response.text();
      const json = text ? JSON.parse(text) : null;
      const challengeId = String(json?.challenge?.challengeId || '');
      if (challengeId) {
        const recoveryOutbox = await service.readEmailOtpOutboxEntry({
          challengeId,
          userId: 'alice.testnet',
          walletId: 'alice.testnet',
        });
        if (recoveryOutbox.ok) latestRecoveryOtpCode = recoveryOutbox.otpCode;
      }
      return new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    };

    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const result = await loginWithEmailOtpAndBootstrapEcdsaCapability({
      relayUrl,
      walletId: 'alice.testnet',
      otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
      appSessionJwt: 'app-session-recover',
      authorizationJwt: 'bootstrap-auth-jwt',
      sessionId: 'ecdsa-session-cf-1',
      ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      fetchImpl: recoveryFetchImpl,
      workerCtx: {
        requestWorkerOperation: async ({ request }: any) => {
          if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
            return (
              await secp256k1PrivateKey32ToPublicKey33(
                new Uint8Array(request.payload.privateKey32),
              )
            ).buffer.slice(0);
          }
          if (request.type === 'signSecp256k1Recoverable') {
            return (
              await signSecp256k1Recoverable(
                new Uint8Array(request.payload.digest32),
                new Uint8Array(request.payload.privateKey32),
              )
            ).buffer.slice(0);
          }
          throw new Error(`Unexpected worker operation: ${request.type}`);
        },
      },
      shamirRuntime: createHandleShamirRuntime(),
      bootstrapEcdsaSession: async (args) => {
        bootstrapCalls.push({ ...args });
        return {
          thresholdEcdsaKeyRef: {
            type: 'threshold-ecdsa-secp256k1',
            userId: 'alice.testnet',
            relayerUrl: relayUrl,
            ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
            backendBinding: {
              relayerKeyId: 'rk-cf-1',
              clientVerifyingShareB64u: enrolled.thresholdEcdsaClientVerifyingShareB64u,
            },
            participantIds: [1, 2],
            thresholdSessionKind: 'jwt',
            thresholdSessionId: 'ecdsa-session-cf-1',
            thresholdSessionJwt: 'jwt-ecdsa-cf',
          },
          keygen: {
            ok: true,
            ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
            relayerKeyId: 'rk-cf-1',
            clientVerifyingShareB64u: enrolled.thresholdEcdsaClientVerifyingShareB64u,
            participantIds: [1, 2],
          },
          session: {
            ok: true,
            sessionId: 'ecdsa-session-cf-1',
            jwt: 'jwt-ecdsa-cf',
            remainingUses: 3,
            expiresAtMs: Date.now() + 60_000,
            clientVerifyingShareB64u: enrolled.thresholdEcdsaClientVerifyingShareB64u,
          },
        };
      },
    });

    expect('clientSecretB64u' in result.recovery).toBe(false);
    expect('clientRootShare32B64u' in result.recovery).toBe(false);
    expect(result.recovery.unlockPublicKeyB64u).toBe(enrolled.unlockPublicKeyB64u);
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toEqual({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      relayerUrl: relayUrl,
      ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-cf-1',
      authorizationJwt: 'bootstrap-auth-jwt',
      clientRootShare32B64u: expectedClientRootShare32B64u,
    });
  });

  test('new-device email Email OTP succeeds under a different app session after enrollment', async () => {
    const service = makeService();
    const enrollVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(enrollVersion.ok).toBe(true);
    let recoveryAppSessionVersion = '';
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session-enroll': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: (enrollVersion as { appSessionVersion: string }).appSessionVersion,
          email: 'alice@example.com',
          deviceId: 'device-enroll',
        },
        'app-session-recover': () => ({
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: recoveryAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'device-recover',
        }),
      }),
    });
    const srv = await startExpressRouter(router);

    try {
      const plaintextSecretB64u = makeClientSecret32B64u(59);
      const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
        clientSecretB64u: plaintextSecretB64u,
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
      });

      let latestEnrollOtpCode = '';
      const enrollFetchImpl: typeof fetch = async (input, init) => {
        const url = String(typeof input === 'string' ? input : input.url || '');
        const nextInit = { ...(init || {}) };
        if (
          url.endsWith('/wallet/email-otp/enroll/verify') &&
          nextInit.body &&
          typeof nextInit.body === 'string' &&
          latestEnrollOtpCode
        ) {
          const body = JSON.parse(nextInit.body);
          nextInit.body = JSON.stringify({ ...body, otpCode: latestEnrollOtpCode });
        }
        const response = await fetch(input, nextInit);
        if (!url.endsWith('/wallet/email-otp/enroll/challenge')) return response;
        const text = await response.text();
        const json = text ? JSON.parse(text) : null;
        const challengeId = String(json?.challenge?.challengeId || '');
        if (challengeId) {
          const enrollOutbox = await service.readEmailOtpOutboxEntry({
            challengeId,
            userId: 'alice.testnet',
            walletId: 'alice.testnet',
          });
          if (enrollOutbox.ok) latestEnrollOtpCode = enrollOutbox.otpCode;
        }
        return new Response(text, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };

      const enrolled = await enrollEmailOtpWallet({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session-enroll',
        clientSecretB64u: plaintextSecretB64u,
        fetchImpl: enrollFetchImpl,
        shamirRuntime: createHandleShamirRuntime(),
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return (
                await secp256k1PrivateKey32ToPublicKey33(
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        },
      });

      const rotatedVersion = await service.rotateAppSessionVersion({ userId: 'alice.testnet' });
      expect(rotatedVersion.ok).toBe(true);
      recoveryAppSessionVersion = (rotatedVersion as { appSessionVersion: string }).appSessionVersion;

      let latestRecoveryOtpCode = '';
      const recoveryFetchImpl: typeof fetch = async (input, init) => {
        const url = String(typeof input === 'string' ? input : input.url || '');
        const nextInit = { ...(init || {}) };
        if (
          url.endsWith('/wallet/email-otp/verify') &&
          nextInit.body &&
          typeof nextInit.body === 'string' &&
          latestRecoveryOtpCode
        ) {
          const body = JSON.parse(nextInit.body);
          nextInit.body = JSON.stringify({ ...body, otpCode: latestRecoveryOtpCode });
        }
        const response = await fetch(input, nextInit);
        if (!url.endsWith('/wallet/email-otp/challenge')) return response;
        const text = await response.text();
        const json = text ? JSON.parse(text) : null;
        const challengeId = String(json?.challenge?.challengeId || '');
        if (challengeId) {
          const recoveryOutbox = await service.readEmailOtpOutboxEntry({
            challengeId,
            userId: 'alice.testnet',
            walletId: 'alice.testnet',
          });
          if (recoveryOutbox.ok) latestRecoveryOtpCode = recoveryOutbox.otpCode;
        }
        return new Response(text, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };

      const recovered = await loginWithEmailOtpAndUnlockWallet({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session-recover',
        fetchImpl: recoveryFetchImpl,
        shamirRuntime: createHandleShamirRuntime(),
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return (
                await secp256k1PrivateKey32ToPublicKey33(
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            if (request.type === 'signSecp256k1Recoverable') {
              return (
                await signSecp256k1Recoverable(
                  new Uint8Array(request.payload.digest32),
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        },
      });

      expect('clientSecretB64u' in recovered).toBe(false);
      expect(recovered.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
      expect(recovered.emailOtpKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      expect(recovered.unlockPublicKeyB64u).toBe(enrolled.unlockPublicKeyB64u);

      const enrollmentRecord = await service.readEmailOtpEnrollment({ walletId: 'alice.testnet' });
      expect(enrollmentRecord.ok).toBe(true);
      if (!enrollmentRecord.ok) return;
      expect(typeof enrollmentRecord.enrollment.lastEmailOtpLoginAtMs).toBe('number');
      expect(enrollmentRecord.enrollment.lastEmailOtpLoginAtMs).toBeGreaterThan(0);
    } finally {
      await srv.close();
    }
  });

  test('SSO session plus Email OTP enrollment persists canonical verifier material over real Email OTP routes', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(appSessionVersion),
    });
    const srv = await startExpressRouter(router);

    try {
      const plaintextSecretB64u = makeClientSecret32B64u(41);
      const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
        clientSecretB64u: plaintextSecretB64u,
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
      });
      const expectedUnlockPublicKeyB64u = base64UrlEncode(
        await secp256k1PrivateKey32ToPublicKey33(
          await deriveEmailOtpUnlockAuthSeed({
            clientSecretB64u: plaintextSecretB64u,
            walletId: 'alice.testnet',
          }),
        ),
      );
      const expectedThresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
        await secp256k1PrivateKey32ToPublicKey33(base64UrlDecode(expectedClientRootShare32B64u)),
      );

      let latestEnrollOtpCode = '';
      const fetchImpl: typeof fetch = async (input, init) => {
        const url = String(typeof input === 'string' ? input : input.url || '');
        const nextInit = { ...(init || {}) };
        if (
          url.endsWith('/wallet/email-otp/enroll/verify') &&
          nextInit.body &&
          typeof nextInit.body === 'string' &&
          latestEnrollOtpCode
        ) {
          const body = JSON.parse(nextInit.body);
          nextInit.body = JSON.stringify({
            ...body,
            otpCode: latestEnrollOtpCode,
          });
        }

        const response = await fetch(input, nextInit);
        if (!url.endsWith('/wallet/email-otp/enroll/challenge')) {
          return response;
        }

        const text = await response.text();
        const json = text ? JSON.parse(text) : null;
        const challengeId = String(json?.challenge?.challengeId || '');
        if (challengeId) {
          const enrollOutbox = await service.readEmailOtpOutboxEntry({
            challengeId,
            userId: 'alice.testnet',
            walletId: 'alice.testnet',
          });
          if (enrollOutbox.ok) {
            latestEnrollOtpCode = enrollOutbox.otpCode;
          }
        }
        return new Response(text, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };

      const result = await enrollEmailOtpWallet({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session',
        clientSecretB64u: plaintextSecretB64u,
        fetchImpl,
        shamirRuntime: createHandleShamirRuntime(),
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return (
                await secp256k1PrivateKey32ToPublicKey33(
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        },
      });

      expect('clientSecretB64u' in result).toBe(false);
      expect(result.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
      expect(result.unlockPublicKeyB64u).toBe(expectedUnlockPublicKeyB64u);
      expect(result.thresholdEcdsaClientVerifyingShareB64u).toBe(
        expectedThresholdEcdsaClientVerifyingShareB64u,
      );
      expect(result.emailOtpKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);

      const enrolled = await service.readEmailOtpEnrollment({ walletId: 'alice.testnet' });
      expect(enrolled.ok).toBe(true);
      if (!enrolled.ok) return;
      expect(enrolled.enrollment.walletId).toBe('alice.testnet');
      expect(enrolled.enrollment.userId).toBe('alice.testnet');
      expect(enrolled.enrollment.otpChannel).toBe('email_otp');
      expect(enrolled.enrollment.emailOtpEscrowBlob).toBe(addServerSeal(plaintextSecretB64u));
      expect(enrolled.enrollment.emailOtpKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      expect(enrolled.enrollment.unlockPublicKey).toBe(expectedUnlockPublicKeyB64u);
      expect(enrolled.enrollment.unlockKeyVersion).toBe('email-otp-unlock-v1');
      expect(enrolled.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe(
        expectedThresholdEcdsaClientVerifyingShareB64u,
      );
      expect(enrolled.enrollment.otpFailureCount).toBe(0);
      expect(enrolled.enrollment.otpLockedUntilMs).toBeUndefined();
      expect(enrolled.enrollment.lastEmailOtpLoginAtMs).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('recovered client secret reaches canonical ECDSA bootstrap input over real Email OTP routes', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(appSessionVersion),
    });
    const srv = await startExpressRouter(router);

    try {
      const enrollChallenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/enroll/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(enrollChallenge.status).toBe(200);
      const enrollChallengeId = String(enrollChallenge.json?.challenge?.challengeId || '');
      const enrollOutbox = await service.readEmailOtpOutboxEntry({
        challengeId: enrollChallengeId,
        userId: 'alice.testnet',
        walletId: 'alice.testnet',
      });
      expect(enrollOutbox.ok).toBe(true);
      if (!enrollOutbox.ok) return;

      const plaintextSecretB64u = makeClientSecret32B64u(23);
      const enrollWrappedCiphertext = addClientSeal(plaintextSecretB64u);
      const enrollSeal = await fetchJson(`${srv.baseUrl}/wallet/email-otp/enroll/seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          wrappedCiphertext: enrollWrappedCiphertext,
        }),
      });
      expect(enrollSeal.status).toBe(200);
      const emailOtpEscrowBlob = removeClientSeal(String(enrollSeal.json?.ciphertext || ''));
      const expectedClientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
        clientSecretB64u: plaintextSecretB64u,
        walletId: 'alice.testnet',
        userId: 'alice.testnet',
      });
      const unlockPublicKey = base64UrlEncode(
        await secp256k1PrivateKey32ToPublicKey33(
          await deriveEmailOtpUnlockAuthSeed({
            clientSecretB64u: plaintextSecretB64u,
            walletId: 'alice.testnet',
          }),
        ),
      );
      const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
        await secp256k1PrivateKey32ToPublicKey33(base64UrlDecode(expectedClientRootShare32B64u)),
      );
      const enrollVerify = await fetchJson(`${srv.baseUrl}/wallet/email-otp/enroll/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId: enrollChallengeId,
          otpChannel: 'email_otp',
          otpCode: enrollOutbox.otpCode,
          emailOtpEscrowBlob,
          emailOtpKeyVersion: EMAIL_OTP_KEY_VERSION,
          unlockPublicKey,
          unlockKeyVersion: 'email-otp-unlock-v1',
          thresholdEcdsaClientVerifyingShareB64u,
        }),
      });
      expect(enrollVerify.status).toBe(200);

      const bootstrapCalls: Array<Record<string, unknown>> = [];
      let latestRecoveryOtpCode = '';
      const fetchImpl: typeof fetch = async (input, init) => {
        const url = String(typeof input === 'string' ? input : input.url || '');
        const nextInit = { ...(init || {}) };
        if (
          url.endsWith('/wallet/email-otp/verify') &&
          nextInit.body &&
          typeof nextInit.body === 'string' &&
          latestRecoveryOtpCode
        ) {
          const body = JSON.parse(nextInit.body);
          nextInit.body = JSON.stringify({
            ...body,
            otpCode: latestRecoveryOtpCode,
          });
        }

        const response = await fetch(input, nextInit);
        if (!url.endsWith('/wallet/email-otp/challenge')) {
          return response;
        }

        const text = await response.text();
        const json = text ? JSON.parse(text) : null;
        const challengeId = String(json?.challenge?.challengeId || '');
        if (challengeId) {
          const recoveryOutbox = await service.readEmailOtpOutboxEntry({
            challengeId,
            userId: 'alice.testnet',
            walletId: 'alice.testnet',
          });
          if (recoveryOutbox.ok) {
            latestRecoveryOtpCode = recoveryOutbox.otpCode;
          }
        }
        return new Response(text, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      };
      const result = await loginWithEmailOtpAndBootstrapEcdsaCapability({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        otpCode: 'placeholder-not-used-by-test-fetch-wrapper',
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session',
        authorizationJwt: 'bootstrap-auth-jwt',
        sessionId: 'ecdsa-session-otp-1',
        ecdsaThresholdKeyId: 'ecdsa-key-otp-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        fetchImpl,
        workerCtx: {
          requestWorkerOperation: async ({ request }: any) => {
            if (request.type === 'secp256k1PrivateKey32ToPublicKey33') {
              return (
                await secp256k1PrivateKey32ToPublicKey33(
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            if (request.type === 'signSecp256k1Recoverable') {
              return (
                await signSecp256k1Recoverable(
                  new Uint8Array(request.payload.digest32),
                  new Uint8Array(request.payload.privateKey32),
                )
              ).buffer.slice(0);
            }
            throw new Error(`Unexpected worker operation: ${request.type}`);
          },
        },
        shamirRuntime: createHandleShamirRuntime(),
        bootstrapEcdsaSession: async (args) => {
          bootstrapCalls.push({ ...args });
          return {
            thresholdEcdsaKeyRef: {
              type: 'threshold-ecdsa-secp256k1',
              userId: 'alice.testnet',
              relayerUrl: srv.baseUrl,
              ecdsaThresholdKeyId: 'ecdsa-key-otp-1',
              backendBinding: {
                relayerKeyId: 'rk-otp-1',
                clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
              },
              participantIds: [1, 2],
              thresholdSessionKind: 'jwt',
              thresholdSessionId: 'ecdsa-session-otp-1',
              thresholdSessionJwt: 'jwt-ecdsa',
            },
            keygen: {
              ok: true,
              ecdsaThresholdKeyId: 'ecdsa-key-otp-1',
              relayerKeyId: 'rk-otp-1',
              clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
              participantIds: [1, 2],
            },
            session: {
              ok: true,
              sessionId: 'ecdsa-session-otp-1',
              jwt: 'jwt-ecdsa',
              remainingUses: 3,
              expiresAtMs: Date.now() + 60_000,
              clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u,
            },
          };
        },
      });

      expect('clientSecretB64u' in result.recovery).toBe(false);
      expect('clientRootShare32B64u' in result.recovery).toBe(false);
      expect(bootstrapCalls).toHaveLength(1);
      expect(bootstrapCalls[0]).toEqual({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        relayerUrl: srv.baseUrl,
        ecdsaThresholdKeyId: 'ecdsa-key-otp-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        sessionId: 'ecdsa-session-otp-1',
        authorizationJwt: 'bootstrap-auth-jwt',
        clientRootShare32B64u: expectedClientRootShare32B64u,
      });
    } finally {
      await srv.close();
    }
  });
});
