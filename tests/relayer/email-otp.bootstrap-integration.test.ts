import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '@server/core/ThresholdService/ethSignerWasm';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '@server/threshold/session/signingSessionSeal';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  deriveEmailOtpEcdsaClientRootShare32B64u,
  deriveEmailOtpUnlockAuthSeed,
} from '../helpers/emailOtpDerivation';
import { enrollEmailOtpWallet } from '@/web/SeamsWeb/emailOtp';
import {
  callCf,
  fetchJson,
  makeCfCtx,
  makeEmailOtpRecoveryWrappedEnrollmentEscrows,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

const EMAIL_OTP_KEY_VERSION = 'kek-s-email-otp-test';
const SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
const CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(
  modInverse(5n, decodePositiveBigIntB64u(SHAMIR_PRIME_B64U) - 1n),
);
const DEFAULT_RUNTIME_POLICY_SCOPE = {
  orgId: 'org_email_otp_bootstrap_integration',
  projectId: 'project_email_otp_bootstrap_integration',
  envId: 'env_email_otp_bootstrap_integration',
} as const;

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
    thresholdStore: {
      SIGNING_SESSION_SEAL_KEY_VERSION: EMAIL_OTP_KEY_VERSION,
      SIGNING_SESSION_SHAMIR_P_B64U: SHAMIR_PRIME_B64U,
      SIGNING_SESSION_SEAL_E_S_B64U: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      SIGNING_SESSION_SEAL_D_S_B64U: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
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
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        runtimePolicyScope: DEFAULT_RUNTIME_POLICY_SCOPE,
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
      const header = Array.isArray(rawHeader)
        ? String(rawHeader[0] || '')
        : String(rawHeader || '');
      const token = header.startsWith('Bearer ') ? header.slice('Bearer '.length).trim() : '';
      const entry = claimsByToken[token];
      const claims = typeof entry === 'function' ? entry() : entry;
      if (!claims) return { ok: false } as const;
      if (claims.kind === 'app_session_v1') {
        return {
          ok: true,
          claims: {
            orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
            runtimePolicyScope: DEFAULT_RUNTIME_POLICY_SCOPE,
            ...claims,
          } as any,
        } as const;
      }
      return { ok: true, claims: claims as any } as const;
    },
  });
}

function addClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.addServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function removeClientSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  return String(
    runtime.removeServerSeal({
      ciphertextB64u,
      exponentB64u: CLIENT_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
}

function addServerSeal(ciphertextB64u: string): string {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
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
    const url = new URL(
      typeof input === 'string'
        ? input
        : input instanceof Request
          ? input.url
          : String(input || 'https://relay.test'),
    );
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

async function requestEmailOtpWithOutbox(args: {
  fetchImpl: typeof fetch;
  relayUrl: string;
  route: '/wallet/email-otp/registration/challenge' | '/wallet/email-otp/login/challenge';
  service: AuthService;
  appSessionJwt: string;
  walletId?: string;
  userId?: string;
}): Promise<{ challengeId: string; otpCode: string }> {
  const walletId = String(args.walletId || 'alice.testnet').trim() || 'alice.testnet';
  const userId = String(args.userId || walletId).trim() || walletId;
  const response = await args.fetchImpl(`${args.relayUrl}${args.route}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${args.appSessionJwt}`,
    },
    body: JSON.stringify({
      walletId,
      otpChannel: 'email_otp',
    }),
  });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  const json = text ? JSON.parse(text) : null;
  const challengeId = String(json?.challenge?.challengeId || '').trim();
  expect(challengeId).toBeTruthy();
  const outbox = await args.service.readEmailOtpOutboxEntry({
    challengeId,
    userId,
    walletId,
  });
  expect(outbox.ok).toBe(true);
  if (!outbox.ok) throw new Error(outbox.message || 'missing Email OTP outbox entry');
  return { challengeId, otpCode: outbox.otpCode };
}

async function postWorkerJson(args: {
  fetchImpl: typeof fetch;
  relayUrl: string;
  path: string;
  appSessionJwt?: string;
  body: Record<string, unknown>;
}): Promise<Record<string, any>> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (args.appSessionJwt) headers.Authorization = `Bearer ${args.appSessionJwt}`;
  const response = await args.fetchImpl(`${args.relayUrl}${args.path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(args.body),
  });
  const text = await response.text();
  expect(response.status, text).toBe(200);
  return text ? JSON.parse(text) : {};
}

const deviceEnrollmentEscrows = new Map<string, string>();
const deviceEnrollmentKey = (walletId: string, userId: string) => `${walletId}:${userId}`;

function createEmailOtpRouteWorkerCtx(args: { fetchImpl: typeof fetch; relayUrl: string }) {
  const readPayloadAppSessionJwt = (payload: Record<string, any>): string => {
    const directJwt = String(payload.appSessionJwt || '').trim();
    if (directJwt) return directJwt;
    const authLane = payload.routePlan?.authLane;
    return authLane?.kind === 'app_session' ? String(authLane.jwt || '').trim() : '';
  };

  const loginWithEmailOtp = async (payload: Record<string, any>) => {
    const appSessionJwt = readPayloadAppSessionJwt(payload);
    const walletId = String(payload.walletId || '').trim();
    const userId = String(payload.userId || walletId).trim() || walletId;
    const challengeId = String(payload.challengeId || '').trim();
    const verified = await postWorkerJson({
      fetchImpl: args.fetchImpl,
      relayUrl: args.relayUrl,
      path: '/wallet/email-otp/login/verify',
      appSessionJwt,
      body: {
        walletId,
        challengeId,
        otpCode: String(payload.otpCode || ''),
        otpChannel: 'email_otp',
      },
    });
    const enrollmentEscrowCiphertextB64u = deviceEnrollmentEscrows.get(
      deviceEnrollmentKey(walletId, userId),
    );
    if (!enrollmentEscrowCiphertextB64u) {
      throw new Error('Missing device-local Email OTP enrollment escrow');
    }
    const wrappedCiphertext = addClientSeal(enrollmentEscrowCiphertextB64u);
    const unsealed = await postWorkerJson({
      fetchImpl: args.fetchImpl,
      relayUrl: args.relayUrl,
      path: '/wallet/email-otp/unseal',
      appSessionJwt,
      body: {
        loginGrant: String(verified.loginGrant || ''),
        wrappedCiphertext,
      },
    });
    const clientSecretB64u = removeClientSeal(String(unsealed.ciphertext || ''));
    const unlockSeed = await deriveEmailOtpUnlockAuthSeed({
      clientSecretB64u,
      walletId,
    });
    const clientUnlockPublicKeyB64u = base64UrlEncode(
      await secp256k1PrivateKey32ToPublicKey33(unlockSeed),
    );
    const unlockChallenge = await postWorkerJson({
      fetchImpl: args.fetchImpl,
      relayUrl: args.relayUrl,
      path: '/wallet/unlock/challenge',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      },
    });
    const unlockChallengeB64u = String(unlockChallenge.challengeB64u || '');
    const unlockSignatureB64u = base64UrlEncode(
      await signSecp256k1Recoverable(base64UrlDecode(unlockChallengeB64u), unlockSeed),
    );
    await postWorkerJson({
      fetchImpl: args.fetchImpl,
      relayUrl: args.relayUrl,
      path: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId,
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        challengeId: String(unlockChallenge.challengeId || ''),
        unlockProof: {
          publicKey: clientUnlockPublicKeyB64u,
          signature: unlockSignatureB64u,
        },
      },
    });
    const clientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
      clientSecretB64u,
      walletId,
      userId,
    });
    return {
      clientRootShare32B64u,
      loginGrant: String(verified.loginGrant || ''),
      challengeId,
      enrollmentSealKeyVersion: String(unsealed.enrollmentSealKeyVersion || ''),
      unlockChallengeId: String(unlockChallenge.challengeId || ''),
      unlockChallengeB64u,
      clientUnlockPublicKeyB64u,
      unlockSignatureB64u,
    };
  };

  return {
    requestWorkerOperation: async ({ request }: any) => {
      const payload = request.payload || {};
      if (request.type === 'enrollEmailOtpWallet') {
        const appSessionJwt = readPayloadAppSessionJwt(payload);
        const walletId = String(payload.walletId || '').trim();
        const userId = String(payload.userId || walletId).trim() || walletId;
        const clientSecret32 =
          payload.clientSecret32 instanceof ArrayBuffer
            ? new Uint8Array(payload.clientSecret32)
            : Uint8Array.from({ length: 32 }, () => 7);
        const clientSecretB64u = base64UrlEncode(clientSecret32);
        const enrollSeal = await postWorkerJson({
          fetchImpl: args.fetchImpl,
          relayUrl: args.relayUrl,
          path: '/wallet/email-otp/registration/seal',
          appSessionJwt,
          body: {
            walletId,
            wrappedCiphertext: addClientSeal(clientSecretB64u),
          },
        });
        const enrollmentEscrowCiphertextB64u = removeClientSeal(
          String(enrollSeal.ciphertext || ''),
        );
        deviceEnrollmentEscrows.set(
          deviceEnrollmentKey(walletId, userId),
          enrollmentEscrowCiphertextB64u,
        );
        const clientRootShare32B64u = await deriveEmailOtpEcdsaClientRootShare32B64u({
          clientSecretB64u,
          walletId,
          userId,
        });
        const clientUnlockPublicKeyB64u = base64UrlEncode(
          await secp256k1PrivateKey32ToPublicKey33(
            await deriveEmailOtpUnlockAuthSeed({ clientSecretB64u, walletId }),
          ),
        );
        const thresholdEcdsaClientVerifyingShareB64u = base64UrlEncode(
          await secp256k1PrivateKey32ToPublicKey33(base64UrlDecode(clientRootShare32B64u)),
        );
        await postWorkerJson({
          fetchImpl: args.fetchImpl,
          relayUrl: args.relayUrl,
          path: '/wallet/email-otp/registration/finalize',
          appSessionJwt,
          body: {
            walletId,
            challengeId: String(payload.challengeId || ''),
            otpCode: String(payload.otpCode || ''),
            otpChannel: 'email_otp',
            recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
              walletId,
              userId,
              enrollmentSealKeyVersion: String(enrollSeal.enrollmentSealKeyVersion || ''),
            }),
            enrollmentSealKeyVersion: String(enrollSeal.enrollmentSealKeyVersion || ''),
            clientUnlockPublicKeyB64u: clientUnlockPublicKeyB64u,
            unlockKeyVersion: 'email-otp-unlock-v1',
            thresholdEcdsaClientVerifyingShareB64u,
          },
        });
        return {
          clientRootShare32B64u,
          thresholdEcdsaClientVerifyingShareB64u,
          challengeId: String(payload.challengeId || ''),
          otpChannel: 'email_otp',
          enrollmentSealKeyVersion: String(enrollSeal.enrollmentSealKeyVersion || ''),
          clientUnlockPublicKeyB64u,
          unlockKeyVersion: 'email-otp-unlock-v1',
        };
      }
      if (request.type === 'testRecoverEmailOtpWithRouteWorker') {
        return await loginWithEmailOtp(payload);
      }
      if (request.type === 'testPrepareEmailOtpEcdsaBootstrapWithRouteWorker') {
        const recovered = await loginWithEmailOtp(payload);
        return {
          loginGrant: recovered.loginGrant,
          challengeId: recovered.challengeId,
          enrollmentSealKeyVersion: recovered.enrollmentSealKeyVersion,
          unlockChallengeId: recovered.unlockChallengeId,
          unlockChallengeB64u: recovered.unlockChallengeB64u,
          clientUnlockPublicKeyB64u: recovered.clientUnlockPublicKeyB64u,
          unlockSignatureB64u: recovered.unlockSignatureB64u,
          clientRootShare32: base64UrlDecode(recovered.clientRootShare32B64u).buffer.slice(0),
        };
      }
      throw new Error(`Unexpected worker operation: ${request.type}`);
    },
  };
}

async function recoverEmailOtpWithRouteWorker(args: {
  fetchImpl: typeof fetch;
  relayUrl: string;
  walletId: string;
  challengeId: string;
  otpCode: string;
  appSessionJwt: string;
}) {
  return await createEmailOtpRouteWorkerCtx({
    fetchImpl: args.fetchImpl,
    relayUrl: args.relayUrl,
  }).requestWorkerOperation({
    request: {
      type: 'testRecoverEmailOtpWithRouteWorker',
      payload: {
        relayUrl: args.relayUrl,
        walletId: args.walletId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: args.appSessionJwt,
      },
    },
  });
}

async function bootstrapEmailOtpViaRouteWorker(args: {
  fetchImpl: typeof fetch;
  relayUrl: string;
  walletId: string;
  challengeId: string;
  otpCode: string;
  appSessionJwt: string;
  routeAuth: { kind: 'app_session'; jwt: string };
  sessionId: string;
  ecdsaThresholdKeyId: string;
  participantIds: number[];
  sessionKind: 'jwt' | 'cookie';
  bootstrapEcdsaSession: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
}) {
  const prepared = await createEmailOtpRouteWorkerCtx({
    fetchImpl: args.fetchImpl,
    relayUrl: args.relayUrl,
  }).requestWorkerOperation({
    request: {
      type: 'testPrepareEmailOtpEcdsaBootstrapWithRouteWorker',
      payload: {
        relayUrl: args.relayUrl,
        walletId: args.walletId,
        challengeId: args.challengeId,
        otpCode: args.otpCode,
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: args.appSessionJwt,
      },
    },
  });
  const preparedRecord = prepared as Record<string, unknown>;
  const clientRootShare32 =
    preparedRecord.clientRootShare32 instanceof ArrayBuffer
      ? new Uint8Array(preparedRecord.clientRootShare32)
      : String(preparedRecord.clientRootShare32B64u || '').trim()
        ? base64UrlDecode(String(preparedRecord.clientRootShare32B64u || '').trim())
        : null;
  if (!clientRootShare32) {
    throw new Error('Email OTP ECDSA preparation did not return clientRootShare32');
  }
  try {
    const bootstrap = await args.bootstrapEcdsaSession({
      nearAccountId: args.walletId,
      chain: 'evm',
      relayerUrl: args.relayUrl,
      ecdsaThresholdKeyId: args.ecdsaThresholdKeyId,
      participantIds: args.participantIds,
      sessionKind: args.sessionKind,
      sessionId: args.sessionId,
      routeAuth: args.routeAuth,
      clientRootShare32,
    });
    return {
      recovery: {
        loginGrant: prepared.loginGrant,
        challengeId: prepared.challengeId,
        enrollmentSealKeyVersion: prepared.enrollmentSealKeyVersion,
        unlockChallengeId: prepared.unlockChallengeId,
        unlockChallengeB64u: prepared.unlockChallengeB64u,
        clientUnlockPublicKeyB64u: prepared.clientUnlockPublicKeyB64u,
        unlockSignatureB64u: prepared.unlockSignatureB64u,
      },
      bootstrap,
    };
  } finally {
    clientRootShare32.fill(0);
  }
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

    const enrollOtp = await requestEmailOtpWithOutbox({
      fetchImpl: cfFetch,
      relayUrl,
      route: '/wallet/email-otp/registration/challenge',
      service,
      appSessionJwt: 'app-session-enroll',
    });
    const enrolled = await enrollEmailOtpWallet({
      relayUrl,
      walletId: 'alice.testnet',
      challengeId: enrollOtp.challengeId,
      otpCode: enrollOtp.otpCode,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
      appSessionJwt: 'app-session-enroll',
      clientSecret32: base64UrlDecode(plaintextSecretB64u),
      workerCtx: createEmailOtpRouteWorkerCtx({ fetchImpl: cfFetch, relayUrl }),
    });

    const rotatedVersion = await service.rotateAppSessionVersion({ userId: 'alice.testnet' });
    expect(rotatedVersion.ok).toBe(true);
    recoveryAppSessionVersion = (rotatedVersion as { appSessionVersion: string }).appSessionVersion;

    const recoveryOtp = await requestEmailOtpWithOutbox({
      fetchImpl: cfFetch,
      relayUrl,
      route: '/wallet/email-otp/login/challenge',
      service,
      appSessionJwt: 'app-session-recover',
    });
    const bootstrapCalls: Array<Record<string, unknown>> = [];
    const result = await bootstrapEmailOtpViaRouteWorker({
      fetchImpl: cfFetch,
      relayUrl,
      walletId: 'alice.testnet',
      challengeId: recoveryOtp.challengeId,
      otpCode: recoveryOtp.otpCode,
      appSessionJwt: 'app-session-recover',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      sessionId: 'ecdsa-session-cf-1',
      ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      bootstrapEcdsaSession: async (args) => {
        bootstrapCalls.push({
          ...args,
          ...(args.clientRootShare32 instanceof Uint8Array
            ? { clientRootShare32: Uint8Array.from(args.clientRootShare32) }
            : {}),
        });
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
            thresholdSessionAuthToken: 'jwt-ecdsa-cf',
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
    expect(result.recovery.clientUnlockPublicKeyB64u).toBe(enrolled.clientUnlockPublicKeyB64u);
    expect(bootstrapCalls).toHaveLength(1);
    expect(bootstrapCalls[0]).toEqual({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      relayerUrl: relayUrl,
      ecdsaThresholdKeyId: 'ecdsa-key-cf-1',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      sessionId: 'ecdsa-session-cf-1',
      routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
      clientRootShare32: base64UrlDecode(expectedClientRootShare32B64u),
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

      const enrollOtp = await requestEmailOtpWithOutbox({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        route: '/wallet/email-otp/registration/challenge',
        service,
        appSessionJwt: 'app-session-enroll',
      });
      const enrolled = await enrollEmailOtpWallet({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        challengeId: enrollOtp.challengeId,
        otpCode: enrollOtp.otpCode,
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session-enroll',
        clientSecret32: base64UrlDecode(plaintextSecretB64u),
        workerCtx: createEmailOtpRouteWorkerCtx({ fetchImpl: fetch, relayUrl: srv.baseUrl }),
      });

      const rotatedVersion = await service.rotateAppSessionVersion({ userId: 'alice.testnet' });
      expect(rotatedVersion.ok).toBe(true);
      recoveryAppSessionVersion = (rotatedVersion as { appSessionVersion: string })
        .appSessionVersion;

      const recoveryOtp = await requestEmailOtpWithOutbox({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        route: '/wallet/email-otp/login/challenge',
        service,
        appSessionJwt: 'app-session-recover',
      });
      const recovered = await recoverEmailOtpWithRouteWorker({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        challengeId: recoveryOtp.challengeId,
        otpCode: recoveryOtp.otpCode,
        appSessionJwt: 'app-session-recover',
      });

      expect('clientSecretB64u' in recovered).toBe(false);
      expect(recovered.clientRootShare32B64u).toBe(expectedClientRootShare32B64u);
      expect(recovered.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      expect(recovered.clientUnlockPublicKeyB64u).toBe(enrolled.clientUnlockPublicKeyB64u);

      const enrollmentRecord = await service.readEmailOtpEnrollment({
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      });
      expect(enrollmentRecord.ok).toBe(true);
      if (!enrollmentRecord.ok) return;
      const authState = await (service as any).getEmailOtpAuthStateStore().get('alice.testnet');
      expect(typeof authState?.lastEmailOtpLoginAtMs).toBe('number');
      expect(authState?.lastEmailOtpLoginAtMs).toBeGreaterThan(0);
    } finally {
      await srv.close();
    }
  });

  test('Email OTP app-session routes reject threshold-session auth tokens', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'threshold-session-token': {
          kind: 'threshold_ecdsa_session_v1',
          sub: 'alice.testnet',
          walletId: 'alice.testnet',
          rpId: 'example.localhost',
          sessionId: 'threshold-ecdsa-session-1',
          relayerKeyId: 'rk-1',
          participantIds: [1, 2],
          thresholdExpiresAtMs: Date.now() + 60_000,
        },
      }),
    });
    const srv = await startExpressRouter(router);

    try {
      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-session-token',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(401);
      expect(challenge.json?.code).toBe('unauthorized');
      expect(challenge.json?.message).toBe('No valid app session');

      const verify = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-session-token',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId: 'challenge-not-used',
          otpChannel: 'email_otp',
          otpCode: '123456',
        }),
      });
      expect(verify.status).toBe(401);
      expect(verify.json?.code).toBe('unauthorized');
      expect(verify.json?.message).toBe('No valid app session');
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

      const enrollOtp = await requestEmailOtpWithOutbox({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        route: '/wallet/email-otp/registration/challenge',
        service,
        appSessionJwt: 'app-session',
      });
      const result = await enrollEmailOtpWallet({
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        challengeId: enrollOtp.challengeId,
        otpCode: enrollOtp.otpCode,
        shamirPrimeB64u: SHAMIR_PRIME_B64U,
        appSessionJwt: 'app-session',
        clientSecret32: base64UrlDecode(plaintextSecretB64u),
        workerCtx: createEmailOtpRouteWorkerCtx({ fetchImpl: fetch, relayUrl: srv.baseUrl }),
      });

      expect('clientSecretB64u' in result).toBe(false);
      expect(result.clientUnlockPublicKeyB64u).toBe(expectedUnlockPublicKeyB64u);
      expect(result.thresholdEcdsaClientVerifyingShareB64u).toBe(
        expectedThresholdEcdsaClientVerifyingShareB64u,
      );
      expect(result.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);

      const enrolled = await service.readEmailOtpEnrollment({
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      });
      expect(enrolled.ok).toBe(true);
      if (!enrolled.ok) return;
      expect(enrolled.enrollment.walletId).toBe('alice.testnet');
      expect(enrolled.enrollment.providerUserId).toBe('alice.testnet');
      expect(enrolled.enrollment.recoveryWrappedEnrollmentEscrowCount).toBe(10);
      expect(enrolled.enrollment.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      expect(enrolled.enrollment.clientUnlockPublicKeyB64u).toBe(expectedUnlockPublicKeyB64u);
      expect(enrolled.enrollment.unlockKeyVersion).toBe('email-otp-unlock-v1');
      expect(enrolled.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe(
        expectedThresholdEcdsaClientVerifyingShareB64u,
      );
      const authState = await (service as any).getEmailOtpAuthStateStore().get('alice.testnet');
      expect(authState?.otpFailureCount).toBe(0);
      expect(authState?.otpLockedUntilMs).toBeUndefined();
      expect(authState?.lastEmailOtpLoginAtMs).toBeUndefined();
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
      const enrollChallenge = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/registration/challenge`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
          }),
        },
      );
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
      const enrollSeal = await fetchJson(`${srv.baseUrl}/wallet/email-otp/registration/seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          wrappedCiphertext: enrollWrappedCiphertext,
        }),
      });
      expect(enrollSeal.status).toBe(200);
      const enrollmentEscrowCiphertextB64u = removeClientSeal(
        String(enrollSeal.json?.ciphertext || ''),
      );
      expect(enrollmentEscrowCiphertextB64u).toBe(addServerSeal(plaintextSecretB64u));
      deviceEnrollmentEscrows.set(
        deviceEnrollmentKey('alice.testnet', 'alice.testnet'),
        enrollmentEscrowCiphertextB64u,
      );
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
      const enrollVerify = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/registration/finalize`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId: enrollChallengeId,
            otpChannel: 'email_otp',
            otpCode: enrollOutbox.otpCode,
            recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
              walletId: 'alice.testnet',
              userId: 'alice.testnet',
              enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
            }),
            enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
            clientUnlockPublicKeyB64u: unlockPublicKey,
            unlockKeyVersion: 'email-otp-unlock-v1',
            thresholdEcdsaClientVerifyingShareB64u,
          }),
        },
      );
      expect(enrollVerify.status).toBe(200);

      const bootstrapCalls: Array<Record<string, unknown>> = [];
      const recoveryOtp = await requestEmailOtpWithOutbox({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        route: '/wallet/email-otp/login/challenge',
        service,
        appSessionJwt: 'app-session',
      });
      const result = await bootstrapEmailOtpViaRouteWorker({
        fetchImpl: fetch,
        relayUrl: srv.baseUrl,
        walletId: 'alice.testnet',
        challengeId: recoveryOtp.challengeId,
        otpCode: recoveryOtp.otpCode,
        appSessionJwt: 'app-session',
        routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
        sessionId: 'ecdsa-session-otp-1',
        ecdsaThresholdKeyId: 'ecdsa-key-otp-1',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        bootstrapEcdsaSession: async (args) => {
          bootstrapCalls.push({
            ...args,
            ...(args.clientRootShare32 instanceof Uint8Array
              ? { clientRootShare32: Uint8Array.from(args.clientRootShare32) }
              : {}),
          });
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
              thresholdSessionAuthToken: 'jwt-ecdsa',
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
        routeAuth: { kind: 'app_session', jwt: 'bootstrap-auth-jwt' },
        clientRootShare32: base64UrlDecode(expectedClientRootShare32B64u),
      });
    } finally {
      await srv.close();
    }
  });
});
