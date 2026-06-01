import { test, expect } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { signSecp256k1Recoverable } from '@server/core/ThresholdService/ethSignerWasm';
import {
  createInMemoryConsoleWebhookService,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '@server/threshold/session/signingSessionSeal';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
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
const SHAMIR_PRIME_B64U = encodePositiveBigIntB64u(257n);
const SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(3n);
const SHAMIR_SERVER_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(171n);
const CLIENT_ENCRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(5n);
const CLIENT_DECRYPT_EXPONENT_B64U = encodePositiveBigIntB64u(205n);
const VALID_SECP256K1_PRIVATE_KEY_32 = Uint8Array.from(
  Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex'),
);
const VALID_SECP256K1_PUBLIC_KEY_33_B64U = base64UrlEncode(
  Uint8Array.from(
    Buffer.from('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex'),
  ),
);
const GOOGLE_EMAIL_OTP_USER_ID = 'google:117142622123955425762';
const DEFAULT_RUNTIME_POLICY_SCOPE = {
  orgId: 'org_email_otp_routes',
  projectId: 'project_email_otp_routes',
  envId: 'env_email_otp_routes',
  signingRootVersion: 'v1',
} as const;

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

function makeWrappedCiphertext(plaintextSecretB64u: string): {
  wrappedCiphertext: string;
  clientCiphertext: string;
} {
  const runtime = createSigningSessionSealShamir3PassBigIntRuntime();
  const escrowCiphertext = String(
    runtime.addServerSeal({
      ciphertextB64u: plaintextSecretB64u,
      exponentB64u: SHAMIR_SERVER_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
  const wrappedCiphertext = String(
    runtime.addServerSeal({
      ciphertextB64u: escrowCiphertext,
      exponentB64u: CLIENT_ENCRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
  const clientCiphertext = String(
    runtime.removeServerSeal({
      ciphertextB64u: wrappedCiphertext,
      exponentB64u: SHAMIR_SERVER_DECRYPT_EXPONENT_B64U,
      shamirPrimeB64u: SHAMIR_PRIME_B64U,
    }),
  );
  return { wrappedCiphertext, clientCiphertext };
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

async function seedCanonicalWallet(
  service: AuthService,
  walletId = 'alice.testnet',
  rpId = 'localhost',
): Promise<void> {
  const walletStore = (service as any).getWalletStore();
  const existing = await walletStore.getWallet({ walletId });
  if (existing) return;
  const nowMs = Date.now();
  await walletStore.putSubject({
    version: 'wallet_v1',
    walletId,
    rpId,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
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

function makeGoogleEmailOtpAppSessionAdapter(appSessionVersion: string) {
  return makeSessionAdapter({
    parse: async () => ({
      ok: true,
      claims: {
        kind: 'app_session_v1',
        sub: GOOGLE_EMAIL_OTP_USER_ID,
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        runtimePolicyScope: DEFAULT_RUNTIME_POLICY_SCOPE,
        appSessionVersion,
        provider: 'oidc',
        oidcProvider: 'google',
        providerSubject: GOOGLE_EMAIL_OTP_USER_ID,
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
      if (
        claims.kind === 'threshold_ed25519_session_v1' ||
        claims.kind === 'threshold_ecdsa_session_v2'
      ) {
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

function makeThresholdSessionClaims(overrides?: Record<string, unknown>): Record<string, unknown> {
  return {
    kind: 'threshold_ecdsa_session_v2',
    sub: 'alice.testnet',
    walletId: 'alice.testnet',
    sessionId: 'ecdsa-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    keyScope: 'evm-family',
    relayerKeyId: 'relayer-key-1',
    keyHandle: 'ecdsa-key-handle-1',
    rpId: 'example.localhost',
    orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
    runtimePolicyScope: DEFAULT_RUNTIME_POLICY_SCOPE,
    thresholdExpiresAtMs: Date.now() + 60_000,
    participantIds: [1, 2],
    ...overrides,
  };
}

function makeSigningSessionStatusPolicy(args?: {
  claims?: Record<string, unknown>;
  statusById?: Record<string, any | null>;
  onStatusRead?: (thresholdSessionId: string) => void;
  onConsumeUseCount?: (thresholdSessionId: string) => void;
}) {
  const claims = args?.claims || makeThresholdSessionClaims();
  const userId = String(claims.sub || 'alice.testnet');
  const sessionId = String(claims.sessionId || 'ecdsa-session-1');
  const walletSigningSessionId = String(
    claims.walletSigningSessionId || 'wallet-signing-session-1',
  );
  const rpId = String(claims.rpId || 'example.localhost');
  const relayerKeyId = String(claims.relayerKeyId || 'relayer-key-1');
  const participantIds = Array.isArray(claims.participantIds)
    ? claims.participantIds.map((value) => Number(value))
    : [1, 2];
  const expiresAtMs = Math.floor(Number(claims.thresholdExpiresAtMs) || Date.now() + 60_000);
  const makeThresholdStatus = (id: string, recordRelayerKeyId: string) => ({
    kind: 'threshold_session' as const,
    curve: 'ecdsa' as const,
    thresholdSessionId: id,
    userId,
    expiresAtMs,
    remainingUses: 7,
    relayerKeyId: recordRelayerKeyId,
    rpId,
    participantIds,
  });
  const makeWalletBudgetStatus = (id: string, recordRelayerKeyId: string) => ({
    kind: 'wallet_budget' as const,
    curve: 'ecdsa' as const,
    thresholdSessionId: id,
    walletSigningSessionId,
    userId,
    expiresAtMs,
    remainingUses: 7,
    relayerKeyId: recordRelayerKeyId,
    rpId,
    participantIds,
  });
  const walletBudgetId = `wallet-signing:${walletSigningSessionId}`;
  const statusById: Record<string, any | null> = {
    [sessionId]: makeThresholdStatus(sessionId, relayerKeyId),
    [walletBudgetId]: makeWalletBudgetStatus(walletBudgetId, 'wallet-signing-budget'),
    ...(args?.statusById || {}),
  };
  return {
    getThresholdSession: async ({
      thresholdSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      thresholdSessionId: string;
    }) => {
      const status = statusById[thresholdSessionId];
      if (!status || status.kind !== 'threshold_session') return null;
      return {
        curve: 'ecdsa' as const,
        thresholdSessionId,
        userId: status.userId,
        expiresAtMs: status.expiresAtMs,
        relayerKeyId: status.relayerKeyId,
        rpId: status.rpId,
        participantIds: status.participantIds,
        remainingUses: status.remainingUses,
      };
    },
    getThresholdSessionStatuses: async ({
      thresholdSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      thresholdSessionId: string;
    }) => {
      args?.onStatusRead?.(thresholdSessionId);
      const status = statusById[thresholdSessionId] || null;
      return status?.kind === 'threshold_session' ? [status] : [];
    },
    getWalletBudgetStatus: async ({
      walletSigningSessionId: requestedWalletSigningSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      walletSigningSessionId: string;
    }) => {
      args?.onStatusRead?.(`wallet-signing:${requestedWalletSigningSessionId}`);
      const walletStatus = statusById[`wallet-signing:${requestedWalletSigningSessionId}`] || null;
      return walletStatus?.kind === 'wallet_budget' ? walletStatus : null;
    },
    consumeUseCount: async ({
      thresholdSessionId,
    }: {
      curve: 'ecdsa' | 'ed25519';
      thresholdSessionId: string;
    }) => {
      args?.onConsumeUseCount?.(thresholdSessionId);
      return { ok: false, code: 'test_forbidden', message: 'unexpected consumeUseCount' };
    },
  };
}

function makeSigningSessionSealOptions(args?: {
  claims?: Record<string, unknown>;
  statusById?: Record<string, any | null>;
  onStatusRead?: (thresholdSessionId: string) => void;
  onConsumeUseCount?: (thresholdSessionId: string) => void;
}) {
  return {
    enabled: true,
    service: {
      applyServerSeal: async () => ({
        ok: false as const,
        code: 'not_implemented',
        message: 'not implemented',
      }),
      removeServerSeal: async () => ({
        ok: false as const,
        code: 'not_implemented',
        message: 'not implemented',
      }),
    },
    sessionPolicy: makeSigningSessionStatusPolicy(args),
  };
}

function makeWebhookRecorder() {
  const dispatched: Array<{ eventType: string; payload: Record<string, unknown> }> = [];
  const webhooks = createInMemoryConsoleWebhookService({
    dispatcher: {
      dispatch: async (input) => {
        const body = JSON.parse(input.body) as Record<string, unknown>;
        dispatched.push({
          eventType: String(body.type || ''),
          payload:
            body.data && typeof body.data === 'object' && !Array.isArray(body.data)
              ? (body.data as Record<string, unknown>)
              : {},
        });
        return { ok: true, statusCode: 200, responseBody: 'ok' };
      },
    },
  });
  return { dispatched, webhooks };
}

async function enrollEmailOtpOverExpress(args: {
  service: AuthService;
  baseUrl: string;
  authToken?: string;
  userId?: string;
}): Promise<void> {
  await seedCanonicalWallet(args.service);
  const authToken = args.authToken || 'app-session';
  const userId = args.userId || 'alice.testnet';
  const enrollChallenge = await fetchJson(
    `${args.baseUrl}/wallet/email-otp/registration/challenge`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
      body: JSON.stringify({
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      }),
    },
  );
  expect(enrollChallenge.status).toBe(200);
  const enrollChallengeId = String(enrollChallenge.json?.challenge?.challengeId || '');
  const enrollOutbox = await fetchJson(
    `${args.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(enrollChallengeId)}&walletId=alice.testnet`,
    {
      method: 'GET',
      headers: { Authorization: `Bearer ${authToken}` },
    },
  );
  expect(enrollOutbox.status).toBe(200);
  const enrollOtpCode = String(enrollOutbox.json?.otpCode || '');
  const enrollPlaintextSecretB64u = encodePositiveBigIntB64u(11n);
  const enrollWrappedCiphertext = addClientSeal(enrollPlaintextSecretB64u);
  const enrollSeal = await fetchJson(`${args.baseUrl}/wallet/email-otp/registration/seal`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
    body: JSON.stringify({
      walletId: 'alice.testnet',
      wrappedCiphertext: enrollWrappedCiphertext,
    }),
  });
  expect(enrollSeal.status).toBe(200);
  const enrollmentEscrowCiphertextB64u = removeClientSeal(
    String(enrollSeal.json?.ciphertext || ''),
  );
  expect(enrollmentEscrowCiphertextB64u).toBe(addServerSeal(enrollPlaintextSecretB64u));
  const enrollVerify = await fetchJson(`${args.baseUrl}/wallet/email-otp/registration/finalize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${authToken}` },
    body: JSON.stringify({
      walletId: 'alice.testnet',
      challengeId: enrollChallengeId,
      otpChannel: 'email_otp',
      otpCode: enrollOtpCode,
      recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
        walletId: 'alice.testnet',
        userId,
        enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
      }),
      enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
      clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
    }),
  });
  expect(enrollVerify.status).toBe(200);
}

async function enrollEmailOtpOverCloudflare(args: {
  service: AuthService;
  handler: ReturnType<typeof createCloudflareRouter>;
  ctx: Awaited<ReturnType<typeof makeCfCtx>>['ctx'];
  authToken?: string;
  userId?: string;
}): Promise<void> {
  await seedCanonicalWallet(args.service);
  const authToken = args.authToken || 'app-session';
  const userId = args.userId || 'alice.testnet';
  const enrollChallenge = await callCf(args.handler, {
    method: 'POST',
    path: '/wallet/email-otp/registration/challenge',
    headers: { Authorization: `Bearer ${authToken}` },
    body: {
      walletId: 'alice.testnet',
      otpChannel: 'email_otp',
    },
    ctx: args.ctx,
  });
  expect(enrollChallenge.status).toBe(200);
  const enrollChallengeId = String(enrollChallenge.json?.challenge?.challengeId || '');
  const enrollOutbox = await callCf(args.handler, {
    method: 'GET',
    path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(enrollChallengeId)}&walletId=alice.testnet`,
    headers: { Authorization: `Bearer ${authToken}` },
    ctx: args.ctx,
  });
  expect(enrollOutbox.status).toBe(200);
  const enrollOtpCode = String(enrollOutbox.json?.otpCode || '');
  const enrollPlaintextSecretB64u = encodePositiveBigIntB64u(13n);
  const enrollWrappedCiphertext = addClientSeal(enrollPlaintextSecretB64u);
  const enrollSeal = await callCf(args.handler, {
    method: 'POST',
    path: '/wallet/email-otp/registration/seal',
    headers: { Authorization: `Bearer ${authToken}` },
    body: {
      walletId: 'alice.testnet',
      wrappedCiphertext: enrollWrappedCiphertext,
    },
    ctx: args.ctx,
  });
  expect(enrollSeal.status).toBe(200);
  const enrollmentEscrowCiphertextB64u = removeClientSeal(
    String(enrollSeal.json?.ciphertext || ''),
  );
  expect(enrollmentEscrowCiphertextB64u).toBe(addServerSeal(enrollPlaintextSecretB64u));
  const enrollVerify = await callCf(args.handler, {
    method: 'POST',
    path: '/wallet/email-otp/registration/finalize',
    headers: { Authorization: `Bearer ${authToken}` },
    body: {
      walletId: 'alice.testnet',
      challengeId: enrollChallengeId,
      otpChannel: 'email_otp',
      otpCode: enrollOtpCode,
      recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
        walletId: 'alice.testnet',
        userId,
        enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
      }),
      enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
      clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      unlockKeyVersion: 'email-otp-unlock-v1',
      thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
    },
    ctx: args.ctx,
  });
  expect(enrollVerify.status).toBe(200);
}

test.describe('Email OTP routes', () => {
  test('Express: login challenge requires completed Email OTP enrollment', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const srv = await startExpressRouter(router);
    try {
      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(404);
      expect(challenge.json?.code).toBe('not_found');
    } finally {
      await srv.close();
    }
  });

  test('Cloudflare: login challenge requires completed Email OTP enrollment', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(404);
    expect(challenge.json?.code).toBe('not_found');
  });

  test('Express: recovery challenge returns only recovery-wrapped enrollment escrows after OTP', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });
      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/recovery-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(200);
      expect(challenge.json?.challenge?.action).toBe('wallet_email_otp_device_recovery');
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session' },
        },
      );
      expect(outbox.status).toBe(200);

      const recovered = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/recovery-wrapped-escrows`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId,
            otpChannel: 'email_otp',
            otpCode: outbox.json?.otpCode,
          }),
        },
      );
      expect(recovered.status).toBe(200);
      expect(typeof recovered.json?.recoveryConsumeGrant).toBe('string');
      const records = recovered.json?.recoveryWrappedEnrollmentEscrows;
      expect(Array.isArray(records) && records.length).toBe(10);
      expect(JSON.stringify(records)).not.toContain('encSB64u');
      expect(records?.[0]).toMatchObject({
        version: 'email_otp_recovery_wrapped_enrollment_escrow_v1',
        walletId: 'alice.testnet',
        recoveryKeyStatus: 'active',
      });
      expect(typeof records?.[0]?.nonceB64u).toBe('string');
      expect(typeof records?.[0]?.wrappedDeviceEnrollmentEscrowB64u).toBe('string');
      const rejectedFailureReport = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/recovery-key/attempt-failed`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            recoveryConsumeGrant: recovered.json?.recoveryConsumeGrant,
            recoveryKey: 'must-not-be-sent',
          }),
        },
      );
      expect(rejectedFailureReport.status).toBe(400);
      expect(rejectedFailureReport.json?.code).toBe('invalid_body');

      const failureReport = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/recovery-key/attempt-failed`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            recoveryConsumeGrant: recovered.json?.recoveryConsumeGrant,
          }),
        },
      );
      expect(failureReport.status).toBe(200);
      expect(failureReport.json).toMatchObject({
        ok: true,
        walletId: 'alice.testnet',
      });

      const consume = await fetchJson(`${srv.baseUrl}/wallet/email-otp/recovery-key/consume`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          recoveryKeyId: records?.[0]?.recoveryKeyId,
          recoveryConsumeGrant: recovered.json?.recoveryConsumeGrant,
        }),
      });
      expect(consume.status).toBe(200);
      expect(consume.json).toMatchObject({
        ok: true,
        walletId: 'alice.testnet',
        recoveryKeyId: records?.[0]?.recoveryKeyId,
        activeRecoveryWrappedEnrollmentEscrowCount: 9,
      });
      const consumeAgain = await fetchJson(`${srv.baseUrl}/wallet/email-otp/recovery-key/consume`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          recoveryKeyId: records?.[0]?.recoveryKeyId,
          recoveryConsumeGrant: recovered.json?.recoveryConsumeGrant,
        }),
      });
      expect(consumeAgain.status).toBe(400);
      expect(consumeAgain.json?.code).toBe('recovery_consume_grant_invalid_or_expired');
    } finally {
      await srv.close();
    }
  });

  test('Cloudflare: recovery challenge returns only recovery-wrapped enrollment escrows after OTP', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();
    await enrollEmailOtpOverCloudflare({ service, handler, ctx: cf.ctx });
    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/recovery-challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(200);
    const challengeId = String(challenge.json?.challenge?.challengeId || '');
    const outbox = await callCf(handler, {
      method: 'GET',
      path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
      headers: { Authorization: 'Bearer app-session' },
      ctx: cf.ctx,
    });
    expect(outbox.status).toBe(200);
    const recovered = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/recovery-wrapped-escrows',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        challengeId,
        otpChannel: 'email_otp',
        otpCode: outbox.json?.otpCode,
      },
      ctx: cf.ctx,
    });
    expect(recovered.status).toBe(200);
    expect(typeof recovered.json?.recoveryConsumeGrant).toBe('string');
    const records = recovered.json?.recoveryWrappedEnrollmentEscrows;
    expect(Array.isArray(records) && records.length).toBe(10);
    expect(JSON.stringify(records)).not.toContain('encSB64u');
    const consume = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/recovery-key/consume',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        recoveryKeyId: records?.[0]?.recoveryKeyId,
        recoveryConsumeGrant: recovered.json?.recoveryConsumeGrant,
      },
      ctx: cf.ctx,
    });
    expect(consume.status).toBe(200);
    expect(consume.json?.activeRecoveryWrappedEnrollmentEscrowCount).toBe(9);
  });

  test('Express: export_key Email OTP challenge and verify use route policy and emit export audit events', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-export-policy-express', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const authorizations: Array<Record<string, unknown>> = [];
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-export-policy-express',
      },
      emailOtpExportPolicy: {
        authorize: async (input) => {
          authorizations.push(input as unknown as Record<string, unknown>);
          return {
            ok: true,
            decision: 'ALLOW',
            policyId: 'policy_export_allowed',
            approvalId: `approval_${input.phase}`,
            reason: 'test export policy allow',
          };
        },
      },
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });
      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
          operation: 'export_key',
        }),
      });
      expect(challenge.status).toBe(200);
      expect(challenge.json?.challenge?.operation).toBe('export_key');
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session' },
        },
      );
      expect(outbox.status).toBe(200);
      const otpCode = String(outbox.json?.otpCode || '');
      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
          operation: 'export_key',
        }),
      });
      expect(verified.status).toBe(200);
      expect(verified.json?.ok).toBe(true);

      expect(authorizations.map((entry) => entry.phase)).toEqual(['challenge', 'verify']);
      expect(authorizations[0]).toMatchObject({
        operation: 'export_key',
        userId: 'alice.testnet',
        walletId: 'alice.testnet',
      });
      expect(authorizations[1]).toMatchObject({
        operation: 'export_key',
        phase: 'verify',
        challengeId,
      });
      const challengeEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.export_challenge_issued',
      );
      expect(challengeEvent?.payload).toMatchObject({
        walletId: 'alice.testnet',
        operation: 'export_key',
        source: 'login_challenge',
        challengeId,
        policyDecision: 'ALLOW',
        policySource: 'adapter',
        policyId: 'policy_export_allowed',
        approvalId: 'approval_challenge',
      });
      const approvedEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.export_approved',
      );
      expect(approvedEvent?.payload).toMatchObject({
        walletId: 'alice.testnet',
        operation: 'export_key',
        source: 'login_verify',
        challengeId,
        policyDecision: 'ALLOW',
        policySource: 'adapter',
        policyId: 'policy_export_allowed',
        approvalId: 'approval_verify',
      });
    } finally {
      await srv.close();
    }
  });

  test('Express: signing-session auth can request and verify export OTP without app-session refresh', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      {
        orgId: 'org-email-otp-signing-session-export',
        actorUserId: 'test-admin',
        roles: ['admin'],
      },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const authorizations: Array<Record<string, unknown>> = [];
    const thresholdClaims = makeThresholdSessionClaims({
      projectId: 'proj_local',
      environmentId: 'dev',
    });
    const statusReads: string[] = [];
    const consumeUseCountCalls: string[] = [];
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion,
          email: 'alice@example.com',
        },
        'threshold-session': thresholdClaims,
      }),
      signingSessionSeal: makeSigningSessionSealOptions({
        claims: thresholdClaims,
        onStatusRead: (thresholdSessionId) => statusReads.push(thresholdSessionId),
        onConsumeUseCount: (thresholdSessionId) => consumeUseCountCalls.push(thresholdSessionId),
      }),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-signing-session-export',
      },
      emailOtpExportPolicy: {
        authorize: async (input) => {
          authorizations.push(input as unknown as Record<string, unknown>);
          return {
            ok: true,
            decision: 'ALLOW',
            policyId: 'policy_signing_session_export_allowed',
            approvalId: `approval_${input.phase}`,
            reason: 'test signing-session export policy allow',
          };
        },
      },
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });
      const challenge = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
            email: 'attacker@example.com',
          }),
        },
      );
      expect(challenge.status).toBe(200);
      expect(challenge.json?.challenge?.operation).toBe('export_key');
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await service.readEmailOtpOutboxEntry({
        challengeId,
        userId: 'alice.testnet',
        walletId: 'alice.testnet',
      });
      expect(outbox.ok).toBe(true);
      expect((service as any).emailOtpMemoryOutbox.get(challengeId)?.email).toBe(
        'alice@example.com',
      );
      const otpCode = outbox.ok ? outbox.otpCode : '';

      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/signing-session/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-session',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
          operation: 'export_key',
        }),
      });
      expect(verified.status).toBe(200);
      expect(verified.json?.ok).toBe(true);
      expect(verified.json?.appSessionJwt).toBeUndefined();
      const loginGrant = String(verified.json?.loginGrant || '');
      expect(loginGrant.length).toBeGreaterThan(10);

      const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
      const wrapped = makeWrappedCiphertext(plaintextSecretB64u);
      const unsealed = await fetchJson(`${srv.baseUrl}/wallet/email-otp/signing-session/unseal`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer threshold-session',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          loginGrant,
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(unsealed.status).toBe(200);
      expect(unsealed.json?.ok).toBe(true);
      expect(unsealed.json?.ciphertext).toBe(wrapped.clientCiphertext);

      expect(authorizations.map((entry) => entry.phase)).toEqual(['challenge', 'verify']);
      expect(authorizations[0]).toMatchObject({
        operation: 'export_key',
        sourceIp: expect.any(String),
        appSessionVersion:
          'signing-session:threshold_ecdsa_session_v2:wallet-signing-session-1:ecdsa-session-1',
      });
      const issuedEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.export_challenge_issued',
      );
      expect(issuedEvent?.payload).toMatchObject({
        walletId: 'alice.testnet',
        operation: 'export_key',
        source: 'signing_session_challenge',
        challengeId,
      });
      const approvedEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.export_approved',
      );
      expect(approvedEvent?.payload).toMatchObject({
        walletId: 'alice.testnet',
        operation: 'export_key',
        source: 'signing_session_verify',
        challengeId,
      });
      expect(statusReads).toContain('ecdsa-session-1');
      expect(statusReads).toContain('wallet-signing:wallet-signing-session-1');
      expect(consumeUseCountCalls).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  test('Express: Google SSO Email OTP enrollment can request export OTP through restored signing-session auth', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({
      userId: GOOGLE_EMAIL_OTP_USER_ID,
    });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const thresholdClaims = makeThresholdSessionClaims();
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'google-app-session': {
          kind: 'app_session_v1',
          sub: GOOGLE_EMAIL_OTP_USER_ID,
          walletId: 'alice.testnet',
          appSessionVersion,
          provider: 'oidc',
          oidcProvider: 'google',
          providerSubject: GOOGLE_EMAIL_OTP_USER_ID,
          email: 'alice@example.com',
        },
        'threshold-session': thresholdClaims,
      }),
      signingSessionSeal: makeSigningSessionSealOptions({ claims: thresholdClaims }),
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({
        service,
        baseUrl: srv.baseUrl,
        authToken: 'google-app-session',
        userId: GOOGLE_EMAIL_OTP_USER_ID,
      });
      const enrollment = await service.readEmailOtpEnrollment({
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      });
      expect(enrollment.ok).toBe(true);
      expect(enrollment.ok && enrollment.enrollment.providerUserId).toBe(GOOGLE_EMAIL_OTP_USER_ID);

      const challenge = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
          }),
        },
      );
      expect(challenge.status).toBe(200);
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await service.readEmailOtpOutboxEntry({
        challengeId,
        userId: 'alice.testnet',
        walletId: 'alice.testnet',
      });
      expect(outbox.ok).toBe(true);
      expect((service as any).emailOtpMemoryOutbox.get(challengeId)?.email).toBe(
        'alice@example.com',
      );
    } finally {
      await srv.close();
    }
  });

  test('Express: invalid Email OTP enrollment without verified email is rejected', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const thresholdClaims = makeThresholdSessionClaims();
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion,
          email: 'alice@example.com',
        },
        'threshold-session': thresholdClaims,
      }),
      signingSessionSeal: makeSigningSessionSealOptions({ claims: thresholdClaims }),
    });
    const srv = await startExpressRouter(router);
    try {
      const nowMs = Date.now();
      await expect(
        (service as any).getEmailOtpWalletEnrollmentStore().put({
          version: 'email_otp_wallet_enrollment_v1',
          walletId: 'alice.testnet',
          providerUserId: 'alice.testnet',
          orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
          verifiedEmail: '',
          enrollmentEscrowCiphertextB64u: 'invalid-email-otp-escrow-blob',
          enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
          clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          unlockKeyVersion: 'email-otp-unlock-v1',
          thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
        }),
      ).rejects.toThrow('Invalid Email OTP wallet enrollment record');

      const loginChallenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(loginChallenge.status).toBe(404);
      expect(loginChallenge.json?.code).toBe('not_found');

      const exportChallenge = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
          }),
        },
      );
      expect(exportChallenge.status).toBe(404);
      expect(exportChallenge.json?.code).toBe('not_found');

      const unchangedEnrollment = await service.readEmailOtpEnrollment({
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      });
      expect(unchangedEnrollment.ok).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('Express: signing-session Email OTP challenge accepts transaction auth and rejects mismatched auth', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const thresholdClaims = makeThresholdSessionClaims();
    const exhaustedThresholdClaims = makeThresholdSessionClaims({
      sessionId: 'exhausted-ecdsa-session',
      walletSigningSessionId: 'exhausted-wallet-signing-session',
    });
    const exhaustedSessionStatus = makeSigningSessionStatusPolicy({
      claims: exhaustedThresholdClaims,
    });
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion,
          email: 'alice@example.com',
        },
        'threshold-session': thresholdClaims,
        'expired-threshold-session': makeThresholdSessionClaims({
          sessionId: 'expired-ecdsa-session',
          thresholdExpiresAtMs: Date.now() - 1_000,
        }),
        'exhausted-threshold-session': exhaustedThresholdClaims,
      }),
      signingSessionSeal: makeSigningSessionSealOptions({
        claims: thresholdClaims,
        statusById: {
          'exhausted-ecdsa-session': {
            ...((await exhaustedSessionStatus.getThresholdSessionStatuses({
              curve: 'ecdsa',
              thresholdSessionId: 'exhausted-ecdsa-session',
            }))?.[0] as any),
            remainingUses: 0,
          },
          'wallet-signing:exhausted-wallet-signing-session': {
            ...(await exhaustedSessionStatus.getWalletBudgetStatus?.({
              curve: 'ecdsa',
              walletSigningSessionId: 'exhausted-wallet-signing-session',
              thresholdSessionId: 'exhausted-ecdsa-session',
            }) as any),
            remainingUses: 0,
          },
        },
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });
      const appSessionAttempt = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
          }),
        },
      );
      expect(appSessionAttempt.status).toBe(401);
      expect(appSessionAttempt.json?.code).toBe('unauthorized');

      const transactionSign = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'transaction_sign',
          }),
        },
      );
      expect(transactionSign.status).toBe(200);
      expect(transactionSign.json?.challenge?.operation).toBe('transaction_sign');
      const transactionSignChallengeId = String(transactionSign.json?.challenge?.challengeId || '');
      const transactionSignOutbox = await service.readEmailOtpOutboxEntry({
        challengeId: transactionSignChallengeId,
        userId: 'alice.testnet',
        walletId: 'alice.testnet',
      });
      expect(transactionSignOutbox.ok).toBe(true);
      const transactionSignVerified = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/verify`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId: transactionSignChallengeId,
            otpChannel: 'email_otp',
            otpCode: transactionSignOutbox.ok ? transactionSignOutbox.otpCode : '',
            operation: 'transaction_sign',
          }),
        },
      );
      expect(transactionSignVerified.status).toBe(200);
      expect(transactionSignVerified.json?.ok).toBe(true);
      expect(transactionSignVerified.json?.loginGrant).toEqual(expect.any(String));

      const crossWallet = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer threshold-session',
          },
          body: JSON.stringify({
            walletId: 'bob.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
          }),
        },
      );
      expect(crossWallet.status).toBe(403);
      expect(crossWallet.json?.code).toBe('wallet_identity_mismatch');

      const expired = await fetchJson(`${srv.baseUrl}/wallet/email-otp/signing-session/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer expired-threshold-session',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
          operation: 'export_key',
        }),
      });
      expect(expired.status).toBe(401);
      expect(expired.json?.code).toBe('unauthorized');

      const exhausted = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/signing-session/challenge`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer exhausted-threshold-session',
          },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            otpChannel: 'email_otp',
            operation: 'export_key',
          }),
        },
      );
      expect(exhausted.status).toBe(200);
      expect(exhausted.json?.challenge?.operation).toBe('export_key');
    } finally {
      await srv.close();
    }
  });

  test('Express: Email OTP verify tolerates app-session JWT refresh with same stable scope', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const appSessionVersion = (appVersion as { appSessionVersion: string }).appSessionVersion;
    const stableClaims = {
      kind: 'app_session_v1',
      sub: 'alice.testnet',
      appSessionVersion,
      walletId: 'alice.testnet',
      provider: 'oidc',
      oidcProvider: 'google',
      providerSubject: 'google:alice',
      email: 'alice@example.com',
    };
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session-before-refresh': {
          ...stableClaims,
          googleEmailOtpResolutionMode: 'register_started',
          name: 'Alice Before Refresh',
          deviceId: 'device-before-refresh',
          iat: 1776498000,
          exp: 1776501600,
          jti: 'session-before-refresh',
        },
        'app-session-after-refresh': {
          ...stableClaims,
          googleEmailOtpResolutionMode: 'existing_wallet',
          name: 'Alice After Refresh',
          deviceId: 'device-after-refresh',
          iat: 1776498060,
          exp: 1776501660,
          jti: 'session-after-refresh',
        },
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      await enrollEmailOtpOverExpress({
        service,
        baseUrl: srv.baseUrl,
        authToken: 'app-session-before-refresh',
        userId: 'google:alice',
      });
      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer app-session-before-refresh',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
          operation: 'export_key',
        }),
      });
      expect(challenge.status).toBe(200);
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session-after-refresh' },
        },
      );
      expect(outbox.status).toBe(200);
      const otpCode = String(outbox.json?.otpCode || '');
      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer app-session-after-refresh',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
          operation: 'export_key',
        }),
      });
      expect(verified.status).toBe(200);
      expect(verified.json?.ok).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('Cloudflare: export_key Email OTP challenge can be denied by route policy and audited', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-export-policy-cf', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const authorizations: Array<Record<string, unknown>> = [];
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-export-policy-cf',
      },
      emailOtpExportPolicy: {
        authorize: async (input) => {
          authorizations.push(input as unknown as Record<string, unknown>);
          return {
            ok: false,
            decision: 'DENY',
            code: 'export_key_policy_denied',
            message: 'Email OTP export is blocked by test policy',
            policyId: 'policy_export_blocked',
            reason: 'test export policy deny',
          };
        },
      },
    });
    const cf = makeCfCtx();
    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
        operation: 'export_key',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(403);
    expect(challenge.json).toMatchObject({
      ok: false,
      code: 'export_key_policy_denied',
      message: 'Email OTP export is blocked by test policy',
    });
    expect(authorizations).toHaveLength(1);
    expect(authorizations[0]).toMatchObject({
      operation: 'export_key',
      phase: 'challenge',
      userId: 'alice.testnet',
      walletId: 'alice.testnet',
    });
    const deniedEvent = dispatched.find(
      (entry) => entry.eventType === 'wallet.email_otp.export_denied',
    );
    expect(deniedEvent?.payload).toMatchObject({
      walletId: 'alice.testnet',
      operation: 'export_key',
      source: 'login_challenge',
      policyDecision: 'DENY',
      policySource: 'adapter',
      policyId: 'policy_export_blocked',
      code: 'export_key_policy_denied',
      message: 'Email OTP export is blocked by test policy',
    });
  });

  test('Express: local development memory OTP flow issues challenge, serves dev outbox, verifies OTP, and consumes grants single-use', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const srv = await startExpressRouter(router);

    try {
      await seedCanonicalWallet(service);
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
      expect(enrollChallenge.json?.challenge?.action).toBe('wallet_email_otp_registration');
      const enrollChallengeId = String(enrollChallenge.json?.challenge?.challengeId || '');
      const enrollOutbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(enrollChallengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session' },
        },
      );
      expect(enrollOutbox.status).toBe(200);
      const enrollOtpCode = String(enrollOutbox.json?.otpCode || '');
      const enrollPlaintextSecretB64u = encodePositiveBigIntB64u(11n);
      const enrollWrappedCiphertext = addClientSeal(enrollPlaintextSecretB64u);
      const enrollSeal = await fetchJson(`${srv.baseUrl}/wallet/email-otp/registration/seal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          wrappedCiphertext: enrollWrappedCiphertext,
        }),
      });
      expect(enrollSeal.status).toBe(200);
      expect(enrollSeal.json?.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      const enrollmentEscrowCiphertextB64u = removeClientSeal(
        String(enrollSeal.json?.ciphertext || ''),
      );
      expect(enrollmentEscrowCiphertextB64u).toBe(addServerSeal(enrollPlaintextSecretB64u));
      const enrollVerify = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/registration/finalize`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId: enrollChallengeId,
            otpChannel: 'email_otp',
            otpCode: enrollOtpCode,
            recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
              walletId: 'alice.testnet',
              userId: 'alice.testnet',
              enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
            }),
            enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
            clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
            unlockKeyVersion: 'email-otp-unlock-v1',
            thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          }),
        },
      );
      expect(enrollVerify.status).toBe(200);
      const enrolled = await service.readEmailOtpEnrollment({
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      });
      expect(enrolled.ok).toBe(true);
      expect(enrolled.ok && enrolled.enrollment.recoveryWrappedEnrollmentEscrowCount).toBe(10);
      expect(enrolled.ok && enrolled.enrollment.enrollmentSealKeyVersion).toBe(
        EMAIL_OTP_KEY_VERSION,
      );
      expect(enrolled.ok && enrolled.enrollment.clientUnlockPublicKeyB64u).toBe(
        VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      );
      expect(enrolled.ok && enrolled.enrollment.thresholdEcdsaClientVerifyingShareB64u).toBe(
        VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      );

      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(200);
      expect(challenge.json?.ok).toBe(true);
      expect(challenge.json?.delivery?.mode).toBe('memory');
      expect(challenge.json?.challenge?.walletId).toBe('alice.testnet');
      expect(challenge.json?.challenge?.userId).toBe('alice.testnet');
      expect(challenge.json?.challenge?.action).toBe('wallet_email_otp_login');
      expect(challenge.json?.challenge?.otpChannel).toBe('email_otp');
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      expect(challengeId.length).toBeGreaterThan(10);

      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session' },
        },
      );
      expect(outbox.status).toBe(200);
      expect(outbox.json?.walletId).toBe('alice.testnet');
      const otpCode = String(outbox.json?.otpCode || '');
      expect(otpCode).toMatch(/^\d{6}$/);

      const plaintextSecretB64u = encodePositiveBigIntB64u(7n);
      const wrapped = makeWrappedCiphertext(plaintextSecretB64u);
      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify-and-unseal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(verified.status).toBe(200);
      expect(verified.json?.ok).toBe(true);
      expect(verified.json?.loginGrant).toBeUndefined();
      expect(verified.json?.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
      expect(verified.json?.ciphertext).toBe(wrapped.clientCiphertext);
      expect(removeClientSeal(String(verified.json?.ciphertext || ''))).toBe(plaintextSecretB64u);

      const unlockChallenge = await fetchJson(`${srv.baseUrl}/wallet/unlock/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          unlockBackend: 'email_otp',
          walletId: 'alice.testnet',
          orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        }),
      });
      expect(unlockChallenge.status).toBe(200);
      expect(unlockChallenge.json?.unlockBackend).toBe('email_otp');
      expect(unlockChallenge.json?.unlockKeyVersion).toBe('email-otp-unlock-v1');
      const unlockChallengeId = String(unlockChallenge.json?.challengeId || '');
      const unlockChallengeDigest = base64UrlDecode(
        String(unlockChallenge.json?.challengeB64u || ''),
      );
      const unlockSignature65 = await signSecp256k1Recoverable(
        unlockChallengeDigest,
        VALID_SECP256K1_PRIVATE_KEY_32,
      );

      const unlockVerify = await fetchJson(`${srv.baseUrl}/wallet/unlock/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          unlockBackend: 'email_otp',
          walletId: 'alice.testnet',
          orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
          challengeId: unlockChallengeId,
          unlockProof: {
            publicKey: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
            signature: base64UrlEncode(unlockSignature65),
          },
        }),
      });
      expect(unlockVerify.status).toBe(200);
      expect(unlockVerify.json?.ok).toBe(true);
      expect(unlockVerify.json?.unlocked).toBe(true);
      expect(unlockVerify.json?.unlockBackend).toBe('email_otp');
      const authStateAfterUnlock = await (service as any)
        .getEmailOtpAuthStateStore()
        .get('alice.testnet');
      expect(typeof authStateAfterUnlock?.lastEmailOtpLoginAtMs === 'number').toBe(true);

      const replay = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify-and-unseal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(replay.status).toBe(400);
      expect(replay.json?.code).toBe('challenge_expired_or_invalid');
    } finally {
      await srv.close();
    }
  });

  test('Express: wrong OTP attempts persist lockout across fresh Email OTP challenges', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const srv = await startExpressRouter(router);

    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });

      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(200);
      const challengeId = String(challenge.json?.challenge?.challengeId || '');

      let exhausted: Awaited<ReturnType<typeof fetchJson>> | null = null;
      let totalAttempts = 0;
      while (!exhausted) {
        totalAttempts += 1;
        const invalid = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId,
            otpChannel: 'email_otp',
            otpCode: '000000',
          }),
        });
        expect(invalid.status).toBe(400);
        if (invalid.json?.code === 'otp_attempts_exhausted') {
          exhausted = invalid;
          break;
        }
        expect(invalid.json?.code).toBe('invalid_otp');
        expect(typeof invalid.json?.attemptsRemaining).toBe('number');
        expect(Number(invalid.json?.attemptsRemaining)).toBeGreaterThan(0);
      }
      if (!exhausted) throw new Error('expected otp_attempts_exhausted response');
      expect(exhausted.status).toBe(400);
      expect(exhausted.json?.code).toBe('otp_attempts_exhausted');
      expect(exhausted.json?.attemptsRemaining).toBe(0);
      expect(typeof exhausted.json?.lockedUntilMs).toBe('number');

      const authState = await (service as any).getEmailOtpAuthStateStore().get('alice.testnet');
      expect(authState?.otpFailureCount).toBe(totalAttempts);
      expect(typeof authState?.lastOtpFailureAtMs).toBe('number');
      expect(typeof authState?.otpLockedUntilMs).toBe('number');

      const lockedChallenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(lockedChallenge.status).toBe(400);
      expect(lockedChallenge.json?.code).toBe('otp_locked_out');
      expect(typeof lockedChallenge.json?.lockedUntilMs).toBe('number');
    } finally {
      await srv.close();
    }
  });

  test('Express: Email OTP routes emit structured audit webhook events for enrollment, failure, lockout, and login', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-express-audit', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-express-audit',
      },
    });
    const srv = await startExpressRouter(router);

    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });

      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(200);
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session' },
        },
      );
      expect(outbox.status).toBe(200);
      const otpCode = String(outbox.json?.otpCode || '');
      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
        }),
      });
      expect(verified.status).toBe(200);
      const loginGrant = String(verified.json?.loginGrant || '');
      const plaintextSecretB64u = encodePositiveBigIntB64u(17n);
      const wrapped = makeWrappedCiphertext(plaintextSecretB64u);
      const unsealed = await fetchJson(`${srv.baseUrl}/wallet/email-otp/unseal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          loginGrant,
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(unsealed.status).toBe(200);

      const unlockChallenge = await fetchJson(`${srv.baseUrl}/wallet/unlock/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          unlockBackend: 'email_otp',
          walletId: 'alice.testnet',
          orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        }),
      });
      expect(unlockChallenge.status).toBe(200);
      const unlockChallengeId = String(unlockChallenge.json?.challengeId || '');
      const unlockChallengeDigest = base64UrlDecode(
        String(unlockChallenge.json?.challengeB64u || ''),
      );
      const unlockSignature65 = await signSecp256k1Recoverable(
        unlockChallengeDigest,
        VALID_SECP256K1_PRIVATE_KEY_32,
      );
      const unlockVerify = await fetchJson(`${srv.baseUrl}/wallet/unlock/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          unlockBackend: 'email_otp',
          walletId: 'alice.testnet',
          orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
          challengeId: unlockChallengeId,
          unlockProof: {
            publicKey: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
            signature: base64UrlEncode(unlockSignature65),
          },
        }),
      });
      expect(unlockVerify.status).toBe(200);

      const failingChallenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(failingChallenge.status).toBe(200);
      const failingChallengeId = String(failingChallenge.json?.challenge?.challengeId || '');
      let exhausted = false;
      while (!exhausted) {
        const invalid = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
          body: JSON.stringify({
            walletId: 'alice.testnet',
            challengeId: failingChallengeId,
            otpChannel: 'email_otp',
            otpCode: '000000',
          }),
        });
        expect(invalid.status).toBe(400);
        exhausted = invalid.json?.code === 'otp_attempts_exhausted';
      }
      const lockedChallenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(lockedChallenge.status).toBe(400);

      const eventTypes = dispatched.map((entry) => entry.eventType);
      expect(eventTypes).toContain('wallet.email_otp.enrolled');
      expect(eventTypes).toContain('wallet.email_otp.logged_in');
      expect(eventTypes).toContain('wallet.email_otp.failed');
      expect(eventTypes).toContain('wallet.email_otp.locked');

      const enrolledEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.enrolled',
      );
      expect(enrolledEvent?.payload.walletId).toBe('alice.testnet');
      expect(enrolledEvent?.payload.otpChannel).toBe('email_otp');

      const loggedInEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.logged_in',
      );
      expect(loggedInEvent?.payload.walletId).toBe('alice.testnet');
      expect(loggedInEvent?.payload.challengeId).toBe(unlockChallengeId);

      const failedEvent = dispatched.find((entry) => entry.eventType === 'wallet.email_otp.failed');
      expect(failedEvent?.payload.source).toBe('login_verify');
      expect(['invalid_otp', 'otp_attempts_exhausted']).toContain(
        String(failedEvent?.payload.code || ''),
      );

      const lockedEvent = dispatched.find((entry) => entry.eventType === 'wallet.email_otp.locked');
      expect(['login_challenge', 'login_verify']).toContain(
        String(lockedEvent?.payload.source || ''),
      );
      expect(['otp_locked_out', 'otp_attempts_exhausted']).toContain(
        String(lockedEvent?.payload.code || ''),
      );
    } finally {
      await srv.close();
    }
  });

  test('Express: Email OTP routes do not emit device-diff events after enrollment cleanup', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const currentAppSessionVersion = (appVersion as { appSessionVersion: string })
      .appSessionVersion;
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-express-new-device', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const router = createRelayRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session-enroll': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: currentAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'device-enroll',
        },
        'app-session-login': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: currentAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'device-login',
        },
      }),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-express-new-device',
      },
    });
    const srv = await startExpressRouter(router);

    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl, authToken: 'app-session-enroll' });

      const challenge = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/challenge`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer app-session-login',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(challenge.status).toBe(200);
      const challengeId = String(challenge.json?.challenge?.challengeId || '');
      const outbox = await fetchJson(
        `${srv.baseUrl}/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
        {
          method: 'GET',
          headers: { Authorization: 'Bearer app-session-login' },
        },
      );
      expect(outbox.status).toBe(200);
      const otpCode = String(outbox.json?.otpCode || '');
      const verified = await fetchJson(`${srv.baseUrl}/wallet/email-otp/login/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer app-session-login',
        },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode,
        }),
      });
      expect(verified.status).toBe(200);
      const loginGrant = String(verified.json?.loginGrant || '');
      const wrapped = makeWrappedCiphertext(encodePositiveBigIntB64u(23n));
      const unsealed = await fetchJson(`${srv.baseUrl}/wallet/email-otp/unseal`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer app-session-login',
        },
        body: JSON.stringify({
          loginGrant,
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(unsealed.status).toBe(200);

      const newDeviceEvent = dispatched.find(
        (entry) => entry.eventType === 'wallet.email_otp.new_device',
      );
      expect(newDeviceEvent).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('Express: unseal rejects an invalid login grant', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const router = createRelayRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const srv = await startExpressRouter(router);

    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: srv.baseUrl });
      const wrapped = makeWrappedCiphertext(encodePositiveBigIntB64u(31n));
      const unsealed = await fetchJson(`${srv.baseUrl}/wallet/email-otp/unseal`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          loginGrant: 'invalid-grant',
          wrappedCiphertext: wrapped.wrappedCiphertext,
        }),
      });
      expect(unsealed.status).toBe(400);
      expect(unsealed.json?.code).toBe('login_grant_invalid_or_expired');
    } finally {
      await srv.close();
    }
  });

  test('Cloudflare: local development memory OTP flow issues challenge, serves dev outbox, verifies OTP, and consumes grants single-use', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    await seedCanonicalWallet(service);
    const enrollChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/registration/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(enrollChallenge.status).toBe(200);
    expect(enrollChallenge.json?.challenge?.action).toBe('wallet_email_otp_registration');
    const enrollChallengeId = String(enrollChallenge.json?.challenge?.challengeId || '');
    const enrollOutbox = await callCf(handler, {
      method: 'GET',
      path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(enrollChallengeId)}&walletId=alice.testnet`,
      headers: { Authorization: 'Bearer app-session' },
      ctx: cf.ctx,
    });
    expect(enrollOutbox.status).toBe(200);
    const enrollOtpCode = String(enrollOutbox.json?.otpCode || '');
    const enrollPlaintextSecretB64u = encodePositiveBigIntB64u(13n);
    const enrollWrappedCiphertext = addClientSeal(enrollPlaintextSecretB64u);
    const enrollSeal = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/registration/seal',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        wrappedCiphertext: enrollWrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(enrollSeal.status).toBe(200);
    expect(enrollSeal.json?.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    const enrollmentEscrowCiphertextB64u = removeClientSeal(
      String(enrollSeal.json?.ciphertext || ''),
    );
    expect(enrollmentEscrowCiphertextB64u).toBe(addServerSeal(enrollPlaintextSecretB64u));
    const enrollVerify = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/registration/finalize',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        challengeId: enrollChallengeId,
        otpChannel: 'email_otp',
        otpCode: enrollOtpCode,
        recoveryWrappedEnrollmentEscrows: makeEmailOtpRecoveryWrappedEnrollmentEscrows({
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
        }),
        enrollmentSealKeyVersion: EMAIL_OTP_KEY_VERSION,
        clientUnlockPublicKeyB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
        unlockKeyVersion: 'email-otp-unlock-v1',
        thresholdEcdsaClientVerifyingShareB64u: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
      },
      ctx: cf.ctx,
    });
    expect(enrollVerify.status).toBe(200);
    const enrolled = await service.readEmailOtpEnrollment({
      walletId: 'alice.testnet',
      orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
    });
    expect(enrolled.ok).toBe(true);
    expect(enrolled.ok && enrolled.enrollment.recoveryWrappedEnrollmentEscrowCount).toBe(10);

    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(200);
    expect(challenge.json?.ok).toBe(true);
    expect(challenge.json?.delivery?.mode).toBe('memory');
    expect(challenge.json?.challenge?.action).toBe('wallet_email_otp_login');
    const challengeId = String(challenge.json?.challenge?.challengeId || '');
    expect(challengeId.length).toBeGreaterThan(10);

    const outbox = await callCf(handler, {
      method: 'GET',
      path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
      headers: { Authorization: 'Bearer app-session' },
      ctx: cf.ctx,
    });
    expect(outbox.status).toBe(200);
    const otpCode = String(outbox.json?.otpCode || '');
    expect(otpCode).toMatch(/^\d{6}$/);

    const plaintextSecretB64u = encodePositiveBigIntB64u(9n);
    const wrapped = makeWrappedCiphertext(plaintextSecretB64u);
    const verified = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/verify-and-unseal',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        challengeId,
        otpChannel: 'email_otp',
        otpCode,
        wrappedCiphertext: wrapped.wrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(verified.status).toBe(200);
    expect(verified.json?.loginGrant).toBeUndefined();
    expect(verified.json?.enrollmentSealKeyVersion).toBe(EMAIL_OTP_KEY_VERSION);
    expect(verified.json?.ciphertext).toBe(wrapped.clientCiphertext);
    expect(removeClientSeal(String(verified.json?.ciphertext || ''))).toBe(plaintextSecretB64u);

    const unlockChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/challenge',
      body: {
        unlockBackend: 'email_otp',
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      },
      ctx: cf.ctx,
    });
    expect(unlockChallenge.status).toBe(200);
    expect(unlockChallenge.json?.unlockBackend).toBe('email_otp');
    expect(unlockChallenge.json?.unlockKeyVersion).toBe('email-otp-unlock-v1');
    const unlockChallengeId = String(unlockChallenge.json?.challengeId || '');
    const unlockChallengeDigest = base64UrlDecode(
      String(unlockChallenge.json?.challengeB64u || ''),
    );
    const unlockSignature65 = await signSecp256k1Recoverable(
      unlockChallengeDigest,
      VALID_SECP256K1_PRIVATE_KEY_32,
    );

    const unlockVerify = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          signature: base64UrlEncode(unlockSignature65),
        },
      },
      ctx: cf.ctx,
    });
    expect(unlockVerify.status).toBe(200);
    expect(unlockVerify.json?.ok).toBe(true);
    expect(unlockVerify.json?.unlocked).toBe(true);
    expect(unlockVerify.json?.unlockBackend).toBe('email_otp');
    const authStateAfterUnlock = await (service as any)
      .getEmailOtpAuthStateStore()
      .get('alice.testnet');
    expect(typeof authStateAfterUnlock?.lastEmailOtpLoginAtMs === 'number').toBe(true);

    const consumedReplay = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/verify-and-unseal',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        challengeId,
        otpChannel: 'email_otp',
        otpCode,
        wrappedCiphertext: wrapped.wrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(consumedReplay.status).toBe(400);
    expect(consumedReplay.json?.code).toBe('challenge_expired_or_invalid');
  });

  test('Cloudflare: wrong OTP attempts persist lockout across fresh Email OTP challenges', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({ service, handler, ctx: cf.ctx });

    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(200);
    const challengeId = String(challenge.json?.challenge?.challengeId || '');

    let exhausted: Awaited<ReturnType<typeof callCf>> | null = null;
    let totalAttempts = 0;
    while (!exhausted) {
      totalAttempts += 1;
      const invalid = await callCf(handler, {
        method: 'POST',
        path: '/wallet/email-otp/login/verify',
        headers: { Authorization: 'Bearer app-session' },
        body: {
          walletId: 'alice.testnet',
          challengeId,
          otpChannel: 'email_otp',
          otpCode: '000000',
        },
        ctx: cf.ctx,
      });
      expect(invalid.status).toBe(400);
      if (invalid.json?.code === 'otp_attempts_exhausted') {
        exhausted = invalid;
        break;
      }
      expect(invalid.json?.code).toBe('invalid_otp');
      expect(typeof invalid.json?.attemptsRemaining).toBe('number');
      expect(Number(invalid.json?.attemptsRemaining)).toBeGreaterThan(0);
    }
    if (!exhausted) throw new Error('expected otp_attempts_exhausted response');
    expect(exhausted.status).toBe(400);
    expect(exhausted.json?.code).toBe('otp_attempts_exhausted');
    expect(exhausted.json?.attemptsRemaining).toBe(0);
    expect(typeof exhausted.json?.lockedUntilMs).toBe('number');

    const authState = await (service as any).getEmailOtpAuthStateStore().get('alice.testnet');
    expect(authState?.otpFailureCount).toBe(totalAttempts);
    expect(typeof authState?.lastOtpFailureAtMs).toBe('number');
    expect(typeof authState?.otpLockedUntilMs).toBe('number');

    const lockedChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(lockedChallenge.status).toBe(400);
    expect(lockedChallenge.json?.code).toBe('otp_locked_out');
    expect(typeof lockedChallenge.json?.lockedUntilMs).toBe('number');
  });

  test('Cloudflare: Email OTP routes emit structured audit webhook events for enrollment, failure, lockout, and login', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-cf-audit', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-cf-audit',
      },
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({ service, handler, ctx: cf.ctx });

    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(200);
    const challengeId = String(challenge.json?.challenge?.challengeId || '');
    const outbox = await callCf(handler, {
      method: 'GET',
      path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
      headers: { Authorization: 'Bearer app-session' },
      ctx: cf.ctx,
    });
    expect(outbox.status).toBe(200);
    const otpCode = String(outbox.json?.otpCode || '');
    const verified = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/verify',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        challengeId,
        otpChannel: 'email_otp',
        otpCode,
      },
      ctx: cf.ctx,
    });
    expect(verified.status).toBe(200);
    const loginGrant = String(verified.json?.loginGrant || '');
    const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
    const wrapped = makeWrappedCiphertext(plaintextSecretB64u);
    const unsealed = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/unseal',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        loginGrant,
        wrappedCiphertext: wrapped.wrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(unsealed.status).toBe(200);

    const unlockChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/challenge',
      body: {
        unlockBackend: 'email_otp',
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
      },
      ctx: cf.ctx,
    });
    expect(unlockChallenge.status).toBe(200);
    const unlockChallengeId = String(unlockChallenge.json?.challengeId || '');
    const unlockChallengeDigest = base64UrlDecode(
      String(unlockChallenge.json?.challengeB64u || ''),
    );
    const unlockSignature65 = await signSecp256k1Recoverable(
      unlockChallengeDigest,
      VALID_SECP256K1_PRIVATE_KEY_32,
    );
    const unlockVerify = await callCf(handler, {
      method: 'POST',
      path: '/wallet/unlock/verify',
      body: {
        unlockBackend: 'email_otp',
        walletId: 'alice.testnet',
        orgId: DEFAULT_RUNTIME_POLICY_SCOPE.orgId,
        challengeId: unlockChallengeId,
        unlockProof: {
          publicKey: VALID_SECP256K1_PUBLIC_KEY_33_B64U,
          signature: base64UrlEncode(unlockSignature65),
        },
      },
      ctx: cf.ctx,
    });
    expect(unlockVerify.status).toBe(200);

    const failingChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(failingChallenge.status).toBe(200);
    const failingChallengeId = String(failingChallenge.json?.challenge?.challengeId || '');
    let exhausted = false;
    while (!exhausted) {
      const invalid = await callCf(handler, {
        method: 'POST',
        path: '/wallet/email-otp/login/verify',
        headers: { Authorization: 'Bearer app-session' },
        body: {
          walletId: 'alice.testnet',
          challengeId: failingChallengeId,
          otpChannel: 'email_otp',
          otpCode: '000000',
        },
        ctx: cf.ctx,
      });
      expect(invalid.status).toBe(400);
      exhausted = invalid.json?.code === 'otp_attempts_exhausted';
    }
    const lockedChallenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(lockedChallenge.status).toBe(400);

    const eventTypes = dispatched.map((entry) => entry.eventType);
    expect(eventTypes).toContain('wallet.email_otp.enrolled');
    expect(eventTypes).toContain('wallet.email_otp.logged_in');
    expect(eventTypes).toContain('wallet.email_otp.failed');
    expect(eventTypes).toContain('wallet.email_otp.locked');

    const enrolledEvent = dispatched.find(
      (entry) => entry.eventType === 'wallet.email_otp.enrolled',
    );
    expect(enrolledEvent?.payload.walletId).toBe('alice.testnet');
    expect(enrolledEvent?.payload.otpChannel).toBe('email_otp');

    const loggedInEvent = dispatched.find(
      (entry) => entry.eventType === 'wallet.email_otp.logged_in',
    );
    expect(loggedInEvent?.payload.walletId).toBe('alice.testnet');
    expect(loggedInEvent?.payload.challengeId).toBe(unlockChallengeId);

    const failedEvent = dispatched.find((entry) => entry.eventType === 'wallet.email_otp.failed');
    expect(failedEvent?.payload.source).toBe('login_verify');
    expect(['invalid_otp', 'otp_attempts_exhausted']).toContain(
      String(failedEvent?.payload.code || ''),
    );

    const lockedEvent = dispatched.find((entry) => entry.eventType === 'wallet.email_otp.locked');
    expect(['login_challenge', 'login_verify']).toContain(
      String(lockedEvent?.payload.source || ''),
    );
    expect(['otp_locked_out', 'otp_attempts_exhausted']).toContain(
      String(lockedEvent?.payload.code || ''),
    );
  });

  test('Cloudflare: Email OTP routes do not emit device-diff events after enrollment cleanup', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const currentAppSessionVersion = (appVersion as { appSessionVersion: string })
      .appSessionVersion;
    const { dispatched, webhooks } = makeWebhookRecorder();
    await webhooks.createEndpoint(
      { orgId: 'org-email-otp-cf-new-device', actorUserId: 'test-admin', roles: ['admin'] },
      {
        url: 'https://example.com/relay-webhooks',
        eventCategories: ['wallet'],
      },
    );
    const handler = createCloudflareRouter(service, {
      session: makeTokenBoundAppSessionAdapter({
        'app-session-enroll': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: currentAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'cf-device-enroll',
        },
        'app-session-login': {
          kind: 'app_session_v1',
          sub: 'alice.testnet',
          appSessionVersion: currentAppSessionVersion,
          email: 'alice@example.com',
          deviceId: 'cf-device-login',
        },
      }),
      relayWebhooks: {
        service: webhooks,
        orgId: 'org-email-otp-cf-new-device',
      },
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({
      service,
      handler,
      ctx: cf.ctx,
      authToken: 'app-session-enroll',
    });

    const challenge = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/challenge',
      headers: { Authorization: 'Bearer app-session-login' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(challenge.status).toBe(200);
    const challengeId = String(challenge.json?.challenge?.challengeId || '');
    const outbox = await callCf(handler, {
      method: 'GET',
      path: `/wallet/email-otp/dev/otp-outbox?challengeId=${encodeURIComponent(challengeId)}&walletId=alice.testnet`,
      headers: { Authorization: 'Bearer app-session-login' },
      ctx: cf.ctx,
    });
    expect(outbox.status).toBe(200);
    const otpCode = String(outbox.json?.otpCode || '');
    const verified = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/login/verify',
      headers: { Authorization: 'Bearer app-session-login' },
      body: {
        walletId: 'alice.testnet',
        challengeId,
        otpChannel: 'email_otp',
        otpCode,
      },
      ctx: cf.ctx,
    });
    expect(verified.status).toBe(200);
    const loginGrant = String(verified.json?.loginGrant || '');
    const wrapped = makeWrappedCiphertext(encodePositiveBigIntB64u(29n));
    const unsealed = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/unseal',
      headers: { Authorization: 'Bearer app-session-login' },
      body: {
        loginGrant,
        wrappedCiphertext: wrapped.wrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(unsealed.status).toBe(200);

    const newDeviceEvent = dispatched.find(
      (entry) => entry.eventType === 'wallet.email_otp.new_device',
    );
    expect(newDeviceEvent).toBeUndefined();
  });

  test('Cloudflare: unseal rejects an invalid login grant', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({ service, handler, ctx: cf.ctx });
    const wrapped = makeWrappedCiphertext(encodePositiveBigIntB64u(37n));
    const unsealed = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/unseal',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        loginGrant: 'invalid-grant',
        wrappedCiphertext: wrapped.wrappedCiphertext,
      },
      ctx: cf.ctx,
    });
    expect(unsealed.status).toBe(400);
    expect(unsealed.json?.code).toBe('login_grant_invalid_or_expired');
  });

  test('Express: Email OTP enrollment mutations require fresh passkey auth after Email OTP', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const server = await startExpressRouter(
      createRelayRouter(service, {
        session: makeAppSessionAdapter(
          (appVersion as { appSessionVersion: string }).appSessionVersion,
        ),
      }),
    );
    try {
      await enrollEmailOtpOverExpress({ service, baseUrl: server.baseUrl });
      const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
      const current = await enrollmentStore.get('alice.testnet');
      expect(current).toBeTruthy();
      const nowMs = Date.now();
      await (service as any).getEmailOtpAuthStateStore().put({
        version: 'email_otp_auth_state_v1',
        walletId: 'alice.testnet',
        providerUserId: current.providerUserId,
        orgId: current.orgId,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        lastEmailOtpLoginAtMs: nowMs,
      });

      await enrollmentStore.put({
        ...current,
        updatedAtMs: Date.now(),
      });

      const gated = await fetchJson(`${server.baseUrl}/wallet/email-otp/registration/challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer app-session' },
        body: JSON.stringify({
          walletId: 'alice.testnet',
          otpChannel: 'email_otp',
        }),
      });
      expect(gated.status).toBe(403);
      expect(gated.json?.code).toBe('stronger_auth_required');
    } finally {
      await server.close();
    }
  });

  test('Express: Google SSO Email OTP enrollment can re-enroll after Email OTP login without passkey', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({
      userId: GOOGLE_EMAIL_OTP_USER_ID,
    });
    expect(appVersion.ok).toBe(true);
    const server = await startExpressRouter(
      createRelayRouter(service, {
        session: makeGoogleEmailOtpAppSessionAdapter(
          (appVersion as { appSessionVersion: string }).appSessionVersion,
        ),
      }),
    );
    try {
      await enrollEmailOtpOverExpress({
        service,
        baseUrl: server.baseUrl,
        userId: GOOGLE_EMAIL_OTP_USER_ID,
      });
      const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
      const current = await enrollmentStore.get('alice.testnet');
      expect(current).toBeTruthy();
      const nowMs = Date.now();
      await (service as any).getEmailOtpAuthStateStore().put({
        version: 'email_otp_auth_state_v1',
        walletId: 'alice.testnet',
        providerUserId: current.providerUserId,
        orgId: current.orgId,
        createdAtMs: nowMs,
        updatedAtMs: nowMs,
        lastEmailOtpLoginAtMs: nowMs,
      });

      await enrollEmailOtpOverExpress({
        service,
        baseUrl: server.baseUrl,
        userId: GOOGLE_EMAIL_OTP_USER_ID,
      });
    } finally {
      await server.close();
    }
  });

  test('Cloudflare: Email OTP enrollment mutations require fresh passkey auth after Email OTP', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({ userId: 'alice.testnet' });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({ service, handler, ctx: cf.ctx });
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    const current = await enrollmentStore.get('alice.testnet');
    expect(current).toBeTruthy();
    const nowMs = Date.now();
    await (service as any).getEmailOtpAuthStateStore().put({
      version: 'email_otp_auth_state_v1',
      walletId: 'alice.testnet',
      providerUserId: current.providerUserId,
      orgId: current.orgId,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      lastEmailOtpLoginAtMs: nowMs,
    });

    const gated = await callCf(handler, {
      method: 'POST',
      path: '/wallet/email-otp/registration/challenge',
      headers: { Authorization: 'Bearer app-session' },
      body: {
        walletId: 'alice.testnet',
        otpChannel: 'email_otp',
      },
      ctx: cf.ctx,
    });
    expect(gated.status).toBe(403);
    expect(gated.json?.code).toBe('stronger_auth_required');
  });

  test('Cloudflare: Google SSO Email OTP enrollment can re-enroll after Email OTP login without passkey', async () => {
    const service = makeService();
    const appVersion = await service.getOrCreateAppSessionVersion({
      userId: GOOGLE_EMAIL_OTP_USER_ID,
    });
    expect(appVersion.ok).toBe(true);
    const handler = createCloudflareRouter(service, {
      session: makeGoogleEmailOtpAppSessionAdapter(
        (appVersion as { appSessionVersion: string }).appSessionVersion,
      ),
    });
    const cf = makeCfCtx();

    await enrollEmailOtpOverCloudflare({
      service,
      handler,
      ctx: cf.ctx,
      userId: GOOGLE_EMAIL_OTP_USER_ID,
    });
    const enrollmentStore = (service as any).getEmailOtpWalletEnrollmentStore();
    const current = await enrollmentStore.get('alice.testnet');
    expect(current).toBeTruthy();
    const nowMs = Date.now();
    await (service as any).getEmailOtpAuthStateStore().put({
      version: 'email_otp_auth_state_v1',
      walletId: 'alice.testnet',
      providerUserId: current.providerUserId,
      orgId: current.orgId,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      lastEmailOtpLoginAtMs: nowMs,
    });

    await enrollEmailOtpOverCloudflare({
      service,
      handler,
      ctx: cf.ctx,
      userId: GOOGLE_EMAIL_OTP_USER_ID,
    });
  });
});
