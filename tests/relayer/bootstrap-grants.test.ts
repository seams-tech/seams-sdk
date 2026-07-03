import { test, expect } from '@playwright/test';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRouterApiBootstrapGrantBroker,
  createRouterApiRouter,
  type ConsoleApiKeyService,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, makeFakeAuthService, startExpressRouter } from './helpers';

const authOrgId = 'org-bootstrap-grants';
const authUserId = 'user-bootstrap-grants';
const projectId = 'project-bootstrap-grants';
const environmentId = `${projectId}:prod`;
const allowedOrigin = 'https://app.example.com';

async function seedEnvironment(input?: { liveEnvironmentsEnabled?: boolean }) {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const ctx = {
    orgId: authOrgId,
    actorUserId: authUserId,
    roles: ['admin'],
  };
  await orgProjectEnv.upsertOrganization(ctx, {
    name: 'Bootstrap Grants Org',
    slug: 'bootstrap-grants-org',
  });
  await orgProjectEnv.createProject(ctx, {
    id: projectId,
    name: 'Bootstrap Grants Project',
    liveEnvironmentsEnabled: input?.liveEnvironmentsEnabled ?? true,
  });
  return orgProjectEnv;
}

async function createPublishableKey(input: {
  allowedOrigins?: string[];
  rateLimitBucket?: string;
  quotaBucket?: string;
}) {
  const apiKeys = createInMemoryConsoleApiKeyService();
  const created = await apiKeys.createApiKey(
    {
      orgId: authOrgId,
      actorUserId: authUserId,
      roles: ['admin'],
    },
    {
      kind: 'publishable_key',
      name: 'browser-app',
      environmentId,
      allowedOrigins: input.allowedOrigins || [allowedOrigin],
      rateLimitBucket: input.rateLimitBucket || 'default_web_v1',
      quotaBucket: input.quotaBucket || 'free_registrations_v1',
    },
  );
  return { apiKeys, secret: created.secret };
}

async function makeGrantBody(overrides?: Partial<Record<string, unknown>>) {
  const relayBody = makeWalletRegistrationIntentBody(overrides);
  const signerSelection = relayBody.signerSelection as { signers?: Array<Record<string, unknown>> };
  const nearSigner = signerSelection.signers?.find(isNearEd25519Signer);
  const accountProvisioning = nearSigner?.accountProvisioning as
    | Record<string, unknown>
    | undefined;
  const authority = bootstrapGrantAuthorityFromRegistrationAuthMethod(
    relayBody.authMethod as Record<string, unknown>,
  );
  const clientContext = {
    sdk: 'web',
    sdkVersion: '0.0.0-test',
  };
  const newAccountId = String(accountProvisioning?.requestedAccountId || '');
  if (newAccountId) {
    return {
      environmentId,
      flow: 'registration_v1',
      newAccountId,
      authority,
      clientContext,
    };
  }
  return {
    environmentId,
    flow: 'registration_v1',
    authority,
    clientContext,
  };
}

function bootstrapGrantAuthorityFromRegistrationAuthMethod(authMethod: Record<string, unknown>) {
  if (authMethod.kind !== 'passkey') {
    return { kind: 'wallet_auth' };
  }
  const rpId = String(authMethod.rpId || '').trim();
  if (!rpId) {
    throw new Error('Passkey bootstrap grant test body requires rpId');
  }
  return {
    kind: 'passkey_rp',
    rpId,
  };
}

function makeStaleRootRpIdGrantBody() {
  return {
    environmentId,
    flow: 'registration_v1',
    newAccountId: 'alice.w3a-relayer.testnet',
    rpId: 'app.example.com',
    clientContext: {
      sdk: 'web',
      sdkVersion: '0.0.0-test',
    },
  };
}

function isNearEd25519Signer(signer: Record<string, unknown>): boolean {
  return signer.kind === 'near_ed25519';
}

function makeGoogleEmailOtpRegistrationAuthMethod() {
  return {
    kind: 'email_otp',
    proofKind: 'google_sso_registration',
    email: 'alice@example.com',
    appSessionJwt: 'app-session-jwt',
    googleEmailOtpRegistrationAttemptId: 'attempt-1',
    googleEmailOtpRegistrationOfferId: 'offer-1',
    googleEmailOtpRegistrationCandidateId: 'candidate-1',
  };
}

function makeWalletRegistrationIntentBody(overrides?: Partial<Record<string, unknown>>) {
  return {
    wallet: { kind: 'provided', walletId: 'alice.w3a-relayer.testnet' },
    authMethod: { kind: 'passkey', rpId: 'app.example.com' },
    signerSelection: {
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: {
            kind: 'sponsored_named_account',
            requestedAccountId: 'alice.w3a-relayer.testnet',
            sponsor: 'relayer',
          },
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    },
    ...(overrides || {}),
  };
}

function makeRouterApiService() {
  return makeFakeAuthService({
    createRegistrationIntent: async (input: Record<string, any>) => ({
      ok: true,
      intent: {
        version: 'registration_intent_v1',
        walletId: input.request.wallet.walletId,
        authMethod: input.request.authMethod,
        signerSelection: input.request.signerSelection,
        nonceB64u: 'nonce-test',
      },
      registrationIntentDigestB64u: 'digest-test',
      registrationIntentGrant: 'rig_test',
      expiresAtMs: Date.now() + 60_000,
    }),
  });
}

test.describe('managed bootstrap grants', () => {
  test('broker preserves class-backed publishable-key method binding', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const apiKeysRequiringThis = {
      inner: apiKeys,
      authenticatePublishableKey: async function (
        this: { inner: ConsoleApiKeyService },
        request: Parameters<NonNullable<ConsoleApiKeyService['authenticatePublishableKey']>>[0],
      ) {
        return await this.inner.authenticatePublishableKey!(request);
      },
    } as ConsoleApiKeyService & { inner: ConsoleApiKeyService };
    const broker = createRouterApiBootstrapGrantBroker({
      apiKeys: apiKeysRequiringThis,
      tokenStore: bootstrapTokens,
      orgProjectEnv,
    });

    const auth = await broker.authenticatePublishableKey({
      publishableKey: secret,
      origin: allowedOrigin,
      environmentId,
    });
    expect(auth.ok).toBe(true);
  });

  test('express issues bootstrap token for valid publishable_key', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const broker = createRouterApiBootstrapGrantBroker({
      apiKeys,
      tokenStore: bootstrapTokens,
      orgProjectEnv,
      rateLimitsByBucket: {
        default_web_v1: { windowMs: 60_000, maxIssued: 10 },
      },
      quotasByBucket: {
        free_registrations_v1: { maxIssued: 10 },
      },
    });
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: broker,
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(await makeGrantBody()),
      });
      expect(res.status, res.text).toBe(200);
      expect(res.json?.ok).toBe(true);
      expect(
        String((res.json?.grant && (res.json.grant as Record<string, unknown>).token) || ''),
      ).toContain('tbt_v1_');
      expect((res.json?.grant as Record<string, unknown>)?.envId).toBe('prod');
      expect((res.json?.grant as Record<string, unknown>)?.origin).toBe(allowedOrigin);
      expect((res.json?.grant as Record<string, unknown>)?.mode).toBe('free');
    } finally {
      await srv.close();
    }
  });

  test('express rejects stale root RP ID bootstrap grant bodies', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(makeStaleRootRpIdGrantBody()),
      });
      expect(res.status, res.text).toBe(400);
      expect(res.json?.code).toBe('invalid_body');
      expect(res.json?.message).toContain('Root field rpId is not valid');
    } finally {
      await srv.close();
    }
  });

  test('express broker enforces rate limits', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const broker = createRouterApiBootstrapGrantBroker({
      apiKeys,
      tokenStore: bootstrapTokens,
      orgProjectEnv,
      rateLimitsByBucket: {
        default_web_v1: { windowMs: 60_000, maxIssued: 1 },
      },
      quotasByBucket: {
        free_registrations_v1: { maxIssued: 10 },
      },
    });
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: broker,
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const body = await makeGrantBody();
      const first = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(body),
      });
      expect(first.status, first.text).toBe(200);

      const second = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(body),
      });
      expect(second.status, second.text).toBe(429);
      expect(second.json?.code).toBe('publishable_key_rate_limited');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare broker blocks disallowed origins', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({
      allowedOrigins: ['https://allowed.example.com'],
    });
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const handler = createCloudflareRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/v1/registration/bootstrap-grants',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${secret}`,
      },
      body: await makeGrantBody(),
    });
    expect(res.status, res.text).toBe(403);
    expect(res.json?.code).toBe('publishable_key_origin_blocked');
  });

  test('cloudflare broker enforces quota limits', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const handler = createCloudflareRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
        rateLimitsByBucket: {
          default_web_v1: { windowMs: 60_000, maxIssued: 10 },
        },
        quotasByBucket: {
          free_registrations_v1: { maxIssued: 1 },
        },
      }),
      bootstrapTokenStore: bootstrapTokens,
    });

    const body = await makeGrantBody();
    const first = await callCf(handler, {
      method: 'POST',
      path: '/v1/registration/bootstrap-grants',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${secret}`,
      },
      body,
    });
    expect(first.status, first.text).toBe(200);

    const second = await callCf(handler, {
      method: 'POST',
      path: '/v1/registration/bootstrap-grants',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${secret}`,
      },
      body,
    });
    expect(second.status, second.text).toBe(429);
    expect(second.json?.code).toBe('publishable_key_quota_exhausted');
  });

  test('express redeems issued bootstrap token for wallet registration intent once', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const grantBody = await makeGrantBody();
      const issued = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(grantBody),
      });
      expect(issued.status, issued.text).toBe(200);
      const token = String((issued.json?.grant as Record<string, unknown>)?.token || '');
      expect(token).toContain('tbt_v1_');

      const relayBody = makeWalletRegistrationIntentBody();
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(res.status, res.text).toBe(200);
      expect(res.json?.ok).toBe(true);

      const exhausted = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(exhausted.status, exhausted.text).toBe(409);
      expect(exhausted.json?.message).toContain('bootstrap_token_already_used');
    } finally {
      await srv.close();
    }
  });

  test('express redeems Email OTP bootstrap token without RP ID binding', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const relayBody = makeWalletRegistrationIntentBody({
        authMethod: makeGoogleEmailOtpRegistrationAuthMethod(),
      });
      const grantBody = await makeGrantBody({
        authMethod: relayBody.authMethod,
      });
      expect(grantBody).not.toHaveProperty('rpId');
      expect(grantBody.authority).toEqual({ kind: 'wallet_auth' });

      const issued = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(grantBody),
      });
      expect(issued.status, issued.text).toBe(200);
      const token = String((issued.json?.grant as Record<string, unknown>)?.token || '');
      expect(token).toContain('tbt_v1_');

      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(res.status, res.text).toBe(200);
      expect(res.json?.ok).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('express binds bootstrap token to current signer-set NEAR account identity', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const relayBody = makeWalletRegistrationIntentBody({
        wallet: { kind: 'provided', walletId: 'alice-wallet' },
      });
      const issued = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(await makeGrantBody({ wallet: relayBody.wallet })),
      });
      expect(issued.status, issued.text).toBe(200);
      const token = String((issued.json?.grant as Record<string, unknown>)?.token || '');

      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(res.status, res.text).toBe(200);
      expect(res.json?.ok).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('express rejects expired bootstrap tokens deterministically', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    let currentNow = new Date('2026-03-07T00:00:00.000Z');
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService({
      now: () => currentNow,
    });
    const router = createRouterApiRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
        now: () => currentNow,
        tokenTtlMs: 1_000,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });
    const srv = await startExpressRouter(router);
    try {
      const grantBody = await makeGrantBody();
      const issued = await fetchJson(`${srv.baseUrl}/v1/registration/bootstrap-grants`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(grantBody),
      });
      expect(issued.status, issued.text).toBe(200);
      const token = String((issued.json?.grant as Record<string, unknown>)?.token || '');

      currentNow = new Date(currentNow.getTime() + 2_000);
      const relayBody = makeWalletRegistrationIntentBody();
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(res.status, res.text).toBe(401);
      expect(res.json?.message).toContain('bootstrap_token_expired');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare rejects bootstrap token account mismatches', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const handler = createCloudflareRouter(makeRouterApiService(), {
      bootstrapGrantBroker: createRouterApiBootstrapGrantBroker({
        apiKeys,
        tokenStore: bootstrapTokens,
        orgProjectEnv,
      }),
      bootstrapTokenStore: bootstrapTokens,
    });

    const issued = await callCf(handler, {
      method: 'POST',
      path: '/v1/registration/bootstrap-grants',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${secret}`,
      },
      body: await makeGrantBody(),
    });
    expect(issued.status, issued.text).toBe(200);
    const token = String((issued.json?.grant as Record<string, unknown>)?.token || '');

    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: makeWalletRegistrationIntentBody({
        wallet: { kind: 'provided', walletId: 'mallory.w3a-relayer.testnet' },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: {
                kind: 'sponsored_named_account',
                requestedAccountId: 'mallory.w3a-relayer.testnet',
                sponsor: 'relayer',
              },
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      }),
    });
    expect(res.status, res.text).toBe(409);
    expect(res.json?.message).toContain('bootstrap_token_request_mismatch');
  });
});
