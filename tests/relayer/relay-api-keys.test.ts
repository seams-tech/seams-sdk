import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createRelayApiKeyAuthAdapter,
  createRelayRouter,
  type ConsoleApiKeyService,
  type ConsoleWallet,
  type RelayUsageMeterEvent,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import type { ApiCredentialScope } from '@shared/console/apiKeyScopes';
import {
  callCf,
  fetchJson,
  getPath,
  makeCfCtx,
  makeFakeAuthService,
  startExpressRouter,
} from './helpers';

const apiKeyCtx = {
  orgId: 'org-relay-api-keys',
  actorUserId: 'user-relay-admin',
  roles: ['admin'],
};

function makeRegistrationBody(): Record<string, unknown> {
  return {
    walletSubject: { kind: 'provided', walletSubjectId: 'alice.testnet' },
    rpId: 'example.localhost',
    signerSelection: {
      mode: 'ed25519_only',
      ed25519: {
        nearAccountId: 'alice.testnet',
        signerSlot: 1,
        createNearAccount: true,
        keyPurpose: 'ed25519-hss/y_relayer',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
        derivationVersion: 1,
      },
    },
  };
}

function makeRelayService() {
  const service = makeFakeAuthService();
  (service as any).createRegistrationIntent = async (input: Record<string, any>) => ({
    ok: true,
    intent: {
      version: 'registration_intent_v1',
      walletSubjectId: input.request.walletSubject.walletSubjectId,
      rpId: input.request.rpId,
      authMethod: input.request.authMethod,
      signerSelection: input.request.signerSelection,
      nonceB64u: 'nonce-test',
    },
    registrationIntentDigestB64u: 'digest-test',
    registrationIntentGrant: 'rig_test',
    expiresAtMs: Date.now() + 60_000,
  });
  return service;
}

function makeWallet(overrides: Partial<ConsoleWallet> = {}): ConsoleWallet {
  const id = String(overrides.id || 'wlt_wallet_1');
  const environmentId = String(overrides.environmentId || 'env-prod');
  const projectId = String(
    overrides.projectId ||
      (environmentId.includes(':') ? environmentId.split(':')[0] : 'proj_wallets'),
  );
  return {
    id,
    orgId: 'org-relay-api-keys',
    projectId,
    environmentId,
    userId: String(overrides.userId || 'user-wallet-1'),
    externalRefId: String(overrides.externalRefId || `${id}:external`),
    address: String(overrides.address || `0x${'1'.repeat(40)}`),
    chain: overrides.chain || 'Ethereum',
    walletType: overrides.walletType || 'SMART',
    status: overrides.status || 'ACTIVE',
    policyId: overrides.policyId === undefined ? null : overrides.policyId,
    balanceMinor: overrides.balanceMinor === undefined ? 100 : overrides.balanceMinor,
    lastActivityAt:
      overrides.lastActivityAt === undefined
        ? '2026-03-14T00:00:00.000Z'
        : overrides.lastActivityAt,
    createdAt: overrides.createdAt || '2026-03-14T00:00:00.000Z',
    updatedAt: overrides.updatedAt || '2026-03-14T00:00:00.000Z',
    ...overrides,
  };
}

async function createActiveSecret(
  apiKeys: ConsoleApiKeyService,
  input: { scopes: ApiCredentialScope[]; ipAllowlist?: string[]; expiresAt?: string },
): Promise<{ apiKeyId: string; secret: string }> {
  const created = await apiKeys.createApiKey(apiKeyCtx, {
    kind: 'secret_key',
    name: 'registration-key',
    environmentId: 'env-prod',
    scopes: input.scopes,
    ...(input.ipAllowlist ? { ipAllowlist: input.ipAllowlist } : {}),
    ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
  });
  return { apiKeyId: created.apiKey.id, secret: created.secret };
}

test.describe('relay API key auth (express)', () => {

  test('rejects missing API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.localhost' },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(String(res.json?.message || '')).toContain('secret_key_missing');
    } finally {
      await srv.close();
    }
  });

  test('rejects invalid API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer sk_invalidsecret',
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(String(res.json?.message || '')).toContain('secret_key_invalid');
    } finally {
      await srv.close();
    }
  });

  test('rejects revoked API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId);
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(String(res.json?.message || '')).toContain('secret_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('rejects key missing required scope', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: [],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(String(res.json?.message || '')).toContain('secret_key_forbidden_scope');
    } finally {
      await srv.close();
    }
  });

  test('rejects key when environment header mismatches', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
          'x-seams-environment-id': 'env-stage',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(String(res.json?.message || '')).toContain('secret_key_environment_mismatch');
    } finally {
      await srv.close();
    }
  });

  test('rejects key blocked by IP allowlist', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.10/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
          'x-forwarded-for': '198.51.100.2',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(String(res.json?.message || '')).toContain('secret_key_ip_blocked');
    } finally {
      await srv.close();
    }
  });

  test('rejects expired API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(String(res.json?.message || '')).toContain('secret_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('accepts valid scoped key and records usage', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const meteredEvents: RelayUsageMeterEvent[] = [];
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      apiKeyUsageMeter: {
        recordEvent: async (event) => {
          meteredEvents.push(event);
        },
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          Origin: 'https://example.localhost',
          'x-forwarded-for': '127.0.0.1',
          'x-seams-environment-id': 'env-prod',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(key?.lastUsedAt).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /wallets/register/intent'] || 0)).toBe(1);
      expect(meteredEvents.length).toBe(0);
    } finally {
      await srv.close();
    }
  });

  test('dashboard onboarding key works with SDK registration client call', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const billing = createInMemoryConsoleBillingService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      billing,
      teamRbac,
    });

    const consoleRouter = createConsoleRouter({
      auth: {
        authenticate: async () => ({
          ok: true,
          claims: {
            userId: apiKeyCtx.actorUserId,
            orgId: apiKeyCtx.orgId,
            roles: ['admin'],
          },
        }),
      },
      onboarding,
      apiKeys,
      orgProjectEnv,
      billing,
      teamRbac,
    });
    const relayRouter = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    consoleRouter.use(relayRouter);

    const srv = await startExpressRouter(consoleRouter);
    try {
      const organization = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Dashboard SDK Org', slug: 'dashboard-sdk-org' },
        }),
      });
      expect(organization.status).toBe(201);

      const checkoutSession = await billing.createStripeCheckoutSession(
        {
          orgId: apiKeyCtx.orgId,
          actorUserId: apiKeyCtx.actorUserId,
          roles: ['admin'],
        },
        {
          successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
          cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
          creditPackId: 'usd_25',
        },
      );
      const settleResult = await billing.processStripeWebhookEvent({
        eventId: `evt_relay_api_keys_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        eventType: 'checkout.session.completed',
        orgId: apiKeyCtx.orgId,
        checkoutSessionId: checkoutSession.id,
        providerCustomerRef: checkoutSession.customerRef,
        providerRef: checkoutSession.id,
      });
      expect(settleResult.accepted).toBe(true);

      const project = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_dashboard_sdk', name: 'Dashboard SDK Project' },
          environment: {
            id: 'proj_dashboard_sdk:prod',
            name: 'Production',
          },
        }),
      });
      expect(project.status).toBe(201);
      const onboardingEnvironmentId = String(
        getPath(project.json, 'result', 'environment', 'id') || '',
      );
      expect(onboardingEnvironmentId.length).toBeGreaterThan(0);

      const apiKeyCreate = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'secret_key',
          name: 'dashboard-sdk-key',
          environmentId: onboardingEnvironmentId,
          scopes: ['accounts.create'],
        }),
      });
      expect(apiKeyCreate.status).toBe(201);
      const apiKeyId = String(getPath(apiKeyCreate.json, 'apiKey', 'id') || '');
      const apiKeySecret = String(getPath(apiKeyCreate.json, 'secret') || '');
      expect(apiKeyId.length).toBeGreaterThan(0);
      expect(apiKeySecret.length).toBeGreaterThan(0);

      const res = await fetchJson(`${srv.baseUrl}/wallets/register/intent`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeySecret}`,
          Origin: 'https://example.localhost',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.ok).toBe(true);

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /wallets/register/intent'] || 0)).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('API credential wallet routes require wallets.read scope and stay bound to the key environment', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeWallet({
          id: 'wlt_env_prod_1',
          environmentId: 'env-prod',
          projectId: 'proj_prod',
          userId: 'user-prod',
          externalRefId: 'prod-wallet-1',
          address: `0x${'3'.repeat(40)}`,
        }),
        makeWallet({
          id: 'wlt_env_stage_1',
          environmentId: 'env-stage',
          projectId: 'proj_stage',
          userId: 'user-stage',
          externalRefId: 'stage-wallet-1',
          address: `0x${'4'.repeat(40)}`,
        }),
      ],
    });
    const { secret: limitedSecret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const { secret: readSecret } = await createActiveSecret(apiKeys, {
      scopes: ['wallets.read'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      wallets,
    });
    const srv = await startExpressRouter(router);
    try {
      const denied = await fetchJson(`${srv.baseUrl}/v1/wallets`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${limitedSecret}`,
        },
      });
      expect(denied.status).toBe(403);
      expect(denied.json?.code).toBe('secret_key_forbidden_scope');

      const listed = await fetchJson(
        `${srv.baseUrl}/v1/wallets?environmentId=env-stage&userId=user-prod`,
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${readSecret}`,
            'x-forwarded-for': '127.0.0.1',
          },
        },
      );
      expect(listed.status).toBe(200);
      expect(getPath(listed.json, 'wallets', 0, 'id')).toBe('wlt_env_prod_1');
      expect(getPath(listed.json, 'wallets', 1)).toBeUndefined();

      const searched = await fetchJson(`${srv.baseUrl}/v1/wallets/search?q=stage-wallet-1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(searched.status).toBe(200);
      expect(getPath(searched.json, 'wallets', 0)).toBeUndefined();

      const wallet = await fetchJson(`${srv.baseUrl}/v1/wallets/wlt_env_prod_1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(wallet.status).toBe(200);
      expect(getPath(wallet.json, 'wallet', 'id')).toBe('wlt_env_prod_1');

      const hidden = await fetchJson(`${srv.baseUrl}/v1/wallets/wlt_env_stage_1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(hidden.status).toBe(404);
      expect(hidden.json?.code).toBe('wallet_not_found');
    } finally {
      await srv.close();
    }
  });
});

test.describe('relay API key auth (cloudflare)', () => {
  test('rejects missing API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(String(res.json?.message || '')).toContain('secret_key_missing');
  });

  test('rejects invalid API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: { Authorization: 'Bearer sk_invalidsecret' },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(String(res.json?.message || '')).toContain('secret_key_invalid');
  });

  test('rejects revoked API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId);
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(String(res.json?.message || '')).toContain('secret_key_revoked');
  });

  test('rejects key missing required scope', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: [],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(String(res.json?.message || '')).toContain('secret_key_forbidden_scope');
  });

  test('rejects key when environment header mismatches', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: {
        Authorization: `Bearer ${secret}`,
        'x-seams-environment-id': 'env-stage',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(String(res.json?.message || '')).toContain('secret_key_environment_mismatch');
  });

  test('rejects key blocked by IP allowlist', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.10/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '198.51.100.55',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(String(res.json?.message || '')).toContain('secret_key_ip_blocked');
  });

  test('rejects expired API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(String(res.json?.message || '')).toContain('secret_key_revoked');
  });

  test('accepts valid scoped key and records usage', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const meteredEvents: RelayUsageMeterEvent[] = [];
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.20/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      apiKeyUsageMeter: {
        recordEvent: async (event) => {
          meteredEvents.push(event);
        },
      },
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/wallets/register/intent',
      origin: 'https://example.localhost',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '203.0.113.20',
        'x-seams-environment-id': 'env-prod',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(200);
    expect(res.json?.ok).toBe(true);

    const keys = await apiKeys.listApiKeys(apiKeyCtx);
    const key = keys.find((entry) => entry.id === apiKeyId);
    expect(key).toBeTruthy();
    expect(key?.lastUsedAt).toBeTruthy();
    expect(Number(key?.endpointUsageCounts['POST /wallets/register/intent'] || 0)).toBe(1);
    expect(meteredEvents.length).toBe(0);
  });

  test('API credential wallet routes require wallets.read scope and stay bound to the key environment', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeWallet({
          id: 'wlt_env_prod_1',
          environmentId: 'env-prod',
          projectId: 'proj_prod',
          userId: 'user-prod',
          externalRefId: 'prod-wallet-1',
          address: `0x${'3'.repeat(40)}`,
        }),
        makeWallet({
          id: 'wlt_env_stage_1',
          environmentId: 'env-stage',
          projectId: 'proj_stage',
          userId: 'user-stage',
          externalRefId: 'stage-wallet-1',
          address: `0x${'4'.repeat(40)}`,
        }),
      ],
    });
    const { secret: limitedSecret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const { secret: readSecret } = await createActiveSecret(apiKeys, {
      scopes: ['wallets.read'],
      ipAllowlist: ['203.0.113.20/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      wallets,
    });
    const { ctx } = makeCfCtx();

    const denied = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets',
      headers: {
        Authorization: `Bearer ${limitedSecret}`,
      },
      ctx,
    });
    expect(denied.status).toBe(403);
    expect(denied.json?.code).toBe('secret_key_forbidden_scope');

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets?environmentId=env-stage&userId=user-prod',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(listed.status).toBe(200);
    expect(getPath(listed.json, 'wallets', 0, 'id')).toBe('wlt_env_prod_1');
    expect(getPath(listed.json, 'wallets', 1)).toBeUndefined();

    const searched = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/search?q=stage-wallet-1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(searched.status).toBe(200);
    expect(getPath(searched.json, 'wallets', 0)).toBeUndefined();

    const wallet = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/wlt_env_prod_1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(wallet.status).toBe(200);
    expect(getPath(wallet.json, 'wallet', 'id')).toBe('wlt_env_prod_1');

    const hidden = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/wlt_env_stage_1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(hidden.status).toBe(404);
    expect(hidden.json?.code).toBe('wallet_not_found');
  });
});
