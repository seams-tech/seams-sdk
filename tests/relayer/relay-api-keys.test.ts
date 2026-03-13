import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleTeamRbacService,
  createRelayApiKeyAuthAdapter,
  createRelayRouter,
  type ConsoleApiKeyService,
  type RelayUsageMeterEvent,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import type { MachineApiKeyScope } from '@shared/console/apiKeyScopes';
import { callCf, fetchJson, getPath, makeCfCtx, makeFakeAuthService, startExpressRouter } from './helpers';

const apiKeyCtx = {
  orgId: 'org-relay-api-keys',
  actorUserId: 'user-relay-admin',
  roles: ['admin'],
};

function makeRegistrationBody(): Record<string, unknown> {
  return {
    new_account_id: 'alice.testnet',
    rp_id: 'example.localhost',
    webauthn_registration: { id: 'cred-1' },
  };
}

function makeRelayService() {
  return makeFakeAuthService({
    createAccountAndRegisterUser: async () => ({
      success: true,
      transactionHash: 'tx-123',
    }),
  });
}

function makeSerializedRegistrationCredential() {
  return {
    id: 'cred_registration_1',
    rawId: 'raw_registration_1',
    type: 'public-key',
    response: {
      clientDataJSON: 'Y2xpZW50RGF0YQ',
      attestationObject: 'YXR0ZXN0YXRpb24',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {},
      },
    },
  };
}

async function createActiveSecret(
  apiKeys: ConsoleApiKeyService,
  input: { scopes: MachineApiKeyScope[]; ipAllowlist?: string[]; expiresAt?: string },
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('secret_key_missing');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer sk_invalidsecret',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('secret_key_invalid');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_revoked');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_forbidden_scope');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-tatchi-environment-id': 'env-stage',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_environment_mismatch');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '198.51.100.2',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_ip_blocked');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_revoked');
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
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '127.0.0.1',
          'x-tatchi-environment-id': 'env-prod',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(key?.lastUsedAt).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
      expect(meteredEvents.length).toBe(1);
      expect(meteredEvents[0]?.action).toBe('wallet_created');
      expect(meteredEvents[0]?.succeeded).toBe(true);
      expect(meteredEvents[0]?.orgId).toBe('org-relay-api-keys');
      expect(meteredEvents[0]?.environmentId).toBe('env-prod');
      expect(meteredEvents[0]?.walletId).toBe('alice.testnet');
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
      const onboardingEnvironmentId = String(getPath(project.json, 'result', 'environment', 'id') || '');
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

      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeySecret}`,
        },
        body: JSON.stringify({
          new_account_id: 'alice.w3a-relayer.testnet',
          rp_id: 'example.localhost',
          webauthn_registration: makeSerializedRegistrationCredential(),
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);
      expect(res.json?.transactionHash).toBe('tx-123');

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
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
      path: '/registration/bootstrap',
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('secret_key_missing');
  });

  test('rejects invalid API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: { Authorization: 'Bearer sk_invalidsecret' },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('secret_key_invalid');
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
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_revoked');
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
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_forbidden_scope');
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
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'x-tatchi-environment-id': 'env-stage',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_environment_mismatch');
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
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '198.51.100.55',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_ip_blocked');
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
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_revoked');
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
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '203.0.113.20',
        'x-tatchi-environment-id': 'env-prod',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(200);
    expect(res.json?.success).toBe(true);

    const keys = await apiKeys.listApiKeys(apiKeyCtx);
    const key = keys.find((entry) => entry.id === apiKeyId);
    expect(key).toBeTruthy();
    expect(key?.lastUsedAt).toBeTruthy();
    expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
    expect(meteredEvents.length).toBe(1);
    expect(meteredEvents[0]?.action).toBe('wallet_created');
    expect(meteredEvents[0]?.succeeded).toBe(true);
    expect(meteredEvents[0]?.orgId).toBe('org-relay-api-keys');
    expect(meteredEvents[0]?.environmentId).toBe('env-prod');
    expect(meteredEvents[0]?.walletId).toBe('alice.testnet');
  });
});
