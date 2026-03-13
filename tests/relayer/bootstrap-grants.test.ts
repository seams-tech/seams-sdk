import { test, expect } from '@playwright/test';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayBootstrapGrantBroker,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { computeRegistrationBootstrapRequestHashSha256 } from '@shared/utils/registrationBootstrapHash';
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
  const relayBody = makeRelayRegistrationBody(overrides);
  const requestHashSha256 = await computeRegistrationBootstrapRequestHashSha256(relayBody);
  return {
    environmentId,
    newAccountId: String(relayBody.new_account_id),
    rpId: String(relayBody.rp_id),
    requestHashSha256,
    clientContext: {
      sdk: 'web',
      sdkVersion: '0.0.0-test',
    },
  };
}

function makeRelayRegistrationBody(overrides?: Partial<Record<string, unknown>>) {
  return {
    new_account_id: 'alice.w3a-relayer.testnet',
    device_number: 1,
    rp_id: 'app.example.com',
    webauthn_registration: { id: 'cred-1' },
    ...(overrides || {}),
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

test.describe('managed bootstrap grants', () => {
  test('express issues bootstrap token for valid publishable_key', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const broker = createRelayBootstrapGrantBroker({
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
    const router = createRelayRouter(makeRelayService(), {
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
      expect(String(res.json?.grant && (res.json.grant as Record<string, unknown>).token || '')).toContain(
        'tbt_v1_',
      );
      expect((res.json?.grant as Record<string, unknown>)?.environmentId).toBe(environmentId);
      expect((res.json?.grant as Record<string, unknown>)?.origin).toBe(allowedOrigin);
      expect((res.json?.grant as Record<string, unknown>)?.mode).toBe('free');
    } finally {
      await srv.close();
    }
  });

  test('express broker enforces rate limits', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const broker = createRelayBootstrapGrantBroker({
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
    const router = createRelayRouter(makeRelayService(), {
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
    const handler = createCloudflareRouter(makeRelayService(), {
      bootstrapGrantBroker: createRelayBootstrapGrantBroker({
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
    const handler = createCloudflareRouter(makeRelayService(), {
      bootstrapGrantBroker: createRelayBootstrapGrantBroker({
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

  test('express redeems issued bootstrap token once for registration', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const router = createRelayRouter(makeRelayService(), {
      bootstrapGrantBroker: createRelayBootstrapGrantBroker({
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

      const relayBody = makeRelayRegistrationBody();
      const first = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(first.status, first.text).toBe(200);
      expect(first.json?.success).toBe(true);

      const second = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(second.status, second.text).toBe(409);
      expect(second.json?.code).toBe('bootstrap_token_already_used');
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
    const router = createRelayRouter(makeRelayService(), {
      bootstrapGrantBroker: createRelayBootstrapGrantBroker({
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
      const relayBody = makeRelayRegistrationBody();
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
          Origin: allowedOrigin,
        },
        body: JSON.stringify(relayBody),
      });
      expect(res.status, res.text).toBe(401);
      expect(res.json?.code).toBe('bootstrap_token_expired');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare rejects bootstrap token request-hash mismatches', async () => {
    const orgProjectEnv = await seedEnvironment();
    const { apiKeys, secret } = await createPublishableKey({});
    const bootstrapTokens = createInMemoryConsoleBootstrapTokenService();
    const handler = createCloudflareRouter(makeRelayService(), {
      bootstrapGrantBroker: createRelayBootstrapGrantBroker({
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
      path: '/registration/bootstrap',
      origin: allowedOrigin,
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: makeRelayRegistrationBody({ device_number: 2 }),
    });
    expect(res.status, res.text).toBe(409);
    expect(res.json?.code).toBe('bootstrap_token_request_mismatch');
  });
});
