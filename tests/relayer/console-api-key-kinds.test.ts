import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayApiKeyAuthAdapter,
  createRelayRouter,
  type ConsoleAuthAdapter,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import {
  callCf,
  fetchJson,
  getPath,
  makeFakeAuthService,
  startExpressRouter,
} from './helpers';

const authOrgId = 'org-api-key-kinds';
const authUserId = 'user-api-key-kinds';
const projectId = 'project-api-key-kinds';
const environmentId = `${authOrgId}:${projectId}:prod`;

function makeConsoleAuthAdapter(roles: string[]): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId: authUserId,
        orgId: authOrgId,
        roles,
      },
    }),
  };
}

async function seedActiveEnvironment() {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const ctx = {
    orgId: authOrgId,
    actorUserId: authUserId,
    roles: ['admin'],
  };
  await orgProjectEnv.upsertOrganization(ctx, {
    name: 'API Key Kinds Org',
    slug: 'api-key-kinds-org',
  });
  await orgProjectEnv.createProject(ctx, {
    id: projectId,
    name: 'API Key Kinds Project',
    liveEnvironmentsEnabled: true,
  });
  return orgProjectEnv;
}

test.describe('console API key kinds', () => {
  test('express console router creates and lists publishable_key records', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'publishable_key',
          name: 'web-app',
          environmentId,
          allowedOrigins: ['https://app.example.com', 'https://app.example.com'],
          rateLimitBucket: 'default_web_v1',
          quotaBucket: 'free_registrations_v1',
          riskPolicy: { captcha: 'adaptive' },
          paymentPolicy: { mode: 'disabled' },
        }),
      });
      expect(created.status, created.text).toBe(201);
      expect(getPath(created.json, 'apiKey', 'kind')).toBe('publishable_key');
      expect(String(getPath(created.json, 'secret') || '')).toContain('tpk_v1_');
      expect(getPath(created.json, 'apiKey', 'allowedOrigins')).toEqual(['https://app.example.com']);
      expect(getPath(created.json, 'apiKey', 'scopes')).toBeUndefined();
      expect(getPath(created.json, 'apiKey', 'ipAllowlist')).toBeUndefined();
      expect(getPath(created.json, 'apiKey', 'rateLimitBucket')).toBe('default_web_v1');
      expect(getPath(created.json, 'apiKey', 'quotaBucket')).toBe('free_registrations_v1');

      const listed = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'GET',
      });
      expect(listed.status, listed.text).toBe(200);
      expect(getPath(listed.json, 'apiKeys', 0, 'kind')).toBe('publishable_key');
      expect(getPath(listed.json, 'apiKeys', 0, 'allowedOrigins')).toEqual([
        'https://app.example.com',
      ]);
      expect(getPath(listed.json, 'apiKeys', 0, 'scopes')).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('cloudflare console router creates publishable_key records', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        kind: 'publishable_key',
        name: 'cloudflare-web-app',
        environmentId,
        allowedOrigins: ['https://cf.example.com'],
        rateLimitBucket: 'default_web_v1',
        quotaBucket: 'free_registrations_v1',
        paymentPolicy: { mode: 'disabled' },
      },
    });
    expect(created.status, created.text).toBe(201);
    expect(getPath(created.json, 'apiKey', 'kind')).toBe('publishable_key');
    expect(String(getPath(created.json, 'secret') || '')).toContain('tpk_v1_');
    expect(getPath(created.json, 'apiKey', 'allowedOrigins')).toEqual(['https://cf.example.com']);
    expect(getPath(created.json, 'apiKey', 'scopes')).toBeUndefined();
    expect(getPath(created.json, 'apiKey', 'ipAllowlist')).toBeUndefined();
  });

  test('express console router updates publishable_key origins and broker policy', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'publishable_key',
          name: 'web-app',
          environmentId,
          allowedOrigins: ['https://app.example.com'],
          rateLimitBucket: 'default_web_v1',
          quotaBucket: 'free_registrations_v1',
        }),
      });
      expect(created.status, created.text).toBe(201);
      const apiKeyId = String(getPath(created.json, 'apiKey', 'id') || '');
      expect(apiKeyId).toBeTruthy();

      const updated = await fetchJson(`${srv.baseUrl}/console/api-keys/${encodeURIComponent(apiKeyId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'web-app-updated',
          allowedOrigins: ['https://admin.example.com', 'https://localhost:8443'],
          rateLimitBucket: 'browser_burst_v1',
          quotaBucket: 'paid_v1',
          paymentPolicy: { mode: 'quota_then_x402' },
        }),
      });
      expect(updated.status, updated.text).toBe(200);
      expect(getPath(updated.json, 'apiKey', 'name')).toBe('web-app-updated');
      expect(getPath(updated.json, 'apiKey', 'allowedOrigins')).toEqual([
        'https://admin.example.com',
        'https://localhost:8443',
      ]);
      expect(getPath(updated.json, 'apiKey', 'rateLimitBucket')).toBe('browser_burst_v1');
      expect(getPath(updated.json, 'apiKey', 'quotaBucket')).toBe('paid_v1');
      expect(getPath(updated.json, 'apiKey', 'paymentPolicy')).toEqual({
        mode: 'quota_then_x402',
      });
    } finally {
      await srv.close();
    }
  });

  test('cloudflare console router updates secret_key scopes and ip allowlist', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        kind: 'secret_key',
        name: 'server-app',
        environmentId,
        scopes: ['accounts.create'],
      },
    });
    expect(created.status, created.text).toBe(201);
    const apiKeyId = String(getPath(created.json, 'apiKey', 'id') || '');
    expect(apiKeyId).toBeTruthy();

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/api-keys/${encodeURIComponent(apiKeyId)}`,
      body: {
        name: 'server-app-updated',
        scopes: ['accounts.create', 'accounts.sync'],
        ipAllowlist: ['203.0.113.10/32'],
      },
    });
    expect(updated.status, updated.text).toBe(200);
    expect(getPath(updated.json, 'apiKey', 'name')).toBe('server-app-updated');
    expect(getPath(updated.json, 'apiKey', 'scopes')).toEqual([
      'accounts.create',
      'accounts.sync',
    ]);
    expect(getPath(updated.json, 'apiKey', 'ipAllowlist')).toEqual(['203.0.113.10/32']);
  });

  test('express console router deletes revoked API keys and blocks deleting active keys', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'secret_key',
          name: 'delete-target',
          environmentId,
          scopes: ['wallets:read'],
        }),
      });
      expect(created.status, created.text).toBe(201);
      const apiKeyId = String(getPath(created.json, 'apiKey', 'id') || '').trim();
      expect(apiKeyId).toBeTruthy();

      const deleteActive = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(apiKeyId)}/purge`,
        { method: 'DELETE' },
      );
      expect(deleteActive.status, deleteActive.text).toBe(409);
      expect(deleteActive.json?.code).toBe('api_key_not_revoked');

      const revoked = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(apiKeyId)}`,
        { method: 'DELETE' },
      );
      expect(revoked.status, revoked.text).toBe(200);
      expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

      const deleted = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(apiKeyId)}/purge`,
        { method: 'DELETE' },
      );
      expect(deleted.status, deleted.text).toBe(200);
      expect(getPath(deleted.json, 'deleted')).toBe(true);
      expect(String(getPath(deleted.json, 'apiKey', 'id') || '')).toBe(apiKeyId);

      const listed = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'GET',
      });
      expect(listed.status, listed.text).toBe(200);
      const listedRows = Array.isArray(getPath(listed.json, 'apiKeys'))
        ? (getPath(listed.json, 'apiKeys') as unknown[])
        : [];
      expect(
        listedRows.some((entry) => String((entry as Record<string, unknown>).id || '') === apiKeyId),
      ).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('cloudflare console router deletes revoked API keys', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = await seedActiveEnvironment();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        kind: 'secret_key',
        name: 'delete-target-cf',
        environmentId,
        scopes: ['wallets:read'],
      },
    });
    expect(created.status, created.text).toBe(201);
    const apiKeyId = String(getPath(created.json, 'apiKey', 'id') || '').trim();
    expect(apiKeyId).toBeTruthy();

    const revoked = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(apiKeyId)}`,
    });
    expect(revoked.status, revoked.text).toBe(200);
    expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(apiKeyId)}/purge`,
    });
    expect(deleted.status, deleted.text).toBe(200);
    expect(getPath(deleted.json, 'deleted')).toBe(true);
    expect(String(getPath(deleted.json, 'apiKey', 'id') || '')).toBe(apiKeyId);
  });

  test('relay bootstrap rejects publishable_key credentials', async () => {
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
        allowedOrigins: ['https://app.example.com'],
        rateLimitBucket: 'default_web_v1',
        quotaBucket: 'free_registrations_v1',
      },
    );

    const router = createRelayRouter(
      makeFakeAuthService({
        createAccountAndRegisterUser: async () => ({
          success: true,
          transactionHash: 'tx-123',
        }),
      }),
      {
        apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      },
    );
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${created.secret}`,
        },
        body: JSON.stringify({
          new_account_id: 'alice.testnet',
          rp_id: 'example.localhost',
          webauthn_registration: { id: 'cred-1' },
        }),
      });
      expect(res.status, res.text).toBe(401);
      expect(res.json?.code).toBe('secret_key_invalid');
    } finally {
      await srv.close();
    }
  });
});
