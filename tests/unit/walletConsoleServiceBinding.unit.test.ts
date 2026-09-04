import { test, expect } from '@playwright/test';
import { WALLET_API_CREDENTIAL_SCOPE_VALIDATION } from '@seams-internal/wallet-console-shared/apiKeyScopes';
import { createInMemoryConsoleApiKeyService } from '@seams-internal/console-server/apiKeys/index';
import {
  createRouterApiKeyAuthAdapter,
  createRouterApiPublishableKeyAuthAdapter,
} from '@seams-internal/wallet-console-server/router/routerApiKeyAuth';
import { createWalletConsoleOpsHandler } from '@seams-internal/wallet-console-server/serviceBinding/walletConsoleOpsHandler';
import { createWalletConsoleOpsClient } from '@seams-internal/wallet-console-server/serviceBinding/walletConsoleOpsClient';
import { createWalletConsoleRelayProxyExtension } from '@seams-internal/wallet-console-server/serviceBinding/walletConsoleRelay';
import { createWalletRuntimeOpsHandler } from '@seams-internal/wallet-console-server/serviceBinding/walletRuntimeOpsHandler';
import type { RouterApiUsageMeterEvent } from '@seams/wallet-server/cloud-host';
import type { TenantRootIdentityV1 } from '@seams-internal/wallet-console-server/tenantRootCreation/types';

const CTX = {
  orgId: 'org-binding-test',
  actorUserId: 'user-binding-test',
  projectId: 'project-1',
  environmentId: 'env-1',
};

const TENANT_ROOT_IDENTITY: TenantRootIdentityV1 = {
  orgId: CTX.orgId,
  projectId: CTX.projectId,
  envId: CTX.environmentId,
  signingRootId: `${CTX.projectId}:${CTX.environmentId}`,
  signingRootVersion: 'runtime-v1',
};

function bindingHarness() {
  const apiKeys = createInMemoryConsoleApiKeyService({
    scopeValidation: WALLET_API_CREDENTIAL_SCOPE_VALIDATION,
  });
  const recorded: RouterApiUsageMeterEvent[] = [];
  const handler = createWalletConsoleOpsHandler({
    apiKeyAuth: createRouterApiKeyAuthAdapter(apiKeys),
    publishableKeyAuth: createRouterApiPublishableKeyAuthAdapter(apiKeys),
    usageMeter: {
      async recordEvent(event) {
        recorded.push(event);
      },
    },
    projectEnvironments: {
      async listEnvironments() {
        return [];
      },
    },
    tenantRootActiveLineage: {
      async resolveActiveLineage(identity) {
        if (
          identity.orgId !== TENANT_ROOT_IDENTITY.orgId ||
          identity.projectId !== TENANT_ROOT_IDENTITY.projectId ||
          identity.envId !== TENANT_ROOT_IDENTITY.envId ||
          identity.signingRootId !== TENANT_ROOT_IDENTITY.signingRootId ||
          identity.signingRootVersion !== TENANT_ROOT_IDENTITY.signingRootVersion
        ) {
          return null;
        }
        return {
          identityDigestB64u: 'identity-digest-1',
          custodyLineageB64u: 'custody-lineage-1',
        };
      },
    },
  });
  const client = createWalletConsoleOpsClient({
    async fetch(input, init) {
      const request = typeof input === 'string' ? new Request(input, init) : input;
      const response = await handler(request);
      if (!response) throw new Error(`unhandled internal path: ${request.url}`);
      return response;
    },
  });
  return { apiKeys, client, recorded };
}

test('secret-key auth round-trips through the exact binding operation', async () => {
  const { apiKeys, client } = bindingHarness();
  const created = await apiKeys.createApiKey(CTX, {
    kind: 'secret_key',
    name: 'binding-test',
    environmentId: CTX.environmentId,
    scopes: ['wallets.read'],
  });
  const result = await client.apiKeyAuth.authenticate({
    secret: created.secret,
    endpoint: '/v1/wallets',
    requiredScopes: ['wallets.read'],
  });
  expect(result.ok).toBe(true);
  if (result.ok) {
    expect(result.principal.orgId).toBe(CTX.orgId);
    expect(result.principal.environmentId).toBe(CTX.environmentId);
    expect(result.principal.scopes).toContain('wallets.read');
  }
});

test('invalid secret key fails closed across the binding with status and code', async () => {
  const { client } = bindingHarness();
  const result = await client.apiKeyAuth.authenticate({
    secret: 'sk_not_a_real_secret',
    endpoint: '/v1/wallets',
    requiredScopes: ['wallets.read'],
  });
  expect(result.ok).toBe(false);
  if (!result.ok) {
    expect([401, 403]).toContain(result.status);
    expect(String(result.code)).toContain('secret_key');
  }
});

test('publishable-key auth enforces origin binding across the binding', async () => {
  const { apiKeys, client } = bindingHarness();
  const created = await apiKeys.createApiKey(CTX, {
    kind: 'publishable_key',
    name: 'binding-pub',
    environmentId: CTX.environmentId,
    allowedOrigins: ['https://app.example.com'],
    rateLimitBucket: 'default',
    quotaBucket: 'default',
  });
  const allowed = await client.publishableKeyAuth.authenticate({
    secret: created.secret,
    origin: 'https://app.example.com',
    environmentId: CTX.environmentId,
  });
  expect(allowed.ok).toBe(true);
  const blocked = await client.publishableKeyAuth.authenticate({
    secret: created.secret,
    origin: 'https://evil.example.com',
    environmentId: CTX.environmentId,
  });
  expect(blocked.ok).toBe(false);
});

test('usage events ingest through the binding with idempotency key preserved', async () => {
  const { client, recorded } = bindingHarness();
  await client.usageMeter.recordEvent({
    orgId: CTX.orgId,
    environmentId: CTX.environmentId,
    apiKeyId: 'key-1',
    endpoint: '/v1/wallets',
    walletId: 'wallet-1',
    action: 'wallet_created',
    succeeded: true,
    sourceEventId: 'evt-123',
  });
  expect(recorded).toHaveLength(1);
  expect(recorded[0].sourceEventId).toBe('evt-123');
  expect(recorded[0].action).toBe('wallet_created');
});

test('active tenant-root lineage resolves through the exact private operation', async () => {
  const { client } = bindingHarness();
  await expect(
    client.tenantRootActiveLineage.resolveActiveLineage(TENANT_ROOT_IDENTITY),
  ).resolves.toEqual({
    identityDigestB64u: 'identity-digest-1',
    custodyLineageB64u: 'custody-lineage-1',
  });
});

test('active tenant-root lineage forwards only the canonical identity through the binding', async () => {
  const { client } = bindingHarness();
  await expect(
    client.tenantRootActiveLineage.resolveActiveLineage({
      ...TENANT_ROOT_IDENTITY,
      envId: 'env-selected-by-caller',
    }),
  ).resolves.toBeNull();
});

test('active tenant-root lineage rejects incomplete or extra identity fields at the boundary', async () => {
  const handler = createWalletConsoleOpsHandler({
    apiKeyAuth: {
      async authenticate() {
        throw new Error('must not run');
      },
    },
    publishableKeyAuth: {
      async authenticate() {
        throw new Error('must not run');
      },
    },
    usageMeter: {
      async recordEvent() {
        throw new Error('must not run');
      },
    },
    projectEnvironments: {
      async listEnvironments() {
        throw new Error('must not run');
      },
    },
    tenantRootActiveLineage: {
      async resolveActiveLineage() {
        throw new Error('must not run');
      },
    },
  });
  const response = await handler(
    new Request(
      'https://wallet-console.internal/internal/wallet-console/v1/tenant-root/active-lineage',
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          ...TENANT_ROOT_IDENTITY,
          extra: 'rejected',
        }),
      },
    ),
  );
  expect(response?.status).toBe(400);
  await expect(response?.json()).resolves.toMatchObject({ code: 'invalid_body' });
});

test('unknown internal operations are rejected, never forwarded', async () => {
  const { client } = bindingHarness();
  await expect(
    client.usageMeter.recordEvent({
      orgId: '',
      environmentId: '',
      apiKeyId: '',
      endpoint: '/v1/wallets',
      walletId: '',
      action: 'wallet_created',
      succeeded: true,
    }),
  ).rejects.toThrow(/usage ingestion failed/);
});

test('public Console origins cannot invoke service-binding operations', async () => {
  const handler = createWalletConsoleOpsHandler({
    apiKeyAuth: {
      async authenticate() {
        throw new Error('must not run');
      },
    },
    publishableKeyAuth: {
      async authenticate() {
        throw new Error('must not run');
      },
    },
    usageMeter: {
      async recordEvent() {
        throw new Error('must not run');
      },
    },
    projectEnvironments: {
      async listEnvironments() {
        throw new Error('must not run');
      },
    },
    tenantRootActiveLineage: {
      async resolveActiveLineage() {
        throw new Error('must not run');
      },
    },
  });
  const response = await handler(
    new Request('https://staging.console.seams.sh/internal/wallet-console/v1/usage-events', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    }),
  );
  expect(response).toBeNull();
});

test('split Gateway proxy preserves the complete Wallet Console relay surface', () => {
  const extension = createWalletConsoleRelayProxyExtension({
    async fetch() {
      return new Response(null, { status: 204 });
    },
  });
  expect(extension.routes.map((route) => `${route.method} ${route.path}`)).toEqual([
    'GET /v1/wallets',
    'GET /v1/wallets/search',
    'GET /v1/wallets/:id',
    'POST /signed-delegate',
    'POST /sponsorships/evm/call',
  ]);
});

test('Wallet runtime operations reject public Gateway origins', async () => {
  const handler = createWalletRuntimeOpsHandler(async () => {
    throw new Error('must not resolve public requests');
  });
  const response = await handler(
    new Request('https://staging.api.seams.sh/internal/wallet-runtime/v1/relayer-account', {
      method: 'POST',
    }),
  );
  expect(response).toBeNull();
});
