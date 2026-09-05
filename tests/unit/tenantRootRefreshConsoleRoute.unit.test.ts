import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/service';
import type { ConsoleAuthClaims } from '../../packages/console-server-ts/src/router/consoleAuth';
import {
  createTenantRootRefreshConsoleRouteV1,
  type TenantRootRefreshConsoleRouteDependenciesV1,
  type TenantRootRefreshRouterRequestV1,
} from '../../packages/wallet-console-server-ts/src/tenantRootCreation/consoleRoute';
import { tenantRootIdentityDigestB64uV1 } from '../../packages/wallet-console-server-ts/src/tenantRootCreation/grantSigner';
import type {
  TenantRootCreationGrantRecordV1,
  TenantRootIdentityV1,
} from '../../packages/wallet-console-server-ts/src/tenantRootCreation/types';

const ORG_ID = 'org-refresh-test';
const USER_ID = 'operator-refresh-test';
const PROJECT_ID = 'project-refresh-test';
const ENVIRONMENT_ID = `${PROJECT_ID}:dev`;
const CUSTODY_LINEAGE_B64U = 'custody-lineage-refresh-test';

function claimsFor(role: ConsoleAuthClaims['role']): ConsoleAuthClaims {
  const common = {
    userId: USER_ID,
    orgId: ORG_ID,
    membershipId: 'membership-refresh-test',
    authorizationVersion: 1,
    platformSupport: false,
    projectId: PROJECT_ID,
    environmentId: ENVIRONMENT_ID,
  };
  if (role === 'MEMBER') {
    return {
      ...common,
      role,
      adminPermissions: [],
      projectAccess: { kind: 'assigned', assignments: [] },
    };
  }
  return {
    ...common,
    role,
    adminPermissions: [],
    projectAccess: { kind: 'all' },
  };
}

async function createEnvironmentService() {
  const service = createInMemoryConsoleOrgProjectEnvService();
  await service.upsertOrganization(
    { orgId: ORG_ID, actorUserId: USER_ID },
    { name: 'Refresh Test Organization' },
  );
  await service.createProject(
    { orgId: ORG_ID, actorUserId: USER_ID },
    { id: PROJECT_ID, name: 'Refresh Test Project' },
  );
  return service;
}

function activeGrant(
  identity: TenantRootIdentityV1,
  identityDigestB64u: string,
): TenantRootCreationGrantRecordV1 {
  return {
    namespace: 'refresh-test',
    operationId: 'creation-operation-refresh-test',
    identity,
    identityDigestB64u,
    custodyLineageB64u: CUSTODY_LINEAGE_B64U,
    grantNonceB64u: 'grant-nonce-refresh-test',
    grantKeyId: 'grant-key-refresh-test',
    grantB64u: 'grant-refresh-test',
    grantDigestB64u: 'grant-digest-refresh-test',
    issuedAtMs: 1,
    expiresAtMs: 2,
    createdAtMs: 1,
    updatedAtMs: 1,
    status: 'ACTIVE',
    ready: {
      revision: 1,
      rootCommitmentB64u: 'root-commitment-refresh-test',
      journalDigestB64u: 'journal-digest-refresh-test',
      capabilityDigestB64u: 'capability-digest-refresh-test',
    },
  };
}

function successfulRouterRefreshResponse(): Response {
  return new Response(
    JSON.stringify({
      activation_receipt_digest_b64u: 'activation-receipt-refresh-test',
      lifecycle_revision: 2,
    }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  );
}

async function createRoute(
  role: ConsoleAuthClaims['role'] = 'OWNER',
  routerResponse: () => Response = successfulRouterRefreshResponse,
): Promise<{
  readonly route: (request: Request) => Promise<Response | null>;
  readonly lookup: { identity: TenantRootIdentityV1; identityDigestB64u: string }[];
  readonly forwarded: Request[];
}> {
  const orgProjectEnv = await createEnvironmentService();
  const lookup: { identity: TenantRootIdentityV1; identityDigestB64u: string }[] = [];
  const forwarded: Request[] = [];
  const dependencies: TenantRootRefreshConsoleRouteDependenciesV1 = {
    auth: { authenticate: () => ({ ok: true, claims: claimsFor(role) }) },
    orgProjectEnv,
    grants: {
      async findActiveLineageByIdentity(input) {
        lookup.push(input);
        return activeGrant(input.identity, input.identityDigestB64u);
      },
    },
    router: {
      async fetch(input, init) {
        forwarded.push(new Request(input, init));
        return routerResponse();
      },
    },
    internalServiceAuthSecret: 'router-internal-refresh-test',
  };
  return { route: createTenantRootRefreshConsoleRouteV1(dependencies), lookup, forwarded };
}

test('refresh route resolves active lineage and forwards only the bounded Router request', async () => {
  const { route, lookup, forwarded } = await createRoute();
  const response = await route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({ operationId: 'refresh-operation-test' }),
    }),
  );

  expect(response?.status).toBe(200);
  await expect(response?.json()).resolves.toEqual({
    ok: true,
    status: 'ACTIVE',
    activationReceiptDigestB64u: 'activation-receipt-refresh-test',
    lifecycleRevision: 2,
  });
  expect(lookup).toHaveLength(1);
  expect(forwarded).toHaveLength(1);
  const expectedIdentity: TenantRootIdentityV1 = {
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENVIRONMENT_ID,
    signingRootId: `${PROJECT_ID}:dev`,
    signingRootVersion: 'default',
  };
  const identityDigestB64u = await tenantRootIdentityDigestB64uV1(expectedIdentity);
  expect(lookup[0]).toEqual({ identity: expectedIdentity, identityDigestB64u });
  expect(forwarded[0]?.url).toBe(
    'https://mpc-router.router-ab.internal/router-ab/internal/tenant-root/refresh/v1/execute',
  );
  expect(forwarded[0]?.method).toBe('POST');
  expect(forwarded[0]?.headers.get('x-router-ab-internal-service-auth')).toBe(
    'router-internal-refresh-test',
  );
  await expect(forwarded[0]?.json()).resolves.toEqual({
    operation_id: 'refresh-operation-test',
    identity_digest_b64u: identityDigestB64u,
    custody_lineage_b64u: CUSTODY_LINEAGE_B64U,
  });
});

test('refresh route requires projects.manage authorization before resolving lineage', async () => {
  const { route, lookup, forwarded } = await createRoute('ADMIN');
  const response = await route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({ operationId: 'refresh-operation-forbidden' }),
    }),
  );

  expect(response?.status).toBe(403);
  await expect(response?.json()).resolves.toMatchObject({ ok: false, code: 'forbidden' });
  expect(lookup).toHaveLength(0);
  expect(forwarded).toHaveLength(0);
});

test('refresh route rejects missing or smuggled request selectors', async () => {
  const { route, lookup, forwarded } = await createRoute();
  const response = await route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({
        operationId: 'refresh-operation-smuggled',
        identity_digest_b64u: 'caller-identity',
        custody_lineage_b64u: 'caller-lineage',
        authority_id: 'caller-authority',
        role: 'deriver_a',
        now_ms: 1,
        signer_key_id: 'caller-signer',
        mode: 'emergency',
      }),
    }),
  );

  expect(response?.status).toBe(400);
  await expect(response?.json()).resolves.toMatchObject({ ok: false, code: 'invalid_request' });
  expect(lookup).toHaveLength(0);
  expect(forwarded).toHaveLength(0);
});

const boundedRefreshRequest: TenantRootRefreshRouterRequestV1 = {
  operation_id: 'refresh-operation-type-test',
  identity_digest_b64u: 'identity-digest-type-test',
  custody_lineage_b64u: 'custody-lineage-type-test',
};

void boundedRefreshRequest;

const refreshRequestWithAuthority: TenantRootRefreshRouterRequestV1 = {
  ...boundedRefreshRequest,
  // @ts-expect-error The Router request cannot carry caller-selected authority.
  authority_id: 'caller-authority',
};

void refreshRequestWithAuthority;

// @ts-expect-error A refresh must retain its operation identity across retries.
const refreshRequestWithoutOperation: TenantRootRefreshRouterRequestV1 = {
  identity_digest_b64u: 'identity-digest-type-test',
  custody_lineage_b64u: 'custody-lineage-type-test',
};

void refreshRequestWithoutOperation;

function throttledRouterRefreshResponse(): Response {
  return new Response(
    JSON.stringify({
      code: 'tenant_root_refresh_throttled',
      retry_at_ms: 1_800_000_000_000,
    }),
    { status: 429 },
  );
}

function inProgressRouterRefreshResponse(): Response {
  return new Response(JSON.stringify({ code: 'tenant_root_refresh_in_progress' }), { status: 409 });
}

function invalidRetryRouterRefreshResponse(): Response {
  return new Response(
    JSON.stringify({
      code: 'tenant_root_refresh_throttled',
      retry_at_ms: '1800000000000',
    }),
    { status: 429 },
  );
}

test('refresh route preserves server cooldown and in-progress outcomes and rejects malformed retry times', async () => {
  const throttled = await createRoute('OWNER', throttledRouterRefreshResponse);
  const cooldown = await throttled.route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({ operationId: 'refresh-throttled' }),
    }),
  );
  expect(cooldown?.status).toBe(429);
  expect(cooldown?.headers.get('Retry-After')).toBe(new Date(1_800_000_000_000).toUTCString());
  await expect(cooldown?.json()).resolves.toMatchObject({
    ok: false,
    code: 'tenant_root_refresh_throttled',
    retryAtMs: 1_800_000_000_000,
  });

  const pending = await createRoute('OWNER', inProgressRouterRefreshResponse);
  const conflict = await pending.route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({ operationId: 'refresh-conflict' }),
    }),
  );
  expect(conflict?.status).toBe(409);
  await expect(conflict?.json()).resolves.toMatchObject({
    ok: false,
    code: 'tenant_root_refresh_in_progress',
  });

  const invalid = await createRoute('OWNER', invalidRetryRouterRefreshResponse);
  const rejected = await invalid.route(
    new Request('https://console.test/console/tenant-root/refresh', {
      method: 'POST',
      body: JSON.stringify({ operationId: 'refresh-invalid-time' }),
    }),
  );
  expect(rejected?.status).toBe(502);
});
