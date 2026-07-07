import { test, expect } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleApprovalService,
  createInMemoryConsoleAuditService,
  createInMemoryConsoleAuditExportsService,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleEnterpriseIsolationService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleObservabilityService,
  createInMemoryConsoleKeyExportService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  type ConsoleApiKeyService,
  type ConsoleApprovalService,
  type ConsoleAuditService,
  type ConsoleAuditExportsService,
  type ConsoleAuthAdapter,
  type ConsoleBillingService,
  type ConsoleObservabilityService,
  type ConsoleEnterpriseIsolationService,
  type ConsoleObservabilityIngestionService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicyService,
  type ConsoleWallet,
  type ConsoleTeamRbacService,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@seams-internal/console-server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@seams-internal/console-server/router/cloudflare-adaptor';
import { callCf, fetchJson, getPath, startExpressRouter } from './helpers';
import type {
  PostgresTenantStorageRoute,
  TenantStorageRouteResolver,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { parseOrgId, type OrgId } from '../../packages/shared-ts/src/utils/domainIds';

function orgIdFromString(input: string): OrgId {
  const parsed = parseOrgId(input);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

const postgresTenantStorageRoute: PostgresTenantStorageRoute = {
  kind: 'postgres',
  namespace: 'seams',
  orgId: orgIdFromString('org-1'),
  routeVersion: 2,
  migrationReason: 'd1_size_limit',
  postgresRegion: 'wnam',
  postgresBackupRegion: 'enam',
  console: {
    kind: 'postgres',
    hyperdriveBindingName: 'SEAMS_POSTGRES',
    hyperdrive: { connectionString: 'postgres://example.invalid/seams' },
    postgresSchema: 'seams_console',
  },
  signer: {
    kind: 'postgres',
    hyperdriveBindingName: 'SEAMS_POSTGRES',
    hyperdrive: { connectionString: 'postgres://example.invalid/seams' },
    postgresSchema: 'seams_signer',
    kekProvider: {
      kind: 'worker_secret',
      workerSecretsByKekId: {
        'signing-root-kek-test-r1': 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      },
      encoding: 'base64url',
    },
  },
};

const postgresTenantStorageRouteResolver: TenantStorageRouteResolver = {
  resolveTenantStorageRoute(): PostgresTenantStorageRoute {
    return postgresTenantStorageRoute;
  },
};

function makeConsoleAuthAdapter(
  roles: string[],
  orgId = 'org-1',
  userId = 'user-1',
): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId,
        orgId,
        roles,
      },
    }),
  };
}

type EvmGasSponsorshipRulesFixtureInput = {
  readonly environmentId: string;
  readonly projectId: string | null;
  readonly chainId: number;
  readonly capMinor: number;
  readonly enabled: boolean;
};

const TEST_EVM_SPONSORSHIP_CONTRACT = '0x1111111111111111111111111111111111111111';

type ObservabilityIngestionEntry = {
  readonly ingestCtx: Record<string, unknown>;
  readonly event: Record<string, unknown>;
};

function evmGasSponsorshipRulesFixture(
  input: EvmGasSponsorshipRulesFixtureInput,
): Record<string, unknown> {
  return {
    kind: 'evm_call',
    executionMode: 'evm_eoa',
    scopeType: 'ENVIRONMENT',
    ...(input.projectId ? { projectId: input.projectId } : {}),
    environmentId: input.environmentId,
    enabled: input.enabled,
    allowedCalls: [
      {
        chainId: input.chainId,
        to: TEST_EVM_SPONSORSHIP_CONTRACT,
        functionSignature: 'sponsor(address,uint256)',
        maxGasLimit: '100000',
        maxValueWei: '0',
      },
    ],
    spendCap: {
      mode: 'CHAIN_TOTAL',
      period: 'MONTHLY',
      capsByChain: [{ chainId: input.chainId, capMinor: input.capMinor }],
    },
  };
}

function observabilityEventType(entry: ObservabilityIngestionEntry): string {
  return String(getPath(entry, 'event', 'eventType') || '');
}

function isPolicyObservabilityEventType(eventType: string): boolean {
  return eventType.startsWith('policy.');
}

function observabilityEventTypes(entries: readonly ObservabilityIngestionEntry[]): string[] {
  return entries.map(observabilityEventType);
}

function policyObservabilityEventTypes(entries: readonly ObservabilityIngestionEntry[]): string[] {
  return observabilityEventTypes(entries).filter(isPolicyObservabilityEventType);
}

function sortedWebhookDeliveryEventTypes(input: {
  readonly items: readonly { readonly eventType: string }[];
}): string[] {
  return input.items.map((entry) => entry.eventType).sort();
}

function makeObservabilityIngestionCollector(
  ingested: ObservabilityIngestionEntry[],
): ConsoleObservabilityIngestionService {
  const appendOne = async (
    ingestCtx: Parameters<ConsoleObservabilityIngestionService['appendEvent']>[0],
    event: Parameters<ConsoleObservabilityIngestionService['appendEvent']>[1],
  ) => {
    ingested.push({
      ingestCtx: ingestCtx as unknown as Record<string, unknown>,
      event: event as unknown as Record<string, unknown>,
    });
    return { accepted: 1, deduplicated: 0 };
  };

  return {
    appendEvent: appendOne,
    appendEvents: async (ingestCtx, events) => {
      for (const event of events) {
        ingested.push({
          ingestCtx: ingestCtx as unknown as Record<string, unknown>,
          event: event as unknown as Record<string, unknown>,
        });
      }
      return { accepted: events.length, deduplicated: 0 };
    },
  };
}

function makeObservabilityRequestRecorder(): {
  requests: Array<Record<string, unknown>>;
  service: ConsoleObservabilityService;
} {
  const requests: Array<Record<string, unknown>> = [];
  return {
    requests,
    service: {
      async getSummary() {
        return {
          generatedAt: new Date('2026-03-13T00:00:00.000Z').toISOString(),
          status: { state: 'ok' },
          errorRate: 0,
          p95LatencyMs: 0,
          failingServices: 0,
          deadLetterCount: 0,
        };
      },
      async listEvents(_ctx, request = {}) {
        requests.push({ ...request });
        return {
          status: { state: 'ok' },
          events: [],
          totalPages: 1,
        };
      },
      async getTimeseries() {
        return {
          status: { state: 'ok' },
          buckets: [],
        };
      },
      async listServices() {
        return {
          status: { state: 'ok' },
          services: [],
        };
      },
    },
  };
}

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

function makeSeedWallet(input: {
  id: string;
  orgId: string;
  projectId: string;
  environmentId: string;
}): ConsoleWallet {
  const ts = new Date().toISOString();
  return {
    id: input.id,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    userId: `user_${input.id}`,
    externalRefId: `ext_${input.id}`,
    address: `0x${input.id.padEnd(40, '0').slice(0, 40)}`,
    chain: 'Ethereum',
    walletType: 'EOA',
    status: 'ACTIVE',
    policyId: 'policy_default',
    balanceMinor: 0,
    lastActivityAt: null,
    createdAt: ts,
    updatedAt: ts,
  };
}

async function seedOrgProjectEnvironment(
  service: ConsoleOrgProjectEnvService,
  input: {
    orgId: string;
    projectId: string;
    actorUserId: string;
  },
): Promise<void> {
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: ['admin'],
  };
  await service.upsertOrganization(ctx, {
    name: 'Default Organization',
    slug: 'default-organization',
  });
  const existingProjects = await service.listProjects(ctx);
  if (existingProjects.some((entry) => entry.id === input.projectId)) return;
  await service.createProject(ctx, {
    id: input.projectId,
    name: 'Default Project',
    liveEnvironmentsEnabled: true,
  });
}

test.describe('console router (express)', () => {
  test('GET /console/healthz works and relay paths are isolated', async () => {
    const router = createConsoleRouter({ healthz: true });
    const srv = await startExpressRouter(router);
    try {
      const health = await fetchJson(`${srv.baseUrl}/console/healthz`, { method: 'GET' });
      expect(health.status).toBe(200);
      expect(health.json?.service).toBe('console');

      const relayPath = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(relayPath.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('webhooks_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('api_keys_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/org returns org_project_env_not_configured without org/project/env service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/org`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('org_project_env_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/members returns team_rbac_not_configured without Team RBAC service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/members`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('team_rbac_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/approvals returns approvals_not_configured without approvals service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/approvals`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('approvals_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/audit/events returns audit_not_configured without audit service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/audit/events`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('audit_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/audit/exports returns audit_exports_not_configured without export service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/audit/exports`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('audit_exports_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/summary returns observability_not_configured without service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/observability/summary`, {
        method: 'GET',
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('observability_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/* returns scaffolded responses when service is configured', async () => {
    const observability = createInMemoryConsoleObservabilityService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['support'],
        'org-observability-express',
        'user-observability-express',
      ),
      observability,
    });
    const srv = await startExpressRouter(router);
    try {
      const summary = await fetchJson(`${srv.baseUrl}/console/observability/summary`, {
        method: 'GET',
      });
      expect(summary.status).toBe(200);
      expect(getPath(summary.json, 'summary', 'status', 'state')).toBe('not_configured');

      const events = await fetchJson(`${srv.baseUrl}/console/observability/events?limit=5`, {
        method: 'GET',
      });
      expect(events.status).toBe(200);
      expect(getPath(events.json, 'status', 'state')).toBe('not_configured');
      expect(Array.isArray(events.json?.events)).toBe(true);
      expect(events.json?.totalPages).toBe(1);

      const timeseries = await fetchJson(
        `${srv.baseUrl}/console/observability/timeseries?bucketMinutes=5`,
        { method: 'GET' },
      );
      expect(timeseries.status).toBe(200);
      expect(getPath(timeseries.json, 'status', 'state')).toBe('not_configured');
      expect(Array.isArray(timeseries.json?.buckets)).toBe(true);

      const services = await fetchJson(`${srv.baseUrl}/console/observability/services?limit=10`, {
        method: 'GET',
      });
      expect(services.status).toBe(200);
      expect(getPath(services.json, 'status', 'state')).toBe('not_configured');
      expect(Array.isArray(services.json?.services)).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/* does not emit durable observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['support'],
        'org-observability-express-read-noise',
        'user-observability-express-read-noise',
      ),
      observability: createInMemoryConsoleObservabilityService(),
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });
    const srv = await startExpressRouter(router);
    try {
      const paths = [
        '/console/observability/summary',
        '/console/observability/events?limit=5',
        '/console/observability/timeseries?bucketMinutes=5',
        '/console/observability/services?limit=10',
      ];
      for (const path of paths) {
        const res = await fetchJson(`${srv.baseUrl}${path}`, { method: 'GET' });
        expect(res.status).toBe(200);
      }
      expect(ingested).toEqual([]);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/* requires observability read role', async () => {
    const observability = createInMemoryConsoleObservabilityService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-observability-express-forbidden',
        'user-observability-express-forbidden',
      ),
      observability,
    });
    const srv = await startExpressRouter(router);
    try {
      const paths = [
        '/console/observability/summary',
        '/console/observability/events',
        '/console/observability/timeseries',
        '/console/observability/services',
      ];
      for (const path of paths) {
        const res = await fetchJson(`${srv.baseUrl}${path}`, { method: 'GET' });
        expect(res.status).toBe(403);
        expect(res.json?.code).toBe('forbidden');
      }
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/events rejects query windows larger than 7 days', async () => {
    const observability = createInMemoryConsoleObservabilityService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-express-window',
        'user-observability-express-window',
      ),
      observability,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/observability/events?from=2026-01-01T00:00:00.000Z&to=2026-01-10T00:00:00.000Z`,
        { method: 'GET' },
      );
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/observability/events forwards component and query filters to observability service', async () => {
    const recorder = makeObservabilityRequestRecorder();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-express-component',
        'user-observability-express-component',
      ),
      observability: recorder.service,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/observability/events?query=invoice&level=ERROR&service=billing&component=checkout_reconcile&eventType=billing.payment_reconcile.failed&from=2026-03-12T00:00:00.000Z&to=2026-03-13T00:00:00.000Z&limit=25`,
        { method: 'GET' },
      );
      expect(res.status).toBe(200);
      expect(recorder.requests).toHaveLength(1);
      expect(recorder.requests[0]).toMatchObject({
        query: 'invoice',
        level: 'ERROR',
        service: 'billing',
        component: 'checkout_reconcile',
        eventType: 'billing.payment_reconcile.failed',
        from: '2026-03-12T00:00:00.000Z',
        to: '2026-03-13T00:00:00.000Z',
        limit: 25,
      });
    } finally {
      await srv.close();
    }
  });

  test('policy publish failures emit approval observability events (express)', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const basePolicies = createInMemoryConsolePolicyService();
    const failingPolicies: ConsolePolicyService = {
      ...basePolicies,
      publishPolicy: async () => {
        throw new Error('policy publish failed');
      },
    };
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-express-failure',
        'user-observability-express-failure',
      ),
      policies: failingPolicies,
      observabilityIngestion,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/policies/pol_obs_failure/publish`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-request-id': 'req_obs_policy_publish',
        },
        body: JSON.stringify({ approvalId: 'apr_obs_failure' }),
      });
      expect(res.status).toBe(500);
      expect(res.json?.code).toBe('internal');

      await expect
        .poll(
          () =>
            ingested.filter((entry) => entry.event.eventType === 'approval.policy_publish.failed')
              .length,
        )
        .toBe(1);
      const approvalFailure = ingested.find(
        (entry) => entry.event.eventType === 'approval.policy_publish.failed',
      );
      expect(approvalFailure).toBeTruthy();
      expect(String(getPath(approvalFailure?.event || null, 'metadata', 'resourceId') || '')).toBe(
        'pol_obs_failure',
      );
      expect(String(getPath(approvalFailure?.event || null, 'metadata', 'approvalId') || '')).toBe(
        'apr_obs_failure',
      );
      expect(String((approvalFailure?.event?.requestId as string) || '')).toBe(
        'req_obs_policy_publish',
      );
    } finally {
      await srv.close();
    }
  });

  test('billing document finalization failures emit billing observability events (express)', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      generateMonthlyInvoice: async () => {
        throw new Error('invoice generation failed');
      },
    };
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-express-billing',
        'user-observability-express-billing',
      ),
      billing: failingBilling,
      observabilityIngestion,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-request-id': 'req_obs_billing_finalize',
        },
        body: JSON.stringify({ periodMonthUtc: '2026-03' }),
      });
      expect(res.status).toBe(500);
      expect(res.json?.code).toBe('internal');

      await expect
        .poll(
          () =>
            ingested.filter(
              (entry) => entry.event.eventType === 'billing.invoice_finalization.failed',
            ).length,
        )
        .toBe(1);

      const billingFailure = ingested.find(
        (entry) => entry.event.eventType === 'billing.invoice_finalization.failed',
      );
      expect(billingFailure).toBeTruthy();
      expect(String(getPath(billingFailure?.event || null, 'metadata', 'invoiceId') || '')).toBe(
        'monthly:2026-03',
      );
      expect(String((billingFailure?.event?.requestId as string) || '')).toBe(
        'req_obs_billing_finalize',
      );
    } finally {
      await srv.close();
    }
  });

  test('billing checkout reconcile failures emit payment reconcile observability events (express)', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      reconcileStripeCheckoutSession: async () => {
        throw new Error('checkout reconcile failed');
      },
    };
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-express-reconcile',
        'user-observability-express-reconcile',
      ),
      billing: failingBilling,
      observabilityIngestion,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session/reconcile`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-request-id': 'req_obs_billing_reconcile',
          },
          body: JSON.stringify({ checkoutSessionId: 'cs_obs_billing_reconcile' }),
        },
      );
      expect(res.status).toBe(500);
      expect(res.json?.code).toBe('internal');

      await expect
        .poll(
          () =>
            ingested.filter((entry) => entry.event.eventType === 'billing.payment_reconcile.failed')
              .length,
        )
        .toBe(1);

      const billingFailure = ingested.find(
        (entry) => entry.event.eventType === 'billing.payment_reconcile.failed',
      );
      expect(billingFailure).toBeTruthy();
      expect(String(getPath(billingFailure?.event || null, 'metadata', 'operation') || '')).toBe(
        'PAYMENT_RECONCILE',
      );
      expect(String(getPath(billingFailure?.event || null, 'metadata', 'providerRef') || '')).toBe(
        'cs_obs_billing_reconcile',
      );
      expect(String((billingFailure?.event?.requestId as string) || '')).toBe(
        'req_obs_billing_reconcile',
      );
    } finally {
      await srv.close();
    }
  });

  test('invalid Stripe webhook secrets emit invalid signature observability events (express)', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const router = createConsoleRouter({
      billing: createInMemoryConsoleBillingService(),
      billingStripeWebhookSecret: 'whsec_expected_express',
      observabilityIngestion,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': 'whsec_wrong_express',
          'x-request-id': 'req_obs_stripe_invalid_signature',
        },
        body: JSON.stringify({
          eventId: 'evt_obs_invalid_signature',
          eventType: 'checkout.session.completed',
          orgId: 'org-observability-express-webhook-invalid',
          checkoutSessionId: 'cs_obs_invalid_signature',
          providerRef: 'cs_obs_invalid_signature',
        }),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('unauthorized');

      await expect
        .poll(
          () =>
            ingested.filter(
              (entry) => entry.event.eventType === 'billing.stripe_webhook.invalid_signature',
            ).length,
        )
        .toBe(1);

      const webhookFailure = ingested.find(
        (entry) => entry.event.eventType === 'billing.stripe_webhook.invalid_signature',
      );
      expect(webhookFailure).toBeTruthy();
      expect(String(webhookFailure?.event?.orgId || '')).toBe(
        'org-observability-express-webhook-invalid',
      );
      expect(
        String(getPath(webhookFailure?.event || null, 'metadata', 'stripeEventId') || ''),
      ).toBe('evt_obs_invalid_signature');
      expect(String(getPath(webhookFailure?.event || null, 'metadata', 'providerRef') || '')).toBe(
        'cs_obs_invalid_signature',
      );
      expect(String((webhookFailure?.event?.requestId as string) || '')).toBe(
        'req_obs_stripe_invalid_signature',
      );
    } finally {
      await srv.close();
    }
  });

  test('Stripe webhook processing failures emit processing observability events (express)', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      processStripeWebhookEvent: async () => {
        throw new Error('stripe webhook processing failed');
      },
    };
    const router = createConsoleRouter({
      billing: failingBilling,
      billingStripeWebhookSecret: 'whsec_expected_processing_express',
      observabilityIngestion,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': 'whsec_expected_processing_express',
          'x-request-id': 'req_obs_stripe_processing',
        },
        body: JSON.stringify({
          eventId: 'evt_obs_processing_failed',
          eventType: 'checkout.session.completed',
          orgId: 'org-observability-express-webhook-processing',
          checkoutSessionId: 'cs_obs_processing_failed',
          providerRef: 'cs_obs_processing_failed',
        }),
      });
      expect(res.status).toBe(500);
      expect(res.json?.code).toBe('internal');

      await expect
        .poll(
          () =>
            ingested.filter(
              (entry) => entry.event.eventType === 'billing.stripe_webhook.processing.failed',
            ).length,
        )
        .toBe(1);

      const webhookFailure = ingested.find(
        (entry) => entry.event.eventType === 'billing.stripe_webhook.processing.failed',
      );
      expect(webhookFailure).toBeTruthy();
      expect(String(webhookFailure?.event?.orgId || '')).toBe(
        'org-observability-express-webhook-processing',
      );
      expect(String(getPath(webhookFailure?.event || null, 'metadata', 'failureCode') || '')).toBe(
        'internal',
      );
      expect(
        String(getPath(webhookFailure?.event || null, 'metadata', 'checkoutSessionId') || ''),
      ).toBe('cs_obs_processing_failed');
      expect(String((webhookFailure?.event?.requestId as string) || '')).toBe(
        'req_obs_stripe_processing',
      );
    } finally {
      await srv.close();
    }
  });

  test('GET /console/isolation/status returns enterprise_isolation_not_configured without service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/isolation/status`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('enterprise_isolation_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/onboarding/state and telemetry return onboarding_not_configured without onboarding service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/onboarding/state`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('onboarding_not_configured');

      const telemetry = await fetchJson(`${srv.baseUrl}/console/onboarding/telemetry`, {
        method: 'GET',
      });
      expect(telemetry.status).toBe(501);
      expect(telemetry.json?.code).toBe('onboarding_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/onboarding/telemetry requires admin or ops role', async () => {
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-onboarding-telemetry-role',
        'user-onboarding-telemetry-role',
      ),
      onboarding,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/onboarding/telemetry`, {
        method: 'GET',
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/onboarding/telemetry validates windowMinutes query', async () => {
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-telemetry-query',
        'user-onboarding-telemetry-query',
      ),
      onboarding,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/onboarding/telemetry?windowMinutes=0`, {
        method: 'GET',
      });
      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/ops-cockpit/summary aggregates operator queues', async () => {
    const orgId = 'org-ops-cockpit-summary-express';
    const actorUserId = 'user-ops-cockpit-summary-express';
    const roles = ['admin'];
    const serviceCtx = { orgId, actorUserId, roles };

    const approvals = createInMemoryConsoleApprovalService();
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        async dispatch() {
          return {
            ok: false,
            statusCode: 500,
            errorMessage: 'mock dispatch failure',
          };
        },
      },
    });
    const auditExports = createInMemoryConsoleAuditExportsService();
    const enterpriseIsolation = createInMemoryConsoleEnterpriseIsolationService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing,
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });

    await approvals.createApprovalRequest(serviceCtx, {
      operationType: 'KEY_EXPORT',
      reason: 'Operator approval pending',
    });
    const generatedInvoice = await billing.generateMonthlyInvoice(serviceCtx, {
      periodMonthUtc: '2026-03',
    });
    await billing.processStripeWebhookEvent({
      eventId: 'evt_ops_cockpit_express_invoice_failed',
      orgId,
      eventType: 'invoice.payment_failed',
      invoiceId: generatedInvoice.invoice.id,
      invoiceStatus: 'UNCOLLECTIBLE',
    } as any);
    await auditExports.createExport(serviceCtx, { format: 'JSONL' });
    await enterpriseIsolation.triggerIsolation(serviceCtx, {
      scope: 'ORG',
      trigger: 'SLA_BREACH',
      reason: 'SLA breach',
    });
    const endpoint = await webhooks.createEndpoint(serviceCtx, {
      url: 'https://example.com/ops-cockpit-webhook',
      eventCategories: ['billing'],
    });
    await webhooks.emitEvent(serviceCtx, {
      eventType: 'billing.invoice.payment_failed',
      payload: { invoiceId: generatedInvoice.invoice.id, endpointId: endpoint.id },
    });

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(roles, orgId, actorUserId),
      approvals,
      billing,
      webhooks,
      auditExports,
      enterpriseIsolation,
      onboarding,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/ops-cockpit/summary?windowMinutes=60`, {
        method: 'GET',
      });
      expect(res.status).toBe(200);
      expect(getPath(res.json, 'summary', 'approvals', 'pendingCount')).toBe(1);
      expect(getPath(res.json, 'summary', 'billing', 'failedInvoiceCount')).toBe(0);
      expect(getPath(res.json, 'summary', 'webhooks', 'deadLetterCount')).toBe(1);
      expect(getPath(res.json, 'summary', 'auditExports', 'queuedExportCount')).toBe(1);
      expect(getPath(res.json, 'summary', 'enterpriseIsolation', 'activeRequestCount')).toBe(1);
      expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'state')).toBe('ok');
      expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'windowMinutes')).toBe(60);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/ops-cockpit/summary is partial for non-ops telemetry viewers', async () => {
    const orgId = 'org-ops-cockpit-summary-role-express';
    const actorUserId = 'user-ops-cockpit-summary-role-express';
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['security_admin'], orgId, actorUserId),
      onboarding,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/ops-cockpit/summary`, {
        method: 'GET',
      });
      expect(res.status).toBe(200);
      expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'state')).toBe(
        'forbidden',
      );
      expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'code')).toBe(
        'forbidden',
      );
    } finally {
      await srv.close();
    }
  });

  test('GET /console/ops-cockpit/summary requires ops cockpit read role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-ops-cockpit-summary-forbidden-express',
        'user-ops-cockpit-summary-forbidden-express',
      ),
      onboarding: createInMemoryConsoleOnboardingService({
        orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
        apiKeys: createInMemoryConsoleApiKeyService(),
        billing: createInMemoryConsoleBillingService(),
        teamRbac: createInMemoryConsoleTeamRbacService(),
      }),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/ops-cockpit/summary`, {
        method: 'GET',
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('onboarding organization and project steps are idempotent and auditable', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const billing = createInMemoryConsoleBillingService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      billing,
      teamRbac,
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-onboarding-1', 'user-onboarding-1'),
      onboarding,
      billing,
      teamRbac,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const before = await fetchJson(`${srv.baseUrl}/console/onboarding/state`, { method: 'GET' });
      expect(before.status).toBe(200);
      expect(getPath(before.json, 'state', 'hasApiKey')).toBe(false);
      expect(getPath(before.json, 'state', 'complete')).toBe(false);
      expect(getPath(before.json, 'state', 'accountReady')).toBe(true);
      expect(getPath(before.json, 'state', 'organizationReady')).toBe(false);
      expect(getPath(before.json, 'state', 'billingReady')).toBe(false);
      expect(getPath(before.json, 'state', 'projectReady')).toBe(false);
      expect(getPath(before.json, 'state', 'onboardingComplete')).toBe(false);
      expect(getPath(before.json, 'state', 'currentStep')).toBe('organization');

      const organization = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Acme Org', slug: 'acme-org' },
        }),
      });
      expect(organization.status).toBe(201);
      expect(getPath(organization.json, 'result', 'created', 'organization')).toBe(true);
      expect(getPath(organization.json, 'result', 'created', 'owner')).toBe(true);
      expect(getPath(organization.json, 'result', 'state', 'organizationReady')).toBe(true);
      expect(getPath(organization.json, 'result', 'state', 'currentStep')).toBe('project');

      const project = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_onboarding', name: 'Onboarding Project' },
          environment: {
            id: 'proj_onboarding-dev',
            name: 'Development',
          },
        }),
      });
      expect(project.status).toBe(201);
      expect(String(getPath(project.json, 'result', 'project', 'id'))).toBe('proj_onboarding');
      expect(String(getPath(project.json, 'result', 'environment', 'id'))).toBe(
        'proj_onboarding:dev',
      );
      expect(getPath(project.json, 'result', 'created', 'project')).toBe(true);
      expect(getPath(project.json, 'result', 'created', 'environment')).toBe(false);

      const after = await fetchJson(`${srv.baseUrl}/console/onboarding/state`, { method: 'GET' });
      expect(after.status).toBe(200);
      expect(getPath(after.json, 'state', 'hasApiKey')).toBe(false);
      expect(getPath(after.json, 'state', 'complete')).toBe(false);
      expect(getPath(after.json, 'state', 'organizationReady')).toBe(true);
      expect(getPath(after.json, 'state', 'projectReady')).toBe(true);
      expect(getPath(after.json, 'state', 'billingReady')).toBe(false);
      expect(getPath(after.json, 'state', 'onboardingComplete')).toBe(true);
      expect(getPath(after.json, 'state', 'currentStep')).toBe('complete');

      const auditEvents = await fetchJson(`${srv.baseUrl}/console/audit/events?limit=20`, {
        method: 'GET',
      });
      expect(auditEvents.status).toBe(200);
      const rows = Array.isArray(auditEvents.json?.events) ? auditEvents.json?.events : [];
      const actions = rows.map((row: any) => String(row?.action || ''));
      expect(actions).toContain('member.owner.bootstrap');
      expect(actions).toContain('organization.configure');
      expect(actions).toContain('project.create');
      expect(actions).not.toContain('environment.create');
      expect(actions).not.toContain('api_key.create');

      const members = await fetchJson(`${srv.baseUrl}/console/members?status=ACTIVE`, {
        method: 'GET',
      });
      expect(members.status).toBe(200);
      const memberRows = Array.isArray(members.json?.members) ? members.json?.members : [];
      const actorMember = memberRows.find(
        (entry: any) => String(entry?.userId || '') === 'user-onboarding-1',
      );
      expect(actorMember).toBeTruthy();
      const actorRoles = Array.isArray(actorMember?.roles) ? actorMember.roles : [];
      expect(
        actorRoles.some(
          (entry: any) =>
            String(entry?.scope || '').toUpperCase() === 'ORG' &&
            String(entry?.role || '').toLowerCase() === 'owner',
        ),
      ).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('onboarding organization step configures org profile and is idempotent', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      teamRbac,
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-org-step',
        'user-onboarding-org-step',
      ),
      onboarding,
      teamRbac,
    });
    const srv = await startExpressRouter(router);
    try {
      const before = await fetchJson(`${srv.baseUrl}/console/onboarding/state`, { method: 'GET' });
      expect(before.status).toBe(200);
      expect(getPath(before.json, 'state', 'organizationReady')).toBe(false);
      expect(getPath(before.json, 'state', 'currentStep')).toBe('organization');

      const first = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Acme Org', slug: 'acme-org' },
        }),
      });
      expect(first.status).toBe(201);
      expect(getPath(first.json, 'result', 'organization', 'id')).toBe('org-onboarding-org-step');
      expect(getPath(first.json, 'result', 'organization', 'name')).toBe('Acme Org');
      expect(getPath(first.json, 'result', 'organization', 'slug')).toBe('acme-org');
      expect(getPath(first.json, 'result', 'created', 'organization')).toBe(true);
      expect(getPath(first.json, 'result', 'state', 'organizationReady')).toBe(true);
      expect(getPath(first.json, 'result', 'state', 'currentStep')).toBe('project');

      const second = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Acme Org Updated', slug: 'acme-org-updated' },
        }),
      });
      expect(second.status).toBe(200);
      expect(getPath(second.json, 'result', 'organization', 'name')).toBe('Acme Org Updated');
      expect(getPath(second.json, 'result', 'organization', 'slug')).toBe('acme-org-updated');
      expect(getPath(second.json, 'result', 'created', 'organization')).toBe(false);
    } finally {
      await srv.close();
    }
  });

  test('onboarding project step creates default development environment without billing', async () => {
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
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-project-step',
        'user-onboarding-project-step',
      ),
      onboarding,
      billing,
      teamRbac,
    });
    const srv = await startExpressRouter(router);
    try {
      const blockedByOrganization = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_step', name: 'Step Project' },
        }),
      });
      expect(blockedByOrganization.status).toBe(409);
      expect(blockedByOrganization.json?.code).toBe('organization_required');

      const organization = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Step Org', slug: 'step-org' },
        }),
      });
      expect(organization.status).toBe(201);

      const created = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_step', name: 'Step Project' },
        }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'result', 'project', 'id')).toBe('proj_step');
      expect(getPath(created.json, 'result', 'environment', 'key')).toBe('dev');
      expect(getPath(created.json, 'result', 'created', 'project')).toBe(true);
      expect(getPath(created.json, 'result', 'created', 'environment')).toBe(false);
      expect(getPath(created.json, 'result', 'state', 'billingReady')).toBe(false);
      expect(getPath(created.json, 'result', 'state', 'projectReady')).toBe(true);
      expect(getPath(created.json, 'result', 'state', 'onboardingComplete')).toBe(true);
      expect(getPath(created.json, 'result', 'state', 'currentStep')).toBe('complete');

      const replay = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_step', name: 'Step Project' },
        }),
      });
      expect(replay.status).toBe(200);
      expect(getPath(replay.json, 'result', 'created', 'project')).toBe(false);
      expect(getPath(replay.json, 'result', 'created', 'environment')).toBe(false);

      const telemetry = await fetchJson(
        `${srv.baseUrl}/console/onboarding/telemetry?windowMinutes=60`,
        { method: 'GET' },
      );
      expect(telemetry.status).toBe(200);
      expect(getPath(telemetry.json, 'telemetry', 'windowMinutes')).toBe(60);
      const operations = Array.isArray(getPath(telemetry.json, 'telemetry', 'operations'))
        ? (getPath(telemetry.json, 'telemetry', 'operations') as any[])
        : [];
      const projectOperation = operations.find(
        (entry) => String(entry?.operation || '') === 'project',
      );
      expect(projectOperation).toBeTruthy();
      expect(Number(getPath(projectOperation, 'requestCount') || 0)).toBeGreaterThanOrEqual(3);
      expect(Number(getPath(projectOperation, 'errorCount') || 0)).toBeGreaterThanOrEqual(1);
      const alerts = Array.isArray(getPath(telemetry.json, 'telemetry', 'alerts'))
        ? (getPath(telemetry.json, 'telemetry', 'alerts') as any[])
        : [];
      expect(
        alerts.some(
          (entry) =>
            String(entry?.operation || '') === 'project' &&
            String(entry?.code || '') === 'onboarding_error_rate_slo_breached',
        ),
      ).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects allows creation without billing method', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-project-billing-gate',
        actorUserId: 'user-project-billing-gate',
        roles: ['admin'],
      },
      { name: 'Project Billing Gate Org', slug: 'project-billing-gate-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-project-billing-gate',
        'user-project-billing-gate',
      ),
      orgProjectEnv,
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 'proj_gated', name: 'Gated Project' }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'project', 'id')).toBe('proj_gated');
      expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects auto-provisions environments with live environments disabled without billing readiness', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-gate',
        actorUserId: 'user-env-billing-gate',
        roles: ['admin'],
      },
      { name: 'Environment Billing Gate Org', slug: 'environment-billing-gate-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-env-billing-gate', 'user-env-billing-gate'),
      orgProjectEnv,
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 'proj_env_gated', name: 'Env Gated Project' }),
      });
      expect(created.status).toBe(201);
      expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent('proj_env_gated')}`,
        {
          method: 'GET',
        },
      );
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
      expect(rows.length).toBe(3);
      const statusByKey = new Map<string, string>(
        rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
      );
      expect(statusByKey.get('dev')).toBe('ACTIVE');
      expect(statusByKey.get('staging')).toBe('DISABLED');
      expect(statusByKey.get('prod')).toBe('DISABLED');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects enables live environments when billing is ready', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-project-live-billing-ready',
        actorUserId: 'user-project-live-billing-ready',
        roles: ['admin'],
      },
      { name: 'Project Billing Ready Org', slug: 'project-billing-ready-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-project-live-billing-ready',
        'user-project-live-billing-ready',
      ),
      orgProjectEnv,
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const checkoutSession = await billing.createStripeCheckoutSession(
        {
          orgId: 'org-project-live-billing-ready',
          actorUserId: 'user-project-live-billing-ready',
          roles: ['admin'],
        },
        {
          successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
          cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
          creditPackId: 'usd_25',
        },
      );
      const settle = await billing.processStripeWebhookEvent({
        eventId: `evt_project_live_ready_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        eventType: 'checkout.session.completed',
        orgId: 'org-project-live-billing-ready',
        checkoutSessionId: checkoutSession.id,
        providerCustomerRef: checkoutSession.customerRef,
        providerRef: checkoutSession.id,
      });
      expect(settle.accepted).toBe(true);

      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 'proj_live_ready', name: 'Live Ready Project' }),
      });
      expect(created.status).toBe(201);
      expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent('proj_live_ready')}`,
        {
          method: 'GET',
        },
      );
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
      expect(rows.length).toBe(3);
      const statusByKey = new Map<string, string>(
        rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
      );
      expect(statusByKey.get('dev')).toBe('ACTIVE');
      expect(statusByKey.get('staging')).toBe('ACTIVE');
      expect(statusByKey.get('prod')).toBe('ACTIVE');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects keeps live environments disabled when billing service is not configured', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-no-billing-service',
        actorUserId: 'user-env-no-billing-service',
        roles: ['admin'],
      },
      { name: 'No Billing Service Org', slug: 'no-billing-service-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-no-billing-service',
        'user-env-no-billing-service',
      ),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'proj_env_no_billing_service',
          name: 'No Billing Service Project',
        }),
      });
      expect(created.status).toBe(201);
      expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent('proj_env_no_billing_service')}`,
        {
          method: 'GET',
        },
      );
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
      expect(rows.length).toBe(3);
      const statusByKey = new Map<string, string>(
        rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
      );
      expect(statusByKey.get('dev')).toBe('ACTIVE');
      expect(statusByKey.get('staging')).toBe('DISABLED');
      expect(statusByKey.get('prod')).toBe('DISABLED');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects enables live environments when billing bypass is explicitly enabled', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-bypass',
        actorUserId: 'user-env-billing-bypass',
        roles: ['admin'],
      },
      { name: 'Billing Bypass Org', slug: 'billing-bypass-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-env-billing-bypass', 'user-env-billing-bypass'),
      orgProjectEnv,
      allowLiveEnvironmentBillingBypass: true,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'proj_env_billing_bypass',
          name: 'Billing Bypass Project',
        }),
      });
      expect(created.status).toBe(201);
      expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent('proj_env_billing_bypass')}`,
        {
          method: 'GET',
        },
      );
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
      expect(rows.length).toBe(3);
      const statusByKey = new Map<string, string>(
        rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
      );
      expect(statusByKey.get('dev')).toBe('ACTIVE');
      expect(statusByKey.get('staging')).toBe('ACTIVE');
      expect(statusByKey.get('prod')).toBe('ACTIVE');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/environments skips billing gate when bypass is explicitly enabled', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-bypass-gate',
        actorUserId: 'user-env-billing-bypass-gate',
        roles: ['admin'],
      },
      { name: 'Billing Bypass Gate Org', slug: 'billing-bypass-gate-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-billing-bypass-gate',
        'user-env-billing-bypass-gate',
      ),
      orgProjectEnv,
      allowLiveEnvironmentBillingBypass: true,
    });
    const srv = await startExpressRouter(router);
    try {
      const response = await fetchJson(`${srv.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'env_billing_bypass_staging',
          projectId: 'project_missing_for_bypass_gate_test',
          key: 'staging',
          name: 'Staging',
        }),
      });
      expect(response.status).toBe(404);
      expect(response.json?.code).toBe('project_not_found');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/environments blocks staging/prod when billing service is not configured', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-no-billing-service-gate',
        actorUserId: 'user-env-no-billing-service-gate',
        roles: ['admin'],
      },
      { name: 'No Billing Service Gate Org', slug: 'no-billing-service-gate-org' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-no-billing-service-gate',
        'user-env-no-billing-service-gate',
      ),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const blockedStaging = await fetchJson(`${srv.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'env_no_billing_service_gated_staging',
          projectId: 'project_missing_for_gate_test',
          key: 'staging',
          name: 'Staging',
        }),
      });
      expect(blockedStaging.status).toBe(409);
      expect(blockedStaging.json?.code).toBe('billing_required_live_environment');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/projects keeps live environments enabled when prepaid balance is low but positive', async () => {
    const billing = createInMemoryConsoleBillingService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const claims = {
      orgId: 'org-env-low-balance-live-enabled',
      actorUserId: 'user-env-low-balance-live-enabled',
      roles: ['platform_admin'],
    };
    await orgProjectEnv.upsertOrganization(claims, {
      name: 'Low Balance Live Enabled Org',
      slug: 'low-balance-live-enabled-org',
    });
    await billing.grantManualSupportCredit(claims, {
      amountMinor: 1500,
      reasonCode: 'bootstrap_credit',
      note: 'Seed low but positive prepaid balance',
      idempotencyKey: 'router-live-enabled-low-balance',
    });

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-low-balance-live-enabled',
        'user-env-low-balance-live-enabled',
      ),
      billing,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'proj_env_low_balance_live_enabled',
          name: 'Low Balance Project',
        }),
      });
      expect(created.status).toBe(201);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent('proj_env_low_balance_live_enabled')}`,
        {
          method: 'GET',
        },
      );
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
      const statusByKey = new Map<string, string>(
        rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
      );
      expect(statusByKey.get('staging')).toBe('ACTIVE');
      expect(statusByKey.get('prod')).toBe('ACTIVE');
    } finally {
      await srv.close();
    }
  });

  test('audit routes return seeded timeline and evidence rows', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-1', 'user-audit-admin'),
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const events = await fetchJson(
        `${srv.baseUrl}/console/audit/events?category=POLICY&limit=5`,
        { method: 'GET' },
      );
      expect(events.status).toBe(200);
      const eventRows = Array.isArray(events.json?.events) ? events.json?.events : [];
      expect(eventRows.length).toBeGreaterThan(0);
      expect(String(getPath(eventRows[0], 'category'))).toBe('POLICY');

      const evidence = await fetchJson(
        `${srv.baseUrl}/console/audit/evidence?domain=BILLING&limit=5`,
        { method: 'GET' },
      );
      expect(evidence.status).toBe(200);
      const evidenceRows = Array.isArray(evidence.json?.evidence) ? evidence.json?.evidence : [];
      expect(evidenceRows.length).toBeGreaterThan(0);
      expect(String(getPath(evidenceRows[0], 'domain'))).toBe('BILLING');
    } finally {
      await srv.close();
    }
  });

  test('audit read routes require audit read role', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const auditExports: ConsoleAuditExportsService = createInMemoryConsoleAuditExportsService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-audit-read-role-1',
        'user-audit-read-role-1',
      ),
      audit,
      auditExports,
    });
    const srv = await startExpressRouter(router);
    try {
      for (const path of [
        '/console/audit/events?limit=5',
        '/console/audit/evidence?limit=5',
        '/console/audit/exports',
        '/console/audit/exports/aexp_missing',
      ]) {
        const res = await fetchJson(`${srv.baseUrl}${path}`, { method: 'GET' });
        expect(res.status, path).toBe(403);
        expect(res.json?.code, path).toBe('forbidden');
      }
    } finally {
      await srv.close();
    }
  });

  test('in-memory audit service filters events by free-text query', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const rows = await audit.listEvents(
      {
        orgId: 'org-audit-search-1',
        actorUserId: 'user-audit-search-admin',
        roles: ['admin'],
      },
      { q: 'pi_demo_01', limit: 20 },
    );
    expect(rows.length).toBe(1);
    expect(String(getPath(rows[0] as any, 'metadata', 'paymentIntentId'))).toBe('pi_demo_01');
  });

  test('approval creation emits audit timeline events', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const approvals: ConsoleApprovalService = createInMemoryConsoleApprovalService();
    const policies: ConsolePolicyService = createInMemoryConsolePolicyService();
    const policyCtx = {
      orgId: 'org-audit-live-1',
      actorUserId: 'user-audit-live-admin',
      roles: ['admin'],
    };
    const gasPolicy = await policies.createPolicy(policyCtx, {
      kind: 'GAS_SPONSORSHIP',
      name: 'Gas publish policy',
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-live-1', 'user-audit-live-admin'),
      approvals,
      audit,
      policies,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'apr_audit_live_1',
          operationType: 'POLICY_PUBLISH',
          reason: 'Publish policy v2',
          resourceType: 'policy',
          resourceId: gasPolicy.id,
        }),
      });
      expect(created.status).toBe(201);
      expect(String(getPath(created.json, 'approval', 'policyId') || '')).toBe(gasPolicy.id);
      expect(String(getPath(created.json, 'approval', 'policyName') || '')).toBe(
        'Gas publish policy',
      );
      expect(String(getPath(created.json, 'approval', 'policyKind') || '')).toBe('GAS_SPONSORSHIP');

      const events = await fetchJson(
        `${srv.baseUrl}/console/audit/events?category=APPROVAL&limit=20`,
        {
          method: 'GET',
        },
      );
      expect(events.status).toBe(200);
      const eventRows = Array.isArray(events.json?.events) ? events.json?.events : [];
      const createdEvent = eventRows.find(
        (row: any) => String(row?.action || '') === 'approval.request.create',
      );
      expect(createdEvent).toBeTruthy();
      expect(String(getPath(createdEvent, 'policyId') || '')).toBe(gasPolicy.id);
      expect(String(getPath(createdEvent, 'policyName') || '')).toBe('Gas publish policy');
      expect(String(getPath(createdEvent, 'policyKind') || '')).toBe('GAS_SPONSORSHIP');
      expect(String(getPath(createdEvent, 'metadata', 'approvalId'))).toBe('apr_audit_live_1');
      expect(String(getPath(createdEvent, 'metadata', 'resourceId'))).toBe(gasPolicy.id);
      expect(String(getPath(createdEvent, 'metadata', 'policyId'))).toBe(gasPolicy.id);
      expect(String(getPath(createdEvent, 'metadata', 'policyKind'))).toBe('GAS_SPONSORSHIP');
    } finally {
      await srv.close();
    }
  });

  test('audit export and enterprise isolation routes support scaffold flows', async () => {
    const auditExports: ConsoleAuditExportsService = createInMemoryConsoleAuditExportsService();
    const enterpriseIsolation: ConsoleEnterpriseIsolationService =
      createInMemoryConsoleEnterpriseIsolationService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-export-1', 'user-audit-export-admin'),
      auditExports,
      enterpriseIsolation,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdExport = await fetchJson(`${srv.baseUrl}/console/audit/exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'aexp_scaffold_1',
          format: 'JSONL',
          domain: 'POLICY',
          projectId: 'proj_scaffold_1',
          environmentId: 'env_scaffold_1',
        }),
      });
      expect(createdExport.status).toBe(201);
      expect(String(getPath(createdExport.json, 'export', 'status') || '')).toBe('QUEUED');

      const listExports = await fetchJson(`${srv.baseUrl}/console/audit/exports?domain=POLICY`, {
        method: 'GET',
      });
      expect(listExports.status).toBe(200);
      const exportRows = Array.isArray(listExports.json?.exports) ? listExports.json?.exports : [];
      expect(exportRows.some((entry: any) => String(entry?.id || '') === 'aexp_scaffold_1')).toBe(
        true,
      );

      const getExport = await fetchJson(
        `${srv.baseUrl}/console/audit/exports/${encodeURIComponent('aexp_scaffold_1')}`,
        { method: 'GET' },
      );
      expect(getExport.status).toBe(200);
      expect(String(getPath(getExport.json, 'export', 'id') || '')).toBe('aexp_scaffold_1');

      const initialIsolation = await fetchJson(
        `${srv.baseUrl}/console/isolation/status?scope=ORG`,
        { method: 'GET' },
      );
      expect(initialIsolation.status).toBe(200);
      expect(String(getPath(initialIsolation.json, 'isolation', 'status') || '')).toBe('SHARED');

      const triggerIsolation = await fetchJson(`${srv.baseUrl}/console/isolation/trigger`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope: 'ORG',
          trigger: 'COMPLIANCE',
          reason: 'Enterprise compliance requirement',
          ticketId: 'INC-42',
        }),
      });
      expect(triggerIsolation.status).toBe(202);
      expect(String(getPath(triggerIsolation.json, 'isolation', 'status') || '')).toBe('REQUESTED');
      expect(String(getPath(triggerIsolation.json, 'isolation', 'mode') || '')).toBe('DEDICATED');
    } finally {
      await srv.close();
    }
  });

  test('team member routes enforce role scope validation and mutation RBAC', async () => {
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-team-1', 'user-team-admin-1'),
      teamRbac,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const initial = await fetchJson(`${adminServer.baseUrl}/console/members`, { method: 'GET' });
      expect(initial.status).toBe(200);
      const initialRows = Array.isArray(initial.json?.members) ? initial.json?.members : [];
      expect(initialRows.length).toBeGreaterThanOrEqual(1);

      const invited = await fetchJson(`${adminServer.baseUrl}/console/members/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: 'member-team-1-user',
          email: 'dev1@example.com',
          roles: [{ role: 'admin_manage_members' }, { role: 'wallet_operations_write' }],
        }),
      });
      expect(invited.status).toBe(201);
      const invitedMemberId = String(getPath(invited.json, 'member', 'id') || '');
      expect(invitedMemberId).toContain('mbr_');
      expect(getPath(invited.json, 'member', 'status')).toBe('ACTIVE');

      const invitedOnly = await fetchJson(`${adminServer.baseUrl}/console/members?status=ACTIVE`, {
        method: 'GET',
      });
      expect(invitedOnly.status).toBe(200);
      const invitedRows = Array.isArray(invitedOnly.json?.members) ? invitedOnly.json?.members : [];
      expect(invitedRows.some((entry: any) => String(entry?.id || '') === invitedMemberId)).toBe(
        true,
      );

      const updated = await fetchJson(
        `${adminServer.baseUrl}/console/members/${encodeURIComponent(invitedMemberId)}/roles`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            roles: [{ role: 'integrations_read' }],
          }),
        },
      );
      expect(updated.status).toBe(200);
      expect(getPath(updated.json, 'member', 'roles', 0, 'role')).toBe('integrations_read');
      expect(getPath(updated.json, 'member', 'roles', 0, 'scope')).toBe('ORG');

      const removed = await fetchJson(
        `${adminServer.baseUrl}/console/members/${encodeURIComponent(invitedMemberId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(removed.status).toBe(200);
      expect(removed.json?.removed).toBe(true);
      expect(getPath(removed.json, 'member', 'status')).toBe('REMOVED');

      const invalidScope = await fetchJson(`${adminServer.baseUrl}/console/members/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: 'member-team-invalid-user',
          email: 'invalid@example.com',
          roles: [{ role: 'wallet_operations_read', projectId: 'project-team-1' }],
        }),
      });
      expect(invalidScope.status).toBe(400);
      expect(invalidScope.json?.code).toBe('invalid_body');
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-team-1', 'user-team-dev-1'),
      teamRbac,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbidden = await fetchJson(`${developerServer.baseUrl}/console/members/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: 'member-team-forbidden-user',
          email: 'forbidden@example.com',
          roles: [{ role: 'overview_read' }],
        }),
      });
      expect(forbidden.status).toBe(403);
      expect(forbidden.json?.code).toBe('forbidden');
    } finally {
      await developerServer.close();
    }
  });

  test('approval routes enforce mutation RBAC, MFA requirements, and state transitions', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-approvals-1', 'user-approvals-admin-1'),
      approvals,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const initial = await fetchJson(`${adminServer.baseUrl}/console/approvals`, {
        method: 'GET',
      });
      expect(initial.status).toBe(200);
      const initialRows = Array.isArray(initial.json?.approvals) ? initial.json?.approvals : [];
      expect(initialRows).toHaveLength(0);

      const created = await fetchJson(`${adminServer.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'apr_key_export_1',
          operationType: 'KEY_EXPORT',
          reason: 'Approval for sensitive key export',
        }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'approval', 'id')).toBe('apr_key_export_1');
      expect(getPath(created.json, 'approval', 'status')).toBe('PENDING');
      expect(getPath(created.json, 'approval', 'requiredApprovals')).toBe(2);
      expect(getPath(created.json, 'approval', 'requireMfa')).toBe(true);

      const missingMfa = await fetchJson(
        `${adminServer.baseUrl}/console/approvals/apr_key_export_1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'approve without mfa',
            mfaVerified: false,
          }),
        },
      );
      expect(missingMfa.status).toBe(400);
      expect(missingMfa.json?.code).toBe('mfa_required');

      const firstApproval = await fetchJson(
        `${adminServer.baseUrl}/console/approvals/apr_key_export_1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'first approval',
            mfaVerified: true,
          }),
        },
      );
      expect(firstApproval.status).toBe(200);
      expect(getPath(firstApproval.json, 'approval', 'status')).toBe('PENDING');
      expect(Number(getPath(firstApproval.json, 'approval', 'decisions', 'length') || 0)).toBe(1);

      const securityAdminRouter = createConsoleRouter({
        auth: makeConsoleAuthAdapter(
          ['security_admin'],
          'org-approvals-1',
          'user-approvals-security-admin-1',
        ),
        approvals,
      });
      const securityAdminServer = await startExpressRouter(securityAdminRouter);
      try {
        const secondApproval = await fetchJson(
          `${securityAdminServer.baseUrl}/console/approvals/apr_key_export_1/approve`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              reason: 'second approval',
              mfaVerified: true,
            }),
          },
        );
        expect(secondApproval.status).toBe(200);
        expect(getPath(secondApproval.json, 'approval', 'status')).toBe('APPROVED');
        expect(Number(getPath(secondApproval.json, 'approval', 'decisions', 'length') || 0)).toBe(
          2,
        );
        expect(String(getPath(secondApproval.json, 'approval', 'resolvedAt') || '')).toBeTruthy();
      } finally {
        await securityAdminServer.close();
      }

      const alreadyResolved = await fetchJson(
        `${adminServer.baseUrl}/console/approvals/apr_key_export_1/reject`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'late reject',
          }),
        },
      );
      expect(alreadyResolved.status).toBe(409);
      expect(alreadyResolved.json?.code).toBe('invalid_state');

      const filtered = await fetchJson(
        `${adminServer.baseUrl}/console/approvals?status=APPROVED&operationType=KEY_EXPORT`,
        {
          method: 'GET',
        },
      );
      expect(filtered.status).toBe(200);
      const filteredRows = Array.isArray(filtered.json?.approvals) ? filtered.json?.approvals : [];
      expect(
        filteredRows.some((entry: any) => String(entry?.id || '') === 'apr_key_export_1'),
      ).toBe(true);
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-approvals-1', 'user-approvals-developer-1'),
      approvals,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbiddenCreate = await fetchJson(`${developerServer.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationType: 'POLICY_PUBLISH',
          reason: 'unauthorized create',
        }),
      });
      expect(forbiddenCreate.status).toBe(403);
      expect(forbiddenCreate.json?.code).toBe('forbidden');

      const readOnlyList = await fetchJson(`${developerServer.baseUrl}/console/approvals`, {
        method: 'GET',
      });
      expect(readOnlyList.status).toBe(200);
    } finally {
      await developerServer.close();
    }
  });

  test('sensitive operation routes require approved queue entries when approvals service is configured', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const orgId = 'org-sensitive-approval-1';
    const actorUserId = 'user-sensitive-approval-admin-1';
    const claimsRoles = ['admin'];
    const approvalCtx = {
      orgId,
      actorUserId,
      roles: claimsRoles,
    };

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(claimsRoles, orgId, actorUserId),
      approvals,
      policies,
      keyExports,
    });
    const server = await startExpressRouter(router);
    try {
      const createPolicy = await fetchJson(`${server.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Sensitive Policy',
        }),
      });
      expect(createPolicy.status).toBe(201);
      const policyId = String(getPath(createPolicy.json, 'policy', 'id') || '');
      expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

      const publishWithoutApproval = await fetchJson(
        `${server.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(publishWithoutApproval.status).toBe(400);
      expect(publishWithoutApproval.json?.code).toBe('approval_required');

      const policyApproval = await approvals.createApprovalRequest(approvalCtx, {
        id: 'apr_policy_sensitive_1',
        operationType: 'POLICY_PUBLISH',
        reason: 'Publish policy approval',
        resourceType: 'policy',
        resourceId: policyId,
      });
      await approvals.approveApprovalRequest(approvalCtx, policyApproval.id, {
        reason: 'Policy publish approved',
        mfaVerified: true,
      });

      const publishWithApproval = await fetchJson(
        `${server.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            approvalId: policyApproval.id,
          }),
        },
      );
      expect(publishWithApproval.status).toBe(200);
      expect(getPath(publishWithApproval.json, 'result', 'policy', 'status')).toBe('PUBLISHED');

      const exportId = 'ke_sensitive_1';
      const createExport = await fetchJson(`${server.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: exportId,
          environmentId: 'env_sensitive_1',
          reason: 'Key export request',
          requiredApprovals: 1,
        }),
      });
      expect(createExport.status).toBe(201);

      const approveExportWithoutApproval = await fetchJson(
        `${server.baseUrl}/console/key-exports/${encodeURIComponent(exportId)}/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Approve export',
            mfaVerified: true,
          }),
        },
      );
      expect(approveExportWithoutApproval.status).toBe(400);
      expect(approveExportWithoutApproval.json?.code).toBe('approval_required');

      const keyExportApproval = await approvals.createApprovalRequest(approvalCtx, {
        id: 'apr_key_export_sensitive_1',
        operationType: 'KEY_EXPORT',
        reason: 'Key export approval',
        requiredApprovals: 1,
        requireMfa: true,
        resourceType: 'key_export',
        resourceId: exportId,
      });
      await approvals.approveApprovalRequest(approvalCtx, keyExportApproval.id, {
        reason: 'Key export approved',
        mfaVerified: true,
      });

      const approveExportWithApproval = await fetchJson(
        `${server.baseUrl}/console/key-exports/${encodeURIComponent(exportId)}/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Approve export',
            mfaVerified: true,
            approvalId: keyExportApproval.id,
          }),
        },
      );
      expect(approveExportWithApproval.status).toBe(200);
      expect(getPath(approveExportWithApproval.json, 'keyExport', 'status')).toBe('APPROVED');
    } finally {
      await server.close();
    }
  });

  test('approval queue mutations emit approval lifecycle webhook events when webhook endpoint is configured', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-approval-events-1', 'user-approval-events-1'),
      approvals,
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const endpointCreated = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/approval-events',
          eventCategories: ['policy'],
        }),
      });
      expect(endpointCreated.status).toBe(201);
      const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const createdOne = await fetchJson(`${srv.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'apr_events_1',
          operationType: 'POLICY_PUBLISH',
          reason: 'Approval event create/approve',
          requiredApprovals: 1,
        }),
      });
      expect(createdOne.status).toBe(201);

      const approvedOne = await fetchJson(`${srv.baseUrl}/console/approvals/apr_events_1/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: 'Approve with event',
          mfaVerified: true,
        }),
      });
      expect(approvedOne.status).toBe(200);

      const createdTwo = await fetchJson(`${srv.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'apr_events_2',
          operationType: 'KEY_EXPORT',
          reason: 'Approval event create/reject',
        }),
      });
      expect(createdTwo.status).toBe(201);

      const rejectedTwo = await fetchJson(`${srv.baseUrl}/console/approvals/apr_events_2/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: 'Reject with event',
        }),
      });
      expect(rejectedTwo.status).toBe(200);

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        { method: 'GET' },
      );
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
      expect(eventTypes).toContain('policy.approval.created');
      expect(eventTypes).toContain('policy.approval.approved');
      expect(eventTypes).toContain('policy.approval.rejected');
    } finally {
      await srv.close();
    }
  });

  test('org/project/environment routes return hierarchical metadata', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-meta-1',
        actorUserId: 'user-meta-1',
        roles: ['admin'],
      },
      { name: 'Org Meta 1', slug: 'org-meta-1' },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-1', 'user-meta-1'),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdProject = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'project-meta-1',
          name: 'Project Meta 1',
        }),
      });
      expect(createdProject.status).toBe(201);

      const org = await fetchJson(`${srv.baseUrl}/console/org`, { method: 'GET' });
      expect(org.status).toBe(200);
      expect(getPath(org.json, 'org', 'id')).toBe('org-meta-1');

      const projects = await fetchJson(`${srv.baseUrl}/console/projects`, { method: 'GET' });
      expect(projects.status).toBe(200);
      const projectRows = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
      expect(projectRows.length).toBeGreaterThanOrEqual(1);
      const projectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
      expect(projectId).toBeTruthy();
      expect(
        Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0),
      ).toBeGreaterThanOrEqual(1);

      const environments = await fetchJson(`${srv.baseUrl}/console/environments`, {
        method: 'GET',
      });
      expect(environments.status).toBe(200);
      const environmentRows = Array.isArray(environments.json?.environments)
        ? environments.json?.environments
        : [];
      expect(environmentRows.length).toBeGreaterThanOrEqual(1);
      expect(String(getPath(environments.json, 'environments', 0, 'projectId') || '')).toBe(
        projectId,
      );

      const scoped = await fetchJson(
        `${srv.baseUrl}/console/environments?projectId=${encodeURIComponent(projectId)}`,
        {
          method: 'GET',
        },
      );
      expect(scoped.status).toBe(200);
      const scopedRows = Array.isArray(scoped.json?.environments) ? scoped.json?.environments : [];
      expect(scopedRows.length).toBeGreaterThanOrEqual(1);
      expect(scopedRows.every((entry: any) => String(entry?.projectId || '') === projectId)).toBe(
        true,
      );
    } finally {
      await srv.close();
    }
  });

  test('org/project/environment mutation routes enforce role and lifecycle rules', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-meta-mutate-1',
        actorUserId: 'user-meta-mutate-1',
        roles: ['admin'],
      },
      { name: 'Org Meta Mutate 1', slug: 'org-meta-mutate-1' },
    );
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-mutate-1', 'user-meta-mutate-1'),
      orgProjectEnv,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const createdProject = await fetchJson(`${adminServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'project-mutate-1',
          name: 'Project Mutate',
        }),
      });
      expect(createdProject.status).toBe(201);
      expect(getPath(createdProject.json, 'project', 'id')).toBe('project-mutate-1');
      expect(getPath(createdProject.json, 'project', 'status')).toBe('ACTIVE');
      expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(3);
      const environmentsForProject = await fetchJson(
        `${adminServer.baseUrl}/console/environments?projectId=${encodeURIComponent('project-mutate-1')}`,
        { method: 'GET' },
      );
      expect(environmentsForProject.status).toBe(200);
      const projectEnvironmentRows = Array.isArray(environmentsForProject.json?.environments)
        ? environmentsForProject.json?.environments
        : [];
      const managedEnvironmentId = String(getPath(projectEnvironmentRows, 0, 'id') || '');
      expect(managedEnvironmentId).toBeTruthy();

      const updatedProject = await fetchJson(
        `${adminServer.baseUrl}/console/projects/project-mutate-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Project Mutate Renamed' }),
        },
      );
      expect(updatedProject.status).toBe(200);
      expect(getPath(updatedProject.json, 'project', 'name')).toBe('Project Mutate Renamed');

      const updatedEnvironment = await fetchJson(
        `${adminServer.baseUrl}/console/environments/${encodeURIComponent(managedEnvironmentId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'Staging Renamed' }),
        },
      );
      expect(updatedEnvironment.status).toBe(200);
      expect(getPath(updatedEnvironment.json, 'environment', 'name')).toBe('Staging Renamed');

      const archivedProject = await fetchJson(
        `${adminServer.baseUrl}/console/projects/project-mutate-1/archive`,
        {
          method: 'POST',
        },
      );
      expect(archivedProject.status).toBe(200);
      expect(getPath(archivedProject.json, 'project', 'status')).toBe('ARCHIVED');

      const archivedProjects = await fetchJson(
        `${adminServer.baseUrl}/console/projects?status=ARCHIVED`,
        { method: 'GET' },
      );
      expect(archivedProjects.status).toBe(200);
      const archivedProjectRows = Array.isArray(archivedProjects.json?.projects)
        ? archivedProjects.json?.projects
        : [];
      expect(archivedProjectRows.length).toBeGreaterThanOrEqual(1);
      expect(
        archivedProjectRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED'),
      ).toBe(true);

      const activeProjects = await fetchJson(
        `${adminServer.baseUrl}/console/projects?status=ACTIVE`,
        {
          method: 'GET',
        },
      );
      expect(activeProjects.status).toBe(200);
      const activeProjectRows = Array.isArray(activeProjects.json?.projects)
        ? activeProjects.json?.projects
        : [];
      expect(
        activeProjectRows.every((entry: any) => String(entry?.status || '') === 'ACTIVE'),
      ).toBe(true);

      const invalidProjectStatus = await fetchJson(
        `${adminServer.baseUrl}/console/projects?status=INVALID`,
        {
          method: 'GET',
        },
      );
      expect(invalidProjectStatus.status).toBe(400);
      expect(invalidProjectStatus.json?.code).toBe('invalid_query');

      const archivedOnly = await fetchJson(
        `${adminServer.baseUrl}/console/environments?projectId=project-mutate-1&status=ARCHIVED`,
        { method: 'GET' },
      );
      expect(archivedOnly.status).toBe(200);
      const archivedRows = Array.isArray(archivedOnly.json?.environments)
        ? archivedOnly.json?.environments
        : [];
      expect(archivedRows.length).toBeGreaterThanOrEqual(1);
      expect(archivedRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(
        true,
      );

      const activeOnly = await fetchJson(
        `${adminServer.baseUrl}/console/environments?projectId=project-mutate-1&status=ACTIVE`,
        { method: 'GET' },
      );
      expect(activeOnly.status).toBe(200);
      const activeRows = Array.isArray(activeOnly.json?.environments)
        ? activeOnly.json?.environments
        : [];
      expect(activeRows.length).toBe(0);

      const invalidStatus = await fetchJson(
        `${adminServer.baseUrl}/console/environments?status=INVALID`,
        {
          method: 'GET',
        },
      );
      expect(invalidStatus.status).toBe(400);
      expect(invalidStatus.json?.code).toBe('invalid_query');

      const createOnArchived = await fetchJson(`${adminServer.baseUrl}/console/environments`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId: 'project-mutate-1',
          key: 'dev',
        }),
      });
      expect(createOnArchived.status).toBe(409);
      expect(createOnArchived.json?.code).toBe('project_archived');
    } finally {
      await adminServer.close();
    }

    const devRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-meta-mutate-1', 'user-meta-dev-1'),
      orgProjectEnv,
    });
    const devServer = await startExpressRouter(devRouter);
    try {
      const forbidden = await fetchJson(`${devServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Forbidden Project',
        }),
      });
      expect(forbidden.status).toBe(403);
      expect(forbidden.json?.code).toBe('forbidden');
    } finally {
      await devServer.close();
    }
  });

  test('GET /console/wallets returns wallets_not_configured without wallet service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/wallets`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('wallets_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/policies returns policies_not_configured without policy service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/policies`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('policies_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/policy/coverage returns wallets_not_configured without wallet service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/policy/coverage`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('wallets_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/export/governance returns key_exports_not_configured without key export service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/export/governance`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('key_exports_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints return *_not_configured when services are not wired', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const srv = await startExpressRouter(router);
    try {
      const gas = await fetchJson(`${srv.baseUrl}/console/policies?kind=GAS_SPONSORSHIP`, {
        method: 'GET',
      });
      expect(gas.status).toBe(501);
      expect(gas.json?.code).toBe('policies_not_configured');

      const keyExports = await fetchJson(`${srv.baseUrl}/console/key-exports`, { method: 'GET' });
      expect(keyExports.status).toBe(501);
      expect(keyExports.json?.code).toBe('key_exports_not_configured');

      const runtimeSnapshots = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('env-test')}`,
        { method: 'GET' },
      );
      expect(runtimeSnapshots.status).toBe(501);
      expect(runtimeSnapshots.json?.code).toBe('runtime_snapshots_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints support scaffold CRUD flows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-express-1', 'user-scaffold-express-1'),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdGas = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Scaffold gas policy express',
          rules: evmGasSponsorshipRulesFixture({
            environmentId: 'prod',
            projectId: null,
            chainId: 1,
            capMinor: 500000,
            enabled: true,
          }),
        }),
      });
      expect(createdGas.status).toBe(201);
      const createdGasId = String(getPath(createdGas.json, 'policy', 'id') || '');
      expect(createdGasId.startsWith('policy_')).toBe(true);

      const listedGas = await fetchJson(`${srv.baseUrl}/console/policies?kind=GAS_SPONSORSHIP`, {
        method: 'GET',
      });
      expect(listedGas.status).toBe(200);
      const listedGasRows: unknown[] = Array.isArray(listedGas.json?.policies)
        ? (listedGas.json?.policies as unknown[])
        : [];
      expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

      const patchedGas = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(createdGasId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rules: evmGasSponsorshipRulesFixture({
              environmentId: 'prod',
              projectId: null,
              chainId: 1,
              capMinor: 500000,
              enabled: false,
            }),
          }),
        },
      );
      expect(patchedGas.status).toBe(200);
      expect(getPath(patchedGas.json, 'policy', 'rules', 'enabled')).toBe(false);

      const publishedGas = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(createdGasId)}/publish`,
        { method: 'POST' },
      );
      expect(publishedGas.status).toBe(200);

      const createdKeyExport = await fetchJson(`${srv.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-1',
          environmentId: 'prod',
          reason: 'Emergency rotation',
          requiredApprovals: 1,
        }),
      });
      expect(createdKeyExport.status).toBe(201);
      expect(getPath(createdKeyExport.json, 'keyExport', 'status')).toBe('PENDING_APPROVAL');

      const approvedKeyExport = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Approved with MFA',
            mfaVerified: true,
          }),
        },
      );
      expect(approvedKeyExport.status).toBe(200);
      expect(getPath(approvedKeyExport.json, 'keyExport', 'status')).toBe('APPROVED');

      const publishedSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: 'prod',
          }),
        },
      );
      expect(publishedSnapshot.status).toBe(201);
      expect(Number(getPath(publishedSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);
      expect(String(getPath(publishedSnapshot.json, 'snapshot', 'checksum') || '')).toContain(
        'fnv1a32:',
      );
      expect(
        getPath(publishedSnapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status'),
      ).toBe('resolved');
      const latestSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(latestSnapshot.status).toBe(200);
      expect(getPath(latestSnapshot.json, 'snapshot', 'environmentId')).toBe('prod');
      expect(Number(getPath(latestSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);

      const listedSnapshots = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&limit=5`,
        { method: 'GET' },
      );
      expect(listedSnapshots.status).toBe(200);
      const snapshotRows = Array.isArray(listedSnapshots.json?.snapshots)
        ? listedSnapshots.json?.snapshots
        : [];
      expect(snapshotRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await srv.close();
    }
  });

  test('runtime snapshot publish-current emits not_configured markers and monotonic versions', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-contract-express-1',
        'user-runtime-contract-express-1',
      ),
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const first = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          projectId: 'project-alpha',
          snapshotId: 'runtime-contract-v1',
          effectiveAt: '2026-03-01T00:00:00.000Z',
        }),
      });
      expect(first.status).toBe(201);
      expect(getPath(first.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v1');
      expect(Number(getPath(first.json, 'snapshot', 'version') || 0)).toBe(1);
      expect(getPath(first.json, 'snapshot', 'payload', 'policy', 'status')).toBe('not_configured');
      expect(getPath(first.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
        'not_configured',
      );
      const firstChecksum = String(getPath(first.json, 'snapshot', 'checksum') || '');
      expect(firstChecksum).toContain('fnv1a32:');

      const second = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          projectId: 'project-alpha',
          snapshotId: 'runtime-contract-v2',
          effectiveAt: '2026-03-01T01:00:00.000Z',
        }),
      });
      expect(second.status).toBe(201);
      expect(getPath(second.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
      expect(Number(getPath(second.json, 'snapshot', 'version') || 0)).toBe(2);
      expect(String(getPath(second.json, 'snapshot', 'checksum') || '')).not.toBe(firstChecksum);

      const latest = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent('prod')}&projectId=${encodeURIComponent('project-alpha')}`,
        { method: 'GET' },
      );
      expect(latest.status).toBe(200);
      expect(getPath(latest.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
      expect(Number(getPath(latest.json, 'snapshot', 'version') || 0)).toBe(2);

      const listed = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&projectId=${encodeURIComponent('project-alpha')}&limit=2`,
        { method: 'GET' },
      );
      expect(listed.status).toBe(200);
      expect(getPath(listed.json, 'snapshots', 0, 'snapshotId')).toBe('runtime-contract-v2');
      expect(getPath(listed.json, 'snapshots', 1, 'snapshotId')).toBe('runtime-contract-v1');
    } finally {
      await srv.close();
    }
  });

  test('runtime snapshot publish-current resolves published policy state instead of attached draft rules', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const policies = createInMemoryConsolePolicyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-policy-express-1',
        'user-runtime-policy-express-1',
      ),
      runtimeSnapshots,
      policies,
    });
    const srv = await startExpressRouter(router);
    try {
      const environmentId = 'env-runtime-policy-express-1';
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Runtime policy express',
          assignment: {
            scopeType: 'ENVIRONMENT',
            scopeId: environmentId,
          },
          rules: {
            blockedActions: ['delete_key'],
            allowedChains: ['Ethereum'],
          },
        }),
      });
      expect(created.status).toBe(201);
      const policyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

      const published = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
        { method: 'POST' },
      );
      expect(published.status).toBe(200);

      const drafted = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rules: {
              blockedActions: ['export_key'],
              allowedChains: ['NEAR'],
            },
          }),
        },
      );
      expect(drafted.status).toBe(200);
      expect(getPath(drafted.json, 'policy', 'status')).toBe('DRAFT');

      const snapshot = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId,
          snapshotId: 'runtime-policy-live-express-v1',
        }),
      });
      expect(snapshot.status).toBe(201);
      expect(getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'status')).toBe('resolved');
      const snapshotPolicies = Array.isArray(
        getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'policies'),
      )
        ? (getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'policies') as any[])
        : [];
      const livePolicy = snapshotPolicies.find((entry) => String(entry?.id || '') === policyId);
      expect(livePolicy).toBeTruthy();
      expect(String(getPath(livePolicy, 'status') || '')).toBe('PUBLISHED');
      expect(getPath(livePolicy, 'rules', 'blockedActions', 0)).toBe('delete_key');
      expect(getPath(livePolicy, 'rules', 'allowedChains', 0)).toBe('Ethereum');
      expect(getPath(livePolicy, 'rules', 'blockedActions', 0)).not.toBe('export_key');

      const snapshotAssignments = Array.isArray(
        getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'assignments'),
      )
        ? (getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'assignments') as any[])
        : [];
      expect(
        snapshotAssignments.some(
          (entry) =>
            String(entry?.policyId || '') === policyId &&
            String(entry?.scopeType || '') === 'ENVIRONMENT' &&
            String(entry?.scopeId || '') === environmentId,
        ),
      ).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('runtime snapshot publish-current resolves published gas sponsorship policy state instead of draft gas rules', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const policies = createInMemoryConsolePolicyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-gas-policy-express-1',
        'user-runtime-gas-policy-express-1',
      ),
      runtimeSnapshots,
      policies,
    });
    const srv = await startExpressRouter(router);
    try {
      const environmentId = 'env-runtime-gas-policy-express-1';
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Runtime gas policy express',
          rules: evmGasSponsorshipRulesFixture({
            environmentId,
            projectId: null,
            chainId: 1,
            capMinor: 500000,
            enabled: true,
          }),
        }),
      });
      expect(created.status).toBe(201);
      const policyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

      const published = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
        { method: 'POST' },
      );
      expect(published.status).toBe(200);

      const drafted = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rules: evmGasSponsorshipRulesFixture({
              environmentId,
              projectId: null,
              chainId: 10,
              capMinor: 500000,
              enabled: true,
            }),
          }),
        },
      );
      expect(drafted.status).toBe(200);
      expect(getPath(drafted.json, 'policy', 'status')).toBe('DRAFT');

      const snapshot = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish-current`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId,
          snapshotId: 'runtime-gas-policy-live-express-v1',
        }),
      });
      expect(snapshot.status).toBe(201);
      expect(getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
        'resolved',
      );
      expect(
        Number(getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'policyCount') || 0),
      ).toBe(1);
      expect(
        getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'policies', 0, 'id'),
      ).toBe(policyId);
      expect(
        getPath(
          snapshot.json,
          'snapshot',
          'payload',
          'gasSponsorship',
          'policies',
          0,
          'allowedChainIds',
          0,
        ),
      ).toBe(1);
      expect(
        getPath(
          snapshot.json,
          'snapshot',
          'payload',
          'gasSponsorship',
          'resolvedPolicies',
          0,
          'policyId',
        ),
      ).toBe(policyId);
      expect(
        getPath(
          snapshot.json,
          'snapshot',
          'payload',
          'gasSponsorship',
          'resolvedPolicies',
          0,
          'allowedChainIds',
          0,
        ),
      ).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('new console endpoint mutations enforce role gates', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const auditExports = createInMemoryConsoleAuditExportsService();
    const billing = createInMemoryConsoleBillingService();
    const enterpriseIsolation = createInMemoryConsoleEnterpriseIsolationService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const approvals = createInMemoryConsoleApprovalService();
    const onboarding = createInMemoryConsoleOnboardingService({
      apiKeys,
      orgProjectEnv,
      teamRbac,
    });
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-express-rbac-1',
        'user-scaffold-express-rbac-1',
      ),
      onboarding,
      orgProjectEnv,
      teamRbac,
      approvals,
      apiKeys,
      auditExports,
      billing,
      enterpriseIsolation,
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const gasCreate = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Forbidden gas policy express',
        }),
      });
      expect(gasCreate.status).toBe(403);
      expect(gasCreate.json?.code).toBe('forbidden');

      const configureOnboardingOrganization = await fetchJson(
        `${srv.baseUrl}/console/onboarding/organization`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Forbidden onboarding organization express',
            slug: 'forbidden-onboarding-org-express',
          }),
        },
      );
      expect(configureOnboardingOrganization.status).toBe(403);
      expect(configureOnboardingOrganization.json?.code).toBe('forbidden');

      const createProject = await fetchJson(`${srv.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'proj-express-rbac-1',
          name: 'Forbidden project express',
        }),
      });
      expect(createProject.status).toBe(403);
      expect(createProject.json?.code).toBe('forbidden');

      const inviteMember = await fetchJson(`${srv.baseUrl}/console/members/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: 'member-express-rbac-1',
          email: 'forbidden-member-express@example.com',
          roles: [{ role: 'overview_read' }],
        }),
      });
      expect(inviteMember.status).toBe(403);
      expect(inviteMember.json?.code).toBe('forbidden');

      const createApproval = await fetchJson(`${srv.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operationType: 'KEY_EXPORT',
          reason: 'Forbidden approval request express',
        }),
      });
      expect(createApproval.status).toBe(403);
      expect(createApproval.json?.code).toBe('forbidden');

      const createAuditExport = await fetchJson(`${srv.baseUrl}/console/audit/exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'aexp-express-rbac-1',
          format: 'JSONL',
          domain: 'POLICY',
        }),
      });
      expect(createAuditExport.status).toBe(403);
      expect(createAuditExport.json?.code).toBe('forbidden');

      const triggerIsolation = await fetchJson(`${srv.baseUrl}/console/isolation/trigger`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scope: 'ORG',
          trigger: 'COMPLIANCE',
          reason: 'Forbidden isolation express',
        }),
      });
      expect(triggerIsolation.status).toBe(403);
      expect(triggerIsolation.json?.code).toBe('forbidden');

      const createKeyExport = await fetchJson(`${srv.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-rbac-1',
          environmentId: 'prod',
          reason: 'Trying as developer',
          requiredApprovals: 1,
        }),
      });
      expect(createKeyExport.status).toBe(403);
      expect(createKeyExport.json?.code).toBe('forbidden');

      const approve = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-rbac-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'trying as non-admin',
            mfaVerified: true,
          }),
        },
      );
      expect(approve.status).toBe(403);
      expect(approve.json?.code).toBe('forbidden');

      const publishSnapshot = await fetchJson(`${srv.baseUrl}/console/runtime-snapshots/publish`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          environmentId: 'prod',
          payload: {
            policy: {},
            gasSponsorship: {},
          },
        }),
      });
      expect(publishSnapshot.status).toBe(403);
      expect(publishSnapshot.json?.code).toBe('forbidden');

      const publishCurrentSnapshot = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: 'prod',
          }),
        },
      );
      expect(publishCurrentSnapshot.status).toBe(403);
      expect(publishCurrentSnapshot.json?.code).toBe('forbidden');

      const generateInvoice = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-01',
        }),
      });
      expect(generateInvoice.status).toBe(403);
      expect(generateInvoice.json?.code).toBe('forbidden');

      const appendSupportCredit = await fetchJson(
        `${srv.baseUrl}/console/billing/adjustments/support-credit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amountMinor: 100,
            reasonCode: 'incident_credit',
            note: 'Forbidden support credit express',
            idempotencyKey: 'manual-credit-express-rbac',
          }),
        },
      );
      expect(appendSupportCredit.status).toBe(403);
      expect(appendSupportCredit.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoint validation errors return typed error codes', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-express-validation-1',
        'user-scaffold-express-validation-1',
      ),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const invalidGasScope = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Invalid gas scope express',
          rules: {
            scopeType: 'NOT_A_SCOPE',
          },
        }),
      });
      expect(invalidGasScope.status).toBe(400);
      expect(invalidGasScope.json?.code).toBe('invalid_body');

      const invalidStatusQuery = await fetchJson(
        `${srv.baseUrl}/console/key-exports?status=NOT_A_STATUS`,
        {
          method: 'GET',
        },
      );
      expect(invalidStatusQuery.status).toBe(400);
      expect(invalidStatusQuery.json?.code).toBe('invalid_query');

      const createdKeyExport = await fetchJson(`${srv.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-validation-1',
          environmentId: 'prod',
          reason: 'Validation flow',
          requiredApprovals: 1,
        }),
      });
      expect(createdKeyExport.status).toBe(201);

      const approveWithoutMfa = await fetchJson(
        `${srv.baseUrl}/console/key-exports/ke-express-validation-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'Missing MFA check',
            mfaVerified: false,
          }),
        },
      );
      expect(approveWithoutMfa.status).toBe(400);
      expect(approveWithoutMfa.json?.code).toBe('mfa_required');

      const invalidSnapshotQuery = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent('prod')}&limit=999`,
        { method: 'GET' },
      );
      expect(invalidSnapshotQuery.status).toBe(400);
      expect(invalidSnapshotQuery.json?.code).toBe('invalid_query');

      const invalidSnapshotBody = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: 'prod',
            payload: {
              policy: {},
            },
          }),
        },
      );
      expect(invalidSnapshotBody.status).toBe(400);
      expect(invalidSnapshotBody.json?.code).toBe('invalid_body');

      const invalidPublishCurrentBody = await fetchJson(
        `${srv.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            projectId: 'project-only',
          }),
        },
      );
      expect(invalidPublishCurrentBody.status).toBe(400);
      expect(invalidPublishCurrentBody.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('new console endpoints enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-express-isolation-owner';
    const attackerOrgId = 'org-scaffold-express-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-express-isolation-user'),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerGasId = '';
    try {
      const createGas = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Isolation gas policy express',
          rules: evmGasSponsorshipRulesFixture({
            environmentId: ownerEnvironmentId,
            projectId: null,
            chainId: 11_155_111,
            capMinor: 500000,
            enabled: true,
          }),
        }),
      });
      expect(createGas.status).toBe(201);
      ownerGasId = String(getPath(createGas.json, 'policy', 'id') || '');
      expect(ownerGasId.startsWith('policy_')).toBe(true);

      const createKeyExport = await fetchJson(`${ownerServer.baseUrl}/console/key-exports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'ke-express-isolation-1',
          environmentId: ownerEnvironmentId,
          reason: 'Owner export request',
          requiredApprovals: 1,
        }),
      });
      expect(createKeyExport.status).toBe(201);

      const publishSnapshot = await fetchJson(
        `${ownerServer.baseUrl}/console/runtime-snapshots/publish-current`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            environmentId: ownerEnvironmentId,
          }),
        },
      );
      expect(publishSnapshot.status).toBe(201);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        attackerOrgId,
        'attacker-scaffold-express-isolation-user',
      ),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const gasList = await fetchJson(
        `${attackerServer.baseUrl}/console/policies?kind=GAS_SPONSORSHIP`,
        { method: 'GET' },
      );
      expect(gasList.status).toBe(200);
      const attackerGasRows = Array.isArray(gasList.json?.policies) ? gasList.json?.policies : [];
      expect(attackerGasRows.length).toBe(0);

      const patchGas = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerGasId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ rules: { enabled: false } }),
        },
      );
      expect(patchGas.status).toBe(404);
      expect(patchGas.json?.code).toBe('policy_not_found');

      const keyExportsList = await fetchJson(
        `${attackerServer.baseUrl}/console/key-exports?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(keyExportsList.status).toBe(200);
      const attackerKeyExportRows = Array.isArray(keyExportsList.json?.exports)
        ? keyExportsList.json?.exports
        : [];
      expect(attackerKeyExportRows.length).toBe(0);

      const approveKeyExport = await fetchJson(
        `${attackerServer.baseUrl}/console/key-exports/ke-express-isolation-1/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'attacker approve attempt',
            mfaVerified: true,
          }),
        },
      );
      expect(approveKeyExport.status).toBe(404);
      expect(approveKeyExport.json?.code).toBe('key_export_not_found');

      const attackerSnapshots = await fetchJson(
        `${attackerServer.baseUrl}/console/runtime-snapshots?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerSnapshots.status).toBe(200);
      const attackerSnapshotRows = Array.isArray(attackerSnapshots.json?.snapshots)
        ? attackerSnapshots.json?.snapshots
        : [];
      expect(attackerSnapshotRows.length).toBe(0);

      const attackerLatestSnapshot = await fetchJson(
        `${attackerServer.baseUrl}/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerLatestSnapshot.status).toBe(200);
      expect(attackerLatestSnapshot.json?.snapshot).toBeNull();
    } finally {
      await attackerServer.close();
    }
  });

  test('wallet routes support list/search/detail', async () => {
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_express_seed_1',
          orgId: 'org-wallet-express-1',
          projectId: 'proj_wallet_express_seed_1',
          environmentId: 'env_wallet_express_seed_1',
        }),
      ],
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-wallet-express-1', 'user-wallet-express-1'),
      wallets,
    });
    const srv = await startExpressRouter(router);
    try {
      const listed = await fetchJson(`${srv.baseUrl}/console/wallets?limit=5&chain=Ethereum`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const rows = Array.isArray(listed.json?.wallets) ? listed.json?.wallets : [];
      expect(rows.length).toBeGreaterThanOrEqual(1);
      const walletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
      expect(walletId).toBeTruthy();

      const searched = await fetchJson(
        `${srv.baseUrl}/console/wallets/search?q=${encodeURIComponent(walletId.slice(0, 10))}`,
        { method: 'GET' },
      );
      expect(searched.status).toBe(200);
      const searchedRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
      expect(searchedRows.some((entry: any) => String(entry?.id || '') === walletId)).toBe(true);

      const detail = await fetchJson(
        `${srv.baseUrl}/console/wallets/${encodeURIComponent(walletId)}`,
        { method: 'GET' },
      );
      expect(detail.status).toBe(200);
      expect(String(getPath(detail.json, 'wallet', 'id') || '')).toBe(walletId);

      const missing = await fetchJson(`${srv.baseUrl}/console/wallets/wallet_missing`, {
        method: 'GET',
      });
      expect(missing.status).toBe(404);
      expect(missing.json?.code).toBe('wallet_not_found');
    } finally {
      await srv.close();
    }
  });

  test('wallet read routes require wallet read role', async () => {
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_express_forbidden_1',
          orgId: 'org-wallet-read-role-1',
          projectId: 'proj_wallet_read_role_1',
          environmentId: 'env_wallet_read_role_1',
        }),
      ],
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-wallet-read-role-1',
        'user-wallet-read-role-1',
      ),
      wallets,
    });
    const srv = await startExpressRouter(router);
    try {
      for (const path of [
        '/console/wallets?limit=5',
        '/console/wallets/search?q=wallet_express',
        '/console/wallets/wallet_express_forbidden_1',
      ]) {
        const res = await fetchJson(`${srv.baseUrl}${path}`, { method: 'GET' });
        expect(res.status, path).toBe(403);
        expect(res.json?.code, path).toBe('forbidden');
      }
    } finally {
      await srv.close();
    }
  });

  test('policy/gas/export insight routes return aggregated views', async () => {
    const orgId = 'org-insights-express-1';
    const projectId = 'default-project';
    const environmentId = `${projectId}:prod`;
    const wallet = makeSeedWallet({
      id: 'wallet_insights_express_1',
      orgId,
      projectId,
      environmentId,
    });
    wallet.lastActivityAt = wallet.updatedAt;
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [wallet],
    });
    const keyExports = createInMemoryConsoleKeyExportService();
    const policies = createInMemoryConsolePolicyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId,
      projectId,
      actorUserId: 'user-insights-express-1',
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-insights-express-1'),
      wallets,
      keyExports,
      policies,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      await keyExports.createKeyExport(
        {
          orgId,
          actorUserId: 'user-insights-express-1',
          roles: ['admin'],
        },
        {
          environmentId,
          reason: 'Break-glass recovery for production wallet',
        },
      );

      const approvedRequest = await keyExports.createKeyExport(
        {
          orgId,
          actorUserId: 'user-insights-approver-1',
          roles: ['admin'],
        },
        {
          environmentId: `${projectId}:stage`,
          reason: 'Stage export drill',
          requiredApprovals: 1,
        },
      );
      await keyExports.approveKeyExport(
        {
          orgId,
          actorUserId: 'user-insights-approver-1',
          roles: ['admin'],
        },
        approvedRequest.id,
        {
          reason: 'Approved stage export drill',
          mfaVerified: true,
        },
      );

      const coverage = await fetchJson(`${srv.baseUrl}/console/policy/coverage`, { method: 'GET' });
      expect(coverage.status).toBe(200);
      expect(
        Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
      const policyRows: unknown[] = Array.isArray(getPath(coverage.json, 'coverage', 'policies'))
        ? (getPath(coverage.json, 'coverage', 'policies') as unknown[])
        : [];
      expect(policyRows.length).toBeGreaterThanOrEqual(1);
      expect(
        policyRows.some((row) => String(getPath(row, 'policyKind') || '') === 'TRANSACTION'),
      ).toBe(true);

      const readiness = await fetchJson(`${srv.baseUrl}/console/gas/readiness`, { method: 'GET' });
      expect(readiness.status).toBe(200);
      expect(
        Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
      const chainRows: unknown[] = Array.isArray(getPath(readiness.json, 'readiness', 'chains'))
        ? (getPath(readiness.json, 'readiness', 'chains') as unknown[])
        : [];
      expect(chainRows.length).toBeGreaterThanOrEqual(1);
      const readinessWalletRows: unknown[] = Array.isArray(
        getPath(readiness.json, 'readiness', 'recentWalletSample'),
      )
        ? (getPath(readiness.json, 'readiness', 'recentWalletSample') as unknown[])
        : [];
      expect(
        readinessWalletRows.some(
          (row) => String(getPath(row, 'policyKind') || '') === 'TRANSACTION',
        ),
      ).toBe(true);

      const governance = await fetchJson(
        `${srv.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(environmentId)}`,
        {
          method: 'GET',
        },
      );
      expect(governance.status).toBe(200);
      expect(Number(getPath(governance.json, 'governance', 'totals', 'requestCount') || 0)).toBe(2);
      expect(
        Number(
          getPath(governance.json, 'governance', 'totals', 'selectedEnvironmentRequestCount') || 0,
        ),
      ).toBe(1);
      expect(
        Number(getPath(governance.json, 'governance', 'totals', 'pendingApprovalCount') || 0),
      ).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('policy routes support draft/update/simulate/publish lifecycle with role gates', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-express-1', 'user-policy-admin-1'),
      policies,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const listed = await fetchJson(`${adminServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const policiesBefore = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(policiesBefore.length).toBeGreaterThanOrEqual(1);
      const defaultPolicyBefore = policiesBefore.find(
        (entry) => getPath(entry, 'isSystemDefault') === true,
      );
      expect(defaultPolicyBefore).toBeTruthy();
      expect(String(getPath(defaultPolicyBefore, 'id') || '')).toMatch(
        /^policy_[a-z0-9]+_[a-z0-9]+$/,
      );

      const created = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Policy Express Lifecycle',
          rules: {
            blockedActions: [],
            allowedChains: ['ethereum'],
            maxAmountMinor: 5000,
          },
        }),
      });
      expect(created.status).toBe(201);
      const lifecyclePolicyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(lifecyclePolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
      expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
      expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

      const allowedSimulation = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(lifecyclePolicyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'transfer',
            chain: 'ethereum',
            amountMinor: 4000,
          }),
        },
      );
      expect(allowedSimulation.status).toBe(200);
      expect(getPath(allowedSimulation.json, 'simulation', 'decision')).toBe('ALLOW');

      const patched = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(lifecyclePolicyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rules: {
              blockedActions: ['transfer'],
              allowedChains: ['ethereum'],
            },
          }),
        },
      );
      expect(patched.status).toBe(200);
      expect(getPath(patched.json, 'policy', 'status')).toBe('DRAFT');

      const deniedSimulation = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(lifecyclePolicyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'transfer',
            chain: 'ethereum',
            amountMinor: 1,
          }),
        },
      );
      expect(deniedSimulation.status).toBe(200);
      expect(getPath(deniedSimulation.json, 'simulation', 'decision')).toBe('DENY');

      const published = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(lifecyclePolicyId)}/publish`,
        {
          method: 'POST',
        },
      );
      expect(published.status).toBe(200);
      expect(getPath(published.json, 'result', 'published')).toBe(true);
      expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
      expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-policy-express-1', 'user-policy-dev-1'),
      policies,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbiddenCreate = await fetchJson(`${developerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Forbidden policy',
        }),
      });
      expect(forbiddenCreate.status).toBe(403);
      expect(forbiddenCreate.json?.code).toBe('forbidden');
    } finally {
      await developerServer.close();
    }
  });

  test('policy routes enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-owner-express', 'owner-policy-user'),
      policies,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerPolicyId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Owner Policy',
        }),
      });
      expect(created.status).toBe(201);
      ownerPolicyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(ownerPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-attacker-express',
        'attacker-policy-user',
      ),
      policies,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const listed = await fetchJson(`${attackerServer.baseUrl}/console/policies`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
        false,
      );

      const patched = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker update' }),
        },
      );
      expect(patched.status).toBe(404);
      expect(patched.json?.code).toBe('policy_not_found');

      const simulated = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ action: 'transfer' }),
        },
      );
      expect(simulated.status).toBe(404);
      expect(simulated.json?.code).toBe('policy_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('policy create rejects client-supplied ids', async () => {
    const policies = createInMemoryConsolePolicyService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-create-id-validation', 'user-policy-id'),
      policies,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy_user_supplied',
          name: 'Should fail',
        }),
      });
      expect(created.status).toBe(400);
      expect(created.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('policy create, update, and delete append audit rows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-audit-express',
        'user-policy-audit-express',
      ),
      policies,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Express audited policy',
          rules: {
            scopeType: 'ENVIRONMENT',
            projectId: 'proj_policy_audit_express',
            environmentId: 'env_policy_audit_express',
            enabled: true,
          },
        }),
      });
      expect(created.status).toBe(201);
      const policyId = String(getPath(created.json, 'policy', 'id') || '');
      const createdVersion = Number(getPath(created.json, 'policy', 'version') || 0);
      expect(policyId).toBeTruthy();

      const updated = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Express audited policy updated',
          }),
        },
      );
      expect(updated.status).toBe(200);

      const deleted = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(deleted.status).toBe(200);

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-policy-audit-express',
          actorUserId: 'user-policy-audit-express',
          roles: ['admin'],
        },
        { category: 'POLICY', limit: 20 },
      );
      const lifecycleEvents = auditEvents.filter((event) =>
        ['policy.create', 'policy.update', 'policy.delete'].includes(String(event.action || '')),
      );
      expect(lifecycleEvents.map((event) => String(event.action || '')).sort()).toEqual([
        'policy.create',
        'policy.delete',
        'policy.update',
      ]);
      expect(lifecycleEvents.every((event) => event.category === 'POLICY')).toBe(true);
      const lifecycleByAction = Object.fromEntries(
        lifecycleEvents.map((event) => [String(event.action || ''), event]),
      );
      expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyId')).toBe(policyId);
      expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyName')).toBe(
        'Express audited policy updated',
      );
      expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyKind')).toBe(
        'GAS_SPONSORSHIP',
      );
      expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'environmentId')).toBe(
        'env_policy_audit_express',
      );
      expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'projectId')).toBe(
        'proj_policy_audit_express',
      );
      expect(lifecycleByAction['policy.delete']?.environmentId).toBe('env_policy_audit_express');
      expect(lifecycleByAction['policy.delete']?.projectId).toBe('proj_policy_audit_express');
      expect(getPath(lifecycleByAction['policy.create'], 'metadata', 'policyName')).toBe(
        'Express audited policy',
      );
      expect(getPath(lifecycleByAction['policy.create'], 'metadata', 'version')).toBe(
        createdVersion,
      );
    } finally {
      await srv.close();
    }
  });

  test('successful policy create stays quiet while Stripe top-up emits billing observability', async () => {
    const ingested: ObservabilityIngestionEntry[] = [];
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-success-express',
        'user-observability-success-express',
      ),
      policies: createInMemoryConsolePolicyService(),
      billing: createInMemoryConsoleBillingService(),
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });
    const srv = await startExpressRouter(router);
    try {
      const createdPolicy = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Healthy observability policy',
          rules: evmGasSponsorshipRulesFixture({
            projectId: 'proj_obs_success_express',
            environmentId: 'env_obs_success_express',
            chainId: 1,
            capMinor: 500000,
            enabled: true,
          }),
        }),
      });
      expect(createdPolicy.status).toBe(201);
      expect(String(getPath(createdPolicy.json, 'policy', 'id') || '')).toBeTruthy();

      const createdCheckout = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
            cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
            creditPackId: 'usd_25',
          }),
        },
      );
      expect(createdCheckout.status).toBe(201);
      const checkoutSessionId = String(
        getPath(createdCheckout.json, 'checkoutSession', 'id') || '',
      );
      expect(checkoutSessionId).toBeTruthy();

      const reconciled = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ checkoutSessionId }),
        },
      );
      expect(reconciled.status).toBe(200);
      expect(getPath(reconciled.json, 'result', 'settled')).toBe(true);

      expect(policyObservabilityEventTypes(ingested)).toEqual([]);
      expect(observabilityEventTypes(ingested)).toEqual(['billing.balance.recovered']);
    } finally {
      await srv.close();
    }
  });

  test('policy assignment upsert and delete append audit rows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-assignment-audit-express',
        'user-policy-assignment-audit-express',
      ),
      policies,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Express assignment audited policy',
        }),
      });
      expect(created.status).toBe(201);
      const policyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(policyId).toBeTruthy();

      const assignmentUpsert = await fetchJson(`${srv.baseUrl}/console/policies/assignments`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ENVIRONMENT',
          scopeId: 'env_policy_assignment_audit_express',
          policyId,
        }),
      });
      expect(assignmentUpsert.status).toBe(200);
      const assignmentId = String(getPath(assignmentUpsert.json, 'assignment', 'id') || '');
      expect(assignmentId).toBeTruthy();

      const assignmentDelete = await fetchJson(
        `${srv.baseUrl}/console/policies/assignments/${encodeURIComponent(assignmentId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(assignmentDelete.status).toBe(200);

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-policy-assignment-audit-express',
          actorUserId: 'user-policy-assignment-audit-express',
          roles: ['admin'],
        },
        { category: 'POLICY', limit: 20 },
      );
      const assignmentEvents = auditEvents.filter((event) =>
        ['policy.assignment.upsert', 'policy.assignment.delete'].includes(
          String(event.action || ''),
        ),
      );
      expect(assignmentEvents.map((event) => String(event.action || '')).sort()).toEqual([
        'policy.assignment.delete',
        'policy.assignment.upsert',
      ]);
      const assignmentByAction = Object.fromEntries(
        assignmentEvents.map((event) => [String(event.action || ''), event]),
      );
      expect(
        getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentId'),
      ).toBe(assignmentId);
      expect(getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'policyId')).toBe(
        policyId,
      );
      expect(
        getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentScopeType'),
      ).toBe('ENVIRONMENT');
      expect(
        getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentScopeId'),
      ).toBe('env_policy_assignment_audit_express');
      expect(
        getPath(assignmentByAction['policy.assignment.delete'], 'metadata', 'policyName'),
      ).toBe('Express assignment audited policy');
      expect(assignmentByAction['policy.assignment.upsert']?.environmentId).toBe(
        'env_policy_assignment_audit_express',
      );
      expect(assignmentByAction['policy.assignment.delete']?.environmentId).toBe(
        'env_policy_assignment_audit_express',
      );
    } finally {
      await srv.close();
    }
  });

  test('policy publish appends audit row with final version and scope metadata', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-publish-audit-express',
        'user-policy-publish-audit-express',
      ),
      policies,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'GAS_SPONSORSHIP',
          name: 'Express published audit policy',
          rules: evmGasSponsorshipRulesFixture({
            environmentId: 'env_policy_publish_audit_express',
            projectId: 'proj_policy_publish_audit_express',
            chainId: 1,
            capMinor: 500000,
            enabled: true,
          }),
        }),
      });
      expect(created.status).toBe(201);
      const policyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(policyId).toBeTruthy();

      const published = await fetchJson(
        `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
        {
          method: 'POST',
        },
      );
      expect(published.status).toBe(200);
      expect(getPath(published.json, 'result', 'published')).toBe(true);
      expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
      expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-policy-publish-audit-express',
          actorUserId: 'user-policy-publish-audit-express',
          roles: ['admin'],
        },
        { category: 'POLICY', limit: 20 },
      );
      const publishEvent = auditEvents.find(
        (event) => String(event.action || '') === 'policy.publish',
      );
      expect(publishEvent).toBeTruthy();
      expect(getPath(publishEvent, 'metadata', 'policyId')).toBe(policyId);
      expect(getPath(publishEvent, 'metadata', 'policyName')).toBe(
        'Express published audit policy',
      );
      expect(getPath(publishEvent, 'metadata', 'policyKind')).toBe('GAS_SPONSORSHIP');
      expect(getPath(publishEvent, 'metadata', 'version')).toBe(1);
      expect(getPath(publishEvent, 'metadata', 'status')).toBe('PUBLISHED');
      expect(getPath(publishEvent, 'metadata', 'scopeType')).toBe('ENVIRONMENT');
      expect(getPath(publishEvent, 'metadata', 'projectId')).toBe(
        'proj_policy_publish_audit_express',
      );
      expect(getPath(publishEvent, 'metadata', 'environmentId')).toBe(
        'env_policy_publish_audit_express',
      );
      expect(getPath(publishEvent, 'metadata', 'published')).toBe(true);
      expect(publishEvent?.projectId).toBe('proj_policy_publish_audit_express');
      expect(publishEvent?.environmentId).toBe('env_policy_publish_audit_express');
    } finally {
      await srv.close();
    }
  });

  test('policy creation can attach a draft to scope in one request', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-create-attach-express',
        'policy-create-attach-admin',
      ),
      policies,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const environmentScopeId = 'env_policy_create_attach_express_1';
      const created = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Attached draft express',
          assignment: {
            scopeType: 'ENVIRONMENT',
            scopeId: environmentScopeId,
          },
        }),
      });
      expect(created.status).toBe(201);
      const createdPolicyId = String(getPath(created.json, 'policy', 'id') || '');
      expect(createdPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

      const listedAssignments = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments?scopeType=ENVIRONMENT&scopeId=${encodeURIComponent(environmentScopeId)}`,
        { method: 'GET' },
      );
      expect(listedAssignments.status).toBe(200);
      const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
        ? listedAssignments.json?.assignments
        : [];
      expect(assignmentRows.length).toBe(1);
      expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
        createdPolicyId,
      );
    } finally {
      await adminServer.close();
    }
  });

  test('policy assignments support precedence and drive policy coverage', async () => {
    const policies = createInMemoryConsolePolicyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_policy_assign_express_1',
          orgId: 'org-policy-assign-express',
          projectId: 'proj_policy_assign_express_1',
          environmentId: 'env_policy_assign_express_1',
        }),
      ],
    });
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-assign-express', 'policy-assign-admin'),
      policies,
      wallets,
    });
    const adminServer = await startExpressRouter(adminRouter);
    try {
      const listedWallets = await fetchJson(`${adminServer.baseUrl}/console/wallets`, {
        method: 'GET',
      });
      expect(listedWallets.status).toBe(200);
      const walletId = String(getPath(listedWallets.json, 'wallets', 0, 'id') || '');
      const projectId = String(getPath(listedWallets.json, 'wallets', 0, 'projectId') || '');
      const environmentId = String(
        getPath(listedWallets.json, 'wallets', 0, 'environmentId') || '',
      );
      expect(walletId).toBeTruthy();
      expect(projectId).toBeTruthy();
      expect(environmentId).toBeTruthy();

      const createProjectPolicy = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Project Policy Express',
        }),
      });
      expect(createProjectPolicy.status).toBe(201);
      const projectPolicyId = String(getPath(createProjectPolicy.json, 'policy', 'id') || '');
      expect(projectPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
      const publishProjectPolicy = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(projectPolicyId)}/publish`,
        { method: 'POST' },
      );
      expect(publishProjectPolicy.status).toBe(200);
      const createWalletPolicy = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Wallet Policy Express',
        }),
      });
      expect(createWalletPolicy.status).toBe(201);
      const walletPolicyId = String(getPath(createWalletPolicy.json, 'policy', 'id') || '');
      expect(walletPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

      const projectAssignment = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'PROJECT',
            scopeId: projectId,
            policyId: projectPolicyId,
          }),
        },
      );
      expect(projectAssignment.status).toBe(200);

      const walletAssignment = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'WALLET',
            scopeId: walletId,
            policyId: walletPolicyId,
          }),
        },
      );
      expect(walletAssignment.status).toBe(200);
      const walletAssignmentId = String(getPath(walletAssignment.json, 'assignment', 'id') || '');
      expect(walletAssignmentId).toBeTruthy();

      const listedAssignments = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments?scopeType=WALLET&scopeId=${encodeURIComponent(walletId)}`,
        { method: 'GET' },
      );
      expect(listedAssignments.status).toBe(200);
      const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
        ? listedAssignments.json?.assignments
        : [];
      expect(assignmentRows.length).toBe(1);
      expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
        walletPolicyId,
      );

      const walletCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(walletCoverage.status).toBe(200);
      const policyRows = Array.isArray(getPath(walletCoverage.json, 'coverage', 'policies'))
        ? (getPath(walletCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(policyRows.some((entry) => String(entry?.policyId || '') === projectPolicyId)).toBe(
        true,
      );
      expect(policyRows.some((entry) => String(entry?.policyId || '') === walletPolicyId)).toBe(
        false,
      );

      const publishWalletPolicy = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent(walletPolicyId)}/publish`,
        { method: 'POST' },
      );
      expect(publishWalletPolicy.status).toBe(200);

      const liveWalletCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(liveWalletCoverage.status).toBe(200);
      const livePolicyRows = Array.isArray(getPath(liveWalletCoverage.json, 'coverage', 'policies'))
        ? (getPath(liveWalletCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(livePolicyRows.some((entry) => String(entry?.policyId || '') === walletPolicyId)).toBe(
        true,
      );

      const removedWalletAssignment = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments/${encodeURIComponent(walletAssignmentId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(removedWalletAssignment.status).toBe(200);
      expect(getPath(removedWalletAssignment.json, 'removed')).toBe(true);

      const projectCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(projectCoverage.status).toBe(200);
      const projectPolicyRows = Array.isArray(getPath(projectCoverage.json, 'coverage', 'policies'))
        ? (getPath(projectCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(
        projectPolicyRows.some((entry) => String(entry?.policyId || '') === projectPolicyId),
      ).toBe(true);
    } finally {
      await adminServer.close();
    }

    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-policy-assign-express',
        'policy-assign-developer',
      ),
      policies,
      wallets,
    });
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const forbiddenAssignment = await fetchJson(
        `${developerServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'ORG',
            scopeId: 'org-policy-assign-express',
            policyId: 'policy_forbidden_org_assignment_express',
          }),
        },
      );
      expect(forbiddenAssignment.status).toBe(403);
      expect(forbiddenAssignment.json?.code).toBe('forbidden');
    } finally {
      await developerServer.close();
    }
  });

  test('API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const environmentId = 'default-project:prod';
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-1',
      projectId: 'default-project',
      actorUserId: 'user-1',
    });
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
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
          name: 'server-key',
          environmentId,
          kind: 'secret_key',
          scopes: ['accounts.create'],
          ipAllowlist: ['203.0.113.10/32'],
          expiresAt,
        }),
      });
      expect(created.status).toBe(201);
      const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      const createdSecret = String(getPath(created.json, 'secret') || '');
      expect(keyId).toBeTruthy();
      expect(createdSecret).toContain('sk_');
      expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);
      expect(String(getPath(created.json, 'apiKey', 'expiresAt') || '')).toBe(expiresAt);

      const listed = await fetchJson(`${srv.baseUrl}/console/api-keys`, { method: 'GET' });
      expect(listed.status).toBe(200);
      expect(Array.isArray(listed.json?.apiKeys)).toBe(true);
      expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
      expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

      const rotated = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'scheduled rotation' }),
        },
      );
      expect(rotated.status).toBe(200);
      const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
      expect(rotatedSecret).toContain('sk_');
      expect(rotatedSecret).not.toBe(createdSecret);
      expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

      const revoked = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}`,
        {
          method: 'DELETE',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'security incident' }),
        },
      );
      expect(revoked.status).toBe(200);
      expect(getPath(revoked.json, 'revoked')).toBe(true);
      expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');
      expect(getPath(revoked.json, 'apiKey', 'revokedReason')).toBe('security incident');

      const rotateRevoked = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
        },
      );
      expect(rotateRevoked.status).toBe(409);
      expect(rotateRevoked.json?.code).toBe('api_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('API key create validates environment scope against caller org', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-api-key-env-validation', 'user-api-key-admin'),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'invalid-environment-key',
          environmentId: 'env-missing',
          kind: 'secret_key',
          scopes: ['accounts.create'],
        }),
      });
      expect(created.status).toBe(400);
      expect(created.json?.code).toBe('invalid_environment');
    } finally {
      await srv.close();
    }
  });

  test('API key create rejects non-future expiresAt timestamp', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-api-key-expiry-validation',
        'user-api-key-admin',
      ),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'invalid-expiry-key',
          environmentId: 'default-project:prod',
          kind: 'secret_key',
          scopes: ['accounts.create'],
          expiresAt: '2000-01-01T00:00:00.000Z',
        }),
      });
      expect(created.status).toBe(400);
      expect(created.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('API key mutation routes require owner/admin/security_admin role', async () => {
    const orgId = 'org-api-key-rbac';
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const created = await apiKeys.createApiKey(
      { orgId, actorUserId: 'seed-admin', roles: ['admin'] },
      {
        name: 'seed-key',
        environmentId: 'env-rbac',
        kind: 'secret_key',
        scopes: ['accounts.create'],
      },
    );

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], orgId, 'user-api-key-developer'),
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const forbiddenCreate = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'developer-create-key',
          environmentId: 'env-rbac',
          kind: 'secret_key',
          scopes: ['accounts.create'],
        }),
      });
      expect(forbiddenCreate.status).toBe(403);
      expect(forbiddenCreate.json?.code).toBe('forbidden');

      const forbiddenRotate = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(created.apiKey.id)}/rotate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'developer rotate' }),
        },
      );
      expect(forbiddenRotate.status).toBe(403);
      expect(forbiddenRotate.json?.code).toBe('forbidden');

      const forbiddenDelete = await fetchJson(
        `${srv.baseUrl}/console/api-keys/${encodeURIComponent(created.apiKey.id)}`,
        { method: 'DELETE' },
      );
      expect(forbiddenDelete.status).toBe(403);
      expect(forbiddenDelete.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('webhook endpoint CRUD, deliveries, and replay flow works', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/hook',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const listed = await fetchJson(`${srv.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const endpoints = Array.isArray(listed.json?.endpoints) ? listed.json?.endpoints : [];
      expect(endpoints.length).toBe(1);
      expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

      const emitted = await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-test',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.paid',
          payload: {
            invoiceId: 'inv_router_1',
          },
        },
      );
      expect(emitted.attempted).toBe(1);
      expect(emitted.delivered).toBe(0);
      expect(emitted.failed).toBe(1);

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      expect(rows.length).toBe(1);
      expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
      expect(Number(getPath(deliveries.json, 'deliveries', 0, 'attemptCount') || 0)).toBe(1);
      const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
      expect(deliveryId).toBeTruthy();

      const attemptsBeforeReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts`,
        {
          method: 'GET',
        },
      );
      expect(attemptsBeforeReplay.status).toBe(200);
      expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

      const unresolvedDlq = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
        {
          method: 'GET',
        },
      );
      expect(unresolvedDlq.status).toBe(200);
      const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters)
        ? unresolvedDlq.json?.deadLetters
        : [];
      expect(unresolvedRows.length).toBe(1);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

      const replayed = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deliveryId }),
        },
      );
      expect(replayed.status).toBe(200);
      expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
      expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'attemptCount') || 0)).toBe(2);
      expect(Number(getPath(replayed.json, 'replay', 'delivery', 'replayCount') || 0)).toBe(1);

      const attemptsAfterReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`,
        {
          method: 'GET',
        },
      );
      expect(attemptsAfterReplay.status).toBe(200);
      const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts)
        ? attemptsAfterReplay.json?.attempts
        : [];
      expect(replayAttempts.length).toBe(1);
      expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'status')).toBe('SUCCEEDED');
      expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
      const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
      expect(attemptsNextCursor).toBeTruthy();

      const attemptsSecondPage = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`,
        {
          method: 'GET',
        },
      );
      expect(attemptsSecondPage.status).toBe(200);
      const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
        ? attemptsSecondPage.json?.attempts
        : [];
      expect(replayAttemptsSecondPage.length).toBe(1);
      expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
      expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

      const unresolvedAfterReplay = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
        {
          method: 'GET',
        },
      );
      expect(unresolvedAfterReplay.status).toBe(200);
      const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
        ? unresolvedAfterReplay.json?.deadLetters
        : [];
      expect(unresolvedRowsAfterReplay.length).toBe(0);

      const resolvedDlq = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`,
        {
          method: 'GET',
        },
      );
      expect(resolvedDlq.status).toBe(200);
      const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters)
        ? resolvedDlq.json?.deadLetters
        : [];
      expect(resolvedRows.length).toBe(1);
      expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
      expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

      const updated = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            status: 'DISABLED',
            eventCategories: ['wallet', 'policy'],
          }),
        },
      );
      expect(updated.status).toBe(200);
      expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

      const emittedDisabled = await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-test',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.paid',
          payload: {
            invoiceId: 'inv_router_2',
          },
        },
      );
      expect(emittedDisabled.attempted).toBe(0);
      expect(emittedDisabled.delivered).toBe(0);
      expect(emittedDisabled.failed).toBe(0);

      const deleted = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(deleted.status).toBe(200);
      expect(deleted.json?.removed).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('webhook endpoint create, update, delete, and replay append audit rows', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-webhook-audit-express',
        'user-webhook-audit-express',
      ),
      webhooks,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/express-webhook-audit',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const updated = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: 'https://example.com/express-webhook-audit-updated',
          }),
        },
      );
      expect(updated.status).toBe(200);

      const emitted = await webhooks.emitEvent(
        {
          orgId: 'org-webhook-audit-express',
          actorUserId: 'system-webhooks-audit-express',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.generated',
          payload: {
            invoiceId: 'inv_webhook_audit_express',
          },
        },
      );
      expect(emitted.attempted).toBe(1);
      expect(emitted.failed).toBe(1);

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        { method: 'GET' },
      );
      expect(deliveries.status).toBe(200);
      const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
      expect(deliveryId).toBeTruthy();

      const replayed = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deliveryId }),
        },
      );
      expect(replayed.status).toBe(200);
      expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');

      const deleted = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(200);
      expect(deleted.json?.removed).toBe(true);

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-webhook-audit-express',
          actorUserId: 'user-webhook-audit-express',
          roles: ['admin'],
        },
        { category: 'WEBHOOK', limit: 20 },
      );
      const webhookEvents = auditEvents.filter((event) =>
        [
          'webhook.endpoint.create',
          'webhook.endpoint.update',
          'webhook.endpoint.delete',
          'webhook.delivery.replay_requested',
        ].includes(String(event.action || '')),
      );
      expect(webhookEvents.map((event) => String(event.action || '')).sort()).toEqual([
        'webhook.delivery.replay_requested',
        'webhook.endpoint.create',
        'webhook.endpoint.delete',
        'webhook.endpoint.update',
      ]);
      expect(webhookEvents.every((event) => event.category === 'WEBHOOK')).toBe(true);
      expect(
        webhookEvents.every((event) => event.actorUserId === 'user-webhook-audit-express'),
      ).toBe(true);

      const webhookByAction = Object.fromEntries(
        webhookEvents.map((event) => [String(event.action || ''), event]),
      );
      expect(getPath(webhookByAction['webhook.endpoint.create'], 'metadata', 'endpointId')).toBe(
        endpointId,
      );
      expect(getPath(webhookByAction['webhook.endpoint.create'], 'metadata', 'endpointUrl')).toBe(
        'https://example.com/express-webhook-audit',
      );
      expect(getPath(webhookByAction['webhook.endpoint.update'], 'metadata', 'endpointUrl')).toBe(
        'https://example.com/express-webhook-audit-updated',
      );
      expect(
        getPath(webhookByAction['webhook.endpoint.update'], 'metadata', 'eventCategories'),
      ).toEqual(['billing']);
      expect(
        getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'endpointId'),
      ).toBe(endpointId);
      expect(
        getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'deliveryId'),
      ).toBe(deliveryId);
      expect(
        getPath(
          webhookByAction['webhook.delivery.replay_requested'],
          'metadata',
          'requestedDeliveryId',
        ),
      ).toBe(deliveryId);
      expect(
        getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'selectionMode'),
      ).toBe('explicit_delivery');
      expect(
        getPath(
          webhookByAction['webhook.delivery.replay_requested'],
          'metadata',
          'deliveryEventType',
        ),
      ).toBe('billing.invoice.generated');
      expect(
        Number(
          getPath(
            webhookByAction['webhook.delivery.replay_requested'],
            'metadata',
            'replayCount',
          ) || 0,
        ),
      ).toBe(1);
      expect(getPath(webhookByAction['webhook.endpoint.delete'], 'metadata', 'endpointId')).toBe(
        endpointId,
      );
      expect(getPath(webhookByAction['webhook.endpoint.delete'], 'metadata', 'endpointUrl')).toBe(
        'https://example.com/express-webhook-audit-updated',
      );
    } finally {
      await srv.close();
    }
  });

  test('webhook delivery failures append dead-letter and endpoint degraded observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
      endpointDegradedThreshold: 2,
      dispatcher: {
        dispatch: async () => ({
          ok: false,
          statusCode: 500,
          responseBody: 'temporary failure',
          errorMessage: 'upstream failure',
        }),
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/observability-webhook',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-observability',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.failed',
          payload: { invoiceId: 'inv_obs_webhook_1' },
        },
      );
      await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-observability',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.failed',
          payload: { invoiceId: 'inv_obs_webhook_2' },
        },
      );

      const deadLetterEvents = ingested.filter(
        (entry) => entry.event.eventType === 'webhook.delivery.dead_letter',
      );
      const degradedEvents = ingested.filter(
        (entry) => entry.event.eventType === 'webhook.endpoint.degraded',
      );
      expect(deadLetterEvents).toHaveLength(2);
      expect(degradedEvents).toHaveLength(1);
      expect(String(getPath(deadLetterEvents[0]?.event, 'metadata', 'endpointId') || '')).toBe(
        endpointId,
      );
      expect(
        Number(getPath(degradedEvents[0]?.event, 'metadata', 'unresolvedDeadLetterCount') || 0),
      ).toBe(2);
    } finally {
      await srv.close();
    }
  });

  test('webhook mutations require console config mutation role', async () => {
    const webhooks = createInMemoryConsoleWebhookService();
    const adminRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const developerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer']),
      webhooks,
    });
    const adminServer = await startExpressRouter(adminRouter);
    const developerServer = await startExpressRouter(developerRouter);
    try {
      const created = await fetchJson(`${adminServer.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/restricted-webhook',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const listed = await fetchJson(`${developerServer.baseUrl}/console/webhooks`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);

      const forbiddenCreate = await fetchJson(`${developerServer.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/forbidden-webhook',
          eventCategories: ['billing'],
        }),
      });
      expect(forbiddenCreate.status).toBe(403);
      expect(forbiddenCreate.json?.code).toBe('forbidden');

      const emitted = await webhooks.emitEvent(
        {
          orgId: 'org-1',
          actorUserId: 'system-webhooks-rbac-test',
          roles: ['ops'],
        },
        {
          eventType: 'billing.invoice.paid',
          payload: {
            invoiceId: 'inv_webhook_rbac_express',
          },
        },
      );
      expect(emitted.attempted).toBe(1);
      const deliveries = await fetchJson(
        `${adminServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        {
          method: 'GET',
        },
      );
      const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
      expect(deliveryId).toBeTruthy();

      const forbiddenUpdate = await fetchJson(
        `${developerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ status: 'DISABLED' }),
        },
      );
      expect(forbiddenUpdate.status).toBe(403);
      expect(forbiddenUpdate.json?.code).toBe('forbidden');

      const forbiddenReplay = await fetchJson(
        `${developerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ deliveryId }),
        },
      );
      expect(forbiddenReplay.status).toBe(403);
      expect(forbiddenReplay.json?.code).toBe('forbidden');

      const forbiddenDelete = await fetchJson(
        `${developerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        {
          method: 'DELETE',
        },
      );
      expect(forbiddenDelete.status).toBe(403);
      expect(forbiddenDelete.json?.code).toBe('forbidden');
    } finally {
      await adminServer.close();
      await developerServer.close();
    }
  });

  test('webhook list endpoints reject malformed cursor', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/bad-cursor-express',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(400);
      expect(deliveries.json?.code).toBe('invalid_query');

      const attempts = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const deadLetters = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`,
        {
          method: 'GET',
        },
      );
      expect(deadLetters.status).toBe(400);
      expect(deadLetters.json?.code).toBe('invalid_query');

      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
        {
          method: 'GET',
        },
      );
      expect(oversizedSortKey.status).toBe(400);
      expect(oversizedSortKey.json?.code).toBe('invalid_query');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/checkout-session returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/checkout-session creates checkout session', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          creditPackId: 'usd_25',
        }),
      });
      expect(created.status).toBe(201);
      const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
      const checkoutSessionUrl = String(getPath(created.json, 'checkoutSession', 'url') || '');
      expect(checkoutSessionId).toBeTruthy();
      expect(checkoutSessionUrl).toContain('https://checkout.stripe.com/pay/');
      expect(String(getPath(created.json, 'checkoutSession', 'customerRef') || '')).toContain(
        'cus_',
      );
      expect(getPath(created.json, 'checkoutSession', 'creditPackId')).toBe('usd_25');
      expect(Number(getPath(created.json, 'checkoutSession', 'amountMinor') || 0)).toBe(2500);
      expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
        /^\d{4}-\d{2}-\d{2}T/,
      );

      const customCreated = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
            cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
            creditPackId: 'usd_custom',
            customAmountMinor: 12345,
          }),
        },
      );
      expect(customCreated.status).toBe(201);
      expect(getPath(customCreated.json, 'checkoutSession', 'creditPackId')).toBe('usd_custom');
      expect(Number(getPath(customCreated.json, 'checkoutSession', 'amountMinor') || 0)).toBe(
        12345,
      );

      const invalid = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: '/dashboard/billing',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          creditPackId: 'usd_25',
        }),
      });
      expect(invalid.status).toBe(400);
      expect(invalid.json?.code).toBe('invalid_body');

      const missingCustomAmount = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
            cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
            creditPackId: 'usd_custom',
          }),
        },
      );
      expect(missingCustomAmount.status).toBe(400);
      expect(missingCustomAmount.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/checkout-session/reconcile settles a paid checkout session', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          creditPackId: 'usd_25',
        }),
      });
      expect(created.status).toBe(201);
      const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
      expect(checkoutSessionId).toBeTruthy();

      const reconciled = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            checkoutSessionId,
          }),
        },
      );
      expect(reconciled.status).toBe(200);
      expect(getPath(reconciled.json, 'result', 'settled')).toBe(true);
      expect(getPath(reconciled.json, 'result', 'settledNow')).toBe(true);
      expect(getPath(reconciled.json, 'result', 'purchase', 'status')).toBe('SETTLED');
      expect(getPath(reconciled.json, 'result', 'invoice', 'documentType')).toBe(
        'PURCHASE_RECEIPT',
      );

      const duplicate = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session/reconcile`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            checkoutSessionId,
          }),
        },
      );
      expect(duplicate.status).toBe(200);
      expect(getPath(duplicate.json, 'result', 'settled')).toBe(true);
      expect(getPath(duplicate.json, 'result', 'settledNow')).toBe(false);

      const overview = await fetchJson(`${srv.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(overview.status).toBe(200);
      expect(Number(getPath(overview.json, 'overview', 'creditBalanceMinor') || 0)).toBe(2500);

      const auditEvents = await audit.listEvents({
        orgId: 'org-1',
        actorUserId: 'user-1',
        roles: ['admin'],
      });
      const settlementEvents = auditEvents.filter(
        (event) => String(event.action || '') === 'billing.credit_purchase.settled',
      );
      expect(settlementEvents).toHaveLength(1);
      expect(settlementEvents[0]?.actorType).toBe('USER');
      expect(settlementEvents[0]?.actorUserId).toBe('user-1');
      expect(getPath(settlementEvents[0], 'metadata', 'purchaseId')).toBe(
        getPath(reconciled.json, 'result', 'purchase', 'id'),
      );
      expect(getPath(settlementEvents[0], 'metadata', 'receiptId')).toBe(
        getPath(reconciled.json, 'result', 'invoice', 'id'),
      );
      expect(getPath(settlementEvents[0], 'metadata', 'settlementSource')).toBe(
        'stripe_checkout_reconcile',
      );
      expect(getPath(settlementEvents[0], 'metadata', 'settlementEventId')).toBe(
        `stripe_checkout_reconcile:${checkoutSessionId}`,
      );
    } finally {
      await srv.close();
    }
  });

  test('GET /console/platform/billing/account resolves project-scoped lookup for platform_admin', async () => {
    const billing = createInMemoryConsoleBillingService({
      now: () => new Date('2026-03-20T00:00:00.000Z'),
    });
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const targetCtx = {
      orgId: 'org-platform-target-express',
      actorUserId: 'platform-user-express',
      roles: ['platform_admin'],
    };
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-platform-target-express',
      projectId: 'proj-platform-target-express',
      actorUserId: 'platform-user-express',
    });
    await teamRbac.bootstrapOwner({
      orgId: 'org-platform-target-express',
      actorUserId: 'owner-platform-target-express',
      roles: ['owner'],
      actorEmail: 'owner-platform-target-express@example.com',
      actorDisplayName: 'Owner Express',
    });
    await teamRbac.inviteMember(
      {
        orgId: 'org-platform-target-express',
        actorUserId: 'owner-platform-target-express',
        roles: ['owner'],
      },
      {
        userId: 'admin-platform-target-express',
        email: 'admin-platform-target-express@example.com',
        displayName: 'Admin Express',
        roles: [{ role: 'admin', scope: 'ORG' }],
      },
    );
    await billing.grantManualSupportCredit(targetCtx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Seed manual credit',
      idempotencyKey: 'platform-lookup-credit-express',
    });
    await billing.recordUsageEvent(targetCtx, {
      walletId: 'wallet-platform-express',
      action: 'transfer',
      succeeded: true,
      occurredAt: '2026-02-15T00:00:00.000Z',
      sourceEventId: 'usage-platform-express',
    });

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-express',
        'platform-user-express',
      ),
      billing,
      orgProjectEnv,
      teamRbac,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/platform/billing/account?projectId=${encodeURIComponent(
          'proj-platform-target-express',
        )}&periodMonthUtc=2026-03&eventType=MANUAL_ADJUSTMENT`,
        { method: 'GET' },
      );
      expect(res.status).toBe(200);
      expect(String(getPath(res.json, 'result', 'organization', 'id') || '')).toBe(
        'org-platform-target-express',
      );
      expect(String(getPath(res.json, 'result', 'project', 'id') || '')).toBe(
        'proj-platform-target-express',
      );
      expect(Number(getPath(res.json, 'result', 'overview', 'creditBalanceMinor') || 0)).toBe(900);
      const entries = Array.isArray(getPath(res.json, 'result', 'activity', 'entries'))
        ? (getPath(res.json, 'result', 'activity', 'entries') as any[])
        : [];
      expect(entries).toHaveLength(1);
      expect(String(entries[0]?.type || '')).toBe('MANUAL_ADJUSTMENT');
      expect(String(entries[0]?.reasonCode || '')).toBe('incident_credit');
      const teamMembers = Array.isArray(getPath(res.json, 'result', 'teamMembers'))
        ? (getPath(res.json, 'result', 'teamMembers') as any[])
        : [];
      expect(teamMembers.map((entry) => String(entry?.displayName || ''))).toEqual([
        'Owner Express',
        'Admin Express',
      ]);
      expect(teamMembers.map((entry) => String(entry?.access || ''))).toEqual(['OWNER', 'ADMIN']);
      expect(teamMembers.map((entry) => String(entry?.status || ''))).toEqual(['ACTIVE', 'ACTIVE']);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/platform/billing/search finds organization matches for platform_admin', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const searchCtx = {
      orgId: 'org-platform-search-primary-express',
      actorUserId: 'platform-user-express',
      roles: ['platform_admin'],
    };
    await orgProjectEnv.upsertOrganization(searchCtx, {
      name: 'Watchbook Marketplace',
      slug: 'watchbook-marketplace',
    });
    await orgProjectEnv.createProject(searchCtx, {
      id: 'proj-platform-search-primary-express',
      name: 'Marketplace API',
      liveEnvironmentsEnabled: true,
    });
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-platform-search-secondary-express',
        actorUserId: 'platform-user-express',
        roles: ['platform_admin'],
      },
      {
        name: 'Acme Labs',
        slug: 'acme-labs',
      },
    );

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-express',
        'platform-user-express',
      ),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/platform/billing/search?query=${encodeURIComponent('watchbook')}`,
        { method: 'GET' },
      );
      expect(res.status).toBe(200);
      const organizations = Array.isArray(getPath(res.json, 'organizations'))
        ? (getPath(res.json, 'organizations') as any[])
        : [];
      expect(organizations).toHaveLength(1);
      expect(String(organizations[0]?.id || '')).toBe('org-platform-search-primary-express');
      expect(String(organizations[0]?.name || '')).toBe('Watchbook Marketplace');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/platform/billing/search returns the 5 most recent organizations when query is empty', async () => {
    let currentNow = new Date('2026-03-01T00:00:00.000Z');
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService({
      now: () => currentNow,
    });
    const organizations = [
      ['org-platform-recent-1-express', 'Recent One'],
      ['org-platform-recent-2-express', 'Recent Two'],
      ['org-platform-recent-3-express', 'Recent Three'],
      ['org-platform-recent-4-express', 'Recent Four'],
      ['org-platform-recent-5-express', 'Recent Five'],
      ['org-platform-recent-6-express', 'Recent Six'],
    ] as const;
    for (const [index, [orgId, name]] of organizations.entries()) {
      currentNow = new Date(`2026-03-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`);
      await orgProjectEnv.upsertOrganization(
        {
          orgId,
          actorUserId: 'platform-user-express',
          roles: ['platform_admin'],
        },
        {
          name,
          slug: name.toLowerCase().replace(/\s+/g, '-'),
        },
      );
    }

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-express',
        'platform-user-express',
      ),
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/platform/billing/search?query=&limit=5`, {
        method: 'GET',
      });
      expect(res.status).toBe(200);
      const rows = Array.isArray(getPath(res.json, 'organizations'))
        ? (getPath(res.json, 'organizations') as any[])
        : [];
      expect(rows.map((row) => String(row?.id || ''))).toEqual([
        'org-platform-recent-6-express',
        'org-platform-recent-5-express',
        'org-platform-recent-4-express',
        'org-platform-recent-3-express',
        'org-platform-recent-2-express',
      ]);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/platform/billing/adjustments/support-credit applies to target org for platform_admin', async () => {
    const billing = createInMemoryConsoleBillingService({
      now: () => new Date('2026-03-20T00:00:00.000Z'),
    });
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-platform-adjust-target-express',
      projectId: 'proj-platform-adjust-target-express',
      actorUserId: 'platform-user-express',
    });

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-express',
        'platform-user-express',
      ),
      billing,
      audit,
      orgProjectEnv,
      teamRbac,
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(
        `${srv.baseUrl}/console/platform/billing/adjustments/support-credit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            orgId: 'org-platform-adjust-target-express',
            amountMinor: 1500,
            reasonCode: 'incident_credit',
            note: 'Applied by platform admin',
            idempotencyKey: 'platform-adjust-credit-express',
          }),
        },
      );
      expect(res.status).toBe(201);
      expect(String(getPath(res.json, 'result', 'adjustment', 'orgId') || '')).toBe(
        'org-platform-adjust-target-express',
      );
      expect(Number(getPath(res.json, 'result', 'creditBalanceMinor') || 0)).toBe(1500);

      const lookup = await fetchJson(
        `${srv.baseUrl}/console/platform/billing/account?orgId=${encodeURIComponent(
          'org-platform-adjust-target-express',
        )}`,
        { method: 'GET' },
      );
      expect(lookup.status).toBe(200);
      expect(Number(getPath(lookup.json, 'result', 'overview', 'creditBalanceMinor') || 0)).toBe(
        1500,
      );

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-platform-adjust-target-express',
          actorUserId: 'platform-user-express',
          roles: ['platform_admin'],
        },
        { limit: 10 },
      );
      const adjustmentAudit = auditEvents.find(
        (event) => String(event.action || '') === 'billing.adjustment.support_credit',
      );
      expect(String(adjustmentAudit?.metadata?.organizationId || '')).toBe(
        'org-platform-adjust-target-express',
      );
      expect(String(adjustmentAudit?.metadata?.organizationName || '')).toBe(
        'Default Organization',
      );
      expect(String(adjustmentAudit?.metadata?.note || '')).toBe('Applied by platform admin');
      expect(String(adjustmentAudit?.metadata?.platformBilling || '')).toBe('true');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/adjustments/support-credit requires platform_admin role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/adjustments/support-credit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amountMinor: 100,
          reasonCode: 'incident_credit',
          note: 'Should be rejected',
          idempotencyKey: 'manual-credit-express-forbidden',
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
      expect(String(res.json?.message || '')).toContain('platform_admin');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/adjustments/admin-debit allows platform_admin for large debit amounts', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/adjustments/admin-debit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amountMinor: 50000,
          reasonCode: 'large_debit_correction',
          note: 'Platform operator approved large debit',
          idempotencyKey: 'manual-debit-express-large-platform',
        }),
      });
      expect(res.status).toBe(201);
      expect(Number(getPath(res.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(-50000);
    } finally {
      await srv.close();
    }
  });

  test('manual billing adjustment routes append audited support credits and admin debits (express)', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin', 'billing_admin']),
      billing,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const supportCredit = await fetchJson(
        `${srv.baseUrl}/console/billing/adjustments/support-credit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amountMinor: 1200,
            reasonCode: 'incident_credit',
            note: 'Applied support credit after incident review',
            idempotencyKey: 'manual-credit-express-1',
          }),
        },
      );
      expect(supportCredit.status).toBe(201);
      expect(getPath(supportCredit.json, 'result', 'created')).toBe(true);
      expect(Number(getPath(supportCredit.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(
        1200,
      );

      const duplicateCredit = await fetchJson(
        `${srv.baseUrl}/console/billing/adjustments/support-credit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amountMinor: 1200,
            reasonCode: 'incident_credit',
            note: 'Applied support credit after incident review',
            idempotencyKey: 'manual-credit-express-1',
          }),
        },
      );
      expect(duplicateCredit.status).toBe(200);
      expect(getPath(duplicateCredit.json, 'result', 'created')).toBe(false);
      expect(getPath(duplicateCredit.json, 'result', 'adjustment', 'id')).toBe(
        getPath(supportCredit.json, 'result', 'adjustment', 'id'),
      );

      const adminDebit = await fetchJson(`${srv.baseUrl}/console/billing/adjustments/admin-debit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amountMinor: 200,
          reasonCode: 'duplicate_credit_correction',
          note: 'Corrected duplicate support credit',
          idempotencyKey: 'manual-debit-express-1',
        }),
      });
      expect(adminDebit.status).toBe(201);
      expect(getPath(adminDebit.json, 'result', 'created')).toBe(true);
      expect(Number(getPath(adminDebit.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(
        -200,
      );

      const overview = await fetchJson(`${srv.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(overview.status).toBe(200);
      expect(Number(getPath(overview.json, 'overview', 'creditBalanceMinor') || 0)).toBe(1000);

      const activity = await fetchJson(`${srv.baseUrl}/console/billing/account/activity?limit=5`, {
        method: 'GET',
      });
      expect(activity.status).toBe(200);
      expect(
        (Array.isArray(getPath(activity.json, 'activity', 'entries'))
          ? (getPath(activity.json, 'activity', 'entries') as unknown[])
          : []
        ).map((entry) => Number(getPath(entry, 'amountMinor') || 0)),
      ).toEqual([-200, 1200]);

      const auditEvents = await audit.listEvents(
        { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
        { limit: 20 },
      );
      expect(
        auditEvents
          .filter((event) =>
            ['billing.adjustment.support_credit', 'billing.adjustment.admin_debit'].includes(
              String(event.action || ''),
            ),
          )
          .map((event) => String(event.action || '')),
      ).toEqual([
        'billing.adjustment.admin_debit',
        'billing.adjustment.support_credit',
        'billing.adjustment.support_credit',
      ]);
    } finally {
      await srv.close();
    }
  });

  test('manual billing adjustments emit sponsorship balance transition webhook events and observability logs (express)', async () => {
    const billing = createInMemoryConsoleBillingService();
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    await billing.grantManualSupportCredit(
      { orgId: 'org-1', actorUserId: 'seed-user', roles: ['platform_admin'] },
      {
        amountMinor: 4000,
        reasonCode: 'seed_credit',
        note: 'Seed balance for transition events',
        idempotencyKey: 'seed-balance-transition-express',
      },
    );
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const endpoint = await webhooks.createEndpoint(
      { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
      {
        url: 'https://example.com/billing-transition-express',
        eventCategories: ['billing'],
      },
    );
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin']),
      billing,
      webhooks,
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });
    const srv = await startExpressRouter(router);
    try {
      const lowBalance = await fetchJson(`${srv.baseUrl}/console/billing/adjustments/admin-debit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amountMinor: 2500,
          reasonCode: 'lower_to_threshold',
          note: 'Drop balance into low state',
          idempotencyKey: 'balance-transition-express-low',
        }),
      });
      expect(lowBalance.status).toBe(201);

      const blocked = await fetchJson(`${srv.baseUrl}/console/billing/adjustments/admin-debit`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          amountMinor: 2000,
          reasonCode: 'lower_to_blocked',
          note: 'Drop balance into blocked state',
          idempotencyKey: 'balance-transition-express-blocked',
        }),
      });
      expect(blocked.status).toBe(201);

      const recovered = await fetchJson(
        `${srv.baseUrl}/console/billing/adjustments/support-credit`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amountMinor: 5000,
            reasonCode: 'restore_balance',
            note: 'Recover balance to healthy',
            idempotencyKey: 'balance-transition-express-recovered',
          }),
        },
      );
      expect(recovered.status).toBe(201);

      const deliveries = await webhooks.listDeliveries(
        { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
        endpoint.id,
      );
      expect(sortedWebhookDeliveryEventTypes(deliveries)).toEqual([
        'billing.balance.blocked',
        'billing.balance.low_balance',
        'billing.balance.recovered',
      ]);
      expect(ingested.map((entry) => String(entry.event.eventType || ''))).toEqual([
        'billing.balance.low_balance',
        'billing.balance.blocked',
        'billing.balance.recovered',
      ]);
      expect(
        ingested.map((entry) => String(getPath(entry.event, 'metadata', 'currentState') || '')),
      ).toEqual(['LOW_BALANCE', 'BLOCKED', 'HEALTHY']);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId: 'evt_missing_secret',
          providerRef: 'pi_provider_missing',
          providerStatus: 'SUCCEEDED',
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('stripe_webhook_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('Stripe webhook settles prepaid purchase receipts idempotently', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const secret = 'whsec_console_router_projection_test';
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      audit,
      billingStripeWebhookSecret: secret,
    });
    const srv = await startExpressRouter(router);
    try {
      const checkoutSession = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/checkout-session`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
            cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
            creditPackId: 'usd_25',
          }),
        },
      );
      expect(checkoutSession.status).toBe(201);
      const checkoutSessionId = String(
        getPath(checkoutSession.json, 'checkoutSession', 'id') || '',
      );
      const providerCustomerRef = String(
        getPath(checkoutSession.json, 'checkoutSession', 'customerRef') || '',
      );
      expect(checkoutSessionId).toBeTruthy();
      expect(providerCustomerRef).toBeTruthy();

      const purchaseEventId = `evt_express_purchase_projection_${Date.now()}`;
      const projectedPurchase = await fetchJson(`${srv.baseUrl}/console/billing/stripe/webhook`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-console-stripe-webhook-secret': secret,
        },
        body: JSON.stringify({
          eventId: purchaseEventId,
          eventType: 'checkout.session.completed',
          orgId: 'org-1',
          checkoutSessionId,
          providerCustomerRef,
          providerRef: checkoutSessionId,
        }),
      });
      expect(projectedPurchase.status).toBe(200);
      expect(projectedPurchase.json?.accepted).toBe(true);
      expect(getPath(projectedPurchase.json, 'purchase', 'status')).toBe('SETTLED');
      expect(getPath(projectedPurchase.json, 'purchase', 'creditPackId')).toBe('usd_25');
      const receiptInvoiceId = String(getPath(projectedPurchase.json, 'invoice', 'id') || '');
      expect(receiptInvoiceId).toContain('receipt_');

      const projectedPurchaseDuplicate = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/webhook`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-console-stripe-webhook-secret': secret,
          },
          body: JSON.stringify({
            eventId: purchaseEventId,
            eventType: 'checkout.session.completed',
            orgId: 'org-1',
            checkoutSessionId,
            providerCustomerRef,
            providerRef: checkoutSessionId,
          }),
        },
      );
      expect(projectedPurchaseDuplicate.status).toBe(200);
      expect(projectedPurchaseDuplicate.json?.accepted).toBe(false);
      expect(getPath(projectedPurchaseDuplicate.json, 'purchase', 'status')).toBe('SETTLED');

      const overviewAfter = await fetchJson(`${srv.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(overviewAfter.status).toBe(200);
      expect(Number(getPath(overviewAfter.json, 'overview', 'creditBalanceMinor') || 0)).toBe(2500);

      const auditEvents = await audit.listEvents({
        orgId: 'org-1',
        actorUserId: 'user-1',
        roles: ['admin'],
      });
      const settlementEvents = auditEvents.filter(
        (event) => String(event.action || '') === 'billing.credit_purchase.settled',
      );
      expect(settlementEvents).toHaveLength(1);
      expect(settlementEvents[0]?.category).toBe('BILLING');
      expect(settlementEvents[0]?.actorType).toBe('SYSTEM');
      expect(settlementEvents[0]?.actorUserId).toBe('system-stripe-webhook');
      expect(getPath(settlementEvents[0], 'metadata', 'purchaseId')).toBe(
        getPath(projectedPurchase.json, 'purchase', 'id'),
      );
      expect(getPath(settlementEvents[0], 'metadata', 'receiptId')).toBe(receiptInvoiceId);
      expect(getPath(settlementEvents[0], 'metadata', 'settlementSource')).toBe('stripe_webhook');
      expect(getPath(settlementEvents[0], 'metadata', 'settlementEventId')).toBe(purchaseEventId);
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/invoices/:id/pdf returns billing document PDF export', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      const periodMonthUtc = String(getPath(invoices.json, 'invoices', 0, 'periodMonthUtc') || '');
      expect(invoiceId).toBeTruthy();
      expect(periodMonthUtc).toMatch(/^\d{4}-\d{2}$/);

      const pdf = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(invoiceId)}/pdf`,
        {
          method: 'GET',
        },
      );
      expect(pdf.status).toBe(200);
      expect(String(pdf.headers.get('content-type') || '')).toContain('application/pdf');
      expect(String(pdf.headers.get('content-disposition') || '')).toContain(
        `statement_${periodMonthUtc}_${invoiceId}.pdf`,
      );
      expect(pdf.text.startsWith('%PDF-1.4')).toBe(true);
      expect(pdf.text).toContain('Usage statement');
      expect(pdf.text).toContain(`Organization: org-1`);
      expect(pdf.text).toContain(`Document ID: ${invoiceId}`);
      expect(pdf.text).toContain(
        'Visibility: Customer-facing export \\(internal ledger adjustments excluded\\).',
      );

      const auditEvents = await audit.listEvents({
        orgId: 'org-1',
        actorUserId: 'user-1',
        roles: ['admin'],
      });
      expect(auditEvents.length).toBe(1);
      expect(auditEvents[0]?.action).toBe('billing.invoice.pdf_export');
      expect(auditEvents[0]?.category).toBe('BILLING');
      expect(
        String((auditEvents[0]?.metadata as Record<string, unknown>)?.exportPolicy || ''),
      ).toBe('CUSTOMER_FACING_EXCLUDES_INTERNAL_ACTIVITY');
      expect(getPath(auditEvents[0], 'metadata', 'invoiceId')).toBe(invoiceId);
      expect(getPath(auditEvents[0], 'metadata', 'exportPolicy')).toBe(
        'CUSTOMER_FACING_EXCLUDES_INTERNAL_ACTIVITY',
      );

      const missing = await fetchJson(`${srv.baseUrl}/console/billing/invoices/inv_missing/pdf`, {
        method: 'GET',
      });
      expect(missing.status).toBe(404);
      expect(missing.json?.code).toBe('invoice_not_found');
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/invoices supports server-side filters, pagination, and activity', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const billingCtx = {
      orgId: 'org-1',
      actorUserId: 'admin-activity-user',
      roles: ['admin'],
    };
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_january_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_january_1',
      occurredAt: '2026-01-09T00:00:00.000Z',
    });
    await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-01' });
    current = new Date('2026-02-20T00:00:00.000Z');
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_february_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_february_1',
      occurredAt: '2026-02-11T00:00:00.000Z',
    });
    await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-02' });
    current = new Date('2026-03-20T00:00:00.000Z');
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_march_1',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_march_1',
      occurredAt: '2026-03-15T00:00:00.000Z',
    });
    const march = await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-03' });
    const checkoutSession = await billing.createStripeCheckoutSession(billingCtx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
      creditPackId: 'usd_25',
    });
    await billing.processStripeWebhookEvent({
      eventId: 'evt_billing_purchase_settled',
      eventType: 'checkout.session.completed',
      orgId: billingCtx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });

    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const firstPage = await fetchJson(`${srv.baseUrl}/console/billing/invoices?limit=1`, {
        method: 'GET',
      });
      expect(firstPage.status).toBe(200);
      expect(Array.isArray(firstPage.json?.invoices)).toBe(true);
      expect((firstPage.json?.invoices as unknown[]).length).toBe(1);
      expect(Number(firstPage.json?.totalCount || 0)).toBe(4);
      expect(String(firstPage.json?.nextCursor || '')).toBeTruthy();
      expect(Number(getPath(firstPage.json, 'summary', 'receiptCount') || 0)).toBe(1);
      expect(Number(getPath(firstPage.json, 'summary', 'statementCount') || 0)).toBe(3);

      const secondPage = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices?limit=1&cursor=${encodeURIComponent(String(firstPage.json?.nextCursor || ''))}`,
        {
          method: 'GET',
        },
      );
      expect(secondPage.status).toBe(200);
      expect((secondPage.json?.invoices as unknown[]).length).toBe(1);
      expect(getPath(firstPage.json, 'invoices', 0, 'id')).not.toBe(
        getPath(secondPage.json, 'invoices', 0, 'id'),
      );

      const paid = await fetchJson(`${srv.baseUrl}/console/billing/invoices?status=PAID`, {
        method: 'GET',
      });
      expect(paid.status).toBe(200);
      expect(Number(paid.json?.totalCount || 0)).toBe(4);
      expect(Number(getPath(paid.json, 'summary', 'paidCount') || 0)).toBe(4);

      const receipts = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices?documentType=PURCHASE_RECEIPT`,
        {
          method: 'GET',
        },
      );
      expect(receipts.status).toBe(200);
      expect(Number(receipts.json?.totalCount || 0)).toBe(1);
      expect(getPath(receipts.json, 'invoices', 0, 'documentType')).toBe('PURCHASE_RECEIPT');

      const february = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices?documentType=USAGE_STATEMENT&periodMonthUtc=2026-02`,
        {
          method: 'GET',
        },
      );
      expect(february.status).toBe(200);
      expect(Number(february.json?.totalCount || 0)).toBe(1);
      expect(getPath(february.json, 'invoices', 0, 'periodMonthUtc')).toBe('2026-02');
      expect(getPath(february.json, 'invoices', 0, 'documentType')).toBe('USAGE_STATEMENT');

      const activity = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(march.invoice.id)}/activity`,
        {
          method: 'GET',
        },
      );
      expect(activity.status).toBe(200);
      const entries = Array.isArray(getPath(activity.json, 'activity', 'entries'))
        ? (getPath(activity.json, 'activity', 'entries') as Array<Record<string, unknown>>)
        : [];
      expect(entries.length).toBeGreaterThanOrEqual(2);
      expect(
        entries.some(
          (entry) =>
            String(entry.type || '') === 'LEDGER' && String(entry.toState || '') === 'USAGE_DEBIT',
        ),
      ).toBe(true);
    } finally {
      await srv.close();
    }
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const e1 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: 'usage_evt_1',
        }),
      });
      expect(e1.status).toBe(200);
      expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
      expect(getPath(e1.json, 'result', 'counted')).toBe(true);
      expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
      const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const e2 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_1',
          action: 'swap',
          succeeded: true,
          sourceEventId: 'usage_evt_2',
        }),
      });
      expect(e2.status).toBe(200);
      expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);

      const e3 = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(e3.status).toBe(200);
      expect(Number(getPath(e3.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const excluded = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_3',
          action: 'wallet_created',
          succeeded: true,
          sourceEventId: 'usage_evt_4',
        }),
      });
      expect(excluded.status).toBe(200);
      expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const duplicate = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_2',
          action: 'approve',
          succeeded: true,
          sourceEventId: 'usage_evt_3',
        }),
      });
      expect(duplicate.status).toBe(200);
      expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
      expect(getPath(duplicate.json, 'result', 'counted')).toBe(false);
      expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

      const usage = await fetchJson(
        `${srv.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        {
          method: 'GET',
        },
      );
      expect(usage.status).toBe(200);
      expect(getPath(usage.json, 'usage', 'usageMetricVersion')).toBe('maw_v1');
      expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
      expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/usage/events requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_usage_role_express',
          action: 'transfer',
          succeeded: true,
          sourceEventId: 'usage_role_express_1',
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-01',
        }),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('billing read routes require billing read role', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-billing-read-role-1',
        'user-billing-read-role-1',
      ),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      for (const path of [
        '/console/billing/overview',
        '/console/billing/account/activity?limit=5',
        '/console/billing/usage/monthly-active-wallets?monthUtc=2026-03',
        '/console/billing/invoices',
        '/console/billing/invoices/inv_missing',
        '/console/billing/invoices/inv_missing/pdf',
        '/console/billing/invoices/inv_missing/activity',
        '/console/billing/invoices/inv_missing/line-items',
      ]) {
        const res = await fetchJson(`${srv.baseUrl}${path}`, { method: 'GET' });
        expect(res.status, path).toBe(403);
        expect(res.json?.code, path).toBe('forbidden');
      }
    } finally {
      await srv.close();
    }
  });

  test('billing_admin can access billing read routes', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin'], 'org-1', 'user-billing-admin-read-1'),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      const overview = await fetchJson(`${srv.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(overview.status).toBe(200);

      const invoices = await fetchJson(`${srv.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
    } finally {
      await srv.close();
    }
  });

  test('invoice generation endpoint returns deterministic prepaid statement line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing,
    });
    const srv = await startExpressRouter(router);
    try {
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_1',
          action: 'transfer',
          succeeded: true,
          occurredAt: '2026-01-05T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_1',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_2',
          action: 'swap',
          succeeded: true,
          occurredAt: '2026-01-06T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_2',
        }),
      });
      await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_gen_3',
          action: 'wallet_created',
          succeeded: true,
          occurredAt: '2026-01-07T01:00:00.000Z',
          sourceEventId: 'router_gen_evt_3',
        }),
      });

      const generated = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ periodMonthUtc: '2026-01' }),
      });
      expect(generated.status).toBe(200);
      expect(getPath(generated.json, 'generation', 'generated')).toBe(false);
      expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(
        600,
      );
      const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
      expect(invoiceId).toBeTruthy();

      const lineItems = await fetchJson(
        `${srv.baseUrl}/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`,
        {
          method: 'GET',
        },
      );
      expect(lineItems.status).toBe(200);
      const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
      expect(items.length).toBe(1);
      expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE_DEBIT"');
    } finally {
      await srv.close();
    }
  });

  test('billing invoice generation appends audit rows', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-billing-invoice-audit-express',
        'user-billing-invoice-audit-express',
      ),
      billing,
      audit,
    });
    const srv = await startExpressRouter(router);
    try {
      const usage = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_invoice_audit_express',
          action: 'transfer',
          succeeded: true,
          occurredAt: '2026-03-05T01:00:00.000Z',
          sourceEventId: 'usage_evt_invoice_audit_express',
        }),
      });
      expect(usage.status).toBe(200);

      const generated = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-03',
        }),
      });
      expect(generated.status).toBe(200);
      const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
      expect(invoiceId).toBeTruthy();

      const auditEvents = await audit.listEvents(
        {
          orgId: 'org-billing-invoice-audit-express',
          actorUserId: 'user-billing-invoice-audit-express',
          roles: ['admin'],
        },
        { category: 'BILLING', limit: 20 },
      );
      const invoiceEvent = auditEvents.find(
        (event) => String(event.action || '') === 'billing.invoice.generated',
      );
      expect(invoiceEvent).toBeTruthy();
      expect(getPath(invoiceEvent, 'metadata', 'invoiceId')).toBe(invoiceId);
      expect(getPath(invoiceEvent, 'metadata', 'periodMonthUtc')).toBe('2026-03');
      expect(getPath(invoiceEvent, 'metadata', 'invoiceDocumentType')).toBe('USAGE_STATEMENT');
      expect(getPath(invoiceEvent, 'metadata', 'monthlyActiveWallets')).toBe(1);
      expect(getPath(invoiceEvent, 'metadata', 'lineItemCount')).toBe(
        Array.isArray(getPath(generated.json, 'generation', 'lineItems'))
          ? (getPath(generated.json, 'generation', 'lineItems') as any[]).length
          : 0,
      );
      expect(getPath(invoiceEvent, 'metadata', 'generated')).toBe(
        getPath(generated.json, 'generation', 'generated'),
      );
    } finally {
      await srv.close();
    }
  });

  test('billing document generation emits webhook events when webhook endpoint is configured', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });
    const srv = await startExpressRouter(router);
    try {
      const endpointCreated = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/billing-events',
          eventCategories: ['billing'],
        }),
      });
      expect(endpointCreated.status).toBe(201);
      const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const usage = await fetchJson(`${srv.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_webhook_invoice_generated',
          action: 'transfer',
          succeeded: true,
          sourceEventId: 'usage_evt_webhook_invoice_generated',
        }),
      });
      expect(usage.status).toBe(200);

      const generated = await fetchJson(`${srv.baseUrl}/console/billing/invoices/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          periodMonthUtc: '2026-03',
        }),
      });
      expect(generated.status).toBe(200);
      expect(String(getPath(generated.json, 'generation', 'invoice', 'id') || '')).toBeTruthy();

      const deliveries = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        {
          method: 'GET',
        },
      );
      expect(deliveries.status).toBe(200);
      const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
      const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
      expect(eventTypes).toContain('billing.invoice.generated');
      expect(rows.length).toBeGreaterThanOrEqual(1);

      const pageOne = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`,
        {
          method: 'GET',
        },
      );
      expect(pageOne.status).toBe(200);
      const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
      expect(pageOneRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await srv.close();
    }
  });
});

test.describe('console router (cloudflare)', () => {
  test('GET /console/healthz works', async () => {
    const handler = createCloudflareConsoleRouter({ healthz: true });
    const res = await callCf(handler, { method: 'GET', path: '/console/healthz' });
    expect(res.status).toBe(200);
    expect(res.json?.service).toBe('console');
  });

  test('GET /console/webhooks returns webhooks_not_configured without webhook service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('webhooks_not_configured');
  });

  test('GET /console/webhooks rejects Postgres tenant routes in Cloudflare runtime', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      tenantStorageRouteResolver: postgresTenantStorageRouteResolver,
      tenantStorageNamespace: 'seams',
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(res.status).toBe(500);
    expect(res.json?.code).toBe('tenant_storage_backend_not_supported_in_cloudflare_runtime');
    expect(res.json?.route).toMatchObject({
      backendFamily: 'postgres',
      namespace: 'seams',
      orgId: 'org-1',
      routeVersion: 2,
    });
  });

  test('GET /console/api-keys returns api_keys_not_configured without API key service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('api_keys_not_configured');
  });

  test('GET /console/org returns org_project_env_not_configured without org/project/env service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('org_project_env_not_configured');
  });

  test('GET /console/members returns team_rbac_not_configured without Team RBAC service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/members',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('team_rbac_not_configured');
  });

  test('GET /console/approvals returns approvals_not_configured without approvals service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('approvals_not_configured');
  });

  test('GET /console/audit/events returns audit_not_configured without audit service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/events',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('audit_not_configured');
  });

  test('GET /console/audit/exports returns audit_exports_not_configured without export service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/exports',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('audit_exports_not_configured');
  });

  test('GET /console/observability/summary returns observability_not_configured without service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/summary',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('observability_not_configured');
  });

  test('cloudflare GET /console/observability/* returns scaffolded responses when service is configured', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['support'], 'org-observability-cf', 'user-observability-cf'),
      observability: createInMemoryConsoleObservabilityService(),
    });

    const summary = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/summary',
    });
    expect(summary.status).toBe(200);
    expect(getPath(summary.json, 'summary', 'status', 'state')).toBe('not_configured');

    const events = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/events?limit=5',
    });
    expect(events.status).toBe(200);
    expect(getPath(events.json, 'status', 'state')).toBe('not_configured');
    expect(Array.isArray(events.json?.events)).toBe(true);
    expect(events.json?.totalPages).toBe(1);

    const timeseries = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/timeseries?bucketMinutes=5',
    });
    expect(timeseries.status).toBe(200);
    expect(getPath(timeseries.json, 'status', 'state')).toBe('not_configured');
    expect(Array.isArray(timeseries.json?.buckets)).toBe(true);

    const services = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/services?limit=10',
    });
    expect(services.status).toBe(200);
    expect(getPath(services.json, 'status', 'state')).toBe('not_configured');
    expect(Array.isArray(services.json?.services)).toBe(true);
  });

  test('cloudflare GET /console/observability/* does not emit durable observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['support'],
        'org-observability-cf-read-noise',
        'user-observability-cf-read-noise',
      ),
      observability: createInMemoryConsoleObservabilityService(),
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });
    const paths = [
      '/console/observability/summary',
      '/console/observability/events?limit=5',
      '/console/observability/timeseries?bucketMinutes=5',
      '/console/observability/services?limit=10',
    ];
    for (const path of paths) {
      const res = await callCf(handler, { method: 'GET', path });
      expect(res.status).toBe(200);
    }
    expect(ingested).toEqual([]);
  });

  test('cloudflare GET /console/observability/* requires observability read role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-observability-cf-forbidden',
        'user-observability-cf-forbidden',
      ),
      observability: createInMemoryConsoleObservabilityService(),
    });
    const paths = [
      '/console/observability/summary',
      '/console/observability/events',
      '/console/observability/timeseries',
      '/console/observability/services',
    ];
    for (const path of paths) {
      const res = await callCf(handler, {
        method: 'GET',
        path,
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    }
  });

  test('cloudflare GET /console/observability/events rejects query windows larger than 7 days', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-cf-window',
        'user-observability-cf-window',
      ),
      observability: createInMemoryConsoleObservabilityService(),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/events?from=2026-01-01T00:00:00.000Z&to=2026-01-10T00:00:00.000Z',
    });
    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_query');
  });

  test('cloudflare GET /console/observability/events forwards component and query filters to observability service', async () => {
    const recorder = makeObservabilityRequestRecorder();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-cf-component',
        'user-observability-cf-component',
      ),
      observability: recorder.service,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/observability/events?query=invoice&level=ERROR&service=billing&component=checkout_reconcile&eventType=billing.payment_reconcile.failed&from=2026-03-12T00:00:00.000Z&to=2026-03-13T00:00:00.000Z&limit=25',
    });
    expect(res.status).toBe(200);
    expect(recorder.requests).toHaveLength(1);
    expect(recorder.requests[0]).toMatchObject({
      query: 'invoice',
      level: 'ERROR',
      service: 'billing',
      component: 'checkout_reconcile',
      eventType: 'billing.payment_reconcile.failed',
      from: '2026-03-12T00:00:00.000Z',
      to: '2026-03-13T00:00:00.000Z',
      limit: 25,
    });
  });

  test('cloudflare policy publish failures emit approval observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const basePolicies = createInMemoryConsolePolicyService();
    const failingPolicies: ConsolePolicyService = {
      ...basePolicies,
      publishPolicy: async () => {
        throw new Error('policy publish failed');
      },
    };
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-cf-failure',
        'user-observability-cf-failure',
      ),
      policies: failingPolicies,
      observabilityIngestion,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/policies/pol_obs_failure/publish',
      headers: {
        'x-request-id': 'req_obs_policy_publish_cf',
      },
      body: { approvalId: 'apr_obs_failure_cf' },
    });
    expect(res.status).toBe(500);
    expect(res.json?.code).toBe('internal');

    await expect
      .poll(
        () =>
          ingested.filter((entry) => entry.event.eventType === 'approval.policy_publish.failed')
            .length,
      )
      .toBe(1);
    const approvalFailure = ingested.find(
      (entry) => entry.event.eventType === 'approval.policy_publish.failed',
    );
    expect(approvalFailure).toBeTruthy();
    expect(String(getPath(approvalFailure?.event || null, 'metadata', 'resourceId') || '')).toBe(
      'pol_obs_failure',
    );
    expect(String(getPath(approvalFailure?.event || null, 'metadata', 'approvalId') || '')).toBe(
      'apr_obs_failure_cf',
    );
    expect(String((approvalFailure?.event?.requestId as string) || '')).toBe(
      'req_obs_policy_publish_cf',
    );
  });

  test('cloudflare billing document finalization failures emit billing observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      generateMonthlyInvoice: async () => {
        throw new Error('invoice generation failed');
      },
    };
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['ops'],
        'org-observability-cf-billing',
        'user-observability-cf-billing',
      ),
      billing: failingBilling,
      observabilityIngestion,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      headers: {
        'x-request-id': 'req_obs_billing_finalize_cf',
      },
      body: { periodMonthUtc: '2026-03' },
    });
    expect(res.status).toBe(500);
    expect(res.json?.code).toBe('internal');

    await expect
      .poll(
        () =>
          ingested.filter(
            (entry) => entry.event.eventType === 'billing.invoice_finalization.failed',
          ).length,
      )
      .toBe(1);

    const billingFailure = ingested.find(
      (entry) => entry.event.eventType === 'billing.invoice_finalization.failed',
    );
    expect(billingFailure).toBeTruthy();
    expect(String(getPath(billingFailure?.event || null, 'metadata', 'invoiceId') || '')).toBe(
      'monthly:2026-03',
    );
    expect(String((billingFailure?.event?.requestId as string) || '')).toBe(
      'req_obs_billing_finalize_cf',
    );
  });

  test('cloudflare billing checkout reconcile failures emit payment reconcile observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      reconcileStripeCheckoutSession: async () => {
        throw new Error('checkout reconcile failed');
      },
    };
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-cf-reconcile',
        'user-observability-cf-reconcile',
      ),
      billing: failingBilling,
      observabilityIngestion,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session/reconcile',
      headers: {
        'x-request-id': 'req_obs_billing_reconcile_cf',
      },
      body: { checkoutSessionId: 'cs_obs_billing_reconcile_cf' },
    });
    expect(res.status).toBe(500);
    expect(res.json?.code).toBe('internal');

    await expect
      .poll(
        () =>
          ingested.filter((entry) => entry.event.eventType === 'billing.payment_reconcile.failed')
            .length,
      )
      .toBe(1);

    const billingFailure = ingested.find(
      (entry) => entry.event.eventType === 'billing.payment_reconcile.failed',
    );
    expect(billingFailure).toBeTruthy();
    expect(String(getPath(billingFailure?.event || null, 'metadata', 'operation') || '')).toBe(
      'PAYMENT_RECONCILE',
    );
    expect(String(getPath(billingFailure?.event || null, 'metadata', 'providerRef') || '')).toBe(
      'cs_obs_billing_reconcile_cf',
    );
    expect(String((billingFailure?.event?.requestId as string) || '')).toBe(
      'req_obs_billing_reconcile_cf',
    );
  });

  test('cloudflare invalid Stripe webhook secrets emit invalid signature observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const handler = createCloudflareConsoleRouter({
      billing: createInMemoryConsoleBillingService(),
      billingStripeWebhookSecret: 'whsec_expected_cf',
      observabilityIngestion,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': 'whsec_wrong_cf',
        'x-request-id': 'req_obs_stripe_invalid_signature_cf',
      },
      body: {
        eventId: 'evt_obs_invalid_signature_cf',
        eventType: 'checkout.session.completed',
        orgId: 'org-observability-cf-webhook-invalid',
        checkoutSessionId: 'cs_obs_invalid_signature_cf',
        providerRef: 'cs_obs_invalid_signature_cf',
      },
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('unauthorized');

    await expect
      .poll(
        () =>
          ingested.filter(
            (entry) => entry.event.eventType === 'billing.stripe_webhook.invalid_signature',
          ).length,
      )
      .toBe(1);

    const webhookFailure = ingested.find(
      (entry) => entry.event.eventType === 'billing.stripe_webhook.invalid_signature',
    );
    expect(webhookFailure).toBeTruthy();
    expect(String(webhookFailure?.event?.orgId || '')).toBe('org-observability-cf-webhook-invalid');
    expect(String(getPath(webhookFailure?.event || null, 'metadata', 'stripeEventId') || '')).toBe(
      'evt_obs_invalid_signature_cf',
    );
    expect(String(getPath(webhookFailure?.event || null, 'metadata', 'providerRef') || '')).toBe(
      'cs_obs_invalid_signature_cf',
    );
    expect(String((webhookFailure?.event?.requestId as string) || '')).toBe(
      'req_obs_stripe_invalid_signature_cf',
    );
  });

  test('cloudflare Stripe webhook processing failures emit processing observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const observabilityIngestion = makeObservabilityIngestionCollector(ingested);
    const baseBilling = createInMemoryConsoleBillingService();
    const failingBilling: ConsoleBillingService = {
      ...baseBilling,
      processStripeWebhookEvent: async () => {
        throw new Error('stripe webhook processing failed');
      },
    };
    const handler = createCloudflareConsoleRouter({
      billing: failingBilling,
      billingStripeWebhookSecret: 'whsec_expected_processing_cf',
      observabilityIngestion,
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': 'whsec_expected_processing_cf',
        'x-request-id': 'req_obs_stripe_processing_cf',
      },
      body: {
        eventId: 'evt_obs_processing_failed_cf',
        eventType: 'checkout.session.completed',
        orgId: 'org-observability-cf-webhook-processing',
        checkoutSessionId: 'cs_obs_processing_failed_cf',
        providerRef: 'cs_obs_processing_failed_cf',
      },
    });
    expect(res.status).toBe(500);
    expect(res.json?.code).toBe('internal');

    await expect
      .poll(
        () =>
          ingested.filter(
            (entry) => entry.event.eventType === 'billing.stripe_webhook.processing.failed',
          ).length,
      )
      .toBe(1);

    const webhookFailure = ingested.find(
      (entry) => entry.event.eventType === 'billing.stripe_webhook.processing.failed',
    );
    expect(webhookFailure).toBeTruthy();
    expect(String(webhookFailure?.event?.orgId || '')).toBe(
      'org-observability-cf-webhook-processing',
    );
    expect(String(getPath(webhookFailure?.event || null, 'metadata', 'failureCode') || '')).toBe(
      'internal',
    );
    expect(
      String(getPath(webhookFailure?.event || null, 'metadata', 'checkoutSessionId') || ''),
    ).toBe('cs_obs_processing_failed_cf');
    expect(String((webhookFailure?.event?.requestId as string) || '')).toBe(
      'req_obs_stripe_processing_cf',
    );
  });

  test('GET /console/isolation/status returns enterprise_isolation_not_configured without service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/isolation/status',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('enterprise_isolation_not_configured');
  });

  test('GET /console/onboarding/state and telemetry return onboarding_not_configured without onboarding service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('onboarding_not_configured');

    const telemetry = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/telemetry',
    });
    expect(telemetry.status).toBe(501);
    expect(telemetry.json?.code).toBe('onboarding_not_configured');
  });

  test('cloudflare GET /console/onboarding/telemetry requires admin or ops role', async () => {
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-onboarding-telemetry-role-cf',
        'user-onboarding-telemetry-role-cf',
      ),
      onboarding,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/telemetry',
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('cloudflare GET /console/onboarding/telemetry validates windowMinutes query', async () => {
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-telemetry-query-cf',
        'user-onboarding-telemetry-query-cf',
      ),
      onboarding,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/telemetry?windowMinutes=0',
    });
    expect(res.status).toBe(400);
    expect(res.json?.code).toBe('invalid_query');
  });

  test('cloudflare GET /console/ops-cockpit/summary aggregates operator queues', async () => {
    const orgId = 'org-ops-cockpit-summary-cf';
    const actorUserId = 'user-ops-cockpit-summary-cf';
    const roles = ['admin'];
    const serviceCtx = { orgId, actorUserId, roles };

    const approvals = createInMemoryConsoleApprovalService();
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        async dispatch() {
          return {
            ok: false,
            statusCode: 500,
            errorMessage: 'mock dispatch failure',
          };
        },
      },
    });
    const auditExports = createInMemoryConsoleAuditExportsService();
    const enterpriseIsolation = createInMemoryConsoleEnterpriseIsolationService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing,
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });

    await approvals.createApprovalRequest(serviceCtx, {
      operationType: 'KEY_EXPORT',
      reason: 'Operator approval pending',
    });
    const generatedInvoice = await billing.generateMonthlyInvoice(serviceCtx, {
      periodMonthUtc: '2026-03',
    });
    await billing.processStripeWebhookEvent({
      eventId: 'evt_ops_cockpit_cf_invoice_failed',
      orgId,
      eventType: 'invoice.payment_failed',
      invoiceId: generatedInvoice.invoice.id,
      invoiceStatus: 'UNCOLLECTIBLE',
    } as any);
    await auditExports.createExport(serviceCtx, { format: 'JSONL' });
    await enterpriseIsolation.triggerIsolation(serviceCtx, {
      scope: 'ORG',
      trigger: 'SLA_BREACH',
      reason: 'SLA breach',
    });
    const endpoint = await webhooks.createEndpoint(serviceCtx, {
      url: 'https://example.com/ops-cockpit-webhook-cf',
      eventCategories: ['billing'],
    });
    await webhooks.emitEvent(serviceCtx, {
      eventType: 'billing.invoice.payment_failed',
      payload: { invoiceId: generatedInvoice.invoice.id, endpointId: endpoint.id },
    });

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(roles, orgId, actorUserId),
      approvals,
      billing,
      webhooks,
      auditExports,
      enterpriseIsolation,
      onboarding,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/ops-cockpit/summary?windowMinutes=60',
    });
    expect(res.status).toBe(200);
    expect(getPath(res.json, 'summary', 'approvals', 'pendingCount')).toBe(1);
    expect(getPath(res.json, 'summary', 'billing', 'failedInvoiceCount')).toBe(0);
    expect(getPath(res.json, 'summary', 'webhooks', 'deadLetterCount')).toBe(1);
    expect(getPath(res.json, 'summary', 'auditExports', 'queuedExportCount')).toBe(1);
    expect(getPath(res.json, 'summary', 'enterpriseIsolation', 'activeRequestCount')).toBe(1);
    expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'state')).toBe('ok');
    expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'windowMinutes')).toBe(60);
  });

  test('cloudflare GET /console/ops-cockpit/summary is partial for non-ops telemetry viewers', async () => {
    const orgId = 'org-ops-cockpit-summary-role-cf';
    const actorUserId = 'user-ops-cockpit-summary-role-cf';
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
      apiKeys: createInMemoryConsoleApiKeyService(),
      billing: createInMemoryConsoleBillingService(),
      teamRbac: createInMemoryConsoleTeamRbacService(),
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['security_admin'], orgId, actorUserId),
      onboarding,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/ops-cockpit/summary',
    });
    expect(res.status).toBe(200);
    expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'state')).toBe(
      'forbidden',
    );
    expect(getPath(res.json, 'summary', 'onboardingTelemetry', 'status', 'code')).toBe('forbidden');
  });

  test('cloudflare GET /console/ops-cockpit/summary requires ops cockpit read role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-ops-cockpit-summary-forbidden-cf',
        'user-ops-cockpit-summary-forbidden-cf',
      ),
      onboarding: createInMemoryConsoleOnboardingService({
        orgProjectEnv: createInMemoryConsoleOrgProjectEnvService(),
        apiKeys: createInMemoryConsoleApiKeyService(),
        billing: createInMemoryConsoleBillingService(),
        teamRbac: createInMemoryConsoleTeamRbacService(),
      }),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/ops-cockpit/summary',
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('cloudflare onboarding organization and project steps are idempotent and auditable', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const billing = createInMemoryConsoleBillingService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      billing,
      teamRbac,
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-onboarding-cf-1', 'user-onboarding-cf-1'),
      onboarding,
      billing,
      teamRbac,
      audit,
    });

    const before = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(before.status).toBe(200);
    expect(getPath(before.json, 'state', 'hasApiKey')).toBe(false);
    expect(getPath(before.json, 'state', 'complete')).toBe(false);
    expect(getPath(before.json, 'state', 'accountReady')).toBe(true);
    expect(getPath(before.json, 'state', 'organizationReady')).toBe(false);
    expect(getPath(before.json, 'state', 'billingReady')).toBe(false);
    expect(getPath(before.json, 'state', 'projectReady')).toBe(false);
    expect(getPath(before.json, 'state', 'onboardingComplete')).toBe(false);
    expect(getPath(before.json, 'state', 'currentStep')).toBe('organization');

    const organization = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Acme Org CF', slug: 'acme-org-cf' },
      },
    });
    expect(organization.status).toBe(201);
    expect(getPath(organization.json, 'result', 'created', 'organization')).toBe(true);
    expect(getPath(organization.json, 'result', 'created', 'owner')).toBe(true);
    expect(getPath(organization.json, 'result', 'state', 'organizationReady')).toBe(true);
    expect(getPath(organization.json, 'result', 'state', 'currentStep')).toBe('project');

    const project = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_onboarding_cf', name: 'Onboarding Project CF' },
        environment: { id: 'proj_onboarding_cf-dev', name: 'Development' },
      },
    });
    expect(project.status).toBe(201);
    expect(String(getPath(project.json, 'result', 'project', 'id'))).toBe('proj_onboarding_cf');
    expect(String(getPath(project.json, 'result', 'environment', 'id'))).toBe(
      'proj_onboarding_cf:dev',
    );
    expect(getPath(project.json, 'result', 'created', 'project')).toBe(true);
    expect(getPath(project.json, 'result', 'created', 'environment')).toBe(false);

    const after = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(after.status).toBe(200);
    expect(getPath(after.json, 'state', 'hasApiKey')).toBe(false);
    expect(getPath(after.json, 'state', 'complete')).toBe(false);
    expect(getPath(after.json, 'state', 'organizationReady')).toBe(true);
    expect(getPath(after.json, 'state', 'projectReady')).toBe(true);
    expect(getPath(after.json, 'state', 'billingReady')).toBe(false);
    expect(getPath(after.json, 'state', 'onboardingComplete')).toBe(true);
    expect(getPath(after.json, 'state', 'currentStep')).toBe('complete');

    const auditEvents = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/events?limit=20',
    });
    expect(auditEvents.status).toBe(200);
    const rows = Array.isArray(auditEvents.json?.events) ? auditEvents.json?.events : [];
    const actions = rows.map((row: any) => String(row?.action || ''));
    expect(actions).toContain('member.owner.bootstrap');
    expect(actions).toContain('organization.configure');
    expect(actions).toContain('project.create');
    expect(actions).not.toContain('environment.create');
    expect(actions).not.toContain('api_key.create');

    const members = await callCf(handler, {
      method: 'GET',
      path: '/console/members?status=ACTIVE',
    });
    expect(members.status).toBe(200);
    const memberRows = Array.isArray(members.json?.members) ? members.json?.members : [];
    const actorMember = memberRows.find(
      (entry: any) => String(entry?.userId || '') === 'user-onboarding-cf-1',
    );
    expect(actorMember).toBeTruthy();
    const actorRoles = Array.isArray(actorMember?.roles) ? actorMember.roles : [];
    expect(
      actorRoles.some(
        (entry: any) =>
          String(entry?.scope || '').toUpperCase() === 'ORG' &&
          String(entry?.role || '').toLowerCase() === 'owner',
      ),
    ).toBe(true);
  });

  test('cloudflare onboarding project step creates default development environment without billing', async () => {
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
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-project-step-cf',
        'user-onboarding-project-step-cf',
      ),
      onboarding,
      billing,
      teamRbac,
    });

    const blocked = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_step_cf', name: 'Step Project CF' },
      },
    });
    expect(blocked.status).toBe(409);
    expect(blocked.json?.code).toBe('organization_required');

    const organization = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Step Org CF', slug: 'step-org-cf' },
      },
    });
    expect(organization.status).toBe(201);

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_step_cf', name: 'Step Project CF' },
      },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'result', 'project', 'id')).toBe('proj_step_cf');
    expect(getPath(created.json, 'result', 'environment', 'key')).toBe('dev');
    expect(getPath(created.json, 'result', 'created', 'project')).toBe(true);
    expect(getPath(created.json, 'result', 'created', 'environment')).toBe(false);
    expect(getPath(created.json, 'result', 'state', 'billingReady')).toBe(false);
    expect(getPath(created.json, 'result', 'state', 'projectReady')).toBe(true);
    expect(getPath(created.json, 'result', 'state', 'onboardingComplete')).toBe(true);
    expect(getPath(created.json, 'result', 'state', 'currentStep')).toBe('complete');

    const replay = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: 'proj_step_cf', name: 'Step Project CF' },
      },
    });
    expect(replay.status).toBe(200);
    expect(getPath(replay.json, 'result', 'created', 'project')).toBe(false);
    expect(getPath(replay.json, 'result', 'created', 'environment')).toBe(false);

    const telemetry = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/telemetry?windowMinutes=60',
    });
    expect(telemetry.status).toBe(200);
    expect(getPath(telemetry.json, 'telemetry', 'windowMinutes')).toBe(60);
    const operations = Array.isArray(getPath(telemetry.json, 'telemetry', 'operations'))
      ? (getPath(telemetry.json, 'telemetry', 'operations') as any[])
      : [];
    const projectOperation = operations.find(
      (entry) => String(entry?.operation || '') === 'project',
    );
    expect(projectOperation).toBeTruthy();
    expect(Number(getPath(projectOperation, 'requestCount') || 0)).toBeGreaterThanOrEqual(3);
    expect(Number(getPath(projectOperation, 'errorCount') || 0)).toBeGreaterThanOrEqual(1);
    const alerts = Array.isArray(getPath(telemetry.json, 'telemetry', 'alerts'))
      ? (getPath(telemetry.json, 'telemetry', 'alerts') as any[])
      : [];
    expect(
      alerts.some(
        (entry) =>
          String(entry?.operation || '') === 'project' &&
          String(entry?.code || '') === 'onboarding_error_rate_slo_breached',
      ),
    ).toBe(true);
  });

  test('cloudflare onboarding organization step configures org profile and is idempotent', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      teamRbac,
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-onboarding-org-step-cf',
        'user-onboarding-org-step-cf',
      ),
      onboarding,
      teamRbac,
    });

    const before = await callCf(handler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(before.status).toBe(200);
    expect(getPath(before.json, 'state', 'organizationReady')).toBe(false);
    expect(getPath(before.json, 'state', 'currentStep')).toBe('organization');

    const first = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Acme Org CF', slug: 'acme-org-cf' },
      },
    });
    expect(first.status).toBe(201);
    expect(getPath(first.json, 'result', 'organization', 'id')).toBe('org-onboarding-org-step-cf');
    expect(getPath(first.json, 'result', 'organization', 'name')).toBe('Acme Org CF');
    expect(getPath(first.json, 'result', 'organization', 'slug')).toBe('acme-org-cf');
    expect(getPath(first.json, 'result', 'created', 'organization')).toBe(true);
    expect(getPath(first.json, 'result', 'state', 'organizationReady')).toBe(true);
    expect(getPath(first.json, 'result', 'state', 'currentStep')).toBe('project');

    const second = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Acme Org CF Updated', slug: 'acme-org-cf-updated' },
      },
    });
    expect(second.status).toBe(200);
    expect(getPath(second.json, 'result', 'organization', 'name')).toBe('Acme Org CF Updated');
    expect(getPath(second.json, 'result', 'organization', 'slug')).toBe('acme-org-cf-updated');
    expect(getPath(second.json, 'result', 'created', 'organization')).toBe(false);
  });

  test('cloudflare POST /console/projects allows creation without billing method', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-project-billing-gate-cf',
        actorUserId: 'user-project-billing-gate-cf',
        roles: ['admin'],
      },
      { name: 'Project Billing Gate Org CF', slug: 'project-billing-gate-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-project-billing-gate-cf',
        'user-project-billing-gate-cf',
      ),
      orgProjectEnv,
      billing,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: { id: 'proj_gated_cf', name: 'Gated Project CF' },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'project', 'id')).toBe('proj_gated_cf');
    expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);
  });

  test('cloudflare POST /console/projects auto-provisions environments with live environments disabled without billing readiness', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-gate-cf',
        actorUserId: 'user-env-billing-gate-cf',
        roles: ['admin'],
      },
      { name: 'Environment Billing Gate Org CF', slug: 'environment-billing-gate-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-billing-gate-cf',
        'user-env-billing-gate-cf',
      ),
      orgProjectEnv,
      billing,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: { id: 'proj_env_gated_cf', name: 'Env Gated Project CF' },
    });
    expect(created.status).toBe(201);
    expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

    const listed = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('proj_env_gated_cf')}`,
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
    expect(rows.length).toBe(3);
    const statusByKey = new Map<string, string>(
      rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
    );
    expect(statusByKey.get('dev')).toBe('ACTIVE');
    expect(statusByKey.get('staging')).toBe('DISABLED');
    expect(statusByKey.get('prod')).toBe('DISABLED');
  });

  test('cloudflare POST /console/projects enables live environments when billing is ready', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const billing = createInMemoryConsoleBillingService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-project-live-billing-ready-cf',
        actorUserId: 'user-project-live-billing-ready-cf',
        roles: ['admin'],
      },
      { name: 'Project Billing Ready Org CF', slug: 'project-billing-ready-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-project-live-billing-ready-cf',
        'user-project-live-billing-ready-cf',
      ),
      orgProjectEnv,
      billing,
    });

    const checkoutSession = await billing.createStripeCheckoutSession(
      {
        orgId: 'org-project-live-billing-ready-cf',
        actorUserId: 'user-project-live-billing-ready-cf',
        roles: ['admin'],
      },
      {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
        creditPackId: 'usd_25',
      },
    );
    const settle = await billing.processStripeWebhookEvent({
      eventId: `evt_project_live_ready_cf_${Date.now()}_${Math.random().toString(16).slice(2)}`,
      eventType: 'checkout.session.completed',
      orgId: 'org-project-live-billing-ready-cf',
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });
    expect(settle.accepted).toBe(true);

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: { id: 'proj_live_ready_cf', name: 'Live Ready Project CF' },
    });
    expect(created.status).toBe(201);
    expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

    const listed = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('proj_live_ready_cf')}`,
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
    expect(rows.length).toBe(3);
    const statusByKey = new Map<string, string>(
      rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
    );
    expect(statusByKey.get('dev')).toBe('ACTIVE');
    expect(statusByKey.get('staging')).toBe('ACTIVE');
    expect(statusByKey.get('prod')).toBe('ACTIVE');
  });

  test('cloudflare POST /console/projects keeps live environments disabled when billing service is not configured', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-no-billing-service-cf',
        actorUserId: 'user-env-no-billing-service-cf',
        roles: ['admin'],
      },
      { name: 'No Billing Service Org CF', slug: 'no-billing-service-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-no-billing-service-cf',
        'user-env-no-billing-service-cf',
      ),
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: { id: 'proj_env_no_billing_service_cf', name: 'No Billing Service Project CF' },
    });
    expect(created.status).toBe(201);
    expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

    const listed = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('proj_env_no_billing_service_cf')}`,
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
    expect(rows.length).toBe(3);
    const statusByKey = new Map<string, string>(
      rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
    );
    expect(statusByKey.get('dev')).toBe('ACTIVE');
    expect(statusByKey.get('staging')).toBe('DISABLED');
    expect(statusByKey.get('prod')).toBe('DISABLED');
  });

  test('cloudflare POST /console/projects enables live environments when billing bypass is explicitly enabled', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-bypass-cf',
        actorUserId: 'user-env-billing-bypass-cf',
        roles: ['admin'],
      },
      { name: 'Billing Bypass Org CF', slug: 'billing-bypass-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-billing-bypass-cf',
        'user-env-billing-bypass-cf',
      ),
      orgProjectEnv,
      allowLiveEnvironmentBillingBypass: true,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: { id: 'proj_env_billing_bypass_cf', name: 'Billing Bypass Project CF' },
    });
    expect(created.status).toBe(201);
    expect(Number(getPath(created.json, 'project', 'environmentCount') || 0)).toBe(3);

    const listed = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('proj_env_billing_bypass_cf')}`,
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
    expect(rows.length).toBe(3);
    const statusByKey = new Map<string, string>(
      rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
    );
    expect(statusByKey.get('dev')).toBe('ACTIVE');
    expect(statusByKey.get('staging')).toBe('ACTIVE');
    expect(statusByKey.get('prod')).toBe('ACTIVE');
  });

  test('cloudflare POST /console/environments skips billing gate when bypass is explicitly enabled', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-billing-bypass-gate-cf',
        actorUserId: 'user-env-billing-bypass-gate-cf',
        roles: ['admin'],
      },
      { name: 'Billing Bypass Gate Org CF', slug: 'billing-bypass-gate-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-billing-bypass-gate-cf',
        'user-env-billing-bypass-gate-cf',
      ),
      orgProjectEnv,
      allowLiveEnvironmentBillingBypass: true,
    });

    const response = await callCf(handler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        id: 'env_billing_bypass_staging_cf',
        projectId: 'project_missing_for_bypass_gate_test_cf',
        key: 'staging',
        name: 'Staging',
      },
    });
    expect(response.status).toBe(404);
    expect(response.json?.code).toBe('project_not_found');
  });

  test('cloudflare POST /console/environments blocks staging/prod when billing service is not configured', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-env-no-billing-service-gate-cf',
        actorUserId: 'user-env-no-billing-service-gate-cf',
        roles: ['admin'],
      },
      { name: 'No Billing Service Gate Org CF', slug: 'no-billing-service-gate-org-cf' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-no-billing-service-gate-cf',
        'user-env-no-billing-service-gate-cf',
      ),
      orgProjectEnv,
    });

    const blockedStaging = await callCf(handler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        id: 'env_no_billing_service_gated_staging_cf',
        projectId: 'project_missing_for_gate_test_cf',
        key: 'staging',
        name: 'Staging',
      },
    });
    expect(blockedStaging.status).toBe(409);
    expect(blockedStaging.json?.code).toBe('billing_required_live_environment');
  });

  test('cloudflare POST /console/projects keeps live environments enabled when prepaid balance is low but positive', async () => {
    const billing = createInMemoryConsoleBillingService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const claims = {
      orgId: 'org-env-low-balance-live-enabled-cf',
      actorUserId: 'user-env-low-balance-live-enabled-cf',
      roles: ['platform_admin'],
    };
    await orgProjectEnv.upsertOrganization(claims, {
      name: 'Low Balance Live Enabled Org CF',
      slug: 'low-balance-live-enabled-org-cf',
    });
    await billing.grantManualSupportCredit(claims, {
      amountMinor: 1500,
      reasonCode: 'bootstrap_credit',
      note: 'Seed low but positive prepaid balance',
      idempotencyKey: 'router-live-enabled-low-balance-cf',
    });

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-env-low-balance-live-enabled-cf',
        'user-env-low-balance-live-enabled-cf',
      ),
      billing,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: 'proj_env_low_balance_live_enabled_cf',
        name: 'Low Balance Project CF',
      },
    });
    expect(created.status).toBe(201);

    const listed = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('proj_env_low_balance_live_enabled_cf')}`,
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.environments) ? listed.json?.environments : [];
    const statusByKey = new Map<string, string>(
      rows.map((entry: any) => [String(entry?.key || ''), String(entry?.status || '')]),
    );
    expect(statusByKey.get('staging')).toBe('ACTIVE');
    expect(statusByKey.get('prod')).toBe('ACTIVE');
  });

  test('cloudflare audit routes return seeded timeline and evidence rows', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-cf-1', 'user-audit-cf-admin'),
      audit,
    });

    const events = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/events?category=POLICY&limit=5',
    });
    expect(events.status).toBe(200);
    const eventRows = Array.isArray(events.json?.events) ? events.json?.events : [];
    expect(eventRows.length).toBeGreaterThan(0);
    expect(String(getPath(eventRows[0], 'category'))).toBe('POLICY');

    const evidence = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/evidence?domain=BILLING&limit=5',
    });
    expect(evidence.status).toBe(200);
    const evidenceRows = Array.isArray(evidence.json?.evidence) ? evidence.json?.evidence : [];
    expect(evidenceRows.length).toBeGreaterThan(0);
    expect(String(getPath(evidenceRows[0], 'domain'))).toBe('BILLING');
  });

  test('cloudflare audit read routes require audit read role', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const auditExports: ConsoleAuditExportsService = createInMemoryConsoleAuditExportsService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-audit-read-role-cf-1',
        'user-audit-read-role-cf-1',
      ),
      audit,
      auditExports,
    });

    for (const path of [
      '/console/audit/events?limit=5',
      '/console/audit/evidence?limit=5',
      '/console/audit/exports',
      '/console/audit/exports/aexp_missing',
    ]) {
      const res = await callCf(handler, {
        method: 'GET',
        path,
      });
      expect(res.status, path).toBe(403);
      expect(res.json?.code, path).toBe('forbidden');
    }
  });

  test('cloudflare in-memory audit service filters events by free-text query', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService();
    const rows = await audit.listEvents(
      {
        orgId: 'org-audit-search-cf-1',
        actorUserId: 'user-audit-search-cf-admin',
        roles: ['admin'],
      },
      { q: 'pi_demo_01', limit: 20 },
    );
    expect(rows.length).toBe(1);
    expect(String(getPath(rows[0] as any, 'metadata', 'paymentIntentId'))).toBe('pi_demo_01');
  });

  test('cloudflare approval creation emits audit timeline events', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const approvals: ConsoleApprovalService = createInMemoryConsoleApprovalService();
    const policies: ConsolePolicyService = createInMemoryConsolePolicyService();
    const policyCtx = {
      orgId: 'org-audit-cf-live-1',
      actorUserId: 'user-audit-cf-live-admin',
      roles: ['admin'],
    };
    const gasPolicy = await policies.createPolicy(policyCtx, {
      kind: 'GAS_SPONSORSHIP',
      name: 'Gas publish policy CF',
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-cf-live-1', 'user-audit-cf-live-admin'),
      approvals,
      audit,
      policies,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: 'apr_audit_cf_live_1',
        operationType: 'POLICY_PUBLISH',
        reason: 'Publish policy v2',
        resourceType: 'policy',
        resourceId: gasPolicy.id,
      },
    });
    expect(created.status).toBe(201);
    expect(String(getPath(created.json, 'approval', 'policyId') || '')).toBe(gasPolicy.id);
    expect(String(getPath(created.json, 'approval', 'policyName') || '')).toBe(
      'Gas publish policy CF',
    );
    expect(String(getPath(created.json, 'approval', 'policyKind') || '')).toBe('GAS_SPONSORSHIP');

    const events = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/events?category=APPROVAL&limit=20',
    });
    expect(events.status).toBe(200);
    const eventRows = Array.isArray(events.json?.events) ? events.json?.events : [];
    const createdEvent = eventRows.find(
      (row: any) => String(row?.action || '') === 'approval.request.create',
    );
    expect(createdEvent).toBeTruthy();
    expect(String(getPath(createdEvent, 'policyId') || '')).toBe(gasPolicy.id);
    expect(String(getPath(createdEvent, 'policyName') || '')).toBe('Gas publish policy CF');
    expect(String(getPath(createdEvent, 'policyKind') || '')).toBe('GAS_SPONSORSHIP');
    expect(String(getPath(createdEvent, 'metadata', 'approvalId'))).toBe('apr_audit_cf_live_1');
    expect(String(getPath(createdEvent, 'metadata', 'resourceId'))).toBe(gasPolicy.id);
    expect(String(getPath(createdEvent, 'metadata', 'policyId'))).toBe(gasPolicy.id);
    expect(String(getPath(createdEvent, 'metadata', 'policyKind'))).toBe('GAS_SPONSORSHIP');
  });

  test('cloudflare audit export and enterprise isolation routes support scaffold flows', async () => {
    const auditExports: ConsoleAuditExportsService = createInMemoryConsoleAuditExportsService();
    const enterpriseIsolation: ConsoleEnterpriseIsolationService =
      createInMemoryConsoleEnterpriseIsolationService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-audit-export-cf-1',
        'user-audit-export-cf-admin',
      ),
      auditExports,
      enterpriseIsolation,
    });

    const createdExport = await callCf(handler, {
      method: 'POST',
      path: '/console/audit/exports',
      body: {
        id: 'aexp_cf_scaffold_1',
        format: 'CSV',
        domain: 'SECURITY',
        projectId: 'proj_cf_scaffold_1',
        environmentId: 'env_cf_scaffold_1',
      },
    });
    expect(createdExport.status).toBe(201);
    expect(String(getPath(createdExport.json, 'export', 'status') || '')).toBe('QUEUED');

    const listExports = await callCf(handler, {
      method: 'GET',
      path: '/console/audit/exports?domain=SECURITY',
    });
    expect(listExports.status).toBe(200);
    const exportRows = Array.isArray(listExports.json?.exports) ? listExports.json?.exports : [];
    expect(exportRows.some((entry: any) => String(entry?.id || '') === 'aexp_cf_scaffold_1')).toBe(
      true,
    );

    const getExport = await callCf(handler, {
      method: 'GET',
      path: `/console/audit/exports/${encodeURIComponent('aexp_cf_scaffold_1')}`,
    });
    expect(getExport.status).toBe(200);
    expect(String(getPath(getExport.json, 'export', 'id') || '')).toBe('aexp_cf_scaffold_1');

    const initialIsolation = await callCf(handler, {
      method: 'GET',
      path: '/console/isolation/status?scope=ORG',
    });
    expect(initialIsolation.status).toBe(200);
    expect(String(getPath(initialIsolation.json, 'isolation', 'status') || '')).toBe('SHARED');

    const triggerIsolation = await callCf(handler, {
      method: 'POST',
      path: '/console/isolation/trigger',
      body: {
        scope: 'ORG',
        trigger: 'MANUAL',
        reason: 'High-value customer isolation request',
        ticketId: 'OPS-321',
      },
    });
    expect(triggerIsolation.status).toBe(202);
    expect(String(getPath(triggerIsolation.json, 'isolation', 'status') || '')).toBe('REQUESTED');
    expect(String(getPath(triggerIsolation.json, 'isolation', 'mode') || '')).toBe('DEDICATED');
  });

  test('cloudflare team member routes enforce role scope validation and mutation RBAC', async () => {
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-team-cf-1', 'user-team-cf-admin-1'),
      teamRbac,
    });

    const initial = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/members',
    });
    expect(initial.status).toBe(200);
    const initialRows = Array.isArray(initial.json?.members) ? initial.json?.members : [];
    expect(initialRows.length).toBeGreaterThanOrEqual(1);

    const invited = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/members/invite',
      body: {
        userId: 'member-team-cf-1-user',
        email: 'cf-dev@example.com',
        roles: [{ role: 'admin_manage_members' }, { role: 'wallet_operations_write' }],
      },
    });
    expect(invited.status).toBe(201);
    const invitedMemberId = String(getPath(invited.json, 'member', 'id') || '');
    expect(invitedMemberId).toContain('mbr_');
    expect(getPath(invited.json, 'member', 'status')).toBe('ACTIVE');

    const invitedOnly = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/members?status=ACTIVE',
    });
    expect(invitedOnly.status).toBe(200);
    const invitedRows = Array.isArray(invitedOnly.json?.members) ? invitedOnly.json?.members : [];
    expect(invitedRows.some((entry: any) => String(entry?.id || '') === invitedMemberId)).toBe(
      true,
    );

    const updated = await callCf(adminHandler, {
      method: 'PATCH',
      path: `/console/members/${encodeURIComponent(invitedMemberId)}/roles`,
      body: {
        roles: [{ role: 'integrations_read' }],
      },
    });
    expect(updated.status).toBe(200);
    expect(getPath(updated.json, 'member', 'roles', 0, 'role')).toBe('integrations_read');
    expect(getPath(updated.json, 'member', 'roles', 0, 'scope')).toBe('ORG');

    const removed = await callCf(adminHandler, {
      method: 'DELETE',
      path: `/console/members/${encodeURIComponent(invitedMemberId)}`,
    });
    expect(removed.status).toBe(200);
    expect(removed.json?.removed).toBe(true);
    expect(getPath(removed.json, 'member', 'status')).toBe('REMOVED');

    const invalidScope = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/members/invite',
      body: {
        userId: 'member-team-cf-invalid-user',
        email: 'cf-invalid@example.com',
        roles: [{ role: 'wallet_operations_read', projectId: 'project-team-cf-1' }],
      },
    });
    expect(invalidScope.status).toBe(400);
    expect(invalidScope.json?.code).toBe('invalid_body');

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-team-cf-1', 'user-team-cf-dev-1'),
      teamRbac,
    });
    const forbidden = await callCf(developerHandler, {
      method: 'POST',
      path: '/console/members/invite',
      body: {
        userId: 'member-team-cf-forbidden-user',
        email: 'cf-forbidden@example.com',
        roles: [{ role: 'overview_read' }],
      },
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.json?.code).toBe('forbidden');
  });

  test('cloudflare approval routes enforce mutation RBAC, MFA requirements, and state transitions', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-approvals-cf-1', 'user-approvals-cf-admin-1'),
      approvals,
    });

    const initial = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(initial.status).toBe(200);
    const initialRows = Array.isArray(initial.json?.approvals) ? initial.json?.approvals : [];
    expect(initialRows).toHaveLength(0);

    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: 'apr_key_export_cf_1',
        operationType: 'KEY_EXPORT',
        reason: 'Approval for key export',
      },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'approval', 'id')).toBe('apr_key_export_cf_1');
    expect(getPath(created.json, 'approval', 'requiredApprovals')).toBe(2);
    expect(getPath(created.json, 'approval', 'requireMfa')).toBe(true);

    const missingMfa = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/approvals/apr_key_export_cf_1/approve',
      body: {
        reason: 'approve without mfa',
        mfaVerified: false,
      },
    });
    expect(missingMfa.status).toBe(400);
    expect(missingMfa.json?.code).toBe('mfa_required');

    const firstApproval = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/approvals/apr_key_export_cf_1/approve',
      body: {
        reason: 'first approval',
        mfaVerified: true,
      },
    });
    expect(firstApproval.status).toBe(200);
    expect(getPath(firstApproval.json, 'approval', 'status')).toBe('PENDING');
    expect(Number(getPath(firstApproval.json, 'approval', 'decisions', 'length') || 0)).toBe(1);

    const securityAdminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['security_admin'],
        'org-approvals-cf-1',
        'user-approvals-cf-security-admin-1',
      ),
      approvals,
    });
    const secondApproval = await callCf(securityAdminHandler, {
      method: 'POST',
      path: '/console/approvals/apr_key_export_cf_1/approve',
      body: {
        reason: 'second approval',
        mfaVerified: true,
      },
    });
    expect(secondApproval.status).toBe(200);
    expect(getPath(secondApproval.json, 'approval', 'status')).toBe('APPROVED');
    expect(Number(getPath(secondApproval.json, 'approval', 'decisions', 'length') || 0)).toBe(2);
    expect(String(getPath(secondApproval.json, 'approval', 'resolvedAt') || '')).toBeTruthy();

    const invalidStateReject = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/approvals/apr_key_export_cf_1/reject',
      body: {
        reason: 'late reject',
      },
    });
    expect(invalidStateReject.status).toBe(409);
    expect(invalidStateReject.json?.code).toBe('invalid_state');

    const filtered = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/approvals?status=APPROVED&operationType=KEY_EXPORT',
    });
    expect(filtered.status).toBe(200);
    const filteredRows = Array.isArray(filtered.json?.approvals) ? filtered.json?.approvals : [];
    expect(
      filteredRows.some((entry: any) => String(entry?.id || '') === 'apr_key_export_cf_1'),
    ).toBe(true);

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-approvals-cf-1',
        'user-approvals-cf-developer-1',
      ),
      approvals,
    });
    const forbiddenCreate = await callCf(developerHandler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        operationType: 'POLICY_PUBLISH',
        reason: 'unauthorized create',
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');

    const readOnlyList = await callCf(developerHandler, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(readOnlyList.status).toBe(200);
  });

  test('cloudflare sensitive operation routes require approved queue entries when approvals service is configured', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const orgId = 'org-sensitive-approval-cf-1';
    const actorUserId = 'user-sensitive-approval-cf-admin-1';
    const claimsRoles = ['admin'];
    const approvalCtx = {
      orgId,
      actorUserId,
      roles: claimsRoles,
    };

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(claimsRoles, orgId, actorUserId),
      approvals,
      policies,
      keyExports,
    });

    const createPolicy = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Sensitive Policy CF',
      },
    });
    expect(createPolicy.status).toBe(201);
    const policyId = String(getPath(createPolicy.json, 'policy', 'id') || '');
    expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const publishWithoutApproval = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(policyId)}/publish`,
      body: {},
    });
    expect(publishWithoutApproval.status).toBe(400);
    expect(publishWithoutApproval.json?.code).toBe('approval_required');

    const policyApproval = await approvals.createApprovalRequest(approvalCtx, {
      id: 'apr_policy_sensitive_cf_1',
      operationType: 'POLICY_PUBLISH',
      reason: 'Publish policy approval CF',
      resourceType: 'policy',
      resourceId: policyId,
    });
    await approvals.approveApprovalRequest(approvalCtx, policyApproval.id, {
      reason: 'Policy publish approved CF',
      mfaVerified: true,
    });

    const publishWithApproval = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(policyId)}/publish`,
      body: {
        approvalId: policyApproval.id,
      },
    });
    expect(publishWithApproval.status).toBe(200);
    expect(getPath(publishWithApproval.json, 'result', 'policy', 'status')).toBe('PUBLISHED');

    const exportId = 'ke_sensitive_cf_1';
    const createExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: exportId,
        environmentId: 'env_sensitive_cf_1',
        reason: 'Key export request CF',
        requiredApprovals: 1,
      },
    });
    expect(createExport.status).toBe(201);

    const approveExportWithoutApproval = await callCf(handler, {
      method: 'POST',
      path: `/console/key-exports/${encodeURIComponent(exportId)}/approve`,
      body: {
        reason: 'Approve export CF',
        mfaVerified: true,
      },
    });
    expect(approveExportWithoutApproval.status).toBe(400);
    expect(approveExportWithoutApproval.json?.code).toBe('approval_required');

    const keyExportApproval = await approvals.createApprovalRequest(approvalCtx, {
      id: 'apr_key_export_sensitive_cf_1',
      operationType: 'KEY_EXPORT',
      reason: 'Key export approval CF',
      requiredApprovals: 1,
      requireMfa: true,
      resourceType: 'key_export',
      resourceId: exportId,
    });
    await approvals.approveApprovalRequest(approvalCtx, keyExportApproval.id, {
      reason: 'Key export approved CF',
      mfaVerified: true,
    });

    const approveExportWithApproval = await callCf(handler, {
      method: 'POST',
      path: `/console/key-exports/${encodeURIComponent(exportId)}/approve`,
      body: {
        reason: 'Approve export CF',
        mfaVerified: true,
        approvalId: keyExportApproval.id,
      },
    });
    expect(approveExportWithApproval.status).toBe(200);
    expect(getPath(approveExportWithApproval.json, 'keyExport', 'status')).toBe('APPROVED');
  });

  test('cloudflare approval queue mutations emit approval lifecycle webhook events', async () => {
    const approvals = createInMemoryConsoleApprovalService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-approval-events-cf-1',
        'user-approval-events-cf-1',
      ),
      approvals,
      webhooks,
    });

    const endpointCreated = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/approval-events-cf',
        eventCategories: ['policy'],
      },
    });
    expect(endpointCreated.status).toBe(201);
    const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const createdOne = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: 'apr_events_cf_1',
        operationType: 'POLICY_PUBLISH',
        reason: 'Approval event create/approve cf',
        requiredApprovals: 1,
      },
    });
    expect(createdOne.status).toBe(201);

    const approvedOne = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals/apr_events_cf_1/approve',
      body: {
        reason: 'Approve with event cf',
        mfaVerified: true,
      },
    });
    expect(approvedOne.status).toBe(200);

    const createdTwo = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: 'apr_events_cf_2',
        operationType: 'KEY_EXPORT',
        reason: 'Approval event create/reject cf',
      },
    });
    expect(createdTwo.status).toBe(201);

    const rejectedTwo = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals/apr_events_cf_2/reject',
      body: {
        reason: 'Reject with event cf',
      },
    });
    expect(rejectedTwo.status).toBe(200);

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
    expect(eventTypes).toContain('policy.approval.created');
    expect(eventTypes).toContain('policy.approval.approved');
    expect(eventTypes).toContain('policy.approval.rejected');
  });

  test('cloudflare org/project/environment routes return hierarchical metadata', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-meta-cf-1',
        actorUserId: 'user-meta-cf-1',
        roles: ['admin'],
      },
      { name: 'Org Meta CF 1', slug: 'org-meta-cf-1' },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-cf-1', 'user-meta-cf-1'),
      orgProjectEnv,
    });

    const createdProject = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: 'project-meta-cf-1',
        name: 'Project Meta CF 1',
      },
    });
    expect(createdProject.status).toBe(201);

    const org = await callCf(handler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(org.status).toBe(200);
    expect(getPath(org.json, 'org', 'id')).toBe('org-meta-cf-1');

    const projects = await callCf(handler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(projects.status).toBe(200);
    const projectRows = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
    expect(projectRows.length).toBeGreaterThanOrEqual(1);
    const projectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
    expect(projectId).toBeTruthy();
    expect(
      Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0),
    ).toBeGreaterThanOrEqual(1);

    const environments = await callCf(handler, {
      method: 'GET',
      path: '/console/environments',
    });
    expect(environments.status).toBe(200);
    const environmentRows = Array.isArray(environments.json?.environments)
      ? environments.json?.environments
      : [];
    expect(environmentRows.length).toBeGreaterThanOrEqual(1);
    expect(String(getPath(environments.json, 'environments', 0, 'projectId') || '')).toBe(
      projectId,
    );

    const scoped = await callCf(handler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(projectId)}`,
    });
    expect(scoped.status).toBe(200);
    const scopedRows = Array.isArray(scoped.json?.environments) ? scoped.json?.environments : [];
    expect(scopedRows.length).toBeGreaterThanOrEqual(1);
    expect(scopedRows.every((entry: any) => String(entry?.projectId || '') === projectId)).toBe(
      true,
    );
  });

  test('cloudflare org/project/environment mutation routes enforce role and lifecycle rules', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-meta-cf-mutate-1',
        actorUserId: 'user-meta-cf-mutate-1',
        roles: ['admin'],
      },
      { name: 'Org Meta CF Mutate 1', slug: 'org-meta-cf-mutate-1' },
    );
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-meta-cf-mutate-1', 'user-meta-cf-mutate-1'),
      orgProjectEnv,
    });

    const createdProject = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: 'project-cf-mutate-1',
        name: 'Project CF Mutate',
      },
    });
    expect(createdProject.status).toBe(201);
    expect(getPath(createdProject.json, 'project', 'id')).toBe('project-cf-mutate-1');
    expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(3);
    const environmentsForProject = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent('project-cf-mutate-1')}`,
    });
    expect(environmentsForProject.status).toBe(200);
    const projectEnvironmentRows = Array.isArray(environmentsForProject.json?.environments)
      ? environmentsForProject.json?.environments
      : [];
    const managedEnvironmentId = String(getPath(projectEnvironmentRows, 0, 'id') || '');
    expect(managedEnvironmentId).toBeTruthy();

    const updatedProject = await callCf(adminHandler, {
      method: 'PATCH',
      path: '/console/projects/project-cf-mutate-1',
      body: { name: 'Project CF Mutate Renamed' },
    });
    expect(updatedProject.status).toBe(200);
    expect(getPath(updatedProject.json, 'project', 'name')).toBe('Project CF Mutate Renamed');

    const archivedEnvironment = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/environments/${encodeURIComponent(managedEnvironmentId)}/archive`,
    });
    expect(archivedEnvironment.status).toBe(200);
    expect(getPath(archivedEnvironment.json, 'environment', 'status')).toBe('ARCHIVED');

    const archivedProject = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/projects/project-cf-mutate-1/archive',
    });
    expect(archivedProject.status).toBe(200);
    expect(getPath(archivedProject.json, 'project', 'status')).toBe('ARCHIVED');

    const archivedProjects = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=ARCHIVED',
    });
    expect(archivedProjects.status).toBe(200);
    const archivedProjectRows = Array.isArray(archivedProjects.json?.projects)
      ? archivedProjects.json?.projects
      : [];
    expect(archivedProjectRows.length).toBeGreaterThanOrEqual(1);
    expect(
      archivedProjectRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED'),
    ).toBe(true);

    const activeProjects = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=ACTIVE',
    });
    expect(activeProjects.status).toBe(200);
    const activeProjectRows = Array.isArray(activeProjects.json?.projects)
      ? activeProjects.json?.projects
      : [];
    expect(activeProjectRows.every((entry: any) => String(entry?.status || '') === 'ACTIVE')).toBe(
      true,
    );

    const invalidProjectStatus = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/projects?status=INVALID',
    });
    expect(invalidProjectStatus.status).toBe(400);
    expect(invalidProjectStatus.json?.code).toBe('invalid_query');

    const archivedOnly = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?projectId=project-cf-mutate-1&status=ARCHIVED',
    });
    expect(archivedOnly.status).toBe(200);
    const archivedRows = Array.isArray(archivedOnly.json?.environments)
      ? archivedOnly.json?.environments
      : [];
    expect(archivedRows.length).toBeGreaterThanOrEqual(1);
    expect(archivedRows.every((entry: any) => String(entry?.status || '') === 'ARCHIVED')).toBe(
      true,
    );

    const activeOnly = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?projectId=project-cf-mutate-1&status=ACTIVE',
    });
    expect(activeOnly.status).toBe(200);
    const activeRows = Array.isArray(activeOnly.json?.environments)
      ? activeOnly.json?.environments
      : [];
    expect(activeRows.length).toBe(0);

    const invalidStatus = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/environments?status=INVALID',
    });
    expect(invalidStatus.status).toBe(400);
    expect(invalidStatus.json?.code).toBe('invalid_query');

    const createOnArchived = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/environments',
      body: {
        projectId: 'project-cf-mutate-1',
        key: 'dev',
      },
    });
    expect(createOnArchived.status).toBe(409);
    expect(createOnArchived.json?.code).toBe('project_archived');

    const devHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-meta-cf-mutate-1', 'user-meta-cf-dev-1'),
      orgProjectEnv,
    });
    const forbidden = await callCf(devHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        name: 'Forbidden CF Project',
      },
    });
    expect(forbidden.status).toBe(403);
    expect(forbidden.json?.code).toBe('forbidden');
  });

  test('GET /console/wallets returns wallets_not_configured without wallet service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('wallets_not_configured');
  });

  test('GET /console/policies returns policies_not_configured without policy service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('policies_not_configured');
  });

  test('GET /console/policy/coverage returns wallets_not_configured without wallet service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/policy/coverage',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('wallets_not_configured');
  });

  test('GET /console/export/governance returns key_exports_not_configured without key export service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/export/governance',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('key_exports_not_configured');
  });

  test('cloudflare new console endpoints return *_not_configured when services are not wired', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });

    const gas = await callCf(handler, {
      method: 'GET',
      path: '/console/policies?kind=GAS_SPONSORSHIP',
    });
    expect(gas.status).toBe(501);
    expect(gas.json?.code).toBe('policies_not_configured');

    const keyExports = await callCf(handler, {
      method: 'GET',
      path: '/console/key-exports',
    });
    expect(keyExports.status).toBe(501);
    expect(keyExports.json?.code).toBe('key_exports_not_configured');

    const runtimeSnapshots = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=env-test',
    });
    expect(runtimeSnapshots.status).toBe(501);
    expect(runtimeSnapshots.json?.code).toBe('runtime_snapshots_not_configured');
  });

  test('cloudflare new console endpoints support scaffold CRUD flows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-cf-1', 'user-scaffold-cf-1'),
      policies,
      keyExports,
      runtimeSnapshots,
    });

    const createdGas = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Scaffold gas policy cloudflare',
        rules: evmGasSponsorshipRulesFixture({
          environmentId: 'prod',
          projectId: null,
          chainId: 1,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(createdGas.status).toBe(201);
    const createdGasId = String(getPath(createdGas.json, 'policy', 'id') || '');
    expect(createdGasId.startsWith('policy_')).toBe(true);

    const listedGas = await callCf(handler, {
      method: 'GET',
      path: '/console/policies?kind=GAS_SPONSORSHIP',
    });
    expect(listedGas.status).toBe(200);
    const listedGasRows: unknown[] = Array.isArray(listedGas.json?.policies)
      ? (listedGas.json?.policies as unknown[])
      : [];
    expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

    const patchedGas = await callCf(handler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(createdGasId)}`,
      body: {
        rules: evmGasSponsorshipRulesFixture({
          environmentId: 'prod',
          projectId: null,
          chainId: 1,
          capMinor: 500000,
          enabled: false,
        }),
      },
    });
    expect(patchedGas.status).toBe(200);
    expect(getPath(patchedGas.json, 'policy', 'rules', 'enabled')).toBe(false);

    const publishedGas = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(createdGasId)}/publish`,
    });
    expect(publishedGas.status).toBe(200);

    const createdKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-1',
        environmentId: 'prod',
        reason: 'Emergency rotation',
        requiredApprovals: 1,
      },
    });
    expect(createdKeyExport.status).toBe(201);
    expect(getPath(createdKeyExport.json, 'keyExport', 'status')).toBe('PENDING_APPROVAL');

    const approvedKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-1/approve',
      body: {
        reason: 'Approved with MFA',
        mfaVerified: true,
      },
    });
    expect(approvedKeyExport.status).toBe(200);
    expect(getPath(approvedKeyExport.json, 'keyExport', 'status')).toBe('APPROVED');

    const publishedSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
      },
    });
    expect(publishedSnapshot.status).toBe(201);
    expect(Number(getPath(publishedSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);
    expect(String(getPath(publishedSnapshot.json, 'snapshot', 'checksum') || '')).toContain(
      'fnv1a32:',
    );
    expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
      'resolved',
    );
    const latestSnapshot = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots/latest?environmentId=prod',
    });
    expect(latestSnapshot.status).toBe(200);
    expect(getPath(latestSnapshot.json, 'snapshot', 'environmentId')).toBe('prod');
    expect(Number(getPath(latestSnapshot.json, 'snapshot', 'version') || 0)).toBe(1);

    const listedSnapshots = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&limit=5',
    });
    expect(listedSnapshots.status).toBe(200);
    const snapshotRows = Array.isArray(listedSnapshots.json?.snapshots)
      ? listedSnapshots.json?.snapshots
      : [];
    expect(snapshotRows.length).toBeGreaterThanOrEqual(1);
  });

  test('cloudflare runtime snapshot publish-current emits not_configured markers and monotonic versions', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-contract-cf-1',
        'user-runtime-contract-cf-1',
      ),
      runtimeSnapshots,
    });

    const first = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
        projectId: 'project-alpha',
        snapshotId: 'runtime-contract-v1',
        effectiveAt: '2026-03-01T00:00:00.000Z',
      },
    });
    expect(first.status).toBe(201);
    expect(getPath(first.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v1');
    expect(Number(getPath(first.json, 'snapshot', 'version') || 0)).toBe(1);
    expect(getPath(first.json, 'snapshot', 'payload', 'policy', 'status')).toBe('not_configured');
    expect(getPath(first.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
      'not_configured',
    );
    const firstChecksum = String(getPath(first.json, 'snapshot', 'checksum') || '');
    expect(firstChecksum).toContain('fnv1a32:');

    const second = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
        projectId: 'project-alpha',
        snapshotId: 'runtime-contract-v2',
        effectiveAt: '2026-03-01T01:00:00.000Z',
      },
    });
    expect(second.status).toBe(201);
    expect(getPath(second.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
    expect(Number(getPath(second.json, 'snapshot', 'version') || 0)).toBe(2);
    expect(String(getPath(second.json, 'snapshot', 'checksum') || '')).not.toBe(firstChecksum);

    const latest = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots/latest?environmentId=prod&projectId=project-alpha',
    });
    expect(latest.status).toBe(200);
    expect(getPath(latest.json, 'snapshot', 'snapshotId')).toBe('runtime-contract-v2');
    expect(Number(getPath(latest.json, 'snapshot', 'version') || 0)).toBe(2);

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&projectId=project-alpha&limit=2',
    });
    expect(listed.status).toBe(200);
    expect(getPath(listed.json, 'snapshots', 0, 'snapshotId')).toBe('runtime-contract-v2');
    expect(getPath(listed.json, 'snapshots', 1, 'snapshotId')).toBe('runtime-contract-v1');
  });

  test('cloudflare runtime snapshot publish-current resolves published policy state instead of attached draft rules', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const policies = createInMemoryConsolePolicyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-policy-cf-1',
        'user-runtime-policy-cf-1',
      ),
      runtimeSnapshots,
      policies,
    });

    const environmentId = 'env-runtime-policy-cf-1';
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Runtime policy cloudflare',
        assignment: {
          scopeType: 'ENVIRONMENT',
          scopeId: environmentId,
        },
        rules: {
          blockedActions: ['delete_key'],
          allowedChains: ['Ethereum'],
        },
      },
    });
    expect(created.status).toBe(201);
    const policyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const published = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(policyId)}/publish`,
    });
    expect(published.status).toBe(200);

    const drafted = await callCf(handler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(policyId)}`,
      body: {
        rules: {
          blockedActions: ['export_key'],
          allowedChains: ['NEAR'],
        },
      },
    });
    expect(drafted.status).toBe(200);
    expect(getPath(drafted.json, 'policy', 'status')).toBe('DRAFT');

    const snapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId,
        snapshotId: 'runtime-policy-live-cf-v1',
      },
    });
    expect(snapshot.status).toBe(201);
    expect(getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'status')).toBe('resolved');
    const snapshotPolicies = Array.isArray(
      getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'policies'),
    )
      ? (getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'policies') as any[])
      : [];
    const livePolicy = snapshotPolicies.find((entry) => String(entry?.id || '') === policyId);
    expect(livePolicy).toBeTruthy();
    expect(String(getPath(livePolicy, 'status') || '')).toBe('PUBLISHED');
    expect(getPath(livePolicy, 'rules', 'blockedActions', 0)).toBe('delete_key');
    expect(getPath(livePolicy, 'rules', 'allowedChains', 0)).toBe('Ethereum');
    expect(getPath(livePolicy, 'rules', 'blockedActions', 0)).not.toBe('export_key');

    const snapshotAssignments = Array.isArray(
      getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'assignments'),
    )
      ? (getPath(snapshot.json, 'snapshot', 'payload', 'policy', 'assignments') as any[])
      : [];
    expect(
      snapshotAssignments.some(
        (entry) =>
          String(entry?.policyId || '') === policyId &&
          String(entry?.scopeType || '') === 'ENVIRONMENT' &&
          String(entry?.scopeId || '') === environmentId,
      ),
    ).toBe(true);
  });

  test('cloudflare runtime snapshot publish-current resolves published gas sponsorship policy state instead of draft gas rules', async () => {
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const policies = createInMemoryConsolePolicyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-runtime-gas-policy-cf-1',
        'user-runtime-gas-policy-cf-1',
      ),
      runtimeSnapshots,
      policies,
    });

    const environmentId = 'env-runtime-gas-policy-cf-1';
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Runtime gas policy cloudflare',
        rules: evmGasSponsorshipRulesFixture({
          environmentId,
          projectId: null,
          chainId: 1,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(created.status).toBe(201);
    const policyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(policyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const published = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(policyId)}/publish`,
    });
    expect(published.status).toBe(200);

    const drafted = await callCf(handler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(policyId)}`,
      body: {
        rules: evmGasSponsorshipRulesFixture({
          environmentId,
          projectId: null,
          chainId: 10,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(drafted.status).toBe(200);
    expect(getPath(drafted.json, 'policy', 'status')).toBe('DRAFT');

    const snapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId,
        snapshotId: 'runtime-gas-policy-live-cf-v1',
      },
    });
    expect(snapshot.status).toBe(201);
    expect(getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'status')).toBe(
      'resolved',
    );
    expect(
      Number(getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'policyCount') || 0),
    ).toBe(1);
    expect(
      getPath(snapshot.json, 'snapshot', 'payload', 'gasSponsorship', 'policies', 0, 'id'),
    ).toBe(policyId);
    expect(
      getPath(
        snapshot.json,
        'snapshot',
        'payload',
        'gasSponsorship',
        'policies',
        0,
        'allowedChainIds',
        0,
      ),
    ).toBe(1);
    expect(
      getPath(
        snapshot.json,
        'snapshot',
        'payload',
        'gasSponsorship',
        'resolvedPolicies',
        0,
        'policyId',
      ),
    ).toBe(policyId);
    expect(
      getPath(
        snapshot.json,
        'snapshot',
        'payload',
        'gasSponsorship',
        'resolvedPolicies',
        0,
        'allowedChainIds',
        0,
      ),
    ).toBe(1);
  });

  test('cloudflare new console endpoint mutations enforce role gates', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const auditExports = createInMemoryConsoleAuditExportsService();
    const billing = createInMemoryConsoleBillingService();
    const enterpriseIsolation = createInMemoryConsoleEnterpriseIsolationService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const approvals = createInMemoryConsoleApprovalService();
    const onboarding = createInMemoryConsoleOnboardingService({
      apiKeys,
      orgProjectEnv,
      teamRbac,
    });
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-cf-rbac-1',
        'user-scaffold-cf-rbac-1',
      ),
      onboarding,
      orgProjectEnv,
      teamRbac,
      approvals,
      apiKeys,
      auditExports,
      billing,
      enterpriseIsolation,
      policies,
      keyExports,
      runtimeSnapshots,
    });

    const gasCreate = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Forbidden gas policy cloudflare',
      },
    });
    expect(gasCreate.status).toBe(403);
    expect(gasCreate.json?.code).toBe('forbidden');

    const configureOnboardingOrganization = await callCf(handler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        name: 'Forbidden onboarding organization cloudflare',
        slug: 'forbidden-onboarding-org-cloudflare',
      },
    });
    expect(configureOnboardingOrganization.status).toBe(403);
    expect(configureOnboardingOrganization.json?.code).toBe('forbidden');

    const createProject = await callCf(handler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: 'proj-cf-rbac-1',
        name: 'Forbidden project cloudflare',
      },
    });
    expect(createProject.status).toBe(403);
    expect(createProject.json?.code).toBe('forbidden');

    const inviteMember = await callCf(handler, {
      method: 'POST',
      path: '/console/members/invite',
      body: {
        userId: 'member-cf-rbac-1',
        email: 'forbidden-member-cloudflare@example.com',
        roles: [{ role: 'overview_read' }],
      },
    });
    expect(inviteMember.status).toBe(403);
    expect(inviteMember.json?.code).toBe('forbidden');

    const createApproval = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        operationType: 'KEY_EXPORT',
        reason: 'Forbidden approval request cloudflare',
      },
    });
    expect(createApproval.status).toBe(403);
    expect(createApproval.json?.code).toBe('forbidden');

    const createAuditExport = await callCf(handler, {
      method: 'POST',
      path: '/console/audit/exports',
      body: {
        id: 'aexp-cf-rbac-1',
        format: 'CSV',
        domain: 'SECURITY',
      },
    });
    expect(createAuditExport.status).toBe(403);
    expect(createAuditExport.json?.code).toBe('forbidden');

    const triggerIsolation = await callCf(handler, {
      method: 'POST',
      path: '/console/isolation/trigger',
      body: {
        scope: 'ORG',
        trigger: 'COMPLIANCE',
        reason: 'Forbidden isolation cloudflare',
      },
    });
    expect(triggerIsolation.status).toBe(403);
    expect(triggerIsolation.json?.code).toBe('forbidden');

    const createKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-rbac-1',
        environmentId: 'prod',
        reason: 'Trying as developer',
        requiredApprovals: 1,
      },
    });
    expect(createKeyExport.status).toBe(403);
    expect(createKeyExport.json?.code).toBe('forbidden');

    const approve = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-rbac-1/approve',
      body: {
        reason: 'trying as non-admin',
        mfaVerified: true,
      },
    });
    expect(approve.status).toBe(403);
    expect(approve.json?.code).toBe('forbidden');

    const publishSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish',
      body: {
        environmentId: 'prod',
        payload: {
          policy: {},
          gasSponsorship: {},
        },
      },
    });
    expect(publishSnapshot.status).toBe(403);
    expect(publishSnapshot.json?.code).toBe('forbidden');

    const publishCurrentSnapshot = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: 'prod',
      },
    });
    expect(publishCurrentSnapshot.status).toBe(403);
    expect(publishCurrentSnapshot.json?.code).toBe('forbidden');

    const generateInvoice = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(generateInvoice.status).toBe(403);
    expect(generateInvoice.json?.code).toBe('forbidden');

    const appendSupportCredit = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 100,
        reasonCode: 'incident_credit',
        note: 'Forbidden support credit cloudflare',
        idempotencyKey: 'manual-credit-cloudflare-rbac',
      },
    });
    expect(appendSupportCredit.status).toBe(403);
    expect(appendSupportCredit.json?.code).toBe('forbidden');
  });

  test('cloudflare new console endpoint validation errors return typed error codes', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-cf-validation-1',
        'user-scaffold-cf-validation-1',
      ),
      policies,
      keyExports,
      runtimeSnapshots,
    });

    const invalidGasScope = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Invalid gas scope cloudflare',
        rules: {
          scopeType: 'NOT_A_SCOPE',
        },
      },
    });
    expect(invalidGasScope.status).toBe(400);
    expect(invalidGasScope.json?.code).toBe('invalid_body');

    const invalidStatusQuery = await callCf(handler, {
      method: 'GET',
      path: '/console/key-exports?status=NOT_A_STATUS',
    });
    expect(invalidStatusQuery.status).toBe(400);
    expect(invalidStatusQuery.json?.code).toBe('invalid_query');

    const createdKeyExport = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-validation-1',
        environmentId: 'prod',
        reason: 'Validation flow',
        requiredApprovals: 1,
      },
    });
    expect(createdKeyExport.status).toBe(201);

    const approveWithoutMfa = await callCf(handler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-validation-1/approve',
      body: {
        reason: 'Missing MFA check',
        mfaVerified: false,
      },
    });
    expect(approveWithoutMfa.status).toBe(400);
    expect(approveWithoutMfa.json?.code).toBe('mfa_required');

    const invalidSnapshotQuery = await callCf(handler, {
      method: 'GET',
      path: '/console/runtime-snapshots?environmentId=prod&limit=999',
    });
    expect(invalidSnapshotQuery.status).toBe(400);
    expect(invalidSnapshotQuery.json?.code).toBe('invalid_query');

    const invalidSnapshotBody = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish',
      body: {
        environmentId: 'prod',
        payload: {
          policy: {},
        },
      },
    });
    expect(invalidSnapshotBody.status).toBe(400);
    expect(invalidSnapshotBody.json?.code).toBe('invalid_body');

    const invalidPublishCurrentBody = await callCf(handler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        projectId: 'project-only',
      },
    });
    expect(invalidPublishCurrentBody.status).toBe(400);
    expect(invalidPublishCurrentBody.json?.code).toBe('invalid_body');
  });

  test('cloudflare new console endpoints enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-cf-isolation-owner';
    const attackerOrgId = 'org-scaffold-cf-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner-cf';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-cf-isolation-user'),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const createGas = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Isolation gas policy cloudflare',
        rules: evmGasSponsorshipRulesFixture({
          environmentId: ownerEnvironmentId,
          projectId: null,
          chainId: 11_155_111,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(createGas.status).toBe(201);
    const ownerGasId = String(getPath(createGas.json, 'policy', 'id') || '');
    expect(ownerGasId.startsWith('policy_')).toBe(true);

    const createKeyExport = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/key-exports',
      body: {
        id: 'ke-cf-isolation-1',
        environmentId: ownerEnvironmentId,
        reason: 'Owner export request',
        requiredApprovals: 1,
      },
    });
    expect(createKeyExport.status).toBe(201);

    const publishSnapshot = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/runtime-snapshots/publish-current',
      body: {
        environmentId: ownerEnvironmentId,
      },
    });
    expect(publishSnapshot.status).toBe(201);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-scaffold-cf-isolation-user'),
      policies,
      keyExports,
      runtimeSnapshots,
    });
    const gasList = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/policies?kind=GAS_SPONSORSHIP',
    });
    expect(gasList.status).toBe(200);
    const attackerGasRows = Array.isArray(gasList.json?.policies) ? gasList.json?.policies : [];
    expect(attackerGasRows.length).toBe(0);

    const patchGas = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(ownerGasId)}`,
      body: { rules: { enabled: false } },
    });
    expect(patchGas.status).toBe(404);
    expect(patchGas.json?.code).toBe('policy_not_found');

    const keyExportsList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/key-exports?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(keyExportsList.status).toBe(200);
    const attackerKeyExportRows = Array.isArray(keyExportsList.json?.exports)
      ? keyExportsList.json?.exports
      : [];
    expect(attackerKeyExportRows.length).toBe(0);

    const approveKeyExport = await callCf(attackerHandler, {
      method: 'POST',
      path: '/console/key-exports/ke-cf-isolation-1/approve',
      body: {
        reason: 'attacker approve attempt',
        mfaVerified: true,
      },
    });
    expect(approveKeyExport.status).toBe(404);
    expect(approveKeyExport.json?.code).toBe('key_export_not_found');

    const attackerSnapshots = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/runtime-snapshots?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerSnapshots.status).toBe(200);
    const attackerSnapshotRows = Array.isArray(attackerSnapshots.json?.snapshots)
      ? attackerSnapshots.json?.snapshots
      : [];
    expect(attackerSnapshotRows.length).toBe(0);

    const attackerLatestSnapshot = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/runtime-snapshots/latest?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerLatestSnapshot.status).toBe(200);
    expect(attackerLatestSnapshot.json?.snapshot).toBeNull();
  });

  test('cloudflare wallet routes support list/search/detail', async () => {
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_cf_seed_1',
          orgId: 'org-wallet-cf-1',
          projectId: 'proj_wallet_cf_seed_1',
          environmentId: 'env_wallet_cf_seed_1',
        }),
      ],
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-wallet-cf-1', 'user-wallet-cf-1'),
      wallets,
    });

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets?limit=5&chain=Ethereum',
    });
    expect(listed.status).toBe(200);
    const rows = Array.isArray(listed.json?.wallets) ? listed.json?.wallets : [];
    expect(rows.length).toBeGreaterThanOrEqual(1);
    const walletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
    expect(walletId).toBeTruthy();

    const searched = await callCf(handler, {
      method: 'GET',
      path: `/console/wallets/search?q=${encodeURIComponent(walletId.slice(0, 10))}`,
    });
    expect(searched.status).toBe(200);
    const searchedRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
    expect(searchedRows.some((entry: any) => String(entry?.id || '') === walletId)).toBe(true);

    const detail = await callCf(handler, {
      method: 'GET',
      path: `/console/wallets/${encodeURIComponent(walletId)}`,
    });
    expect(detail.status).toBe(200);
    expect(String(getPath(detail.json, 'wallet', 'id') || '')).toBe(walletId);

    const missing = await callCf(handler, {
      method: 'GET',
      path: '/console/wallets/wallet_missing',
    });
    expect(missing.status).toBe(404);
    expect(missing.json?.code).toBe('wallet_not_found');
  });

  test('cloudflare wallet read routes require wallet read role', async () => {
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_cf_forbidden_1',
          orgId: 'org-wallet-read-role-cf-1',
          projectId: 'proj_wallet_read_role_cf_1',
          environmentId: 'env_wallet_read_role_cf_1',
        }),
      ],
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-wallet-read-role-cf-1',
        'user-wallet-read-role-cf-1',
      ),
      wallets,
    });

    for (const path of [
      '/console/wallets?limit=5',
      '/console/wallets/search?q=wallet_cf',
      '/console/wallets/wallet_cf_forbidden_1',
    ]) {
      const res = await callCf(handler, {
        method: 'GET',
        path,
      });
      expect(res.status, path).toBe(403);
      expect(res.json?.code, path).toBe('forbidden');
    }
  });

  test('cloudflare policy/gas/export insight routes return aggregated views', async () => {
    const orgId = 'org-insights-cloudflare-1';
    const projectId = 'default-project';
    const environmentId = `${projectId}:prod`;
    const wallet = makeSeedWallet({
      id: 'wallet_insights_cf_1',
      orgId,
      projectId,
      environmentId,
    });
    wallet.lastActivityAt = wallet.updatedAt;
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [wallet],
    });
    const keyExports = createInMemoryConsoleKeyExportService();
    const policies = createInMemoryConsolePolicyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId,
      projectId,
      actorUserId: 'user-insights-cloudflare-1',
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-insights-cloudflare-1'),
      wallets,
      keyExports,
      policies,
      orgProjectEnv,
    });

    await keyExports.createKeyExport(
      {
        orgId,
        actorUserId: 'user-insights-cloudflare-1',
        roles: ['admin'],
      },
      {
        environmentId,
        reason: 'Break-glass recovery for production wallet',
      },
    );

    const approvedRequest = await keyExports.createKeyExport(
      {
        orgId,
        actorUserId: 'user-insights-cloudflare-approver-1',
        roles: ['admin'],
      },
      {
        environmentId: `${projectId}:stage`,
        reason: 'Stage export drill',
        requiredApprovals: 1,
      },
    );
    await keyExports.approveKeyExport(
      {
        orgId,
        actorUserId: 'user-insights-cloudflare-approver-1',
        roles: ['admin'],
      },
      approvedRequest.id,
      {
        reason: 'Approved stage export drill',
        mfaVerified: true,
      },
    );

    const coverage = await callCf(handler, {
      method: 'GET',
      path: '/console/policy/coverage',
    });
    expect(coverage.status).toBe(200);
    expect(
      Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0),
    ).toBeGreaterThanOrEqual(1);
    const policyRows: unknown[] = Array.isArray(getPath(coverage.json, 'coverage', 'policies'))
      ? (getPath(coverage.json, 'coverage', 'policies') as unknown[])
      : [];
    expect(policyRows.length).toBeGreaterThanOrEqual(1);
    expect(
      policyRows.some((row) => String(getPath(row, 'policyKind') || '') === 'TRANSACTION'),
    ).toBe(true);

    const readiness = await callCf(handler, {
      method: 'GET',
      path: '/console/gas/readiness',
    });
    expect(readiness.status).toBe(200);
    expect(
      Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0),
    ).toBeGreaterThanOrEqual(1);
    const chainRows: unknown[] = Array.isArray(getPath(readiness.json, 'readiness', 'chains'))
      ? (getPath(readiness.json, 'readiness', 'chains') as unknown[])
      : [];
    expect(chainRows.length).toBeGreaterThanOrEqual(1);
    const readinessWalletRows: unknown[] = Array.isArray(
      getPath(readiness.json, 'readiness', 'recentWalletSample'),
    )
      ? (getPath(readiness.json, 'readiness', 'recentWalletSample') as unknown[])
      : [];
    expect(
      readinessWalletRows.some((row) => String(getPath(row, 'policyKind') || '') === 'TRANSACTION'),
    ).toBe(true);

    const governance = await callCf(handler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(governance.status).toBe(200);
    expect(Number(getPath(governance.json, 'governance', 'totals', 'requestCount') || 0)).toBe(2);
    expect(
      Number(
        getPath(governance.json, 'governance', 'totals', 'selectedEnvironmentRequestCount') || 0,
      ),
    ).toBe(1);
    expect(
      Number(getPath(governance.json, 'governance', 'totals', 'pendingApprovalCount') || 0),
    ).toBe(1);
  });

  test('cloudflare policy routes support draft/update/simulate/publish lifecycle with role gates', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-cf-1', 'user-policy-admin-cf-1'),
      policies,
    });

    const listed = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(listed.status).toBe(200);
    const policiesBefore = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
    expect(policiesBefore.length).toBeGreaterThanOrEqual(1);
    const defaultPolicyBefore = policiesBefore.find(
      (entry) => getPath(entry, 'isSystemDefault') === true,
    );
    expect(defaultPolicyBefore).toBeTruthy();
    expect(String(getPath(defaultPolicyBefore, 'id') || '')).toMatch(
      /^policy_[a-z0-9]+_[a-z0-9]+$/,
    );

    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Policy Cloudflare Lifecycle',
        rules: {
          blockedActions: [],
          allowedChains: ['ethereum'],
          maxAmountMinor: 5000,
        },
      },
    });
    expect(created.status).toBe(201);
    const lifecyclePolicyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(lifecyclePolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
    expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
    expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

    const allowedSimulation = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(lifecyclePolicyId)}/simulate`,
      body: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 4000,
      },
    });
    expect(allowedSimulation.status).toBe(200);
    expect(getPath(allowedSimulation.json, 'simulation', 'decision')).toBe('ALLOW');

    const patched = await callCf(adminHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(lifecyclePolicyId)}`,
      body: {
        rules: {
          blockedActions: ['transfer'],
          allowedChains: ['ethereum'],
        },
      },
    });
    expect(patched.status).toBe(200);
    expect(getPath(patched.json, 'policy', 'status')).toBe('DRAFT');

    const deniedSimulation = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(lifecyclePolicyId)}/simulate`,
      body: {
        action: 'transfer',
        chain: 'ethereum',
        amountMinor: 1,
      },
    });
    expect(deniedSimulation.status).toBe(200);
    expect(getPath(deniedSimulation.json, 'simulation', 'decision')).toBe('DENY');

    const published = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(lifecyclePolicyId)}/publish`,
    });
    expect(published.status).toBe(200);
    expect(getPath(published.json, 'result', 'published')).toBe(true);
    expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
    expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], 'org-policy-cf-1', 'user-policy-dev-cf-1'),
      policies,
    });
    const forbiddenCreate = await callCf(developerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Forbidden policy',
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');
  });

  test('cloudflare policy routes enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    let ownerPolicyId = '';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-owner-cf', 'owner-policy-user-cf'),
      policies,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Owner Policy CF',
      },
    });
    expect(created.status).toBe(201);
    ownerPolicyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(ownerPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-attacker-cf', 'attacker-policy-user-cf'),
      policies,
    });
    const listed = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/policies',
    });
    expect(listed.status).toBe(200);
    const attackerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
    expect(attackerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
      false,
    );

    const patched = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}`,
      body: {
        name: 'attacker update cf',
      },
    });
    expect(patched.status).toBe(404);
    expect(patched.json?.code).toBe('policy_not_found');

    const simulated = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
      body: {
        action: 'transfer',
      },
    });
    expect(simulated.status).toBe(404);
    expect(simulated.json?.code).toBe('policy_not_found');
  });

  test('cloudflare policy create rejects client-supplied ids', async () => {
    const policies = createInMemoryConsolePolicyService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-create-id-validation-cf',
        'user-policy-id-cf',
      ),
      policies,
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy_user_supplied_cf',
        name: 'Should fail CF',
      },
    });
    expect(created.status).toBe(400);
    expect(created.json?.code).toBe('invalid_body');
  });

  test('cloudflare policy create, update, and delete append audit rows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-audit-cloudflare',
        'user-policy-audit-cloudflare',
      ),
      policies,
      audit,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Cloudflare audited policy',
        rules: {
          scopeType: 'ENVIRONMENT',
          projectId: 'proj_policy_audit_cloudflare',
          environmentId: 'env_policy_audit_cloudflare',
          enabled: true,
        },
      },
    });
    expect(created.status).toBe(201);
    const policyId = String(getPath(created.json, 'policy', 'id') || '');
    const createdVersion = Number(getPath(created.json, 'policy', 'version') || 0);
    expect(policyId).toBeTruthy();

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(policyId)}`,
      body: {
        name: 'Cloudflare audited policy updated',
      },
    });
    expect(updated.status).toBe(200);

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/policies/${encodeURIComponent(policyId)}`,
    });
    expect(deleted.status).toBe(200);

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-policy-audit-cloudflare',
        actorUserId: 'user-policy-audit-cloudflare',
        roles: ['admin'],
      },
      { category: 'POLICY', limit: 20 },
    );
    const lifecycleEvents = auditEvents.filter((event) =>
      ['policy.create', 'policy.update', 'policy.delete'].includes(String(event.action || '')),
    );
    expect(lifecycleEvents.map((event) => String(event.action || '')).sort()).toEqual([
      'policy.create',
      'policy.delete',
      'policy.update',
    ]);
    expect(lifecycleEvents.every((event) => event.category === 'POLICY')).toBe(true);
    const lifecycleByAction = Object.fromEntries(
      lifecycleEvents.map((event) => [String(event.action || ''), event]),
    );
    expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyId')).toBe(policyId);
    expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyName')).toBe(
      'Cloudflare audited policy updated',
    );
    expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'policyKind')).toBe(
      'GAS_SPONSORSHIP',
    );
    expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'environmentId')).toBe(
      'env_policy_audit_cloudflare',
    );
    expect(getPath(lifecycleByAction['policy.delete'], 'metadata', 'projectId')).toBe(
      'proj_policy_audit_cloudflare',
    );
    expect(lifecycleByAction['policy.delete']?.environmentId).toBe('env_policy_audit_cloudflare');
    expect(lifecycleByAction['policy.delete']?.projectId).toBe('proj_policy_audit_cloudflare');
    expect(getPath(lifecycleByAction['policy.create'], 'metadata', 'policyName')).toBe(
      'Cloudflare audited policy',
    );
    expect(getPath(lifecycleByAction['policy.create'], 'metadata', 'version')).toBe(createdVersion);
  });

  test('cloudflare successful policy create stays quiet while Stripe top-up emits billing observability', async () => {
    const ingested: ObservabilityIngestionEntry[] = [];
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-observability-success-cf',
        'user-observability-success-cf',
      ),
      policies: createInMemoryConsolePolicyService(),
      billing: createInMemoryConsoleBillingService(),
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });

    const createdPolicy = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Healthy observability policy cloudflare',
        rules: evmGasSponsorshipRulesFixture({
          projectId: 'proj_obs_success_cf',
          environmentId: 'env_obs_success_cf',
          chainId: 1,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(createdPolicy.status).toBe(201);
    expect(String(getPath(createdPolicy.json, 'policy', 'id') || '')).toBeTruthy();

    const createdCheckout = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      },
    });
    expect(createdCheckout.status).toBe(201);
    const checkoutSessionId = String(getPath(createdCheckout.json, 'checkoutSession', 'id') || '');
    expect(checkoutSessionId).toBeTruthy();

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session/reconcile',
      body: { checkoutSessionId },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'result', 'settled')).toBe(true);

    expect(policyObservabilityEventTypes(ingested)).toEqual([]);
    expect(observabilityEventTypes(ingested)).toEqual(['billing.balance.recovered']);
  });

  test('cloudflare policy assignment upsert and delete append audit rows', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-assignment-audit-cloudflare',
        'user-policy-assignment-audit-cloudflare',
      ),
      policies,
      audit,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Cloudflare assignment audited policy',
      },
    });
    expect(created.status).toBe(201);
    const policyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(policyId).toBeTruthy();

    const assignmentUpsert = await callCf(handler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'ENVIRONMENT',
        scopeId: 'env_policy_assignment_audit_cloudflare',
        policyId,
      },
    });
    expect(assignmentUpsert.status).toBe(200);
    const assignmentId = String(getPath(assignmentUpsert.json, 'assignment', 'id') || '');
    expect(assignmentId).toBeTruthy();

    const assignmentDelete = await callCf(handler, {
      method: 'DELETE',
      path: `/console/policies/assignments/${encodeURIComponent(assignmentId)}`,
    });
    expect(assignmentDelete.status).toBe(200);

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-policy-assignment-audit-cloudflare',
        actorUserId: 'user-policy-assignment-audit-cloudflare',
        roles: ['admin'],
      },
      { category: 'POLICY', limit: 20 },
    );
    const assignmentEvents = auditEvents.filter((event) =>
      ['policy.assignment.upsert', 'policy.assignment.delete'].includes(String(event.action || '')),
    );
    expect(assignmentEvents.map((event) => String(event.action || '')).sort()).toEqual([
      'policy.assignment.delete',
      'policy.assignment.upsert',
    ]);
    const assignmentByAction = Object.fromEntries(
      assignmentEvents.map((event) => [String(event.action || ''), event]),
    );
    expect(
      getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentId'),
    ).toBe(assignmentId);
    expect(getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'policyId')).toBe(
      policyId,
    );
    expect(
      getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentScopeType'),
    ).toBe('ENVIRONMENT');
    expect(
      getPath(assignmentByAction['policy.assignment.upsert'], 'metadata', 'assignmentScopeId'),
    ).toBe('env_policy_assignment_audit_cloudflare');
    expect(getPath(assignmentByAction['policy.assignment.delete'], 'metadata', 'policyName')).toBe(
      'Cloudflare assignment audited policy',
    );
    expect(assignmentByAction['policy.assignment.upsert']?.environmentId).toBe(
      'env_policy_assignment_audit_cloudflare',
    );
    expect(assignmentByAction['policy.assignment.delete']?.environmentId).toBe(
      'env_policy_assignment_audit_cloudflare',
    );
  });

  test('cloudflare policy publish appends audit row with final version and scope metadata', async () => {
    const policies = createInMemoryConsolePolicyService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-publish-audit-cloudflare',
        'user-policy-publish-audit-cloudflare',
      ),
      policies,
      audit,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        kind: 'GAS_SPONSORSHIP',
        name: 'Cloudflare published audit policy',
        rules: evmGasSponsorshipRulesFixture({
          environmentId: 'env_policy_publish_audit_cloudflare',
          projectId: 'proj_policy_publish_audit_cloudflare',
          chainId: 1,
          capMinor: 500000,
          enabled: true,
        }),
      },
    });
    expect(created.status).toBe(201);
    const policyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(policyId).toBeTruthy();

    const published = await callCf(handler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(policyId)}/publish`,
    });
    expect(published.status).toBe(200);
    expect(getPath(published.json, 'result', 'published')).toBe(true);
    expect(getPath(published.json, 'result', 'policy', 'status')).toBe('PUBLISHED');
    expect(Number(getPath(published.json, 'result', 'policy', 'version') || 0)).toBe(1);

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-policy-publish-audit-cloudflare',
        actorUserId: 'user-policy-publish-audit-cloudflare',
        roles: ['admin'],
      },
      { category: 'POLICY', limit: 20 },
    );
    const publishEvent = auditEvents.find(
      (event) => String(event.action || '') === 'policy.publish',
    );
    expect(publishEvent).toBeTruthy();
    expect(getPath(publishEvent, 'metadata', 'policyId')).toBe(policyId);
    expect(getPath(publishEvent, 'metadata', 'policyName')).toBe(
      'Cloudflare published audit policy',
    );
    expect(getPath(publishEvent, 'metadata', 'policyKind')).toBe('GAS_SPONSORSHIP');
    expect(getPath(publishEvent, 'metadata', 'version')).toBe(1);
    expect(getPath(publishEvent, 'metadata', 'status')).toBe('PUBLISHED');
    expect(getPath(publishEvent, 'metadata', 'scopeType')).toBe('ENVIRONMENT');
    expect(getPath(publishEvent, 'metadata', 'projectId')).toBe(
      'proj_policy_publish_audit_cloudflare',
    );
    expect(getPath(publishEvent, 'metadata', 'environmentId')).toBe(
      'env_policy_publish_audit_cloudflare',
    );
    expect(getPath(publishEvent, 'metadata', 'published')).toBe(true);
    expect(publishEvent?.projectId).toBe('proj_policy_publish_audit_cloudflare');
    expect(publishEvent?.environmentId).toBe('env_policy_publish_audit_cloudflare');
  });

  test('cloudflare policy assignments support precedence and drive policy coverage', async () => {
    const policies = createInMemoryConsolePolicyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_policy_assign_cloudflare_1',
          orgId: 'org-policy-assign-cloudflare',
          projectId: 'proj_policy_assign_cloudflare_1',
          environmentId: 'env_policy_assign_cloudflare_1',
        }),
      ],
    });
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-assign-cloudflare',
        'policy-assign-admin-cf',
      ),
      policies,
      wallets,
    });

    const listedWallets = await callCf(adminHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(listedWallets.status).toBe(200);
    const walletId = String(getPath(listedWallets.json, 'wallets', 0, 'id') || '');
    const projectId = String(getPath(listedWallets.json, 'wallets', 0, 'projectId') || '');
    const environmentId = String(getPath(listedWallets.json, 'wallets', 0, 'environmentId') || '');
    expect(walletId).toBeTruthy();
    expect(projectId).toBeTruthy();
    expect(environmentId).toBeTruthy();

    const createProjectPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Project Policy Cloudflare',
      },
    });
    expect(createProjectPolicy.status).toBe(201);
    const projectPolicyId = String(getPath(createProjectPolicy.json, 'policy', 'id') || '');
    expect(projectPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);
    const publishProjectPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(projectPolicyId)}/publish`,
    });
    expect(publishProjectPolicy.status).toBe(200);

    const createWalletPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Wallet Policy Cloudflare',
      },
    });
    expect(createWalletPolicy.status).toBe(201);
    const walletPolicyId = String(getPath(createWalletPolicy.json, 'policy', 'id') || '');
    expect(walletPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const projectAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'PROJECT',
        scopeId: projectId,
        policyId: projectPolicyId,
      },
    });
    expect(projectAssignment.status).toBe(200);

    const walletAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'WALLET',
        scopeId: walletId,
        policyId: walletPolicyId,
      },
    });
    expect(walletAssignment.status).toBe(200);
    const walletAssignmentId = String(getPath(walletAssignment.json, 'assignment', 'id') || '');
    expect(walletAssignmentId).toBeTruthy();

    const listedAssignments = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policies/assignments?scopeType=WALLET&scopeId=${encodeURIComponent(walletId)}`,
    });
    expect(listedAssignments.status).toBe(200);
    const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
      ? listedAssignments.json?.assignments
      : [];
    expect(assignmentRows.length).toBe(1);
    expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
      walletPolicyId,
    );

    const walletCoverage = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(walletCoverage.status).toBe(200);
    const walletPolicyRows = Array.isArray(getPath(walletCoverage.json, 'coverage', 'policies'))
      ? (getPath(walletCoverage.json, 'coverage', 'policies') as any[])
      : [];
    expect(
      walletPolicyRows.some((entry) => String(entry?.policyId || '') === projectPolicyId),
    ).toBe(true);
    expect(walletPolicyRows.some((entry) => String(entry?.policyId || '') === walletPolicyId)).toBe(
      false,
    );

    const publishWalletPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(walletPolicyId)}/publish`,
    });
    expect(publishWalletPolicy.status).toBe(200);

    const liveWalletCoverage = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(liveWalletCoverage.status).toBe(200);
    const liveWalletPolicyRows = Array.isArray(
      getPath(liveWalletCoverage.json, 'coverage', 'policies'),
    )
      ? (getPath(liveWalletCoverage.json, 'coverage', 'policies') as any[])
      : [];
    expect(
      liveWalletPolicyRows.some((entry) => String(entry?.policyId || '') === walletPolicyId),
    ).toBe(true);

    const removedWalletAssignment = await callCf(adminHandler, {
      method: 'DELETE',
      path: `/console/policies/assignments/${encodeURIComponent(walletAssignmentId)}`,
    });
    expect(removedWalletAssignment.status).toBe(200);
    expect(getPath(removedWalletAssignment.json, 'removed')).toBe(true);

    const projectCoverage = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(projectCoverage.status).toBe(200);
    const projectPolicyRows = Array.isArray(getPath(projectCoverage.json, 'coverage', 'policies'))
      ? (getPath(projectCoverage.json, 'coverage', 'policies') as any[])
      : [];
    expect(
      projectPolicyRows.some((entry) => String(entry?.policyId || '') === projectPolicyId),
    ).toBe(true);

    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-policy-assign-cloudflare',
        'policy-assign-developer-cf',
      ),
      policies,
      wallets,
    });
    const forbiddenAssignment = await callCf(developerHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'ORG',
        scopeId: 'org-policy-assign-cloudflare',
        policyId: 'policy_forbidden_org_assignment_cloudflare',
      },
    });
    expect(forbiddenAssignment.status).toBe(403);
    expect(forbiddenAssignment.json?.code).toBe('forbidden');
  });

  test('cloudflare policy creation can attach a draft to scope in one request', async () => {
    const policies = createInMemoryConsolePolicyService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-policy-create-attach-cloudflare',
        'policy-create-attach-admin-cf',
      ),
      policies,
    });

    const environmentScopeId = 'env_policy_create_attach_cloudflare_1';
    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        name: 'Attached draft cloudflare',
        assignment: {
          scopeType: 'ENVIRONMENT',
          scopeId: environmentScopeId,
        },
      },
    });
    expect(created.status).toBe(201);
    const createdPolicyId = String(getPath(created.json, 'policy', 'id') || '');
    expect(createdPolicyId).toMatch(/^policy_[a-z0-9]+_[a-z0-9]+$/);

    const listedAssignments = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/policies/assignments?scopeType=ENVIRONMENT&scopeId=${encodeURIComponent(environmentScopeId)}`,
    });
    expect(listedAssignments.status).toBe(200);
    const assignmentRows = Array.isArray(listedAssignments.json?.assignments)
      ? listedAssignments.json?.assignments
      : [];
    expect(assignmentRows.length).toBe(1);
    expect(String(getPath(listedAssignments.json, 'assignments', 0, 'policyId') || '')).toBe(
      createdPolicyId,
    );
  });

  test('cloudflare API key lifecycle works and secrets are reveal-once on create/rotate', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const environmentId = 'default-project:prod';
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-1',
      projectId: 'default-project',
      actorUserId: 'user-1',
    });
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'cloudflare-key',
        environmentId,
        kind: 'secret_key',
        scopes: ['accounts.create'],
        ipAllowlist: ['198.51.100.5/32'],
        expiresAt,
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    const createdSecret = String(getPath(created.json, 'secret') || '');
    expect(keyId).toBeTruthy();
    expect(createdSecret).toContain('sk_');
    expect(Number(getPath(created.json, 'apiKey', 'secretVersion') || 0)).toBe(1);
    expect(String(getPath(created.json, 'apiKey', 'expiresAt') || '')).toBe(expiresAt);

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(listed.status).toBe(200);
    expect(String(getPath(listed.json, 'apiKeys', 0, 'id') || '')).toBe(keyId);
    expect(getPath(listed.json, 'apiKeys', 0, 'secret')).toBeUndefined();

    const rotated = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
      body: {
        reason: 'manual rotate',
      },
    });
    expect(rotated.status).toBe(200);
    const rotatedSecret = String(getPath(rotated.json, 'secret') || '');
    expect(rotatedSecret).toContain('sk_');
    expect(rotatedSecret).not.toBe(createdSecret);
    expect(Number(getPath(rotated.json, 'apiKey', 'secretVersion') || 0)).toBe(2);

    const revoked = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}`,
      body: {
        reason: 'security incident',
      },
    });
    expect(revoked.status).toBe(200);
    expect(getPath(revoked.json, 'revoked')).toBe(true);
    expect(getPath(revoked.json, 'apiKey', 'status')).toBe('REVOKED');
    expect(getPath(revoked.json, 'apiKey', 'revokedReason')).toBe('security incident');

    const rotateRevoked = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
    });
    expect(rotateRevoked.status).toBe(409);
    expect(rotateRevoked.json?.code).toBe('api_key_revoked');
  });

  test('cloudflare API key create validates environment scope against caller org', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-api-key-env-validation-cf',
        'user-api-key-admin-cf',
      ),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'invalid-environment-key-cf',
        environmentId: 'env-missing',
        kind: 'secret_key',
        scopes: ['accounts.create'],
      },
    });
    expect(created.status).toBe(400);
    expect(created.json?.code).toBe('invalid_environment');
  });

  test('cloudflare API key create rejects non-future expiresAt timestamp', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-api-key-expiry-validation-cf',
        'user-api-key-admin-cf',
      ),
      apiKeys,
      orgProjectEnv,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'invalid-expiry-key-cf',
        environmentId: 'default-project:prod',
        kind: 'secret_key',
        scopes: ['accounts.create'],
        expiresAt: '2000-01-01T00:00:00.000Z',
      },
    });
    expect(created.status).toBe(400);
    expect(created.json?.code).toBe('invalid_body');
  });

  test('cloudflare API key mutation routes require owner/admin/security_admin role', async () => {
    const orgId = 'org-api-key-rbac-cf';
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const created = await apiKeys.createApiKey(
      { orgId, actorUserId: 'seed-admin-cf', roles: ['admin'] },
      {
        name: 'seed-key-cf',
        environmentId: 'env-rbac-cf',
        kind: 'secret_key',
        scopes: ['accounts.create'],
      },
    );

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer'], orgId, 'user-api-key-developer-cf'),
      apiKeys,
      orgProjectEnv,
    });

    const forbiddenCreate = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'developer-create-key-cf',
        environmentId: 'env-rbac-cf',
        kind: 'secret_key',
        scopes: ['accounts.create'],
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');

    const forbiddenRotate = await callCf(handler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(created.apiKey.id)}/rotate`,
      body: {
        reason: 'developer rotate',
      },
    });
    expect(forbiddenRotate.status).toBe(403);
    expect(forbiddenRotate.json?.code).toBe('forbidden');

    const forbiddenDelete = await callCf(handler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(created.apiKey.id)}`,
    });
    expect(forbiddenDelete.status).toBe(403);
    expect(forbiddenDelete.json?.code).toBe('forbidden');
  });

  test('cloudflare webhook routes support delivery attempts, dead letters, and replay', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-webhook',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(listed.status).toBe(200);
    expect(Array.isArray(listed.json?.endpoints)).toBe(true);
    expect(String(getPath(listed.json, 'endpoints', 0, 'id') || '')).toBe(endpointId);

    const emitted = await webhooks.emitEvent(
      {
        orgId: 'org-1',
        actorUserId: 'system-webhooks-test',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.paid',
        payload: {
          invoiceId: 'inv_cf_1',
        },
      },
    );
    expect(emitted.attempted).toBe(1);
    expect(emitted.delivered).toBe(0);
    expect(emitted.failed).toBe(1);

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    expect(rows.length).toBe(1);
    expect(String(getPath(deliveries.json, 'deliveries', 0, 'status') || '')).toBe('FAILED');
    const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
    expect(deliveryId).toBeTruthy();

    const attemptsBeforeReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts`,
    });
    expect(attemptsBeforeReplay.status).toBe(200);
    expect(Number(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(getPath(attemptsBeforeReplay.json, 'attempts', 0, 'status')).toBe('FAILED');

    const unresolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedDlq.status).toBe(200);
    const unresolvedRows = Array.isArray(unresolvedDlq.json?.deadLetters)
      ? unresolvedDlq.json?.deadLetters
      : [];
    expect(unresolvedRows.length).toBe(1);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(getPath(unresolvedDlq.json, 'deadLetters', 0, 'resolvedAt')).toBeNull();

    const replayed = await callCf(handler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: { deliveryId },
    });
    expect(replayed.status).toBe(200);
    expect(getPath(replayed.json, 'replay', 'replayed')).toBe(true);
    expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');

    const attemptsAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1`,
    });
    expect(attemptsAfterReplay.status).toBe(200);
    const replayAttempts = Array.isArray(attemptsAfterReplay.json?.attempts)
      ? attemptsAfterReplay.json?.attempts
      : [];
    expect(replayAttempts.length).toBe(1);
    expect(Number(getPath(attemptsAfterReplay.json, 'attempts', 0, 'attemptNo') || 0)).toBe(2);
    expect(getPath(attemptsAfterReplay.json, 'attempts', 0, 'isReplay')).toBe(true);
    const attemptsNextCursor = String(attemptsAfterReplay.json?.nextCursor || '');
    expect(attemptsNextCursor).toBeTruthy();

    const attemptsSecondPage = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?deliveryId=${encodeURIComponent(deliveryId)}&limit=1&cursor=${encodeURIComponent(attemptsNextCursor)}`,
    });
    expect(attemptsSecondPage.status).toBe(200);
    const replayAttemptsSecondPage = Array.isArray(attemptsSecondPage.json?.attempts)
      ? attemptsSecondPage.json?.attempts
      : [];
    expect(replayAttemptsSecondPage.length).toBe(1);
    expect(Number(getPath(attemptsSecondPage.json, 'attempts', 0, 'attemptNo') || 0)).toBe(1);
    expect(String(attemptsSecondPage.json?.nextCursor || '')).toBe('');

    const unresolvedAfterReplay = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters`,
    });
    expect(unresolvedAfterReplay.status).toBe(200);
    const unresolvedRowsAfterReplay = Array.isArray(unresolvedAfterReplay.json?.deadLetters)
      ? unresolvedAfterReplay.json?.deadLetters
      : [];
    expect(unresolvedRowsAfterReplay.length).toBe(0);

    const resolvedDlq = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?includeResolved=true`,
    });
    expect(resolvedDlq.status).toBe(200);
    const resolvedRows = Array.isArray(resolvedDlq.json?.deadLetters)
      ? resolvedDlq.json?.deadLetters
      : [];
    expect(resolvedRows.length).toBe(1);
    expect(getPath(resolvedDlq.json, 'deadLetters', 0, 'deliveryId')).toBe(deliveryId);
    expect(Boolean(getPath(resolvedDlq.json, 'deadLetters', 0, 'resolvedAt'))).toBe(true);

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
      body: {
        status: 'DISABLED',
      },
    });
    expect(updated.status).toBe(200);
    expect(getPath(updated.json, 'endpoint', 'status')).toBe('DISABLED');

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(200);
    expect(deleted.json?.removed).toBe(true);
  });

  test('cloudflare webhook endpoint create, update, delete, and replay append audit rows', async () => {
    let dispatchCalls = 0;
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => {
          dispatchCalls += 1;
          if (dispatchCalls === 1) {
            return {
              ok: false,
              statusCode: 500,
              responseBody: 'temporary failure',
              errorMessage: 'upstream failure',
            };
          }
          return {
            ok: true,
            statusCode: 200,
            responseBody: 'ok',
          };
        },
      },
    });
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-webhook-audit-cloudflare',
        'user-webhook-audit-cloudflare',
      ),
      webhooks,
      audit,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-webhook-audit',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const updated = await callCf(handler, {
      method: 'PATCH',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
      body: {
        url: 'https://example.com/cloudflare-webhook-audit-updated',
      },
    });
    expect(updated.status).toBe(200);

    const emitted = await webhooks.emitEvent(
      {
        orgId: 'org-webhook-audit-cloudflare',
        actorUserId: 'system-webhooks-audit-cloudflare',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.generated',
        payload: {
          invoiceId: 'inv_webhook_audit_cloudflare',
        },
      },
    );
    expect(emitted.attempted).toBe(1);
    expect(emitted.failed).toBe(1);

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
    expect(deliveryId).toBeTruthy();

    const replayed = await callCf(handler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: { deliveryId },
    });
    expect(replayed.status).toBe(200);
    expect(getPath(replayed.json, 'replay', 'delivery', 'status')).toBe('SUCCEEDED');

    const deleted = await callCf(handler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(200);
    expect(deleted.json?.removed).toBe(true);

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-webhook-audit-cloudflare',
        actorUserId: 'user-webhook-audit-cloudflare',
        roles: ['admin'],
      },
      { category: 'WEBHOOK', limit: 20 },
    );
    const webhookEvents = auditEvents.filter((event) =>
      [
        'webhook.endpoint.create',
        'webhook.endpoint.update',
        'webhook.endpoint.delete',
        'webhook.delivery.replay_requested',
      ].includes(String(event.action || '')),
    );
    expect(webhookEvents.map((event) => String(event.action || '')).sort()).toEqual([
      'webhook.delivery.replay_requested',
      'webhook.endpoint.create',
      'webhook.endpoint.delete',
      'webhook.endpoint.update',
    ]);
    expect(webhookEvents.every((event) => event.category === 'WEBHOOK')).toBe(true);
    expect(
      webhookEvents.every((event) => event.actorUserId === 'user-webhook-audit-cloudflare'),
    ).toBe(true);

    const webhookByAction = Object.fromEntries(
      webhookEvents.map((event) => [String(event.action || ''), event]),
    );
    expect(getPath(webhookByAction['webhook.endpoint.create'], 'metadata', 'endpointId')).toBe(
      endpointId,
    );
    expect(getPath(webhookByAction['webhook.endpoint.create'], 'metadata', 'endpointUrl')).toBe(
      'https://example.com/cloudflare-webhook-audit',
    );
    expect(getPath(webhookByAction['webhook.endpoint.update'], 'metadata', 'endpointUrl')).toBe(
      'https://example.com/cloudflare-webhook-audit-updated',
    );
    expect(
      getPath(webhookByAction['webhook.endpoint.update'], 'metadata', 'eventCategories'),
    ).toEqual(['billing']);
    expect(
      getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'endpointId'),
    ).toBe(endpointId);
    expect(
      getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'deliveryId'),
    ).toBe(deliveryId);
    expect(
      getPath(
        webhookByAction['webhook.delivery.replay_requested'],
        'metadata',
        'requestedDeliveryId',
      ),
    ).toBe(deliveryId);
    expect(
      getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'selectionMode'),
    ).toBe('explicit_delivery');
    expect(
      getPath(
        webhookByAction['webhook.delivery.replay_requested'],
        'metadata',
        'deliveryEventType',
      ),
    ).toBe('billing.invoice.generated');
    expect(
      Number(
        getPath(webhookByAction['webhook.delivery.replay_requested'], 'metadata', 'replayCount') ||
          0,
      ),
    ).toBe(1);
    expect(getPath(webhookByAction['webhook.endpoint.delete'], 'metadata', 'endpointId')).toBe(
      endpointId,
    );
    expect(getPath(webhookByAction['webhook.endpoint.delete'], 'metadata', 'endpointUrl')).toBe(
      'https://example.com/cloudflare-webhook-audit-updated',
    );
  });

  test('cloudflare webhook delivery failures append dead-letter and endpoint degraded observability events', async () => {
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    const webhooks = createInMemoryConsoleWebhookService({
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
      endpointDegradedThreshold: 2,
      dispatcher: {
        dispatch: async () => ({
          ok: false,
          statusCode: 500,
          responseBody: 'temporary failure',
          errorMessage: 'upstream failure',
        }),
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-observability-webhook',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    await webhooks.emitEvent(
      {
        orgId: 'org-1',
        actorUserId: 'system-webhooks-observability',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.failed',
        payload: { invoiceId: 'inv_obs_webhook_cf_1' },
      },
    );
    await webhooks.emitEvent(
      {
        orgId: 'org-1',
        actorUserId: 'system-webhooks-observability',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.failed',
        payload: { invoiceId: 'inv_obs_webhook_cf_2' },
      },
    );

    const deadLetterEvents = ingested.filter(
      (entry) => entry.event.eventType === 'webhook.delivery.dead_letter',
    );
    const degradedEvents = ingested.filter(
      (entry) => entry.event.eventType === 'webhook.endpoint.degraded',
    );
    expect(deadLetterEvents).toHaveLength(2);
    expect(degradedEvents).toHaveLength(1);
    expect(String(getPath(deadLetterEvents[0]?.event, 'metadata', 'endpointId') || '')).toBe(
      endpointId,
    );
    expect(
      Number(getPath(degradedEvents[0]?.event, 'metadata', 'unresolvedDeadLetterCount') || 0),
    ).toBe(2);
  });

  test('cloudflare webhook mutations require console config mutation role', async () => {
    const webhooks = createInMemoryConsoleWebhookService();
    const adminHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks,
    });
    const developerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['developer']),
      webhooks,
    });

    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-restricted-webhook',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const listed = await callCf(developerHandler, {
      method: 'GET',
      path: '/console/webhooks',
    });
    expect(listed.status).toBe(200);

    const forbiddenCreate = await callCf(developerHandler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-forbidden-webhook',
        eventCategories: ['billing'],
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');

    const emitted = await webhooks.emitEvent(
      {
        orgId: 'org-1',
        actorUserId: 'system-webhooks-rbac-cloudflare',
        roles: ['ops'],
      },
      {
        eventType: 'billing.invoice.paid',
        payload: {
          invoiceId: 'inv_webhook_rbac_cloudflare',
        },
      },
    );
    expect(emitted.attempted).toBe(1);
    const deliveries = await callCf(adminHandler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    const deliveryId = String(getPath(deliveries.json, 'deliveries', 0, 'id') || '');
    expect(deliveryId).toBeTruthy();

    const forbiddenUpdate = await callCf(developerHandler, {
      method: 'PATCH',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
      body: {
        status: 'DISABLED',
      },
    });
    expect(forbiddenUpdate.status).toBe(403);
    expect(forbiddenUpdate.json?.code).toBe('forbidden');

    const forbiddenReplay = await callCf(developerHandler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: { deliveryId },
    });
    expect(forbiddenReplay.status).toBe(403);
    expect(forbiddenReplay.json?.code).toBe('forbidden');

    const forbiddenDelete = await callCf(developerHandler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(forbiddenDelete.status).toBe(403);
    expect(forbiddenDelete.json?.code).toBe('forbidden');
  });

  test('cloudflare webhook list endpoints reject malformed cursor', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      webhooks: createInMemoryConsoleWebhookService(),
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/bad-cursor-cloudflare',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=bad_cursor`,
    });
    expect(deliveries.status).toBe(400);
    expect(deliveries.json?.code).toBe('invalid_query');

    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=bad_cursor`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const deadLetters = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/dead-letters?cursor=bad_cursor`,
    });
    expect(deadLetters.status).toBe(400);
    expect(deadLetters.json?.code).toBe('invalid_query');

    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?cursor=9007199254740992%3Aoverflow`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('POST /console/billing/stripe/checkout-session returns billing_not_configured without billing service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('billing_not_configured');
  });

  test('POST /console/billing/stripe/checkout-session creates checkout session', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      },
    });
    expect(created.status).toBe(201);
    const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
    const checkoutSessionUrl = String(getPath(created.json, 'checkoutSession', 'url') || '');
    expect(checkoutSessionId).toBeTruthy();
    expect(checkoutSessionUrl).toContain('https://checkout.stripe.com/pay/');
    expect(String(getPath(created.json, 'checkoutSession', 'customerRef') || '')).toContain('cus_');
    expect(getPath(created.json, 'checkoutSession', 'creditPackId')).toBe('usd_25');
    expect(Number(getPath(created.json, 'checkoutSession', 'amountMinor') || 0)).toBe(2500);
    expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
      /^\d{4}-\d{2}-\d{2}T/,
    );

    const customCreated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_custom',
        customAmountMinor: 12345,
      },
    });
    expect(customCreated.status).toBe(201);
    expect(getPath(customCreated.json, 'checkoutSession', 'creditPackId')).toBe('usd_custom');
    expect(Number(getPath(customCreated.json, 'checkoutSession', 'amountMinor') || 0)).toBe(12345);

    const invalid = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: '/dashboard/billing',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.json?.code).toBe('invalid_body');

    const missingCustomAmount = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_custom',
      },
    });
    expect(missingCustomAmount.status).toBe(400);
    expect(missingCustomAmount.json?.code).toBe('invalid_body');
  });

  test('POST /console/billing/stripe/checkout-session/reconcile settles a paid checkout session', async () => {
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
      audit,
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      },
    });
    expect(created.status).toBe(201);
    const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
    expect(checkoutSessionId).toBeTruthy();

    const reconciled = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session/reconcile',
      body: {
        checkoutSessionId,
      },
    });
    expect(reconciled.status).toBe(200);
    expect(getPath(reconciled.json, 'result', 'settled')).toBe(true);
    expect(getPath(reconciled.json, 'result', 'settledNow')).toBe(true);
    expect(getPath(reconciled.json, 'result', 'purchase', 'status')).toBe('SETTLED');
    expect(getPath(reconciled.json, 'result', 'invoice', 'documentType')).toBe('PURCHASE_RECEIPT');

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session/reconcile',
      body: {
        checkoutSessionId,
      },
    });
    expect(duplicate.status).toBe(200);
    expect(getPath(duplicate.json, 'result', 'settled')).toBe(true);
    expect(getPath(duplicate.json, 'result', 'settledNow')).toBe(false);

    const overview = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overview.status).toBe(200);
    expect(Number(getPath(overview.json, 'overview', 'creditBalanceMinor') || 0)).toBe(2500);

    const auditEvents = await audit.listEvents({
      orgId: 'org-1',
      actorUserId: 'user-1',
      roles: ['admin'],
    });
    const settlementEvents = auditEvents.filter(
      (event) => String(event.action || '') === 'billing.credit_purchase.settled',
    );
    expect(settlementEvents).toHaveLength(1);
    expect(settlementEvents[0]?.actorType).toBe('USER');
    expect(settlementEvents[0]?.actorUserId).toBe('user-1');
    expect(getPath(settlementEvents[0], 'metadata', 'purchaseId')).toBe(
      getPath(reconciled.json, 'result', 'purchase', 'id'),
    );
    expect(getPath(settlementEvents[0], 'metadata', 'receiptId')).toBe(
      getPath(reconciled.json, 'result', 'invoice', 'id'),
    );
    expect(getPath(settlementEvents[0], 'metadata', 'settlementSource')).toBe(
      'stripe_checkout_reconcile',
    );
    expect(getPath(settlementEvents[0], 'metadata', 'settlementEventId')).toBe(
      `stripe_checkout_reconcile:${checkoutSessionId}`,
    );
  });

  test('GET /console/platform/billing/account resolves project-scoped lookup for platform_admin', async () => {
    const billing = createInMemoryConsoleBillingService({
      now: () => new Date('2026-03-20T00:00:00.000Z'),
    });
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const targetCtx = {
      orgId: 'org-platform-target-cloudflare',
      actorUserId: 'platform-user-cloudflare',
      roles: ['platform_admin'],
    };
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-platform-target-cloudflare',
      projectId: 'proj-platform-target-cloudflare',
      actorUserId: 'platform-user-cloudflare',
    });
    await teamRbac.bootstrapOwner({
      orgId: 'org-platform-target-cloudflare',
      actorUserId: 'owner-platform-target-cloudflare',
      roles: ['owner'],
      actorEmail: 'owner-platform-target-cloudflare@example.com',
      actorDisplayName: 'Owner Cloudflare',
    });
    await teamRbac.inviteMember(
      {
        orgId: 'org-platform-target-cloudflare',
        actorUserId: 'owner-platform-target-cloudflare',
        roles: ['owner'],
      },
      {
        userId: 'admin-platform-target-cloudflare',
        email: 'admin-platform-target-cloudflare@example.com',
        displayName: 'Admin Cloudflare',
        roles: [{ role: 'admin', scope: 'ORG' }],
      },
    );
    await billing.grantManualSupportCredit(targetCtx, {
      amountMinor: 1200,
      reasonCode: 'incident_credit',
      note: 'Seed manual credit',
      idempotencyKey: 'platform-lookup-credit-cloudflare',
    });
    await billing.recordUsageEvent(targetCtx, {
      walletId: 'wallet-platform-cloudflare',
      action: 'transfer',
      succeeded: true,
      occurredAt: '2026-02-15T00:00:00.000Z',
      sourceEventId: 'usage-platform-cloudflare',
    });

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-cloudflare',
        'platform-user-cloudflare',
      ),
      billing,
      orgProjectEnv,
      teamRbac,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: `/console/platform/billing/account?projectId=${encodeURIComponent(
        'proj-platform-target-cloudflare',
      )}&periodMonthUtc=2026-03&eventType=MANUAL_ADJUSTMENT`,
    });
    expect(res.status).toBe(200);
    expect(String(getPath(res.json, 'result', 'organization', 'id') || '')).toBe(
      'org-platform-target-cloudflare',
    );
    expect(String(getPath(res.json, 'result', 'project', 'id') || '')).toBe(
      'proj-platform-target-cloudflare',
    );
    expect(Number(getPath(res.json, 'result', 'overview', 'creditBalanceMinor') || 0)).toBe(900);
    const entries = Array.isArray(getPath(res.json, 'result', 'activity', 'entries'))
      ? (getPath(res.json, 'result', 'activity', 'entries') as any[])
      : [];
    expect(entries).toHaveLength(1);
    expect(String(entries[0]?.type || '')).toBe('MANUAL_ADJUSTMENT');
    expect(String(entries[0]?.reasonCode || '')).toBe('incident_credit');
    const teamMembers = Array.isArray(getPath(res.json, 'result', 'teamMembers'))
      ? (getPath(res.json, 'result', 'teamMembers') as any[])
      : [];
    expect(teamMembers.map((entry) => String(entry?.displayName || ''))).toEqual([
      'Owner Cloudflare',
      'Admin Cloudflare',
    ]);
    expect(teamMembers.map((entry) => String(entry?.access || ''))).toEqual(['OWNER', 'ADMIN']);
    expect(teamMembers.map((entry) => String(entry?.status || ''))).toEqual(['ACTIVE', 'ACTIVE']);
  });

  test('GET /console/platform/billing/search finds organization matches for platform_admin', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const searchCtx = {
      orgId: 'org-platform-search-primary-cloudflare',
      actorUserId: 'platform-user-cloudflare',
      roles: ['platform_admin'],
    };
    await orgProjectEnv.upsertOrganization(searchCtx, {
      name: 'Watchbook Marketplace',
      slug: 'watchbook-marketplace',
    });
    await orgProjectEnv.createProject(searchCtx, {
      id: 'proj-platform-search-primary-cloudflare',
      name: 'Marketplace API',
      liveEnvironmentsEnabled: true,
    });
    await orgProjectEnv.upsertOrganization(
      {
        orgId: 'org-platform-search-secondary-cloudflare',
        actorUserId: 'platform-user-cloudflare',
        roles: ['platform_admin'],
      },
      {
        name: 'Acme Labs',
        slug: 'acme-labs',
      },
    );

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-cloudflare',
        'platform-user-cloudflare',
      ),
      orgProjectEnv,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: `/console/platform/billing/search?query=${encodeURIComponent('watchbook')}`,
    });
    expect(res.status).toBe(200);
    const organizations = Array.isArray(getPath(res.json, 'organizations'))
      ? (getPath(res.json, 'organizations') as any[])
      : [];
    expect(organizations).toHaveLength(1);
    expect(String(organizations[0]?.id || '')).toBe('org-platform-search-primary-cloudflare');
    expect(String(organizations[0]?.name || '')).toBe('Watchbook Marketplace');
  });

  test('GET /console/platform/billing/search returns the 5 most recent organizations when query is empty', async () => {
    let currentNow = new Date('2026-03-01T00:00:00.000Z');
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService({
      now: () => currentNow,
    });
    const organizations = [
      ['org-platform-recent-1-cloudflare', 'Recent One'],
      ['org-platform-recent-2-cloudflare', 'Recent Two'],
      ['org-platform-recent-3-cloudflare', 'Recent Three'],
      ['org-platform-recent-4-cloudflare', 'Recent Four'],
      ['org-platform-recent-5-cloudflare', 'Recent Five'],
      ['org-platform-recent-6-cloudflare', 'Recent Six'],
    ] as const;
    for (const [index, [orgId, name]] of organizations.entries()) {
      currentNow = new Date(`2026-03-${String(index + 1).padStart(2, '0')}T00:00:00.000Z`);
      await orgProjectEnv.upsertOrganization(
        {
          orgId,
          actorUserId: 'platform-user-cloudflare',
          roles: ['platform_admin'],
        },
        {
          name,
          slug: name.toLowerCase().replace(/\s+/g, '-'),
        },
      );
    }

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-cloudflare',
        'platform-user-cloudflare',
      ),
      orgProjectEnv,
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/platform/billing/search?query=&limit=5',
    });
    expect(res.status).toBe(200);
    const rows = Array.isArray(getPath(res.json, 'organizations'))
      ? (getPath(res.json, 'organizations') as any[])
      : [];
    expect(rows.map((row) => String(row?.id || ''))).toEqual([
      'org-platform-recent-6-cloudflare',
      'org-platform-recent-5-cloudflare',
      'org-platform-recent-4-cloudflare',
      'org-platform-recent-3-cloudflare',
      'org-platform-recent-2-cloudflare',
    ]);
  });

  test('POST /console/platform/billing/adjustments/support-credit applies to target org for platform_admin', async () => {
    const billing = createInMemoryConsoleBillingService({
      now: () => new Date('2026-03-20T00:00:00.000Z'),
    });
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId: 'org-platform-adjust-target-cloudflare',
      projectId: 'proj-platform-adjust-target-cloudflare',
      actorUserId: 'platform-user-cloudflare',
    });

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['platform_admin'],
        'org-platform-session-cloudflare',
        'platform-user-cloudflare',
      ),
      billing,
      audit,
      orgProjectEnv,
      teamRbac,
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/platform/billing/adjustments/support-credit',
      body: {
        orgId: 'org-platform-adjust-target-cloudflare',
        amountMinor: 1500,
        reasonCode: 'incident_credit',
        note: 'Applied by platform admin',
        idempotencyKey: 'platform-adjust-credit-cloudflare',
      },
    });
    expect(res.status).toBe(201);
    expect(String(getPath(res.json, 'result', 'adjustment', 'orgId') || '')).toBe(
      'org-platform-adjust-target-cloudflare',
    );
    expect(Number(getPath(res.json, 'result', 'creditBalanceMinor') || 0)).toBe(1500);

    const lookup = await callCf(handler, {
      method: 'GET',
      path: `/console/platform/billing/account?orgId=${encodeURIComponent(
        'org-platform-adjust-target-cloudflare',
      )}`,
    });
    expect(lookup.status).toBe(200);
    expect(Number(getPath(lookup.json, 'result', 'overview', 'creditBalanceMinor') || 0)).toBe(
      1500,
    );

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-platform-adjust-target-cloudflare',
        actorUserId: 'platform-user-cloudflare',
        roles: ['platform_admin'],
      },
      { limit: 10 },
    );
    const adjustmentAudit = auditEvents.find(
      (event) => String(event.action || '') === 'billing.adjustment.support_credit',
    );
    expect(String(adjustmentAudit?.metadata?.organizationId || '')).toBe(
      'org-platform-adjust-target-cloudflare',
    );
    expect(String(adjustmentAudit?.metadata?.organizationName || '')).toBe('Default Organization');
    expect(String(adjustmentAudit?.metadata?.note || '')).toBe('Applied by platform admin');
    expect(String(adjustmentAudit?.metadata?.platformBilling || '')).toBe('true');
  });

  test('POST /console/billing/stripe/webhook requires configured shared secret', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      body: {
        eventId: 'evt_cf_missing_secret',
        providerRef: 'pi_provider_missing',
        providerStatus: 'SUCCEEDED',
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('stripe_webhook_not_configured');
  });

  test('POST /console/billing/invoices/generate requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('POST /console/billing/adjustments/support-credit requires platform_admin role (cloudflare)', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['ops']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 100,
        reasonCode: 'incident_credit',
        note: 'Should be rejected',
        idempotencyKey: 'manual-credit-cloudflare-forbidden',
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
    expect(String(res.json?.message || '')).toContain('platform_admin');
  });

  test('POST /console/billing/adjustments/admin-debit allows platform_admin for large debit amounts (cloudflare)', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/admin-debit',
      body: {
        amountMinor: 50000,
        reasonCode: 'large_debit_correction',
        note: 'Platform operator approved large debit',
        idempotencyKey: 'manual-debit-cloudflare-large-platform',
      },
    });
    expect(res.status).toBe(201);
    expect(Number(getPath(res.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(-50000);
  });

  test('manual billing adjustment routes append audited support credits and admin debits (cloudflare)', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin', 'billing_admin']),
      billing,
      audit,
    });

    const supportCredit = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 1200,
        reasonCode: 'incident_credit',
        note: 'Applied support credit after incident review',
        idempotencyKey: 'manual-credit-cloudflare-1',
      },
    });
    expect(supportCredit.status).toBe(201);
    expect(getPath(supportCredit.json, 'result', 'created')).toBe(true);
    expect(Number(getPath(supportCredit.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(
      1200,
    );

    const duplicateCredit = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 1200,
        reasonCode: 'incident_credit',
        note: 'Applied support credit after incident review',
        idempotencyKey: 'manual-credit-cloudflare-1',
      },
    });
    expect(duplicateCredit.status).toBe(200);
    expect(getPath(duplicateCredit.json, 'result', 'created')).toBe(false);
    expect(getPath(duplicateCredit.json, 'result', 'adjustment', 'id')).toBe(
      getPath(supportCredit.json, 'result', 'adjustment', 'id'),
    );

    const adminDebit = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/admin-debit',
      body: {
        amountMinor: 200,
        reasonCode: 'duplicate_credit_correction',
        note: 'Corrected duplicate support credit',
        idempotencyKey: 'manual-debit-cloudflare-1',
      },
    });
    expect(adminDebit.status).toBe(201);
    expect(getPath(adminDebit.json, 'result', 'created')).toBe(true);
    expect(Number(getPath(adminDebit.json, 'result', 'adjustment', 'amountMinor') || 0)).toBe(-200);

    const overview = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overview.status).toBe(200);
    expect(Number(getPath(overview.json, 'overview', 'creditBalanceMinor') || 0)).toBe(1000);

    const activity = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/account/activity?limit=5',
    });
    expect(activity.status).toBe(200);
    expect(
      (Array.isArray(getPath(activity.json, 'activity', 'entries'))
        ? (getPath(activity.json, 'activity', 'entries') as unknown[])
        : []
      ).map((entry) => Number(getPath(entry, 'amountMinor') || 0)),
    ).toEqual([-200, 1200]);

    const auditEvents = await audit.listEvents(
      { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
      { limit: 20 },
    );
    expect(
      auditEvents
        .filter((event) =>
          ['billing.adjustment.support_credit', 'billing.adjustment.admin_debit'].includes(
            String(event.action || ''),
          ),
        )
        .map((event) => String(event.action || ''))
        .sort(),
    ).toEqual([
      'billing.adjustment.admin_debit',
      'billing.adjustment.support_credit',
      'billing.adjustment.support_credit',
    ]);
  });

  test('manual billing adjustments emit sponsorship balance transition webhook events and observability logs (cloudflare)', async () => {
    const billing = createInMemoryConsoleBillingService();
    const ingested: Array<{
      ingestCtx: Record<string, unknown>;
      event: Record<string, unknown>;
    }> = [];
    await billing.grantManualSupportCredit(
      { orgId: 'org-1', actorUserId: 'seed-user', roles: ['platform_admin'] },
      {
        amountMinor: 4000,
        reasonCode: 'seed_credit',
        note: 'Seed balance for transition events',
        idempotencyKey: 'seed-balance-transition-cloudflare',
      },
    );
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const endpoint = await webhooks.createEndpoint(
      { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
      {
        url: 'https://example.com/billing-transition-cloudflare',
        eventCategories: ['billing'],
      },
    );
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['platform_admin']),
      billing,
      webhooks,
      observabilityIngestion: makeObservabilityIngestionCollector(ingested),
    });

    const lowBalance = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/admin-debit',
      body: {
        amountMinor: 2500,
        reasonCode: 'lower_to_threshold',
        note: 'Drop balance into low state',
        idempotencyKey: 'balance-transition-cloudflare-low',
      },
    });
    expect(lowBalance.status).toBe(201);

    const blocked = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/admin-debit',
      body: {
        amountMinor: 2000,
        reasonCode: 'lower_to_blocked',
        note: 'Drop balance into blocked state',
        idempotencyKey: 'balance-transition-cloudflare-blocked',
      },
    });
    expect(blocked.status).toBe(201);

    const recovered = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/adjustments/support-credit',
      body: {
        amountMinor: 5000,
        reasonCode: 'restore_balance',
        note: 'Recover balance to healthy',
        idempotencyKey: 'balance-transition-cloudflare-recovered',
      },
    });
    expect(recovered.status).toBe(201);

    const deliveries = await webhooks.listDeliveries(
      { orgId: 'org-1', actorUserId: 'user-1', roles: ['platform_admin'] },
      endpoint.id,
    );
    expect(sortedWebhookDeliveryEventTypes(deliveries)).toEqual([
      'billing.balance.blocked',
      'billing.balance.low_balance',
      'billing.balance.recovered',
    ]);
    expect(ingested.map((entry) => String(entry.event.eventType || ''))).toEqual([
      'billing.balance.low_balance',
      'billing.balance.blocked',
      'billing.balance.recovered',
    ]);
    expect(
      ingested.map((entry) => String(getPath(entry.event, 'metadata', 'currentState') || '')),
    ).toEqual(['LOW_BALANCE', 'BLOCKED', 'HEALTHY']);
  });

  test('Stripe webhook settles prepaid purchase receipts idempotently', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const secret = 'whsec_console_router_cf_projection_test';
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      audit,
      billingStripeWebhookSecret: secret,
    });

    const checkoutSession = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_25',
      },
    });
    expect(checkoutSession.status).toBe(201);
    const checkoutSessionId = String(getPath(checkoutSession.json, 'checkoutSession', 'id') || '');
    const providerCustomerRef = String(
      getPath(checkoutSession.json, 'checkoutSession', 'customerRef') || '',
    );
    expect(checkoutSessionId).toBeTruthy();
    expect(providerCustomerRef).toBeTruthy();

    const purchaseEventId = `evt_cf_purchase_projection_${Date.now()}`;
    const projectedPurchase = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId: purchaseEventId,
        eventType: 'checkout.session.completed',
        orgId: 'org-1',
        checkoutSessionId,
        providerCustomerRef,
        providerRef: checkoutSessionId,
      },
    });
    expect(projectedPurchase.status).toBe(200);
    expect(projectedPurchase.json?.accepted).toBe(true);
    expect(getPath(projectedPurchase.json, 'purchase', 'status')).toBe('SETTLED');
    expect(getPath(projectedPurchase.json, 'purchase', 'creditPackId')).toBe('usd_25');
    const receiptInvoiceId = String(getPath(projectedPurchase.json, 'invoice', 'id') || '');
    expect(receiptInvoiceId).toContain('receipt_');

    const projectedPurchaseDuplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/webhook',
      headers: {
        'x-console-stripe-webhook-secret': secret,
      },
      body: {
        eventId: purchaseEventId,
        eventType: 'checkout.session.completed',
        orgId: 'org-1',
        checkoutSessionId,
        providerCustomerRef,
        providerRef: checkoutSessionId,
      },
    });
    expect(projectedPurchaseDuplicate.status).toBe(200);
    expect(projectedPurchaseDuplicate.json?.accepted).toBe(false);
    expect(getPath(projectedPurchaseDuplicate.json, 'purchase', 'status')).toBe('SETTLED');

    const overviewAfter = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overviewAfter.status).toBe(200);
    expect(Number(getPath(overviewAfter.json, 'overview', 'creditBalanceMinor') || 0)).toBe(2500);

    const auditEvents = await audit.listEvents({
      orgId: 'org-1',
      actorUserId: 'user-1',
      roles: ['admin'],
    });
    const settlementEvents = auditEvents.filter(
      (event) => String(event.action || '') === 'billing.credit_purchase.settled',
    );
    expect(settlementEvents).toHaveLength(1);
    expect(settlementEvents[0]?.category).toBe('BILLING');
    expect(settlementEvents[0]?.actorType).toBe('SYSTEM');
    expect(settlementEvents[0]?.actorUserId).toBe('system-stripe-webhook');
    expect(getPath(settlementEvents[0], 'metadata', 'purchaseId')).toBe(
      getPath(projectedPurchase.json, 'purchase', 'id'),
    );
    expect(getPath(settlementEvents[0], 'metadata', 'receiptId')).toBe(receiptInvoiceId);
    expect(getPath(settlementEvents[0], 'metadata', 'settlementSource')).toBe('stripe_webhook');
    expect(getPath(settlementEvents[0], 'metadata', 'settlementEventId')).toBe(purchaseEventId);
  });

  test('GET /console/billing/invoices/:id/pdf returns billing document PDF export', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      audit,
    });

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
    const invoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
    const periodMonthUtc = String(getPath(invoices.json, 'invoices', 0, 'periodMonthUtc') || '');
    expect(invoiceId).toBeTruthy();
    expect(periodMonthUtc).toMatch(/^\d{4}-\d{2}$/);

    const pdf = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}/pdf`,
    });
    expect(pdf.status).toBe(200);
    expect(String(pdf.headers.get('content-type') || '')).toContain('application/pdf');
    expect(String(pdf.headers.get('content-disposition') || '')).toContain(
      `statement_${periodMonthUtc}_${invoiceId}.pdf`,
    );
    expect(pdf.text.startsWith('%PDF-1.4')).toBe(true);
    expect(pdf.text).toContain('Usage statement');
    expect(pdf.text).toContain(`Organization: org-1`);
    expect(pdf.text).toContain(`Document ID: ${invoiceId}`);
    expect(pdf.text).toContain(
      'Visibility: Customer-facing export \\(internal ledger adjustments excluded\\).',
    );

    const auditEvents = await audit.listEvents({
      orgId: 'org-1',
      actorUserId: 'user-1',
      roles: ['admin'],
    });
    expect(auditEvents.length).toBe(1);
    expect(auditEvents[0]?.action).toBe('billing.invoice.pdf_export');
    expect(String((auditEvents[0]?.metadata as Record<string, unknown>)?.exportPolicy || '')).toBe(
      'CUSTOMER_FACING_EXCLUDES_INTERNAL_ACTIVITY',
    );
    expect(getPath(auditEvents[0], 'metadata', 'invoiceId')).toBe(invoiceId);
    expect(getPath(auditEvents[0], 'metadata', 'exportPolicy')).toBe(
      'CUSTOMER_FACING_EXCLUDES_INTERNAL_ACTIVITY',
    );

    const missing = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices/inv_missing/pdf',
    });
    expect(missing.status).toBe(404);
    expect(missing.json?.code).toBe('invoice_not_found');
  });

  test('cloudflare billing documents support server-side filters, pagination, and activity', async () => {
    let current = new Date('2026-01-20T00:00:00.000Z');
    const billing = createInMemoryConsoleBillingService({
      now: () => current,
    });
    const billingCtx = {
      orgId: 'org-1',
      actorUserId: 'admin-activity-user-cf',
      roles: ['admin'],
    };
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_january_1_cf',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_january_1_cf',
      occurredAt: '2026-01-09T00:00:00.000Z',
    });
    await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-01' });
    current = new Date('2026-02-20T00:00:00.000Z');
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_february_1_cf',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_february_1_cf',
      occurredAt: '2026-02-11T00:00:00.000Z',
    });
    await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-02' });
    current = new Date('2026-03-20T00:00:00.000Z');
    await billing.recordUsageEvent(billingCtx, {
      walletId: 'wallet_march_1_cf',
      action: 'transfer',
      succeeded: true,
      sourceEventId: 'usage_march_1_cf',
      occurredAt: '2026-03-15T00:00:00.000Z',
    });
    const march = await billing.generateMonthlyInvoice(billingCtx, { periodMonthUtc: '2026-03' });
    const checkoutSession = await billing.createStripeCheckoutSession(billingCtx, {
      successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
      cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
      creditPackId: 'usd_25',
    });
    await billing.processStripeWebhookEvent({
      eventId: 'evt_billing_purchase_settled_cf',
      eventType: 'checkout.session.completed',
      orgId: billingCtx.orgId,
      checkoutSessionId: checkoutSession.id,
      providerCustomerRef: checkoutSession.customerRef,
      providerRef: checkoutSession.id,
    });

    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const firstPage = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices?limit=1',
    });
    expect(firstPage.status).toBe(200);
    expect(Array.isArray(firstPage.json?.invoices)).toBe(true);
    expect((firstPage.json?.invoices as unknown[]).length).toBe(1);
    expect(Number(firstPage.json?.totalCount || 0)).toBe(4);
    expect(String(firstPage.json?.nextCursor || '')).toBeTruthy();
    expect(Number(getPath(firstPage.json, 'summary', 'receiptCount') || 0)).toBe(1);
    expect(Number(getPath(firstPage.json, 'summary', 'statementCount') || 0)).toBe(3);

    const secondPage = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices?limit=1&cursor=${encodeURIComponent(String(firstPage.json?.nextCursor || ''))}`,
    });
    expect(secondPage.status).toBe(200);
    expect((secondPage.json?.invoices as unknown[]).length).toBe(1);
    expect(getPath(firstPage.json, 'invoices', 0, 'id')).not.toBe(
      getPath(secondPage.json, 'invoices', 0, 'id'),
    );

    const paid = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices?status=PAID',
    });
    expect(paid.status).toBe(200);
    expect(Number(paid.json?.totalCount || 0)).toBe(4);
    expect(Number(getPath(paid.json, 'summary', 'paidCount') || 0)).toBe(4);

    const receipts = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices?documentType=PURCHASE_RECEIPT',
    });
    expect(receipts.status).toBe(200);
    expect(Number(receipts.json?.totalCount || 0)).toBe(1);
    expect(getPath(receipts.json, 'invoices', 0, 'documentType')).toBe('PURCHASE_RECEIPT');

    const february = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices?documentType=USAGE_STATEMENT&periodMonthUtc=2026-02',
    });
    expect(february.status).toBe(200);
    expect(Number(february.json?.totalCount || 0)).toBe(1);
    expect(getPath(february.json, 'invoices', 0, 'periodMonthUtc')).toBe('2026-02');
    expect(getPath(february.json, 'invoices', 0, 'documentType')).toBe('USAGE_STATEMENT');

    const activity = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(march.invoice.id)}/activity`,
    });
    expect(activity.status).toBe(200);
    const entries = Array.isArray(getPath(activity.json, 'activity', 'entries'))
      ? (getPath(activity.json, 'activity', 'entries') as Array<Record<string, unknown>>)
      : [];
    expect(
      entries.some(
        (entry) =>
          String(entry.type || '') === 'LEDGER' && String(entry.toState || '') === 'USAGE_DEBIT',
      ),
    ).toBe(true);
  });

  test('billing usage endpoints compute MAW with exclusions and idempotency', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    const e1 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_1',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_1',
      },
    });
    expect(e1.status).toBe(200);
    expect(getPath(e1.json, 'result', 'accepted')).toBe(true);
    expect(getPath(e1.json, 'result', 'counted')).toBe(true);
    expect(Number(getPath(e1.json, 'result', 'monthlyActiveWallets') || 0)).toBe(1);
    const monthUtc = String(getPath(e1.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const e2 = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(e2.status).toBe(200);
    expect(Number(getPath(e2.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const excluded = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_3',
        action: 'wallet_created',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_3',
      },
    });
    expect(excluded.status).toBe(200);
    expect(getPath(excluded.json, 'result', 'counted')).toBe(false);
    expect(Number(getPath(excluded.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const duplicate = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_2',
        action: 'swap',
        succeeded: true,
        sourceEventId: 'usage_cf_evt_2',
      },
    });
    expect(duplicate.status).toBe(200);
    expect(getPath(duplicate.json, 'result', 'accepted')).toBe(false);
    expect(Number(getPath(duplicate.json, 'result', 'monthlyActiveWallets') || 0)).toBe(2);

    const usage = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(usage.status).toBe(200);
    expect(getPath(usage.json, 'usage', 'monthUtc')).toBe(monthUtc);
    expect(Number(getPath(usage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(2);
  });

  test('cloudflare POST /console/billing/usage/events requires admin or ops role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });

    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_usage_role_cloudflare',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_role_cloudflare_1',
      },
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
  });

  test('cloudflare billing read routes require billing read role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-billing-read-role-cf-1',
        'user-billing-read-role-cf-1',
      ),
      billing: createInMemoryConsoleBillingService(),
    });

    for (const path of [
      '/console/billing/overview',
      '/console/billing/account/activity?limit=5',
      '/console/billing/usage/monthly-active-wallets?monthUtc=2026-03',
      '/console/billing/invoices',
      '/console/billing/invoices/inv_missing',
      '/console/billing/invoices/inv_missing/pdf',
      '/console/billing/invoices/inv_missing/activity',
      '/console/billing/invoices/inv_missing/line-items',
    ]) {
      const res = await callCf(handler, {
        method: 'GET',
        path,
      });
      expect(res.status, path).toBe(403);
      expect(res.json?.code, path).toBe('forbidden');
    }
  });

  test('cloudflare billing_admin can access billing read routes', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin'], 'org-1', 'user-billing-admin-read-cf-1'),
      billing: createInMemoryConsoleBillingService(),
    });

    const overview = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(overview.status).toBe(200);

    const invoices = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(invoices.status).toBe(200);
  });

  test('invoice generation endpoint returns deterministic prepaid statement line items', async () => {
    const billing = createInMemoryConsoleBillingService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
    });

    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_1',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-01-05T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_1',
      },
    });
    await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_gen_2',
        action: 'swap',
        succeeded: true,
        occurredAt: '2026-01-06T01:00:00.000Z',
        sourceEventId: 'router_cf_gen_evt_2',
      },
    });

    const generated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-01',
      },
    });
    expect(generated.status).toBe(200);
    expect(getPath(generated.json, 'generation', 'generated')).toBe(false);
    expect(Number(getPath(generated.json, 'generation', 'invoice', 'amountDueMinor') || 0)).toBe(
      600,
    );
    const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
    expect(invoiceId).toBeTruthy();

    const lineItems = await callCf(handler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(invoiceId)}/line-items`,
    });
    expect(lineItems.status).toBe(200);
    const items = Array.isArray(lineItems.json?.lineItems) ? lineItems.json?.lineItems : [];
    expect(items.length).toBe(1);
    expect(JSON.stringify(items)).toContain('"itemType":"MAW_USAGE_DEBIT"');
  });

  test('cloudflare billing invoice generation appends audit rows', async () => {
    const billing = createInMemoryConsoleBillingService();
    const audit: ConsoleAuditService = createInMemoryConsoleAuditService({ seedDemoData: false });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-billing-invoice-audit-cloudflare',
        'user-billing-invoice-audit-cloudflare',
      ),
      billing,
      audit,
    });

    const usage = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_invoice_audit_cloudflare',
        action: 'transfer',
        succeeded: true,
        occurredAt: '2026-03-05T01:00:00.000Z',
        sourceEventId: 'usage_evt_invoice_audit_cloudflare',
      },
    });
    expect(usage.status).toBe(200);

    const generated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-03',
      },
    });
    expect(generated.status).toBe(200);
    const invoiceId = String(getPath(generated.json, 'generation', 'invoice', 'id') || '');
    expect(invoiceId).toBeTruthy();

    const auditEvents = await audit.listEvents(
      {
        orgId: 'org-billing-invoice-audit-cloudflare',
        actorUserId: 'user-billing-invoice-audit-cloudflare',
        roles: ['admin'],
      },
      { category: 'BILLING', limit: 20 },
    );
    const invoiceEvent = auditEvents.find(
      (event) => String(event.action || '') === 'billing.invoice.generated',
    );
    expect(invoiceEvent).toBeTruthy();
    expect(getPath(invoiceEvent, 'metadata', 'invoiceId')).toBe(invoiceId);
    expect(getPath(invoiceEvent, 'metadata', 'periodMonthUtc')).toBe('2026-03');
    expect(getPath(invoiceEvent, 'metadata', 'invoiceDocumentType')).toBe('USAGE_STATEMENT');
    expect(getPath(invoiceEvent, 'metadata', 'monthlyActiveWallets')).toBe(1);
    expect(getPath(invoiceEvent, 'metadata', 'lineItemCount')).toBe(
      Array.isArray(getPath(generated.json, 'generation', 'lineItems'))
        ? (getPath(generated.json, 'generation', 'lineItems') as any[]).length
        : 0,
    );
    expect(getPath(invoiceEvent, 'metadata', 'generated')).toBe(
      getPath(generated.json, 'generation', 'generated'),
    );
  });

  test('cloudflare billing document generation emits webhook events', async () => {
    const billing = createInMemoryConsoleBillingService();
    const webhooks = createInMemoryConsoleWebhookService({
      dispatcher: {
        dispatch: async () => ({
          ok: true,
          statusCode: 200,
          responseBody: 'ok',
        }),
      },
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      webhooks,
    });

    const endpointCreated = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/cloudflare-billing-events',
        eventCategories: ['billing'],
      },
    });
    expect(endpointCreated.status).toBe(201);
    const endpointId = String(getPath(endpointCreated.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const usage = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_cf_webhook_invoice_generated',
        action: 'transfer',
        succeeded: true,
        sourceEventId: 'usage_evt_cf_webhook_invoice_generated',
      },
    });
    expect(usage.status).toBe(200);

    const generated = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/invoices/generate',
      body: {
        periodMonthUtc: '2026-03',
      },
    });
    expect(generated.status).toBe(200);
    expect(String(getPath(generated.json, 'generation', 'invoice', 'id') || '')).toBeTruthy();

    const deliveries = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(200);
    const rows = Array.isArray(deliveries.json?.deliveries) ? deliveries.json?.deliveries : [];
    const eventTypes = rows.map((row: any) => String(row?.eventType || ''));
    expect(eventTypes).toContain('billing.invoice.generated');
    expect(rows.length).toBeGreaterThanOrEqual(1);

    const pageOne = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries?limit=2`,
    });
    expect(pageOne.status).toBe(200);
    const pageOneRows = Array.isArray(pageOne.json?.deliveries) ? pageOne.json?.deliveries : [];
    expect(pageOneRows.length).toBeGreaterThanOrEqual(1);
  });
});
