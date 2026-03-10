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
  createInMemoryConsoleGasSponsorshipService,
  createInMemoryConsoleKeyExportService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsolePolicyService,
  createInMemoryConsoleRuntimeSnapshotService,
  createInMemoryConsoleSmartWalletService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleApiKeyService,
  createPostgresConsoleApprovalService,
  createPostgresConsoleAuditService,
  createPostgresConsoleBillingService,
  createPostgresConsoleOrgProjectEnvService,
  createPostgresConsolePolicyService,
  createPostgresConsoleTeamRbacService,
  createPostgresConsoleWalletService,
  createPostgresConsoleWebhookService,
  type ConsoleApiKeyService,
  type ConsoleApprovalService,
  type ConsoleAuditService,
  type ConsoleAuditExportsService,
  type ConsoleAuthAdapter,
  type ConsoleBillingService,
  type ConsoleEnterpriseIsolationService,
  type ConsoleObservabilityIngestionService,
  type ConsoleOrgProjectEnvService,
  type ConsolePolicyService,
  type ConsoleWallet,
  type ConsoleTeamRbacService,
  type ConsoleWalletService,
  type ConsoleWebhookService,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, getPath, startExpressRouter } from './helpers';
import { getPostgresPool } from '../../server/src/storage/postgres';
import { withConsoleTenantContextTx } from '../../server/src/console/shared/postgresTenantContext';

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

function makeObservabilityIngestionCollector(
  ingested: Array<{
    ingestCtx: Record<string, unknown>;
    event: Record<string, unknown>;
  }>,
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

const REMOVED_BILLING_SETTLEMENT_ROUTE_CASES: Array<{
  method: 'GET' | 'POST';
  path: string;
  body?: Record<string, unknown>;
}> = [
  {
    method: 'POST',
    path: '/console/billing/stripe/payment-intent',
    body: { invoiceId: 'inv_removed' },
  },
  {
    method: 'POST',
    path: '/console/billing/stripe/payment-intents/pi_removed/reconcile',
    body: { providerStatus: 'FAILED' },
  },
  { method: 'GET', path: '/console/billing/stablecoins/assets' },
  {
    method: 'POST',
    path: '/console/billing/stablecoins/quotes',
    body: { invoiceId: 'inv_removed', asset: 'USDC', chain: 'Ethereum' },
  },
  {
    method: 'POST',
    path: '/console/billing/stablecoins/payment-intents',
    body: { invoiceId: 'inv_removed', quoteId: 'quote_removed' },
  },
  { method: 'GET', path: '/console/billing/stablecoins/payment-intents/scpi_removed' },
  { method: 'POST', path: '/console/billing/stablecoins/payment-intents/scpi_removed/cancel' },
  {
    method: 'POST',
    path: '/console/billing/stablecoins/payment-intents/scpi_removed/reconcile',
    body: { observedAmountMinor: 0, observedConfirmations: 0 },
  },
];

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

  test('policy publish failures emit approval observability events and router timing (express)', async () => {
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
      await expect
        .poll(
          () =>
            ingested.filter((entry) => entry.event.eventType === 'router.request.completed').length,
        )
        .toBeGreaterThanOrEqual(1);

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

      const routerTiming = ingested.find(
        (entry) =>
          entry.event.eventType === 'router.request.completed' &&
          String(getPath(entry.event, 'metadata', 'route') || '').includes('/console/policies'),
      );
      expect(routerTiming).toBeTruthy();
    } finally {
      await srv.close();
    }
  });

  test('billing invoice finalization failures emit billing observability events (express)', async () => {
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
      expect(getPath(res.json, 'summary', 'billing', 'failedInvoiceCount')).toBe(1);
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
      auth: makeConsoleAuthAdapter(['developer'], orgId, actorUserId),
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
      const paymentMethod = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerRef: 'pm_project_live_ready_1',
          brand: 'visa',
          last4: '4242',
          expMonth: 12,
          expYear: 2030,
        }),
      });
      expect(paymentMethod.status).toBe(201);

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
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-live-1', 'user-audit-live-admin'),
      approvals,
      audit,
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
          resourceId: 'policy_live_1',
        }),
      });
      expect(created.status).toBe(201);

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
      expect(String(getPath(createdEvent, 'metadata', 'approvalId'))).toBe('apr_audit_live_1');
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
      const policyId = 'policy_sensitive_1';
      const createPolicy = await fetchJson(`${server.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: policyId,
          name: 'Sensitive Policy',
        }),
      });
      expect(createPolicy.status).toBe(201);

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

  test('GET /console/export/governance returns api_keys_not_configured without API key service', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/export/governance`, { method: 'GET' });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('api_keys_not_configured');
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
      const gas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, { method: 'GET' });
      expect(gas.status).toBe(501);
      expect(gas.json?.code).toBe('gas_sponsorship_not_configured');

      const smartWallets = await fetchJson(`${srv.baseUrl}/console/smart-wallets`, {
        method: 'GET',
      });
      expect(smartWallets.status).toBe(501);
      expect(smartWallets.json?.code).toBe('smart_wallets_not_configured');

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
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-express-1', 'user-scaffold-express-1'),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdGas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'gs-express-1',
          scopeType: 'ENVIRONMENT',
          environmentId: 'prod',
          enabled: true,
          allowedChainIds: [1],
          spendCap: {
            mode: 'CHAIN_TOTAL',
            period: 'MONTHLY',
            capsByChain: [{ chainId: 1, capMinor: 500000 }],
          },
        }),
      });
      expect(createdGas.status).toBe(201);
      expect(getPath(createdGas.json, 'config', 'id')).toBe('gs-express-1');

      const listedGas = await fetchJson(
        `${srv.baseUrl}/console/gas-sponsorship?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(listedGas.status).toBe(200);
      const listedGasRows: unknown[] = Array.isArray(listedGas.json?.configs)
        ? (listedGas.json?.configs as unknown[])
        : [];
      expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

      const patchedGas = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship/gs-express-1`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false }),
      });
      expect(patchedGas.status).toBe(200);
      expect(getPath(patchedGas.json, 'config', 'enabled')).toBe(false);

      const createdSmartWallet = await fetchJson(`${srv.baseUrl}/console/smart-wallets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'sw-express-1',
          scopeType: 'ENVIRONMENT',
          environmentId: 'prod',
          mode: 'REQUIRED',
          accountType: 'SMART_ACCOUNT',
        }),
      });
      expect(createdSmartWallet.status).toBe(201);
      expect(getPath(createdSmartWallet.json, 'config', 'id')).toBe('sw-express-1');

      const listedSmartWallets = await fetchJson(
        `${srv.baseUrl}/console/smart-wallets?environmentId=${encodeURIComponent('prod')}`,
        { method: 'GET' },
      );
      expect(listedSmartWallets.status).toBe(200);
      const listedSmartWalletRows: unknown[] = Array.isArray(listedSmartWallets.json?.configs)
        ? (listedSmartWallets.json?.configs as unknown[])
        : [];
      expect(listedSmartWalletRows.length).toBeGreaterThanOrEqual(1);

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
      expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
        'resolved',
      );

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
      expect(getPath(first.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
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
      const policyId = 'policy-runtime-live-express-1';
      const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: policyId,
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

  test('new console endpoint mutations enforce role gates', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-express-rbac-1',
        'user-scaffold-express-rbac-1',
      ),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const gasCreate = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ORG',
        }),
      });
      expect(gasCreate.status).toBe(403);
      expect(gasCreate.json?.code).toBe('forbidden');

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
            smartWallets: {},
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
    } finally {
      await srv.close();
    }
  });

  test('new console endpoint validation errors return typed error codes', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-express-validation-1',
        'user-scaffold-express-validation-1',
      ),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const srv = await startExpressRouter(router);
    try {
      const invalidGasScope = await fetchJson(`${srv.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scopeType: 'ENVIRONMENT',
        }),
      });
      expect(invalidGasScope.status).toBe(400);
      expect(invalidGasScope.json?.code).toBe('invalid_scope');

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
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-express-isolation-owner';
    const attackerOrgId = 'org-scaffold-express-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-express-isolation-user'),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const createGas = await fetchJson(`${ownerServer.baseUrl}/console/gas-sponsorship`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'gs-express-isolation-1',
          scopeType: 'ENVIRONMENT',
          environmentId: ownerEnvironmentId,
          allowedChainIds: [11_155_111],
        }),
      });
      expect(createGas.status).toBe(201);

      const createSmartWallet = await fetchJson(`${ownerServer.baseUrl}/console/smart-wallets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'sw-express-isolation-1',
          scopeType: 'ENVIRONMENT',
          environmentId: ownerEnvironmentId,
          mode: 'REQUIRED',
          accountType: 'SMART_ACCOUNT',
        }),
      });
      expect(createSmartWallet.status).toBe(201);

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
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const gasList = await fetchJson(
        `${attackerServer.baseUrl}/console/gas-sponsorship?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(gasList.status).toBe(200);
      const attackerGasRows = Array.isArray(gasList.json?.configs) ? gasList.json?.configs : [];
      expect(attackerGasRows.length).toBe(0);

      const patchGas = await fetchJson(
        `${attackerServer.baseUrl}/console/gas-sponsorship/gs-express-isolation-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: false }),
        },
      );
      expect(patchGas.status).toBe(404);
      expect(patchGas.json?.code).toBe('gas_sponsorship_not_found');

      const smartWalletList = await fetchJson(
        `${attackerServer.baseUrl}/console/smart-wallets?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(smartWalletList.status).toBe(200);
      const attackerSmartWalletRows = Array.isArray(smartWalletList.json?.configs)
        ? smartWalletList.json?.configs
        : [];
      expect(attackerSmartWalletRows.length).toBe(0);

      const patchSmartWallet = await fetchJson(
        `${attackerServer.baseUrl}/console/smart-wallets/sw-express-isolation-1`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: false }),
        },
      );
      expect(patchSmartWallet.status).toBe(404);
      expect(patchSmartWallet.json?.code).toBe('smart_wallet_config_not_found');

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

  test('policy/gas/export insight routes return aggregated views', async () => {
    const orgId = 'org-insights-express-1';
    const projectId = 'default-project';
    const environmentId = `${orgId}:${projectId}:prod`;
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_insights_express_1',
          orgId,
          projectId,
          environmentId,
        }),
      ],
    });
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId,
      projectId,
      actorUserId: 'user-insights-express-1',
    });
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-insights-express-1'),
      wallets,
      apiKeys,
      orgProjectEnv,
    });
    const srv = await startExpressRouter(router);
    try {
      const createdExportKey = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'export-key',
          environmentId,
          kind: 'secret_key',
          scopes: ['wallets:read', 'keys:export'],
        }),
      });
      expect(createdExportKey.status).toBe(201);

      const createdNonExportKey = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'non-export-key',
          environmentId,
          kind: 'secret_key',
          scopes: ['wallets:read'],
        }),
      });
      expect(createdNonExportKey.status).toBe(201);

      const coverage = await fetchJson(`${srv.baseUrl}/console/policy/coverage`, { method: 'GET' });
      expect(coverage.status).toBe(200);
      expect(
        Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
      const policyRows: unknown[] = Array.isArray(getPath(coverage.json, 'coverage', 'policies'))
        ? (getPath(coverage.json, 'coverage', 'policies') as unknown[])
        : [];
      expect(policyRows.length).toBeGreaterThanOrEqual(1);

      const readiness = await fetchJson(`${srv.baseUrl}/console/gas/readiness`, { method: 'GET' });
      expect(readiness.status).toBe(200);
      expect(
        Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
      const chainRows: unknown[] = Array.isArray(getPath(readiness.json, 'readiness', 'chains'))
        ? (getPath(readiness.json, 'readiness', 'chains') as unknown[])
        : [];
      expect(chainRows.length).toBeGreaterThanOrEqual(1);

      const governance = await fetchJson(
        `${srv.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(environmentId)}`,
        {
          method: 'GET',
        },
      );
      expect(governance.status).toBe(200);
      expect(Number(getPath(governance.json, 'governance', 'totals', 'apiKeyCount') || 0)).toBe(2);
      expect(
        Number(getPath(governance.json, 'governance', 'totals', 'exportScopedKeyCount') || 0),
      ).toBe(1);
      expect(
        Number(
          getPath(
            governance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
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

      const created = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-express-lifecycle-1',
          name: 'Policy Express Lifecycle',
          rules: {
            blockedActions: [],
            allowedChains: ['ethereum'],
            maxAmountMinor: 5000,
          },
        }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'policy', 'id')).toBe('policy-express-lifecycle-1');
      expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
      expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

      const allowedSimulation = await fetchJson(
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/simulate`,
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
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1`,
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
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/simulate`,
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
        `${adminServer.baseUrl}/console/policies/policy-express-lifecycle-1/publish`,
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
          id: 'policy-express-forbidden-1',
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
    const ownerPolicyId = 'policy-owner-express-isolation-1';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerPolicyId,
          name: 'Owner Policy',
        }),
      });
      expect(created.status).toBe(201);
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
          id: 'policy-create-attach-express-1',
          name: 'Attached draft express',
          assignment: {
            scopeType: 'ENVIRONMENT',
            scopeId: environmentScopeId,
          },
        }),
      });
      expect(created.status).toBe(201);
      expect(getPath(created.json, 'policy', 'id')).toBe('policy-create-attach-express-1');

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
        'policy-create-attach-express-1',
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
          id: 'policy-project-express-1',
          name: 'Project Policy Express',
        }),
      });
      expect(createProjectPolicy.status).toBe(201);
      const publishProjectPolicy = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent('policy-project-express-1')}/publish`,
        { method: 'POST' },
      );
      expect(publishProjectPolicy.status).toBe(200);
      const createWalletPolicy = await fetchJson(`${adminServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: 'policy-wallet-express-1',
          name: 'Wallet Policy Express',
        }),
      });
      expect(createWalletPolicy.status).toBe(201);

      const projectAssignment = await fetchJson(
        `${adminServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'PROJECT',
            scopeId: projectId,
            policyId: 'policy-project-express-1',
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
            policyId: 'policy-wallet-express-1',
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
        'policy-wallet-express-1',
      );

      const walletCoverage = await fetchJson(
        `${adminServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(projectId)}&environmentId=${encodeURIComponent(environmentId)}`,
        { method: 'GET' },
      );
      expect(walletCoverage.status).toBe(200);
      const policyRows = Array.isArray(getPath(walletCoverage.json, 'coverage', 'policies'))
        ? (getPath(walletCoverage.json, 'coverage', 'policies') as any[])
        : [];
      expect(
        policyRows.some((entry) => String(entry?.policyId || '') === 'policy-project-express-1'),
      ).toBe(true);
      expect(
        policyRows.some((entry) => String(entry?.policyId || '') === 'policy-wallet-express-1'),
      ).toBe(false);

      const publishWalletPolicy = await fetchJson(
        `${adminServer.baseUrl}/console/policies/${encodeURIComponent('policy-wallet-express-1')}/publish`,
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
      expect(
        livePolicyRows.some((entry) => String(entry?.policyId || '') === 'policy-wallet-express-1'),
      ).toBe(true);

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
        projectPolicyRows.some(
          (entry) => String(entry?.policyId || '') === 'policy-project-express-1',
        ),
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
            policyId: 'org-policy-assign-express:policy:default',
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
          scopes: ['wallets:read', 'billing:read'],
          ipAllowlist: ['203.0.113.10/32'],
          expiresAt,
        }),
      });
      expect(created.status).toBe(201);
      const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      const createdSecret = String(getPath(created.json, 'secret') || '');
      expect(keyId).toBeTruthy();
      expect(createdSecret).toContain('tsk_');
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
      expect(rotatedSecret).toContain('tsk_');
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

  test('legacy billing settlement routes are removed (express)', async () => {
    const router = createConsoleRouter({});
    const srv = await startExpressRouter(router);
    try {
      for (const routeCase of REMOVED_BILLING_SETTLEMENT_ROUTE_CASES) {
        const res = await fetchJson(`${srv.baseUrl}${routeCase.path}`, {
          method: routeCase.method,
          ...(routeCase.body
            ? {
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(routeCase.body),
              }
            : {}),
        });
        expect(res.status, `${routeCase.method} ${routeCase.path}`).toBe(404);
      }
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['billing_admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('forbidden');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/payment-methods returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/payment-methods`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
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
          creditPackId: 'usd_200',
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
      expect(getPath(created.json, 'checkoutSession', 'creditPackId')).toBe('usd_200');
      expect(Number(getPath(created.json, 'checkoutSession', 'amountMinor') || 0)).toBe(20000);
      expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
        /^\d{4}-\d{2}-\d{2}T/,
      );

      const invalid = await fetchJson(`${srv.baseUrl}/console/billing/stripe/checkout-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          successUrl: '/dashboard/billing',
          cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
          creditPackId: 'usd_200',
        }),
      });
      expect(invalid.status).toBe(400);
      expect(invalid.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/customer-portal-session returns billing_not_configured without billing service', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/stripe/customer-portal-session`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          returnUrl: 'https://app.example.com/dashboard/billing',
        }),
      });
      expect(res.status).toBe(501);
      expect(res.json?.code).toBe('billing_not_configured');
    } finally {
      await srv.close();
    }
  });

  test('POST /console/billing/stripe/customer-portal-session creates portal session', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/customer-portal-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            returnUrl: 'https://app.example.com/dashboard/billing',
          }),
        },
      );
      expect(created.status).toBe(201);
      const sessionId = String(getPath(created.json, 'portalSession', 'id') || '');
      const sessionUrl = String(getPath(created.json, 'portalSession', 'url') || '');
      expect(sessionId).toBeTruthy();
      expect(sessionUrl).toContain('https://billing.stripe.com/p/session/');
      expect(String(getPath(created.json, 'portalSession', 'customerRef') || '')).toContain('cus_');

      const invalid = await fetchJson(
        `${srv.baseUrl}/console/billing/stripe/customer-portal-session`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            returnUrl: '/dashboard/billing',
          }),
        },
      );
      expect(invalid.status).toBe(400);
      expect(invalid.json?.code).toBe('invalid_body');
    } finally {
      await srv.close();
    }
  });

  test('legacy billing subscription route is removed', async () => {
    const router = createConsoleRouter({ auth: makeConsoleAuthAdapter(['admin']) });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/console/billing/subscription`, {
        method: 'GET',
      });
      expect(res.status).toBe(404);
    } finally {
      await srv.close();
    }
  });

  test('legacy billing subscription lifecycle routes are removed', async () => {
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const srv = await startExpressRouter(router);
    try {
      const canceled = await fetchJson(`${srv.baseUrl}/console/billing/subscription/cancel`, {
        method: 'POST',
      });
      expect(canceled.status).toBe(404);

      const resumed = await fetchJson(`${srv.baseUrl}/console/billing/subscription/resume`, {
        method: 'POST',
      });
      expect(resumed.status).toBe(404);
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
    const secret = 'whsec_console_router_projection_test';
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
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
            creditPackId: 'usd_200',
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
      expect(getPath(projectedPurchase.json, 'purchase', 'creditPackId')).toBe('usd_200');
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
      expect(Number(getPath(overviewAfter.json, 'overview', 'creditBalanceMinor') || 0)).toBe(
        20000,
      );
    } finally {
      await srv.close();
    }
  });

  test('GET /console/billing/invoices/:id/pdf returns invoice PDF export', async () => {
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

      const auditEvents = await audit.listEvents({
        orgId: 'org-1',
        actorUserId: 'user-1',
        roles: ['admin'],
      });
      expect(auditEvents.length).toBe(1);
      expect(auditEvents[0]?.action).toBe('billing.invoice.pdf_export');
      expect(auditEvents[0]?.category).toBe('BILLING');
      expect(getPath(auditEvents[0], 'metadata', 'invoiceId')).toBe(invoiceId);
      expect(getPath(auditEvents[0], 'metadata', 'exportPolicy')).toBe('ALL_INVOICE_STATES');

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
      creditPackId: 'usd_200',
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

  test('billing invoice generation emits webhook events when webhook endpoint is configured', async () => {
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

  test('cloudflare policy publish failures emit approval observability events and router timing', async () => {
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
    await expect
      .poll(
        () =>
          ingested.filter((entry) => entry.event.eventType === 'router.request.completed').length,
      )
      .toBeGreaterThanOrEqual(1);

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

    const routerTiming = ingested.find(
      (entry) =>
        entry.event.eventType === 'router.request.completed' &&
        String(getPath(entry.event, 'metadata', 'route') || '').includes(
          '/console/policies/pol_obs_failure/publish',
        ),
    );
    expect(routerTiming).toBeTruthy();
  });

  test('cloudflare billing invoice finalization failures emit billing observability events', async () => {
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
    expect(getPath(res.json, 'summary', 'billing', 'failedInvoiceCount')).toBe(1);
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
      auth: makeConsoleAuthAdapter(['developer'], orgId, actorUserId),
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

    const paymentMethod = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/payment-methods',
      body: {
        providerRef: 'pm_project_live_ready_cf_1',
        brand: 'visa',
        last4: '4242',
        expMonth: 12,
        expYear: 2030,
      },
    });
    expect(paymentMethod.status).toBe(201);

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
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-audit-cf-live-1', 'user-audit-cf-live-admin'),
      approvals,
      audit,
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: 'apr_audit_cf_live_1',
        operationType: 'POLICY_PUBLISH',
        reason: 'Publish policy v2',
        resourceType: 'policy',
        resourceId: 'policy_cf_live_1',
      },
    });
    expect(created.status).toBe(201);

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
    expect(String(getPath(createdEvent, 'metadata', 'approvalId'))).toBe('apr_audit_cf_live_1');
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

    const policyId = 'policy_sensitive_cf_1';
    const createPolicy = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: policyId,
        name: 'Sensitive Policy CF',
      },
    });
    expect(createPolicy.status).toBe(201);

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

  test('GET /console/export/governance returns api_keys_not_configured without API key service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      wallets: createInMemoryConsoleWalletService(),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/export/governance',
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('api_keys_not_configured');
  });

  test('cloudflare new console endpoints return *_not_configured when services are not wired', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });

    const gas = await callCf(handler, {
      method: 'GET',
      path: '/console/gas-sponsorship',
    });
    expect(gas.status).toBe(501);
    expect(gas.json?.code).toBe('gas_sponsorship_not_configured');

    const smartWallets = await callCf(handler, {
      method: 'GET',
      path: '/console/smart-wallets',
    });
    expect(smartWallets.status).toBe(501);
    expect(smartWallets.json?.code).toBe('smart_wallets_not_configured');

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
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-scaffold-cf-1', 'user-scaffold-cf-1'),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });

    const createdGas = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        id: 'gs-cf-1',
        scopeType: 'ENVIRONMENT',
        environmentId: 'prod',
        enabled: true,
        allowedChainIds: [1],
        spendCap: {
          mode: 'CHAIN_TOTAL',
          period: 'MONTHLY',
          capsByChain: [{ chainId: 1, capMinor: 500000 }],
        },
      },
    });
    expect(createdGas.status).toBe(201);
    expect(getPath(createdGas.json, 'config', 'id')).toBe('gs-cf-1');

    const listedGas = await callCf(handler, {
      method: 'GET',
      path: '/console/gas-sponsorship?environmentId=prod',
    });
    expect(listedGas.status).toBe(200);
    const listedGasRows: unknown[] = Array.isArray(listedGas.json?.configs)
      ? (listedGas.json?.configs as unknown[])
      : [];
    expect(listedGasRows.length).toBeGreaterThanOrEqual(1);

    const patchedGas = await callCf(handler, {
      method: 'PATCH',
      path: '/console/gas-sponsorship/gs-cf-1',
      body: {
        enabled: false,
      },
    });
    expect(patchedGas.status).toBe(200);
    expect(getPath(patchedGas.json, 'config', 'enabled')).toBe(false);

    const createdSmartWallet = await callCf(handler, {
      method: 'POST',
      path: '/console/smart-wallets',
      body: {
        id: 'sw-cf-1',
        scopeType: 'ENVIRONMENT',
        environmentId: 'prod',
        mode: 'REQUIRED',
        accountType: 'SMART_ACCOUNT',
      },
    });
    expect(createdSmartWallet.status).toBe(201);
    expect(getPath(createdSmartWallet.json, 'config', 'id')).toBe('sw-cf-1');

    const listedSmartWallets = await callCf(handler, {
      method: 'GET',
      path: '/console/smart-wallets?environmentId=prod',
    });
    expect(listedSmartWallets.status).toBe(200);
    const listedSmartWalletRows: unknown[] = Array.isArray(listedSmartWallets.json?.configs)
      ? (listedSmartWallets.json?.configs as unknown[])
      : [];
    expect(listedSmartWalletRows.length).toBeGreaterThanOrEqual(1);

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
    expect(getPath(publishedSnapshot.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
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
    expect(getPath(first.json, 'snapshot', 'payload', 'smartWallets', 'status')).toBe(
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
    const policyId = 'policy-runtime-live-cf-1';
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: policyId,
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

  test('cloudflare new console endpoint mutations enforce role gates', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['developer'],
        'org-scaffold-cf-rbac-1',
        'user-scaffold-cf-rbac-1',
      ),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });

    const gasCreate = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        scopeType: 'ORG',
      },
    });
    expect(gasCreate.status).toBe(403);
    expect(gasCreate.json?.code).toBe('forbidden');

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
          smartWallets: {},
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
  });

  test('cloudflare new console endpoint validation errors return typed error codes', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(
        ['admin'],
        'org-scaffold-cf-validation-1',
        'user-scaffold-cf-validation-1',
      ),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });

    const invalidGasScope = await callCf(handler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        scopeType: 'ENVIRONMENT',
      },
    });
    expect(invalidGasScope.status).toBe(400);
    expect(invalidGasScope.json?.code).toBe('invalid_scope');

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
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const smartWallets = createInMemoryConsoleSmartWalletService();
    const keyExports = createInMemoryConsoleKeyExportService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const ownerOrgId = 'org-scaffold-cf-isolation-owner';
    const attackerOrgId = 'org-scaffold-cf-isolation-attacker';
    const ownerEnvironmentId = 'env-isolation-owner-cf';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-scaffold-cf-isolation-user'),
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const createGas = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/gas-sponsorship',
      body: {
        id: 'gs-cf-isolation-1',
        scopeType: 'ENVIRONMENT',
        environmentId: ownerEnvironmentId,
        allowedChainIds: [11_155_111],
      },
    });
    expect(createGas.status).toBe(201);

    const createSmartWallet = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/smart-wallets',
      body: {
        id: 'sw-cf-isolation-1',
        scopeType: 'ENVIRONMENT',
        environmentId: ownerEnvironmentId,
        mode: 'REQUIRED',
        accountType: 'SMART_ACCOUNT',
      },
    });
    expect(createSmartWallet.status).toBe(201);

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
      gasSponsorship,
      smartWallets,
      keyExports,
      runtimeSnapshots,
    });
    const gasList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/gas-sponsorship?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(gasList.status).toBe(200);
    const attackerGasRows = Array.isArray(gasList.json?.configs) ? gasList.json?.configs : [];
    expect(attackerGasRows.length).toBe(0);

    const patchGas = await callCf(attackerHandler, {
      method: 'PATCH',
      path: '/console/gas-sponsorship/gs-cf-isolation-1',
      body: { enabled: false },
    });
    expect(patchGas.status).toBe(404);
    expect(patchGas.json?.code).toBe('gas_sponsorship_not_found');

    const smartWalletList = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/smart-wallets?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(smartWalletList.status).toBe(200);
    const attackerSmartWalletRows = Array.isArray(smartWalletList.json?.configs)
      ? smartWalletList.json?.configs
      : [];
    expect(attackerSmartWalletRows.length).toBe(0);

    const patchSmartWallet = await callCf(attackerHandler, {
      method: 'PATCH',
      path: '/console/smart-wallets/sw-cf-isolation-1',
      body: { enabled: false },
    });
    expect(patchSmartWallet.status).toBe(404);
    expect(patchSmartWallet.json?.code).toBe('smart_wallet_config_not_found');

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

  test('cloudflare policy/gas/export insight routes return aggregated views', async () => {
    const orgId = 'org-insights-cloudflare-1';
    const projectId = 'default-project';
    const environmentId = `${orgId}:${projectId}:prod`;
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeSeedWallet({
          id: 'wallet_insights_cf_1',
          orgId,
          projectId,
          environmentId,
        }),
      ],
    });
    const apiKeys = createInMemoryConsoleApiKeyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    await seedOrgProjectEnvironment(orgProjectEnv, {
      orgId,
      projectId,
      actorUserId: 'user-insights-cloudflare-1',
    });
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-insights-cloudflare-1'),
      wallets,
      apiKeys,
      orgProjectEnv,
    });

    const createdExportKey = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'export-key-cf',
        environmentId,
        kind: 'secret_key',
        scopes: ['wallets:read', 'keys:export'],
      },
    });
    expect(createdExportKey.status).toBe(201);

    const createdNonExportKey = await callCf(handler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'non-export-key-cf',
        environmentId,
        kind: 'secret_key',
        scopes: ['wallets:read'],
      },
    });
    expect(createdNonExportKey.status).toBe(201);

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

    const governance = await callCf(handler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(environmentId)}`,
    });
    expect(governance.status).toBe(200);
    expect(Number(getPath(governance.json, 'governance', 'totals', 'apiKeyCount') || 0)).toBe(2);
    expect(
      Number(getPath(governance.json, 'governance', 'totals', 'exportScopedKeyCount') || 0),
    ).toBe(1);
    expect(
      Number(
        getPath(
          governance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
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

    const created = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-cf-lifecycle-1',
        name: 'Policy Cloudflare Lifecycle',
        rules: {
          blockedActions: [],
          allowedChains: ['ethereum'],
          maxAmountMinor: 5000,
        },
      },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'policy', 'id')).toBe('policy-cf-lifecycle-1');
    expect(getPath(created.json, 'policy', 'status')).toBe('DRAFT');
    expect(Number(getPath(created.json, 'policy', 'version') || 0)).toBe(0);

    const allowedSimulation = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies/policy-cf-lifecycle-1/simulate',
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
      path: '/console/policies/policy-cf-lifecycle-1',
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
      path: '/console/policies/policy-cf-lifecycle-1/simulate',
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
      path: '/console/policies/policy-cf-lifecycle-1/publish',
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
        id: 'policy-cf-forbidden-1',
        name: 'Forbidden policy',
      },
    });
    expect(forbiddenCreate.status).toBe(403);
    expect(forbiddenCreate.json?.code).toBe('forbidden');
  });

  test('cloudflare policy routes enforce org isolation', async () => {
    const policies = createInMemoryConsolePolicyService();
    const ownerPolicyId = 'policy-owner-cf-isolation-1';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], 'org-policy-owner-cf', 'owner-policy-user-cf'),
      policies,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: ownerPolicyId,
        name: 'Owner Policy CF',
      },
    });
    expect(created.status).toBe(201);

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
        id: 'policy-project-cloudflare-1',
        name: 'Project Policy Cloudflare',
      },
    });
    expect(createProjectPolicy.status).toBe(201);
    const publishProjectPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent('policy-project-cloudflare-1')}/publish`,
    });
    expect(publishProjectPolicy.status).toBe(200);

    const createWalletPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: 'policy-wallet-cloudflare-1',
        name: 'Wallet Policy Cloudflare',
      },
    });
    expect(createWalletPolicy.status).toBe(201);

    const projectAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'PROJECT',
        scopeId: projectId,
        policyId: 'policy-project-cloudflare-1',
      },
    });
    expect(projectAssignment.status).toBe(200);

    const walletAssignment = await callCf(adminHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'WALLET',
        scopeId: walletId,
        policyId: 'policy-wallet-cloudflare-1',
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
      'policy-wallet-cloudflare-1',
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
      walletPolicyRows.some(
        (entry) => String(entry?.policyId || '') === 'policy-project-cloudflare-1',
      ),
    ).toBe(true);
    expect(
      walletPolicyRows.some(
        (entry) => String(entry?.policyId || '') === 'policy-wallet-cloudflare-1',
      ),
    ).toBe(false);

    const publishWalletPolicy = await callCf(adminHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent('policy-wallet-cloudflare-1')}/publish`,
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
      liveWalletPolicyRows.some(
        (entry) => String(entry?.policyId || '') === 'policy-wallet-cloudflare-1',
      ),
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
      projectPolicyRows.some(
        (entry) => String(entry?.policyId || '') === 'policy-project-cloudflare-1',
      ),
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
        policyId: 'org-policy-assign-cloudflare:policy:default',
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
        id: 'policy-create-attach-cloudflare-1',
        name: 'Attached draft cloudflare',
        assignment: {
          scopeType: 'ENVIRONMENT',
          scopeId: environmentScopeId,
        },
      },
    });
    expect(created.status).toBe(201);
    expect(getPath(created.json, 'policy', 'id')).toBe('policy-create-attach-cloudflare-1');

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
      'policy-create-attach-cloudflare-1',
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
        scopes: ['wallets:read'],
        ipAllowlist: ['198.51.100.5/32'],
        expiresAt,
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    const createdSecret = String(getPath(created.json, 'secret') || '');
    expect(keyId).toBeTruthy();
    expect(createdSecret).toContain('tsk_');
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
    expect(rotatedSecret).toContain('tsk_');
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

  test('legacy billing settlement routes are removed (cloudflare)', async () => {
    const handler = createCloudflareConsoleRouter({});
    for (const routeCase of REMOVED_BILLING_SETTLEMENT_ROUTE_CASES) {
      const res = await callCf(handler, {
        method: routeCase.method,
        path: routeCase.path,
        ...(routeCase.body ? { body: routeCase.body } : {}),
      });
      expect(res.status, `${routeCase.method} ${routeCase.path}`).toBe(404);
    }
  });

  test('POST /console/billing/payment-methods requires admin role', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['billing_admin']),
      billing: createInMemoryConsoleBillingService(),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/payment-methods',
      body: {},
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('forbidden');
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
        creditPackId: 'usd_200',
      },
    });
    expect(created.status).toBe(201);
    const checkoutSessionId = String(getPath(created.json, 'checkoutSession', 'id') || '');
    const checkoutSessionUrl = String(getPath(created.json, 'checkoutSession', 'url') || '');
    expect(checkoutSessionId).toBeTruthy();
    expect(checkoutSessionUrl).toContain('https://checkout.stripe.com/pay/');
    expect(String(getPath(created.json, 'checkoutSession', 'customerRef') || '')).toContain('cus_');
    expect(getPath(created.json, 'checkoutSession', 'creditPackId')).toBe('usd_200');
    expect(Number(getPath(created.json, 'checkoutSession', 'amountMinor') || 0)).toBe(20000);
    expect(String(getPath(created.json, 'checkoutSession', 'expiresAt') || '')).toMatch(
      /^\d{4}-\d{2}-\d{2}T/,
    );

    const invalid = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: '/dashboard/billing',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_200',
      },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.json?.code).toBe('invalid_body');
  });

  test('POST /console/billing/stripe/customer-portal-session returns billing_not_configured without billing service', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/customer-portal-session',
      body: {
        returnUrl: 'https://app.example.com/dashboard/billing',
      },
    });
    expect(res.status).toBe(501);
    expect(res.json?.code).toBe('billing_not_configured');
  });

  test('POST /console/billing/stripe/customer-portal-session creates portal session', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });

    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/customer-portal-session',
      body: {
        returnUrl: 'https://app.example.com/dashboard/billing',
      },
    });
    expect(created.status).toBe(201);
    const sessionId = String(getPath(created.json, 'portalSession', 'id') || '');
    const sessionUrl = String(getPath(created.json, 'portalSession', 'url') || '');
    expect(sessionId).toBeTruthy();
    expect(sessionUrl).toContain('https://billing.stripe.com/p/session/');
    expect(String(getPath(created.json, 'portalSession', 'customerRef') || '')).toContain('cus_');

    const invalid = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/customer-portal-session',
      body: {
        returnUrl: '/dashboard/billing',
      },
    });
    expect(invalid.status).toBe(400);
    expect(invalid.json?.code).toBe('invalid_body');
  });

  test('legacy billing subscription route is removed', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
    });
    const res = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/subscription',
    });
    expect(res.status).toBe(404);
  });

  test('legacy billing subscription lifecycle routes are removed', async () => {
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing: createInMemoryConsoleBillingService(),
    });

    const canceled = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/subscription/cancel',
    });
    expect(canceled.status).toBe(404);

    const resumed = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/subscription/resume',
    });
    expect(resumed.status).toBe(404);
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

  test('Stripe webhook settles prepaid purchase receipts idempotently', async () => {
    const billing = createInMemoryConsoleBillingService();
    const secret = 'whsec_console_router_cf_projection_test';
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin']),
      billing,
      billingStripeWebhookSecret: secret,
    });

    const checkoutSession = await callCf(handler, {
      method: 'POST',
      path: '/console/billing/stripe/checkout-session',
      body: {
        successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
        cancelUrl: 'https://app.example.com/pricing?checkout=cancel',
        creditPackId: 'usd_200',
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
    expect(getPath(projectedPurchase.json, 'purchase', 'creditPackId')).toBe('usd_200');
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
    expect(Number(getPath(overviewAfter.json, 'overview', 'creditBalanceMinor') || 0)).toBe(20000);
  });

  test('GET /console/billing/invoices/:id/pdf returns invoice PDF export', async () => {
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

    const auditEvents = await audit.listEvents({
      orgId: 'org-1',
      actorUserId: 'user-1',
      roles: ['admin'],
    });
    expect(auditEvents.length).toBe(1);
    expect(auditEvents[0]?.action).toBe('billing.invoice.pdf_export');
    expect(getPath(auditEvents[0], 'metadata', 'invoiceId')).toBe(invoiceId);
    expect(getPath(auditEvents[0], 'metadata', 'exportPolicy')).toBe('ALL_INVOICE_STATES');

    const missing = await callCf(handler, {
      method: 'GET',
      path: '/console/billing/invoices/inv_missing/pdf',
    });
    expect(missing.status).toBe(404);
    expect(missing.json?.code).toBe('invoice_not_found');
  });

  test('cloudflare billing invoices support server-side filters, pagination, and activity', async () => {
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
      creditPackId: 'usd_200',
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

  test('cloudflare billing invoice generation emits webhook events', async () => {
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

test.describe('console router (postgres org-project-env)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:org-project-env:postgres');
  const authOrgId = 'org-router-postgres-org-project-env';
  let orgProjectEnv: ConsoleOrgProjectEnvService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    orgProjectEnv = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
  });

  test('express org/project/environment routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerManagedProjectId = `${ownerOrgId}:managed-project`;
    const ownerManagedEnvironmentId = `${ownerOrgId}:${ownerManagedProjectId}:dev`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-org-project-env-user'),
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerProjectId = '';
    try {
      const projects = await fetchJson(`${ownerServer.baseUrl}/console/projects`, {
        method: 'GET',
      });
      expect(projects.status).toBe(200);
      ownerProjectId = String(getPath(projects.json, 'projects', 0, 'id') || '');
      expect(ownerProjectId).toBeTruthy();
      expect(
        Number(getPath(projects.json, 'projects', 0, 'environmentCount') || 0),
      ).toBeGreaterThanOrEqual(1);

      const createdProject = await fetchJson(`${ownerServer.baseUrl}/console/projects`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerManagedProjectId,
          name: 'Owner Managed Project',
        }),
      });
      expect(createdProject.status).toBe(201);
      expect(Number(getPath(createdProject.json, 'project', 'environmentCount') || 0)).toBe(3);

      const environments = await fetchJson(
        `${ownerServer.baseUrl}/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
        { method: 'GET' },
      );
      expect(environments.status).toBe(200);
      const ownerEnvRows = Array.isArray(environments.json?.environments)
        ? environments.json?.environments
        : [];
      expect(ownerEnvRows.length).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-org-project-env-user'),
      orgProjectEnv: orgProjectEnv!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const org = await fetchJson(`${attackerServer.baseUrl}/console/org`, {
        method: 'GET',
      });
      expect(org.status).toBe(200);
      expect(String(getPath(org.json, 'org', 'id') || '')).toBe(attackerOrgId);
      expect(String(getPath(org.json, 'org', 'id') || '')).not.toBe(ownerOrgId);

      const projects = await fetchJson(`${attackerServer.baseUrl}/console/projects`, {
        method: 'GET',
      });
      expect(projects.status).toBe(200);
      const attackerProjects = Array.isArray(projects.json?.projects)
        ? projects.json?.projects
        : [];
      expect(
        attackerProjects.some((entry: any) => String(entry?.id || '') === ownerProjectId),
      ).toBe(false);
      expect(
        attackerProjects.some((entry: any) => String(entry?.id || '') === ownerManagedProjectId),
      ).toBe(false);

      const scopedEnvironments = await fetchJson(
        `${attackerServer.baseUrl}/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
        {
          method: 'GET',
        },
      );
      expect(scopedEnvironments.status).toBe(200);
      const attackerScopedRows = Array.isArray(scopedEnvironments.json?.environments)
        ? scopedEnvironments.json?.environments
        : [];
      expect(attackerScopedRows.length).toBe(0);

      const patchOwnerProject = await fetchJson(
        `${attackerServer.baseUrl}/console/projects/${encodeURIComponent(ownerManagedProjectId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker rename' }),
        },
      );
      expect(patchOwnerProject.status).toBe(404);
      expect(patchOwnerProject.json?.code).toBe('project_not_found');

      const archiveOwnerEnvironment = await fetchJson(
        `${attackerServer.baseUrl}/console/environments/${encodeURIComponent(ownerManagedEnvironmentId)}/archive`,
        {
          method: 'POST',
        },
      );
      expect(archiveOwnerEnvironment.status).toBe(404);
      expect(archiveOwnerEnvironment.json?.code).toBe('environment_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare org/project/environment routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerManagedProjectId = `${ownerOrgId}:managed-project`;
    const ownerManagedEnvironmentId = `${ownerOrgId}:${ownerManagedProjectId}:dev`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-org-project-env-user-cf'),
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerProjects = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(ownerProjects.status).toBe(200);
    const ownerProjectId = String(getPath(ownerProjects.json, 'projects', 0, 'id') || '');
    expect(ownerProjectId).toBeTruthy();
    expect(
      Number(getPath(ownerProjects.json, 'projects', 0, 'environmentCount') || 0),
    ).toBeGreaterThanOrEqual(1);

    const ownerCreatedProject = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/projects',
      body: {
        id: ownerManagedProjectId,
        name: 'Owner Managed Project CF',
      },
    });
    expect(ownerCreatedProject.status).toBe(201);
    expect(Number(getPath(ownerCreatedProject.json, 'project', 'environmentCount') || 0)).toBe(3);

    const ownerEnvironments = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
    });
    expect(ownerEnvironments.status).toBe(200);
    const ownerEnvRows = Array.isArray(ownerEnvironments.json?.environments)
      ? ownerEnvironments.json?.environments
      : [];
    expect(ownerEnvRows.length).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-org-project-env-user-cf'),
      orgProjectEnv: orgProjectEnv!,
    });
    const org = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/org',
    });
    expect(org.status).toBe(200);
    expect(String(getPath(org.json, 'org', 'id') || '')).toBe(attackerOrgId);
    expect(String(getPath(org.json, 'org', 'id') || '')).not.toBe(ownerOrgId);

    const projects = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/projects',
    });
    expect(projects.status).toBe(200);
    const attackerProjects = Array.isArray(projects.json?.projects) ? projects.json?.projects : [];
    expect(attackerProjects.some((entry: any) => String(entry?.id || '') === ownerProjectId)).toBe(
      false,
    );
    expect(
      attackerProjects.some((entry: any) => String(entry?.id || '') === ownerManagedProjectId),
    ).toBe(false);

    const scopedEnvironments = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/environments?projectId=${encodeURIComponent(ownerProjectId)}`,
    });
    expect(scopedEnvironments.status).toBe(200);
    const attackerScopedRows = Array.isArray(scopedEnvironments.json?.environments)
      ? scopedEnvironments.json?.environments
      : [];
    expect(attackerScopedRows.length).toBe(0);

    const patchOwnerProject = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/projects/${encodeURIComponent(ownerManagedProjectId)}`,
      body: { name: 'attacker rename cf' },
    });
    expect(patchOwnerProject.status).toBe(404);
    expect(patchOwnerProject.json?.code).toBe('project_not_found');

    const archiveOwnerEnvironment = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/environments/${encodeURIComponent(ownerManagedEnvironmentId)}/archive`,
    });
    expect(archiveOwnerEnvironment.status).toBe(404);
    expect(archiveOwnerEnvironment.json?.code).toBe('environment_not_found');
  });
});

test.describe('console router (postgres onboarding)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:onboarding:postgres');
  const authOrgId = 'org-router-postgres-onboarding';
  let orgProjectEnv: ConsoleOrgProjectEnvService | null = null;
  let apiKeys: ConsoleApiKeyService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    orgProjectEnv = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    apiKeys = await createPostgresConsoleApiKeyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_api_keys WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
  });

  test('express onboarding routes enforce org isolation and idempotent reuse', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const projectId = 'proj_onboarding_postgres';
    const environmentId = 'proj_onboarding_postgres:dev';
    const billing = createInMemoryConsoleBillingService();

    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: orgProjectEnv!,
      apiKeys: apiKeys!,
      billing,
    });

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-onboarding-user'),
      onboarding,
      billing,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const before = await fetchJson(`${ownerServer.baseUrl}/console/onboarding/state`, {
        method: 'GET',
      });
      expect(before.status).toBe(200);
      expect(getPath(before.json, 'state', 'complete')).toBe(false);

      const organization = await fetchJson(
        `${ownerServer.baseUrl}/console/onboarding/organization`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            org: { name: 'Onboarding Postgres Org', slug: 'onboarding-postgres-org' },
          }),
        },
      );
      expect(organization.status).toBe(201);
      expect(getPath(organization.json, 'result', 'created', 'organization')).toBe(true);

      const firstProject = await fetchJson(`${ownerServer.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: projectId, name: 'Onboarding Postgres Project' },
          environment: { id: environmentId, name: 'Development' },
        }),
      });
      expect(firstProject.status).toBe(201);
      expect(getPath(firstProject.json, 'result', 'created', 'project')).toBe(true);
      expect(getPath(firstProject.json, 'result', 'created', 'environment')).toBe(false);

      const secondProject = await fetchJson(`${ownerServer.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: projectId, name: 'Onboarding Postgres Project' },
          environment: { id: environmentId, name: 'Development' },
        }),
      });
      expect(secondProject.status).toBe(200);
      expect(getPath(secondProject.json, 'result', 'created', 'project')).toBe(false);
      expect(getPath(secondProject.json, 'result', 'created', 'environment')).toBe(false);

      const after = await fetchJson(`${ownerServer.baseUrl}/console/onboarding/state`, {
        method: 'GET',
      });
      expect(after.status).toBe(200);
      expect(getPath(after.json, 'state', 'complete')).toBe(false);
      expect(getPath(after.json, 'state', 'onboardingComplete')).toBe(true);
      expect(Number(getPath(after.json, 'state', 'activeApiKeyCount') || 0)).toBe(0);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-onboarding-user'),
      onboarding,
      billing,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerState = await fetchJson(`${attackerServer.baseUrl}/console/onboarding/state`, {
        method: 'GET',
      });
      expect(attackerState.status).toBe(200);
      expect(getPath(attackerState.json, 'state', 'complete')).toBe(false);
      expect(Number(getPath(attackerState.json, 'state', 'activeApiKeyCount') || 0)).toBe(0);
      expect(String(getPath(attackerState.json, 'state', 'selectedProjectId') || '')).not.toBe(
        projectId,
      );
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare onboarding routes enforce org isolation and idempotent reuse', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const projectId = 'proj_onboarding_postgres_cf';
    const environmentId = 'proj_onboarding_postgres_cf:dev';
    const billing = createInMemoryConsoleBillingService();

    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv: orgProjectEnv!,
      apiKeys: apiKeys!,
      billing,
    });

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-onboarding-user-cf'),
      onboarding,
      billing,
    });

    const before = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(before.status).toBe(200);
    expect(getPath(before.json, 'state', 'complete')).toBe(false);

    const organization = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/onboarding/organization',
      body: {
        org: { name: 'Onboarding Postgres Org CF', slug: 'onboarding-postgres-org-cf' },
      },
    });
    expect(organization.status).toBe(201);
    expect(getPath(organization.json, 'result', 'created', 'organization')).toBe(true);

    const firstProject = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: projectId, name: 'Onboarding Postgres Project CF' },
        environment: { id: environmentId, name: 'Development' },
      },
    });
    expect(firstProject.status).toBe(201);
    expect(getPath(firstProject.json, 'result', 'created', 'project')).toBe(true);
    expect(getPath(firstProject.json, 'result', 'created', 'environment')).toBe(false);

    const secondProject = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/onboarding/project',
      body: {
        project: { id: projectId, name: 'Onboarding Postgres Project CF' },
        environment: { id: environmentId, name: 'Development' },
      },
    });
    expect(secondProject.status).toBe(200);
    expect(getPath(secondProject.json, 'result', 'created', 'project')).toBe(false);
    expect(getPath(secondProject.json, 'result', 'created', 'environment')).toBe(false);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-onboarding-user-cf'),
      onboarding,
      billing,
    });
    const attackerState = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/onboarding/state',
    });
    expect(attackerState.status).toBe(200);
    expect(getPath(attackerState.json, 'state', 'complete')).toBe(false);
    expect(getPath(attackerState.json, 'state', 'onboardingComplete')).toBe(false);
    expect(Number(getPath(attackerState.json, 'state', 'activeApiKeyCount') || 0)).toBe(0);
    expect(String(getPath(attackerState.json, 'state', 'selectedProjectId') || '')).not.toBe(
      projectId,
    );
  });
});

test.describe('console router (postgres team-rbac)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:team-rbac:postgres');
  const authOrgId = 'org-router-postgres-team-rbac';
  let teamRbac: ConsoleTeamRbacService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    teamRbac = await createPostgresConsoleTeamRbacService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_team_members WHERE namespace = $1', [namespace]);
  });

  test('express team member routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    let ownerMemberId = '';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-team-rbac-user'),
      teamRbac: teamRbac!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const invited = await fetchJson(`${ownerServer.baseUrl}/console/members/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: `${ownerOrgId}:member-user-1`,
          email: 'owner-member@example.com',
          roles: [{ role: 'wallet_operations_read' }],
        }),
      });
      expect(invited.status).toBe(201);
      ownerMemberId = String(getPath(invited.json, 'member', 'id') || '');
      expect(ownerMemberId).toContain('mbr_');

      const listed = await fetchJson(`${ownerServer.baseUrl}/console/members`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const ownerMembers = Array.isArray(listed.json?.members) ? listed.json?.members : [];
      expect(ownerMembers.some((entry: any) => String(entry?.id || '') === ownerMemberId)).toBe(
        true,
      );
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-team-rbac-user'),
      teamRbac: teamRbac!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const listed = await fetchJson(`${attackerServer.baseUrl}/console/members`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const attackerMembers = Array.isArray(listed.json?.members) ? listed.json?.members : [];
      expect(attackerMembers.some((entry: any) => String(entry?.id || '') === ownerMemberId)).toBe(
        false,
      );

      const patchOwnerMember = await fetchJson(
        `${attackerServer.baseUrl}/console/members/${encodeURIComponent(ownerMemberId)}/roles`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            roles: [{ role: 'integrations_read' }],
          }),
        },
      );
      expect(patchOwnerMember.status).toBe(404);
      expect(patchOwnerMember.json?.code).toBe('member_not_found');

      const deleteOwnerMember = await fetchJson(
        `${attackerServer.baseUrl}/console/members/${encodeURIComponent(ownerMemberId)}`,
        { method: 'DELETE' },
      );
      expect(deleteOwnerMember.status).toBe(404);
      expect(deleteOwnerMember.json?.code).toBe('member_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare team member routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    let ownerMemberId = '';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-team-rbac-user-cf'),
      teamRbac: teamRbac!,
    });
    const ownerInvite = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/members/invite',
      body: {
        userId: `${ownerOrgId}:member-user-1`,
        email: 'owner-member-cf@example.com',
        roles: [{ role: 'wallet_operations_read' }],
      },
    });
    expect(ownerInvite.status).toBe(201);
    ownerMemberId = String(getPath(ownerInvite.json, 'member', 'id') || '');
    expect(ownerMemberId).toContain('mbr_');

    const ownerMembers = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/members',
    });
    expect(ownerMembers.status).toBe(200);
    const ownerRows = Array.isArray(ownerMembers.json?.members) ? ownerMembers.json?.members : [];
    expect(ownerRows.some((entry: any) => String(entry?.id || '') === ownerMemberId)).toBe(true);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-team-rbac-user-cf'),
      teamRbac: teamRbac!,
    });
    const attackerMembers = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/members',
    });
    expect(attackerMembers.status).toBe(200);
    const attackerRows = Array.isArray(attackerMembers.json?.members)
      ? attackerMembers.json?.members
      : [];
    expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerMemberId)).toBe(
      false,
    );

    const patchOwnerMember = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/members/${encodeURIComponent(ownerMemberId)}/roles`,
      body: {
        roles: [{ role: 'integrations_read' }],
      },
    });
    expect(patchOwnerMember.status).toBe(404);
    expect(patchOwnerMember.json?.code).toBe('member_not_found');

    const deleteOwnerMember = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/members/${encodeURIComponent(ownerMemberId)}`,
    });
    expect(deleteOwnerMember.status).toBe(404);
    expect(deleteOwnerMember.json?.code).toBe('member_not_found');
  });
});

test.describe('console router (postgres approvals)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:approvals:postgres');
  const authOrgId = 'org-router-postgres-approvals';
  let approvals: ConsoleApprovalService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    approvals = await createPostgresConsoleApprovalService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_approvals WHERE namespace = $1', [namespace]);
  });

  test('express approval routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerApprovalId = `${ownerOrgId}:approval-1`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-approvals-user'),
      approvals: approvals!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/approvals`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerApprovalId,
          operationType: 'KEY_EXPORT',
          reason: 'Owner approval request',
        }),
      });
      expect(created.status).toBe(201);

      const listed = await fetchJson(`${ownerServer.baseUrl}/console/approvals`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const ownerRows = Array.isArray(listed.json?.approvals) ? listed.json?.approvals : [];
      expect(ownerRows.some((entry: any) => String(entry?.id || '') === ownerApprovalId)).toBe(
        true,
      );
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-approvals-user'),
      approvals: approvals!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const listed = await fetchJson(`${attackerServer.baseUrl}/console/approvals`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      const attackerRows = Array.isArray(listed.json?.approvals) ? listed.json?.approvals : [];
      expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerApprovalId)).toBe(
        false,
      );

      const readOwner = await fetchJson(
        `${attackerServer.baseUrl}/console/approvals/${encodeURIComponent(ownerApprovalId)}`,
        { method: 'GET' },
      );
      expect(readOwner.status).toBe(404);
      expect(readOwner.json?.code).toBe('approval_not_found');

      const approveOwner = await fetchJson(
        `${attackerServer.baseUrl}/console/approvals/${encodeURIComponent(ownerApprovalId)}/approve`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'attacker approval attempt',
            mfaVerified: true,
          }),
        },
      );
      expect(approveOwner.status).toBe(404);
      expect(approveOwner.json?.code).toBe('approval_not_found');

      const rejectOwner = await fetchJson(
        `${attackerServer.baseUrl}/console/approvals/${encodeURIComponent(ownerApprovalId)}/reject`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            reason: 'attacker reject attempt',
          }),
        },
      );
      expect(rejectOwner.status).toBe(404);
      expect(rejectOwner.json?.code).toBe('approval_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare approval routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerApprovalId = `${ownerOrgId}:approval-1`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-approvals-user-cf'),
      approvals: approvals!,
    });
    const ownerCreate = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/approvals',
      body: {
        id: ownerApprovalId,
        operationType: 'KEY_EXPORT',
        reason: 'Owner approval request CF',
      },
    });
    expect(ownerCreate.status).toBe(201);

    const ownerList = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(ownerList.status).toBe(200);
    const ownerRows = Array.isArray(ownerList.json?.approvals) ? ownerList.json?.approvals : [];
    expect(ownerRows.some((entry: any) => String(entry?.id || '') === ownerApprovalId)).toBe(true);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-approvals-user-cf'),
      approvals: approvals!,
    });
    const attackerList = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/approvals',
    });
    expect(attackerList.status).toBe(200);
    const attackerRows = Array.isArray(attackerList.json?.approvals)
      ? attackerList.json?.approvals
      : [];
    expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerApprovalId)).toBe(
      false,
    );

    const readOwner = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/approvals/${encodeURIComponent(ownerApprovalId)}`,
    });
    expect(readOwner.status).toBe(404);
    expect(readOwner.json?.code).toBe('approval_not_found');

    const approveOwner = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/approvals/${encodeURIComponent(ownerApprovalId)}/approve`,
      body: {
        reason: 'attacker approval attempt',
        mfaVerified: true,
      },
    });
    expect(approveOwner.status).toBe(404);
    expect(approveOwner.json?.code).toBe('approval_not_found');

    const rejectOwner = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/approvals/${encodeURIComponent(ownerApprovalId)}/reject`,
      body: {
        reason: 'attacker reject attempt',
      },
    });
    expect(rejectOwner.status).toBe(404);
    expect(rejectOwner.json?.code).toBe('approval_not_found');
  });
});

test.describe('console router (postgres wallets)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:wallets:postgres');
  const authOrgId = 'org-router-postgres-wallets';
  let wallets: ConsoleWalletService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    wallets = await createPostgresConsoleWalletService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_wallet_index WHERE namespace = $1', [namespace]);
  });

  test('express wallet routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-user'),
      wallets: wallets!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerWalletId = '';
    try {
      const listed = await fetchJson(`${ownerServer.baseUrl}/console/wallets`, {
        method: 'GET',
      });
      expect(listed.status).toBe(200);
      ownerWalletId = String(getPath(listed.json, 'wallets', 0, 'id') || '');
      expect(ownerWalletId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-user'),
      wallets: wallets!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const detail = await fetchJson(
        `${attackerServer.baseUrl}/console/wallets/${encodeURIComponent(ownerWalletId)}`,
        {
          method: 'GET',
        },
      );
      expect(detail.status).toBe(404);
      expect(detail.json?.code).toBe('wallet_not_found');

      const searched = await fetchJson(
        `${attackerServer.baseUrl}/console/wallets/search?q=${encodeURIComponent(ownerWalletId)}`,
        { method: 'GET' },
      );
      expect(searched.status).toBe(200);
      const attackerRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
      expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerWalletId)).toBe(
        false,
      );
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare wallet routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-user-cf'),
      wallets: wallets!,
    });
    const ownerList = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(ownerList.status).toBe(200);
    const ownerWalletId = String(getPath(ownerList.json, 'wallets', 0, 'id') || '');
    expect(ownerWalletId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-user-cf'),
      wallets: wallets!,
    });
    const detail = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/wallets/${encodeURIComponent(ownerWalletId)}`,
    });
    expect(detail.status).toBe(404);
    expect(detail.json?.code).toBe('wallet_not_found');

    const searched = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/wallets/search?q=${encodeURIComponent(ownerWalletId)}`,
    });
    expect(searched.status).toBe(200);
    const attackerRows = Array.isArray(searched.json?.wallets) ? searched.json?.wallets : [];
    expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerWalletId)).toBe(
      false,
    );
  });

  test('express policy/gas insight routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-insights`;
    const attackerOrgId = `${authOrgId}:attacker-insights`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-insights-user'),
      wallets: wallets!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerProjectId = '';
    let ownerEnvironmentId = '';
    try {
      const ownerList = await fetchJson(`${ownerServer.baseUrl}/console/wallets`, {
        method: 'GET',
      });
      expect(ownerList.status).toBe(200);
      ownerProjectId = String(getPath(ownerList.json, 'wallets', 0, 'projectId') || '');
      ownerEnvironmentId = String(getPath(ownerList.json, 'wallets', 0, 'environmentId') || '');
      expect(ownerProjectId).toBeTruthy();
      expect(ownerEnvironmentId).toBeTruthy();

      const ownerCoverage = await fetchJson(
        `${ownerServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(ownerCoverage.status).toBe(200);
      expect(
        Number(getPath(ownerCoverage.json, 'coverage', 'totals', 'walletCount') || 0),
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-insights-user'),
      wallets: wallets!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const coverage = await fetchJson(
        `${attackerServer.baseUrl}/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(coverage.status).toBe(200);
      expect(Number(getPath(coverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBe(0);

      const readiness = await fetchJson(
        `${attackerServer.baseUrl}/console/gas/readiness?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(readiness.status).toBe(200);
      expect(Number(getPath(readiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare policy/gas insight routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-insights-cf`;
    const attackerOrgId = `${authOrgId}:attacker-insights-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-wallet-insights-user-cf'),
      wallets: wallets!,
    });
    const ownerList = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/wallets',
    });
    expect(ownerList.status).toBe(200);
    const ownerProjectId = String(getPath(ownerList.json, 'wallets', 0, 'projectId') || '');
    const ownerEnvironmentId = String(getPath(ownerList.json, 'wallets', 0, 'environmentId') || '');
    expect(ownerProjectId).toBeTruthy();
    expect(ownerEnvironmentId).toBeTruthy();

    const ownerCoverage = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(ownerCoverage.status).toBe(200);
    expect(
      Number(getPath(ownerCoverage.json, 'coverage', 'totals', 'walletCount') || 0),
    ).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-wallet-insights-user-cf'),
      wallets: wallets!,
    });
    const attackerCoverage = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/policy/coverage?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerCoverage.status).toBe(200);
    expect(Number(getPath(attackerCoverage.json, 'coverage', 'totals', 'walletCount') || 0)).toBe(
      0,
    );

    const attackerReadiness = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/gas/readiness?projectId=${encodeURIComponent(ownerProjectId)}&environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerReadiness.status).toBe(200);
    expect(Number(getPath(attackerReadiness.json, 'readiness', 'totals', 'walletCount') || 0)).toBe(
      0,
    );
  });
});

test('express policy routes expose published policy versions newest-first', async () => {
  const orgId = 'org-router-policy-versions';
  const policyId = `${orgId}:managed-policy`;
  const router = createConsoleRouter({
    auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-policy-versions'),
    policies: createInMemoryConsolePolicyService(),
  });
  const srv = await startExpressRouter(router);
  try {
    const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: policyId,
        name: 'Policy Versions Test',
      }),
    });
    expect(created.status).toBe(201);

    const firstUpdate = await fetchJson(
      `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rules: {
            blockedActions: ['delete_key'],
            allowedChains: ['Ethereum', 'NEAR'],
            maxAmountMinor: 250000,
          },
        }),
      },
    );
    expect(firstUpdate.status).toBe(200);

    const firstPublish = await fetchJson(
      `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
      { method: 'POST' },
    );
    expect(firstPublish.status).toBe(200);

    const secondUpdate = await fetchJson(
      `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}`,
      {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rules: {
            blockedActions: ['export_key'],
            allowedChains: ['Ethereum'],
            maxAmountMinor: 500000,
          },
        }),
      },
    );
    expect(secondUpdate.status).toBe(200);

    const secondPublish = await fetchJson(
      `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/publish`,
      { method: 'POST' },
    );
    expect(secondPublish.status).toBe(200);

    const versions = await fetchJson(
      `${srv.baseUrl}/console/policies/${encodeURIComponent(policyId)}/versions`,
      { method: 'GET' },
    );
    expect(versions.status).toBe(200);
    const rows = Array.isArray(versions.json?.versions) ? versions.json.versions : [];
    expect(rows).toHaveLength(2);
    expect(Number(getPath(rows[0], 'version') || 0)).toBe(2);
    expect(String(getPath(rows[0], 'status') || '')).toBe('PUBLISHED');
    expect(getPath(rows[0], 'rules', 'blockedActions', 0)).toBe('export_key');
    expect(getPath(rows[0], 'rules', 'allowedChains', 0)).toBe('Ethereum');
    expect(Number(getPath(rows[0], 'rules', 'maxAmountMinor') || 0)).toBe(500000);
    expect(Number(getPath(rows[1], 'version') || 0)).toBe(1);
    expect(getPath(rows[1], 'rules', 'blockedActions', 0)).toBe('delete_key');
    expect(getPath(rows[1], 'rules', 'allowedChains', 0)).toBe('Ethereum');
    expect(getPath(rows[1], 'rules', 'allowedChains', 1)).toBe('NEAR');
    expect(Number(getPath(rows[1], 'rules', 'maxAmountMinor') || 0)).toBe(250000);
  } finally {
    await srv.close();
  }
});

test('express policy routes reject invalid contract-call policy rules', async () => {
  const orgId = 'org-router-policy-validation';
  const router = createConsoleRouter({
    auth: makeConsoleAuthAdapter(['admin'], orgId, 'user-policy-validation'),
    policies: createInMemoryConsolePolicyService(),
  });
  const srv = await startExpressRouter(router);
  try {
    const created = await fetchJson(`${srv.baseUrl}/console/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: `${orgId}:invalid-contract-policy`,
        name: 'Invalid Contract Policy',
        rules: {
          allowedContractCalls: [
            {
              contractAddress: '0xabc123',
              functions: ['approve('],
            },
          ],
        },
      }),
    });
    expect(created.status).toBe(400);
    expect(created.json?.code).toBe('invalid_body');
  } finally {
    await srv.close();
  }
});

test.describe('console router (postgres policies)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:policies:postgres');
  const authOrgId = 'org-router-postgres-policies';
  let policies: ConsolePolicyService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    policies = await createPostgresConsolePolicyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_policy_assignments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_policy_versions WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_policies WHERE namespace = $1', [namespace]);
  });

  test('express policy routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerPolicyId = `${ownerOrgId}:managed-policy`;
    let ownerAssignmentId = '';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-policy-user'),
      policies: policies!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: ownerPolicyId,
          name: 'Owner Managed Policy',
        }),
      });
      expect(created.status).toBe(201);

      const published = await fetchJson(
        `${ownerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
        {
          method: 'POST',
        },
      );
      expect(published.status).toBe(200);

      const listed = await fetchJson(`${ownerServer.baseUrl}/console/policies`, { method: 'GET' });
      expect(listed.status).toBe(200);
      const ownerPolicies = Array.isArray(listed.json?.policies) ? listed.json?.policies : [];
      expect(ownerPolicies.some((entry: any) => String(entry?.id || '') === ownerPolicyId)).toBe(
        true,
      );

      const upsertedAssignment = await fetchJson(
        `${ownerServer.baseUrl}/console/policies/assignments`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            scopeType: 'ORG',
            scopeId: ownerOrgId,
            policyId: ownerPolicyId,
          }),
        },
      );
      expect(upsertedAssignment.status).toBe(200);
      ownerAssignmentId = String(getPath(upsertedAssignment.json, 'assignment', 'id') || '');
      expect(ownerAssignmentId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-policy-user'),
      policies: policies!,
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

      const listedAssignments = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/assignments?scopeType=ORG&scopeId=${encodeURIComponent(ownerOrgId)}`,
        { method: 'GET' },
      );
      expect(listedAssignments.status).toBe(200);
      const attackerAssignments = Array.isArray(listedAssignments.json?.assignments)
        ? listedAssignments.json?.assignments
        : [];
      expect(attackerAssignments.length).toBe(0);

      const patched = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}`,
        {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: 'attacker rename' }),
        },
      );
      expect(patched.status).toBe(404);
      expect(patched.json?.code).toBe('policy_not_found');

      const published = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
        { method: 'POST' },
      );
      expect(published.status).toBe(404);
      expect(published.json?.code).toBe('policy_not_found');

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

      const deletedAssignment = await fetchJson(
        `${attackerServer.baseUrl}/console/policies/assignments/${encodeURIComponent(ownerAssignmentId)}`,
        { method: 'DELETE' },
      );
      expect(deletedAssignment.status).toBe(404);
      expect(deletedAssignment.json?.code).toBe('assignment_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare policy routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerPolicyId = `${ownerOrgId}:managed-policy`;
    let ownerAssignmentId = '';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-policy-user-cf'),
      policies: policies!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/policies',
      body: {
        id: ownerPolicyId,
        name: 'Owner Managed Policy CF',
      },
    });
    expect(created.status).toBe(201);

    const ownerPublished = await callCf(ownerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
    });
    expect(ownerPublished.status).toBe(200);

    const ownerAssignment = await callCf(ownerHandler, {
      method: 'PUT',
      path: '/console/policies/assignments',
      body: {
        scopeType: 'ORG',
        scopeId: ownerOrgId,
        policyId: ownerPolicyId,
      },
    });
    expect(ownerAssignment.status).toBe(200);
    ownerAssignmentId = String(getPath(ownerAssignment.json, 'assignment', 'id') || '');
    expect(ownerAssignmentId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-policy-user-cf'),
      policies: policies!,
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

    const listedAssignments = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/policies/assignments?scopeType=ORG&scopeId=${encodeURIComponent(ownerOrgId)}`,
    });
    expect(listedAssignments.status).toBe(200);
    const attackerAssignments = Array.isArray(listedAssignments.json?.assignments)
      ? listedAssignments.json?.assignments
      : [];
    expect(attackerAssignments.length).toBe(0);

    const patched = await callCf(attackerHandler, {
      method: 'PATCH',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}`,
      body: {
        name: 'attacker rename cf',
      },
    });
    expect(patched.status).toBe(404);
    expect(patched.json?.code).toBe('policy_not_found');

    const published = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/publish`,
    });
    expect(published.status).toBe(404);
    expect(published.json?.code).toBe('policy_not_found');

    const simulated = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/policies/${encodeURIComponent(ownerPolicyId)}/simulate`,
      body: {
        action: 'transfer',
      },
    });
    expect(simulated.status).toBe(404);
    expect(simulated.json?.code).toBe('policy_not_found');

    const deletedAssignment = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/policies/assignments/${encodeURIComponent(ownerAssignmentId)}`,
    });
    expect(deletedAssignment.status).toBe(404);
    expect(deletedAssignment.json?.code).toBe('assignment_not_found');
  });
});

test.describe('console router (postgres api keys)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:api-keys:postgres');
  const authOrgId = 'org-router-postgres-api-keys';
  let apiKeys: ConsoleApiKeyService | null = null;
  let orgProjectEnv: ConsoleOrgProjectEnvService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    orgProjectEnv = await createPostgresConsoleOrgProjectEnvService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
    apiKeys = await createPostgresConsoleApiKeyService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await pool.query('DELETE FROM console_api_keys WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_environments WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_projects WHERE namespace = $1', [namespace]);
    await pool.query('DELETE FROM console_organizations WHERE namespace = $1', [namespace]);
  });

  test('express API key routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-api-key-user'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let keyId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'owner-postgres-api-key',
          environmentId: 'default-project:prod',
          kind: 'secret_key',
          scopes: ['wallets:read', 'billing:read'],
          ipAllowlist: ['203.0.113.20/32'],
        }),
      });
      expect(created.status).toBe(201);
      keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      expect(keyId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-api-key-user'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/api-keys`, {
        method: 'GET',
      });
      expect(list.status).toBe(200);
      const attackerKeys = Array.isArray(list.json?.apiKeys) ? list.json?.apiKeys : [];
      expect(attackerKeys.some((entry: any) => String(entry?.id || '') === keyId)).toBe(false);

      const rotate = await fetchJson(
        `${attackerServer.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: 'attacker rotate attempt' }),
        },
      );
      expect(rotate.status).toBe(404);
      expect(rotate.json?.code).toBe('api_key_not_found');

      const deleted = await fetchJson(
        `${attackerServer.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(404);
      expect(deleted.json?.code).toBe('api_key_not_found');

      const purged = await fetchJson(
        `${attackerServer.baseUrl}/console/api-keys/${encodeURIComponent(keyId)}/purge`,
        { method: 'DELETE' },
      );
      expect(purged.status).toBe(404);
      expect(purged.json?.code).toBe('api_key_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare API key routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-api-key-user-cf'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'owner-postgres-api-key-cf',
        environmentId: 'default-project:prod',
        kind: 'secret_key',
        scopes: ['wallets:read'],
        ipAllowlist: ['198.51.100.25/32'],
      },
    });
    expect(created.status).toBe(201);
    const keyId = String(getPath(created.json, 'apiKey', 'id') || '');
    expect(keyId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-api-key-user-cf'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const list = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/api-keys',
    });
    expect(list.status).toBe(200);
    const attackerKeys = Array.isArray(list.json?.apiKeys) ? list.json?.apiKeys : [];
    expect(attackerKeys.some((entry: any) => String(entry?.id || '') === keyId)).toBe(false);

    const rotate = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/rotate`,
      body: {
        reason: 'attacker rotate attempt',
      },
    });
    expect(rotate.status).toBe(404);
    expect(rotate.json?.code).toBe('api_key_not_found');

    const deleted = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}`,
    });
    expect(deleted.status).toBe(404);
    expect(deleted.json?.code).toBe('api_key_not_found');

    const purged = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/api-keys/${encodeURIComponent(keyId)}/purge`,
    });
    expect(purged.status).toBe(404);
    expect(purged.json?.code).toBe('api_key_not_found');
  });

  test('postgres API key rows persist key_prefix for indexed lookup', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const orgId = `${authOrgId}:prefix`;
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], orgId, 'owner-api-key-prefix-user'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const server = await startExpressRouter(router);
    let keyId = '';
    try {
      const created = await fetchJson(`${server.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'prefix-check-key',
          environmentId: 'default-project:prod',
          kind: 'secret_key',
          scopes: ['accounts.create'],
        }),
      });
      expect(created.status).toBe(201);
      keyId = String(getPath(created.json, 'apiKey', 'id') || '');
      expect(keyId).toBeTruthy();
    } finally {
      await server.close();
    }

    const pool = await getPostgresPool(postgresUrl);
    const row = await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
      const out = await q.query(
        `SELECT key_prefix
           FROM console_api_keys
          WHERE namespace = $1
            AND org_id = $2
            AND id = $3`,
        [namespace, orgId, keyId],
      );
      return (out.rows[0] as Record<string, unknown>) || null;
    });
    const keyPrefix = String((row || {}).key_prefix || '');
    expect(keyPrefix.length).toBeGreaterThan(12);
    expect(keyPrefix.startsWith('tsk_v1_')).toBe(true);
  });

  test('express export governance route enforces org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-export`;
    const attackerOrgId = `${authOrgId}:attacker-export`;
    const ownerEnvironmentId = 'default-project:prod';

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-export-user'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'owner-export-governance-key',
          environmentId: ownerEnvironmentId,
          kind: 'secret_key',
          scopes: ['wallets:read', 'keys:export'],
        }),
      });
      expect(created.status).toBe(201);

      const ownerGovernance = await fetchJson(
        `${ownerServer.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(ownerGovernance.status).toBe(200);
      expect(
        Number(
          getPath(
            ownerGovernance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-export-user'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerGovernance = await fetchJson(
        `${attackerServer.baseUrl}/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
        { method: 'GET' },
      );
      expect(attackerGovernance.status).toBe(200);
      expect(
        Number(
          getPath(
            attackerGovernance.json,
            'governance',
            'totals',
            'selectedEnvironmentExportScopedKeyCount',
          ) || 0,
        ),
      ).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare export governance route enforces org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-export-cf`;
    const attackerOrgId = `${authOrgId}:attacker-export-cf`;
    const ownerEnvironmentId = 'default-project:prod';

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-export-user-cf'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/api-keys',
      body: {
        name: 'owner-export-governance-key-cf',
        environmentId: ownerEnvironmentId,
        kind: 'secret_key',
        scopes: ['wallets:read', 'keys:export'],
      },
    });
    expect(created.status).toBe(201);

    const ownerGovernance = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(ownerGovernance.status).toBe(200);
    expect(
      Number(
        getPath(
          ownerGovernance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
    ).toBeGreaterThanOrEqual(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-export-user-cf'),
      apiKeys: apiKeys!,
      orgProjectEnv: orgProjectEnv!,
    });
    const attackerGovernance = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/export/governance?environmentId=${encodeURIComponent(ownerEnvironmentId)}`,
    });
    expect(attackerGovernance.status).toBe(200);
    expect(
      Number(
        getPath(
          attackerGovernance.json,
          'governance',
          'totals',
          'selectedEnvironmentExportScopedKeyCount',
        ) || 0,
      ),
    ).toBe(0);
  });
});

test.describe('console router (postgres audit)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:audit:postgres');
  const authOrgId = 'org-router-postgres-audit';
  let audit: ConsoleAuditService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    audit = await createPostgresConsoleAuditService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    const cleanupOrgIds = [
      `${authOrgId}:owner`,
      `${authOrgId}:attacker`,
      `${authOrgId}:owner-cf`,
      `${authOrgId}:attacker-cf`,
    ];
    for (const orgId of cleanupOrgIds) {
      await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
        await q.query('DELETE FROM console_audit_evidence WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_audit_events WHERE namespace = $1', [namespace]);
      });
    }
  });

  test('express audit routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;
    const ownerActorUserId = 'owner-audit-user';
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: ownerActorUserId,
      roles: ['admin'],
    };

    const ownerEvent = await audit!.appendEvent(ownerCtx, {
      id: `evt_owner_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
      category: 'POLICY',
      action: 'policy.publish',
      outcome: 'SUCCESS',
      summary: 'Owner-only audit event',
      metadata: { path: 'owner-only' },
    });
    const ownerEvidence = await audit!.appendEvidence(ownerCtx, {
      id: `evd_owner_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
      domain: 'POLICY',
      title: 'Owner-only policy evidence',
      summary: 'Owner evidence record',
      eventIds: [ownerEvent.id],
      references: [
        {
          kind: 'APPROVAL',
          referenceId: 'apr_owner_policy_1',
          label: 'Owner policy approval',
        },
      ],
    });

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, ownerActorUserId),
      audit: audit!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    try {
      const ownerEvents = await fetchJson(
        `${ownerServer.baseUrl}/console/audit/events?category=POLICY&actorUserId=${encodeURIComponent(ownerActorUserId)}&q=${encodeURIComponent('owner-only')}&limit=20`,
        { method: 'GET' },
      );
      expect(ownerEvents.status).toBe(200);
      const ownerRows = Array.isArray(ownerEvents.json?.events) ? ownerEvents.json?.events : [];
      expect(ownerRows.some((entry: any) => String(entry?.id || '') === ownerEvent.id)).toBe(true);

      const ownerEvidenceRows = await fetchJson(
        `${ownerServer.baseUrl}/console/audit/evidence?domain=POLICY&limit=20`,
        { method: 'GET' },
      );
      expect(ownerEvidenceRows.status).toBe(200);
      const evidenceRows = Array.isArray(ownerEvidenceRows.json?.evidence)
        ? ownerEvidenceRows.json?.evidence
        : [];
      expect(evidenceRows.some((entry: any) => String(entry?.id || '') === ownerEvidence.id)).toBe(
        true,
      );
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-audit-user'),
      audit: audit!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerEvents = await fetchJson(
        `${attackerServer.baseUrl}/console/audit/events?category=POLICY&actorUserId=${encodeURIComponent(ownerActorUserId)}&q=${encodeURIComponent('owner-only')}&limit=20`,
        { method: 'GET' },
      );
      expect(attackerEvents.status).toBe(200);
      const attackerRows = Array.isArray(attackerEvents.json?.events)
        ? attackerEvents.json?.events
        : [];
      expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerEvent.id)).toBe(
        false,
      );

      const attackerEvidence = await fetchJson(
        `${attackerServer.baseUrl}/console/audit/evidence?domain=POLICY&limit=20`,
        { method: 'GET' },
      );
      expect(attackerEvidence.status).toBe(200);
      const attackerEvidenceRows = Array.isArray(attackerEvidence.json?.evidence)
        ? attackerEvidence.json?.evidence
        : [];
      expect(
        attackerEvidenceRows.some((entry: any) => String(entry?.id || '') === ownerEvidence.id),
      ).toBe(false);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare audit routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;
    const ownerActorUserId = 'owner-audit-user-cf';
    const ownerCtx = {
      orgId: ownerOrgId,
      actorUserId: ownerActorUserId,
      roles: ['admin'],
    };

    const ownerEvent = await audit!.appendEvent(ownerCtx, {
      id: `evt_owner_cf_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
      category: 'POLICY',
      action: 'policy.publish',
      outcome: 'SUCCESS',
      summary: 'Owner-only audit event (cloudflare)',
      metadata: { path: 'owner-only-cf' },
    });
    const ownerEvidence = await audit!.appendEvidence(ownerCtx, {
      id: `evd_owner_cf_${Date.now().toString(36)}_${Math.random().toString(16).slice(2, 8)}`,
      domain: 'POLICY',
      title: 'Owner-only policy evidence (cloudflare)',
      summary: 'Owner evidence record (cloudflare)',
      eventIds: [ownerEvent.id],
      references: [
        {
          kind: 'APPROVAL',
          referenceId: 'apr_owner_policy_cf_1',
          label: 'Owner policy approval cloudflare',
        },
      ],
    });

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, ownerActorUserId),
      audit: audit!,
    });
    const ownerEvents = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/audit/events?category=POLICY&actorUserId=${encodeURIComponent(ownerActorUserId)}&q=${encodeURIComponent('owner-only-cf')}&limit=20`,
    });
    expect(ownerEvents.status).toBe(200);
    const ownerRows = Array.isArray(ownerEvents.json?.events) ? ownerEvents.json?.events : [];
    expect(ownerRows.some((entry: any) => String(entry?.id || '') === ownerEvent.id)).toBe(true);

    const ownerEvidenceRowsResponse = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/audit/evidence?domain=POLICY&limit=20',
    });
    expect(ownerEvidenceRowsResponse.status).toBe(200);
    const ownerEvidenceRows = Array.isArray(ownerEvidenceRowsResponse.json?.evidence)
      ? ownerEvidenceRowsResponse.json?.evidence
      : [];
    expect(
      ownerEvidenceRows.some((entry: any) => String(entry?.id || '') === ownerEvidence.id),
    ).toBe(true);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-audit-user-cf'),
      audit: audit!,
    });
    const attackerEvents = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/audit/events?category=POLICY&actorUserId=${encodeURIComponent(ownerActorUserId)}&q=${encodeURIComponent('owner-only-cf')}&limit=20`,
    });
    expect(attackerEvents.status).toBe(200);
    const attackerRows = Array.isArray(attackerEvents.json?.events)
      ? attackerEvents.json?.events
      : [];
    expect(attackerRows.some((entry: any) => String(entry?.id || '') === ownerEvent.id)).toBe(
      false,
    );

    const attackerEvidence = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/audit/evidence?domain=POLICY&limit=20',
    });
    expect(attackerEvidence.status).toBe(200);
    const attackerEvidenceRows = Array.isArray(attackerEvidence.json?.evidence)
      ? attackerEvidence.json?.evidence
      : [];
    expect(
      attackerEvidenceRows.some((entry: any) => String(entry?.id || '') === ownerEvidence.id),
    ).toBe(false);
  });
});

test.describe('console router (postgres webhooks)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:webhooks:postgres');
  const authOrgId = 'org-router-postgres-webhooks';
  let webhooks: ConsoleWebhookService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    webhooks = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    const cleanupOrgIds = [
      authOrgId,
      `${authOrgId}:owner`,
      `${authOrgId}:attacker`,
      `${authOrgId}:owner-cf`,
      `${authOrgId}:attacker-cf`,
    ];
    for (const orgId of cleanupOrgIds) {
      await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
        await q.query('DELETE FROM console_webhook_attempts WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_dead_letters WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_deliveries WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_webhook_endpoints WHERE namespace = $1', [namespace]);
      });
    }
  });

  test('express attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const router = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const srv = await startExpressRouter(router);
    try {
      const created = await fetchJson(`${srv.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-bad-attempt-cursor-express',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();

      const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
      const attempts = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
        {
          method: 'GET',
        },
      );
      expect(attempts.status).toBe(400);
      expect(attempts.json?.code).toBe('invalid_query');

      const oversizedSortCursor = '9007199254740992:attempt_1';
      const oversizedSortKey = await fetchJson(
        `${srv.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
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

  test('cloudflare attempts list rejects non-numeric attempt cursor id', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const handler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], authOrgId, 'ops-router-postgres'),
      webhooks: webhooks!,
    });
    const created = await callCf(handler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-bad-attempt-cursor-cloudflare',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const cursor = `${Date.parse('2026-01-03T00:00:00.000Z')}:non_numeric_attempt_id`;
    const attempts = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(cursor)}`,
    });
    expect(attempts.status).toBe(400);
    expect(attempts.json?.code).toBe('invalid_query');

    const oversizedSortCursor = '9007199254740992:attempt_1';
    const oversizedSortKey = await callCf(handler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/attempts?cursor=${encodeURIComponent(oversizedSortCursor)}`,
    });
    expect(oversizedSortKey.status).toBe(400);
    expect(oversizedSortKey.json?.code).toBe('invalid_query');
  });

  test('express webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user'),
      webhooks: webhooks!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let endpointId = '';
    try {
      const created = await fetchJson(`${ownerServer.baseUrl}/console/webhooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com/postgres-router-org-isolation-express-owner',
          eventCategories: ['billing'],
        }),
      });
      expect(created.status).toBe(201);
      endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
      expect(endpointId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user'),
      webhooks: webhooks!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/webhooks`, { method: 'GET' });
      expect(list.status).toBe(200);
      const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
      expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(
        false,
      );

      const deliveries = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
        { method: 'GET' },
      );
      expect(deliveries.status).toBe(404);
      expect(deliveries.json?.code).toBe('webhook_not_found');

      const replay = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({}),
        },
      );
      expect(replay.status).toBe(404);
      expect(replay.json?.code).toBe('webhook_not_found');

      const deleted = await fetchJson(
        `${attackerServer.baseUrl}/console/webhooks/${encodeURIComponent(endpointId)}`,
        { method: 'DELETE' },
      );
      expect(deleted.status).toBe(404);
      expect(deleted.json?.code).toBe('webhook_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare webhook routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-user-cf'),
      webhooks: webhooks!,
    });
    const created = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/webhooks',
      body: {
        url: 'https://example.com/postgres-router-org-isolation-cloudflare-owner',
        eventCategories: ['billing'],
      },
    });
    expect(created.status).toBe(201);
    const endpointId = String(getPath(created.json, 'endpoint', 'id') || '');
    expect(endpointId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-user-cf'),
      webhooks: webhooks!,
    });
    const list = await callCf(attackerHandler, { method: 'GET', path: '/console/webhooks' });
    expect(list.status).toBe(200);
    const attackerEndpoints = Array.isArray(list.json?.endpoints) ? list.json?.endpoints : [];
    expect(attackerEndpoints.some((entry: any) => String(entry?.id || '') === endpointId)).toBe(
      false,
    );

    const deliveries = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/deliveries`,
    });
    expect(deliveries.status).toBe(404);
    expect(deliveries.json?.code).toBe('webhook_not_found');

    const replay = await callCf(attackerHandler, {
      method: 'POST',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}/replay`,
      body: {},
    });
    expect(replay.status).toBe(404);
    expect(replay.json?.code).toBe('webhook_not_found');

    const deleted = await callCf(attackerHandler, {
      method: 'DELETE',
      path: `/console/webhooks/${encodeURIComponent(endpointId)}`,
    });
    expect(deleted.status).toBe(404);
    expect(deleted.json?.code).toBe('webhook_not_found');
  });
});

test.describe('console router (postgres billing)', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-router:billing:postgres');
  const authOrgId = 'org-router-postgres-billing';
  let billing: ConsoleBillingService | null = null;

  test.beforeAll(async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    billing = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });
  });

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    for (const orgId of [`${authOrgId}:owner`, `${authOrgId}:attacker`]) {
      await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
        await q.query('DELETE FROM console_stripe_webhook_events WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_payment_methods WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_invoice_line_items WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_usage_rollups_monthly WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_usage_meter_events WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_credit_purchases WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_billing_ledger_postings WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_billing_ledger_entries WHERE namespace = $1', [
          namespace,
        ]);
        await q.query('DELETE FROM console_invoices WHERE namespace = $1', [namespace]);
        await q.query('DELETE FROM console_billing_accounts WHERE namespace = $1', [namespace]);
      });
      await pool.query('DELETE FROM console_billing_ledger_accounts WHERE namespace = $1', [
        namespace,
      ]);
    }
  });

  test('express billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner`;
    const attackerOrgId = `${authOrgId}:attacker`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let ownerInvoiceId = '';
    try {
      const invoices = await fetchJson(`${ownerServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(invoices.status).toBe(200);
      ownerInvoiceId = String(getPath(invoices.json, 'invoices', 0, 'id') || '');
      expect(ownerInvoiceId).toBeTruthy();
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const list = await fetchJson(`${attackerServer.baseUrl}/console/billing/invoices`, {
        method: 'GET',
      });
      expect(list.status).toBe(200);
      const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
      expect(
        attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId),
      ).toBe(false);

      const getInvoice = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
        { method: 'GET' },
      );
      expect(getInvoice.status).toBe(404);
      expect(getInvoice.json?.code).toBe('invoice_not_found');

      const getLineItems = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
        { method: 'GET' },
      );
      expect(getLineItems.status).toBe(404);
      expect(getLineItems.json?.code).toBe('invoice_not_found');

      const getPdf = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/pdf`,
        { method: 'GET' },
      );
      expect(getPdf.status).toBe(404);
      expect(getPdf.json?.code).toBe('invoice_not_found');
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-cf`;
    const attackerOrgId = `${authOrgId}:attacker-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-billing-user-cf'),
      billing: billing!,
    });
    const ownerInvoices = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(ownerInvoices.status).toBe(200);
    const ownerInvoiceId = String(getPath(ownerInvoices.json, 'invoices', 0, 'id') || '');
    expect(ownerInvoiceId).toBeTruthy();

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-billing-user-cf'),
      billing: billing!,
    });
    const list = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/invoices',
    });
    expect(list.status).toBe(200);
    const attackerInvoices = Array.isArray(list.json?.invoices) ? list.json?.invoices : [];
    expect(attackerInvoices.some((entry: any) => String(entry?.id || '') === ownerInvoiceId)).toBe(
      false,
    );

    const getInvoice = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}`,
    });
    expect(getInvoice.status).toBe(404);
    expect(getInvoice.json?.code).toBe('invoice_not_found');

    const getLineItems = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/line-items`,
    });
    expect(getLineItems.status).toBe(404);
    expect(getLineItems.json?.code).toBe('invoice_not_found');

    const getPdf = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/invoices/${encodeURIComponent(ownerInvoiceId)}/pdf`,
    });
    expect(getPdf.status).toBe(404);
    expect(getPdf.json?.code).toBe('invoice_not_found');
  });

  test('express billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage`;
    const attackerOrgId = `${authOrgId}:attacker-usage`;

    const ownerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user'),
      billing: billing!,
    });
    const ownerServer = await startExpressRouter(ownerRouter);
    let monthUtc = '';
    try {
      const event = await fetchJson(`${ownerServer.baseUrl}/console/billing/usage/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          walletId: 'wallet_owner_usage_1',
          action: 'transfer',
          succeeded: true,
          sourceEventId: `owner_usage_evt_${Date.now()}`,
        }),
      });
      expect(event.status).toBe(200);
      monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
      expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

      const ownerOverview = await fetchJson(`${ownerServer.baseUrl}/console/billing/overview`, {
        method: 'GET',
      });
      expect(ownerOverview.status).toBe(200);
      expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

      const ownerUsage = await fetchJson(
        `${ownerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(ownerUsage.status).toBe(200);
      expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);
    } finally {
      await ownerServer.close();
    }

    const attackerRouter = createConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user'),
      billing: billing!,
    });
    const attackerServer = await startExpressRouter(attackerRouter);
    try {
      const attackerOverview = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/overview`,
        {
          method: 'GET',
        },
      );
      expect(attackerOverview.status).toBe(200);
      expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(
        0,
      );

      const attackerUsage = await fetchJson(
        `${attackerServer.baseUrl}/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
        { method: 'GET' },
      );
      expect(attackerUsage.status).toBe(200);
      expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
    } finally {
      await attackerServer.close();
    }
  });

  test('cloudflare billing overview and MAW usage routes enforce org isolation', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');
    const ownerOrgId = `${authOrgId}:owner-usage-cf`;
    const attackerOrgId = `${authOrgId}:attacker-usage-cf`;

    const ownerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], ownerOrgId, 'owner-usage-user-cf'),
      billing: billing!,
    });
    const event = await callCf(ownerHandler, {
      method: 'POST',
      path: '/console/billing/usage/events',
      body: {
        walletId: 'wallet_owner_usage_cf_1',
        action: 'swap',
        succeeded: true,
        sourceEventId: `owner_usage_cf_evt_${Date.now()}`,
      },
    });
    expect(event.status).toBe(200);
    const monthUtc = String(getPath(event.json, 'result', 'monthUtc') || '');
    expect(monthUtc).toMatch(/^\d{4}-\d{2}$/);

    const ownerOverview = await callCf(ownerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(ownerOverview.status).toBe(200);
    expect(Number(getPath(ownerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(1);

    const ownerUsage = await callCf(ownerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(ownerUsage.status).toBe(200);
    expect(Number(getPath(ownerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(1);

    const attackerHandler = createCloudflareConsoleRouter({
      auth: makeConsoleAuthAdapter(['admin'], attackerOrgId, 'attacker-usage-user-cf'),
      billing: billing!,
    });
    const attackerOverview = await callCf(attackerHandler, {
      method: 'GET',
      path: '/console/billing/overview',
    });
    expect(attackerOverview.status).toBe(200);
    expect(Number(getPath(attackerOverview.json, 'overview', 'monthlyActiveWallets') || 0)).toBe(0);

    const attackerUsage = await callCf(attackerHandler, {
      method: 'GET',
      path: `/console/billing/usage/monthly-active-wallets?monthUtc=${encodeURIComponent(monthUtc)}`,
    });
    expect(attackerUsage.status).toBe(200);
    expect(Number(getPath(attackerUsage.json, 'usage', 'monthlyActiveWallets') || 0)).toBe(0);
  });
});
