import { expect, test } from '@playwright/test';
import {
  buildBillingFailureObservabilityEvent,
  buildBillingStripeWebhookFailureObservabilityEvent,
  buildWebhookEndpointDegradedObservabilityEvent,
  buildWebhookDeadLetterObservabilityEvent,
  buildWebhookRetryExhaustedObservabilityEvent,
  createPostgresConsoleObservabilityIngestionService,
  createPostgresConsoleObservabilityService,
  redactConsoleObservabilityMetadata,
} from '@server/router/express-adaptor';
import { withConsoleTenantContextTx } from '../../packages/sdk-server-ts/src/console/shared/postgresTenantContext';
import { getPostgresPool } from '../../packages/sdk-server-ts/src/storage/postgres';

function randomNamespace(prefix: string): string {
  return `${prefix}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
}

function parseJsonObject(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) {
    return raw as Record<string, unknown>;
  }
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
        return parsed as Record<string, unknown>;
      }
    } catch {
      // no-op
    }
  }
  return {};
}

test.describe('console observability ingestion scaffolding', () => {
  test('adapter builders emit normalized envelopes', async () => {
    const event = buildWebhookDeadLetterObservabilityEvent({
      orgId: 'org-observability-adapter',
      projectId: 'proj-observability-adapter',
      environmentId: 'env-observability-adapter',
      endpointId: 'wh_ep_1',
      deliveryId: 'del_1',
      webhookEventId: 'evt_1',
      webhookEventType: 'billing.invoice.failed',
      failedAttempts: 3,
      movedToDlqAt: '2026-03-05T10:00:00.000Z',
    });

    expect(event.eventId).toContain('obs_webhook_dead_letter_');
    expect(event.source).toBe('WEBHOOK');
    expect(event.level).toBe('ERROR');
    expect(event.eventType).toBe('webhook.delivery.dead_letter');
    expect(event.orgId).toBe('org-observability-adapter');
    expect(event.projectId).toBe('proj-observability-adapter');
    expect(event.environmentId).toBe('env-observability-adapter');
    expect(Number(event.ingestedAtMs || 0)).toBeGreaterThan(0);
  });

  test('metadata redaction strips sensitive keys', async () => {
    const output = redactConsoleObservabilityMetadata({
      safe: 'ok',
      apiKey: 'secret-key',
      nested: {
        token: 'sensitive',
        keep: 'value',
      },
    });

    const nested = parseJsonObject(output.metadata.nested);
    expect(output.redactionApplied).toBe(true);
    expect(String(output.metadata.apiKey || '')).toBe('[REDACTED]');
    expect(String(nested.token || '')).toBe('[REDACTED]');
    expect(String(output.metadata.safe || '')).toBe('ok');
    expect(String(nested.keep || '')).toBe('value');
  });

  test('billing builders emit operation-specific and webhook-specific event types', async () => {
    const reconcileFailure = buildBillingFailureObservabilityEvent({
      orgId: 'org-observability-billing-builder',
      operation: 'PAYMENT_RECONCILE',
      providerRef: 'cs_obs_builder',
      failureCode: 'checkout_reconcile_failed',
      failureMessage: 'checkout reconcile failed',
    });
    expect(reconcileFailure.eventType).toBe('billing.payment_reconcile.failed');
    expect(reconcileFailure.component).toBe('checkout_reconcile');
    expect(String(reconcileFailure.metadata.providerRef || '')).toBe('cs_obs_builder');

    const webhookFailure = buildBillingStripeWebhookFailureObservabilityEvent({
      orgId: 'org-observability-billing-builder',
      eventType: 'billing.stripe_webhook.invalid_signature',
      stripeEventId: 'evt_obs_builder',
      checkoutSessionId: 'cs_obs_builder',
      failureCode: 'invalid_signature',
      failureMessage: 'invalid stripe webhook secret',
    });
    expect(webhookFailure.eventType).toBe('billing.stripe_webhook.invalid_signature');
    expect(webhookFailure.component).toBe('stripe_webhook');
    expect(String(webhookFailure.metadata.stripeEventId || '')).toBe('evt_obs_builder');

    const retryExhausted = buildWebhookRetryExhaustedObservabilityEvent({
      orgId: 'org-observability-billing-builder',
      endpointId: 'wh_obs_builder',
      deliveryId: 'whd_obs_builder',
      webhookEventId: 'evt_obs_builder',
      webhookEventType: 'billing.invoice.failed',
      failedAttempts: 5,
      maxAttempts: 5,
      exhaustedAt: '2026-03-12T12:00:00.000Z',
    });
    expect(retryExhausted.eventType).toBe('webhook.delivery.retry_exhausted');
    expect(retryExhausted.component).toBe('delivery_dispatch');
    expect(String(retryExhausted.metadata.endpointId || '')).toBe('wh_obs_builder');

    const endpointDegraded = buildWebhookEndpointDegradedObservabilityEvent({
      orgId: 'org-observability-billing-builder',
      endpointId: 'wh_obs_builder',
      unresolvedDeadLetterCount: 3,
      degradationThreshold: 3,
      latestDeliveryId: 'whd_obs_builder',
      latestWebhookEventId: 'evt_obs_builder',
      latestWebhookEventType: 'billing.invoice.failed',
      degradedAt: '2026-03-12T12:05:00.000Z',
    });
    expect(endpointDegraded.eventType).toBe('webhook.endpoint.degraded');
    expect(endpointDegraded.component).toBe('endpoint_health');
    expect(endpointDegraded.level).toBe('WARN');
  });
});

test.describe('console observability postgres ingestion service', () => {
  const postgresUrl = String(process.env.POSTGRES_URL || '').trim();
  const enabled = Boolean(postgresUrl);
  const namespace = randomNamespace('test:console-observability:postgres');
  const orgId = 'org-observability-postgres';

  test.afterAll(async () => {
    if (!enabled) return;
    const pool = await getPostgresPool(postgresUrl);
    await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) => {
      await q.query('DELETE FROM console_observability_events WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_observability_event_dedup WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_observability_ingest_windows WHERE namespace = $1', [namespace]);
      await q.query('DELETE FROM console_observability_request_rollups_minute WHERE namespace = $1', [
        namespace,
      ]);
    });
  });

  test('appendEvent persists redacted payload and enforces idempotent event ids', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const service = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: true,
    });

    const event = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'invoice_finalize_failed',
      failureMessage: 'finalization failed',
      requestId: 'req_obs_ingest_1',
    });
    event.eventId = 'evt_obs_ingest_1';
    event.metadata = {
      ...event.metadata,
      authorization: 'Bearer top-secret',
      safeFlag: 'true',
    };

    const ctx = {
      orgId,
      actorUserId: 'ops-observability',
      roles: ['ops'],
    };

    const first = await service.appendEvent(ctx, event);
    expect(first.accepted).toBe(1);
    expect(first.deduplicated).toBe(0);

    const second = await service.appendEvent(ctx, event);
    expect(second.accepted).toBe(0);
    expect(second.deduplicated).toBe(1);

    const pool = await getPostgresPool(postgresUrl);
    const rows = await withConsoleTenantContextTx(
      pool,
      { namespace, orgId },
      async (q) =>
        q.query(
          `SELECT event_id, metadata, redaction_applied, redaction_version
             FROM console_observability_events
            WHERE namespace = $1 AND org_id = $2 AND event_id = $3`,
          [namespace, orgId, 'evt_obs_ingest_1'],
        ),
    );
    expect(rows.rows.length).toBe(1);

    const row = rows.rows[0] as Record<string, unknown>;
    const metadata = parseJsonObject(row.metadata);
    expect(String(metadata.authorization || '')).toBe('[REDACTED]');
    expect(String(metadata.safeFlag || '')).toBe('true');
    expect(Boolean(row.redaction_applied)).toBe(true);
    expect(Number(row.redaction_version || 0)).toBeGreaterThanOrEqual(1);
  });

  test('appendEvent rejects cross-org events', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const service = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
    });

    const event = buildBillingFailureObservabilityEvent({
      orgId: 'org-observability-other',
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'invoice_finalize_failed',
      failureMessage: 'finalization failed',
    });

    let caught: any;
    try {
      await service.appendEvent(
        {
          orgId,
          actorUserId: 'ops-observability',
          roles: ['ops'],
        },
        event,
      );
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('invalid_body');
  });

  test('appendEvent rejects legacy router.request.completed events', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const service = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
    });

    const event = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'legacy_router_event',
      failureMessage: 'legacy router events should be rejected',
    });
    event.eventType = 'router.request.completed';

    let caught: any;
    try {
      await service.appendEvent(
        {
          orgId,
          actorUserId: 'ops-observability',
          roles: ['ops'],
        },
        event,
      );
    } catch (error: unknown) {
      caught = error;
    }

    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('invalid_body');
    expect(String(caught?.message || '')).toContain('no longer accepted');
  });

  test('postgres observability service lists events with deterministic cursor ordering', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const ingestService = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date('2023-11-15T00:00:00.000Z'),
    });
    const queryService = await createPostgresConsoleObservabilityService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
    });

    const seedEvents = [
      { eventId: 'evt_obs_cursor_c', ingestedAtMs: 1_700_000_000_000, failureCode: 'failed_c' },
      { eventId: 'evt_obs_cursor_b', ingestedAtMs: 1_700_000_000_000, failureCode: 'failed_b' },
      { eventId: 'evt_obs_cursor_a', ingestedAtMs: 1_700_000_000_000, failureCode: 'failed_a' },
      { eventId: 'evt_obs_cursor_older', ingestedAtMs: 1_699_999_999_000, failureCode: 'failed_old' },
    ];
    for (const seed of seedEvents) {
      const event = buildBillingFailureObservabilityEvent({
        orgId,
        operation: 'INVOICE_FINALIZATION',
        failureCode: seed.failureCode,
        failureMessage: `billing failed ${seed.failureCode}`,
      });
      event.eventId = seed.eventId;
      event.ingestedAtMs = seed.ingestedAtMs;
      event.timestamp = new Date(seed.ingestedAtMs).toISOString();
      await ingestService.appendEvent(
        {
          orgId,
          actorUserId: 'ops-observability',
          roles: ['ops'],
        },
        event,
      );
    }

    const firstPage = await queryService.listEvents(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        limit: 2,
        from: '2023-11-14T00:00:00.000Z',
        to: '2023-11-20T00:00:00.000Z',
      },
    );
    expect(firstPage.status.state).toBe('ok');
    expect(firstPage.events.map((entry) => entry.id)).toEqual([
      'evt_obs_cursor_c',
      'evt_obs_cursor_b',
    ]);
    expect(firstPage.totalPages).toBe(2);
    expect(String(firstPage.nextCursor || '')).toContain(':');

    const secondPage = await queryService.listEvents(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        limit: 2,
        cursor: firstPage.nextCursor,
        from: '2023-11-14T00:00:00.000Z',
        to: '2023-11-20T00:00:00.000Z',
      },
    );
    expect(secondPage.events.map((entry) => entry.id)).toEqual([
      'evt_obs_cursor_a',
      'evt_obs_cursor_older',
    ]);
    expect(secondPage.totalPages).toBe(2);
    expect(secondPage.nextCursor).toBeUndefined();
  });

  test('postgres observability service rejects invalid cursor shape', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const queryService = await createPostgresConsoleObservabilityService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
    });

    let caught: any;
    try {
      await queryService.listEvents(
        {
          orgId,
          actorUserId: 'ops-observability',
          roles: ['ops'],
        },
        { limit: 10, cursor: 'bad_cursor' },
      );
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('invalid_query');
  });

  test('postgres observability service filters events by exact component', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const ingestService = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date('2026-03-05T12:00:00.000Z'),
    });
    const queryService = await createPostgresConsoleObservabilityService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date('2026-03-05T12:00:00.000Z'),
    });

    const finalizationEvent = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'finalization_failed',
      failureMessage: 'invoice finalization failed',
    });
    finalizationEvent.eventId = 'evt_obs_component_finalization';
    finalizationEvent.ingestedAtMs = Date.parse('2026-03-05T11:00:00.000Z');
    finalizationEvent.timestamp = new Date(finalizationEvent.ingestedAtMs).toISOString();

    const reconcileEvent = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'PAYMENT_RECONCILE',
      failureCode: 'reconcile_failed',
      failureMessage: 'checkout reconcile failed',
    });
    reconcileEvent.eventId = 'evt_obs_component_reconcile';
    reconcileEvent.ingestedAtMs = Date.parse('2026-03-05T11:05:00.000Z');
    reconcileEvent.timestamp = new Date(reconcileEvent.ingestedAtMs).toISOString();

    await ingestService.appendEvent(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      finalizationEvent,
    );
    await ingestService.appendEvent(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      reconcileEvent,
    );

    const page = await queryService.listEvents(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        component: 'checkout_reconcile',
        from: '2026-03-05T00:00:00.000Z',
        to: '2026-03-06T00:00:00.000Z',
        limit: 10,
      },
    );

    expect(page.status.state).toBe('ok');
    expect(page.events.map((entry) => entry.id)).toEqual(['evt_obs_component_reconcile']);
    expect(page.events[0]?.component).toBe('checkout_reconcile');
  });

  test('postgres observability events query applies strict default bounded window', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const fixedNowMs = Date.parse('2026-03-05T12:00:00.000Z');
    const ingestService = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNowMs),
    });
    const queryService = await createPostgresConsoleObservabilityService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNowMs),
      queryMaxWindowMs: 1000 * 60 * 60 * 24 * 7,
    });

    const oldEvent = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'old_outside_window',
      failureMessage: 'outside default window',
    });
    oldEvent.eventId = 'evt_obs_default_window_old';
    oldEvent.ingestedAtMs = fixedNowMs - 1000 * 60 * 60 * 24 * 10;
    oldEvent.timestamp = new Date(oldEvent.ingestedAtMs).toISOString();

    const inWindowEvent = buildBillingFailureObservabilityEvent({
      orgId,
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'in_default_window',
      failureMessage: 'inside default window',
    });
    inWindowEvent.eventId = 'evt_obs_default_window_in';
    inWindowEvent.ingestedAtMs = fixedNowMs - 1000 * 60 * 60 * 24;
    inWindowEvent.timestamp = new Date(inWindowEvent.ingestedAtMs).toISOString();

    await ingestService.appendEvent(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      oldEvent,
    );
    await ingestService.appendEvent(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      inWindowEvent,
    );

    const page = await queryService.listEvents(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      { limit: 20 },
    );

    expect(page.events.some((entry) => entry.id === 'evt_obs_default_window_in')).toBe(true);
    expect(page.events.some((entry) => entry.id === 'evt_obs_default_window_old')).toBe(false);
  });

  test('postgres observability ingestion applies ingest backpressure limits', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const service = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      maxBatchSize: 2,
      maxEventsPerMinute: 2,
      now: () => new Date('2026-03-05T13:00:00.000Z'),
    });

    const mkEvent = (eventId: string) => {
      const event = buildBillingFailureObservabilityEvent({
        orgId,
        operation: 'INVOICE_FINALIZATION',
        failureCode: `bp_${eventId}`,
        failureMessage: 'backpressure validation',
      });
      event.eventId = eventId;
      return event;
    };

    await service.appendEvents(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      [mkEvent('evt_obs_bp_1'), mkEvent('evt_obs_bp_2')],
    );

    let caught: any;
    try {
      await service.appendEvent(
        {
          orgId,
          actorUserId: 'ops-observability',
          roles: ['ops'],
        },
        mkEvent('evt_obs_bp_3'),
      );
    } catch (error: unknown) {
      caught = error;
    }
    expect(caught).toBeTruthy();
    expect(String(caught?.code || '')).toBe('rate_limited');
  });

  test('postgres observability ingestion captures only allowlisted route families', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const fixedNowMs = Date.parse('2026-03-05T14:00:00.000Z');
    const projectId = 'proj-allowlist';
    const environmentId = 'env-allowlist';
    const service = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNowMs),
    });
    expect(typeof service.observeRequestMetric).toBe('function');

    const ctx = {
      orgId,
      actorUserId: 'ops-observability',
      roles: ['ops'],
    };

    await service.observeRequestMetric?.(ctx, {
      orgId,
      projectId,
      environmentId,
      route: '/console/account/profile',
      method: 'POST',
      statusCode: 500,
      latencyMs: 31,
      timestamp: new Date(fixedNowMs).toISOString(),
    });

    await service.observeRequestMetric?.(ctx, {
      orgId,
      projectId,
      environmentId,
      route: '/console/policies/pol_allow/publish',
      method: 'POST',
      statusCode: 500,
      latencyMs: 41,
      timestamp: new Date(fixedNowMs + 5_000).toISOString(),
    });

    const pool = await getPostgresPool(postgresUrl);
    const rows = await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) =>
      q.query(
        `SELECT route_family, COUNT(*)::int AS count
           FROM console_observability_request_rollups_minute
          WHERE namespace = $1
            AND org_id = $2
            AND project_id = $3
            AND environment_id = $4
            AND route_family IN ($5, $6)
          GROUP BY route_family`,
        [namespace, orgId, projectId, environmentId, '/console/account/*', '/console/policies/*'],
      ),
    );
    const byRouteFamily = new Map<string, number>();
    for (const row of rows.rows as Array<Record<string, unknown>>) {
      byRouteFamily.set(String(row.route_family || ''), Number(row.count || 0));
    }
    expect(byRouteFamily.get('/console/account/*') || 0).toBe(0);
    expect(byRouteFamily.get('/console/policies/*') || 0).toBe(1);
  });

  test('postgres observability service computes summary, timeseries, and services aggregates', async () => {
    test.skip(!enabled, 'POSTGRES_URL not set');

    const fixedNowMs = Date.parse('2026-03-05T12:00:00.000Z');
    const fromIso = new Date(fixedNowMs - 1000 * 60 * 10).toISOString();
    const toIso = new Date(fixedNowMs).toISOString();

    const ingestService = await createPostgresConsoleObservabilityIngestionService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNowMs),
    });
    const queryService = await createPostgresConsoleObservabilityService({
      postgresUrl,
      namespace,
      logger: console as any,
      ensureSchema: false,
      now: () => new Date(fixedNowMs),
      queryMaxWindowMs: 1000 * 60 * 60 * 24 * 7,
    });

    const billingErr = buildBillingFailureObservabilityEvent({
      orgId,
      projectId: 'proj-agg',
      environmentId: 'env-agg',
      operation: 'INVOICE_FINALIZATION',
      failureCode: 'finalization_failed',
      failureMessage: 'invoice finalization failed',
      timestamp: new Date(fixedNowMs - 1000 * 30).toISOString(),
    });
    billingErr.eventId = 'evt_obs_agg_billing_err';
    billingErr.ingestedAtMs = fixedNowMs - 1000 * 30;

    const deadLetter = buildWebhookDeadLetterObservabilityEvent({
      orgId,
      projectId: 'proj-agg',
      environmentId: 'env-agg',
      endpointId: 'wh_ep_agg',
      deliveryId: 'del_agg',
      webhookEventId: 'evt_agg',
      webhookEventType: 'billing.invoice.failed',
      failedAttempts: 3,
      movedToDlqAt: new Date(fixedNowMs - 1000 * 45).toISOString(),
    });
    deadLetter.eventId = 'evt_obs_agg_dead_letter';
    deadLetter.ingestedAtMs = fixedNowMs - 1000 * 45;
    deadLetter.timestamp = new Date(fixedNowMs - 1000 * 45).toISOString();

    const ingestCtx = {
      orgId,
      actorUserId: 'ops-observability',
      roles: ['ops'],
    };
    expect(typeof ingestService.observeRequestMetric).toBe('function');
    await ingestService.observeRequestMetric?.(ingestCtx, {
      orgId,
      projectId: 'proj-agg',
      environmentId: 'env-agg',
      route: '/console/policies/pol_agg/publish',
      method: 'POST',
      statusCode: 200,
      latencyMs: 40,
      timestamp: new Date(fixedNowMs - 1000 * 60 * 2).toISOString(),
    });
    await ingestService.observeRequestMetric?.(ingestCtx, {
      orgId,
      projectId: 'proj-agg',
      environmentId: 'env-agg',
      route: '/console/policies/pol_agg/publish',
      method: 'POST',
      statusCode: 500,
      latencyMs: 140,
      timestamp: new Date(fixedNowMs - 1000 * 60).toISOString(),
    });
    await ingestService.appendEvents(ingestCtx, [billingErr, deadLetter]);

    const summary = await queryService.getSummary(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        from: fromIso,
        to: toIso,
        projectId: 'proj-agg',
        environmentId: 'env-agg',
      },
    );
    expect(summary.status.state).toBe('ok');
    expect(summary.errorRate).toBeGreaterThan(0.49);
    expect(summary.errorRate).toBeLessThan(0.51);
    expect(summary.deadLetterCount).toBe(1);
    expect(summary.failingServices).toBeGreaterThanOrEqual(3);
    expect(summary.p95LatencyMs).toBeGreaterThan(100);

    const timeseries = await queryService.getTimeseries(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        from: fromIso,
        to: toIso,
        bucketMinutes: 5,
        projectId: 'proj-agg',
        environmentId: 'env-agg',
        service: 'policies',
      },
    );
    expect(timeseries.status.state).toBe('ok');
    expect(timeseries.buckets.length).toBeGreaterThan(0);
    const requestCount = timeseries.buckets.reduce((sum, row) => sum + row.requestCount, 0);
    const errorCount = timeseries.buckets.reduce((sum, row) => sum + row.errorCount, 0);
    expect(requestCount).toBe(2);
    expect(errorCount).toBe(1);

    const services = await queryService.listServices(
      {
        orgId,
        actorUserId: 'ops-observability',
        roles: ['ops'],
      },
      {
        from: fromIso,
        to: toIso,
        projectId: 'proj-agg',
        environmentId: 'env-agg',
        limit: 10,
      },
    );
    expect(services.status.state).toBe('ok');
    const byService = new Map(services.services.map((entry) => [entry.service, entry]));
    expect(byService.get('policies')?.recentFailureCount).toBe(1);
    expect(byService.get('billing')?.recentFailureCount).toBe(1);
    expect(byService.get('webhooks')?.recentFailureCount).toBe(1);
  });
});
