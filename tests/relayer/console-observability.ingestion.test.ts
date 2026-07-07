import { expect, test } from '@playwright/test';
import {
  buildBillingFailureObservabilityEvent,
  buildBillingStripeWebhookFailureObservabilityEvent,
  buildWebhookEndpointDegradedObservabilityEvent,
  buildWebhookDeadLetterObservabilityEvent,
  buildWebhookRetryExhaustedObservabilityEvent,
  redactConsoleObservabilityMetadata,
} from '@seams-internal/console-server/router/express-adaptor';

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
      // Keep malformed metadata as an empty object for assertions.
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
