import type { ConsoleObservabilityLevel, ConsoleObservabilitySource } from './types';

export const CONSOLE_OBSERVABILITY_SOURCES = [
  'WEBHOOK',
  'BILLING',
  'APPROVAL',
  'SYSTEM',
] as const satisfies readonly ConsoleObservabilitySource[];

export const CONSOLE_OBSERVABILITY_SOURCE_SET = new Set<ConsoleObservabilitySource>(
  CONSOLE_OBSERVABILITY_SOURCES,
);

export const CONSOLE_OBSERVABILITY_SOURCES_SQL = CONSOLE_OBSERVABILITY_SOURCES.map(
  (source) => `'${source}'`,
).join(', ');

export interface ConsoleObservabilityEventPolicy {
  source: ConsoleObservabilitySource;
  service: string;
  component: string;
  level: ConsoleObservabilityLevel;
  eventType?: string;
}

export const CONSOLE_OBSERVABILITY_EVENT_POLICIES = {
  webhookDeadLetter: {
    source: 'WEBHOOK',
    service: 'webhooks',
    component: 'delivery_dispatch',
    level: 'ERROR',
    eventType: 'webhook.delivery.dead_letter',
  },
  webhookDeliveryRetryExhausted: {
    source: 'WEBHOOK',
    service: 'webhooks',
    component: 'delivery_dispatch',
    level: 'ERROR',
    eventType: 'webhook.delivery.retry_exhausted',
  },
  webhookEndpointDegraded: {
    source: 'WEBHOOK',
    service: 'webhooks',
    component: 'endpoint_health',
    level: 'WARN',
    eventType: 'webhook.endpoint.degraded',
  },
  billingInvoiceFinalizationFailure: {
    source: 'BILLING',
    service: 'billing',
    component: 'finalization',
    level: 'ERROR',
    eventType: 'billing.invoice_finalization.failed',
  },
  billingPaymentReconcileFailure: {
    source: 'BILLING',
    service: 'billing',
    component: 'checkout_reconcile',
    level: 'ERROR',
    eventType: 'billing.payment_reconcile.failed',
  },
  billingStripeWebhookInvalidSignature: {
    source: 'BILLING',
    service: 'billing',
    component: 'stripe_webhook',
    level: 'ERROR',
    eventType: 'billing.stripe_webhook.invalid_signature',
  },
  billingStripeWebhookProcessingFailure: {
    source: 'BILLING',
    service: 'billing',
    component: 'stripe_webhook',
    level: 'ERROR',
    eventType: 'billing.stripe_webhook.processing.failed',
  },
  billingBalanceLow: {
    source: 'BILLING',
    service: 'billing',
    component: 'sponsorship_prepaid_balance',
    level: 'WARN',
    eventType: 'billing.balance.low_balance',
  },
  billingBalanceBlocked: {
    source: 'BILLING',
    service: 'billing',
    component: 'sponsorship_prepaid_balance',
    level: 'WARN',
    eventType: 'billing.balance.blocked',
  },
  billingBalanceRecovered: {
    source: 'BILLING',
    service: 'billing',
    component: 'sponsorship_prepaid_balance',
    level: 'INFO',
    eventType: 'billing.balance.recovered',
  },
  billingSponsorshipBlocked: {
    source: 'BILLING',
    service: 'billing',
    component: 'sponsorship_prepaid_balance',
    level: 'WARN',
    eventType: 'billing.sponsorship.blocked',
  },
  approvalPublishFailure: {
    source: 'APPROVAL',
    service: 'approvals',
    component: 'policy_publish',
    level: 'ERROR',
    eventType: 'approval.policy_publish.failed',
  },
} as const satisfies Record<string, ConsoleObservabilityEventPolicy>;

export interface ConsoleObservabilityRequestMetricPolicy {
  routeFamily: string;
  service: string;
}

export const CONSOLE_OBSERVABILITY_REQUEST_METRIC_POLICIES = [
  { routeFamily: '/console/approvals/*', service: 'approvals' },
  { routeFamily: '/console/billing/*', service: 'billing' },
  { routeFamily: '/console/webhooks/*', service: 'webhooks' },
  { routeFamily: '/console/policies/*', service: 'policies' },
  { routeFamily: '/console/policy/*', service: 'policy' },
  { routeFamily: '/console/onboarding/*', service: 'onboarding' },
  { routeFamily: '/console/wallets/*', service: 'wallets' },
  { routeFamily: '/console/api-keys/*', service: 'api-keys' },
  { routeFamily: '/console/runtime-snapshots/*', service: 'runtime-snapshots' },
  { routeFamily: '/console/key-exports/*', service: 'key-exports' },
  { routeFamily: '/console/sponsored-calls/*', service: 'sponsored-calls' },
  { routeFamily: '/console/sponsorship-spend-caps/*', service: 'sponsorship-spend-caps' },
  { routeFamily: '/console/isolation/*', service: 'isolation' },
] as const satisfies readonly ConsoleObservabilityRequestMetricPolicy[];

const REQUEST_METRIC_POLICY_BY_ROUTE_FAMILY = new Map<string, ConsoleObservabilityRequestMetricPolicy>(
  CONSOLE_OBSERVABILITY_REQUEST_METRIC_POLICIES.map((policy) => [policy.routeFamily, policy]),
);

export function resolveConsoleObservabilityRequestMetricPolicy(
  routeFamily: string,
): ConsoleObservabilityRequestMetricPolicy | null {
  return REQUEST_METRIC_POLICY_BY_ROUTE_FAMILY.get(routeFamily) || null;
}
