import type { BillingCreditPurchase, BillingInvoice } from './types';

export type BillingStripePostProcessingEffect = 'audit' | 'customer_webhook';

export interface BillingStripeCreditPurchaseSettledPayload {
  readonly kind: 'credit_purchase_settled_v1';
  readonly audit: {
    readonly id: string;
    readonly summary: string;
    readonly metadata: Record<string, unknown>;
  };
  readonly customerWebhook: {
    readonly eventId: string;
    readonly eventType: 'billing.credit_purchase.settled';
    readonly payload: {
      readonly purchaseId: string;
      readonly creditPackId: string;
      readonly amountMinor: number;
      readonly receiptId: string | null;
      readonly source: 'stripe_webhook';
    };
  };
}

export interface BillingStripePostProcessingOutboxItem {
  readonly eventId: string;
  readonly orgId: string;
  readonly payload: BillingStripeCreditPurchaseSettledPayload;
  readonly auditCompletedAt: string | null;
  readonly customerWebhookCompletedAt: string | null;
  readonly attemptCount: number;
  readonly lastError: string | null;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export function buildConsoleBillingCreditPurchaseSettledAuditEvent(input: {
  purchase: BillingCreditPurchase;
  invoice: BillingInvoice | null;
  source: 'stripe_webhook' | 'stripe_checkout_reconcile';
  settlementEventId?: string;
}): {
  summary: string;
  metadata: Record<string, unknown>;
} {
  return {
    summary: `Settled Stripe credit purchase ${input.purchase.id}`,
    metadata: {
      purchaseId: input.purchase.id,
      creditPackId: input.purchase.creditPackId,
      amountMinor: input.purchase.amountMinor,
      currency: input.purchase.currency,
      purchaseStatus: input.purchase.status,
      provider: input.purchase.provider,
      providerCheckoutSessionRef: input.purchase.providerCheckoutSessionRef,
      ...(input.purchase.providerCustomerRef
        ? { providerCustomerRef: input.purchase.providerCustomerRef }
        : {}),
      ...(input.purchase.relatedInvoiceId
        ? { relatedInvoiceId: input.purchase.relatedInvoiceId }
        : {}),
      ...(input.purchase.settledAt ? { settledAt: input.purchase.settledAt } : {}),
      settlementSource: input.source,
      ...(input.settlementEventId ? { settlementEventId: input.settlementEventId } : {}),
      ...(input.invoice
        ? {
            receiptId: input.invoice.id,
            receiptStatus: input.invoice.status,
            receiptDocumentType: input.invoice.documentType,
          }
        : {}),
    },
  };
}

export function buildBillingStripePostProcessingPayload(input: {
  eventId: string;
  purchase: BillingCreditPurchase;
  invoice: BillingInvoice | null;
}): BillingStripeCreditPurchaseSettledPayload {
  const audit = buildConsoleBillingCreditPurchaseSettledAuditEvent({
    purchase: input.purchase,
    invoice: input.invoice,
    source: 'stripe_webhook',
    settlementEventId: input.eventId,
  });
  return {
    kind: 'credit_purchase_settled_v1',
    audit: {
      id: `stripe:${input.eventId}:credit-purchase-settled`,
      summary: audit.summary,
      metadata: audit.metadata,
    },
    customerWebhook: {
      eventId: input.eventId,
      eventType: 'billing.credit_purchase.settled',
      payload: {
        purchaseId: input.purchase.id,
        creditPackId: input.purchase.creditPackId,
        amountMinor: input.purchase.amountMinor,
        receiptId: input.invoice?.id || null,
        source: 'stripe_webhook',
      },
    },
  };
}

function requireRecord(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function requireAmountMinor(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error('payload.customerWebhook.payload.amountMinor must be a positive integer');
  }
  return parsed;
}

export function parseBillingStripePostProcessingPayload(
  value: unknown,
): BillingStripeCreditPurchaseSettledPayload {
  const row = requireRecord(value, 'payload');
  if (row.kind !== 'credit_purchase_settled_v1') {
    throw new Error('Unsupported Stripe post-processing payload kind');
  }
  const audit = requireRecord(row.audit, 'payload.audit');
  const customerWebhook = requireRecord(row.customerWebhook, 'payload.customerWebhook');
  const webhookPayload = requireRecord(
    customerWebhook.payload,
    'payload.customerWebhook.payload',
  );
  const receiptId = webhookPayload.receiptId;
  if (receiptId !== null && typeof receiptId !== 'string') {
    throw new Error('payload.customerWebhook.payload.receiptId must be a string or null');
  }
  if (customerWebhook.eventType !== 'billing.credit_purchase.settled') {
    throw new Error('Unsupported Stripe post-processing webhook event type');
  }
  if (webhookPayload.source !== 'stripe_webhook') {
    throw new Error('Unsupported Stripe post-processing webhook source');
  }
  return {
    kind: 'credit_purchase_settled_v1',
    audit: {
      id: requireString(audit.id, 'payload.audit.id'),
      summary: requireString(audit.summary, 'payload.audit.summary'),
      metadata: requireRecord(audit.metadata, 'payload.audit.metadata'),
    },
    customerWebhook: {
      eventId: requireString(customerWebhook.eventId, 'payload.customerWebhook.eventId'),
      eventType: 'billing.credit_purchase.settled',
      payload: {
        purchaseId: requireString(
          webhookPayload.purchaseId,
          'payload.customerWebhook.payload.purchaseId',
        ),
        creditPackId: requireString(
          webhookPayload.creditPackId,
          'payload.customerWebhook.payload.creditPackId',
        ),
        amountMinor: requireAmountMinor(webhookPayload.amountMinor),
        receiptId,
        source: 'stripe_webhook',
      },
    },
  };
}
