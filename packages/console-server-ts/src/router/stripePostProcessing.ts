import {
  isConsoleAuditError,
  type ConsoleAuditService,
} from '@seams-internal/console-server/audit/index';
import type { ConsoleBillingService } from '@seams-internal/console-server/billing/index';
import type { ConsoleWebhookService } from '@seams-internal/console-server/webhooks/index';
import type { RouterLogger } from '../boundary';

export interface BillingStripePostProcessingDispatchServices {
  readonly billing: ConsoleBillingService;
  readonly audit: ConsoleAuditService | null;
  readonly webhooks: ConsoleWebhookService | null;
  readonly logger: RouterLogger;
}

export interface BillingStripePostProcessingDispatchResult {
  readonly eventId: string;
  readonly found: boolean;
  readonly completed: boolean;
  readonly error: string | null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function deliverAuditEffect(
  services: BillingStripePostProcessingDispatchServices,
  eventId: string,
): Promise<void> {
  const item = await services.billing.getStripePostProcessingOutboxItem(eventId);
  if (!item || item.auditCompletedAt) return;
  if (services.audit) {
    try {
      await services.audit.appendEvent(
        {
          orgId: item.orgId,
          actorUserId: 'system-stripe-webhook',
        },
        {
          id: item.payload.audit.id,
          category: 'BILLING',
          action: 'billing.credit_purchase.settled',
          outcome: 'SUCCESS',
          summary: item.payload.audit.summary,
          actorUserId: 'system-stripe-webhook',
          actorType: 'SYSTEM',
          metadata: item.payload.audit.metadata,
        },
      );
    } catch (error: unknown) {
      if (!isConsoleAuditError(error) || error.code !== 'event_already_exists') throw error;
    }
  }
  await services.billing.completeStripePostProcessingEffect({
    eventId,
    effect: 'audit',
  });
}

async function deliverCustomerWebhookEffect(
  services: BillingStripePostProcessingDispatchServices,
  eventId: string,
): Promise<void> {
  const item = await services.billing.getStripePostProcessingOutboxItem(eventId);
  if (!item || item.customerWebhookCompletedAt) return;
  if (services.webhooks) {
    await services.webhooks.emitEvent(
      {
        orgId: item.orgId,
        actorUserId: 'system-stripe-webhook',
      },
      {
        eventId: item.payload.customerWebhook.eventId,
        eventType: item.payload.customerWebhook.eventType,
        payload: item.payload.customerWebhook.payload,
      },
    );
  }
  await services.billing.completeStripePostProcessingEffect({
    eventId,
    effect: 'customer_webhook',
  });
}

export async function dispatchBillingStripePostProcessingEvent(
  services: BillingStripePostProcessingDispatchServices,
  eventId: string,
): Promise<BillingStripePostProcessingDispatchResult> {
  const item = await services.billing.getStripePostProcessingOutboxItem(eventId);
  if (!item) {
    return { eventId, found: false, completed: true, error: null };
  }
  try {
    await deliverAuditEffect(services, eventId);
    await deliverCustomerWebhookEffect(services, eventId);
    const completed = await services.billing.getStripePostProcessingOutboxItem(eventId);
    return {
      eventId,
      found: true,
      completed: Boolean(
        completed?.auditCompletedAt && completed.customerWebhookCompletedAt,
      ),
      error: null,
    };
  } catch (error: unknown) {
    const message = errorMessage(error);
    await services.billing.recordStripePostProcessingFailure({ eventId, error: message });
    services.logger.warn?.('[console][billing] Stripe post-processing remains pending', {
      eventId,
      orgId: item.orgId,
      message,
    });
    return { eventId, found: true, completed: false, error: message };
  }
}

export async function dispatchPendingBillingStripePostProcessing(
  services: BillingStripePostProcessingDispatchServices,
  limit = 25,
): Promise<BillingStripePostProcessingDispatchResult[]> {
  const pending = await services.billing.listPendingStripePostProcessingOutboxItems(limit);
  const results: BillingStripePostProcessingDispatchResult[] = [];
  for (const item of pending) {
    results.push(await dispatchBillingStripePostProcessingEvent(services, item.eventId));
  }
  return results;
}
