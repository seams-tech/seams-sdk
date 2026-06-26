import type { ConsoleBillingContext, ConsoleBillingService } from '../console/billing/service';
import { resolveBillingLiveEnvironmentState } from '../console/billing/readiness';
import type { BillingLiveEnvironmentState } from '../console/billing/types';
import {
  buildBillingBalanceTransitionObservabilityEvent,
  buildBillingSponsorshipBlockedObservabilityEvent,
} from '../console/observability/adapters';
import type { ConsoleObservabilityIngestionService } from '../console/observability/incidentIngest';
import type { ConsoleWebhookService } from '../console/webhooks/service';
import type { NormalizedRouterLogger } from './logger';

export interface SponsorshipBillingBalanceSnapshot {
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
  state: BillingLiveEnvironmentState;
}

export interface SponsorshipBillingEventServices {
  logger: NormalizedRouterLogger;
  webhooks?: ConsoleWebhookService | null;
  observabilityIngestion?: ConsoleObservabilityIngestionService | null;
  webhookActorUserId?: string;
  webhookRoles?: string[];
}

export interface SponsorshipBalanceTransitionTrigger {
  kind:
    | 'credit_purchase_settled'
    | 'manual_support_credit'
    | 'manual_admin_debit'
    | 'sponsored_execution_debit';
  environmentId?: string;
  routeId?: string;
  ledgerEntryId?: string | null;
  adjustmentId?: string | null;
  purchaseId?: string | null;
  sourceEventId?: string | null;
}

function normalizeRoles(input: string[] | undefined, fallback: string[]): string[] {
  const roles = Array.isArray(input)
    ? input.map((entry) => String(entry || '').trim()).filter(Boolean)
    : [];
  return roles.length > 0 ? roles : fallback;
}

function toBalanceSnapshot(raw: {
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
}): SponsorshipBillingBalanceSnapshot {
  return {
    creditBalanceMinor: raw.creditBalanceMinor,
    lowBalanceThresholdMinor: raw.lowBalanceThresholdMinor,
    state: resolveBillingLiveEnvironmentState(raw),
  };
}

export async function readSponsorshipBillingBalanceSnapshot(
  billing: ConsoleBillingService | null | undefined,
  ctx: ConsoleBillingContext,
): Promise<SponsorshipBillingBalanceSnapshot | null> {
  if (!billing) return null;
  const overview = await billing.getOverview(ctx);
  return toBalanceSnapshot({
    creditBalanceMinor: overview.creditBalanceMinor,
    lowBalanceThresholdMinor: overview.lowBalanceThresholdMinor,
  });
}

async function emitBillingWebhookEvent(
  services: SponsorshipBillingEventServices,
  ctx: ConsoleBillingContext,
  input: {
    eventType: 'billing.balance.low_balance' | 'billing.balance.blocked' | 'billing.balance.recovered';
    payload: Record<string, unknown>;
  },
): Promise<void> {
  if (!services.webhooks) return;
  try {
    await services.webhooks.emitEvent(
      {
        orgId: ctx.orgId,
        actorUserId: String(services.webhookActorUserId || '').trim() || ctx.actorUserId,
        roles: normalizeRoles(services.webhookRoles, ctx.roles),
      },
      {
        eventType: input.eventType,
        payload: input.payload,
      },
    );
  } catch (error: unknown) {
    services.logger.warn('[sponsorship-billing-events] failed to emit billing webhook event', {
      orgId: ctx.orgId,
      eventType: input.eventType,
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

async function emitBillingBalanceTransitionObservabilityEvent(input: {
  services: SponsorshipBillingEventServices;
  ctx: ConsoleBillingContext;
  eventType: 'billing.balance.low_balance' | 'billing.balance.blocked' | 'billing.balance.recovered';
  before: SponsorshipBillingBalanceSnapshot;
  after: SponsorshipBillingBalanceSnapshot;
  trigger: SponsorshipBalanceTransitionTrigger;
}): Promise<void> {
  if (!input.services.observabilityIngestion) return;
  try {
    await input.services.observabilityIngestion.appendEvent(
      {
        orgId: input.ctx.orgId,
        actorUserId: input.ctx.actorUserId,
        roles: normalizeRoles(input.ctx.roles, ['system']),
      },
      buildBillingBalanceTransitionObservabilityEvent({
        orgId: input.ctx.orgId,
        eventType: input.eventType,
        previousState: input.before.state,
        currentState: input.after.state,
        creditBalanceMinor: input.after.creditBalanceMinor,
        lowBalanceThresholdMinor: input.after.lowBalanceThresholdMinor,
        triggerKind: input.trigger.kind,
        ...(input.trigger.environmentId ? { environmentId: input.trigger.environmentId } : {}),
        ...(input.trigger.routeId ? { routeId: input.trigger.routeId } : {}),
        ...(input.trigger.ledgerEntryId ? { ledgerEntryId: input.trigger.ledgerEntryId } : {}),
        ...(input.trigger.adjustmentId ? { adjustmentId: input.trigger.adjustmentId } : {}),
        ...(input.trigger.purchaseId ? { purchaseId: input.trigger.purchaseId } : {}),
        ...(input.trigger.sourceEventId ? { sourceEventId: input.trigger.sourceEventId } : {}),
      }),
    );
  } catch (error: unknown) {
    input.services.logger.warn(
      '[sponsorship-billing-events] failed to append balance transition observability event',
      {
        orgId: input.ctx.orgId,
        eventType: input.eventType,
        message: error instanceof Error ? error.message : String(error),
      },
    );
  }
}

export async function emitSponsorshipBalanceTransitionEvents(input: {
  services: SponsorshipBillingEventServices;
  ctx: ConsoleBillingContext;
  before: SponsorshipBillingBalanceSnapshot | null;
  billing: ConsoleBillingService | null | undefined;
  trigger: SponsorshipBalanceTransitionTrigger;
}): Promise<SponsorshipBillingBalanceSnapshot | null> {
  if (!input.billing) return null;
  const before = input.before || (await readSponsorshipBillingBalanceSnapshot(input.billing, input.ctx));
  const after = await readSponsorshipBillingBalanceSnapshot(input.billing, input.ctx);
  if (!before || !after || before.state === after.state) return after;

  let eventType: 'billing.balance.low_balance' | 'billing.balance.blocked' | 'billing.balance.recovered' | null =
    null;
  if (before.state === 'HEALTHY' && after.state === 'LOW_BALANCE') {
    eventType = 'billing.balance.low_balance';
  } else if (before.state !== 'BLOCKED' && after.state === 'BLOCKED') {
    eventType = 'billing.balance.blocked';
  } else if (before.state !== 'HEALTHY' && after.state === 'HEALTHY') {
    eventType = 'billing.balance.recovered';
  }
  if (!eventType) return after;

  await emitBillingWebhookEvent(input.services, input.ctx, {
    eventType,
    payload: {
      previousState: before.state,
      currentState: after.state,
      creditBalanceMinor: after.creditBalanceMinor,
      lowBalanceThresholdMinor: after.lowBalanceThresholdMinor,
      triggerKind: input.trigger.kind,
      ...(input.trigger.environmentId ? { environmentId: input.trigger.environmentId } : {}),
      ...(input.trigger.routeId ? { routeId: input.trigger.routeId } : {}),
      ...(input.trigger.ledgerEntryId ? { ledgerEntryId: input.trigger.ledgerEntryId } : {}),
      ...(input.trigger.adjustmentId ? { adjustmentId: input.trigger.adjustmentId } : {}),
      ...(input.trigger.purchaseId ? { purchaseId: input.trigger.purchaseId } : {}),
      ...(input.trigger.sourceEventId ? { sourceEventId: input.trigger.sourceEventId } : {}),
    },
  });
  await emitBillingBalanceTransitionObservabilityEvent({
    services: input.services,
    ctx: input.ctx,
    eventType,
    before,
    after,
    trigger: input.trigger,
  });
  return after;
}

export async function emitSponsorshipBlockedObservabilityEvent(input: {
  services: SponsorshipBillingEventServices;
  ctx: ConsoleBillingContext;
  balance: SponsorshipBillingBalanceSnapshot | null;
  environmentId: string;
  policyId: string;
  routeId: string;
  chainFamily: string;
  intentKind: string;
  executorKind: string;
  chainId: number;
  accountRef: string | null;
  targetRef: string;
  idempotencyKey: string;
  sourceEventId: string;
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}): Promise<void> {
  if (!input.services.observabilityIngestion) return;
  const details = input.error.details || {};
  try {
    await input.services.observabilityIngestion.appendEvent(
      {
        orgId: input.ctx.orgId,
        actorUserId: input.ctx.actorUserId,
        roles: normalizeRoles(input.ctx.roles, ['system']),
      },
      buildBillingSponsorshipBlockedObservabilityEvent({
        orgId: input.ctx.orgId,
        environmentId: input.environmentId,
        policyId: input.policyId,
        routeId: input.routeId,
        chainFamily: input.chainFamily,
        intentKind: input.intentKind,
        executorKind: input.executorKind,
        chainId: input.chainId,
        ...(input.accountRef ? { accountRef: input.accountRef } : {}),
        targetRef: input.targetRef,
        idempotencyKey: input.idempotencyKey,
        sourceEventId: input.sourceEventId,
        ...(input.balance ? { balanceState: input.balance.state } : {}),
        ...(input.balance ? { creditBalanceMinor: input.balance.creditBalanceMinor } : {}),
        ...(input.balance
          ? { lowBalanceThresholdMinor: input.balance.lowBalanceThresholdMinor }
          : {}),
        ...(Number.isFinite(Number(details.availableBalanceMinor))
          ? { availableBalanceMinor: Number(details.availableBalanceMinor) }
          : {}),
        ...(Number.isFinite(Number(details.postedBalanceMinor))
          ? { postedBalanceMinor: Number(details.postedBalanceMinor) }
          : {}),
        ...(Number.isFinite(Number(details.reservedMinor))
          ? { reservedMinor: Number(details.reservedMinor) }
          : {}),
        ...(Number.isFinite(Number(details.requestedMinor))
          ? { requestedMinor: Number(details.requestedMinor) }
          : {}),
        failureCode: input.error.code,
        failureMessage: input.error.message,
      }),
    );
  } catch (error: unknown) {
    input.services.logger.warn(
      '[sponsorship-billing-events] failed to append sponsorship blocked observability event',
      {
        orgId: input.ctx.orgId,
        policyId: input.policyId,
        routeId: input.routeId,
        message: error instanceof Error ? error.message : String(error),
      },
    );
  }
}
