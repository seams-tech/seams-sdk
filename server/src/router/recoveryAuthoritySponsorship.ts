import type { ConsoleBillingService } from '../console/billing';
import type { ConsoleBillingPrepaidReservationService } from '../console/billingPrepaidReservations';
import type { ConsoleObservabilityIngestionService } from '../console/observability';
import type { ConsoleRuntimeSnapshotService } from '../console/runtimeSnapshots';
import type { ConsoleSponsoredCallService } from '../console/sponsoredCalls';
import type { ConsoleSponsorshipSpendCapService } from '../console/sponsorshipSpendCaps';
import type { ConsoleWebhookService } from '../console/webhooks';
import type { NormalizedRouterLogger } from './logger';
import type { RelayRouterOptions, RelayRuntimePolicyScope } from './relay';
import type { SponsoredEvmCallExecutorConfig, SponsorshipSpendPricingService } from '../sponsorship';

function normalizeOptionalString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

export type RecoveryAuthoritySponsorshipRuntime = {
  logger: NormalizedRouterLogger;
  billing: ConsoleBillingService;
  ledger: ConsoleSponsoredCallService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  config: SponsoredEvmCallExecutorConfig;
  spendCaps: ConsoleSponsorshipSpendCapService | null;
  pricing: SponsorshipSpendPricingService | null;
  prepaidReservations: ConsoleBillingPrepaidReservationService | null;
  observabilityIngestion: ConsoleObservabilityIngestionService | null;
  webhooks: ConsoleWebhookService | null;
  webhookActorUserId?: string;
  webhookRoles?: string[];
};

export function parseRecoveryAuthoritySponsorshipScope(
  raw: unknown,
): RelayRuntimePolicyScope | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const orgId = normalizeOptionalString(row.orgId);
  const projectId = normalizeOptionalString(row.projectId);
  const envId = normalizeOptionalString(row.envId) || normalizeOptionalString(row.environmentId);
  if (!orgId || !projectId || !envId) return null;
  return {
    orgId,
    projectId,
    envId,
  };
}

export function buildRecoveryAuthoritySponsorshipRuntime(input: {
  logger: NormalizedRouterLogger;
  opts: RelayRouterOptions;
}): RecoveryAuthoritySponsorshipRuntime | null {
  const sponsoredEvmCall = input.opts.sponsoredEvmCall;
  if (
    !sponsoredEvmCall?.config ||
    !sponsoredEvmCall.billing ||
    !sponsoredEvmCall.ledger ||
    !sponsoredEvmCall.runtimeSnapshots
  ) {
    return null;
  }

  return {
    logger: input.logger,
    billing: sponsoredEvmCall.billing,
    ledger: sponsoredEvmCall.ledger,
    runtimeSnapshots: sponsoredEvmCall.runtimeSnapshots,
    config: sponsoredEvmCall.config,
    spendCaps: input.opts.sponsorship?.spendCaps || null,
    pricing: input.opts.sponsorship?.pricing || null,
    prepaidReservations: input.opts.sponsorship?.prepaidReservations || null,
    observabilityIngestion: input.opts.observabilityIngestion || null,
    webhooks: input.opts.relayWebhooks?.service || null,
    webhookActorUserId: normalizeOptionalString(input.opts.relayWebhooks?.actorUserId),
    webhookRoles: Array.isArray(input.opts.relayWebhooks?.roles)
      ? input.opts.relayWebhooks?.roles
      : undefined,
  };
}
