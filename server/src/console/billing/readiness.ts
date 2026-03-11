import { ConsoleBillingError } from './errors';
import type { ConsoleBillingContext, ConsoleBillingService } from './service';
import type { BillingLiveEnvironmentState, BillingOverview } from './types';

export const LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE =
  'A positive prepaid credit balance is required before creating staging or production environments';

export interface BillingLiveEnvironmentReadiness {
  state: BillingLiveEnvironmentState;
  canUseLiveEnvironments: boolean;
}

export function resolveBillingLiveEnvironmentState(
  overview: Pick<BillingOverview, 'creditBalanceMinor' | 'lowBalanceThresholdMinor'>,
): BillingLiveEnvironmentState {
  if (overview.creditBalanceMinor <= 0) return 'BLOCKED';
  if (overview.creditBalanceMinor <= overview.lowBalanceThresholdMinor) return 'LOW_BALANCE';
  return 'HEALTHY';
}

export function getBillingLiveEnvironmentReadinessFromOverview(
  overview: Pick<BillingOverview, 'creditBalanceMinor' | 'lowBalanceThresholdMinor'>,
): BillingLiveEnvironmentReadiness {
  const state = resolveBillingLiveEnvironmentState(overview);
  return {
    state,
    canUseLiveEnvironments: state !== 'BLOCKED',
  };
}

export async function getBillingLiveEnvironmentReadiness(
  billing: ConsoleBillingService,
  ctx: ConsoleBillingContext,
): Promise<BillingLiveEnvironmentReadiness> {
  const overview = await billing.getOverview(ctx);
  return getBillingLiveEnvironmentReadinessFromOverview(overview);
}

export async function ensureBillingReadyForLiveEnvironment(
  billing: ConsoleBillingService,
  ctx: ConsoleBillingContext,
): Promise<void> {
  const readiness = await getBillingLiveEnvironmentReadiness(billing, ctx);
  if (readiness.canUseLiveEnvironments) return;
  throw new ConsoleBillingError(
    'billing_required_live_environment',
    409,
    LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
  );
}
