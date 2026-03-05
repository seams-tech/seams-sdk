import { ConsoleBillingError } from './errors';
import type { ConsoleBillingContext, ConsoleBillingService } from './service';

export const LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE =
  'At least one active payment method is required before creating staging or production environments';

export async function isBillingReadyForLiveEnvironment(
  billing: ConsoleBillingService,
  ctx: ConsoleBillingContext,
): Promise<boolean> {
  const paymentMethods = await billing.listPaymentMethods(ctx);
  return paymentMethods.length > 0;
}

export async function ensureBillingReadyForLiveEnvironment(
  billing: ConsoleBillingService,
  ctx: ConsoleBillingContext,
): Promise<void> {
  if (await isBillingReadyForLiveEnvironment(billing, ctx)) return;
  throw new ConsoleBillingError(
    'billing_required_live_environment',
    409,
    LIVE_ENVIRONMENT_BILLING_REQUIRED_MESSAGE,
  );
}
