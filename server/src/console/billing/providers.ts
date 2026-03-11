import type { BillingCreditPackId } from './types';

export interface StripeCheckoutSessionProviderInput {
  orgId: string;
  successUrl: string;
  cancelUrl: string;
  creditPackId: BillingCreditPackId;
  amountMinor: number;
  now: Date;
}

export interface StripeCheckoutSessionProviderOutput {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripeBillingProviderAdapter {
  createCheckoutSession(
    input: StripeCheckoutSessionProviderInput,
  ): Promise<StripeCheckoutSessionProviderOutput> | StripeCheckoutSessionProviderOutput;
}

export interface BillingProviderAdapters {
  stripe: StripeBillingProviderAdapter;
}

function makeProviderId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function makeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

export function createDefaultBillingProviderAdapters(): BillingProviderAdapters {
  return {
    stripe: {
      createCheckoutSession(
        input: StripeCheckoutSessionProviderInput,
      ): StripeCheckoutSessionProviderOutput {
        const id = makeProviderId('cs', input.now);
        const encodedSuccess = encodeURIComponent(input.successUrl);
        const encodedCancel = encodeURIComponent(input.cancelUrl);
        const encodedPack = encodeURIComponent(String(input.creditPackId || '').trim());
        const encodedAmount = encodeURIComponent(String(Math.max(0, input.amountMinor || 0)));
        return {
          id,
          url: `https://checkout.stripe.com/pay/${id}?success_url=${encodedSuccess}&cancel_url=${encodedCancel}&pack=${encodedPack}&amount_minor=${encodedAmount}`,
          customerRef: makeCustomerRef(input.orgId),
          expiresAt: new Date(input.now.getTime() + 30 * 60 * 1000).toISOString(),
        };
      },
    },
  };
}

export function resolveBillingProviderAdapters(
  overrides?: Partial<BillingProviderAdapters>,
): BillingProviderAdapters {
  const defaults = createDefaultBillingProviderAdapters();
  return {
    stripe: overrides?.stripe || defaults.stripe,
  };
}
