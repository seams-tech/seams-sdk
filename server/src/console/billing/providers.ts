import type { StablecoinAssetSymbol, StablecoinSettlementChain } from './stablecoinAssets';

export interface StripeSetupIntentProviderInput {
  orgId: string;
  returnUrl?: string;
  now: Date;
}

export interface StripeSetupIntentProviderOutput {
  id: string;
  clientSecret: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripeCheckoutSessionProviderInput {
  orgId: string;
  successUrl: string;
  cancelUrl: string;
  planId?: string;
  now: Date;
}

export interface StripeCheckoutSessionProviderOutput {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripeCustomerPortalSessionProviderInput {
  orgId: string;
  returnUrl: string;
  now: Date;
}

export interface StripeCustomerPortalSessionProviderOutput {
  id: string;
  url: string;
  customerRef: string;
  expiresAt: string;
}

export interface StripePaymentIntentProviderInput {
  orgId: string;
  invoiceId: string;
  amountMinor: number;
  currency: 'USD';
  paymentMethodProviderRef: string | null;
  now: Date;
}

export interface StripePaymentIntentProviderOutput {
  providerRef: string;
  clientSecret: string;
}

export interface StablecoinDestinationProviderInput {
  orgId: string;
  chain: StablecoinSettlementChain;
  asset: StablecoinAssetSymbol;
  now: Date;
}

export interface StablecoinDestinationProviderOutput {
  destinationAddress: string;
}

export interface StripeBillingProviderAdapter {
  createSetupIntent(
    input: StripeSetupIntentProviderInput,
  ): Promise<StripeSetupIntentProviderOutput> | StripeSetupIntentProviderOutput;
  createCheckoutSession(
    input: StripeCheckoutSessionProviderInput,
  ): Promise<StripeCheckoutSessionProviderOutput> | StripeCheckoutSessionProviderOutput;
  createCustomerPortalSession(
    input: StripeCustomerPortalSessionProviderInput,
  ): Promise<StripeCustomerPortalSessionProviderOutput> | StripeCustomerPortalSessionProviderOutput;
  createPaymentIntent(
    input: StripePaymentIntentProviderInput,
  ): Promise<StripePaymentIntentProviderOutput> | StripePaymentIntentProviderOutput;
}

export interface StablecoinBillingProviderAdapter {
  allocateDestination(
    input: StablecoinDestinationProviderInput,
  ): Promise<StablecoinDestinationProviderOutput> | StablecoinDestinationProviderOutput;
}

export interface BillingProviderAdapters {
  stripe: StripeBillingProviderAdapter;
  stablecoin: StablecoinBillingProviderAdapter;
}

function makeProviderId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function makeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function makeDestinationAddress(
  orgId: string,
  chain: StablecoinSettlementChain,
  now: Date,
): string {
  const prefix = chain.toLowerCase().replace(/[^a-z0-9]/g, '');
  return `pay_${prefix}_${orgId.slice(0, 8)}_${now.getTime().toString(36)}`;
}

export function createDefaultBillingProviderAdapters(): BillingProviderAdapters {
  return {
    stripe: {
      createSetupIntent(input: StripeSetupIntentProviderInput): StripeSetupIntentProviderOutput {
        const id = makeProviderId('seti', input.now);
        return {
          id,
          clientSecret: `${id}_secret_${Math.random().toString(36).slice(2, 12)}`,
          customerRef: makeCustomerRef(input.orgId),
          expiresAt: new Date(input.now.getTime() + 30 * 60 * 1000).toISOString(),
        };
      },
      createCheckoutSession(
        input: StripeCheckoutSessionProviderInput,
      ): StripeCheckoutSessionProviderOutput {
        const id = makeProviderId('cs', input.now);
        const encodedSuccess = encodeURIComponent(input.successUrl);
        const encodedCancel = encodeURIComponent(input.cancelUrl);
        const encodedPlan = encodeURIComponent(String(input.planId || '').trim() || 'pro_maw_v1');
        return {
          id,
          url: `https://checkout.stripe.com/pay/${id}?success_url=${encodedSuccess}&cancel_url=${encodedCancel}&plan=${encodedPlan}`,
          customerRef: makeCustomerRef(input.orgId),
          expiresAt: new Date(input.now.getTime() + 30 * 60 * 1000).toISOString(),
        };
      },
      createCustomerPortalSession(
        input: StripeCustomerPortalSessionProviderInput,
      ): StripeCustomerPortalSessionProviderOutput {
        const id = makeProviderId('bps', input.now);
        const encodedReturn = encodeURIComponent(input.returnUrl);
        return {
          id,
          url: `https://billing.stripe.com/p/session/${id}?return_url=${encodedReturn}`,
          customerRef: makeCustomerRef(input.orgId),
          expiresAt: new Date(input.now.getTime() + 30 * 60 * 1000).toISOString(),
        };
      },
      createPaymentIntent(
        input: StripePaymentIntentProviderInput,
      ): StripePaymentIntentProviderOutput {
        const providerRef = makeProviderId('pi_provider', input.now);
        return {
          providerRef,
          clientSecret: `${providerRef}_secret_${Math.random().toString(36).slice(2, 12)}`,
        };
      },
    },
    stablecoin: {
      allocateDestination(
        input: StablecoinDestinationProviderInput,
      ): StablecoinDestinationProviderOutput {
        return {
          destinationAddress: makeDestinationAddress(input.orgId, input.chain, input.now),
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
    stablecoin: overrides?.stablecoin || defaults.stablecoin,
  };
}
