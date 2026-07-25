import { secureRandomBase36 } from '@seams-internal/shared-ts/utils/secureRandomId';
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

export interface StripeCheckoutSessionLookupProviderInput {
  checkoutSessionId: string;
}

export interface StripeCheckoutSessionLookupProviderOutput {
  id: string;
  orgId: string | null;
  customerRef: string | null;
  paymentStatus: string;
  checkoutStatus: string;
}

export interface StripeBillingProviderAdapter {
  createCheckoutSession(
    input: StripeCheckoutSessionProviderInput,
  ): Promise<StripeCheckoutSessionProviderOutput> | StripeCheckoutSessionProviderOutput;
  getCheckoutSession(
    input: StripeCheckoutSessionLookupProviderInput,
  ): Promise<StripeCheckoutSessionLookupProviderOutput> | StripeCheckoutSessionLookupProviderOutput;
}

export interface BillingProviderAdapters {
  stripe: StripeBillingProviderAdapter;
}

function makeProviderId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

function makeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function buildMockCheckoutSuccessUrl(successUrl: string, checkoutSessionId: string): string {
  const url = new URL(successUrl);
  url.searchParams.set('checkout_session_id', checkoutSessionId);
  return url.toString();
}

export function createDefaultBillingProviderAdapters(): BillingProviderAdapters {
  const sessions = new Map<string, StripeCheckoutSessionLookupProviderOutput>();
  return {
    stripe: {
      createCheckoutSession(
        input: StripeCheckoutSessionProviderInput,
      ): StripeCheckoutSessionProviderOutput {
        const id = makeProviderId('cs', input.now);
        const customerRef = makeCustomerRef(input.orgId);
        sessions.set(id, {
          id,
          orgId: input.orgId,
          customerRef,
          paymentStatus: 'paid',
          checkoutStatus: 'complete',
        });
        return {
          id,
          url: buildMockCheckoutSuccessUrl(input.successUrl, id),
          customerRef,
          expiresAt: new Date(input.now.getTime() + 30 * 60 * 1000).toISOString(),
        };
      },
      getCheckoutSession(
        input: StripeCheckoutSessionLookupProviderInput,
      ): StripeCheckoutSessionLookupProviderOutput {
        const checkoutSessionId = String(input.checkoutSessionId || '').trim();
        const session = sessions.get(checkoutSessionId);
        if (!session) {
          throw new Error(
            `Stripe checkout session ${checkoutSessionId || '(missing)'} was not found`,
          );
        }
        return session;
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
