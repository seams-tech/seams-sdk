import { secureRandomBase36 } from '../boundary';
import type { BillingCreditPackId, StripeProviderRefundStatus } from './types';

export interface StripeCheckoutSessionProviderInput {
  purchaseId: string;
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
  paymentIntentRef: string | null;
  paymentStatus: string;
  checkoutStatus: string;
  purchaseId: string;
  creditPackId: BillingCreditPackId;
  amountMinor: number;
  currency: 'USD';
}

export interface StripeRefundProviderInput {
  refundId: string;
  orgId: string;
  purchaseId: string;
  providerPaymentRef: string;
  amountMinor: number;
  reason: string;
}

export interface StripeRefundLookupProviderInput {
  providerRefundId: string;
}

export interface StripeRefundProviderOutput {
  id: string;
  status: StripeProviderRefundStatus;
  failureCode: string | null;
}

export interface StripeBillingProviderAdapter {
  createCheckoutSession(
    input: StripeCheckoutSessionProviderInput,
  ): Promise<StripeCheckoutSessionProviderOutput> | StripeCheckoutSessionProviderOutput;
  getCheckoutSession(
    input: StripeCheckoutSessionLookupProviderInput,
  ): Promise<StripeCheckoutSessionLookupProviderOutput> | StripeCheckoutSessionLookupProviderOutput;
  createRefund(
    input: StripeRefundProviderInput,
  ): Promise<StripeRefundProviderOutput> | StripeRefundProviderOutput;
  getRefund(
    input: StripeRefundLookupProviderInput,
  ): Promise<StripeRefundProviderOutput> | StripeRefundProviderOutput;
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
  const refunds = new Map<string, StripeRefundProviderOutput>();
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
          paymentIntentRef: `pi_${input.purchaseId}`,
          paymentStatus: 'paid',
          checkoutStatus: 'complete',
          purchaseId: input.purchaseId,
          creditPackId: input.creditPackId,
          amountMinor: input.amountMinor,
          currency: 'USD',
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
      createRefund(input: StripeRefundProviderInput): StripeRefundProviderOutput {
        const existing = refunds.get(input.refundId);
        if (existing) return existing;
        const refund = {
          id: `re_${input.refundId}`,
          status: 'succeeded',
          failureCode: null,
        } as const;
        refunds.set(input.refundId, refund);
        refunds.set(refund.id, refund);
        return refund;
      },
      getRefund(input: StripeRefundLookupProviderInput): StripeRefundProviderOutput {
        const providerRefundId = String(input.providerRefundId || '').trim();
        const refund = refunds.get(providerRefundId);
        if (!refund) {
          throw new Error(`Stripe refund ${providerRefundId || '(missing)'} was not found`);
        }
        return refund;
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
