import type {
  StripeBillingProviderAdapter,
  StripeCheckoutSessionProviderInput,
  StripeCheckoutSessionProviderOutput,
  StripeCustomerPortalSessionProviderInput,
  StripeCustomerPortalSessionProviderOutput,
  StripePaymentIntentProviderInput,
  StripePaymentIntentProviderOutput,
  StripeSetupIntentProviderInput,
  StripeSetupIntentProviderOutput,
} from '@tatchi-xyz/sdk/server/router/express';

interface StripeApiErrorPayload {
  error?: {
    message?: unknown;
    code?: unknown;
    type?: unknown;
  };
}

interface StripeBillingProviderOptions {
  secretKey: string;
  apiBaseUrl?: string;
  requestTimeoutMs?: number;
}

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function toPositiveInteger(value: unknown, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  const intValue = Math.floor(parsed);
  return intValue > 0 ? intValue : fallback;
}

function resolveExpiresAt(input: {
  now: Date;
  stripeUnixSeconds?: unknown;
  fallbackMinutes: number;
}): string {
  const unixSeconds = Number(input.stripeUnixSeconds);
  if (Number.isFinite(unixSeconds) && unixSeconds > 0) {
    return new Date(unixSeconds * 1000).toISOString();
  }
  return new Date(input.now.getTime() + input.fallbackMinutes * 60 * 1000).toISOString();
}

function setFormField(form: URLSearchParams, key: string, value: unknown): void {
  const normalized = normalizeString(value);
  if (!normalized) return;
  form.set(key, normalized);
}

function toStripeApiErrorMessage(status: number, payload: unknown): string {
  const errorPayload = (payload as StripeApiErrorPayload) || {};
  const message = normalizeString(errorPayload.error?.message);
  const code = normalizeString(errorPayload.error?.code);
  const type = normalizeString(errorPayload.error?.type);
  if (message && code) return `[stripe:${code}] ${message}`;
  if (message) return message;
  if (code && type) return `[stripe:${type}:${code}] request failed (${status})`;
  if (code) return `[stripe:${code}] request failed (${status})`;
  return `Stripe API request failed (${status})`;
}

function buildCreditPackName(input: StripeCheckoutSessionProviderInput): string {
  const checkoutInput = input as StripeCheckoutSessionProviderInput & {
    creditPackId?: string;
  };
  const label = String(checkoutInput.creditPackId || '')
    .trim()
    .replace(/^usd_/, '$');
  return label ? `Tatchi prepaid credit pack ${label}` : 'Tatchi prepaid credit pack';
}

export function createStripeBillingProviderAdapter(
  options: StripeBillingProviderOptions,
): StripeBillingProviderAdapter {
  const secretKey = normalizeString(options.secretKey);
  if (!secretKey) {
    throw new Error('STRIPE_API_SK must be set to enable live Stripe billing provider adapter');
  }

  const apiBaseUrl =
    normalizeString(options.apiBaseUrl).replace(/\/+$/, '') || 'https://api.stripe.com';
  const requestTimeoutMs = toPositiveInteger(options.requestTimeoutMs, 15_000);
  const customerByOrg = new Map<string, string>();

  async function postForm(
    pathname: string,
    form: URLSearchParams,
  ): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetch(`${apiBaseUrl}${pathname}`, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${secretKey}`,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: form.toString(),
        signal: controller.signal,
      });
      const payload = (await response.json().catch(() => ({}))) as Record<string, unknown>;
      if (!response.ok) {
        throw new Error(toStripeApiErrorMessage(response.status, payload));
      }
      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function ensureCustomer(orgId: string): Promise<string> {
    const cached = customerByOrg.get(orgId);
    if (cached) return cached;

    const form = new URLSearchParams();
    setFormField(form, 'name', `Console ${orgId}`);
    setFormField(form, 'metadata[org_id]', orgId);
    setFormField(form, 'description', `Tatchi console billing customer for ${orgId}`);

    const payload = await postForm('/v1/customers', form);
    const customerId = normalizeString(payload.id);
    if (!customerId) {
      throw new Error('Stripe customer create returned missing id');
    }
    customerByOrg.set(orgId, customerId);
    return customerId;
  }

  return {
    async createSetupIntent(
      input: StripeSetupIntentProviderInput,
    ): Promise<StripeSetupIntentProviderOutput> {
      const customerRef = await ensureCustomer(input.orgId);
      const form = new URLSearchParams();
      setFormField(form, 'customer', customerRef);
      setFormField(form, 'usage', 'off_session');
      setFormField(form, 'metadata[org_id]', input.orgId);
      if (input.returnUrl) {
        setFormField(form, 'return_url', input.returnUrl);
      }

      const payload = await postForm('/v1/setup_intents', form);
      const id = normalizeString(payload.id);
      const clientSecret = normalizeString(payload.client_secret);
      if (!id || !clientSecret) {
        throw new Error('Stripe setup intent returned missing id/client_secret');
      }

      return {
        id,
        clientSecret,
        customerRef,
        expiresAt: resolveExpiresAt({
          now: input.now,
          stripeUnixSeconds: payload.expires_at,
          fallbackMinutes: 30,
        }),
      };
    },

    async createCheckoutSession(
      input: StripeCheckoutSessionProviderInput,
    ): Promise<StripeCheckoutSessionProviderOutput> {
      const checkoutInput = input as StripeCheckoutSessionProviderInput & {
        creditPackId?: string;
        amountMinor?: number;
      };
      const customerRef = await ensureCustomer(input.orgId);
      const form = new URLSearchParams();
      setFormField(form, 'mode', 'payment');
      setFormField(form, 'customer', customerRef);
      setFormField(form, 'success_url', input.successUrl);
      setFormField(form, 'cancel_url', input.cancelUrl);
      setFormField(form, 'client_reference_id', input.orgId);
      setFormField(form, 'metadata[org_id]', input.orgId);
      setFormField(form, 'metadata[credit_pack_id]', checkoutInput.creditPackId);
      setFormField(form, 'line_items[0][price_data][currency]', 'usd');
      setFormField(form, 'line_items[0][price_data][unit_amount]', checkoutInput.amountMinor);
      setFormField(
        form,
        'line_items[0][price_data][product_data][name]',
        buildCreditPackName(checkoutInput),
      );
      setFormField(form, 'line_items[0][quantity]', '1');

      const payload = await postForm('/v1/checkout/sessions', form);
      const id = normalizeString(payload.id);
      const url = normalizeString(payload.url);
      if (!id || !url) {
        throw new Error('Stripe checkout session returned missing id/url');
      }

      return {
        id,
        url,
        customerRef,
        expiresAt: resolveExpiresAt({
          now: input.now,
          stripeUnixSeconds: payload.expires_at,
          fallbackMinutes: 30,
        }),
      };
    },

    async createCustomerPortalSession(
      input: StripeCustomerPortalSessionProviderInput,
    ): Promise<StripeCustomerPortalSessionProviderOutput> {
      const customerRef = await ensureCustomer(input.orgId);
      const form = new URLSearchParams();
      setFormField(form, 'customer', customerRef);
      setFormField(form, 'return_url', input.returnUrl);

      const payload = await postForm('/v1/billing_portal/sessions', form);
      const id = normalizeString(payload.id);
      const url = normalizeString(payload.url);
      if (!id || !url) {
        throw new Error('Stripe billing portal session returned missing id/url');
      }

      return {
        id,
        url,
        customerRef,
        expiresAt: resolveExpiresAt({
          now: input.now,
          stripeUnixSeconds: payload.created,
          fallbackMinutes: 30,
        }),
      };
    },

    async createPaymentIntent(
      input: StripePaymentIntentProviderInput,
    ): Promise<StripePaymentIntentProviderOutput> {
      const customerRef = await ensureCustomer(input.orgId);
      const form = new URLSearchParams();
      setFormField(form, 'amount', input.amountMinor);
      setFormField(form, 'currency', input.currency.toLowerCase());
      setFormField(form, 'customer', customerRef);
      setFormField(form, 'automatic_payment_methods[enabled]', 'true');
      setFormField(form, 'metadata[org_id]', input.orgId);
      setFormField(form, 'metadata[invoice_id]', input.invoiceId);
      if (input.paymentMethodProviderRef) {
        setFormField(form, 'payment_method', input.paymentMethodProviderRef);
      }

      const payload = await postForm('/v1/payment_intents', form);
      const providerRef = normalizeString(payload.id);
      const clientSecret = normalizeString(payload.client_secret);
      if (!providerRef || !clientSecret) {
        throw new Error('Stripe payment intent returned missing id/client_secret');
      }

      return {
        providerRef,
        clientSecret,
      };
    },
  };
}
