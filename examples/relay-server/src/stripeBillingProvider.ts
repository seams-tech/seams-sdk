import type {
  StripeBillingProviderAdapter,
  StripeCheckoutSessionLookupProviderInput,
  StripeCheckoutSessionLookupProviderOutput,
  StripeCheckoutSessionProviderInput,
  StripeCheckoutSessionProviderOutput,
} from '@tatchi-xyz/sdk/server/router/express';

interface StripeApiErrorPayload {
  error?: {
    message?: unknown;
    code?: unknown;
    type?: unknown;
  };
}

interface StripeCheckoutSessionPayload {
  id?: unknown;
  customer?: unknown;
  client_reference_id?: unknown;
  payment_status?: unknown;
  status?: unknown;
  metadata?: {
    org_id?: unknown;
  };
}

interface StripeBillingProviderOptions {
  secretKey: string;
  apiBaseUrl?: string;
  requestTimeoutMs?: number;
}

const STRIPE_PUBLISHABLE_KEY_PREFIX = 'pk_';
const STRIPE_SECRET_KEY_PREFIXES = ['sk_', 'rk_'] as const;

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function hasAllowedPrefix(value: string, prefixes: readonly string[]): boolean {
  return prefixes.some((prefix) => value.startsWith(prefix));
}

export function normalizeStripeSecretKey(value: unknown): string {
  const normalized = normalizeString(value);
  if (!normalized) return '';
  if (hasAllowedPrefix(normalized, STRIPE_SECRET_KEY_PREFIXES)) return normalized;
  throw new Error(
    'STRIPE_API_SK must be a Stripe secret key (sk_...) or restricted key (rk_...), not a publishable key.',
  );
}

export function normalizeOptionalStripePublishableKey(value: unknown): string {
  const normalized = normalizeString(value);
  if (!normalized) return '';
  if (normalized.startsWith(STRIPE_PUBLISHABLE_KEY_PREFIX)) return normalized;
  throw new Error('STRIPE_API_PK must be a Stripe publishable key (pk_...).');
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
    amountMinor?: number;
  };
  const amountMinor = Number(checkoutInput.amountMinor);
  if (!Number.isFinite(amountMinor) || amountMinor <= 0) return 'Tatchi prepaid credits';
  const amount = `$${(amountMinor / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
  return `Tatchi prepaid credits (${amount})`;
}

export function createStripeBillingProviderAdapter(
  options: StripeBillingProviderOptions,
): StripeBillingProviderAdapter {
  const secretKey = normalizeStripeSecretKey(options.secretKey);
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

  async function getJson(pathname: string): Promise<Record<string, unknown>> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), requestTimeoutMs);
    try {
      const response = await fetch(`${apiBaseUrl}${pathname}`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${secretKey}`,
        },
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

    async getCheckoutSession(
      input: StripeCheckoutSessionLookupProviderInput,
    ): Promise<StripeCheckoutSessionLookupProviderOutput> {
      const checkoutSessionId = normalizeString(input.checkoutSessionId);
      if (!checkoutSessionId) {
        throw new Error('Stripe checkout session id is required');
      }
      const payload = (await getJson(
        `/v1/checkout/sessions/${encodeURIComponent(checkoutSessionId)}`,
      )) as StripeCheckoutSessionPayload;
      const id = normalizeString(payload.id);
      if (!id) {
        throw new Error('Stripe checkout session lookup returned missing id');
      }
      return {
        id,
        orgId: normalizeString(payload.client_reference_id || payload.metadata?.org_id) || null,
        customerRef: normalizeString(payload.customer) || null,
        paymentStatus: normalizeString(payload.payment_status).toLowerCase() || 'unknown',
        checkoutStatus: normalizeString(payload.status).toLowerCase() || 'unknown',
      };
    },
  };
}
