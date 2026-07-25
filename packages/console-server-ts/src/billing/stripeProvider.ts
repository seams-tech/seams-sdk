import type {
  BillingProviderAdapters,
  StripeBillingProviderAdapter,
  StripeCheckoutSessionLookupProviderInput,
  StripeCheckoutSessionLookupProviderOutput,
  StripeCheckoutSessionProviderInput,
  StripeCheckoutSessionProviderOutput,
} from './providers';

export interface StripeBillingProviderOptions {
  readonly secretKey: string;
  readonly defaultCheckoutPriceId?: string;
  readonly apiBaseUrl?: string;
  readonly requestTimeoutMs?: number;
}

export interface StripeBillingProviderEnv {
  readonly STRIPE_API_SK?: string;
  readonly STRIPE_CHECKOUT_PRICE_ID?: string;
  readonly STRIPE_API_BASE_URL?: string;
  readonly STRIPE_API_TIMEOUT_MS?: string;
}

type UnknownRecord = Readonly<Record<string, unknown>>;

const STRIPE_PUBLISHABLE_KEY_PREFIX = 'pk_';
const STRIPE_SECRET_KEY_PREFIXES = ['sk_', 'rk_'] as const;
const DEFAULT_STRIPE_API_BASE_URL = 'https://api.stripe.com';
const DEFAULT_STRIPE_API_TIMEOUT_MS = 15_000;

function normalizeString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
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
  const integer = Math.floor(parsed);
  return integer > 0 ? integer : fallback;
}

function toUnknownRecord(value: unknown): UnknownRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return {};
  return value as UnknownRecord;
}

async function readJsonResponse(response: Response): Promise<UnknownRecord> {
  try {
    return toUnknownRecord(await response.json());
  } catch {
    return {};
  }
}

function resolveExpiresAt(input: {
  readonly now: Date;
  readonly stripeUnixSeconds: unknown;
  readonly fallbackMinutes: number;
}): string {
  const unixSeconds = Number(input.stripeUnixSeconds);
  if (Number.isFinite(unixSeconds) && unixSeconds > 0) {
    return new Date(unixSeconds * 1000).toISOString();
  }
  return new Date(input.now.getTime() + input.fallbackMinutes * 60 * 1000).toISOString();
}

function setFormField(form: URLSearchParams, key: string, value: string | number): void {
  const normalized = String(value).trim();
  if (normalized) form.set(key, normalized);
}

function toStripeApiErrorMessage(status: number, payload: UnknownRecord): string {
  const error = toUnknownRecord(payload.error);
  const message = normalizeString(error.message);
  const code = normalizeString(error.code);
  const type = normalizeString(error.type);
  if (message && code) return `[stripe:${code}] ${message}`;
  if (message) return message;
  if (code && type) return `[stripe:${type}:${code}] request failed (${status})`;
  if (code) return `[stripe:${code}] request failed (${status})`;
  return `Stripe API request failed (${status})`;
}

function buildCreditPackName(input: StripeCheckoutSessionProviderInput): string {
  const amount = `$${(input.amountMinor / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
  return `Seams prepaid credits (${amount})`;
}

class StripeBillingProvider implements StripeBillingProviderAdapter {
  private readonly secretKey: string;
  private readonly defaultCheckoutPriceId: string;
  private readonly apiBaseUrl: string;
  private readonly requestTimeoutMs: number;
  private readonly customerByOrg = new Map<string, string>();

  constructor(options: StripeBillingProviderOptions) {
    this.secretKey = normalizeStripeSecretKey(options.secretKey);
    if (!this.secretKey) {
      throw new Error('STRIPE_API_SK must be set to enable live Stripe billing provider adapter');
    }
    this.defaultCheckoutPriceId = normalizeString(options.defaultCheckoutPriceId);
    this.apiBaseUrl =
      normalizeString(options.apiBaseUrl).replace(/\/+$/, '') || DEFAULT_STRIPE_API_BASE_URL;
    this.requestTimeoutMs = toPositiveInteger(
      options.requestTimeoutMs,
      DEFAULT_STRIPE_API_TIMEOUT_MS,
    );
  }

  async createCheckoutSession(
    input: StripeCheckoutSessionProviderInput,
  ): Promise<StripeCheckoutSessionProviderOutput> {
    const customerRef = await this.ensureCustomer(input.orgId);
    const form = new URLSearchParams();
    setFormField(form, 'mode', 'payment');
    setFormField(form, 'customer', customerRef);
    setFormField(form, 'success_url', input.successUrl);
    setFormField(form, 'cancel_url', input.cancelUrl);
    setFormField(form, 'client_reference_id', input.orgId);
    setFormField(form, 'metadata[org_id]', input.orgId);
    setFormField(form, 'metadata[credit_pack_id]', input.creditPackId);
    this.setCheckoutLineItem(form, input);

    const payload = await this.postForm('/v1/checkout/sessions', form);
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
  }

  async getCheckoutSession(
    input: StripeCheckoutSessionLookupProviderInput,
  ): Promise<StripeCheckoutSessionLookupProviderOutput> {
    const checkoutSessionId = normalizeString(input.checkoutSessionId);
    if (!checkoutSessionId) {
      throw new Error('Stripe checkout session id is required');
    }
    const payload = await this.getJson(
      `/v1/checkout/sessions/${encodeURIComponent(checkoutSessionId)}`,
    );
    const id = normalizeString(payload.id);
    if (!id) {
      throw new Error('Stripe checkout session lookup returned missing id');
    }
    const metadata = toUnknownRecord(payload.metadata);
    return {
      id,
      orgId:
        normalizeString(payload.client_reference_id) || normalizeString(metadata.org_id) || null,
      customerRef: normalizeString(payload.customer) || null,
      paymentStatus: normalizeString(payload.payment_status).toLowerCase() || 'unknown',
      checkoutStatus: normalizeString(payload.status).toLowerCase() || 'unknown',
    };
  }

  private setCheckoutLineItem(
    form: URLSearchParams,
    input: StripeCheckoutSessionProviderInput,
  ): void {
    if (this.defaultCheckoutPriceId) {
      setFormField(form, 'line_items[0][price]', this.defaultCheckoutPriceId);
    } else {
      setFormField(form, 'line_items[0][price_data][currency]', 'usd');
      setFormField(form, 'line_items[0][price_data][unit_amount]', input.amountMinor);
      setFormField(
        form,
        'line_items[0][price_data][product_data][name]',
        buildCreditPackName(input),
      );
    }
    setFormField(form, 'line_items[0][quantity]', 1);
  }

  private async ensureCustomer(orgId: string): Promise<string> {
    const cached = this.customerByOrg.get(orgId);
    if (cached) return cached;

    const form = new URLSearchParams();
    setFormField(form, 'name', `Console ${orgId}`);
    setFormField(form, 'metadata[org_id]', orgId);
    setFormField(form, 'description', `Seams console billing customer for ${orgId}`);

    const payload = await this.postForm('/v1/customers', form);
    const customerId = normalizeString(payload.id);
    if (!customerId) {
      throw new Error('Stripe customer create returned missing id');
    }
    this.customerByOrg.set(orgId, customerId);
    return customerId;
  }

  private async postForm(pathname: string, form: URLSearchParams): Promise<UnknownRecord> {
    return await this.request(pathname, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: form.toString(),
    });
  }

  private async getJson(pathname: string): Promise<UnknownRecord> {
    return await this.request(pathname, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.secretKey}`,
      },
    });
  }

  private async request(pathname: string, init: RequestInit): Promise<UnknownRecord> {
    const controller = new AbortController();
    const timeout = setTimeout(controller.abort.bind(controller), this.requestTimeoutMs);
    try {
      const response = await fetch(`${this.apiBaseUrl}${pathname}`, {
        ...init,
        signal: controller.signal,
      });
      const payload = await readJsonResponse(response);
      if (!response.ok) {
        throw new Error(toStripeApiErrorMessage(response.status, payload));
      }
      return payload;
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function createStripeBillingProviderAdapter(
  options: StripeBillingProviderOptions,
): StripeBillingProviderAdapter {
  return new StripeBillingProvider(options);
}

export function createStripeBillingProviderAdaptersFromEnv(
  env: StripeBillingProviderEnv,
): BillingProviderAdapters | undefined {
  const secretKey = normalizeStripeSecretKey(env.STRIPE_API_SK);
  if (!secretKey) return undefined;
  const defaultCheckoutPriceId = normalizeString(env.STRIPE_CHECKOUT_PRICE_ID);
  const apiBaseUrl = normalizeString(env.STRIPE_API_BASE_URL);
  const requestTimeoutMs = toPositiveInteger(
    env.STRIPE_API_TIMEOUT_MS,
    DEFAULT_STRIPE_API_TIMEOUT_MS,
  );
  return {
    stripe: createStripeBillingProviderAdapter({
      secretKey,
      ...(defaultCheckoutPriceId ? { defaultCheckoutPriceId } : {}),
      ...(apiBaseUrl ? { apiBaseUrl } : {}),
      requestTimeoutMs,
    }),
  };
}

export function requireStripeBillingProviderAdaptersFromEnv(
  env: StripeBillingProviderEnv,
): BillingProviderAdapters {
  const providers = createStripeBillingProviderAdaptersFromEnv(env);
  if (!providers) {
    throw new Error('STRIPE_API_SK is required for hosted console billing');
  }
  return providers;
}
