import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardBillingOverview {
  planId: string;
  planName: string;
  usageMetricVersion: string;
  currentMonthUtc: string;
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  upcomingChargeEstimateMinor: number;
  openInvoiceCount: number;
}

export interface DashboardBillingUsage {
  usageMetricVersion: string;
  monthUtc: string;
  monthlyActiveWallets: number;
}

export interface DashboardBillingInvoice {
  id: string;
  status: string;
  amountDueMinor: number;
  amountPaidMinor: number;
  railLock: 'CARD' | 'STABLECOIN' | null;
  periodMonthUtc: string;
  dueAt: string | null;
  createdAt: string;
}

export interface DashboardBillingInvoiceLineItem {
  id: string;
  invoiceId: string;
  itemType: string;
  description: string;
  quantity: number;
  unitAmountMinor: number;
  amountMinor: number;
  periodMonthUtc: string;
}

export interface DashboardBillingPaymentMethod {
  id: string;
  provider: string;
  type: string;
  brand: string;
  last4: string;
  expMonth: number;
  expYear: number;
  isDefault: boolean;
  createdAt: string;
}

export interface DashboardAddCardPaymentMethodRequest {
  providerRef: string;
  brand: string;
  last4: string;
  expMonth: number;
  expYear: number;
}

export interface DashboardStripeSetupIntentRequest {
  returnUrl?: string;
}

export interface DashboardStripeSetupIntent {
  id: string;
  clientSecret: string;
  customerRef: string;
  expiresAt: string;
}

export interface DashboardStripePaymentIntentRequest {
  invoiceId: string;
  paymentMethodId?: string;
}

export interface DashboardStripePaymentIntent {
  id: string;
  providerRef: string;
  invoiceId: string;
  amountMinor: number;
  currency: string;
  paymentMethodId: string | null;
  state: string;
  clientSecret: string;
  createdAt: string;
  rail: 'CARD';
}

export interface DashboardStablecoinChainPolicy {
  chain: string;
  requiredConfirmations: number;
  confirmationTimeoutMinutes: number;
  reorgRiskWindowHours: number;
}

export interface DashboardStablecoinAssetSupport {
  asset: string;
  chains: DashboardStablecoinChainPolicy[];
}

export interface DashboardStablecoinQuoteRequest {
  invoiceId: string;
  asset: string;
  chain: string;
}

export interface DashboardStablecoinPaymentQuote {
  id: string;
  orgId: string;
  invoiceId: string;
  asset: string;
  chain: string;
  amountMinor: number;
  createdAt: string;
  expiresAt: string;
  state: 'OPEN' | 'EXPIRED';
}

export interface DashboardStablecoinPaymentIntentRequest {
  invoiceId: string;
  quoteId: string;
}

export interface DashboardStablecoinPaymentIntent {
  id: string;
  orgId: string;
  invoiceId: string;
  quoteId: string;
  asset: string;
  chain: string;
  expectedAmountMinor: number;
  destinationAddress: string;
  state: string;
  rail: 'STABLECOIN';
  requiredConfirmations: number;
  confirmationTimeoutMinutes: number;
  reorgRiskWindowHours: number;
  settledAt: string | null;
  reorgRiskWindowEndsAt: string | null;
  withinReorgRiskWindow: boolean;
  createdAt: string;
  expiresAt: string;
}

interface ConsoleOverviewResponse {
  ok?: boolean;
  message?: string;
  overview?: unknown;
}

interface ConsoleUsageResponse {
  ok?: boolean;
  message?: string;
  usage?: unknown;
}

interface ConsoleInvoicesResponse {
  ok?: boolean;
  message?: string;
  invoices?: unknown;
}

interface ConsoleInvoiceLineItemsResponse {
  ok?: boolean;
  message?: string;
  lineItems?: unknown;
}

interface ConsolePaymentMethodsResponse {
  ok?: boolean;
  message?: string;
  paymentMethods?: unknown;
}

interface ConsolePaymentMethodResponse {
  ok?: boolean;
  message?: string;
  paymentMethod?: unknown;
  removed?: unknown;
}

interface ConsoleStablecoinAssetsResponse {
  ok?: boolean;
  message?: string;
  version?: unknown;
  assets?: unknown;
}

interface ConsoleStripeSetupIntentResponse {
  ok?: boolean;
  message?: string;
  setupIntent?: unknown;
}

interface ConsoleStripePaymentIntentResponse {
  ok?: boolean;
  message?: string;
  paymentIntent?: unknown;
}

interface ConsoleStablecoinQuoteResponse {
  ok?: boolean;
  message?: string;
  quote?: unknown;
}

interface ConsoleStablecoinPaymentIntentResponse {
  ok?: boolean;
  message?: string;
  paymentIntent?: unknown;
}

function decodeOverview(raw: unknown): DashboardBillingOverview | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const planId = String(row.planId || '').trim();
  const currentMonthUtc = String(row.currentMonthUtc || '').trim();
  if (!planId || !currentMonthUtc) return null;
  return {
    planId,
    planName: String(row.planName || '').trim() || planId,
    usageMetricVersion: String(row.usageMetricVersion || '').trim() || 'maw_v1',
    currentMonthUtc,
    monthlyActiveWallets: Number(row.monthlyActiveWallets || 0),
    creditBalanceMinor: Number(row.creditBalanceMinor || 0),
    upcomingChargeEstimateMinor: Number(row.upcomingChargeEstimateMinor || 0),
    openInvoiceCount: Number(row.openInvoiceCount || 0),
  };
}

function decodeUsage(raw: unknown): DashboardBillingUsage | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const monthUtc = String(row.monthUtc || '').trim();
  if (!monthUtc) return null;
  return {
    usageMetricVersion: String(row.usageMetricVersion || '').trim() || 'maw_v1',
    monthUtc,
    monthlyActiveWallets: Number(row.monthlyActiveWallets || 0),
  };
}

function decodeInvoice(raw: unknown): DashboardBillingInvoice | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  const railLockRaw = String(row.railLock || '').trim().toUpperCase();
  return {
    id,
    status: String(row.status || '').trim() || 'OPEN',
    amountDueMinor: Number(row.amountDueMinor || 0),
    amountPaidMinor: Number(row.amountPaidMinor || 0),
    railLock: railLockRaw === 'CARD' || railLockRaw === 'STABLECOIN' ? (railLockRaw as 'CARD' | 'STABLECOIN') : null,
    periodMonthUtc: String(row.periodMonthUtc || '').trim(),
    dueAt: row.dueAt == null ? null : String(row.dueAt || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
  };
}

function decodeInvoiceLineItem(raw: unknown): DashboardBillingInvoiceLineItem | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const invoiceId = String(row.invoiceId || '').trim();
  if (!id || !invoiceId) return null;
  return {
    id,
    invoiceId,
    itemType: String(row.itemType || '').trim(),
    description: String(row.description || '').trim(),
    quantity: Number(row.quantity || 0),
    unitAmountMinor: Number(row.unitAmountMinor || 0),
    amountMinor: Number(row.amountMinor || 0),
    periodMonthUtc: String(row.periodMonthUtc || '').trim(),
  };
}

function decodePaymentMethod(raw: unknown): DashboardBillingPaymentMethod | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  return {
    id,
    provider: String(row.provider || '').trim(),
    type: String(row.type || '').trim(),
    brand: String(row.brand || '').trim(),
    last4: String(row.last4 || '').trim(),
    expMonth: Number(row.expMonth || 0),
    expYear: Number(row.expYear || 0),
    isDefault: row.isDefault === true,
    createdAt: String(row.createdAt || '').trim(),
  };
}

function decodeStripeSetupIntent(raw: unknown): DashboardStripeSetupIntent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const clientSecret = String(row.clientSecret || '').trim();
  const customerRef = String(row.customerRef || '').trim();
  const expiresAt = String(row.expiresAt || '').trim();
  if (!id || !clientSecret || !customerRef || !expiresAt) return null;
  return {
    id,
    clientSecret,
    customerRef,
    expiresAt,
  };
}

function decodeStripePaymentIntent(raw: unknown): DashboardStripePaymentIntent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const providerRef = String(row.providerRef || '').trim();
  const invoiceId = String(row.invoiceId || '').trim();
  const clientSecret = String(row.clientSecret || '').trim();
  if (!id || !providerRef || !invoiceId || !clientSecret) return null;
  return {
    id,
    providerRef,
    invoiceId,
    amountMinor: Number(row.amountMinor || 0),
    currency: String(row.currency || '').trim() || 'USD',
    paymentMethodId: row.paymentMethodId == null ? null : String(row.paymentMethodId || '').trim() || null,
    state: String(row.state || '').trim() || 'CREATED',
    clientSecret,
    createdAt: String(row.createdAt || '').trim(),
    rail: 'CARD',
  };
}

function decodeChainPolicy(raw: unknown): DashboardStablecoinChainPolicy | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const chain = String(row.chain || '').trim();
  if (!chain) return null;
  return {
    chain,
    requiredConfirmations: Number(row.requiredConfirmations || 0),
    confirmationTimeoutMinutes: Number(row.confirmationTimeoutMinutes || 0),
    reorgRiskWindowHours: Number(row.reorgRiskWindowHours || 0),
  };
}

function decodeStablecoinAssetSupport(raw: unknown): DashboardStablecoinAssetSupport | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const asset = String(row.asset || '').trim();
  if (!asset) return null;
  const chainsRaw = Array.isArray(row.chains) ? row.chains : [];
  return {
    asset,
    chains: chainsRaw
      .map((entry) => decodeChainPolicy(entry))
      .filter((entry): entry is DashboardStablecoinChainPolicy => entry !== null),
  };
}

function decodeStablecoinQuote(raw: unknown): DashboardStablecoinPaymentQuote | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const invoiceId = String(row.invoiceId || '').trim();
  if (!id || !orgId || !invoiceId) return null;
  const stateRaw = String(row.state || '').trim().toUpperCase();
  return {
    id,
    orgId,
    invoiceId,
    asset: String(row.asset || '').trim(),
    chain: String(row.chain || '').trim(),
    amountMinor: Number(row.amountMinor || 0),
    createdAt: String(row.createdAt || '').trim(),
    expiresAt: String(row.expiresAt || '').trim(),
    state: stateRaw === 'EXPIRED' ? 'EXPIRED' : 'OPEN',
  };
}

function decodeStablecoinPaymentIntent(raw: unknown): DashboardStablecoinPaymentIntent | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const invoiceId = String(row.invoiceId || '').trim();
  const quoteId = String(row.quoteId || '').trim();
  if (!id || !orgId || !invoiceId || !quoteId) return null;
  return {
    id,
    orgId,
    invoiceId,
    quoteId,
    asset: String(row.asset || '').trim(),
    chain: String(row.chain || '').trim(),
    expectedAmountMinor: Number(row.expectedAmountMinor || 0),
    destinationAddress: String(row.destinationAddress || '').trim(),
    state: String(row.state || '').trim() || 'PENDING',
    rail: 'STABLECOIN',
    requiredConfirmations: Number(row.requiredConfirmations || 0),
    confirmationTimeoutMinutes: Number(row.confirmationTimeoutMinutes || 0),
    reorgRiskWindowHours: Number(row.reorgRiskWindowHours || 0),
    settledAt: row.settledAt == null ? null : String(row.settledAt || '').trim() || null,
    reorgRiskWindowEndsAt:
      row.reorgRiskWindowEndsAt == null ? null : String(row.reorgRiskWindowEndsAt || '').trim() || null,
    withinReorgRiskWindow: row.withinReorgRiskWindow === true,
    createdAt: String(row.createdAt || '').trim(),
    expiresAt: String(row.expiresAt || '').trim(),
  };
}

async function fetchJson(path: string): Promise<any> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}${path}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = await parseConsoleJson(response);
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console billing request failed'));
  }
  return body;
}

export async function getDashboardBillingOverview(): Promise<DashboardBillingOverview> {
  const body = (await fetchJson('/console/billing/overview')) as ConsoleOverviewResponse;
  const overview = decodeOverview(body.overview);
  if (!overview) throw new Error('Billing overview response was invalid');
  return overview;
}

export async function getDashboardBillingMonthlyActiveWallets(
  monthUtc?: string,
): Promise<DashboardBillingUsage> {
  const params = new URLSearchParams();
  if (monthUtc) params.set('monthUtc', monthUtc);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/usage/monthly-active-wallets${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleUsageResponse;
  const usage = decodeUsage(body.usage);
  if (!usage) throw new Error('Billing MAW usage response was invalid');
  return usage;
}

export async function listDashboardBillingInvoices(): Promise<DashboardBillingInvoice[]> {
  const body = (await fetchJson('/console/billing/invoices')) as ConsoleInvoicesResponse;
  const rows = Array.isArray(body.invoices) ? body.invoices : [];
  return rows
    .map((entry) => decodeInvoice(entry))
    .filter((entry): entry is DashboardBillingInvoice => entry !== null);
}

export async function listDashboardBillingInvoiceLineItems(
  invoiceId: string,
): Promise<DashboardBillingInvoiceLineItem[]> {
  const normalizedInvoiceId = String(invoiceId || '').trim();
  if (!normalizedInvoiceId) throw new Error('Invoice id is required');
  const body = (await fetchJson(
    `/console/billing/invoices/${encodeURIComponent(normalizedInvoiceId)}/line-items`,
  )) as ConsoleInvoiceLineItemsResponse;
  const rows = Array.isArray(body.lineItems) ? body.lineItems : [];
  return rows
    .map((entry) => decodeInvoiceLineItem(entry))
    .filter((entry): entry is DashboardBillingInvoiceLineItem => entry !== null);
}

export async function listDashboardBillingPaymentMethods(): Promise<DashboardBillingPaymentMethod[]> {
  const body = (await fetchJson('/console/billing/payment-methods')) as ConsolePaymentMethodsResponse;
  const rows = Array.isArray(body.paymentMethods) ? body.paymentMethods : [];
  return rows
    .map((entry) => decodePaymentMethod(entry))
    .filter((entry): entry is DashboardBillingPaymentMethod => entry !== null);
}

export async function addDashboardCardPaymentMethod(
  input: DashboardAddCardPaymentMethodRequest,
): Promise<DashboardBillingPaymentMethod> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/payment-methods`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsolePaymentMethodResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Add card payment method request failed'));
  }
  const paymentMethod = decodePaymentMethod(body.paymentMethod);
  if (!paymentMethod) throw new Error('Add card payment method response was invalid');
  return paymentMethod;
}

export async function removeDashboardCardPaymentMethod(paymentMethodId: string): Promise<boolean> {
  const normalizedId = String(paymentMethodId || '').trim();
  if (!normalizedId) throw new Error('Payment method id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/payment-methods/${encodeURIComponent(normalizedId)}`, {
    method: 'DELETE',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as ConsolePaymentMethodResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Remove card payment method request failed'));
  }
  return body?.removed === true;
}

export async function setDashboardDefaultCardPaymentMethod(
  paymentMethodId: string,
): Promise<DashboardBillingPaymentMethod> {
  const normalizedId = String(paymentMethodId || '').trim();
  if (!normalizedId) throw new Error('Payment method id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/billing/payment-methods/${encodeURIComponent(normalizedId)}/default`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({}),
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePaymentMethodResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Set default card payment method request failed'));
  }
  const paymentMethod = decodePaymentMethod(body.paymentMethod);
  if (!paymentMethod) throw new Error('Set default card payment method response was invalid');
  return paymentMethod;
}

export async function getDashboardStablecoinAssetSupport(): Promise<{
  version: string;
  assets: DashboardStablecoinAssetSupport[];
}> {
  const body = (await fetchJson('/console/billing/stablecoins/assets')) as ConsoleStablecoinAssetsResponse;
  const rows = Array.isArray(body.assets) ? body.assets : [];
  return {
    version: String(body.version || '').trim() || 'v1',
    assets: rows
      .map((entry) => decodeStablecoinAssetSupport(entry))
      .filter((entry): entry is DashboardStablecoinAssetSupport => entry !== null),
  };
}

export async function createDashboardStripeSetupIntent(
  input: DashboardStripeSetupIntentRequest = {},
): Promise<DashboardStripeSetupIntent> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/setup-intent`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleStripeSetupIntentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Stripe setup intent request failed'));
  }
  const setupIntent = decodeStripeSetupIntent(body.setupIntent);
  if (!setupIntent) throw new Error('Stripe setup intent response was invalid');
  return setupIntent;
}

export async function createDashboardStripePaymentIntent(
  input: DashboardStripePaymentIntentRequest,
): Promise<DashboardStripePaymentIntent> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/payment-intent`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleStripePaymentIntentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Stripe payment intent request failed'));
  }
  const paymentIntent = decodeStripePaymentIntent(body.paymentIntent);
  if (!paymentIntent) throw new Error('Stripe payment intent response was invalid');
  return paymentIntent;
}

export async function createDashboardStablecoinQuote(
  input: DashboardStablecoinQuoteRequest,
): Promise<DashboardStablecoinPaymentQuote> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stablecoins/quotes`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleStablecoinQuoteResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Stablecoin quote request failed'));
  }
  const quote = decodeStablecoinQuote(body.quote);
  if (!quote) throw new Error('Stablecoin quote response was invalid');
  return quote;
}

export async function createDashboardStablecoinPaymentIntent(
  input: DashboardStablecoinPaymentIntentRequest,
): Promise<DashboardStablecoinPaymentIntent> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stablecoins/payment-intents`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleStablecoinPaymentIntentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Stablecoin payment intent request failed'));
  }
  const paymentIntent = decodeStablecoinPaymentIntent(body.paymentIntent);
  if (!paymentIntent) throw new Error('Stablecoin payment intent response was invalid');
  return paymentIntent;
}

export async function getDashboardStablecoinPaymentIntent(
  paymentIntentId: string,
): Promise<DashboardStablecoinPaymentIntent> {
  const normalizedId = String(paymentIntentId || '').trim();
  if (!normalizedId) throw new Error('Stablecoin payment intent id is required');
  const body = (await fetchJson(
    `/console/billing/stablecoins/payment-intents/${encodeURIComponent(normalizedId)}`,
  )) as ConsoleStablecoinPaymentIntentResponse;
  const paymentIntent = decodeStablecoinPaymentIntent(body.paymentIntent);
  if (!paymentIntent) throw new Error('Stablecoin payment intent response was invalid');
  return paymentIntent;
}

export async function cancelDashboardStablecoinPaymentIntent(
  paymentIntentId: string,
): Promise<DashboardStablecoinPaymentIntent> {
  const normalizedId = String(paymentIntentId || '').trim();
  if (!normalizedId) throw new Error('Stablecoin payment intent id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/billing/stablecoins/payment-intents/${encodeURIComponent(normalizedId)}/cancel`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({}),
    },
  );
  const body = (await parseConsoleJson(response)) as ConsoleStablecoinPaymentIntentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Stablecoin payment cancel request failed'));
  }
  const paymentIntent = decodeStablecoinPaymentIntent(body.paymentIntent);
  if (!paymentIntent) throw new Error('Stablecoin payment cancel response was invalid');
  return paymentIntent;
}

export function formatUsdMinor(amountMinor: number): string {
  const n = Number(amountMinor || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
