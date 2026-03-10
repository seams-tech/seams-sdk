import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardBillingOverview {
  usageMetricVersion: string;
  currentMonthUtc: string;
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
  recentUsageDebitMinor: number;
  recentCreditPurchasedMinor: number;
  documentCount: number;
}

export interface DashboardBillingUsage {
  usageMetricVersion: string;
  monthUtc: string;
  monthlyActiveWallets: number;
}

export interface DashboardBillingInvoice {
  id: string;
  documentType: 'PURCHASE_RECEIPT' | 'USAGE_STATEMENT';
  status: string;
  amountDueMinor: number;
  amountPaidMinor: number;
  periodMonthUtc: string;
  dueAt: string | null;
  createdAt: string;
}

export interface DashboardBillingInvoiceListRequest {
  status?: 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE' | 'OVERDUE';
  overdue?: boolean;
  periodMonthUtc?: string;
  documentType?: 'PURCHASE_RECEIPT' | 'USAGE_STATEMENT';
  limit?: number;
  cursor?: string;
}

export interface DashboardBillingInvoiceListSummary {
  totalCount: number;
  openCount: number;
  overdueCount: number;
  paidCount: number;
  outstandingAmountMinor: number;
  latestPeriodMonthUtc: string | null;
  receiptCount: number;
  statementCount: number;
}

export interface DashboardBillingInvoicePage {
  invoices: DashboardBillingInvoice[];
  nextCursor: string | null;
  totalCount: number;
  summary: DashboardBillingInvoiceListSummary;
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

export interface DashboardBillingInvoiceActivityEntry {
  id: string;
  type: 'DOCUMENT' | 'LEDGER';
  invoiceId: string;
  fromState: string | null;
  toState: string;
  occurredAt: string;
  actorType: 'USER' | 'SYSTEM' | 'PROVIDER';
  actorUserId: string | null;
  reason: string | null;
  sourceEventId: string | null;
  summary: string;
}

export interface DashboardBillingInvoiceActivity {
  invoice: DashboardBillingInvoice;
  entries: DashboardBillingInvoiceActivityEntry[];
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

export interface DashboardStripeCheckoutSessionRequest {
  successUrl: string;
  cancelUrl: string;
  creditPackId: 'usd_50' | 'usd_200' | 'usd_500' | 'usd_1000';
}

export interface DashboardStripeCheckoutSession {
  id: string;
  url: string;
  customerRef: string;
  creditPackId: 'usd_50' | 'usd_200' | 'usd_500' | 'usd_1000';
  amountMinor: number;
  expiresAt: string;
}

export interface DashboardStripeCustomerPortalSessionRequest {
  returnUrl: string;
}

export interface DashboardStripeCustomerPortalSession {
  id: string;
  url: string;
  customerRef: string;
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
  nextCursor?: unknown;
  totalCount?: unknown;
  summary?: unknown;
}

interface ConsoleInvoiceResponse {
  ok?: boolean;
  message?: string;
  invoice?: unknown;
}

interface ConsoleInvoiceLineItemsResponse {
  ok?: boolean;
  message?: string;
  lineItems?: unknown;
}

interface ConsoleInvoiceActivityResponse {
  ok?: boolean;
  message?: string;
  activity?: unknown;
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

interface ConsoleStripeSetupIntentResponse {
  ok?: boolean;
  message?: string;
  setupIntent?: unknown;
}

interface ConsoleStripeCheckoutSessionResponse {
  ok?: boolean;
  message?: string;
  checkoutSession?: unknown;
}

interface ConsoleStripeCustomerPortalSessionResponse {
  ok?: boolean;
  message?: string;
  portalSession?: unknown;
}

interface ConsoleBillingErrorBody {
  ok?: boolean;
  code?: unknown;
  message?: unknown;
  details?: unknown;
}

export class DashboardBillingApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(input: { status: number; code?: unknown; message: string; details?: unknown }) {
    super(input.message);
    this.name = 'DashboardBillingApiError';
    this.status = input.status;
    this.code = String(input.code || '').trim();
    this.details = input.details;
  }
}

function buildBillingApiError(
  response: Response,
  body: ConsoleBillingErrorBody | null | undefined,
  fallbackPrefix: string,
): DashboardBillingApiError {
  return new DashboardBillingApiError({
    status: response.status,
    code: body?.code,
    message: consoleErrorMessage(response, body, fallbackPrefix),
    details: body?.details,
  });
}

export function isDashboardBillingApiErrorCode(error: unknown, code: string): boolean {
  if (!(error instanceof DashboardBillingApiError)) return false;
  return error.code === code;
}

function decodeOverview(raw: unknown): DashboardBillingOverview | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const currentMonthUtc = String(row.currentMonthUtc || '').trim();
  if (!currentMonthUtc) return null;
  return {
    usageMetricVersion: String(row.usageMetricVersion || '').trim() || 'maw_v1',
    currentMonthUtc,
    monthlyActiveWallets: Number(row.monthlyActiveWallets || 0),
    creditBalanceMinor: Number(row.creditBalanceMinor || 0),
    lowBalanceThresholdMinor: Number(row.lowBalanceThresholdMinor || 0),
    recentUsageDebitMinor: Number(row.recentUsageDebitMinor || 0),
    recentCreditPurchasedMinor: Number(row.recentCreditPurchasedMinor || 0),
    documentCount: Number(row.documentCount || 0),
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
  const documentTypeRaw = String(row.documentType || '')
    .trim()
    .toUpperCase();
  return {
    id,
    documentType: documentTypeRaw === 'PURCHASE_RECEIPT' ? 'PURCHASE_RECEIPT' : 'USAGE_STATEMENT',
    status: String(row.status || '').trim() || 'OPEN',
    amountDueMinor: Number(row.amountDueMinor || 0),
    amountPaidMinor: Number(row.amountPaidMinor || 0),
    periodMonthUtc: String(row.periodMonthUtc || '').trim(),
    dueAt: row.dueAt == null ? null : String(row.dueAt || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
  };
}

function decodeInvoiceListSummary(raw: unknown): DashboardBillingInvoiceListSummary {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      totalCount: 0,
      openCount: 0,
      overdueCount: 0,
      paidCount: 0,
      outstandingAmountMinor: 0,
      latestPeriodMonthUtc: null,
      receiptCount: 0,
      statementCount: 0,
    };
  }
  const row = raw as Record<string, unknown>;
  return {
    totalCount: Number(row.totalCount || 0),
    openCount: Number(row.openCount || 0),
    overdueCount: Number(row.overdueCount || 0),
    paidCount: Number(row.paidCount || 0),
    outstandingAmountMinor: Number(row.outstandingAmountMinor || 0),
    latestPeriodMonthUtc:
      row.latestPeriodMonthUtc == null
        ? null
        : String(row.latestPeriodMonthUtc || '').trim() || null,
    receiptCount: Number(row.receiptCount || 0),
    statementCount: Number(row.statementCount || 0),
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

function decodeStripeCheckoutSession(raw: unknown): DashboardStripeCheckoutSession | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const url = String(row.url || '').trim();
  const customerRef = String(row.customerRef || '').trim();
  const expiresAt = String(row.expiresAt || '').trim();
  const creditPackId = String(row.creditPackId || '').trim();
  if (!id || !url || !customerRef || !expiresAt || !creditPackId) return null;
  return {
    id,
    url,
    customerRef,
    creditPackId: creditPackId as DashboardStripeCheckoutSession['creditPackId'],
    amountMinor: Number(row.amountMinor || 0),
    expiresAt,
  };
}

function decodeStripeCustomerPortalSession(
  raw: unknown,
): DashboardStripeCustomerPortalSession | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const url = String(row.url || '').trim();
  const customerRef = String(row.customerRef || '').trim();
  const expiresAt = String(row.expiresAt || '').trim();
  if (!id || !url || !customerRef || !expiresAt) return null;
  return {
    id,
    url,
    customerRef,
    expiresAt,
  };
}

function decodeInvoiceActivityEntry(raw: unknown): DashboardBillingInvoiceActivityEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const invoiceId = String(row.invoiceId || '').trim();
  const toState = String(row.toState || '').trim();
  if (!id || !invoiceId || !toState) return null;
  const type = String(row.type || '')
    .trim()
    .toUpperCase();
  const actorType = String(row.actorType || '')
    .trim()
    .toUpperCase();
  return {
    id,
    type: type === 'LEDGER' ? 'LEDGER' : 'DOCUMENT',
    invoiceId,
    fromState: row.fromState == null ? null : String(row.fromState || '').trim() || null,
    toState,
    occurredAt: String(row.occurredAt || '').trim(),
    actorType: actorType === 'USER' || actorType === 'PROVIDER' ? actorType : 'SYSTEM',
    actorUserId: row.actorUserId == null ? null : String(row.actorUserId || '').trim() || null,
    reason: row.reason == null ? null : String(row.reason || '').trim() || null,
    sourceEventId:
      row.sourceEventId == null ? null : String(row.sourceEventId || '').trim() || null,
    summary: String(row.summary || '').trim() || toState,
  };
}

function decodeInvoiceActivity(raw: unknown): DashboardBillingInvoiceActivity | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const invoice = decodeInvoice(row.invoice);
  if (!invoice) return null;
  const entriesRaw = Array.isArray(row.entries) ? row.entries : [];
  return {
    invoice,
    entries: entriesRaw
      .map((entry) => decodeInvoiceActivityEntry(entry))
      .filter((entry): entry is DashboardBillingInvoiceActivityEntry => entry !== null),
  };
}

async function fetchJson(path: string): Promise<Record<string, unknown>> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}${path}`, {
    method: 'GET',
    headers: buildConsoleAcceptHeaders(),
    credentials: 'include',
    cache: 'no-store',
  });
  const body = (await parseConsoleJson(response)) as Record<string, unknown> | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(
      response,
      body as ConsoleBillingErrorBody | null,
      'Console billing request failed',
    );
  }
  return body || {};
}

function parseContentDispositionFilename(raw: string | null): string {
  const header = String(raw || '').trim();
  if (!header) return '';
  const utf8Match = header.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]).trim();
    } catch {
      return utf8Match[1].trim();
    }
  }
  const quotedMatch = header.match(/filename="([^"]+)"/i);
  if (quotedMatch?.[1]) return quotedMatch[1].trim();
  const bareMatch = header.match(/filename=([^;]+)/i);
  return String(bareMatch?.[1] || '').trim();
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

export async function listDashboardBillingInvoices(
  input: DashboardBillingInvoiceListRequest = {},
): Promise<DashboardBillingInvoicePage> {
  const params = new URLSearchParams();
  if (input.status) params.set('status', input.status);
  if (input.overdue === true) params.set('overdue', 'true');
  if (input.periodMonthUtc) params.set('periodMonthUtc', input.periodMonthUtc);
  if (input.documentType) params.set('documentType', input.documentType);
  if (input.limit && Number.isFinite(input.limit) && input.limit > 0) {
    params.set('limit', String(Math.floor(input.limit)));
  }
  if (input.cursor) params.set('cursor', input.cursor);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/invoices${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleInvoicesResponse;
  const rows = Array.isArray(body.invoices) ? body.invoices : [];
  return {
    invoices: rows
      .map((entry) => decodeInvoice(entry))
      .filter((entry): entry is DashboardBillingInvoice => entry !== null),
    nextCursor: body.nextCursor == null ? null : String(body.nextCursor || '').trim() || null,
    totalCount: Number(body.totalCount || 0),
    summary: decodeInvoiceListSummary(body.summary),
  };
}

export async function getDashboardBillingInvoice(
  invoiceId: string,
): Promise<DashboardBillingInvoice> {
  const normalizedInvoiceId = String(invoiceId || '').trim();
  if (!normalizedInvoiceId) throw new Error('Invoice id is required');
  const body = (await fetchJson(
    `/console/billing/invoices/${encodeURIComponent(normalizedInvoiceId)}`,
  )) as ConsoleInvoiceResponse;
  const invoice = decodeInvoice(body.invoice);
  if (!invoice) throw new Error('Billing invoice response was invalid');
  return invoice;
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

export async function getDashboardBillingInvoiceActivity(
  invoiceId: string,
): Promise<DashboardBillingInvoiceActivity> {
  const normalizedInvoiceId = String(invoiceId || '').trim();
  if (!normalizedInvoiceId) throw new Error('Invoice id is required');
  const body = (await fetchJson(
    `/console/billing/invoices/${encodeURIComponent(normalizedInvoiceId)}/activity`,
  )) as ConsoleInvoiceActivityResponse;
  const activity = decodeInvoiceActivity(body.activity);
  if (!activity) throw new Error('Billing invoice activity response was invalid');
  return activity;
}

export async function downloadDashboardBillingInvoicePdf(invoiceId: string): Promise<void> {
  const normalizedInvoiceId = String(invoiceId || '').trim();
  if (!normalizedInvoiceId) throw new Error('Invoice id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/billing/invoices/${encodeURIComponent(normalizedInvoiceId)}/pdf`,
    {
      method: 'GET',
      headers: {
        Accept: 'application/pdf, application/json',
      },
      credentials: 'include',
      cache: 'no-store',
    },
  );
  if (!response.ok) {
    const contentType = String(response.headers.get('content-type') || '').toLowerCase();
    const body = contentType.includes('application/json')
      ? ((await parseConsoleJson(response)) as ConsoleBillingErrorBody | null)
      : null;
    throw buildBillingApiError(response, body, 'Invoice PDF download failed');
  }
  const blob = await response.blob();
  const fallbackFilename = `invoice_${normalizedInvoiceId}.pdf`;
  const filename =
    parseContentDispositionFilename(response.headers.get('content-disposition')) ||
    fallbackFilename;
  const objectUrl = window.URL.createObjectURL(blob);
  try {
    const anchor = document.createElement('a');
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.rel = 'noopener';
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    window.URL.revokeObjectURL(objectUrl);
  }
}

export async function listDashboardBillingPaymentMethods(): Promise<
  DashboardBillingPaymentMethod[]
> {
  const body = (await fetchJson(
    '/console/billing/payment-methods',
  )) as ConsolePaymentMethodsResponse;
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
    throw buildBillingApiError(response, body, 'Add card payment method request failed');
  }
  const paymentMethod = decodePaymentMethod(body.paymentMethod);
  if (!paymentMethod) throw new Error('Add card payment method response was invalid');
  return paymentMethod;
}

export async function removeDashboardCardPaymentMethod(paymentMethodId: string): Promise<boolean> {
  const normalizedId = String(paymentMethodId || '').trim();
  if (!normalizedId) throw new Error('Payment method id is required');
  const base = requireConsoleBaseUrl();
  const response = await fetch(
    `${base}/console/billing/payment-methods/${encodeURIComponent(normalizedId)}`,
    {
      method: 'DELETE',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    },
  );
  const body = (await parseConsoleJson(response)) as ConsolePaymentMethodResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(response, body, 'Remove card payment method request failed');
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
    throw buildBillingApiError(response, body, 'Set default card payment method request failed');
  }
  const paymentMethod = decodePaymentMethod(body.paymentMethod);
  if (!paymentMethod) throw new Error('Set default card payment method response was invalid');
  return paymentMethod;
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
    throw buildBillingApiError(response, body, 'Stripe setup intent request failed');
  }
  const setupIntent = decodeStripeSetupIntent(body.setupIntent);
  if (!setupIntent) throw new Error('Stripe setup intent response was invalid');
  return setupIntent;
}

export async function createDashboardStripeCheckoutSession(
  input: DashboardStripeCheckoutSessionRequest,
): Promise<DashboardStripeCheckoutSession> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/checkout-session`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleStripeCheckoutSessionResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(response, body, 'Stripe checkout session request failed');
  }
  const checkoutSession = decodeStripeCheckoutSession(body.checkoutSession);
  if (!checkoutSession) throw new Error('Stripe checkout session response was invalid');
  return checkoutSession;
}

export async function createDashboardStripeCustomerPortalSession(
  input: DashboardStripeCustomerPortalSessionRequest,
): Promise<DashboardStripeCustomerPortalSession> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/customer-portal-session`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(
    response,
  )) as ConsoleStripeCustomerPortalSessionResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(response, body, 'Stripe customer portal session request failed');
  }
  const portalSession = decodeStripeCustomerPortalSession(body.portalSession);
  if (!portalSession) throw new Error('Stripe customer portal session response was invalid');
  return portalSession;
}

export function formatUsdMinor(amountMinor: number): string {
  const n = Number(amountMinor || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
