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
  liveEnvironmentState: 'HEALTHY' | 'LOW_BALANCE' | 'BLOCKED';
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
  visibility: 'CUSTOMER' | 'INTERNAL';
}

export interface DashboardBillingInvoiceActivity {
  invoice: DashboardBillingInvoice;
  entries: DashboardBillingInvoiceActivityEntry[];
}

export interface DashboardBillingAccountActivityEntry {
  id: string;
  orgId: string;
  type: string;
  amountMinor: number;
  currency: 'USD';
  description: string;
  monthUtc: string | null;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
  actorType: 'USER' | 'SYSTEM' | 'PROVIDER';
  actorUserId: string | null;
  reasonCode: string | null;
  note: string | null;
  idempotencyKey: string | null;
  createdAt: string;
}

export type DashboardBillingManualAdjustmentKind = 'support_credit' | 'admin_debit';

export interface DashboardBillingManualAdjustmentRequest {
  amountMinor: number;
  reasonCode: string;
  note: string;
  idempotencyKey: string;
  relatedInvoiceId?: string;
}

export interface DashboardBillingManualAdjustmentResult {
  created: boolean;
  adjustment: DashboardBillingAccountActivityEntry;
  creditBalanceMinor: number;
}

export type DashboardBillingCreditPackId = 'usd_10' | 'usd_25' | 'usd_50' | 'usd_custom';

export interface DashboardStripeCheckoutSessionRequest {
  successUrl: string;
  cancelUrl: string;
  creditPackId: DashboardBillingCreditPackId;
  customAmountMinor?: number;
}

export interface DashboardStripeCheckoutSession {
  id: string;
  url: string;
  customerRef: string;
  creditPackId: DashboardBillingCreditPackId;
  amountMinor: number;
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

interface ConsoleAccountActivityResponse {
  ok?: boolean;
  message?: string;
  activity?: unknown;
}

interface ConsoleBillingManualAdjustmentResponse {
  ok?: boolean;
  message?: string;
  result?: unknown;
}

interface ConsoleStripeCheckoutSessionResponse {
  ok?: boolean;
  message?: string;
  checkoutSession?: unknown;
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
  const creditBalanceMinor = Number(row.creditBalanceMinor || 0);
  const lowBalanceThresholdMinor = Number(row.lowBalanceThresholdMinor || 0);
  const liveEnvironmentStateRaw = String(row.liveEnvironmentState || '')
    .trim()
    .toUpperCase();
  return {
    usageMetricVersion: String(row.usageMetricVersion || '').trim() || 'maw_v1',
    currentMonthUtc,
    monthlyActiveWallets: Number(row.monthlyActiveWallets || 0),
    creditBalanceMinor,
    lowBalanceThresholdMinor,
    liveEnvironmentState:
      liveEnvironmentStateRaw === 'BLOCKED' || liveEnvironmentStateRaw === 'LOW_BALANCE'
        ? liveEnvironmentStateRaw
        : creditBalanceMinor <= 0
          ? 'BLOCKED'
          : creditBalanceMinor <= lowBalanceThresholdMinor
            ? 'LOW_BALANCE'
            : 'HEALTHY',
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
    visibility:
      String(row.visibility || '')
        .trim()
        .toUpperCase() === 'INTERNAL'
        ? 'INTERNAL'
        : 'CUSTOMER',
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

function decodeAccountActivityEntry(raw: unknown): DashboardBillingAccountActivityEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  if (!id || !orgId) return null;
  const actorType = String(row.actorType || '')
    .trim()
    .toUpperCase();
  return {
    id,
    orgId,
    type: String(row.type || '').trim() || 'MANUAL_ADJUSTMENT',
    amountMinor: Number(row.amountMinor || 0),
    currency: 'USD',
    description: String(row.description || '').trim(),
    monthUtc: row.monthUtc == null ? null : String(row.monthUtc || '').trim() || null,
    relatedInvoiceId:
      row.relatedInvoiceId == null ? null : String(row.relatedInvoiceId || '').trim() || null,
    relatedPurchaseId:
      row.relatedPurchaseId == null ? null : String(row.relatedPurchaseId || '').trim() || null,
    sourceEventId:
      row.sourceEventId == null ? null : String(row.sourceEventId || '').trim() || null,
    actorType: actorType === 'USER' || actorType === 'PROVIDER' ? actorType : 'SYSTEM',
    actorUserId: row.actorUserId == null ? null : String(row.actorUserId || '').trim() || null,
    reasonCode: row.reasonCode == null ? null : String(row.reasonCode || '').trim() || null,
    note: row.note == null ? null : String(row.note || '').trim() || null,
    idempotencyKey:
      row.idempotencyKey == null ? null : String(row.idempotencyKey || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
  };
}

function decodeAccountActivity(
  raw: unknown,
): { entries: DashboardBillingAccountActivityEntry[] } | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const entriesRaw = Array.isArray(row.entries) ? row.entries : [];
  return {
    entries: entriesRaw
      .map((entry) => decodeAccountActivityEntry(entry))
      .filter((entry): entry is DashboardBillingAccountActivityEntry => entry !== null),
  };
}

function decodeBillingManualAdjustmentResult(
  raw: unknown,
): DashboardBillingManualAdjustmentResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const adjustment = decodeAccountActivityEntry(row.adjustment);
  if (!adjustment) return null;
  return {
    created: row.created === true,
    adjustment,
    creditBalanceMinor: Number(row.creditBalanceMinor || 0),
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

export async function listDashboardBillingAccountActivity(
  limit = 25,
): Promise<DashboardBillingAccountActivityEntry[]> {
  const params = new URLSearchParams();
  if (Number.isFinite(limit) && limit > 0) {
    params.set('limit', String(Math.floor(limit)));
  }
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/account/activity${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleAccountActivityResponse;
  const activity = decodeAccountActivity(body.activity);
  if (!activity) throw new Error('Billing account activity response was invalid');
  return activity.entries;
}

async function postBillingManualAdjustment(
  kind: DashboardBillingManualAdjustmentKind,
  input: DashboardBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  const base = requireConsoleBaseUrl();
  const endpoint =
    kind === 'support_credit'
      ? '/console/billing/adjustments/support-credit'
      : '/console/billing/adjustments/admin-debit';
  const response = await fetch(`${base}${endpoint}`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleBillingManualAdjustmentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(response, body, 'Billing manual adjustment request failed');
  }
  const result = decodeBillingManualAdjustmentResult(body.result);
  if (!result) throw new Error('Billing manual adjustment response was invalid');
  return result;
}

export async function createDashboardBillingManualSupportCredit(
  input: DashboardBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  return postBillingManualAdjustment('support_credit', input);
}

export async function createDashboardBillingManualAdminDebit(
  input: DashboardBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  return postBillingManualAdjustment('admin_debit', input);
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
  if (!invoice) throw new Error('Billing document response was invalid');
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
  if (!activity) throw new Error('Billing document activity response was invalid');
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

export function formatUsdMinor(amountMinor: number): string {
  const n = Number(amountMinor || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
