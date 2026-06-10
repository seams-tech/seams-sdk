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
  reservedSponsorshipMinor: number;
  activeSponsorshipReservationCount: number;
  trailing30DaySponsoredSpendMinor: number;
  trailing30DaySponsoredExecutionCount: number;
  trailing90DaySponsoredSpendMinor: number;
  trailing90DaySponsoredExecutionCount: number;
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
  type: DashboardBillingAccountActivityEventType;
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

export interface DashboardSponsoredExecutionHistoryEntry {
  id: string;
  environmentId: string;
  apiKeyId: string;
  apiKeyKind: 'secret_key' | 'publishable_key';
  route: string;
  policyId: string;
  policyNameAtEvent: string | null;
  templateId: string | null;
  chainFamily: 'evm' | 'near';
  intentKind: 'evm_call' | 'near_delegate';
  executorKind: 'evm_eoa' | 'near_delegate';
  accountRef: string;
  targetRef: string;
  sponsorRef: string;
  txOrExecutionRef: string | null;
  receiptStatus: 'success' | 'reverted' | 'broadcast_failed' | 'rpc_rejected';
  feeUnit: 'wei' | 'yocto_near';
  feeAmount: string;
  estimatedSpendMinor: number | null;
  settledSpendMinor: number | null;
  pricingVersion: string | null;
  pricingSource: string | null;
  billingLedgerEntryId: string | null;
  prepaidReservationId: string | null;
  charged: boolean;
  chargedReason: string | null;
  settledAt: string | null;
  errorCode: string | null;
  errorMessage: string | null;
  idempotencyKey: string | null;
  createdAt: string;
}

export interface DashboardSponsoredExecutionHistoryPage {
  items: DashboardSponsoredExecutionHistoryEntry[];
  nextCursor: string | null;
}

export type DashboardSponsoredExecutionReconciliationStatus =
  | 'matched'
  | 'not_charged'
  | 'missing_billing_debit'
  | 'amount_mismatch'
  | 'unexpected_billing_debit';

export interface DashboardSponsoredExecutionReconciliationEntry {
  record: DashboardSponsoredExecutionHistoryEntry;
  billingDebit: DashboardBillingAccountActivityEntry | null;
  status: DashboardSponsoredExecutionReconciliationStatus;
  mismatchReasons: string[];
}

export interface DashboardSponsoredExecutionReconciliationSummary {
  matchedCount: number;
  notChargedCount: number;
  missingBillingDebitCount: number;
  amountMismatchCount: number;
  unexpectedBillingDebitCount: number;
  mismatchCount: number;
}

export interface DashboardSponsoredExecutionReconciliationPage {
  items: DashboardSponsoredExecutionReconciliationEntry[];
  nextCursor: string | null;
  summary: DashboardSponsoredExecutionReconciliationSummary;
}

export interface DashboardSponsoredExecutionHistoryRequest {
  environmentId?: string;
  policyId?: string;
  chainFamily?: 'evm' | 'near';
  receiptStatus?: 'success' | 'reverted' | 'broadcast_failed' | 'rpc_rejected';
  charged?: boolean;
  limit?: number;
  cursor?: string;
  lookbackDays?: number;
}

export type DashboardBillingAccountActivityEventType =
  | 'CREDIT_PURCHASE'
  | 'USAGE_DEBIT'
  | 'SPONSORED_EXECUTION_DEBIT'
  | 'MANUAL_ADJUSTMENT'
  | 'REFUND'
  | 'REVERSAL';

export interface DashboardBillingCreditPurchase {
  id: string;
  orgId: string;
  creditPackId: DashboardBillingCreditPackId;
  status: 'PENDING' | 'SETTLED' | 'CANCELED';
  amountMinor: number;
  currency: 'USD';
  providerCheckoutSessionRef: string;
  providerCustomerRef: string | null;
  relatedInvoiceId: string | null;
  settledAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export type DashboardBillingManualAdjustmentKind = 'support_credit' | 'admin_debit';

export interface DashboardBillingManualAdjustmentRequest {
  amountMinor: number;
  reasonCode: string;
  note: string;
  idempotencyKey: string;
  relatedInvoiceId?: string;
}

export interface DashboardPlatformBillingManualAdjustmentRequest extends DashboardBillingManualAdjustmentRequest {
  orgId: string;
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

export interface DashboardStripeCheckoutSessionReconcileRequest {
  checkoutSessionId: string;
}

export interface DashboardStripeCheckoutSessionReconcileResult {
  settled: boolean;
  settledNow: boolean;
  paymentStatus: string | null;
  checkoutStatus: string | null;
  purchase: DashboardBillingCreditPurchase | null;
  invoice: DashboardBillingInvoice | null;
}

export interface DashboardPlatformBillingOrganization {
  id: string;
  name: string;
  slug: string;
  status: string;
}

export interface DashboardPlatformBillingProject {
  id: string;
  orgId: string;
  name: string;
  slug: string;
  status: string;
  environmentCount: number;
}

export type DashboardPlatformBillingOrganizationMemberAccess = 'OWNER' | 'ADMIN' | 'MEMBER';
export type DashboardPlatformBillingOrganizationMemberStatus =
  | 'ACTIVE'
  | 'INVITED'
  | 'SUSPENDED';

export interface DashboardPlatformBillingOrganizationMember {
  id: string;
  userId: string;
  email: string;
  displayName: string;
  status: DashboardPlatformBillingOrganizationMemberStatus;
  access: DashboardPlatformBillingOrganizationMemberAccess;
  addedAt: string;
}

export interface DashboardPlatformBillingLookupRequest {
  orgId?: string;
  projectId?: string;
  limit?: number;
  periodMonthUtc?: string;
  eventType?: DashboardBillingAccountActivityEventType;
}

export interface DashboardPlatformBillingSearchRequest {
  query: string;
  limit?: number;
}

export interface DashboardPlatformBillingLookupResult {
  resolvedBy: 'org_id' | 'project_id';
  organization: DashboardPlatformBillingOrganization;
  project: DashboardPlatformBillingProject | null;
  overview: DashboardBillingOverview;
  activity: DashboardBillingAccountActivityEntry[];
  teamMembers: DashboardPlatformBillingOrganizationMember[];
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

interface ConsoleSponsoredExecutionHistoryResponse {
  ok?: boolean;
  message?: string;
  page?: unknown;
}

interface ConsoleSponsoredExecutionReconciliationResponse {
  ok?: boolean;
  message?: string;
  page?: unknown;
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

interface ConsoleStripeCheckoutSessionReconcileResponse {
  ok?: boolean;
  message?: string;
  result?: unknown;
}

interface ConsolePlatformBillingLookupResponse {
  ok?: boolean;
  message?: string;
  result?: unknown;
}

interface ConsolePlatformBillingSearchResponse {
  ok?: boolean;
  message?: string;
  organizations?: unknown;
}

interface ConsoleBillingErrorBody {
  ok?: boolean;
  code?: unknown;
  message?: unknown;
  details?: unknown;
}

const PLATFORM_BILLING_MEMBER_STATUS_SET = new Set<DashboardPlatformBillingOrganizationMemberStatus>(
  ['ACTIVE', 'INVITED', 'SUSPENDED'],
);
const PLATFORM_BILLING_MEMBER_ACCESS_SET = new Set<DashboardPlatformBillingOrganizationMemberAccess>(
  ['OWNER', 'ADMIN', 'MEMBER'],
);

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
    reservedSponsorshipMinor: Number(row.reservedSponsorshipMinor || 0),
    activeSponsorshipReservationCount: Number(row.activeSponsorshipReservationCount || 0),
    trailing30DaySponsoredSpendMinor: Number(row.trailing30DaySponsoredSpendMinor || 0),
    trailing30DaySponsoredExecutionCount: Number(row.trailing30DaySponsoredExecutionCount || 0),
    trailing90DaySponsoredSpendMinor: Number(row.trailing90DaySponsoredSpendMinor || 0),
    trailing90DaySponsoredExecutionCount: Number(row.trailing90DaySponsoredExecutionCount || 0),
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

function decodeCreditPurchase(raw: unknown): DashboardBillingCreditPurchase | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const creditPackId = String(row.creditPackId || '').trim();
  const providerCheckoutSessionRef = String(row.providerCheckoutSessionRef || '').trim();
  if (!id || !orgId || !creditPackId || !providerCheckoutSessionRef) return null;
  const status = String(row.status || '')
    .trim()
    .toUpperCase();
  return {
    id,
    orgId,
    creditPackId: creditPackId as DashboardBillingCreditPurchase['creditPackId'],
    status: status === 'SETTLED' || status === 'CANCELED' ? status : 'PENDING',
    amountMinor: Number(row.amountMinor || 0),
    currency: 'USD',
    providerCheckoutSessionRef,
    providerCustomerRef:
      row.providerCustomerRef == null ? null : String(row.providerCustomerRef || '').trim() || null,
    relatedInvoiceId:
      row.relatedInvoiceId == null ? null : String(row.relatedInvoiceId || '').trim() || null,
    settledAt: row.settledAt == null ? null : String(row.settledAt || '').trim() || null,
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
  };
}

function decodeStripeCheckoutSessionReconcileResult(
  raw: unknown,
): DashboardStripeCheckoutSessionReconcileResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  return {
    settled: Boolean(row.settled),
    settledNow: Boolean(row.settledNow),
    paymentStatus:
      row.paymentStatus == null ? null : String(row.paymentStatus || '').trim() || null,
    checkoutStatus:
      row.checkoutStatus == null ? null : String(row.checkoutStatus || '').trim() || null,
    purchase: decodeCreditPurchase(row.purchase),
    invoice: decodeInvoice(row.invoice),
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
  const eventType = String(row.type || '')
    .trim()
    .toUpperCase();
  return {
    id,
    orgId,
    type:
      eventType === 'CREDIT_PURCHASE' ||
      eventType === 'USAGE_DEBIT' ||
      eventType === 'SPONSORED_EXECUTION_DEBIT' ||
      eventType === 'REFUND' ||
      eventType === 'REVERSAL'
        ? eventType
        : 'MANUAL_ADJUSTMENT',
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

function decodePlatformBillingOrganization(
  raw: unknown,
): DashboardPlatformBillingOrganization | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  return {
    id,
    name: String(row.name || '').trim() || id,
    slug: String(row.slug || '').trim(),
    status: String(row.status || '').trim() || 'ACTIVE',
  };
}

function decodePlatformBillingProject(raw: unknown): DashboardPlatformBillingProject | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  if (!id) return null;
  return {
    id,
    orgId: String(row.orgId || '').trim(),
    name: String(row.name || '').trim() || id,
    slug: String(row.slug || '').trim(),
    status: String(row.status || '').trim() || 'ACTIVE',
    environmentCount: Number(row.environmentCount || 0),
  };
}

function decodePlatformBillingOrganizationMember(
  raw: unknown,
): DashboardPlatformBillingOrganizationMember | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const userId = String(row.userId || '').trim();
  const email = String(row.email || '').trim();
  const displayName = String(row.displayName || '').trim();
  const status = String(row.status || '')
    .trim()
    .toUpperCase() as DashboardPlatformBillingOrganizationMemberStatus;
  const access = String(row.access || '')
    .trim()
    .toUpperCase() as DashboardPlatformBillingOrganizationMemberAccess;
  const addedAt = String(row.addedAt || '').trim();
  if (
    !id ||
    !userId ||
    !email ||
    !displayName ||
    !addedAt ||
    !PLATFORM_BILLING_MEMBER_STATUS_SET.has(status) ||
    !PLATFORM_BILLING_MEMBER_ACCESS_SET.has(access)
  ) {
    return null;
  }
  return {
    id,
    userId,
    email,
    displayName,
    status,
    access,
    addedAt,
  };
}

function decodePlatformBillingOrganizationMembers(
  raw: unknown,
): DashboardPlatformBillingOrganizationMember[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => decodePlatformBillingOrganizationMember(entry))
    .filter((entry): entry is DashboardPlatformBillingOrganizationMember => entry !== null);
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

function decodeSponsoredExecutionHistoryEntry(
  raw: unknown,
): DashboardSponsoredExecutionHistoryEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const environmentId = String(row.environmentId || '').trim();
  const apiKeyId = String(row.apiKeyId || '').trim();
  const route = String(row.route || '').trim();
  const policyId = String(row.policyId || '').trim();
  const accountRef = String(row.accountRef || '').trim();
  const targetRef = String(row.targetRef || '').trim();
  const sponsorRef = String(row.sponsorRef || '').trim();
  const createdAt = String(row.createdAt || '').trim();
  if (!id || !environmentId || !apiKeyId || !route || !policyId || !accountRef || !targetRef || !sponsorRef || !createdAt) {
    return null;
  }
  const apiKeyKind = String(row.apiKeyKind || '').trim().toLowerCase();
  const chainFamily = String(row.chainFamily || '').trim().toLowerCase();
  const intentKind = String(row.intentKind || '').trim().toLowerCase();
  const executorKind = String(row.executorKind || '').trim().toLowerCase();
  const receiptStatus = String(row.receiptStatus || '').trim().toLowerCase();
  const feeUnit = String(row.feeUnit || '').trim().toLowerCase();
  if (
    (apiKeyKind !== 'secret_key' && apiKeyKind !== 'publishable_key') ||
    (chainFamily !== 'evm' && chainFamily !== 'near') ||
    (intentKind !== 'evm_call' && intentKind !== 'near_delegate') ||
    (executorKind !== 'evm_eoa' && executorKind !== 'near_delegate') ||
    (receiptStatus !== 'success' &&
      receiptStatus !== 'reverted' &&
      receiptStatus !== 'broadcast_failed' &&
      receiptStatus !== 'rpc_rejected') ||
    (feeUnit !== 'wei' && feeUnit !== 'yocto_near')
  ) {
    return null;
  }
  return {
    id,
    environmentId,
    apiKeyId,
    apiKeyKind,
    route,
    policyId,
    policyNameAtEvent: row.policyNameAtEvent == null ? null : String(row.policyNameAtEvent || '').trim() || null,
    templateId: row.templateId == null ? null : String(row.templateId || '').trim() || null,
    chainFamily,
    intentKind,
    executorKind,
    accountRef,
    targetRef,
    sponsorRef,
    txOrExecutionRef: row.txOrExecutionRef == null ? null : String(row.txOrExecutionRef || '').trim() || null,
    receiptStatus,
    feeUnit,
    feeAmount: String(row.feeAmount || '0').trim() || '0',
    estimatedSpendMinor: row.estimatedSpendMinor == null ? null : Number(row.estimatedSpendMinor || 0),
    settledSpendMinor: row.settledSpendMinor == null ? null : Number(row.settledSpendMinor || 0),
    pricingVersion: row.pricingVersion == null ? null : String(row.pricingVersion || '').trim() || null,
    pricingSource: row.pricingSource == null ? null : String(row.pricingSource || '').trim() || null,
    billingLedgerEntryId:
      row.billingLedgerEntryId == null ? null : String(row.billingLedgerEntryId || '').trim() || null,
    prepaidReservationId:
      row.prepaidReservationId == null ? null : String(row.prepaidReservationId || '').trim() || null,
    charged: row.charged === true,
    chargedReason: row.chargedReason == null ? null : String(row.chargedReason || '').trim() || null,
    settledAt: row.settledAt == null ? null : String(row.settledAt || '').trim() || null,
    errorCode: row.errorCode == null ? null : String(row.errorCode || '').trim() || null,
    errorMessage: row.errorMessage == null ? null : String(row.errorMessage || '').trim() || null,
    idempotencyKey: row.idempotencyKey == null ? null : String(row.idempotencyKey || '').trim() || null,
    createdAt,
  };
}

function decodeSponsoredExecutionHistoryPage(
  raw: unknown,
): DashboardSponsoredExecutionHistoryPage | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const itemsRaw = Array.isArray(row.items) ? row.items : [];
  return {
    items: itemsRaw
      .map((entry) => decodeSponsoredExecutionHistoryEntry(entry))
      .filter((entry): entry is DashboardSponsoredExecutionHistoryEntry => entry !== null),
    nextCursor: row.nextCursor == null ? null : String(row.nextCursor || '').trim() || null,
  };
}

function decodeSponsoredExecutionReconciliationEntry(
  raw: unknown,
): DashboardSponsoredExecutionReconciliationEntry | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const record = decodeSponsoredExecutionHistoryEntry(row.record);
  if (!record) return null;
  const status = String(row.status || '').trim().toLowerCase();
  if (
    status !== 'matched' &&
    status !== 'not_charged' &&
    status !== 'missing_billing_debit' &&
    status !== 'amount_mismatch' &&
    status !== 'unexpected_billing_debit'
  ) {
    return null;
  }
  const billingDebit = row.billingDebit == null ? null : decodeAccountActivityEntry(row.billingDebit);
  const mismatchReasonsRaw = Array.isArray(row.mismatchReasons) ? row.mismatchReasons : [];
  return {
    record,
    billingDebit,
    status,
    mismatchReasons: mismatchReasonsRaw
      .map((value) => String(value || '').trim())
      .filter((value) => value.length > 0),
  };
}

function decodeSponsoredExecutionReconciliationPage(
  raw: unknown,
): DashboardSponsoredExecutionReconciliationPage | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const itemsRaw = Array.isArray(row.items) ? row.items : [];
  const summary =
    row.summary && typeof row.summary === 'object' && !Array.isArray(row.summary)
      ? (row.summary as Record<string, unknown>)
      : null;
  if (!summary) return null;
  return {
    items: itemsRaw
      .map((entry) => decodeSponsoredExecutionReconciliationEntry(entry))
      .filter((entry): entry is DashboardSponsoredExecutionReconciliationEntry => entry !== null),
    nextCursor: row.nextCursor == null ? null : String(row.nextCursor || '').trim() || null,
    summary: {
      matchedCount: Number(summary.matchedCount || 0),
      notChargedCount: Number(summary.notChargedCount || 0),
      missingBillingDebitCount: Number(summary.missingBillingDebitCount || 0),
      amountMismatchCount: Number(summary.amountMismatchCount || 0),
      unexpectedBillingDebitCount: Number(summary.unexpectedBillingDebitCount || 0),
      mismatchCount: Number(summary.mismatchCount || 0),
    },
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

function decodePlatformBillingLookupResult(
  raw: unknown,
): DashboardPlatformBillingLookupResult | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const organization = decodePlatformBillingOrganization(row.organization);
  const overview = decodeOverview(row.overview);
  const activity = decodeAccountActivity(row.activity);
  if (!organization || !overview || !activity) return null;
  const resolvedByRaw = String(row.resolvedBy || '')
    .trim()
    .toLowerCase();
  return {
    resolvedBy: resolvedByRaw === 'project_id' ? 'project_id' : 'org_id',
    organization,
    project: row.project == null ? null : decodePlatformBillingProject(row.project),
    overview,
    activity: activity.entries,
    teamMembers: decodePlatformBillingOrganizationMembers(row.teamMembers),
  };
}

function decodePlatformBillingOrganizations(
  raw: unknown,
): DashboardPlatformBillingOrganization[] | null {
  if (!Array.isArray(raw)) return null;
  return raw
    .map((entry) => decodePlatformBillingOrganization(entry))
    .filter((entry): entry is DashboardPlatformBillingOrganization => entry !== null);
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
  input: {
    limit?: number;
    periodMonthUtc?: string;
    eventType?: DashboardBillingAccountActivityEventType;
  } = {},
): Promise<DashboardBillingAccountActivityEntry[]> {
  const params = new URLSearchParams();
  if (Number.isFinite(input.limit) && Number(input.limit) > 0) {
    params.set('limit', String(Math.floor(Number(input.limit))));
  }
  if (input.periodMonthUtc) params.set('periodMonthUtc', input.periodMonthUtc);
  if (input.eventType) params.set('eventType', input.eventType);
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/account/activity${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleAccountActivityResponse;
  const activity = decodeAccountActivity(body.activity);
  if (!activity) throw new Error('Billing account activity response was invalid');
  return activity.entries;
}

export async function listDashboardSponsoredExecutionHistory(
  input: DashboardSponsoredExecutionHistoryRequest = {},
): Promise<DashboardSponsoredExecutionHistoryPage> {
  const params = new URLSearchParams();
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.policyId) params.set('policyId', input.policyId);
  if (input.chainFamily) params.set('chainFamily', input.chainFamily);
  if (input.receiptStatus) params.set('receiptStatus', input.receiptStatus);
  if (typeof input.charged === 'boolean') params.set('charged', input.charged ? 'true' : 'false');
  if (Number.isFinite(input.limit) && Number(input.limit) > 0) {
    params.set('limit', String(Math.floor(Number(input.limit))));
  }
  if (input.cursor) params.set('cursor', input.cursor);
  if (Number.isFinite(input.lookbackDays) && Number(input.lookbackDays) > 0) {
    params.set('lookbackDays', String(Math.floor(Number(input.lookbackDays))));
  }
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/sponsored-executions${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleSponsoredExecutionHistoryResponse;
  const page = decodeSponsoredExecutionHistoryPage(body.page);
  if (!page) throw new Error('Sponsored execution history response was invalid');
  return page;
}

export async function listDashboardSponsoredExecutionReconciliation(
  input: DashboardSponsoredExecutionHistoryRequest = {},
): Promise<DashboardSponsoredExecutionReconciliationPage> {
  const params = new URLSearchParams();
  if (input.environmentId) params.set('environmentId', input.environmentId);
  if (input.policyId) params.set('policyId', input.policyId);
  if (input.chainFamily) params.set('chainFamily', input.chainFamily);
  if (input.receiptStatus) params.set('receiptStatus', input.receiptStatus);
  if (typeof input.charged === 'boolean') params.set('charged', input.charged ? 'true' : 'false');
  if (Number.isFinite(input.limit) && Number(input.limit) > 0) {
    params.set('limit', String(Math.floor(Number(input.limit))));
  }
  if (input.cursor) params.set('cursor', input.cursor);
  if (Number.isFinite(input.lookbackDays) && Number(input.lookbackDays) > 0) {
    params.set('lookbackDays', String(Math.floor(Number(input.lookbackDays))));
  }
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/billing/sponsored-executions/reconciliation${suffix ? `?${suffix}` : ''}`,
  )) as ConsoleSponsoredExecutionReconciliationResponse;
  const page = decodeSponsoredExecutionReconciliationPage(body.page);
  if (!page) throw new Error('Sponsored execution reconciliation response was invalid');
  return page;
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

export async function getDashboardPlatformBillingAccount(
  input: DashboardPlatformBillingLookupRequest,
): Promise<DashboardPlatformBillingLookupResult> {
  const params = new URLSearchParams();
  if (input.orgId) params.set('orgId', input.orgId);
  if (input.projectId) params.set('projectId', input.projectId);
  if (input.periodMonthUtc) params.set('periodMonthUtc', input.periodMonthUtc);
  if (input.eventType) params.set('eventType', input.eventType);
  if (input.limit && Number.isFinite(input.limit) && input.limit > 0) {
    params.set('limit', String(Math.floor(input.limit)));
  }
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/platform/billing/account${suffix ? `?${suffix}` : ''}`,
  )) as ConsolePlatformBillingLookupResponse;
  const result = decodePlatformBillingLookupResult(body.result);
  if (!result) throw new Error('Platform billing lookup response was invalid');
  return result;
}

export async function searchDashboardPlatformBillingOrganizations(
  input: DashboardPlatformBillingSearchRequest,
): Promise<DashboardPlatformBillingOrganization[]> {
  const params = new URLSearchParams();
  params.set('query', String(input.query || '').trim());
  if (input.limit && Number.isFinite(input.limit) && input.limit > 0) {
    params.set('limit', String(Math.floor(input.limit)));
  }
  const suffix = params.toString();
  const body = (await fetchJson(
    `/console/platform/billing/search${suffix ? `?${suffix}` : ''}`,
  )) as ConsolePlatformBillingSearchResponse;
  const organizations = decodePlatformBillingOrganizations(body.organizations);
  if (!organizations) throw new Error('Platform billing organization search response was invalid');
  return organizations;
}

async function postPlatformBillingManualAdjustment(
  kind: DashboardBillingManualAdjustmentKind,
  input: DashboardPlatformBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  const base = requireConsoleBaseUrl();
  const endpoint =
    kind === 'support_credit'
      ? '/console/platform/billing/adjustments/support-credit'
      : '/console/platform/billing/adjustments/admin-debit';
  const response = await fetch(`${base}${endpoint}`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(response)) as ConsoleBillingManualAdjustmentResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(response, body, 'Platform billing manual adjustment request failed');
  }
  const result = decodeBillingManualAdjustmentResult(body.result);
  if (!result) throw new Error('Platform billing manual adjustment response was invalid');
  return result;
}

export async function createDashboardPlatformBillingManualSupportCredit(
  input: DashboardPlatformBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  return postPlatformBillingManualAdjustment('support_credit', input);
}

export async function createDashboardPlatformBillingManualAdminDebit(
  input: DashboardPlatformBillingManualAdjustmentRequest,
): Promise<DashboardBillingManualAdjustmentResult> {
  return postPlatformBillingManualAdjustment('admin_debit', input);
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

export async function reconcileDashboardStripeCheckoutSession(
  input: DashboardStripeCheckoutSessionReconcileRequest,
): Promise<DashboardStripeCheckoutSessionReconcileResult> {
  const base = requireConsoleBaseUrl();
  const response = await fetch(`${base}/console/billing/stripe/checkout-session/reconcile`, {
    method: 'POST',
    headers: buildConsoleJsonHeaders(),
    credentials: 'include',
    cache: 'no-store',
    body: JSON.stringify(input),
  });
  const body = (await parseConsoleJson(
    response,
  )) as ConsoleStripeCheckoutSessionReconcileResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw buildBillingApiError(
      response,
      body as ConsoleBillingErrorBody | null,
      'Stripe checkout reconciliation failed',
    );
  }
  const result = decodeStripeCheckoutSessionReconcileResult(body.result);
  if (!result) throw new Error('Stripe checkout reconciliation response was invalid');
  return result;
}

export function formatUsdMinor(amountMinor: number): string {
  const n = Number(amountMinor || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}
