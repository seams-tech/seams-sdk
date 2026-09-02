import { secureRandomBase36 } from '../boundary';
import { ConsoleBillingError } from './errors';
import { resolveCreditPackAmountMinorOrThrow } from './creditPacks';
import {
  resolveBillingProviderAdapters,
  type BillingProviderAdapters,
  type StripeRefundProviderOutput,
} from './providers';
import { resolveBillingLiveEnvironmentState } from './readiness';
import { billingBalanceFromEntries, buildBillingBalancedPostings } from './ledger';
import {
  normalizeManualAdjustmentRequest,
  requireKnownManualAdjustmentRelatedInvoiceId,
} from './adjustments';
import {
  buildBillingStripePostProcessingPayload,
  type BillingStripePostProcessingEffect,
  type BillingStripePostProcessingOutboxItem,
} from './stripePostProcessing';
import type {
  BillingCreditPurchase,
  BillingDispute,
  BillingInvoiceActivity,
  BillingInvoiceActivityEntry,
  BillingInvoice,
  BillingInvoiceLineItem,
  BillingInvoiceLineItemType,
  BillingInvoiceListRequest,
  BillingInvoiceListResult,
  BillingInvoiceListSummary,
  BillingLedgerEntry,
  BillingAccountActivityRequest,
  BillingAccountActivityResult,
  BillingManualAdjustmentRequest,
  BillingManualAdjustmentResult,
  BillingMonthlyActiveResources,
  BillingOverview,
  BillingRefund,
  BillingRefundReconcileRequest,
  BillingRefundRequest,
  BillingRefundResult,
  BillingProductExecutionDebitEntry,
  BillingProductExecutionDebitRequest,
  BillingProductExecutionDebitResult,
  BillingUsageEventRequest,
  BillingUsageEventResult,
  GenerateMonthlyInvoiceRequest,
  GenerateMonthlyInvoiceResult,
  StripeCheckoutSessionReconcileRequest,
  StripeCheckoutSessionReconcileResult,
  StripeWebhookEventRequest,
  StripeWebhookEventResult,
  StripeCheckoutSession,
  StripeCheckoutSessionRequest,
  StripeProviderRefundStatus,
  StripeRefundEventItem,
} from './types';

export interface ConsoleBillingContext {
  orgId: string;
  actorUserId: string;
}

export interface ConsoleBillingRefundSupportContext extends ConsoleBillingContext {
  platformSupport: true;
}

export interface ConsoleBillingService {
  getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview>;
  getProductExecutionDebitsByIds(
    ctx: ConsoleBillingContext,
    ledgerEntryIds: string[],
  ): Promise<BillingProductExecutionDebitEntry[]>;
  listAccountActivity(
    ctx: ConsoleBillingContext,
    request?: BillingAccountActivityRequest,
  ): Promise<BillingAccountActivityResult>;
  getMonthlyActiveResources(
    ctx: ConsoleBillingContext,
    monthUtc?: string,
  ): Promise<BillingMonthlyActiveResources>;
  recordUsageEvent(
    ctx: ConsoleBillingContext,
    request: BillingUsageEventRequest,
  ): Promise<BillingUsageEventResult>;
  recordProductExecutionDebit(
    ctx: ConsoleBillingContext,
    request: BillingProductExecutionDebitRequest,
  ): Promise<BillingProductExecutionDebitResult>;
  listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]>;
  listInvoicesPage(
    ctx: ConsoleBillingContext,
    request?: BillingInvoiceListRequest,
  ): Promise<BillingInvoiceListResult>;
  getInvoice(ctx: ConsoleBillingContext, invoiceId: string): Promise<BillingInvoice | null>;
  getInvoiceActivity(
    ctx: ConsoleBillingContext,
    invoiceId: string,
  ): Promise<BillingInvoiceActivity | null>;
  listInvoiceLineItems(
    ctx: ConsoleBillingContext,
    invoiceId: string,
  ): Promise<BillingInvoiceLineItem[]>;
  generateMonthlyInvoice(
    ctx: ConsoleBillingContext,
    request: GenerateMonthlyInvoiceRequest,
  ): Promise<GenerateMonthlyInvoiceResult>;
  grantManualSupportCredit(
    ctx: ConsoleBillingContext,
    request: BillingManualAdjustmentRequest,
  ): Promise<BillingManualAdjustmentResult>;
  appendManualAdminDebit(
    ctx: ConsoleBillingContext,
    request: BillingManualAdjustmentRequest,
  ): Promise<BillingManualAdjustmentResult>;
  listRefunds(ctx: ConsoleBillingContext): Promise<BillingRefund[]>;
  createRefund(
    ctx: ConsoleBillingRefundSupportContext,
    request: BillingRefundRequest,
  ): Promise<BillingRefundResult>;
  reconcileRefund(
    ctx: ConsoleBillingRefundSupportContext,
    request: BillingRefundReconcileRequest,
  ): Promise<BillingRefundResult>;
  createStripeCheckoutSession(
    ctx: ConsoleBillingContext,
    request: StripeCheckoutSessionRequest,
  ): Promise<StripeCheckoutSession>;
  reconcileStripeCheckoutSession(
    ctx: ConsoleBillingContext,
    request: StripeCheckoutSessionReconcileRequest,
  ): Promise<StripeCheckoutSessionReconcileResult>;
  processStripeWebhookEvent(request: StripeWebhookEventRequest): Promise<StripeWebhookEventResult>;
  getStripePostProcessingOutboxItem(
    eventId: string,
  ): Promise<BillingStripePostProcessingOutboxItem | null>;
  listPendingStripePostProcessingOutboxItems(
    limit: number,
  ): Promise<BillingStripePostProcessingOutboxItem[]>;
  completeStripePostProcessingEffect(input: {
    eventId: string;
    effect: BillingStripePostProcessingEffect;
  }): Promise<BillingStripePostProcessingOutboxItem | null>;
  recordStripePostProcessingFailure(input: {
    eventId: string;
    error: string;
  }): Promise<BillingStripePostProcessingOutboxItem | null>;
}

interface OrgBillingStore {
  monthlyActiveResources: number;
  lowBalanceThresholdMinor: number;
  purchases: Map<string, BillingCreditPurchase>;
  refunds: Map<string, BillingRefund>;
  disputes: Map<string, BillingDispute>;
  ledgerEntries: BillingLedgerEntry[];
  usageEventSourceIds: Set<string>;
  monthlyActiveResourcesByMonth: Map<string, Set<string>>;
  statementProjectionCreatedAtByMonth: Map<string, string>;
}

export interface InMemoryConsoleBillingServiceOptions {
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
  consoleBaseUrl?: string;
}

const ACTIVE_RESOURCE_USAGE_DEBIT_MINOR = 300;
const DEFAULT_LOW_BALANCE_THRESHOLD_MINOR = 2000;
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;
const DEFAULT_ACCOUNT_ACTIVITY_LIMIT = 25;
const MAX_ACCOUNT_ACTIVITY_LIMIT = 100;
const DEFAULT_CONSOLE_BASE_URL = 'https://example.localhost';

export function buildStripeCheckoutReturnUrls(consoleBaseUrl?: string): {
  successUrl: string;
  cancelUrl: string;
} {
  const normalized = String(consoleBaseUrl || DEFAULT_CONSOLE_BASE_URL).trim();
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    throw new Error('Console base URL must be an absolute HTTP or HTTPS URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Console base URL must use HTTP or HTTPS');
  }
  const accountUrl = new URL('/dashboard/billing/account', parsed).toString();
  return {
    successUrl: `${accountUrl}?checkout=success&checkout_session_id={CHECKOUT_SESSION_ID}`,
    cancelUrl: `${accountUrl}?checkout=cancel`,
  };
}

function formatCurrentMonthUtc(now: Date): string {
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

function parseMonthUtcOrThrow(input: string): string {
  const value = String(input || '').trim();
  if (!/^\d{4}-\d{2}$/.test(value)) {
    throw new ConsoleBillingError('invalid_month_utc', 400, 'monthUtc must be in YYYY-MM format');
  }
  const month = Number(value.slice(5, 7));
  if (month < 1 || month > 12) {
    throw new ConsoleBillingError(
      'invalid_month_utc',
      400,
      'monthUtc month must be between 01 and 12',
    );
  }
  return value;
}

function monthUtcFromEpochMs(ms: number): string {
  return formatCurrentMonthUtc(new Date(ms));
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

function coerceIsoDate(input: Date): string {
  return input.toISOString();
}

function makeStripeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function makeInvoiceLineItem(input: {
  orgId: string;
  invoiceId: string;
  periodMonthUtc: string;
  itemType: BillingInvoiceLineItemType;
  description: string;
  quantity: number;
  unitAmountMinor: number;
  createdAt: string;
}): BillingInvoiceLineItem {
  return {
    id: `ili_${input.invoiceId}_${input.itemType.toLowerCase()}`,
    orgId: input.orgId,
    invoiceId: input.invoiceId,
    periodMonthUtc: input.periodMonthUtc,
    itemType: input.itemType,
    description: input.description,
    quantity: input.quantity,
    unitAmountMinor: input.unitAmountMinor,
    amountMinor: input.quantity * input.unitAmountMinor,
    createdAt: input.createdAt,
  };
}

function buildInvoiceLineItems(input: {
  orgId: string;
  invoiceId: string;
  periodMonthUtc: string;
  monthlyActiveResources: number;
  productExecutionDebitMinor: number;
  createdAt: string;
}): BillingInvoiceLineItem[] {
  const items: BillingInvoiceLineItem[] = [];
  if (input.monthlyActiveResources > 0) {
    items.push(
      makeInvoiceLineItem({
        orgId: input.orgId,
        invoiceId: input.invoiceId,
        periodMonthUtc: input.periodMonthUtc,
        itemType: 'ACTIVE_RESOURCE_USAGE_DEBIT',
        description: `Monthly Active Resources (${input.periodMonthUtc})`,
        quantity: input.monthlyActiveResources,
        unitAmountMinor: ACTIVE_RESOURCE_USAGE_DEBIT_MINOR,
        createdAt: input.createdAt,
      }),
    );
  }
  if (input.productExecutionDebitMinor > 0) {
    items.push(
      makeInvoiceLineItem({
        orgId: input.orgId,
        invoiceId: input.invoiceId,
        periodMonthUtc: input.periodMonthUtc,
        itemType: 'PRODUCT_EXECUTION_DEBIT',
        description: `Product execution spend (${input.periodMonthUtc})`,
        quantity: 1,
        unitAmountMinor: input.productExecutionDebitMinor,
        createdAt: input.createdAt,
      }),
    );
  }
  return items;
}

function normalizeInvoiceListLimit(limit: number | undefined): number {
  if (!Number.isFinite(Number(limit)) || Number(limit) <= 0) {
    return DEFAULT_INVOICE_LIST_LIMIT;
  }
  return Math.max(1, Math.min(MAX_INVOICE_LIST_LIMIT, Math.floor(Number(limit))));
}

function normalizeAccountActivityLimit(limit: number | undefined): number {
  if (!Number.isFinite(Number(limit)) || Number(limit) <= 0) {
    return DEFAULT_ACCOUNT_ACTIVITY_LIMIT;
  }
  return Math.max(1, Math.min(MAX_ACCOUNT_ACTIVITY_LIMIT, Math.floor(Number(limit))));
}

function isInvoiceOverdueAt(invoice: BillingInvoice, now: Date): boolean {
  if (invoice.status !== 'OPEN' || !invoice.dueAt) return false;
  const dueAtMs = Date.parse(invoice.dueAt);
  if (!Number.isFinite(dueAtMs)) return false;
  return dueAtMs < now.getTime();
}

export function parseInvoiceCursor(
  cursor: string | undefined,
): { createdAtMs: number; id: string } | null {
  const raw = String(cursor || '').trim();
  if (!raw) return null;
  const separatorIndex = raw.indexOf(':');
  if (separatorIndex <= 0 || separatorIndex === raw.length - 1) {
    throw new ConsoleBillingError('invalid_query', 400, 'Invalid invoice cursor format');
  }
  const createdAtMsRaw = raw.slice(0, separatorIndex);
  if (!/^\d+$/.test(createdAtMsRaw)) {
    throw new ConsoleBillingError('invalid_query', 400, 'Invalid invoice cursor sort key');
  }
  let id = '';
  try {
    id = decodeURIComponent(raw.slice(separatorIndex + 1));
  } catch {
    throw new ConsoleBillingError('invalid_query', 400, 'Invalid invoice cursor value');
  }
  if (!id) {
    throw new ConsoleBillingError('invalid_query', 400, 'Invalid invoice cursor value');
  }
  const createdAtMs = Number.parseInt(createdAtMsRaw, 10);
  if (!Number.isSafeInteger(createdAtMs) || createdAtMs < 0) {
    throw new ConsoleBillingError('invalid_query', 400, 'Invalid invoice cursor sort key');
  }
  return { createdAtMs, id };
}

export function encodeInvoiceCursor(invoice: BillingInvoice): string {
  const createdAtMs = Date.parse(invoice.createdAt);
  const safeCreatedAtMs = Number.isFinite(createdAtMs) && createdAtMs >= 0 ? createdAtMs : 0;
  return `${safeCreatedAtMs}:${encodeURIComponent(invoice.id)}`;
}

function filterInvoicesForList(
  invoices: BillingInvoice[],
  request: BillingInvoiceListRequest | undefined,
  now: Date,
): BillingInvoice[] {
  const status = request?.status;
  const periodMonthUtc = String(request?.periodMonthUtc || '').trim();
  const documentType = request?.documentType;
  return invoices.filter((invoice) => {
    if (status && invoice.status !== status) return false;
    if (request?.overdueOnly && !isInvoiceOverdueAt(invoice, now)) return false;
    if (periodMonthUtc && invoice.periodMonthUtc !== periodMonthUtc) return false;
    if (documentType && invoice.documentType !== documentType) return false;
    return true;
  });
}

function buildInvoiceListSummary(invoices: BillingInvoice[], now: Date): BillingInvoiceListSummary {
  const openCount = invoices.filter((invoice) => invoice.status === 'OPEN').length;
  const overdueCount = invoices.filter((invoice) => isInvoiceOverdueAt(invoice, now)).length;
  const paidCount = invoices.filter((invoice) => invoice.status === 'PAID').length;
  const totalOutstandingAmountMinor = invoices.reduce((total, invoice) => {
    return total + Math.max(0, outstandingAmountMinor(invoice));
  }, 0);
  const receiptCount = invoices.filter(
    (invoice) => invoice.documentType === 'PURCHASE_RECEIPT',
  ).length;
  const statementCount = invoices.filter(
    (invoice) => invoice.documentType === 'USAGE_STATEMENT',
  ).length;
  return {
    totalCount: invoices.length,
    openCount,
    overdueCount,
    paidCount,
    outstandingAmountMinor: totalOutstandingAmountMinor,
    latestPeriodMonthUtc: invoices[0]?.periodMonthUtc || null,
    receiptCount,
    statementCount,
  };
}

function sortLineItems(items: BillingInvoiceLineItem[]): BillingInvoiceLineItem[] {
  return [...items].sort((a, b) => a.itemType.localeCompare(b.itemType));
}

function sortLedgerEntriesByMostRecent(entries: BillingLedgerEntry[]): BillingLedgerEntry[] {
  return [...entries].sort((left, right) => {
    const tsDiff = Date.parse(right.createdAt) - Date.parse(left.createdAt);
    if (tsDiff !== 0) return tsDiff;
    return right.id.localeCompare(left.id);
  });
}

function getMemoryStoreBalance(store: OrgBillingStore): number {
  return billingBalanceFromEntries(store.ledgerEntries);
}

function sortRefundsByMostRecent(refunds: Iterable<BillingRefund>): BillingRefund[] {
  return Array.from(refunds).sort((left, right) => {
    const timeDifference = Date.parse(right.createdAt) - Date.parse(left.createdAt);
    if (timeDifference !== 0) return timeDifference;
    return right.id.localeCompare(left.id);
  });
}

function appendMemoryLedgerEntry(
  store: OrgBillingStore,
  input: Omit<BillingLedgerEntry, 'id' | 'postings' | 'createdAt'> & { now: Date },
): BillingLedgerEntry {
  const id = makeId('ble', input.now);
  const createdAt = coerceIsoDate(input.now);
  const entry: BillingLedgerEntry = {
    id,
    orgId: input.orgId,
    type: input.type,
    amountMinor: input.amountMinor,
    currency: 'USD',
    description: input.description,
    monthUtc: input.monthUtc,
    relatedInvoiceId: input.relatedInvoiceId,
    relatedPurchaseId: input.relatedPurchaseId,
    sourceEventId: input.sourceEventId,
    actorType: input.actorType,
    actorUserId: input.actorUserId,
    reasonCode: input.reasonCode,
    note: input.note,
    idempotencyKey: input.idempotencyKey,
    postings: buildBillingBalancedPostings({
      entryId: id,
      type: input.type,
      amountMinor: input.amountMinor,
      createdAt,
    }),
    createdAt,
  };
  store.ledgerEntries.push(entry);
  return entry;
}

export function requireRefundSupportContext(ctx: ConsoleBillingRefundSupportContext): void {
  if (ctx.platformSupport) return;
  throw new ConsoleBillingError(
    'forbidden',
    403,
    'Only internal billing support can create cash refunds',
  );
}

export function normalizeRefundRequest(request: BillingRefundRequest): BillingRefundRequest {
  const purchaseId = request.purchaseId.trim();
  const amountMinor = Number(request.amountMinor);
  const reason = request.reason.trim();
  const idempotencyKey = request.idempotencyKey.trim();
  if (
    !purchaseId ||
    !reason ||
    !idempotencyKey ||
    !Number.isSafeInteger(amountMinor) ||
    amountMinor <= 0
  ) {
    throw new ConsoleBillingError(
      'invalid_refund',
      400,
      'Refund purchaseId, positive amountMinor, reason, and idempotencyKey are required',
    );
  }
  return { purchaseId, amountMinor, reason, idempotencyKey };
}

function activeRefundAmountForPurchase(store: OrgBillingStore, purchaseId: string): number {
  let amountMinor = 0;
  for (const refund of store.refunds.values()) {
    if (refund.purchaseId !== purchaseId) continue;
    if (refund.status === 'failed' || refund.status === 'canceled') continue;
    amountMinor += refund.amountMinor;
  }
  return amountMinor;
}

function pendingConsoleRefundAmount(store: OrgBillingStore): number {
  let amountMinor = 0;
  for (const refund of store.refunds.values()) {
    if (refund.origin !== 'console') continue;
    if (refund.status === 'requested' || refund.status === 'provider_pending') {
      amountMinor += refund.amountMinor;
    }
  }
  return amountMinor;
}

function buildRequestedRefund(input: {
  id: string;
  orgId: string;
  purchaseId: string;
  amountMinor: number;
  reason: string;
  requesterUserId: string;
  idempotencyKey: string;
  now: Date;
}): BillingRefund {
  const timestamp = coerceIsoDate(input.now);
  return {
    id: input.id,
    orgId: input.orgId,
    purchaseId: input.purchaseId,
    amountMinor: input.amountMinor,
    currency: 'USD',
    reason: input.reason,
    origin: 'console',
    requesterUserId: input.requesterUserId,
    idempotencyKey: input.idempotencyKey,
    status: 'requested',
    providerRefundId: null,
    failureCode: null,
    journalEntryId: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

function buildImportedRefund(input: {
  id: string;
  orgId: string;
  purchaseId: string;
  item: StripeRefundEventItem;
  now: Date;
}): BillingRefund {
  const timestamp = coerceIsoDate(input.now);
  return {
    id: input.id,
    orgId: input.orgId,
    purchaseId: input.purchaseId,
    amountMinor: input.item.amountMinor,
    currency: 'USD',
    reason: input.item.reason,
    origin: 'provider',
    requesterUserId: 'stripe',
    idempotencyKey: `stripe:${input.item.providerRefundId}`,
    status: 'provider_pending',
    providerRefundId: input.item.providerRefundId,
    failureCode: null,
    journalEntryId: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

export function providerRefundTransitionAllowed(
  currentStatus: BillingRefund['status'],
  providerStatus: StripeProviderRefundStatus,
): boolean {
  if (currentStatus === 'succeeded') return providerStatus === 'succeeded';
  if (currentStatus === 'failed') return providerStatus === 'failed';
  if (currentStatus === 'canceled') return providerStatus === 'canceled';
  return true;
}

function applyMemoryRefundProviderState(input: {
  store: OrgBillingStore;
  refund: BillingRefund;
  provider: StripeRefundProviderOutput;
  now: Date;
}): BillingRefund {
  const providerRefundId = String(input.provider.id || '').trim();
  if (!providerRefundId) {
    throw new ConsoleBillingError(
      'refund_provider_error',
      502,
      'Stripe refund response is missing its provider reference',
    );
  }
  if (!providerRefundTransitionAllowed(input.refund.status, input.provider.status)) {
    throw new ConsoleBillingError(
      'invalid_refund_transition',
      409,
      `Refund ${input.refund.id} cannot transition from ${input.refund.status} to ${input.provider.status}`,
    );
  }
  if (input.refund.providerRefundId && input.refund.providerRefundId !== providerRefundId) {
    throw new ConsoleBillingError(
      'refund_provider_mismatch',
      409,
      `Refund ${input.refund.id} is already linked to another Stripe refund`,
    );
  }
  if (input.refund.status === 'succeeded') return input.refund;
  const updatedAt = coerceIsoDate(input.now);
  let updated: BillingRefund;
  switch (input.provider.status) {
    case 'pending':
      updated = {
        id: input.refund.id,
        orgId: input.refund.orgId,
        purchaseId: input.refund.purchaseId,
        amountMinor: input.refund.amountMinor,
        currency: 'USD',
        reason: input.refund.reason,
        origin: input.refund.origin,
        requesterUserId: input.refund.requesterUserId,
        idempotencyKey: input.refund.idempotencyKey,
        status: 'provider_pending',
        providerRefundId,
        failureCode: null,
        journalEntryId: null,
        createdAt: input.refund.createdAt,
        updatedAt,
      };
      break;
    case 'failed':
      updated = {
        id: input.refund.id,
        orgId: input.refund.orgId,
        purchaseId: input.refund.purchaseId,
        amountMinor: input.refund.amountMinor,
        currency: 'USD',
        reason: input.refund.reason,
        origin: input.refund.origin,
        requesterUserId: input.refund.requesterUserId,
        idempotencyKey: input.refund.idempotencyKey,
        status: 'failed',
        providerRefundId,
        failureCode: input.provider.failureCode || 'provider_failed',
        journalEntryId: null,
        createdAt: input.refund.createdAt,
        updatedAt,
      };
      break;
    case 'canceled':
      updated = {
        id: input.refund.id,
        orgId: input.refund.orgId,
        purchaseId: input.refund.purchaseId,
        amountMinor: input.refund.amountMinor,
        currency: 'USD',
        reason: input.refund.reason,
        origin: input.refund.origin,
        requesterUserId: input.refund.requesterUserId,
        idempotencyKey: input.refund.idempotencyKey,
        status: 'canceled',
        providerRefundId,
        failureCode: null,
        journalEntryId: null,
        createdAt: input.refund.createdAt,
        updatedAt,
      };
      break;
    case 'succeeded': {
      const ledgerEntry =
        input.store.ledgerEntries.find(
          (entry) => entry.idempotencyKey === `refund:${input.refund.id}`,
        ) ||
        appendMemoryLedgerEntry(input.store, {
          now: input.now,
          orgId: input.refund.orgId,
          type: 'REFUND',
          amountMinor: -input.refund.amountMinor,
          currency: 'USD',
          description: `Stripe refund ${providerRefundId}`,
          monthUtc: formatCurrentMonthUtc(input.now),
          relatedInvoiceId: null,
          relatedPurchaseId: input.refund.purchaseId,
          sourceEventId: providerRefundId,
          actorType: 'PROVIDER',
          actorUserId: null,
          reasonCode: input.refund.reason,
          note: `Refund ${input.refund.id} succeeded`,
          idempotencyKey: `refund:${input.refund.id}`,
        });
      updated = {
        id: input.refund.id,
        orgId: input.refund.orgId,
        purchaseId: input.refund.purchaseId,
        amountMinor: input.refund.amountMinor,
        currency: 'USD',
        reason: input.refund.reason,
        origin: input.refund.origin,
        requesterUserId: input.refund.requesterUserId,
        idempotencyKey: input.refund.idempotencyKey,
        status: 'succeeded',
        providerRefundId,
        failureCode: null,
        journalEntryId: ledgerEntry.id,
        createdAt: input.refund.createdAt,
        updatedAt,
      };
      break;
    }
  }
  input.store.refunds.set(updated.id, updated);
  return updated;
}

function findMemoryPurchaseForProviderEvent(input: {
  stores: ReadonlyMap<string, OrgBillingStore>;
  orgId: string | null;
  purchaseId: string | null;
  providerPaymentRef: string;
}): BillingCreditPurchase | null {
  const stores = input.orgId
    ? [[input.orgId, input.stores.get(input.orgId)] as const]
    : Array.from(input.stores.entries());
  let match: BillingCreditPurchase | null = null;
  for (const [, store] of stores) {
    if (!store) continue;
    for (const purchase of store.purchases.values()) {
      if (purchase.status !== 'SETTLED') continue;
      const matchesId = input.purchaseId && purchase.id === input.purchaseId;
      const matchesPayment = purchase.providerPaymentRef === input.providerPaymentRef;
      if (!matchesId && !matchesPayment) continue;
      if (match && match.id !== purchase.id) {
        throw new ConsoleBillingError(
          'duplicate_provider_reference',
          409,
          'Stripe provider reference maps to multiple purchases',
        );
      }
      match = purchase;
    }
  }
  return match;
}

function findMemoryRefundForProviderEvent(
  stores: ReadonlyMap<string, OrgBillingStore>,
  item: StripeRefundEventItem,
): { store: OrgBillingStore; refund: BillingRefund } | null {
  const storesToSearch = item.orgId
    ? [stores.get(item.orgId)].filter((store): store is OrgBillingStore => Boolean(store))
    : Array.from(stores.values());
  for (const store of storesToSearch) {
    for (const refund of store.refunds.values()) {
      if (item.refundId && refund.id === item.refundId) return { store, refund };
      if (refund.providerRefundId === item.providerRefundId) return { store, refund };
    }
  }
  return null;
}

function applyMemoryRefundEvent(input: {
  stores: ReadonlyMap<string, OrgBillingStore>;
  item: StripeRefundEventItem;
  now: Date;
}): BillingRefund | null {
  const linked = findMemoryRefundForProviderEvent(input.stores, input.item);
  if (linked) {
    if (
      linked.refund.amountMinor !== input.item.amountMinor ||
      (input.item.purchaseId && linked.refund.purchaseId !== input.item.purchaseId)
    ) {
      throw new ConsoleBillingError(
        'refund_provider_mismatch',
        409,
        `Stripe refund ${input.item.providerRefundId} does not match the persisted refund`,
      );
    }
    return applyMemoryRefundProviderState({
      store: linked.store,
      refund: linked.refund,
      provider: {
        id: input.item.providerRefundId,
        status: input.item.status,
        failureCode: input.item.failureCode,
      },
      now: input.now,
    });
  }

  const purchase = findMemoryPurchaseForProviderEvent({
    stores: input.stores,
    orgId: input.item.orgId,
    purchaseId: input.item.purchaseId,
    providerPaymentRef: input.item.providerPaymentRef,
  });
  if (!purchase) return null;
  const store = input.stores.get(purchase.orgId);
  if (!store) return null;
  const refundableRemainder =
    purchase.amountMinor - activeRefundAmountForPurchase(store, purchase.id);
  if (input.item.amountMinor > refundableRemainder) {
    throw new ConsoleBillingError(
      'refund_amount_exceeds_purchase',
      409,
      'Stripe refund exceeds the unrefunded purchase amount',
    );
  }
  const imported = buildImportedRefund({
    id: `brf_ext_${input.item.providerRefundId}`,
    orgId: purchase.orgId,
    purchaseId: purchase.id,
    item: input.item,
    now: input.now,
  });
  store.refunds.set(imported.id, imported);
  return applyMemoryRefundProviderState({
    store,
    refund: imported,
    provider: {
      id: input.item.providerRefundId,
      status: input.item.status,
      failureCode: input.item.failureCode,
    },
    now: input.now,
  });
}

function applyMemoryDisputeOpened(input: {
  store: OrgBillingStore;
  purchase: BillingCreditPurchase;
  providerDisputeId: string;
  amountMinor: number;
  now: Date;
}): BillingDispute {
  const existing = input.store.disputes.get(input.providerDisputeId);
  if (existing) {
    if (existing.purchaseId !== input.purchase.id || existing.amountMinor !== input.amountMinor) {
      throw new ConsoleBillingError(
        'dispute_provider_mismatch',
        409,
        `Stripe dispute ${input.providerDisputeId} does not match the persisted dispute`,
      );
    }
    return existing;
  }
  const openedEntry = appendMemoryLedgerEntry(input.store, {
    now: input.now,
    orgId: input.purchase.orgId,
    type: 'DISPUTE_OPENED',
    amountMinor: -input.amountMinor,
    currency: 'USD',
    description: `Stripe dispute ${input.providerDisputeId} opened`,
    monthUtc: formatCurrentMonthUtc(input.now),
    relatedInvoiceId: input.purchase.relatedInvoiceId,
    relatedPurchaseId: input.purchase.id,
    sourceEventId: input.providerDisputeId,
    actorType: 'PROVIDER',
    actorUserId: null,
    reasonCode: 'stripe_dispute_opened',
    note: `Stripe dispute ${input.providerDisputeId} debited prepaid credit`,
    idempotencyKey: `dispute_opened:${input.providerDisputeId}`,
  });
  const timestamp = coerceIsoDate(input.now);
  const dispute: BillingDispute = {
    id: `bds_${input.providerDisputeId}`,
    orgId: input.purchase.orgId,
    purchaseId: input.purchase.id,
    providerDisputeId: input.providerDisputeId,
    amountMinor: input.amountMinor,
    status: 'open',
    openedJournalEntryId: openedEntry.id,
    resolutionJournalEntryId: null,
    createdAt: timestamp,
    updatedAt: timestamp,
  };
  input.store.disputes.set(input.providerDisputeId, dispute);
  return dispute;
}

function applyMemoryDisputeClosed(input: {
  store: OrgBillingStore;
  dispute: BillingDispute;
  outcome: 'won' | 'lost';
  now: Date;
}): BillingDispute {
  if (input.dispute.status !== 'open') return input.dispute;
  let resolved: BillingDispute;
  if (input.outcome === 'lost') {
    resolved = {
      id: input.dispute.id,
      orgId: input.dispute.orgId,
      purchaseId: input.dispute.purchaseId,
      providerDisputeId: input.dispute.providerDisputeId,
      amountMinor: input.dispute.amountMinor,
      status: 'lost',
      openedJournalEntryId: input.dispute.openedJournalEntryId,
      resolutionJournalEntryId: null,
      createdAt: input.dispute.createdAt,
      updatedAt: coerceIsoDate(input.now),
    };
  } else {
    const resolutionEntry = appendMemoryLedgerEntry(input.store, {
      now: input.now,
      orgId: input.dispute.orgId,
      type: 'DISPUTE_WON',
      amountMinor: input.dispute.amountMinor,
      currency: 'USD',
      description: `Stripe dispute ${input.dispute.providerDisputeId} won`,
      monthUtc: formatCurrentMonthUtc(input.now),
      relatedInvoiceId: null,
      relatedPurchaseId: input.dispute.purchaseId,
      sourceEventId: `won:${input.dispute.providerDisputeId}`,
      actorType: 'PROVIDER',
      actorUserId: null,
      reasonCode: 'stripe_dispute_won',
      note: `Stripe dispute ${input.dispute.providerDisputeId} restored prepaid credit`,
      idempotencyKey: `dispute_won:${input.dispute.providerDisputeId}`,
    });
    resolved = {
      id: input.dispute.id,
      orgId: input.dispute.orgId,
      purchaseId: input.dispute.purchaseId,
      providerDisputeId: input.dispute.providerDisputeId,
      amountMinor: input.dispute.amountMinor,
      status: 'won',
      openedJournalEntryId: input.dispute.openedJournalEntryId,
      resolutionJournalEntryId: resolutionEntry.id,
      createdAt: input.dispute.createdAt,
      updatedAt: coerceIsoDate(input.now),
    };
  }
  input.store.disputes.set(input.dispute.providerDisputeId, resolved);
  return resolved;
}

function outstandingAmountMinor(invoice: BillingInvoice): number {
  return Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
}

function assertStripeCheckoutMatchesPurchase(
  request: Extract<StripeWebhookEventRequest, { eventType: 'checkout.session.completed' }>,
  purchase: BillingCreditPurchase,
): void {
  if (
    request.paymentStatus !== 'paid' ||
    request.currency !== purchase.currency ||
    request.purchaseId !== purchase.id ||
    request.creditPackId !== purchase.creditPackId ||
    request.amountMinor !== purchase.amountMinor
  ) {
    throw new ConsoleBillingError(
      'checkout_session_mismatch',
      409,
      'Stripe Checkout payment does not match the pending credit purchase',
    );
  }
}

export function createInMemoryConsoleBillingService(
  options: InMemoryConsoleBillingServiceOptions = {},
): ConsoleBillingService {
  const nowFn = options.now || (() => new Date());
  const providers = resolveBillingProviderAdapters(options.providers);
  const checkoutReturnUrls = buildStripeCheckoutReturnUrls(options.consoleBaseUrl);
  const orgStores = new Map<string, OrgBillingStore>();
  const stripeWebhookEventIds = new Set<string>();
  const stripePostProcessingOutbox = new Map<string, BillingStripePostProcessingOutboxItem>();

  function cloneStripePostProcessingOutboxItem(
    item: BillingStripePostProcessingOutboxItem,
  ): BillingStripePostProcessingOutboxItem {
    return {
      ...item,
      payload: {
        ...item.payload,
        audit: {
          ...item.payload.audit,
          metadata: { ...item.payload.audit.metadata },
        },
        customerWebhook: {
          ...item.payload.customerWebhook,
          payload: { ...item.payload.customerWebhook.payload },
        },
      },
    };
  }

  function pendingStripePostProcessing(item: BillingStripePostProcessingOutboxItem): boolean {
    return item.auditCompletedAt === null || item.customerWebhookCompletedAt === null;
  }

  function makeUsageStatementId(monthUtc: string): string {
    return `inv_${monthUtc.replace('-', '')}_001`;
  }

  function ensureStatementProjectionSeed(
    store: OrgBillingStore,
    monthUtc: string,
    createdAt: Date,
  ): string {
    const existing = store.statementProjectionCreatedAtByMonth.get(monthUtc);
    if (existing) return existing;
    const createdAtIso = coerceIsoDate(createdAt);
    store.statementProjectionCreatedAtByMonth.set(monthUtc, createdAtIso);
    return createdAtIso;
  }

  function ensureCurrentPeriodStatementSeed(store: OrgBillingStore, now: Date): void {
    ensureStatementProjectionSeed(store, formatCurrentMonthUtc(now), now);
  }

  function getLedgerEntriesForMonth(
    store: OrgBillingStore,
    monthUtc: string,
    type: BillingLedgerEntry['type'],
  ): BillingLedgerEntry[] {
    return store.ledgerEntries.filter(
      (entry) => entry.type === type && entry.monthUtc === monthUtc,
    );
  }

  function getProjectedUsageStatement(
    store: OrgBillingStore,
    orgId: string,
    monthUtc: string,
  ): BillingInvoice | null {
    const usageDebitEntries = getLedgerEntriesForMonth(store, monthUtc, 'USAGE_DEBIT');
    const productExecutionDebitEntries = getLedgerEntriesForMonth(
      store,
      monthUtc,
      'PRODUCT_EXECUTION_DEBIT',
    );
    const debitEntries = [...usageDebitEntries, ...productExecutionDebitEntries];
    const createdAt =
      store.statementProjectionCreatedAtByMonth.get(monthUtc) ||
      debitEntries
        .map((entry) => entry.createdAt)
        .sort((left, right) => Date.parse(left) - Date.parse(right))[0] ||
      null;
    if (!createdAt) return null;
    const amountDueMinor = debitEntries.reduce(
      (total, entry) => total + Math.abs(entry.amountMinor),
      0,
    );
    return {
      id: makeUsageStatementId(monthUtc),
      orgId,
      documentType: 'USAGE_STATEMENT',
      status: 'PAID',
      currency: 'USD',
      amountDueMinor,
      amountPaidMinor: amountDueMinor,
      periodMonthUtc: monthUtc,
      createdAt,
      dueAt: null,
    };
  }

  function getProjectedPurchaseReceipt(purchase: BillingCreditPurchase): BillingInvoice | null {
    if (purchase.status !== 'SETTLED') return null;
    const createdAt = purchase.settledAt || purchase.createdAt;
    const periodMonthUtc = createdAt.slice(0, 7);
    return {
      id: `receipt_${purchase.id}`,
      orgId: purchase.orgId,
      documentType: 'PURCHASE_RECEIPT',
      status: 'PAID',
      currency: 'USD',
      amountDueMinor: purchase.amountMinor,
      amountPaidMinor: purchase.amountMinor,
      periodMonthUtc,
      createdAt,
      dueAt: null,
    };
  }

  function listProjectedInvoices(
    store: OrgBillingStore,
    orgId: string,
    now: Date,
  ): BillingInvoice[] {
    ensureCurrentPeriodStatementSeed(store, now);
    const invoices = new Map<string, BillingInvoice>();

    for (const monthUtc of Array.from(store.statementProjectionCreatedAtByMonth.keys())) {
      const invoice = getProjectedUsageStatement(store, orgId, monthUtc);
      if (invoice) {
        invoices.set(invoice.id, invoice);
      }
    }

    for (const purchase of Array.from(store.purchases.values())) {
      const receipt = getProjectedPurchaseReceipt(purchase);
      if (receipt) {
        invoices.set(receipt.id, receipt);
      }
    }

    return Array.from(invoices.values()).sort((left, right) => {
      const tsDiff = Date.parse(right.createdAt) - Date.parse(left.createdAt);
      if (tsDiff !== 0) return tsDiff;
      return right.id.localeCompare(left.id);
    });
  }

  function getProjectedInvoiceLineItems(
    store: OrgBillingStore,
    invoice: BillingInvoice,
  ): BillingInvoiceLineItem[] {
    if (invoice.documentType === 'PURCHASE_RECEIPT') {
      const purchaseId = invoice.id.startsWith('receipt_')
        ? invoice.id.slice('receipt_'.length)
        : '';
      const purchase = store.purchases.get(purchaseId) || null;
      if (!purchase || purchase.status !== 'SETTLED') return [];
      return [
        makeInvoiceLineItem({
          orgId: invoice.orgId,
          invoiceId: invoice.id,
          periodMonthUtc: invoice.periodMonthUtc,
          itemType: 'CREDIT_TOP_UP',
          description: `Prepaid credit top-up (${purchase.creditPackId})`,
          quantity: 1,
          unitAmountMinor: purchase.amountMinor,
          createdAt: invoice.createdAt,
        }),
      ];
    }

    const monthlyActiveResources = getLedgerEntriesForMonth(
      store,
      invoice.periodMonthUtc,
      'USAGE_DEBIT',
    ).length;
    const productExecutionDebitMinor = Math.abs(
      getLedgerEntriesForMonth(store, invoice.periodMonthUtc, 'PRODUCT_EXECUTION_DEBIT').reduce(
        (total, entry) => total + entry.amountMinor,
        0,
      ),
    );
    return buildInvoiceLineItems({
      orgId: invoice.orgId,
      invoiceId: invoice.id,
      periodMonthUtc: invoice.periodMonthUtc,
      monthlyActiveResources,
      productExecutionDebitMinor,
      createdAt: invoice.createdAt,
    });
  }

  function getProjectedInvoice(
    store: OrgBillingStore,
    orgId: string,
    invoiceId: string,
    now: Date,
  ): BillingInvoice | null {
    return (
      listProjectedInvoices(store, orgId, now).find((invoice) => invoice.id === invoiceId) || null
    );
  }

  function ensureManualAdjustmentRelatedInvoiceId(
    store: OrgBillingStore,
    orgId: string,
    relatedInvoiceId: string | undefined,
    now: Date,
  ): string | null {
    const knownInvoiceIds = new Set(
      listProjectedInvoices(store, orgId, now).map((invoice) => invoice.id),
    );
    return requireKnownManualAdjustmentRelatedInvoiceId({
      relatedInvoiceId,
      knownInvoiceIds,
    });
  }

  function ensureOrgStore(orgId: string): OrgBillingStore {
    const existing = orgStores.get(orgId);
    if (existing) {
      ensureCurrentPeriodStatementSeed(existing, nowFn());
      return existing;
    }

    const store: OrgBillingStore = {
      monthlyActiveResources: 0,
      lowBalanceThresholdMinor: DEFAULT_LOW_BALANCE_THRESHOLD_MINOR,
      purchases: new Map(),
      refunds: new Map(),
      disputes: new Map(),
      ledgerEntries: [],
      usageEventSourceIds: new Set(),
      monthlyActiveResourcesByMonth: new Map(),
      statementProjectionCreatedAtByMonth: new Map(),
    };
    ensureCurrentPeriodStatementSeed(store, nowFn());
    orgStores.set(orgId, store);
    return store;
  }

  function findLedgerEntryByIdempotencyKey(
    store: OrgBillingStore,
    idempotencyKey: string,
  ): BillingLedgerEntry | null {
    const key = String(idempotencyKey || '').trim();
    if (!key) return null;
    return store.ledgerEntries.find((entry) => entry.idempotencyKey === key) || null;
  }

  function getCurrentMonthUsageDebitMinor(store: OrgBillingStore, monthUtc: string): number {
    return Math.abs(
      store.ledgerEntries
        .filter((entry) => entry.type === 'USAGE_DEBIT' && entry.monthUtc === monthUtc)
        .reduce((total, entry) => total + entry.amountMinor, 0),
    );
  }

  function findLedgerEntryBySourceEventIdAndType(
    store: OrgBillingStore,
    type: BillingLedgerEntry['type'],
    sourceEventId: string,
  ): BillingLedgerEntry | null {
    const key = String(sourceEventId || '').trim();
    if (!key) return null;
    return (
      store.ledgerEntries.find((entry) => entry.type === type && entry.sourceEventId === key) ||
      null
    );
  }

  function getCurrentMonthPurchasedMinor(store: OrgBillingStore, monthUtc: string): number {
    return store.ledgerEntries
      .filter((entry) => entry.type === 'CREDIT_PURCHASE' && entry.monthUtc === monthUtc)
      .reduce((total, entry) => total + entry.amountMinor, 0);
  }

  function settleCreditPurchase(
    store: OrgBillingStore,
    input: {
      orgId: string;
      purchaseId: string;
      providerPaymentRef: string;
      now: Date;
    },
  ): Extract<BillingCreditPurchase, { status: 'SETTLED' }> {
    const purchase = store.purchases.get(input.purchaseId);
    if (!purchase) {
      throw new ConsoleBillingError(
        'purchase_not_found',
        404,
        `Credit purchase ${input.purchaseId} was not found`,
      );
    }
    if (purchase.status === 'SETTLED') return purchase;
    if (!purchase.providerCheckoutSessionRef) {
      throw new ConsoleBillingError(
        'purchase_not_ready',
        409,
        `Credit purchase ${input.purchaseId} has no Stripe checkout session`,
      );
    }
    const monthUtc = formatCurrentMonthUtc(input.now);
    appendMemoryLedgerEntry(store, {
      now: input.now,
      orgId: input.orgId,
      type: 'CREDIT_PURCHASE',
      amountMinor: purchase.amountMinor,
      description: `Credit pack ${purchase.creditPackId} settled`,
      monthUtc,
      relatedInvoiceId: `receipt_${purchase.id}`,
      relatedPurchaseId: purchase.id,
      sourceEventId: purchase.providerCheckoutSessionRef,
      actorType: 'PROVIDER',
      actorUserId: null,
      reasonCode: 'credit_purchase',
      note: `Stripe checkout session ${purchase.providerCheckoutSessionRef} settled`,
      idempotencyKey: `credit_purchase_settlement:${purchase.id}`,
      currency: 'USD',
    });
    const settledPurchase: BillingCreditPurchase = {
      id: purchase.id,
      orgId: purchase.orgId,
      creditPackId: purchase.creditPackId,
      status: 'SETTLED',
      amountMinor: purchase.amountMinor,
      currency: 'USD',
      provider: 'stripe',
      providerCheckoutSessionRef: purchase.providerCheckoutSessionRef,
      providerCustomerRef: purchase.providerCustomerRef || makeStripeCustomerRef(input.orgId),
      providerPaymentRef: input.providerPaymentRef,
      relatedInvoiceId: `receipt_${purchase.id}`,
      settledAt: coerceIsoDate(input.now),
      createdAt: purchase.createdAt,
      updatedAt: coerceIsoDate(input.now),
    };
    store.purchases.set(settledPurchase.id, settledPurchase);
    return settledPurchase;
  }

  function ensureMonthlyResourceSet(store: OrgBillingStore, monthUtc: string): Set<string> {
    const existing = store.monthlyActiveResourcesByMonth.get(monthUtc);
    if (existing) return existing;
    const created = new Set<string>();
    store.monthlyActiveResourcesByMonth.set(monthUtc, created);
    return created;
  }

  function getMonthlyActiveResourceCount(store: OrgBillingStore, monthUtc: string): number {
    return ensureMonthlyResourceSet(store, monthUtc).size;
  }

  function resolveWebhookStore(
    request: Extract<
      StripeWebhookEventRequest,
      { eventType: 'checkout.session.completed' | 'checkout.session.expired' }
    >,
  ): {
    orgId: string;
    store: OrgBillingStore;
    purchase: BillingCreditPurchase | null;
  } | null {
    const requestedOrgId = String(request.orgId || '').trim();
    const checkoutSessionRef = String(request.checkoutSessionId || request.providerRef).trim();

    if (requestedOrgId) {
      const store = orgStores.get(requestedOrgId);
      if (!store) return null;
      const purchase =
        Array.from(store.purchases.values()).find(
          (entry) => checkoutSessionRef && entry.providerCheckoutSessionRef === checkoutSessionRef,
        ) || null;
      return {
        orgId: requestedOrgId,
        store,
        purchase,
      };
    }

    let match: {
      orgId: string;
      store: OrgBillingStore;
      purchase: BillingCreditPurchase | null;
    } | null = null;
    for (const [orgId, store] of Array.from(orgStores.entries())) {
      const purchase =
        Array.from(store.purchases.values()).find(
          (entry) => checkoutSessionRef && entry.providerCheckoutSessionRef === checkoutSessionRef,
        ) || null;
      if (!purchase) continue;
      if (match) {
        throw new ConsoleBillingError(
          'duplicate_provider_reference',
          409,
          `Stripe webhook event ${request.eventId} maps to multiple organizations`,
        );
      }
      match = { orgId, store, purchase };
    }
    return match;
  }

  async function processStripeWebhookEventInternal(
    request: StripeWebhookEventRequest,
    enqueuePostProcessing: boolean,
  ): Promise<StripeWebhookEventResult> {
    const now = nowFn();
    if (stripeWebhookEventIds.has(request.eventId)) {
      if (
        request.eventType === 'checkout.session.completed' ||
        request.eventType === 'checkout.session.expired'
      ) {
        const resolved = resolveWebhookStore(request);
        const purchase = resolved?.purchase || null;
        return {
          accepted: false,
          purchase,
          invoice:
            resolved && purchase?.relatedInvoiceId
              ? getProjectedInvoice(resolved.store, resolved.orgId, purchase.relatedInvoiceId, now)
              : null,
          refunds: [],
          dispute: null,
          orgId: resolved?.orgId || request.orgId,
        };
      }
      return {
        accepted: false,
        purchase: null,
        invoice: null,
        refunds: [],
        dispute: null,
        orgId: null,
      };
    }
    let result: StripeWebhookEventResult;
    switch (request.eventType) {
      case 'checkout.session.completed': {
        const resolved = resolveWebhookStore(request);
        if (!resolved || !resolved.purchase) {
          result = {
            accepted: true,
            purchase: null,
            invoice: null,
            refunds: [],
            dispute: null,
            orgId: resolved?.orgId || request.orgId,
          };
          break;
        }
        assertStripeCheckoutMatchesPurchase(request, resolved.purchase);
        const purchase = settleCreditPurchase(resolved.store, {
          orgId: resolved.orgId,
          purchaseId: resolved.purchase.id,
          providerPaymentRef: request.providerPaymentRef,
          now,
        });
        result = {
          accepted: true,
          purchase,
          invoice: getProjectedInvoice(
            resolved.store,
            resolved.orgId,
            purchase.relatedInvoiceId,
            now,
          ),
          refunds: [],
          dispute: null,
          orgId: resolved.orgId,
        };
        break;
      }
      case 'checkout.session.expired': {
        const resolved = resolveWebhookStore(request);
        if (!resolved || !resolved.purchase) {
          result = {
            accepted: true,
            purchase: null,
            invoice: null,
            refunds: [],
            dispute: null,
            orgId: resolved?.orgId || request.orgId,
          };
          break;
        }
        if (resolved.purchase.id !== request.purchaseId) {
          throw new ConsoleBillingError(
            'checkout_session_mismatch',
            409,
            'Expired Stripe Checkout session does not match the pending credit purchase',
          );
        }
        const purchase: BillingCreditPurchase =
          resolved.purchase.status === 'PENDING'
            ? {
                id: resolved.purchase.id,
                orgId: resolved.purchase.orgId,
                creditPackId: resolved.purchase.creditPackId,
                status: 'CANCELED',
                amountMinor: resolved.purchase.amountMinor,
                currency: 'USD',
                provider: 'stripe',
                providerCheckoutSessionRef: resolved.purchase.providerCheckoutSessionRef,
                providerCustomerRef: resolved.purchase.providerCustomerRef,
                providerPaymentRef: null,
                relatedInvoiceId: null,
                settledAt: null,
                createdAt: resolved.purchase.createdAt,
                updatedAt: coerceIsoDate(now),
              }
            : resolved.purchase;
        resolved.store.purchases.set(purchase.id, purchase);
        result = {
          accepted: true,
          purchase,
          invoice: null,
          refunds: [],
          dispute: null,
          orgId: resolved.orgId,
        };
        break;
      }
      case 'refund.created':
      case 'refund.updated': {
        const refund = applyMemoryRefundEvent({
          stores: orgStores,
          item: request.refund,
          now,
        });
        result = {
          accepted: true,
          purchase: null,
          invoice: null,
          refunds: refund ? [refund] : [],
          dispute: null,
          orgId: refund?.orgId || request.refund.orgId,
        };
        break;
      }
      case 'charge.refunded': {
        const refunds: BillingRefund[] = [];
        for (const item of request.refunds) {
          const refund = applyMemoryRefundEvent({ stores: orgStores, item, now });
          if (refund) refunds.push(refund);
        }
        result = {
          accepted: true,
          purchase: null,
          invoice: null,
          refunds,
          dispute: null,
          orgId: refunds[0]?.orgId || request.orgId,
        };
        break;
      }
      case 'charge.dispute.created':
      case 'charge.dispute.closed': {
        const purchase = findMemoryPurchaseForProviderEvent({
          stores: orgStores,
          orgId: request.orgId,
          purchaseId: request.purchaseId,
          providerPaymentRef: request.providerPaymentRef,
        });
        const store = purchase ? orgStores.get(purchase.orgId) : null;
        let dispute: BillingDispute | null = null;
        if (purchase && store) {
          const opened = applyMemoryDisputeOpened({
            store,
            purchase,
            providerDisputeId: request.providerDisputeId,
            amountMinor: request.amountMinor,
            now,
          });
          dispute =
            request.eventType === 'charge.dispute.closed'
              ? applyMemoryDisputeClosed({
                  store,
                  dispute: opened,
                  outcome: request.outcome,
                  now,
                })
              : opened;
        }
        result = {
          accepted: true,
          purchase,
          invoice: null,
          refunds: [],
          dispute,
          orgId: purchase?.orgId || request.orgId,
        };
        break;
      }
    }
    stripeWebhookEventIds.add(request.eventId);
    if (
      enqueuePostProcessing &&
      result.accepted &&
      result.purchase?.status === 'SETTLED' &&
      result.orgId
    ) {
      const createdAt = coerceIsoDate(now);
      stripePostProcessingOutbox.set(request.eventId, {
        eventId: request.eventId,
        orgId: result.orgId,
        payload: buildBillingStripePostProcessingPayload({
          eventId: request.eventId,
          purchase: result.purchase,
          invoice: result.invoice,
        }),
        auditCompletedAt: null,
        customerWebhookCompletedAt: null,
        attemptCount: 0,
        lastError: null,
        createdAt,
        updatedAt: createdAt,
      });
    }
    return result;
  }

  const service: ConsoleBillingService = {
    async getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const currentMonthUtc = formatCurrentMonthUtc(now);
      store.monthlyActiveResources = getMonthlyActiveResourceCount(store, currentMonthUtc);
      const projectedInvoices = listProjectedInvoices(store, ctx.orgId, now);
      const creditBalanceMinor = getMemoryStoreBalance(store);

      return {
        usageMetricVersion: 'active_resource_v1',
        currentMonthUtc,
        monthlyActiveResources: store.monthlyActiveResources,
        creditBalanceMinor,
        lowBalanceThresholdMinor: store.lowBalanceThresholdMinor,
        liveEnvironmentState: resolveBillingLiveEnvironmentState({
          creditBalanceMinor,
          lowBalanceThresholdMinor: store.lowBalanceThresholdMinor,
        }),
        recentUsageDebitMinor: getCurrentMonthUsageDebitMinor(store, currentMonthUtc),
        recentCreditPurchasedMinor: getCurrentMonthPurchasedMinor(store, currentMonthUtc),
        documentCount: projectedInvoices.length,
      };
    },

    async getProductExecutionDebitsByIds(
      ctx: ConsoleBillingContext,
      ledgerEntryIds: string[],
    ): Promise<BillingProductExecutionDebitEntry[]> {
      const store = ensureOrgStore(ctx.orgId);
      const ids = Array.from(
        new Set(
          ledgerEntryIds
            .map((entryId) => String(entryId || '').trim())
            .filter((entryId) => entryId.length > 0),
        ),
      );
      if (ids.length === 0) return [];
      const wanted = new Set(ids);
      return sortLedgerEntriesByMostRecent(store.ledgerEntries).filter(
        (entry): entry is BillingProductExecutionDebitEntry =>
          entry.type === 'PRODUCT_EXECUTION_DEBIT' && wanted.has(entry.id),
      );
    },

    async listAccountActivity(
      ctx: ConsoleBillingContext,
      request: BillingAccountActivityRequest = {},
    ): Promise<BillingAccountActivityResult> {
      const store = ensureOrgStore(ctx.orgId);
      const periodMonthUtc = request.periodMonthUtc
        ? parseMonthUtcOrThrow(request.periodMonthUtc)
        : undefined;
      const eventType = request.eventType || undefined;
      return {
        entries: sortLedgerEntriesByMostRecent(store.ledgerEntries)
          .filter((entry) => {
            if (periodMonthUtc && entry.monthUtc !== periodMonthUtc) return false;
            if (eventType && entry.type !== eventType) return false;
            return true;
          })
          .slice(0, normalizeAccountActivityLimit(request.limit)),
      };
    },

    async getMonthlyActiveResources(
      ctx: ConsoleBillingContext,
      monthUtc?: string,
    ): Promise<BillingMonthlyActiveResources> {
      const store = ensureOrgStore(ctx.orgId);
      const resolvedMonth = monthUtc
        ? parseMonthUtcOrThrow(monthUtc)
        : formatCurrentMonthUtc(nowFn());
      const monthlyActiveResources = getMonthlyActiveResourceCount(store, resolvedMonth);
      if (resolvedMonth === formatCurrentMonthUtc(nowFn())) {
        store.monthlyActiveResources = monthlyActiveResources;
      }
      return {
        usageMetricVersion: 'active_resource_v1',
        monthUtc: resolvedMonth,
        monthlyActiveResources,
      };
    },

    async recordUsageEvent(
      ctx: ConsoleBillingContext,
      request: BillingUsageEventRequest,
    ): Promise<BillingUsageEventResult> {
      const store = ensureOrgStore(ctx.orgId);
      if (request.sourceEventId && store.usageEventSourceIds.has(request.sourceEventId)) {
        const monthUtc = request.occurredAt
          ? monthUtcFromEpochMs(Date.parse(request.occurredAt))
          : formatCurrentMonthUtc(nowFn());
        const statement = getProjectedUsageStatement(store, ctx.orgId, monthUtc);
        return {
          accepted: false,
          counted: false,
          monthUtc,
          monthlyActiveResources: getMonthlyActiveResourceCount(store, monthUtc),
          debitAppliedMinor: 0,
          creditBalanceMinor: getMemoryStoreBalance(store),
          statementId: statement?.id || null,
        };
      }

      const occurredAtMs = request.occurredAt ? Date.parse(request.occurredAt) : nowFn().getTime();
      if (!Number.isFinite(occurredAtMs)) {
        throw new ConsoleBillingError('invalid_usage_event', 400, 'Invalid occurredAt value');
      }
      const monthUtc = monthUtcFromEpochMs(occurredAtMs);
      const counted = request.shouldCount;
      if (request.sourceEventId) {
        store.usageEventSourceIds.add(request.sourceEventId);
      }
      let debitAppliedMinor = 0;
      if (counted) {
        const monthSet = ensureMonthlyResourceSet(store, monthUtc);
        const alreadyCounted = monthSet.has(request.resourceId);
        monthSet.add(request.resourceId);
        if (!alreadyCounted) {
          debitAppliedMinor = ACTIVE_RESOURCE_USAGE_DEBIT_MINOR;
          ensureStatementProjectionSeed(store, monthUtc, new Date(occurredAtMs));
          appendMemoryLedgerEntry(store, {
            now: new Date(occurredAtMs),
            orgId: ctx.orgId,
            type: 'USAGE_DEBIT',
            amountMinor: -debitAppliedMinor,
            currency: 'USD',
            description: `active-resource usage debit for resource ${request.resourceId}`,
            monthUtc,
            relatedInvoiceId: makeUsageStatementId(monthUtc),
            relatedPurchaseId: null,
            sourceEventId: request.sourceEventId || null,
            actorType: 'USER',
            actorUserId: ctx.actorUserId,
            reasonCode: 'usage_debit',
            note: `Usage debit recorded for resource ${request.resourceId}`,
            idempotencyKey: request.sourceEventId
              ? `usage_debit:${request.sourceEventId}`
              : `usage_debit:${monthUtc}:${request.resourceId}:${occurredAtMs}`,
          });
        }
      }

      const monthlyActiveResources = getMonthlyActiveResourceCount(store, monthUtc);
      const statement = getProjectedUsageStatement(store, ctx.orgId, monthUtc);
      if (monthUtc === formatCurrentMonthUtc(nowFn())) {
        store.monthlyActiveResources = monthlyActiveResources;
      }
      return {
        accepted: true,
        counted,
        monthUtc,
        monthlyActiveResources,
        debitAppliedMinor,
        creditBalanceMinor: getMemoryStoreBalance(store),
        statementId: statement?.id || null,
      };
    },

    async recordProductExecutionDebit(
      ctx: ConsoleBillingContext,
      request: BillingProductExecutionDebitRequest,
    ): Promise<BillingProductExecutionDebitResult> {
      const store = ensureOrgStore(ctx.orgId);
      const sourceEventId = String(request.sourceEventId || '').trim();
      if (!sourceEventId) {
        throw new ConsoleBillingError(
          'invalid_product_execution_debit',
          400,
          'sourceEventId is required',
        );
      }
      if (!Number.isInteger(request.amountMinor) || request.amountMinor <= 0) {
        throw new ConsoleBillingError(
          'invalid_product_execution_debit',
          400,
          'amountMinor must be a positive integer',
        );
      }
      const occurredAtMs = request.occurredAt ? Date.parse(request.occurredAt) : nowFn().getTime();
      if (!Number.isFinite(occurredAtMs)) {
        throw new ConsoleBillingError(
          'invalid_product_execution_debit',
          400,
          'Invalid occurredAt value',
        );
      }
      const monthUtc = monthUtcFromEpochMs(occurredAtMs);
      const existing = findLedgerEntryBySourceEventIdAndType(
        store,
        'PRODUCT_EXECUTION_DEBIT',
        sourceEventId,
      );
      const existingStatement = getProjectedUsageStatement(store, ctx.orgId, monthUtc);
      if (existing) {
        return {
          accepted: false,
          debitAppliedMinor: 0,
          ledgerEntryId: existing.id,
          creditBalanceMinor: getMemoryStoreBalance(store),
          monthUtc,
          statementId: existingStatement?.id || null,
        };
      }
      const now = new Date(occurredAtMs);
      ensureStatementProjectionSeed(store, monthUtc, now);
      const entry = appendMemoryLedgerEntry(store, {
        now,
        orgId: ctx.orgId,
        type: 'PRODUCT_EXECUTION_DEBIT',
        amountMinor: -request.amountMinor,
        currency: 'USD',
        description: `Product execution debit for ${request.resourceId}`,
        monthUtc,
        relatedInvoiceId: makeUsageStatementId(monthUtc),
        relatedPurchaseId: null,
        sourceEventId,
        actorType: 'SYSTEM',
        actorUserId: ctx.actorUserId,
        reasonCode: 'product_execution_debit',
        note:
          String(request.note || '').trim() ||
          [
            request.txOrExecutionRef ? `Ref ${request.txOrExecutionRef}` : '',
            request.pricingVersion ? `Pricing ${request.pricingVersion}` : '',
          ]
            .filter(Boolean)
            .join(' · ') ||
          `Product execution debit recorded for ${request.resourceId}`,
        idempotencyKey: `product_execution_debit:${sourceEventId}`,
      });
      const statement = getProjectedUsageStatement(store, ctx.orgId, monthUtc);
      return {
        accepted: true,
        debitAppliedMinor: request.amountMinor,
        ledgerEntryId: entry.id,
        creditBalanceMinor: getMemoryStoreBalance(store),
        monthUtc,
        statementId: statement?.id || null,
      };
    },

    async listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]> {
      const store = ensureOrgStore(ctx.orgId);
      return listProjectedInvoices(store, ctx.orgId, nowFn());
    },

    async listInvoicesPage(
      ctx: ConsoleBillingContext,
      request: BillingInvoiceListRequest = {},
    ): Promise<BillingInvoiceListResult> {
      const now = nowFn();
      const allInvoices = await this.listInvoices(ctx);
      const filteredInvoices = filterInvoicesForList(allInvoices, request, now);
      const limit = normalizeInvoiceListLimit(request.limit);
      const cursor = parseInvoiceCursor(request.cursor);
      const cursorAware = cursor
        ? filteredInvoices.filter((invoice) => {
            const createdAtMs = Date.parse(invoice.createdAt);
            const safeCreatedAtMs = Number.isFinite(createdAtMs) ? createdAtMs : 0;
            if (safeCreatedAtMs < cursor.createdAtMs) return true;
            if (safeCreatedAtMs > cursor.createdAtMs) return false;
            return invoice.id < cursor.id;
          })
        : filteredInvoices;
      const invoices = cursorAware.slice(0, limit);
      const nextCursor =
        cursorAware.length > limit && invoices.length > 0
          ? encodeInvoiceCursor(invoices[invoices.length - 1])
          : null;
      return {
        invoices,
        nextCursor,
        totalCount: filteredInvoices.length,
        summary: buildInvoiceListSummary(filteredInvoices, now),
      };
    },

    async getInvoice(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoice | null> {
      const store = ensureOrgStore(ctx.orgId);
      return getProjectedInvoice(store, ctx.orgId, invoiceId, nowFn());
    },

    async getInvoiceActivity(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceActivity | null> {
      const store = ensureOrgStore(ctx.orgId);
      const invoice = getProjectedInvoice(store, ctx.orgId, invoiceId, nowFn());
      if (!invoice) return null;

      const entries: BillingInvoiceActivityEntry[] = [
        {
          id: `${invoice.id}:issued`,
          type: 'DOCUMENT',
          invoiceId: invoice.id,
          fromState: null,
          toState: invoice.status,
          occurredAt: invoice.createdAt,
          actorType: 'SYSTEM',
          actorUserId: null,
          reason: 'document_created',
          sourceEventId: null,
          summary:
            invoice.documentType === 'PURCHASE_RECEIPT'
              ? `Receipt ${invoice.id} recorded for prepaid credit purchase.`
              : `Usage statement ${invoice.id} recorded for billing period ${invoice.periodMonthUtc}.`,
          visibility: 'CUSTOMER',
        },
      ];

      store.ledgerEntries
        .filter((entry) => entry.relatedInvoiceId === invoice.id)
        .forEach((entry) => {
          entries.push({
            id: `${entry.id}:${entry.type}`,
            type: 'LEDGER',
            invoiceId: invoice.id,
            fromState: null,
            toState: entry.type,
            occurredAt: entry.createdAt,
            actorType: entry.actorType,
            actorUserId: entry.actorUserId,
            reason: entry.reasonCode || entry.type.toLowerCase(),
            sourceEventId: entry.sourceEventId,
            summary: entry.description,
            visibility: entry.type === 'MANUAL_ADJUSTMENT' ? 'INTERNAL' : 'CUSTOMER',
          });
        });

      return {
        invoice,
        entries: [...entries].sort((left, right) => {
          const tsDiff = Date.parse(right.occurredAt) - Date.parse(left.occurredAt);
          if (tsDiff !== 0) return tsDiff;
          return right.id.localeCompare(left.id);
        }),
      };
    },

    async listInvoiceLineItems(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceLineItem[]> {
      const store = ensureOrgStore(ctx.orgId);
      const invoice = getProjectedInvoice(store, ctx.orgId, invoiceId, nowFn());
      if (!invoice) return [];
      return sortLineItems(getProjectedInvoiceLineItems(store, invoice));
    },

    async generateMonthlyInvoice(
      ctx: ConsoleBillingContext,
      request: GenerateMonthlyInvoiceRequest,
    ): Promise<GenerateMonthlyInvoiceResult> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const periodMonthUtc = parseMonthUtcOrThrow(request.periodMonthUtc);
      ensureStatementProjectionSeed(store, periodMonthUtc, now);
      const invoice = getProjectedUsageStatement(store, ctx.orgId, periodMonthUtc);
      if (!invoice) {
        throw new ConsoleBillingError(
          'invoice_generate_failed',
          500,
          `Failed to build statement projection for ${periodMonthUtc}`,
        );
      }
      const nextLineItems = getProjectedInvoiceLineItems(store, invoice);
      const monthlyActiveResources = getLedgerEntriesForMonth(
        store,
        periodMonthUtc,
        'USAGE_DEBIT',
      ).length;

      return {
        generated: false,
        invoice,
        lineItems: sortLineItems(nextLineItems),
        monthlyActiveResources,
        pricing: {
          activeResourceUnitPriceMinor: ACTIVE_RESOURCE_USAGE_DEBIT_MINOR,
        },
      };
    },

    async grantManualSupportCredit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const existing = findLedgerEntryByIdempotencyKey(store, normalizedRequest.idempotencyKey);
      if (existing) {
        return {
          created: false,
          adjustment: existing,
          creditBalanceMinor: getMemoryStoreBalance(store),
        };
      }
      const relatedInvoiceId = ensureManualAdjustmentRelatedInvoiceId(
        store,
        ctx.orgId,
        normalizedRequest.relatedInvoiceId,
        now,
      );
      const adjustment = appendMemoryLedgerEntry(store, {
        now,
        orgId: ctx.orgId,
        type: 'MANUAL_ADJUSTMENT',
        amountMinor: normalizedRequest.amountMinor,
        currency: 'USD',
        description: `Manual support credit (${normalizedRequest.reasonCode})`,
        monthUtc: formatCurrentMonthUtc(now),
        relatedInvoiceId,
        relatedPurchaseId: null,
        sourceEventId: null,
        actorType: 'USER',
        actorUserId: ctx.actorUserId,
        reasonCode: normalizedRequest.reasonCode,
        note: normalizedRequest.note,
        idempotencyKey: normalizedRequest.idempotencyKey,
      });
      return {
        created: true,
        adjustment,
        creditBalanceMinor: getMemoryStoreBalance(store),
      };
    },

    async appendManualAdminDebit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const existing = findLedgerEntryByIdempotencyKey(store, normalizedRequest.idempotencyKey);
      if (existing) {
        return {
          created: false,
          adjustment: existing,
          creditBalanceMinor: getMemoryStoreBalance(store),
        };
      }
      const relatedInvoiceId = ensureManualAdjustmentRelatedInvoiceId(
        store,
        ctx.orgId,
        normalizedRequest.relatedInvoiceId,
        now,
      );
      const adjustment = appendMemoryLedgerEntry(store, {
        now,
        orgId: ctx.orgId,
        type: 'MANUAL_ADJUSTMENT',
        amountMinor: -normalizedRequest.amountMinor,
        currency: 'USD',
        description: `Manual admin debit (${normalizedRequest.reasonCode})`,
        monthUtc: formatCurrentMonthUtc(now),
        relatedInvoiceId,
        relatedPurchaseId: null,
        sourceEventId: null,
        actorType: 'USER',
        actorUserId: ctx.actorUserId,
        reasonCode: normalizedRequest.reasonCode,
        note: normalizedRequest.note,
        idempotencyKey: normalizedRequest.idempotencyKey,
      });
      return {
        created: true,
        adjustment,
        creditBalanceMinor: getMemoryStoreBalance(store),
      };
    },

    async listRefunds(ctx: ConsoleBillingContext): Promise<BillingRefund[]> {
      return sortRefundsByMostRecent(ensureOrgStore(ctx.orgId).refunds.values());
    },

    async createRefund(
      ctx: ConsoleBillingRefundSupportContext,
      request: BillingRefundRequest,
    ): Promise<BillingRefundResult> {
      requireRefundSupportContext(ctx);
      const normalized = normalizeRefundRequest(request);
      const store = ensureOrgStore(ctx.orgId);
      const existing = Array.from(store.refunds.values()).find(
        (refund) => refund.idempotencyKey === normalized.idempotencyKey,
      );
      if (existing) {
        if (
          existing.purchaseId !== normalized.purchaseId ||
          existing.amountMinor !== normalized.amountMinor ||
          existing.reason !== normalized.reason
        ) {
          throw new ConsoleBillingError(
            'refund_idempotency_conflict',
            409,
            'Refund idempotency key was already used for a different request',
          );
        }
        if (existing.status === 'requested' && !existing.providerRefundId) {
          const purchase = store.purchases.get(existing.purchaseId);
          if (!purchase || purchase.status !== 'SETTLED') {
            throw new ConsoleBillingError(
              'purchase_not_refundable',
              409,
              'Only settled credit purchases can be refunded',
            );
          }
          let providerRefund: StripeRefundProviderOutput;
          try {
            providerRefund = await providers.stripe.createRefund({
              refundId: existing.id,
              orgId: ctx.orgId,
              purchaseId: purchase.id,
              providerPaymentRef: purchase.providerPaymentRef,
              amountMinor: existing.amountMinor,
              reason: existing.reason,
            });
          } catch (error: unknown) {
            throw new ConsoleBillingError(
              'refund_provider_error',
              502,
              error instanceof Error ? error.message : 'Stripe refund request failed',
            );
          }
          const refund = applyMemoryRefundProviderState({
            store,
            refund: existing,
            provider: providerRefund,
            now: nowFn(),
          });
          return {
            created: false,
            refund,
            creditBalanceMinor: getMemoryStoreBalance(store),
          };
        }
        return {
          created: false,
          refund: existing,
          creditBalanceMinor: getMemoryStoreBalance(store),
        };
      }
      const purchase = store.purchases.get(normalized.purchaseId);
      if (!purchase || purchase.status !== 'SETTLED') {
        throw new ConsoleBillingError(
          'purchase_not_refundable',
          409,
          'Only settled credit purchases can be refunded',
        );
      }
      const remainingPurchaseAmount =
        purchase.amountMinor - activeRefundAmountForPurchase(store, purchase.id);
      if (normalized.amountMinor > remainingPurchaseAmount) {
        throw new ConsoleBillingError(
          'refund_amount_exceeds_purchase',
          409,
          'Refund amount exceeds the unrefunded purchase amount',
        );
      }
      const unusedCredit = getMemoryStoreBalance(store) - pendingConsoleRefundAmount(store);
      if (normalized.amountMinor > unusedCredit) {
        throw new ConsoleBillingError(
          'refund_amount_exceeds_credit',
          409,
          'Console refund amount exceeds unused prepaid credit',
        );
      }
      const now = nowFn();
      const requested = buildRequestedRefund({
        id: makeId('brf', now),
        orgId: ctx.orgId,
        purchaseId: purchase.id,
        amountMinor: normalized.amountMinor,
        reason: normalized.reason,
        requesterUserId: ctx.actorUserId,
        idempotencyKey: normalized.idempotencyKey,
        now,
      });
      store.refunds.set(requested.id, requested);
      let providerRefund: StripeRefundProviderOutput;
      try {
        providerRefund = await providers.stripe.createRefund({
          refundId: requested.id,
          orgId: ctx.orgId,
          purchaseId: purchase.id,
          providerPaymentRef: purchase.providerPaymentRef,
          amountMinor: requested.amountMinor,
          reason: requested.reason,
        });
      } catch (error: unknown) {
        throw new ConsoleBillingError(
          'refund_provider_error',
          502,
          error instanceof Error ? error.message : 'Stripe refund request failed',
        );
      }
      const refund = applyMemoryRefundProviderState({
        store,
        refund: requested,
        provider: providerRefund,
        now: nowFn(),
      });
      return {
        created: true,
        refund,
        creditBalanceMinor: getMemoryStoreBalance(store),
      };
    },

    async reconcileRefund(
      ctx: ConsoleBillingRefundSupportContext,
      request: BillingRefundReconcileRequest,
    ): Promise<BillingRefundResult> {
      requireRefundSupportContext(ctx);
      const refundId = request.refundId.trim();
      const store = ensureOrgStore(ctx.orgId);
      const refund = store.refunds.get(refundId);
      if (!refund) {
        throw new ConsoleBillingError('refund_not_found', 404, `Refund ${refundId} was not found`);
      }
      if (!refund.providerRefundId) {
        throw new ConsoleBillingError(
          'refund_not_reconcilable',
          409,
          `Refund ${refundId} has no Stripe refund reference`,
        );
      }
      const providerRefund = await providers.stripe.getRefund({
        providerRefundId: refund.providerRefundId,
      });
      const reconciled = applyMemoryRefundProviderState({
        store,
        refund,
        provider: providerRefund,
        now: nowFn(),
      });
      return {
        created: false,
        refund: reconciled,
        creditBalanceMinor: getMemoryStoreBalance(store),
      };
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const amountMinor = resolveCreditPackAmountMinorOrThrow(request.creditPackId);
      const purchaseId = makeId('bcp', now);
      const requestedPurchase: BillingCreditPurchase = {
        id: purchaseId,
        orgId: ctx.orgId,
        creditPackId: request.creditPackId,
        status: 'PENDING',
        amountMinor,
        currency: 'USD',
        provider: 'stripe',
        providerCheckoutSessionRef: null,
        providerCustomerRef: null,
        providerPaymentRef: null,
        relatedInvoiceId: null,
        settledAt: null,
        createdAt: coerceIsoDate(now),
        updatedAt: coerceIsoDate(now),
      };
      store.purchases.set(requestedPurchase.id, requestedPurchase);
      const providerCheckoutSession = await providers.stripe.createCheckoutSession({
        purchaseId,
        orgId: ctx.orgId,
        ...checkoutReturnUrls,
        creditPackId: request.creditPackId,
        amountMinor,
        now,
      });
      const id = String(providerCheckoutSession.id || '').trim();
      const url = String(providerCheckoutSession.url || '').trim();
      const customerRef = String(providerCheckoutSession.customerRef || '').trim();
      const expiresAt = String(providerCheckoutSession.expiresAt || '').trim();
      if (!id || !url || !customerRef || !expiresAt) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          500,
          'Stripe checkout-session provider returned invalid payload',
        );
      }
      const purchase: BillingCreditPurchase = {
        id: purchaseId,
        orgId: ctx.orgId,
        creditPackId: request.creditPackId,
        status: 'PENDING',
        amountMinor,
        currency: 'USD',
        provider: 'stripe',
        providerCheckoutSessionRef: id,
        providerCustomerRef: customerRef,
        providerPaymentRef: null,
        relatedInvoiceId: null,
        settledAt: null,
        createdAt: coerceIsoDate(now),
        updatedAt: coerceIsoDate(now),
      };
      store.purchases.set(purchase.id, purchase);
      return {
        id,
        purchaseId,
        url,
        customerRef,
        creditPackId: request.creditPackId,
        amountMinor,
        expiresAt,
      };
    },

    async reconcileStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionReconcileRequest,
    ): Promise<StripeCheckoutSessionReconcileResult> {
      const checkoutSessionId = String(request.checkoutSessionId || '').trim();
      if (!checkoutSessionId) {
        throw new ConsoleBillingError('invalid_body', 400, 'Field checkoutSessionId is required');
      }
      const store = ensureOrgStore(ctx.orgId);
      const purchase =
        Array.from(store.purchases.values()).find(
          (entry) => entry.providerCheckoutSessionRef === checkoutSessionId,
        ) || null;
      if (!purchase) {
        throw new ConsoleBillingError(
          'purchase_not_found',
          404,
          `No credit purchase found for Stripe checkout session ${checkoutSessionId}`,
        );
      }
      const wasSettled = purchase.status === 'SETTLED';
      const checkoutSession = await providers.stripe.getCheckoutSession({ checkoutSessionId });
      const providerOrgId = String(checkoutSession.orgId || '').trim();
      if (providerOrgId && providerOrgId !== ctx.orgId) {
        throw new ConsoleBillingError(
          'forbidden',
          403,
          'Stripe checkout session does not belong to the current organization',
        );
      }
      const paymentStatus = String(checkoutSession.paymentStatus || '')
        .trim()
        .toLowerCase();
      const checkoutStatus = String(checkoutSession.checkoutStatus || '')
        .trim()
        .toLowerCase();
      if (paymentStatus !== 'paid') {
        if (checkoutStatus === 'expired') {
          const result = await processStripeWebhookEventInternal(
            {
              eventId: `stripe_checkout_expired:${checkoutSessionId}`,
              eventType: 'checkout.session.expired',
              orgId: ctx.orgId,
              checkoutSessionId,
              providerRef: checkoutSessionId,
              purchaseId: checkoutSession.purchaseId,
            },
            false,
          );
          return {
            settled: false,
            settledNow: false,
            purchase: result.purchase,
            invoice: null,
            orgId: result.orgId,
            paymentStatus: paymentStatus || null,
            checkoutStatus,
          };
        }
        const projectedInvoice =
          purchase.relatedInvoiceId == null
            ? null
            : getProjectedInvoice(store, ctx.orgId, purchase.relatedInvoiceId, nowFn());
        return {
          settled: purchase.status === 'SETTLED',
          settledNow: false,
          purchase,
          invoice: projectedInvoice,
          orgId: ctx.orgId,
          paymentStatus: paymentStatus || null,
          checkoutStatus: checkoutStatus || null,
        };
      }
      const providerPaymentRef = String(checkoutSession.paymentIntentRef || '').trim();
      if (!providerPaymentRef) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          502,
          'Paid Stripe checkout session is missing its payment intent',
        );
      }
      const result = await processStripeWebhookEventInternal(
        {
          eventId: `stripe_checkout_reconcile:${checkoutSessionId}`,
          eventType: 'checkout.session.completed',
          orgId: ctx.orgId,
          checkoutSessionId,
          providerCustomerRef:
            String(checkoutSession.customerRef || '').trim() ||
            String(purchase.providerCustomerRef || '').trim() ||
            null,
          providerPaymentRef,
          providerRef: checkoutSessionId,
          purchaseId: checkoutSession.purchaseId,
          creditPackId: checkoutSession.creditPackId,
          amountMinor: checkoutSession.amountMinor,
          currency: checkoutSession.currency,
          paymentStatus: 'paid',
        },
        false,
      );
      return {
        settled: result.purchase?.status === 'SETTLED',
        settledNow: !wasSettled && result.purchase?.status === 'SETTLED',
        purchase: result.purchase,
        invoice: result.invoice,
        orgId: result.orgId,
        paymentStatus: paymentStatus || null,
        checkoutStatus: checkoutStatus || null,
      };
    },

    async processStripeWebhookEvent(
      request: StripeWebhookEventRequest,
    ): Promise<StripeWebhookEventResult> {
      return processStripeWebhookEventInternal(request, true);
    },

    async getStripePostProcessingOutboxItem(
      eventId: string,
    ): Promise<BillingStripePostProcessingOutboxItem | null> {
      const item = stripePostProcessingOutbox.get(String(eventId || '').trim());
      return item ? cloneStripePostProcessingOutboxItem(item) : null;
    },

    async listPendingStripePostProcessingOutboxItems(
      limit: number,
    ): Promise<BillingStripePostProcessingOutboxItem[]> {
      const normalizedLimit = Math.max(1, Math.min(Math.floor(limit), 100));
      return Array.from(stripePostProcessingOutbox.values())
        .filter(pendingStripePostProcessing)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt))
        .slice(0, normalizedLimit)
        .map(cloneStripePostProcessingOutboxItem);
    },

    async completeStripePostProcessingEffect(input: {
      eventId: string;
      effect: BillingStripePostProcessingEffect;
    }): Promise<BillingStripePostProcessingOutboxItem | null> {
      const item = stripePostProcessingOutbox.get(String(input.eventId || '').trim());
      if (!item) return null;
      const completedAt = coerceIsoDate(nowFn());
      const updated: BillingStripePostProcessingOutboxItem =
        input.effect === 'audit'
          ? { ...item, auditCompletedAt: completedAt, lastError: null, updatedAt: completedAt }
          : {
              ...item,
              customerWebhookCompletedAt: completedAt,
              lastError: null,
              updatedAt: completedAt,
            };
      stripePostProcessingOutbox.set(updated.eventId, updated);
      return cloneStripePostProcessingOutboxItem(updated);
    },

    async recordStripePostProcessingFailure(input: {
      eventId: string;
      error: string;
    }): Promise<BillingStripePostProcessingOutboxItem | null> {
      const item = stripePostProcessingOutbox.get(String(input.eventId || '').trim());
      if (!item) return null;
      const updatedAt = coerceIsoDate(nowFn());
      const updated: BillingStripePostProcessingOutboxItem = {
        ...item,
        attemptCount: item.attemptCount + 1,
        lastError: String(input.error || 'Stripe post-processing failed').slice(0, 1000),
        updatedAt,
      };
      stripePostProcessingOutbox.set(updated.eventId, updated);
      return cloneStripePostProcessingOutboxItem(updated);
    },
  };
  return service;
}
