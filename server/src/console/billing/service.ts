import { ConsoleBillingError } from './errors';
import { resolveCreditPackAmountMinorOrThrow } from './creditPacks';
import { resolveBillingProviderAdapters, type BillingProviderAdapters } from './providers';
import { resolveBillingLiveEnvironmentState } from './readiness';
import {
  normalizeManualAdjustmentRequest,
  requireBillingAdjustmentRole,
  requireKnownManualAdjustmentRelatedInvoiceId,
  requireLargeManualAdminDebitEscalationRole,
} from './adjustments';
import type {
  BillingCreditPurchase,
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
  BillingMonthlyActiveWallets,
  BillingOverview,
  BillingUsageAction,
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
} from './types';

export interface ConsoleBillingContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface ConsoleBillingService {
  getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview>;
  listAccountActivity(
    ctx: ConsoleBillingContext,
    request?: BillingAccountActivityRequest,
  ): Promise<BillingAccountActivityResult>;
  getMonthlyActiveWallets(
    ctx: ConsoleBillingContext,
    monthUtc?: string,
  ): Promise<BillingMonthlyActiveWallets>;
  recordUsageEvent(
    ctx: ConsoleBillingContext,
    request: BillingUsageEventRequest,
  ): Promise<BillingUsageEventResult>;
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
  createStripeCheckoutSession(
    ctx: ConsoleBillingContext,
    request: StripeCheckoutSessionRequest,
  ): Promise<StripeCheckoutSession>;
  reconcileStripeCheckoutSession(
    ctx: ConsoleBillingContext,
    request: StripeCheckoutSessionReconcileRequest,
  ): Promise<StripeCheckoutSessionReconcileResult>;
  processStripeWebhookEvent(request: StripeWebhookEventRequest): Promise<StripeWebhookEventResult>;
}

interface OrgBillingStore {
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
  purchases: Map<string, BillingCreditPurchase>;
  ledgerEntries: BillingLedgerEntry[];
  stripeWebhookEventIds: Set<string>;
  usageEventSourceIds: Set<string>;
  monthlyActiveWalletsByMonth: Map<string, Set<string>>;
  statementProjectionCreatedAtByMonth: Map<string, string>;
}

export interface InMemoryConsoleBillingServiceOptions {
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
}

const BILLABLE_USAGE_ACTIONS = new Set<BillingUsageAction>([
  'transfer',
  'swap',
  'approve',
  'contract_call',
]);
const MAW_USAGE_DEBIT_MINOR = 300;
const DEFAULT_LOW_BALANCE_THRESHOLD_MINOR = 2000;
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;
const DEFAULT_ACCOUNT_ACTIVITY_LIMIT = 25;
const MAX_ACCOUNT_ACTIVITY_LIMIT = 100;

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
  const rand = Math.random().toString(36).slice(2, 10);
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
  monthlyActiveWallets: number;
  createdAt: string;
}): BillingInvoiceLineItem[] {
  if (input.monthlyActiveWallets <= 0) return [];
  return [
    makeInvoiceLineItem({
      orgId: input.orgId,
      invoiceId: input.invoiceId,
      periodMonthUtc: input.periodMonthUtc,
      itemType: 'MAW_USAGE_DEBIT',
      description: `Monthly Active Wallets (${input.periodMonthUtc})`,
      quantity: input.monthlyActiveWallets,
      unitAmountMinor: MAW_USAGE_DEBIT_MINOR,
      createdAt: input.createdAt,
    }),
  ];
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

function parseInvoiceCursor(
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

function encodeInvoiceCursor(invoice: BillingInvoice): string {
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

function outstandingAmountMinor(invoice: BillingInvoice): number {
  return Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
}

export function createInMemoryConsoleBillingService(
  options: InMemoryConsoleBillingServiceOptions = {},
): ConsoleBillingService {
  const nowFn = options.now || (() => new Date());
  const providers = resolveBillingProviderAdapters(options.providers);
  const orgStores = new Map<string, OrgBillingStore>();

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

  function getUsageDebitEntriesForMonth(
    store: OrgBillingStore,
    monthUtc: string,
  ): BillingLedgerEntry[] {
    return store.ledgerEntries.filter(
      (entry) => entry.type === 'USAGE_DEBIT' && entry.monthUtc === monthUtc,
    );
  }

  function getProjectedUsageStatement(
    store: OrgBillingStore,
    orgId: string,
    monthUtc: string,
  ): BillingInvoice | null {
    const debitEntries = getUsageDebitEntriesForMonth(store, monthUtc);
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

    const monthlyActiveWallets = getUsageDebitEntriesForMonth(store, invoice.periodMonthUtc).length;
    return buildInvoiceLineItems({
      orgId: invoice.orgId,
      invoiceId: invoice.id,
      periodMonthUtc: invoice.periodMonthUtc,
      monthlyActiveWallets,
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
      monthlyActiveWallets: 0,
      creditBalanceMinor: 0,
      lowBalanceThresholdMinor: DEFAULT_LOW_BALANCE_THRESHOLD_MINOR,
      purchases: new Map(),
      ledgerEntries: [],
      stripeWebhookEventIds: new Set(),
      usageEventSourceIds: new Set(),
      monthlyActiveWalletsByMonth: new Map(),
      statementProjectionCreatedAtByMonth: new Map(),
    };
    ensureCurrentPeriodStatementSeed(store, nowFn());
    orgStores.set(orgId, store);
    return store;
  }

  function appendLedgerEntry(
    store: OrgBillingStore,
    input: Omit<BillingLedgerEntry, 'id' | 'createdAt'> & { now: Date },
  ): BillingLedgerEntry {
    const entry: BillingLedgerEntry = {
      id: makeId('ble', input.now),
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
      createdAt: coerceIsoDate(input.now),
    };
    store.ledgerEntries.push(entry);
    return entry;
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
      now: Date;
    },
  ): BillingCreditPurchase {
    const purchase = store.purchases.get(input.purchaseId);
    if (!purchase) {
      throw new ConsoleBillingError(
        'purchase_not_found',
        404,
        `Credit purchase ${input.purchaseId} was not found`,
      );
    }
    if (purchase.status === 'SETTLED') return purchase;
    const monthUtc = formatCurrentMonthUtc(input.now);
    appendLedgerEntry(store, {
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
    purchase.status = 'SETTLED';
    purchase.relatedInvoiceId = `receipt_${purchase.id}`;
    purchase.providerCustomerRef =
      purchase.providerCustomerRef || makeStripeCustomerRef(input.orgId);
    purchase.settledAt = coerceIsoDate(input.now);
    purchase.updatedAt = coerceIsoDate(input.now);
    store.creditBalanceMinor += purchase.amountMinor;
    store.purchases.set(purchase.id, purchase);
    return purchase;
  }

  function ensureMonthlyWalletSet(store: OrgBillingStore, monthUtc: string): Set<string> {
    const existing = store.monthlyActiveWalletsByMonth.get(monthUtc);
    if (existing) return existing;
    const created = new Set<string>();
    store.monthlyActiveWalletsByMonth.set(monthUtc, created);
    return created;
  }

  function getMonthlyActiveWalletCount(store: OrgBillingStore, monthUtc: string): number {
    return ensureMonthlyWalletSet(store, monthUtc).size;
  }

  function resolveWebhookStore(request: StripeWebhookEventRequest): {
    orgId: string;
    store: OrgBillingStore;
    purchase: BillingCreditPurchase | null;
  } | null {
    const requestedOrgId = String(request.orgId || '').trim();
    const checkoutSessionRef = String(
      request.checkoutSessionId || request.providerRef || '',
    ).trim();
    const providerCustomerRef = String(request.providerCustomerRef || '').trim();

    if (requestedOrgId) {
      const store = orgStores.get(requestedOrgId);
      if (!store) return null;
      const purchase =
        Array.from(store.purchases.values()).find(
          (entry) =>
            (checkoutSessionRef && entry.providerCheckoutSessionRef === checkoutSessionRef) ||
            (providerCustomerRef && entry.providerCustomerRef === providerCustomerRef),
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
          (entry) =>
            (checkoutSessionRef && entry.providerCheckoutSessionRef === checkoutSessionRef) ||
            (providerCustomerRef && entry.providerCustomerRef === providerCustomerRef),
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
  ): Promise<StripeWebhookEventResult> {
    const eventType = String(request.eventType || 'checkout.session.completed').trim();
    if (eventType !== 'checkout.session.completed') {
      return {
        accepted: true,
        purchase: null,
        invoice: null,
        orgId: null,
      };
    }

    const now = nowFn();
    const resolved = resolveWebhookStore(request);
    if (!resolved) {
      return {
        accepted: true,
        purchase: null,
        invoice: null,
        orgId: null,
      };
    }

    const { orgId, store } = resolved;
    const checkoutSessionRef = String(request.checkoutSessionId || request.providerRef || '').trim();
    const providerCustomerRef = String(request.providerCustomerRef || '').trim();
    const matchedPurchase =
      resolved.purchase ||
      Array.from(store.purchases.values()).find(
        (entry) =>
          (checkoutSessionRef && entry.providerCheckoutSessionRef === checkoutSessionRef) ||
          (providerCustomerRef && entry.providerCustomerRef === providerCustomerRef),
      ) ||
      null;

    const projectedInvoice = matchedPurchase?.relatedInvoiceId
      ? getProjectedInvoice(store, orgId, matchedPurchase.relatedInvoiceId, now)
      : null;

    if (store.stripeWebhookEventIds.has(request.eventId)) {
      return {
        accepted: false,
        purchase: matchedPurchase,
        invoice: projectedInvoice,
        orgId,
      };
    }

    let purchase: BillingCreditPurchase | null = matchedPurchase;
    let invoice = projectedInvoice;
    if (matchedPurchase) {
      purchase = settleCreditPurchase(store, {
        orgId,
        purchaseId: matchedPurchase.id,
        now,
      });
      invoice = purchase.relatedInvoiceId
        ? getProjectedInvoice(store, orgId, purchase.relatedInvoiceId, now)
        : null;
    }

    store.stripeWebhookEventIds.add(request.eventId);
    return {
      accepted: true,
      purchase,
      invoice,
      orgId,
    };
  }

  const service: ConsoleBillingService = {
    async getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const currentMonthUtc = formatCurrentMonthUtc(now);
      store.monthlyActiveWallets = getMonthlyActiveWalletCount(store, currentMonthUtc);
      const projectedInvoices = listProjectedInvoices(store, ctx.orgId, now);

      return {
        usageMetricVersion: 'maw_v1',
        currentMonthUtc,
        monthlyActiveWallets: store.monthlyActiveWallets,
        creditBalanceMinor: store.creditBalanceMinor,
        lowBalanceThresholdMinor: store.lowBalanceThresholdMinor,
        liveEnvironmentState: resolveBillingLiveEnvironmentState({
          creditBalanceMinor: store.creditBalanceMinor,
          lowBalanceThresholdMinor: store.lowBalanceThresholdMinor,
        }),
        recentUsageDebitMinor: getCurrentMonthUsageDebitMinor(store, currentMonthUtc),
        recentCreditPurchasedMinor: getCurrentMonthPurchasedMinor(store, currentMonthUtc),
        documentCount: projectedInvoices.length,
      };
    },

    async listAccountActivity(
      ctx: ConsoleBillingContext,
      request: BillingAccountActivityRequest = {},
    ): Promise<BillingAccountActivityResult> {
      const store = ensureOrgStore(ctx.orgId);
      return {
        entries: sortLedgerEntriesByMostRecent(store.ledgerEntries).slice(
          0,
          normalizeAccountActivityLimit(request.limit),
        ),
      };
    },

    async getMonthlyActiveWallets(
      ctx: ConsoleBillingContext,
      monthUtc?: string,
    ): Promise<BillingMonthlyActiveWallets> {
      const store = ensureOrgStore(ctx.orgId);
      const resolvedMonth = monthUtc
        ? parseMonthUtcOrThrow(monthUtc)
        : formatCurrentMonthUtc(nowFn());
      const monthlyActiveWallets = getMonthlyActiveWalletCount(store, resolvedMonth);
      if (resolvedMonth === formatCurrentMonthUtc(nowFn())) {
        store.monthlyActiveWallets = monthlyActiveWallets;
      }
      return {
        usageMetricVersion: 'maw_v1',
        monthUtc: resolvedMonth,
        monthlyActiveWallets,
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
          monthlyActiveWallets: getMonthlyActiveWalletCount(store, monthUtc),
          debitAppliedMinor: 0,
          creditBalanceMinor: store.creditBalanceMinor,
          statementId: statement?.id || null,
        };
      }

      const occurredAtMs = request.occurredAt ? Date.parse(request.occurredAt) : nowFn().getTime();
      if (!Number.isFinite(occurredAtMs)) {
        throw new ConsoleBillingError('invalid_usage_event', 400, 'Invalid occurredAt value');
      }
      const monthUtc = monthUtcFromEpochMs(occurredAtMs);
      const counted =
        BILLABLE_USAGE_ACTIONS.has(request.action) &&
        request.succeeded &&
        !request.isSimulation &&
        !request.isInternalRetry;
      if (request.sourceEventId) {
        store.usageEventSourceIds.add(request.sourceEventId);
      }
      let debitAppliedMinor = 0;
      if (counted) {
        const monthSet = ensureMonthlyWalletSet(store, monthUtc);
        const alreadyCounted = monthSet.has(request.walletId);
        monthSet.add(request.walletId);
        if (!alreadyCounted) {
          debitAppliedMinor = MAW_USAGE_DEBIT_MINOR;
          store.creditBalanceMinor -= debitAppliedMinor;
          ensureStatementProjectionSeed(store, monthUtc, new Date(occurredAtMs));
          appendLedgerEntry(store, {
            now: new Date(occurredAtMs),
            orgId: ctx.orgId,
            type: 'USAGE_DEBIT',
            amountMinor: -debitAppliedMinor,
            currency: 'USD',
            description: `MAW usage debit for wallet ${request.walletId}`,
            monthUtc,
            relatedInvoiceId: makeUsageStatementId(monthUtc),
            relatedPurchaseId: null,
            sourceEventId: request.sourceEventId || null,
            actorType: 'USER',
            actorUserId: ctx.actorUserId,
            reasonCode: 'usage_debit',
            note: `Usage debit recorded for wallet ${request.walletId}`,
            idempotencyKey: request.sourceEventId
              ? `usage_debit:${request.sourceEventId}`
              : `usage_debit:${monthUtc}:${request.walletId}:${occurredAtMs}`,
          });
        }
      }

      const monthlyActiveWallets = getMonthlyActiveWalletCount(store, monthUtc);
      const statement = getProjectedUsageStatement(store, ctx.orgId, monthUtc);
      if (monthUtc === formatCurrentMonthUtc(nowFn())) {
        store.monthlyActiveWallets = monthlyActiveWallets;
      }
      return {
        accepted: true,
        counted,
        monthUtc,
        monthlyActiveWallets,
        debitAppliedMinor,
        creditBalanceMinor: store.creditBalanceMinor,
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
      const monthlyActiveWallets = getUsageDebitEntriesForMonth(store, periodMonthUtc).length;

      return {
        generated: false,
        invoice,
        lineItems: sortLineItems(nextLineItems),
        monthlyActiveWallets,
        pricing: {
          mawUnitPriceMinor: MAW_USAGE_DEBIT_MINOR,
        },
      };
    },

    async grantManualSupportCredit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const existing = findLedgerEntryByIdempotencyKey(store, normalizedRequest.idempotencyKey);
      if (existing) {
        return {
          created: false,
          adjustment: existing,
          creditBalanceMinor: store.creditBalanceMinor,
        };
      }
      const relatedInvoiceId = ensureManualAdjustmentRelatedInvoiceId(
        store,
        ctx.orgId,
        normalizedRequest.relatedInvoiceId,
        now,
      );
      const adjustment = appendLedgerEntry(store, {
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
      store.creditBalanceMinor += normalizedRequest.amountMinor;
      return {
        created: true,
        adjustment,
        creditBalanceMinor: store.creditBalanceMinor,
      };
    },

    async appendManualAdminDebit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const existing = findLedgerEntryByIdempotencyKey(store, normalizedRequest.idempotencyKey);
      if (existing) {
        requireLargeManualAdminDebitEscalationRole(ctx, Math.abs(existing.amountMinor));
        return {
          created: false,
          adjustment: existing,
          creditBalanceMinor: store.creditBalanceMinor,
        };
      }
      requireLargeManualAdminDebitEscalationRole(ctx, normalizedRequest.amountMinor);
      const relatedInvoiceId = ensureManualAdjustmentRelatedInvoiceId(
        store,
        ctx.orgId,
        normalizedRequest.relatedInvoiceId,
        now,
      );
      const adjustment = appendLedgerEntry(store, {
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
      store.creditBalanceMinor -= normalizedRequest.amountMinor;
      return {
        created: true,
        adjustment,
        creditBalanceMinor: store.creditBalanceMinor,
      };
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const amountMinor = resolveCreditPackAmountMinorOrThrow({
        creditPackId: request.creditPackId,
        customAmountMinor: request.customAmountMinor,
      });
      const providerCheckoutSession = await providers.stripe.createCheckoutSession({
        orgId: ctx.orgId,
        successUrl: request.successUrl,
        cancelUrl: request.cancelUrl,
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
        id: makeId('bcp', now),
        orgId: ctx.orgId,
        creditPackId: request.creditPackId,
        status: 'PENDING',
        amountMinor,
        currency: 'USD',
        provider: 'stripe',
        providerCheckoutSessionRef: id,
        providerCustomerRef: customerRef,
        relatedInvoiceId: null,
        settledAt: null,
        createdAt: coerceIsoDate(now),
        updatedAt: coerceIsoDate(now),
      };
      store.purchases.set(purchase.id, purchase);
      return {
        id,
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
        throw new ConsoleBillingError(
          'invalid_body',
          400,
          'Field checkoutSessionId is required',
        );
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
      const paymentStatus = String(checkoutSession.paymentStatus || '').trim().toLowerCase();
      const checkoutStatus = String(checkoutSession.checkoutStatus || '').trim().toLowerCase();
      if (paymentStatus !== 'paid') {
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
      const result = await processStripeWebhookEventInternal({
        eventId: `stripe_checkout_reconcile:${checkoutSessionId}`,
        eventType: 'checkout.session.completed',
        orgId: ctx.orgId,
        checkoutSessionId,
        providerCustomerRef:
          String(checkoutSession.customerRef || '').trim() ||
          String(purchase.providerCustomerRef || '').trim() ||
          undefined,
        providerRef: checkoutSessionId,
      });
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
      return processStripeWebhookEventInternal(request);
    },
  };
  return service;
}
