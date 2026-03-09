import { canTransitionPaymentState, type PaymentState } from './paymentStateMachine';
import { ConsoleBillingError } from './errors';
import { getChainFinalityPolicy } from './stablecoinAssets';
import { resolveBillingProviderAdapters, type BillingProviderAdapters } from './providers';
import type {
  AddCardPaymentMethodRequest,
  BillingInvoiceActivity,
  BillingInvoiceActivityEntry,
  BillingInvoice,
  BillingInvoiceLineItem,
  BillingInvoiceLineItemType,
  BillingInvoiceListRequest,
  BillingInvoiceListResult,
  BillingInvoiceListSummary,
  BillingMonthlyActiveWallets,
  BillingOverview,
  BillingSubscription,
  BillingPaymentMethod,
  BillingUsageAction,
  BillingUsageEventRequest,
  BillingUsageEventResult,
  GenerateMonthlyInvoiceRequest,
  GenerateMonthlyInvoiceResult,
  InvoicePaymentRail,
  StablecoinPaymentIntent,
  StablecoinPaymentIntentReconcileRequest,
  StablecoinPaymentIntentRequest,
  StablecoinPaymentQuote,
  StablecoinQuoteRequest,
  StripePaymentIntent,
  StripePaymentIntentReconcileRequest,
  StripePaymentIntentRequest,
  StripeWebhookEventRequest,
  StripeWebhookEventResult,
  StripeCustomerPortalSession,
  StripeCustomerPortalSessionRequest,
  StripeCheckoutSession,
  StripeCheckoutSessionRequest,
  StripeSetupIntent,
  StripeSetupIntentRequest,
} from './types';

export interface ConsoleBillingContext {
  orgId: string;
  actorUserId: string;
  roles: string[];
}

export interface ConsoleBillingService {
  getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview>;
  getSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription>;
  cancelSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription>;
  resumeSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription>;
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

  listPaymentMethods(ctx: ConsoleBillingContext): Promise<BillingPaymentMethod[]>;
  addCardPaymentMethod(
    ctx: ConsoleBillingContext,
    request: AddCardPaymentMethodRequest,
  ): Promise<BillingPaymentMethod>;
  removeCardPaymentMethod(
    ctx: ConsoleBillingContext,
    paymentMethodId: string,
  ): Promise<{ removed: boolean }>;
  setDefaultCardPaymentMethod(
    ctx: ConsoleBillingContext,
    paymentMethodId: string,
  ): Promise<BillingPaymentMethod | null>;

  createStripeSetupIntent(
    ctx: ConsoleBillingContext,
    request: StripeSetupIntentRequest,
  ): Promise<StripeSetupIntent>;
  createStripeCheckoutSession(
    ctx: ConsoleBillingContext,
    request: StripeCheckoutSessionRequest,
  ): Promise<StripeCheckoutSession>;
  createStripeCustomerPortalSession(
    ctx: ConsoleBillingContext,
    request: StripeCustomerPortalSessionRequest,
  ): Promise<StripeCustomerPortalSession>;
  createStripePaymentIntent(
    ctx: ConsoleBillingContext,
    request: StripePaymentIntentRequest,
  ): Promise<StripePaymentIntent>;
  reconcileStripePaymentIntent(
    ctx: ConsoleBillingContext,
    paymentIntentId: string,
    request: StripePaymentIntentReconcileRequest,
  ): Promise<StripePaymentIntent | null>;
  processStripeWebhookEvent(request: StripeWebhookEventRequest): Promise<StripeWebhookEventResult>;

  createStablecoinQuote(
    ctx: ConsoleBillingContext,
    request: StablecoinQuoteRequest,
  ): Promise<StablecoinPaymentQuote>;
  createStablecoinPaymentIntent(
    ctx: ConsoleBillingContext,
    request: StablecoinPaymentIntentRequest,
  ): Promise<StablecoinPaymentIntent>;
  getStablecoinPaymentIntent(
    ctx: ConsoleBillingContext,
    paymentIntentId: string,
  ): Promise<StablecoinPaymentIntent | null>;
  cancelStablecoinPaymentIntent(
    ctx: ConsoleBillingContext,
    paymentIntentId: string,
  ): Promise<StablecoinPaymentIntent | null>;
  reconcileStablecoinPaymentIntent(
    ctx: ConsoleBillingContext,
    paymentIntentId: string,
    request: StablecoinPaymentIntentReconcileRequest,
  ): Promise<StablecoinPaymentIntent | null>;
}

interface OrgBillingStore {
  planId: string;
  planName: string;
  subscription: BillingSubscription;
  monthlyActiveWallets: number;
  creditBalanceMinor: number;
  invoices: Map<string, BillingInvoice>;
  invoiceLineItems: Map<string, BillingInvoiceLineItem[]>;
  paymentMethods: Map<string, BillingPaymentMethod>;
  stripePaymentIntents: Map<string, StripePaymentIntent>;
  stripeWebhookEventIds: Set<string>;
  stablecoinQuotes: Map<string, StablecoinPaymentQuote>;
  stablecoinPaymentIntents: Map<string, StablecoinPaymentIntent>;
  paymentStateTransitions: Map<
    string,
    Array<{
      fromState: PaymentState | null;
      toState: PaymentState;
      changedAt: string;
      actorType: 'USER' | 'SYSTEM' | 'PROVIDER';
      actorUserId: string | null;
      sourceEventId: string | null;
      reason: string | null;
    }>
  >;
  usageEventSourceIds: Set<string>;
  monthlyActiveWalletsByMonth: Map<string, Set<string>>;
}

export interface InMemoryConsoleBillingServiceOptions {
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
}

const TERMINAL_PAYMENT_STATES = new Set<PaymentState>([
  'SETTLED',
  'PARTIALLY_SETTLED',
  'OVERPAID',
  'FAILED',
  'CANCELED',
  'EXPIRED',
  'REFUNDED',
  'DISPUTED',
]);

const SETTLEMENT_OUTCOME_STATES = new Set<PaymentState>([
  'SETTLED',
  'PARTIALLY_SETTLED',
  'OVERPAID',
]);
const BILLABLE_USAGE_ACTIONS = new Set<BillingUsageAction>([
  'transfer',
  'swap',
  'approve',
  'contract_call',
]);
const DEFAULT_MONTHLY_PLAN_AMOUNT_MINOR = 4900;
const PLAN_BASE_FEE_MINOR = 1900;
const PLAN_MAW_UNIT_PRICE_MINOR = 300;
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;

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

function makeStripeSubscriptionRef(orgId: string): string {
  return `sub_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function makeInitialSubscription(
  orgId: string,
  planId: string,
  planName: string,
  now: Date,
): BillingSubscription {
  const currentPeriodStart = coerceIsoDate(now);
  const currentPeriodEnd = coerceIsoDate(new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000));
  return {
    id: makeId('sub', now),
    orgId,
    provider: 'stripe',
    providerCustomerRef: makeStripeCustomerRef(orgId),
    providerSubscriptionRef: makeStripeSubscriptionRef(orgId),
    planId,
    planName,
    status: 'ACTIVE',
    cancelAtPeriodEnd: false,
    currentPeriodStart,
    currentPeriodEnd,
    cancelAt: null,
    canceledAt: null,
    createdAt: currentPeriodStart,
    updatedAt: currentPeriodStart,
  };
}

function refreshSubscriptionLifecycle(subscription: BillingSubscription, now: Date): void {
  if (subscription.status === 'CANCELED') return;
  if (!subscription.cancelAtPeriodEnd) return;
  const currentPeriodEndMs = Date.parse(subscription.currentPeriodEnd);
  if (!Number.isFinite(currentPeriodEndMs)) return;
  if (now.getTime() < currentPeriodEndMs) return;
  const canceledAtIso = coerceIsoDate(new Date(currentPeriodEndMs));
  subscription.status = 'CANCELED';
  subscription.cancelAtPeriodEnd = false;
  subscription.cancelAt = canceledAtIso;
  subscription.canceledAt = canceledAtIso;
  subscription.updatedAt = coerceIsoDate(now);
}

function makeMonthlyInvoice(orgId: string, monthUtc: string, now: Date): BillingInvoice {
  return {
    id: `inv_${monthUtc.replace('-', '')}_001`,
    orgId,
    status: 'OPEN',
    currency: 'USD',
    amountDueMinor: DEFAULT_MONTHLY_PLAN_AMOUNT_MINOR,
    amountPaidMinor: 0,
    railLock: null,
    periodMonthUtc: monthUtc,
    createdAt: coerceIsoDate(now),
    dueAt: coerceIsoDate(new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000)),
  };
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
  return [
    makeInvoiceLineItem({
      orgId: input.orgId,
      invoiceId: input.invoiceId,
      periodMonthUtc: input.periodMonthUtc,
      itemType: 'PLAN_BASE_FEE',
      description: `Base platform fee (${input.periodMonthUtc})`,
      quantity: 1,
      unitAmountMinor: PLAN_BASE_FEE_MINOR,
      createdAt: input.createdAt,
    }),
    makeInvoiceLineItem({
      orgId: input.orgId,
      invoiceId: input.invoiceId,
      periodMonthUtc: input.periodMonthUtc,
      itemType: 'MAW_USAGE',
      description: `Monthly Active Wallets (${input.periodMonthUtc})`,
      quantity: input.monthlyActiveWallets,
      unitAmountMinor: PLAN_MAW_UNIT_PRICE_MINOR,
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
  return invoices.filter((invoice) => {
    if (status && invoice.status !== status) return false;
    if (request?.overdueOnly && !isInvoiceOverdueAt(invoice, now)) return false;
    if (periodMonthUtc && invoice.periodMonthUtc !== periodMonthUtc) return false;
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
  return {
    totalCount: invoices.length,
    openCount,
    overdueCount,
    paidCount,
    outstandingAmountMinor: totalOutstandingAmountMinor,
    latestPeriodMonthUtc: invoices[0]?.periodMonthUtc || null,
  };
}

function buildPaymentTransitionSummary(
  rail: InvoicePaymentRail,
  toState: PaymentState,
  paymentId: string,
  reason: string | null,
): string {
  const railLabel = rail === 'CARD' ? 'Card payment' : 'Stablecoin payment';
  const stateLabel = String(toState || '')
    .trim()
    .toLowerCase()
    .replace(/_/g, ' ');
  const reasonText = reason
    ? ` Reason: ${String(reason).trim().toLowerCase().replace(/_/g, ' ')}.`
    : '';
  return `${railLabel} ${paymentId} moved to ${stateLabel}.${reasonText}`;
}

function sumLineItemAmounts(lineItems: BillingInvoiceLineItem[]): number {
  return lineItems.reduce((total, item) => total + item.amountMinor, 0);
}

function sortLineItems(items: BillingInvoiceLineItem[]): BillingInvoiceLineItem[] {
  return [...items].sort((a, b) => a.itemType.localeCompare(b.itemType));
}

function lineItemsEquivalent(a: BillingInvoiceLineItem[], b: BillingInvoiceLineItem[]): boolean {
  const left = sortLineItems(a);
  const right = sortLineItems(b);
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) {
    const la = left[i];
    const rb = right[i];
    if (la.itemType !== rb.itemType) return false;
    if (la.quantity !== rb.quantity) return false;
    if (la.unitAmountMinor !== rb.unitAmountMinor) return false;
    if (la.amountMinor !== rb.amountMinor) return false;
    if (la.periodMonthUtc !== rb.periodMonthUtc) return false;
  }
  return true;
}

function outstandingAmountMinor(invoice: BillingInvoice): number {
  return Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
}

function hasAdminRole(roles: string[]): boolean {
  return roles.some(
    (role) =>
      String(role || '')
        .trim()
        .toLowerCase() === 'admin',
  );
}

function requireAdminForCardActions(ctx: ConsoleBillingContext): void {
  if (hasAdminRole(ctx.roles)) return;
  throw new ConsoleBillingError(
    'forbidden',
    403,
    'Only admin can add, remove, or set default card payment methods',
  );
}

function isTerminalPaymentState(state: PaymentState): boolean {
  return TERMINAL_PAYMENT_STATES.has(state);
}

function isActivePaymentState(state: PaymentState): boolean {
  return !isTerminalPaymentState(state);
}

function computeStablecoinReorgRiskWindowEndsAt(
  settledAt: string | null,
  reorgRiskWindowHours: number,
): string | null {
  if (!settledAt) return null;
  const settledAtMs = Date.parse(settledAt);
  if (!Number.isFinite(settledAtMs)) return null;
  return coerceIsoDate(new Date(settledAtMs + reorgRiskWindowHours * 60 * 60 * 1000));
}

function refreshStablecoinRiskWindowState(intent: StablecoinPaymentIntent, now: Date): void {
  intent.reorgRiskWindowEndsAt = computeStablecoinReorgRiskWindowEndsAt(
    intent.settledAt,
    intent.reorgRiskWindowHours,
  );
  if (!intent.reorgRiskWindowEndsAt) {
    intent.withinReorgRiskWindow = false;
    return;
  }
  const riskWindowEndsAtMs = Date.parse(intent.reorgRiskWindowEndsAt);
  intent.withinReorgRiskWindow =
    Number.isFinite(riskWindowEndsAtMs) && now.getTime() < riskWindowEndsAtMs;
}

function decideStablecoinReconcileTransition(input: {
  currentState: PaymentState;
  expectedAmountMinor: number;
  observedAmountMinor: number;
  observedConfirmations: number;
  requiredConfirmations: number;
  confirmationTimedOut: boolean;
}): { targetState: PaymentState | null; reason: string | null } {
  if (input.confirmationTimedOut) {
    return { targetState: 'FAILED', reason: 'CONFIRMATION_TIMEOUT' };
  }

  const confirmationsMet = input.observedConfirmations >= input.requiredConfirmations;
  if (!confirmationsMet) {
    if (input.currentState === 'CONFIRMING') {
      return { targetState: null, reason: null };
    }
    return { targetState: 'CONFIRMING', reason: 'confirmations_pending' };
  }

  if (input.observedAmountMinor <= 0) {
    return { targetState: 'FAILED', reason: 'INVALID_OBSERVED_AMOUNT' };
  }
  if (input.observedAmountMinor < input.expectedAmountMinor) {
    return { targetState: 'PARTIALLY_SETTLED', reason: 'underpaid' };
  }
  if (input.observedAmountMinor > input.expectedAmountMinor) {
    return { targetState: 'OVERPAID', reason: 'overpaid' };
  }
  return { targetState: 'SETTLED', reason: 'amount_matched' };
}

function decideStripeReconcileTransition(input: {
  currentState: PaymentState;
  providerStatus: StripePaymentIntentReconcileRequest['providerStatus'];
  expectedAmountMinor: number;
  settledAmountMinor: number;
}): { targetState: PaymentState | null; reason: string | null } {
  if (input.providerStatus === 'ACTION_REQUIRED') {
    if (input.currentState === 'ACTION_REQUIRED') return { targetState: null, reason: null };
    return { targetState: 'ACTION_REQUIRED', reason: 'provider_action_required' };
  }
  if (input.providerStatus === 'PENDING') {
    if (input.currentState === 'PENDING') return { targetState: null, reason: null };
    return { targetState: 'PENDING', reason: 'provider_pending' };
  }
  if (input.providerStatus === 'FAILED') {
    if (input.currentState === 'FAILED') return { targetState: null, reason: null };
    return { targetState: 'FAILED', reason: 'provider_failed' };
  }
  if (input.providerStatus === 'CANCELED') {
    if (input.currentState === 'CANCELED') return { targetState: null, reason: null };
    return { targetState: 'CANCELED', reason: 'provider_canceled' };
  }
  if (input.settledAmountMinor <= 0) {
    return { targetState: 'FAILED', reason: 'INVALID_SETTLED_AMOUNT' };
  }
  if (input.settledAmountMinor < input.expectedAmountMinor) {
    return { targetState: 'PARTIALLY_SETTLED', reason: 'underpaid' };
  }
  if (input.settledAmountMinor > input.expectedAmountMinor) {
    return { targetState: 'OVERPAID', reason: 'overpaid' };
  }
  return { targetState: 'SETTLED', reason: 'amount_matched' };
}

export function createInMemoryConsoleBillingService(
  options: InMemoryConsoleBillingServiceOptions = {},
): ConsoleBillingService {
  const nowFn = options.now || (() => new Date());
  const providers = resolveBillingProviderAdapters(options.providers);
  const orgStores = new Map<string, OrgBillingStore>();

  function ensureCurrentPeriodInvoice(store: OrgBillingStore, orgId: string, now: Date): void {
    const periodMonthUtc = formatCurrentMonthUtc(now);
    const exists = Array.from(store.invoices.values()).some(
      (invoice) => invoice.periodMonthUtc === periodMonthUtc,
    );
    if (exists) return;
    const invoice = makeMonthlyInvoice(orgId, periodMonthUtc, now);
    store.invoices.set(invoice.id, invoice);
  }

  function ensureOrgStore(orgId: string): OrgBillingStore {
    const existing = orgStores.get(orgId);
    if (existing) {
      ensureCurrentPeriodInvoice(existing, orgId, nowFn());
      return existing;
    }

    const store: OrgBillingStore = {
      planId: 'pro_maw_v1',
      planName: 'Pro MAW',
      subscription: makeInitialSubscription(orgId, 'pro_maw_v1', 'Pro MAW', nowFn()),
      monthlyActiveWallets: 0,
      creditBalanceMinor: 0,
      invoices: new Map(),
      invoiceLineItems: new Map(),
      paymentMethods: new Map(),
      stripePaymentIntents: new Map(),
      stripeWebhookEventIds: new Set(),
      stablecoinQuotes: new Map(),
      stablecoinPaymentIntents: new Map(),
      paymentStateTransitions: new Map(),
      usageEventSourceIds: new Set(),
      monthlyActiveWalletsByMonth: new Map(),
    };
    ensureCurrentPeriodInvoice(store, orgId, nowFn());
    orgStores.set(orgId, store);
    return store;
  }

  function lockInvoiceRail(invoice: BillingInvoice, requestedRail: InvoicePaymentRail): void {
    if (invoice.railLock && invoice.railLock !== requestedRail) {
      throw new ConsoleBillingError(
        'invoice_rail_locked',
        409,
        `Invoice ${invoice.id} is locked to ${invoice.railLock} and cannot use ${requestedRail}`,
      );
    }
    invoice.railLock = requestedRail;
  }

  function ensureInvoiceOpen(invoice: BillingInvoice): void {
    if (invoice.status !== 'OPEN') {
      throw new ConsoleBillingError('invoice_not_open', 409, `Invoice ${invoice.id} is not open`);
    }
    if (outstandingAmountMinor(invoice) <= 0) {
      throw new ConsoleBillingError(
        'invoice_already_paid',
        409,
        `Invoice ${invoice.id} is already fully paid`,
      );
    }
  }

  function appendPaymentStateTransition(
    store: OrgBillingStore,
    paymentId: string,
    input: {
      fromState: PaymentState | null;
      toState: PaymentState;
      changedAt: string;
      actorType: 'USER' | 'SYSTEM' | 'PROVIDER';
      actorUserId: string | null;
      sourceEventId?: string | null;
      reason: string | null;
    },
  ): void {
    const existing = store.paymentStateTransitions.get(paymentId) || [];
    existing.push({
      ...input,
      sourceEventId: input.sourceEventId || null,
    });
    store.paymentStateTransitions.set(paymentId, existing);
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

  function markStablecoinIntentExpiredIfNeeded(
    store: OrgBillingStore,
    intent: StablecoinPaymentIntent,
    now: Date,
  ): void {
    if (intent.state === 'EXPIRED') return;
    const expiresAt = new Date(intent.expiresAt).getTime();
    if (!Number.isFinite(expiresAt) || now.getTime() <= expiresAt) return;
    const fromState = intent.state;
    const transition = canTransitionPaymentState({
      from: fromState,
      to: 'EXPIRED',
    });
    if (transition.ok) {
      intent.state = 'EXPIRED';
      appendPaymentStateTransition(store, intent.id, {
        fromState,
        toState: 'EXPIRED',
        changedAt: coerceIsoDate(now),
        actorType: 'SYSTEM',
        actorUserId: null,
        reason: 'payment_intent_expired',
      });
    }
  }

  return {
    async getSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      refreshSubscriptionLifecycle(store.subscription, now);
      return store.subscription;
    },

    async cancelSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      refreshSubscriptionLifecycle(store.subscription, now);
      if (store.subscription.status === 'CANCELED') {
        throw new ConsoleBillingError(
          'subscription_already_canceled',
          409,
          'Subscription is already canceled',
        );
      }
      if (store.subscription.cancelAtPeriodEnd) {
        return store.subscription;
      }
      store.subscription.cancelAtPeriodEnd = true;
      store.subscription.cancelAt = store.subscription.currentPeriodEnd;
      store.subscription.updatedAt = coerceIsoDate(now);
      return store.subscription;
    },

    async resumeSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      refreshSubscriptionLifecycle(store.subscription, now);
      if (store.subscription.status === 'CANCELED') {
        throw new ConsoleBillingError(
          'subscription_not_resumable',
          409,
          'Subscription is already canceled and cannot be resumed',
        );
      }
      if (!store.subscription.cancelAtPeriodEnd) {
        return store.subscription;
      }
      store.subscription.cancelAtPeriodEnd = false;
      store.subscription.cancelAt = null;
      store.subscription.updatedAt = coerceIsoDate(now);
      return store.subscription;
    },

    async getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const currentMonthUtc = formatCurrentMonthUtc(now);
      store.monthlyActiveWallets = getMonthlyActiveWalletCount(store, currentMonthUtc);
      const openInvoices = Array.from(store.invoices.values()).filter(
        (inv) => inv.status === 'OPEN',
      );
      const upcomingChargeEstimateMinor = openInvoices.reduce(
        (acc, inv) => acc + outstandingAmountMinor(inv),
        0,
      );

      return {
        planId: store.planId,
        planName: store.planName,
        usageMetricVersion: 'maw_v1',
        currentMonthUtc,
        monthlyActiveWallets: store.monthlyActiveWallets,
        creditBalanceMinor: store.creditBalanceMinor,
        upcomingChargeEstimateMinor,
        openInvoiceCount: openInvoices.length,
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
        return {
          accepted: false,
          counted: false,
          monthUtc,
          monthlyActiveWallets: getMonthlyActiveWalletCount(store, monthUtc),
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
      if (counted) {
        ensureMonthlyWalletSet(store, monthUtc).add(request.walletId);
      }

      const monthlyActiveWallets = getMonthlyActiveWalletCount(store, monthUtc);
      if (monthUtc === formatCurrentMonthUtc(nowFn())) {
        store.monthlyActiveWallets = monthlyActiveWallets;
      }
      return {
        accepted: true,
        counted,
        monthUtc,
        monthlyActiveWallets,
      };
    },

    async listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]> {
      const store = ensureOrgStore(ctx.orgId);
      return Array.from(store.invoices.values()).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt),
      );
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
      return store.invoices.get(invoiceId) || null;
    },

    async getInvoiceActivity(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceActivity | null> {
      const store = ensureOrgStore(ctx.orgId);
      const invoice = store.invoices.get(invoiceId) || null;
      if (!invoice) return null;

      const entries: BillingInvoiceActivityEntry[] = [
        {
          id: `${invoice.id}:issued`,
          type: 'INVOICE',
          invoiceId: invoice.id,
          paymentId: null,
          rail: invoice.railLock,
          fromState: null,
          toState: 'OPEN',
          occurredAt: invoice.createdAt,
          actorType: 'SYSTEM',
          actorUserId: null,
          reason: 'invoice_created',
          sourceEventId: null,
          summary: `Invoice ${invoice.id} issued for billing period ${invoice.periodMonthUtc}.`,
        },
      ];

      const paymentIntents: Array<{
        id: string;
        rail: InvoicePaymentRail;
      }> = [
        ...Array.from(store.stripePaymentIntents.values())
          .filter((intent) => intent.invoiceId === invoice.id)
          .map((intent) => ({ id: intent.id, rail: intent.rail })),
        ...Array.from(store.stablecoinPaymentIntents.values())
          .filter((intent) => intent.invoiceId === invoice.id)
          .map((intent) => ({ id: intent.id, rail: intent.rail })),
      ];

      for (const payment of paymentIntents) {
        const transitions = store.paymentStateTransitions.get(payment.id) || [];
        transitions.forEach((transition, index) => {
          entries.push({
            id: `${payment.id}:${index}:${transition.toState}`,
            type: 'PAYMENT',
            invoiceId: invoice.id,
            paymentId: payment.id,
            rail: payment.rail,
            fromState: transition.fromState,
            toState: transition.toState,
            occurredAt: transition.changedAt,
            actorType: transition.actorType,
            actorUserId: transition.actorUserId,
            reason: transition.reason,
            sourceEventId: transition.sourceEventId,
            summary: buildPaymentTransitionSummary(
              payment.rail,
              transition.toState,
              payment.id,
              transition.reason,
            ),
          });
        });
      }

      const sortedEntries = [...entries].sort((left, right) => {
        const tsDiff = Date.parse(right.occurredAt) - Date.parse(left.occurredAt);
        if (tsDiff !== 0) return tsDiff;
        return right.id.localeCompare(left.id);
      });
      const latestPaymentEntry = sortedEntries.find((entry) => entry.type === 'PAYMENT') || null;
      return {
        invoice,
        latestPaymentState: latestPaymentEntry?.toState || null,
        latestPaymentRail: latestPaymentEntry?.rail || null,
        entries: sortedEntries,
      };
    },

    async listInvoiceLineItems(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceLineItem[]> {
      const store = ensureOrgStore(ctx.orgId);
      const invoice = store.invoices.get(invoiceId);
      if (!invoice) return [];
      const lineItems = store.invoiceLineItems.get(invoiceId) || [];
      return sortLineItems(lineItems);
    },

    async generateMonthlyInvoice(
      ctx: ConsoleBillingContext,
      request: GenerateMonthlyInvoiceRequest,
    ): Promise<GenerateMonthlyInvoiceResult> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const periodMonthUtc = parseMonthUtcOrThrow(request.periodMonthUtc);
      const monthlyActiveWallets = getMonthlyActiveWalletCount(store, periodMonthUtc);

      let invoice =
        Array.from(store.invoices.values()).find(
          (item) => item.periodMonthUtc === periodMonthUtc,
        ) || null;
      const created = !invoice;
      if (!invoice) {
        invoice = makeMonthlyInvoice(ctx.orgId, periodMonthUtc, now);
      }
      if (invoice.status === 'VOID' || invoice.status === 'UNCOLLECTIBLE') {
        throw new ConsoleBillingError(
          'invoice_not_billable',
          409,
          `Invoice ${invoice.id} is ${invoice.status} and cannot be regenerated`,
        );
      }

      const nextLineItems = buildInvoiceLineItems({
        orgId: ctx.orgId,
        invoiceId: invoice.id,
        periodMonthUtc,
        monthlyActiveWallets,
        createdAt: coerceIsoDate(now),
      });
      const previousLineItems = store.invoiceLineItems.get(invoice.id) || [];
      const nextAmountDueMinor = sumLineItemAmounts(nextLineItems);

      const unchanged =
        !created &&
        invoice.amountDueMinor === nextAmountDueMinor &&
        lineItemsEquivalent(previousLineItems, nextLineItems);

      invoice.amountDueMinor = nextAmountDueMinor;
      invoice.status = invoice.amountPaidMinor >= invoice.amountDueMinor ? 'PAID' : 'OPEN';
      store.invoices.set(invoice.id, invoice);
      store.invoiceLineItems.set(invoice.id, nextLineItems);

      return {
        generated: !unchanged,
        invoice,
        lineItems: sortLineItems(nextLineItems),
        monthlyActiveWallets,
        pricing: {
          baseFeeMinor: PLAN_BASE_FEE_MINOR,
          mawUnitPriceMinor: PLAN_MAW_UNIT_PRICE_MINOR,
        },
      };
    },

    async listPaymentMethods(ctx: ConsoleBillingContext): Promise<BillingPaymentMethod[]> {
      const store = ensureOrgStore(ctx.orgId);
      return Array.from(store.paymentMethods.values()).sort((a, b) =>
        b.createdAt.localeCompare(a.createdAt),
      );
    },

    async addCardPaymentMethod(
      ctx: ConsoleBillingContext,
      request: AddCardPaymentMethodRequest,
    ): Promise<BillingPaymentMethod> {
      requireAdminForCardActions(ctx);
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const isDefault = Array.from(store.paymentMethods.values()).every(
        (method) => !method.isDefault,
      );
      const paymentMethod: BillingPaymentMethod = {
        id: makeId('pm', now),
        orgId: ctx.orgId,
        provider: 'stripe',
        type: 'card',
        providerRef: request.providerRef,
        brand: request.brand,
        last4: request.last4,
        expMonth: request.expMonth,
        expYear: request.expYear,
        isDefault,
        createdAt: coerceIsoDate(now),
      };
      store.paymentMethods.set(paymentMethod.id, paymentMethod);
      return paymentMethod;
    },

    async removeCardPaymentMethod(
      ctx: ConsoleBillingContext,
      paymentMethodId: string,
    ): Promise<{ removed: boolean }> {
      requireAdminForCardActions(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const current = store.paymentMethods.get(paymentMethodId);
      if (!current) return { removed: false };
      store.paymentMethods.delete(paymentMethodId);

      if (current.isDefault) {
        const next = Array.from(store.paymentMethods.values())[0];
        if (next) {
          next.isDefault = true;
          store.paymentMethods.set(next.id, next);
        }
      }

      return { removed: true };
    },

    async setDefaultCardPaymentMethod(
      ctx: ConsoleBillingContext,
      paymentMethodId: string,
    ): Promise<BillingPaymentMethod | null> {
      requireAdminForCardActions(ctx);
      const store = ensureOrgStore(ctx.orgId);
      const target = store.paymentMethods.get(paymentMethodId);
      if (!target) return null;

      Array.from(store.paymentMethods.values()).forEach((method) => {
        method.isDefault = method.id === paymentMethodId;
        store.paymentMethods.set(method.id, method);
      });

      return store.paymentMethods.get(paymentMethodId) || null;
    },

    async createStripeSetupIntent(
      ctx: ConsoleBillingContext,
      request: StripeSetupIntentRequest,
    ): Promise<StripeSetupIntent> {
      const now = nowFn();
      ensureOrgStore(ctx.orgId);
      const providerSetupIntent = await providers.stripe.createSetupIntent({
        orgId: ctx.orgId,
        returnUrl: request.returnUrl,
        now,
      });
      const id = String(providerSetupIntent.id || '').trim();
      const clientSecret = String(providerSetupIntent.clientSecret || '').trim();
      const customerRef = String(providerSetupIntent.customerRef || '').trim();
      const expiresAt = String(providerSetupIntent.expiresAt || '').trim();
      if (!id || !clientSecret || !customerRef || !expiresAt) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          500,
          'Stripe setup-intent provider returned invalid payload',
        );
      }
      return {
        id,
        clientSecret,
        customerRef,
        expiresAt,
      };
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      const now = nowFn();
      ensureOrgStore(ctx.orgId);
      const providerCheckoutSession = await providers.stripe.createCheckoutSession({
        orgId: ctx.orgId,
        successUrl: request.successUrl,
        cancelUrl: request.cancelUrl,
        planId: request.planId,
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
      return {
        id,
        url,
        customerRef,
        expiresAt,
      };
    },

    async createStripeCustomerPortalSession(
      ctx: ConsoleBillingContext,
      request: StripeCustomerPortalSessionRequest,
    ): Promise<StripeCustomerPortalSession> {
      const now = nowFn();
      ensureOrgStore(ctx.orgId);
      const providerPortalSession = await providers.stripe.createCustomerPortalSession({
        orgId: ctx.orgId,
        returnUrl: request.returnUrl,
        now,
      });
      const id = String(providerPortalSession.id || '').trim();
      const url = String(providerPortalSession.url || '').trim();
      const customerRef = String(providerPortalSession.customerRef || '').trim();
      const expiresAt = String(providerPortalSession.expiresAt || '').trim();
      if (!id || !url || !customerRef || !expiresAt) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          500,
          'Stripe customer-portal session provider returned invalid payload',
        );
      }
      return {
        id,
        url,
        customerRef,
        expiresAt,
      };
    },

    async createStripePaymentIntent(
      ctx: ConsoleBillingContext,
      request: StripePaymentIntentRequest,
    ): Promise<StripePaymentIntent> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const invoice = store.invoices.get(request.invoiceId);
      if (!invoice) {
        throw new ConsoleBillingError(
          'invoice_not_found',
          404,
          `Invoice ${request.invoiceId} was not found`,
        );
      }

      ensureInvoiceOpen(invoice);
      lockInvoiceRail(invoice, 'CARD');
      const activeIntent = Array.from(store.stripePaymentIntents.values()).find(
        (intent) => intent.invoiceId === invoice.id && isActivePaymentState(intent.state),
      );
      if (activeIntent) {
        throw new ConsoleBillingError(
          'active_payment_intent_exists',
          409,
          `Invoice ${invoice.id} already has an active card payment intent (${activeIntent.id})`,
        );
      }

      const paymentMethod = request.paymentMethodId
        ? store.paymentMethods.get(request.paymentMethodId)
        : Array.from(store.paymentMethods.values()).find((method) => method.isDefault) || null;

      if (request.paymentMethodId && !paymentMethod) {
        throw new ConsoleBillingError(
          'payment_method_not_found',
          404,
          `Payment method ${request.paymentMethodId} was not found`,
        );
      }

      const id = makeId('pi', now);
      const amountMinor = outstandingAmountMinor(invoice);
      const providerPaymentIntent = await providers.stripe.createPaymentIntent({
        orgId: ctx.orgId,
        invoiceId: invoice.id,
        amountMinor,
        currency: 'USD',
        paymentMethodProviderRef: paymentMethod?.providerRef || null,
        now,
      });
      const providerRef = String(providerPaymentIntent.providerRef || '').trim();
      const clientSecret = String(providerPaymentIntent.clientSecret || '').trim();
      if (!providerRef || !clientSecret) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          500,
          'Stripe payment-intent provider returned invalid payload',
        );
      }
      const intent: StripePaymentIntent = {
        id,
        providerRef,
        invoiceId: invoice.id,
        amountMinor,
        currency: 'USD',
        paymentMethodId: paymentMethod?.id || null,
        state: 'CREATED',
        clientSecret,
        createdAt: coerceIsoDate(now),
        rail: 'CARD',
      };
      store.stripePaymentIntents.set(intent.id, intent);
      appendPaymentStateTransition(store, intent.id, {
        fromState: null,
        toState: intent.state,
        changedAt: coerceIsoDate(now),
        actorType: 'USER',
        actorUserId: ctx.actorUserId,
        reason: 'payment_intent_created',
      });
      store.invoices.set(invoice.id, invoice);
      return intent;
    },

    async reconcileStripePaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
      request: StripePaymentIntentReconcileRequest,
    ): Promise<StripePaymentIntent | null> {
      const store = ensureOrgStore(ctx.orgId);
      const intent = store.stripePaymentIntents.get(paymentIntentId);
      if (!intent) return null;
      if (isTerminalPaymentState(intent.state)) return intent;

      const settledAmountMinor = request.settledAmountMinor ?? intent.amountMinor;
      if (settledAmountMinor < 0) {
        throw new ConsoleBillingError(
          'invalid_reconciliation_request',
          400,
          'settledAmountMinor must be >= 0',
        );
      }

      const decision = decideStripeReconcileTransition({
        currentState: intent.state,
        providerStatus: request.providerStatus,
        expectedAmountMinor: intent.amountMinor,
        settledAmountMinor,
      });
      if (!decision.targetState) return intent;

      let effectiveFromState = intent.state;
      if (effectiveFromState === 'CREATED' && SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
        const toPending = canTransitionPaymentState({
          from: effectiveFromState,
          to: 'PENDING',
        });
        if (!toPending.ok) {
          throw new ConsoleBillingError('invalid_payment_state', 409, toPending.message, {
            fromState: effectiveFromState,
            toState: 'PENDING',
          });
        }
        intent.state = 'PENDING';
        store.stripePaymentIntents.set(intent.id, intent);
        appendPaymentStateTransition(store, intent.id, {
          fromState: effectiveFromState,
          toState: 'PENDING',
          changedAt: coerceIsoDate(nowFn()),
          actorType: 'PROVIDER',
          actorUserId: null,
          sourceEventId: request.sourceEventId || null,
          reason: 'provider_pending_implied',
        });
        effectiveFromState = 'PENDING';
      }

      const transition = canTransitionPaymentState({
        from: effectiveFromState,
        to: decision.targetState,
      });
      if (!transition.ok) {
        throw new ConsoleBillingError('invalid_payment_state', 409, transition.message, {
          fromState: effectiveFromState,
          toState: decision.targetState,
        });
      }

      const fromState = effectiveFromState;
      intent.state = decision.targetState;
      store.stripePaymentIntents.set(intent.id, intent);
      appendPaymentStateTransition(store, intent.id, {
        fromState,
        toState: decision.targetState,
        changedAt: coerceIsoDate(nowFn()),
        actorType: 'PROVIDER',
        actorUserId: null,
        sourceEventId: request.sourceEventId || null,
        reason: decision.reason,
      });

      if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
        const invoice = store.invoices.get(intent.invoiceId);
        if (invoice) {
          invoice.amountPaidMinor += settledAmountMinor;
          if (invoice.amountPaidMinor >= invoice.amountDueMinor) {
            invoice.status = 'PAID';
          }
          store.invoices.set(invoice.id, invoice);
        }
      }

      return intent;
    },

    async processStripeWebhookEvent(
      request: StripeWebhookEventRequest,
    ): Promise<StripeWebhookEventResult> {
      const now = nowFn();
      const eventType = String(request.eventType || '')
        .trim()
        .toLowerCase();
      const paymentIntentProjection = !eventType || eventType.startsWith('payment_intent.');

      let matchedOrgId: string | null = null;
      let matchedStore: OrgBillingStore | null = null;
      let matchedIntent: StripePaymentIntent | null = null;

      if (paymentIntentProjection) {
        const providerRef = String(request.providerRef || '').trim();
        for (const [orgId, store] of Array.from(orgStores.entries())) {
          const candidate = Array.from(store.stripePaymentIntents.values()).find(
            (intent) => intent.providerRef === providerRef,
          );
          if (!candidate) continue;
          if (matchedIntent) {
            throw new ConsoleBillingError(
              'duplicate_provider_reference',
              409,
              `Stripe provider reference ${providerRef} matches multiple payment intents`,
            );
          }
          matchedOrgId = orgId;
          matchedStore = store;
          matchedIntent = candidate;
        }
      } else {
        const resolverMatches: Array<{ orgId: string; store: OrgBillingStore }> = [];
        const byOrgId = String(request.orgId || '').trim();
        if (byOrgId) {
          const store = orgStores.get(byOrgId);
          if (store) resolverMatches.push({ orgId: byOrgId, store });
        }

        const bySubscriptionRef = String(request.providerSubscriptionRef || '').trim();
        const byCustomerRef = String(request.providerCustomerRef || '').trim();
        const byInvoiceId = String(request.invoiceId || '').trim();
        const byProviderRef = String(request.providerRef || '').trim();

        for (const [orgId, store] of Array.from(orgStores.entries())) {
          if (resolverMatches.some((entry) => entry.orgId === orgId)) continue;
          const subscription = store.subscription;
          const subscriptionMatch =
            (bySubscriptionRef && subscription.providerSubscriptionRef === bySubscriptionRef) ||
            (byCustomerRef && subscription.providerCustomerRef === byCustomerRef) ||
            (byProviderRef &&
              (subscription.providerSubscriptionRef === byProviderRef ||
                subscription.providerCustomerRef === byProviderRef));
          const invoiceMatch = byInvoiceId ? store.invoices.has(byInvoiceId) : false;
          if (subscriptionMatch || invoiceMatch) {
            resolverMatches.push({ orgId, store });
          }
        }

        if (resolverMatches.length > 1) {
          throw new ConsoleBillingError(
            'duplicate_provider_reference',
            409,
            `Stripe webhook event ${request.eventId} maps to multiple organizations`,
          );
        }
        if (resolverMatches.length === 1) {
          matchedOrgId = resolverMatches[0].orgId;
          matchedStore = resolverMatches[0].store;
        }
      }

      if (!matchedOrgId || !matchedStore) {
        return {
          accepted: true,
          paymentIntent: null,
          subscription: null,
          invoice: null,
          orgId: null,
        };
      }

      refreshSubscriptionLifecycle(matchedStore.subscription, now);

      if (matchedStore.stripeWebhookEventIds.has(request.eventId)) {
        return {
          accepted: false,
          paymentIntent: matchedIntent,
          subscription: matchedStore.subscription,
          invoice: request.invoiceId ? matchedStore.invoices.get(request.invoiceId) || null : null,
          orgId: matchedOrgId,
        };
      }

      let reconciled: StripePaymentIntent | null = matchedIntent;
      let projectedSubscription: BillingSubscription | null = matchedStore.subscription;
      let projectedInvoice: BillingInvoice | null = request.invoiceId
        ? matchedStore.invoices.get(request.invoiceId) || null
        : null;

      if (paymentIntentProjection) {
        if (!matchedIntent || !request.providerStatus) {
          return {
            accepted: true,
            paymentIntent: null,
            subscription: projectedSubscription,
            invoice: projectedInvoice,
            orgId: matchedOrgId,
          };
        }
        reconciled = await this.reconcileStripePaymentIntent(
          {
            orgId: matchedOrgId,
            actorUserId: 'system-stripe-webhook',
            roles: ['ops'],
          },
          matchedIntent.id,
          {
            providerStatus: request.providerStatus,
            settledAmountMinor: request.settledAmountMinor,
            sourceEventId: request.eventId,
          },
        );
      } else {
        if (
          eventType === 'checkout.session.completed' ||
          eventType.startsWith('customer.subscription.')
        ) {
          if (request.providerCustomerRef !== undefined) {
            matchedStore.subscription.providerCustomerRef = request.providerCustomerRef || null;
          }
          if (request.providerSubscriptionRef !== undefined) {
            matchedStore.subscription.providerSubscriptionRef =
              request.providerSubscriptionRef || null;
          }
          if (request.planId) matchedStore.subscription.planId = request.planId;
          if (request.planName) matchedStore.subscription.planName = request.planName;
          if (request.currentPeriodStart) {
            matchedStore.subscription.currentPeriodStart = request.currentPeriodStart;
          }
          if (request.currentPeriodEnd) {
            matchedStore.subscription.currentPeriodEnd = request.currentPeriodEnd;
          }
          if (request.subscriptionStatus) {
            matchedStore.subscription.status = request.subscriptionStatus;
          } else if (eventType === 'checkout.session.completed') {
            matchedStore.subscription.status = 'ACTIVE';
          }
          if (request.cancelAtPeriodEnd !== undefined) {
            matchedStore.subscription.cancelAtPeriodEnd = request.cancelAtPeriodEnd;
          }
          if (request.cancelAt !== undefined) {
            matchedStore.subscription.cancelAt = request.cancelAt;
          } else if (!matchedStore.subscription.cancelAtPeriodEnd) {
            matchedStore.subscription.cancelAt = null;
          }
          if (request.canceledAt !== undefined) {
            matchedStore.subscription.canceledAt = request.canceledAt;
          }
          if (
            matchedStore.subscription.status === 'CANCELED' &&
            !matchedStore.subscription.canceledAt
          ) {
            matchedStore.subscription.canceledAt = coerceIsoDate(now);
          }
          matchedStore.subscription.updatedAt = coerceIsoDate(now);
          projectedSubscription = matchedStore.subscription;
        }

        if (eventType.startsWith('invoice.') && request.invoiceId) {
          const invoice = matchedStore.invoices.get(request.invoiceId) || null;
          if (invoice) {
            if (request.invoiceAmountDueMinor !== undefined) {
              invoice.amountDueMinor = request.invoiceAmountDueMinor;
            }
            if (request.invoiceAmountPaidMinor !== undefined) {
              invoice.amountPaidMinor = request.invoiceAmountPaidMinor;
            }
            if (request.invoiceStatus) {
              invoice.status = request.invoiceStatus;
            } else if (invoice.amountPaidMinor >= invoice.amountDueMinor) {
              invoice.status = 'PAID';
            }
            matchedStore.invoices.set(invoice.id, invoice);
            projectedInvoice = invoice;
          } else {
            projectedInvoice = null;
          }
        }
      }

      matchedStore.stripeWebhookEventIds.add(request.eventId);
      return {
        accepted: true,
        paymentIntent: reconciled,
        subscription: projectedSubscription,
        invoice: projectedInvoice,
        orgId: matchedOrgId,
      };
    },

    async createStablecoinQuote(
      ctx: ConsoleBillingContext,
      request: StablecoinQuoteRequest,
    ): Promise<StablecoinPaymentQuote> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const invoice = store.invoices.get(request.invoiceId);
      if (!invoice) {
        throw new ConsoleBillingError(
          'invoice_not_found',
          404,
          `Invoice ${request.invoiceId} was not found`,
        );
      }
      ensureInvoiceOpen(invoice);

      const quote: StablecoinPaymentQuote = {
        id: makeId('scq', now),
        orgId: ctx.orgId,
        invoiceId: invoice.id,
        asset: request.asset,
        chain: request.chain,
        amountMinor: outstandingAmountMinor(invoice),
        createdAt: coerceIsoDate(now),
        expiresAt: coerceIsoDate(new Date(now.getTime() + 15 * 60 * 1000)),
        state: 'OPEN',
      };
      store.stablecoinQuotes.set(quote.id, quote);
      return quote;
    },

    async createStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      request: StablecoinPaymentIntentRequest,
    ): Promise<StablecoinPaymentIntent> {
      const now = nowFn();
      const store = ensureOrgStore(ctx.orgId);
      const invoice = store.invoices.get(request.invoiceId);
      if (!invoice) {
        throw new ConsoleBillingError(
          'invoice_not_found',
          404,
          `Invoice ${request.invoiceId} was not found`,
        );
      }
      ensureInvoiceOpen(invoice);

      const quote = store.stablecoinQuotes.get(request.quoteId);
      if (!quote || quote.orgId !== ctx.orgId) {
        throw new ConsoleBillingError(
          'quote_not_found',
          404,
          `Stablecoin quote ${request.quoteId} was not found`,
        );
      }
      if (quote.invoiceId !== invoice.id) {
        throw new ConsoleBillingError(
          'quote_invoice_mismatch',
          409,
          'Quote does not belong to the specified invoice',
        );
      }

      for (const existingIntent of Array.from(store.stablecoinPaymentIntents.values())) {
        if (existingIntent.invoiceId !== invoice.id) continue;
        markStablecoinIntentExpiredIfNeeded(store, existingIntent, now);
        refreshStablecoinRiskWindowState(existingIntent, now);
        store.stablecoinPaymentIntents.set(existingIntent.id, existingIntent);
      }
      const activeIntent = Array.from(store.stablecoinPaymentIntents.values()).find(
        (intent) => intent.invoiceId === invoice.id && isActivePaymentState(intent.state),
      );
      if (activeIntent) {
        throw new ConsoleBillingError(
          'active_payment_intent_exists',
          409,
          `Invoice ${invoice.id} already has an active stablecoin payment intent (${activeIntent.id})`,
        );
      }
      const consumedIntent = Array.from(store.stablecoinPaymentIntents.values()).find(
        (intent) => intent.quoteId === quote.id,
      );
      if (consumedIntent) {
        throw new ConsoleBillingError(
          'quote_already_consumed',
          409,
          `Stablecoin quote ${quote.id} has already been used by payment intent ${consumedIntent.id}`,
        );
      }

      const quoteExpires = new Date(quote.expiresAt).getTime();
      if (!Number.isFinite(quoteExpires) || now.getTime() > quoteExpires) {
        quote.state = 'EXPIRED';
        store.stablecoinQuotes.set(quote.id, quote);
        throw new ConsoleBillingError(
          'quote_expired',
          409,
          `Stablecoin quote ${quote.id} has expired`,
        );
      }
      const outstandingMinor = outstandingAmountMinor(invoice);
      if (quote.amountMinor !== outstandingMinor) {
        throw new ConsoleBillingError(
          'quote_amount_mismatch',
          409,
          `Stablecoin quote ${quote.id} amount no longer matches invoice ${invoice.id} outstanding balance`,
          {
            quoteAmountMinor: quote.amountMinor,
            outstandingAmountMinor: outstandingMinor,
          },
        );
      }

      lockInvoiceRail(invoice, 'STABLECOIN');

      const policy = getChainFinalityPolicy(quote.chain);
      if (!policy) {
        throw new ConsoleBillingError(
          'unsupported_chain',
          400,
          `Unsupported stablecoin settlement chain: ${quote.chain}`,
        );
      }

      const intent: StablecoinPaymentIntent = {
        id: makeId('scpi', now),
        orgId: ctx.orgId,
        invoiceId: invoice.id,
        quoteId: quote.id,
        asset: quote.asset,
        chain: quote.chain,
        expectedAmountMinor: quote.amountMinor,
        destinationAddress: '',
        state: 'PENDING',
        rail: 'STABLECOIN',
        requiredConfirmations: policy.requiredConfirmations,
        confirmationTimeoutMinutes: policy.confirmationTimeoutMinutes,
        reorgRiskWindowHours: policy.reorgRiskWindowHours,
        settledAt: null,
        reorgRiskWindowEndsAt: null,
        withinReorgRiskWindow: false,
        createdAt: coerceIsoDate(now),
        expiresAt: quote.expiresAt,
      };
      const destination = await providers.stablecoin.allocateDestination({
        orgId: ctx.orgId,
        chain: quote.chain,
        asset: quote.asset,
        now,
      });
      intent.destinationAddress = String(destination.destinationAddress || '').trim();
      if (!intent.destinationAddress) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          500,
          'Stablecoin destination provider returned invalid payload',
        );
      }

      store.stablecoinPaymentIntents.set(intent.id, intent);
      appendPaymentStateTransition(store, intent.id, {
        fromState: null,
        toState: intent.state,
        changedAt: coerceIsoDate(now),
        actorType: 'USER',
        actorUserId: ctx.actorUserId,
        reason: 'payment_intent_created',
      });
      store.invoices.set(invoice.id, invoice);
      return intent;
    },

    async getStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
    ): Promise<StablecoinPaymentIntent | null> {
      const store = ensureOrgStore(ctx.orgId);
      const intent = store.stablecoinPaymentIntents.get(paymentIntentId);
      if (!intent) return null;

      const now = nowFn();
      markStablecoinIntentExpiredIfNeeded(store, intent, now);
      refreshStablecoinRiskWindowState(intent, now);
      store.stablecoinPaymentIntents.set(intent.id, intent);
      return intent;
    },

    async cancelStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
    ): Promise<StablecoinPaymentIntent | null> {
      const store = ensureOrgStore(ctx.orgId);
      const intent = store.stablecoinPaymentIntents.get(paymentIntentId);
      if (!intent) return null;
      const now = nowFn();
      markStablecoinIntentExpiredIfNeeded(store, intent, now);
      refreshStablecoinRiskWindowState(intent, now);
      if (intent.state === 'EXPIRED') {
        store.stablecoinPaymentIntents.set(intent.id, intent);
        return intent;
      }

      const transition = canTransitionPaymentState({
        from: intent.state,
        to: 'CANCELED',
      });
      if (!transition.ok) {
        throw new ConsoleBillingError('invalid_payment_state', 409, transition.message, {
          fromState: intent.state,
          toState: 'CANCELED',
        });
      }

      const fromState = intent.state;
      intent.state = 'CANCELED';
      store.stablecoinPaymentIntents.set(intent.id, intent);
      appendPaymentStateTransition(store, intent.id, {
        fromState,
        toState: 'CANCELED',
        changedAt: coerceIsoDate(now),
        actorType: 'USER',
        actorUserId: ctx.actorUserId,
        reason: 'payment_intent_canceled',
      });
      refreshStablecoinRiskWindowState(intent, now);
      return intent;
    },

    async reconcileStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
      request: StablecoinPaymentIntentReconcileRequest,
    ): Promise<StablecoinPaymentIntent | null> {
      if (request.observedAmountMinor < 0 || request.observedConfirmations < 0) {
        throw new ConsoleBillingError(
          'invalid_reconciliation_request',
          400,
          'Observed amount and confirmations must be non-negative',
        );
      }
      const store = ensureOrgStore(ctx.orgId);
      const intent = store.stablecoinPaymentIntents.get(paymentIntentId);
      if (!intent) return null;
      const now = nowFn();
      markStablecoinIntentExpiredIfNeeded(store, intent, now);
      refreshStablecoinRiskWindowState(intent, now);
      if (intent.state === 'EXPIRED') {
        store.stablecoinPaymentIntents.set(intent.id, intent);
        return intent;
      }

      if (isTerminalPaymentState(intent.state)) return intent;

      const decision = decideStablecoinReconcileTransition({
        currentState: intent.state,
        expectedAmountMinor: intent.expectedAmountMinor,
        observedAmountMinor: request.observedAmountMinor,
        observedConfirmations: request.observedConfirmations,
        requiredConfirmations: intent.requiredConfirmations,
        confirmationTimedOut: Boolean(request.confirmationTimedOut),
      });
      if (!decision.targetState) return intent;

      if (
        SETTLEMENT_OUTCOME_STATES.has(decision.targetState) &&
        request.observedConfirmations < intent.requiredConfirmations
      ) {
        throw new ConsoleBillingError(
          'invalid_payment_state',
          409,
          'Cannot settle payment before chain confirmation threshold is met',
          {
            fromState: intent.state,
            toState: decision.targetState,
          },
        );
      }

      const transition = canTransitionPaymentState({
        from: intent.state,
        to: decision.targetState,
        observedConfirmations: request.observedConfirmations,
        requiredConfirmations: intent.requiredConfirmations,
        confirmationTimedOut: Boolean(request.confirmationTimedOut),
      });
      if (!transition.ok) {
        throw new ConsoleBillingError('invalid_payment_state', 409, transition.message, {
          fromState: intent.state,
          toState: decision.targetState,
        });
      }

      const fromState = intent.state;
      intent.state = decision.targetState;
      if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState) && !intent.settledAt) {
        intent.settledAt = coerceIsoDate(now);
      }
      refreshStablecoinRiskWindowState(intent, now);
      store.stablecoinPaymentIntents.set(intent.id, intent);
      appendPaymentStateTransition(store, intent.id, {
        fromState,
        toState: decision.targetState,
        changedAt: coerceIsoDate(now),
        actorType: 'SYSTEM',
        actorUserId: null,
        sourceEventId: request.sourceEventId || null,
        reason: decision.reason,
      });

      if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
        const invoice = store.invoices.get(intent.invoiceId);
        if (invoice) {
          invoice.amountPaidMinor += request.observedAmountMinor;
          if (invoice.amountPaidMinor >= invoice.amountDueMinor) {
            invoice.status = 'PAID';
          }
          store.invoices.set(invoice.id, invoice);
        }
      }

      refreshStablecoinRiskWindowState(intent, now);
      return intent;
    },
  };
}
