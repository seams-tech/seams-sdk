import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { canTransitionPaymentState, type PaymentState } from './paymentStateMachine';
import { ConsoleBillingError } from './errors';
import { getChainFinalityPolicy } from './stablecoinAssets';
import { resolveBillingProviderAdapters, type BillingProviderAdapters } from './providers';
import type {
  AddCardPaymentMethodRequest,
  BillingInvoice,
  BillingInvoiceLineItem,
  BillingInvoiceLineItemType,
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
import type { ConsoleBillingContext, ConsoleBillingService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;
type PaymentTransitionActorType = 'USER' | 'SYSTEM' | 'PROVIDER';

const CONSOLE_BILLING_MIGRATION_LOCK_ID = 9452360123582;
const DEFAULT_MONTHLY_PLAN_AMOUNT_MINOR = 4900;
const PLAN_BASE_FEE_MINOR = 1900;
const PLAN_MAW_UNIT_PRICE_MINOR = 300;
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

function nowMs(now: Date): number {
  return now.getTime();
}

function monthUtc(now: Date): string {
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

function previousMonthUtc(now: Date): string {
  return monthUtc(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)));
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

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function stableHash32(input: string): number {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function makeBootstrapInvoiceId(orgId: string, periodMonthUtc: string): string {
  const monthPart = periodMonthUtc.replace('-', '');
  const orgPrefix =
    orgId
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .slice(0, 8) || 'org';
  const orgHashPart = stableHash32(orgId).toString(36);
  return `inv_${monthPart}_${orgPrefix}_${orgHashPart}`;
}

function toOptionalFiniteNumber(v: unknown): number | null {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function parseInvoiceRow(row: PgRow): BillingInvoice {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    status: String(row.status || 'OPEN') as BillingInvoice['status'],
    currency: 'USD',
    amountDueMinor: toNumber(row.amount_due_minor),
    amountPaidMinor: toNumber(row.amount_paid_minor),
    railLock: row.rail_lock ? (String(row.rail_lock) as InvoicePaymentRail) : null,
    periodMonthUtc: String(row.period_month_utc || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    dueAt: row.due_at_ms == null ? null : toIso(toNumber(row.due_at_ms)),
  };
}

function parseInvoiceLineItemRow(row: PgRow): BillingInvoiceLineItem {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    invoiceId: String(row.invoice_id || ''),
    periodMonthUtc: String(row.period_month_utc || ''),
    itemType: String(row.item_type || 'PLAN_BASE_FEE') as BillingInvoiceLineItemType,
    description: String(row.description || ''),
    quantity: toNumber(row.quantity),
    unitAmountMinor: toNumber(row.unit_amount_minor),
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
  };
}

function parsePaymentMethodRow(row: PgRow): BillingPaymentMethod {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    provider: 'stripe',
    type: 'card',
    providerRef: String(row.provider_ref || ''),
    brand: String(row.brand || ''),
    last4: String(row.last4 || ''),
    expMonth: toNumber(row.exp_month),
    expYear: toNumber(row.exp_year),
    isDefault: Boolean(row.is_default),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
  };
}

function makeStripeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function makeStripeSubscriptionRef(orgId: string): string {
  return `sub_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function parseSubscriptionRow(row: PgRow): BillingSubscription {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    provider: 'stripe',
    providerCustomerRef: row.provider_customer_ref
      ? String(row.provider_customer_ref || '')
      : null,
    providerSubscriptionRef: row.provider_subscription_ref
      ? String(row.provider_subscription_ref || '')
      : null,
    planId: String(row.plan_id || ''),
    planName: String(row.plan_name || ''),
    status: String(row.status || 'ACTIVE') as BillingSubscription['status'],
    cancelAtPeriodEnd: Boolean(row.cancel_at_period_end),
    currentPeriodStart: toIso(toNumber(row.current_period_start_ms)) || new Date(0).toISOString(),
    currentPeriodEnd: toIso(toNumber(row.current_period_end_ms)) || new Date(0).toISOString(),
    cancelAt: row.cancel_at_ms == null ? null : toIso(toNumber(row.cancel_at_ms)),
    canceledAt: row.canceled_at_ms == null ? null : toIso(toNumber(row.canceled_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseStripePaymentIntentRow(row: PgRow): StripePaymentIntent {
  return {
    id: String(row.id || ''),
    providerRef: String(row.provider_ref || row.id || ''),
    invoiceId: String(row.invoice_id || ''),
    amountMinor: toNumber(row.amount_minor),
    currency: 'USD',
    paymentMethodId: row.payment_method_id ? String(row.payment_method_id) : null,
    state: String(row.state || 'CREATED') as StripePaymentIntent['state'],
    clientSecret: String(row.client_secret || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    rail: 'CARD',
  };
}

function parseStablecoinQuoteRow(row: PgRow): StablecoinPaymentQuote {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    invoiceId: String(row.invoice_id || ''),
    asset: String(row.asset || 'USDC') as StablecoinPaymentQuote['asset'],
    chain: String(row.chain || 'Ethereum') as StablecoinPaymentQuote['chain'],
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    expiresAt: toIso(toNumber(row.expires_at_ms)) || new Date(0).toISOString(),
    state: String(row.state || 'OPEN') as StablecoinPaymentQuote['state'],
  };
}

function parseStablecoinIntentRow(
  row: PgRow,
  referenceNowMs = Date.now(),
): StablecoinPaymentIntent {
  const settledAtMs = toOptionalFiniteNumber(row.settled_at_ms);
  const reorgRiskWindowHours = toNumber(row.reorg_risk_window_hours);
  const storedRiskWindowEndsAtMs = toOptionalFiniteNumber(row.reorg_risk_window_ends_at_ms);
  const resolvedRiskWindowEndsAtMs =
    storedRiskWindowEndsAtMs ??
    (settledAtMs == null ? null : settledAtMs + reorgRiskWindowHours * 60 * 60 * 1000);
  const settledAt = settledAtMs == null ? null : toIso(settledAtMs);
  const reorgRiskWindowEndsAt =
    resolvedRiskWindowEndsAtMs == null ? null : toIso(resolvedRiskWindowEndsAtMs);
  const withinReorgRiskWindow =
    resolvedRiskWindowEndsAtMs != null &&
    Number.isFinite(resolvedRiskWindowEndsAtMs) &&
    referenceNowMs < resolvedRiskWindowEndsAtMs;
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    invoiceId: String(row.invoice_id || ''),
    quoteId: String(row.quote_id || ''),
    asset: String(row.asset || 'USDC') as StablecoinPaymentIntent['asset'],
    chain: String(row.chain || 'Ethereum') as StablecoinPaymentIntent['chain'],
    expectedAmountMinor: toNumber(row.expected_amount_minor),
    destinationAddress: String(row.destination_address || ''),
    state: String(row.state || 'PENDING') as StablecoinPaymentIntent['state'],
    rail: 'STABLECOIN',
    requiredConfirmations: toNumber(row.required_confirmations),
    confirmationTimeoutMinutes: toNumber(row.confirmation_timeout_minutes),
    reorgRiskWindowHours,
    settledAt,
    reorgRiskWindowEndsAt,
    withinReorgRiskWindow,
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    expiresAt: toIso(toNumber(row.expires_at_ms)) || new Date(0).toISOString(),
  };
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

async function appendPaymentStateTransition(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    paymentId: string;
    fromState: PaymentState | null;
    toState: PaymentState;
    changedAtMs: number;
    actorType: PaymentTransitionActorType;
    actorUserId?: string | null;
    sourceEventId?: string | null;
    reason?: string | null;
  },
): Promise<void> {
  await q.query(
    `INSERT INTO console_payment_state_transitions
      (namespace, org_id, payment_id, from_state, to_state, changed_at_ms, actor_type, actor_user_id, source_event_id, reason)
     VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      input.namespace,
      input.orgId,
      input.paymentId,
      input.fromState,
      input.toState,
      input.changedAtMs,
      input.actorType,
      input.actorUserId || null,
      input.sourceEventId || null,
      input.reason || null,
    ],
  );
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function expireStablecoinIntentIfNeeded(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    paymentIntentId: string;
    intent: StablecoinPaymentIntent;
    changedAtMs: number;
  },
): Promise<StablecoinPaymentIntent> {
  if (input.intent.state === 'EXPIRED') return input.intent;
  const expiresAtMs = Date.parse(input.intent.expiresAt);
  if (!Number.isFinite(expiresAtMs) || input.changedAtMs <= expiresAtMs) {
    return input.intent;
  }

  const transition = canTransitionPaymentState({
    from: input.intent.state,
    to: 'EXPIRED',
  });
  if (!transition.ok) {
    return input.intent;
  }

  const updated = await queryOne(
    q,
    `UPDATE console_stablecoin_payment_intents
        SET state = 'EXPIRED'
      WHERE namespace = $1 AND org_id = $2 AND id = $3 AND state = $4
      RETURNING *`,
    [input.namespace, input.orgId, input.paymentIntentId, input.intent.state],
  );
  if (!updated) {
    const current = await queryOne(
      q,
      `SELECT *
         FROM console_stablecoin_payment_intents
        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
      [input.namespace, input.orgId, input.paymentIntentId],
    );
    return current ? parseStablecoinIntentRow(current, input.changedAtMs) : input.intent;
  }

  await appendPaymentStateTransition(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    paymentId: input.paymentIntentId,
    fromState: input.intent.state,
    toState: 'EXPIRED',
    changedAtMs: input.changedAtMs,
    actorType: 'SYSTEM',
    reason: 'payment_intent_expired',
  });
  return parseStablecoinIntentRow(updated, input.changedAtMs);
}

async function refreshSubscriptionLifecycleIfNeeded(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    nowMs: number;
  },
): Promise<BillingSubscription | null> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_subscriptions
      WHERE namespace = $1 AND org_id = $2
      FOR UPDATE`,
    [input.namespace, input.orgId],
  );
  if (!row) return null;

  const current = parseSubscriptionRow(row);
  if (current.status === 'CANCELED') return current;
  if (!current.cancelAtPeriodEnd) return current;

  const currentPeriodEndMs = toNumber(row.current_period_end_ms);
  if (!Number.isFinite(currentPeriodEndMs) || input.nowMs < currentPeriodEndMs) {
    return current;
  }

  const updated = await queryOne(
    q,
    `UPDATE console_subscriptions
        SET status = 'CANCELED',
            cancel_at_period_end = FALSE,
            cancel_at_ms = $4,
            canceled_at_ms = COALESCE(canceled_at_ms, $4),
            updated_at_ms = $5
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      RETURNING *`,
    [input.namespace, input.orgId, current.id, currentPeriodEndMs, input.nowMs],
  );
  return updated ? parseSubscriptionRow(updated) : current;
}

async function ensureOrgBootstrap(input: {
  pool: PgPool;
  namespace: string;
  orgId: string;
  now: Date;
}): Promise<void> {
  const { pool, namespace, orgId, now } = input;
  const createdAtMs = nowMs(now);
  const periodMonth = monthUtc(now);

  await pool.query(
    `INSERT INTO console_billing_accounts
      (namespace, org_id, plan_id, plan_name, usage_metric_version, monthly_active_wallets, credit_balance_minor, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, 'pro_maw_v1', 'Pro MAW', 'maw_v1', 0, 0, $3, $3)
     ON CONFLICT (namespace, org_id) DO NOTHING`,
    [namespace, orgId, createdAtMs],
  );

  await pool.query(
    `INSERT INTO console_subscriptions
      (
        namespace,
        id,
        org_id,
        provider,
        provider_customer_ref,
        provider_subscription_ref,
        plan_id,
        plan_name,
        status,
        cancel_at_period_end,
        current_period_start_ms,
        current_period_end_ms,
        cancel_at_ms,
        canceled_at_ms,
        created_at_ms,
        updated_at_ms
      )
     VALUES
      (
        $1,
        $2,
        $3,
        'stripe',
        $4,
        $5,
        'pro_maw_v1',
        'Pro MAW',
        'ACTIVE',
        FALSE,
        $6,
        $7,
        NULL,
        NULL,
        $6,
        $6
      )
     ON CONFLICT (namespace, org_id) DO NOTHING`,
    [
      namespace,
      makeId('sub', now),
      orgId,
      makeStripeCustomerRef(orgId),
      makeStripeSubscriptionRef(orgId),
      createdAtMs,
      createdAtMs + 30 * 24 * 60 * 60 * 1000,
    ],
  );

  const periodInvoice = await queryOne(
    pool,
    `SELECT id
       FROM console_invoices
      WHERE namespace = $1 AND org_id = $2 AND period_month_utc = $3
      ORDER BY created_at_ms DESC
      LIMIT 1`,
    [namespace, orgId, periodMonth],
  );

  if (periodInvoice) return;

  const dueAtMs = createdAtMs + 14 * 24 * 60 * 60 * 1000;
  const invoiceId = makeBootstrapInvoiceId(orgId, periodMonth);

  await pool.query(
    `INSERT INTO console_invoices
      (namespace, id, org_id, status, currency, amount_due_minor, amount_paid_minor, rail_lock, period_month_utc, created_at_ms, due_at_ms)
     VALUES
      ($1, $2, $3, 'OPEN', 'USD', $4, 0, NULL, $5, $6, $7)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      namespace,
      invoiceId,
      orgId,
      DEFAULT_MONTHLY_PLAN_AMOUNT_MINOR,
      periodMonth,
      createdAtMs,
      dueAtMs,
    ],
  );
}

async function lockInvoiceForPayment(
  q: Queryable,
  namespace: string,
  orgId: string,
  invoiceId: string,
): Promise<BillingInvoice> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_invoices
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      FOR UPDATE`,
    [namespace, orgId, invoiceId],
  );
  if (!row) {
    throw new ConsoleBillingError('invoice_not_found', 404, `Invoice ${invoiceId} was not found`);
  }
  const invoice = parseInvoiceRow(row);
  if (invoice.status !== 'OPEN') {
    throw new ConsoleBillingError('invoice_not_open', 409, `Invoice ${invoice.id} is not open`);
  }
  const outstanding = Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
  if (outstanding <= 0) {
    throw new ConsoleBillingError(
      'invoice_already_paid',
      409,
      `Invoice ${invoice.id} is already fully paid`,
    );
  }
  return invoice;
}

function ensureRailLock(invoice: BillingInvoice, requestedRail: InvoicePaymentRail): void {
  if (invoice.railLock && invoice.railLock !== requestedRail) {
    throw new ConsoleBillingError(
      'invoice_rail_locked',
      409,
      `Invoice ${invoice.id} is locked to ${invoice.railLock} and cannot use ${requestedRail}`,
    );
  }
}

async function setInvoiceRailLock(
  q: Queryable,
  namespace: string,
  invoiceId: string,
  rail: InvoicePaymentRail,
): Promise<void> {
  await q.query(
    `UPDATE console_invoices
        SET rail_lock = $3
      WHERE namespace = $1 AND id = $2`,
    [namespace, invoiceId, rail],
  );
}

async function countMonthlyActiveWallets(
  q: Queryable,
  namespace: string,
  orgId: string,
  monthUtc: string,
): Promise<number> {
  const row = await queryOne(
    q,
    `SELECT COUNT(DISTINCT wallet_id)::BIGINT AS monthly_active_wallets
       FROM console_usage_meter_events
      WHERE namespace = $1
        AND org_id = $2
        AND month_utc = $3
        AND succeeded = TRUE
        AND is_simulation = FALSE
        AND is_internal_retry = FALSE
        AND action IN ('transfer', 'swap', 'approve', 'contract_call')`,
    [namespace, orgId, monthUtc],
  );
  return toNumber(row?.monthly_active_wallets);
}

async function upsertMonthlyActiveWalletRollup(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    monthUtc: string;
    monthlyActiveWallets: number;
    updatedAtMs: number;
  },
): Promise<void> {
  await q.query(
    `INSERT INTO console_usage_rollups_monthly
      (namespace, org_id, month_utc, monthly_active_wallets, updated_at_ms)
     VALUES
      ($1, $2, $3, $4, $5)
     ON CONFLICT (namespace, org_id, month_utc)
     DO UPDATE SET
       monthly_active_wallets = EXCLUDED.monthly_active_wallets,
       updated_at_ms = EXCLUDED.updated_at_ms`,
    [input.namespace, input.orgId, input.monthUtc, input.monthlyActiveWallets, input.updatedAtMs],
  );
}

function makeInvoiceLineItem(input: {
  orgId: string;
  invoiceId: string;
  periodMonthUtc: string;
  itemType: BillingInvoiceLineItemType;
  description: string;
  quantity: number;
  unitAmountMinor: number;
  createdAtMs: number;
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
    createdAt: toIso(input.createdAtMs) || new Date(0).toISOString(),
  };
}

function buildInvoiceLineItems(input: {
  orgId: string;
  invoiceId: string;
  periodMonthUtc: string;
  monthlyActiveWallets: number;
  createdAtMs: number;
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
      createdAtMs: input.createdAtMs,
    }),
    makeInvoiceLineItem({
      orgId: input.orgId,
      invoiceId: input.invoiceId,
      periodMonthUtc: input.periodMonthUtc,
      itemType: 'MAW_USAGE',
      description: `Monthly Active Wallets (${input.periodMonthUtc})`,
      quantity: input.monthlyActiveWallets,
      unitAmountMinor: PLAN_MAW_UNIT_PRICE_MINOR,
      createdAtMs: input.createdAtMs,
    }),
  ];
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

async function listInvoiceLineItemsByInvoice(
  q: Queryable,
  namespace: string,
  orgId: string,
  invoiceId: string,
): Promise<BillingInvoiceLineItem[]> {
  const out = await q.query(
    `SELECT *
       FROM console_invoice_line_items
      WHERE namespace = $1 AND org_id = $2 AND invoice_id = $3
      ORDER BY item_type ASC`,
    [namespace, orgId, invoiceId],
  );
  return out.rows.map((row) => parseInvoiceLineItemRow(row as PgRow));
}

export interface PostgresConsoleBillingSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleBillingPostgresSchema(
  options: PostgresConsoleBillingSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_BILLING_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_accounts (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        plan_id TEXT NOT NULL,
        plan_name TEXT NOT NULL,
        usage_metric_version TEXT NOT NULL,
        monthly_active_wallets INTEGER NOT NULL,
        credit_balance_minor BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id),
        CHECK (usage_metric_version IN ('maw_v1'))
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_subscriptions (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_customer_ref TEXT,
        provider_subscription_ref TEXT,
        plan_id TEXT NOT NULL,
        plan_name TEXT NOT NULL,
        status TEXT NOT NULL,
        cancel_at_period_end BOOLEAN NOT NULL,
        current_period_start_ms BIGINT NOT NULL,
        current_period_end_ms BIGINT NOT NULL,
        cancel_at_ms BIGINT,
        canceled_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, org_id),
        CHECK (provider IN ('stripe')),
        CHECK (status IN ('ACTIVE', 'PAST_DUE', 'CANCELED'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_subscriptions_org_updated_idx
      ON console_subscriptions (namespace, org_id, updated_at_ms DESC)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_usage_meter_events (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        wallet_id TEXT NOT NULL,
        action TEXT NOT NULL,
        succeeded BOOLEAN NOT NULL,
        is_simulation BOOLEAN NOT NULL,
        is_internal_retry BOOLEAN NOT NULL,
        occurred_at_ms BIGINT NOT NULL,
        month_utc TEXT NOT NULL,
        source_event_id TEXT,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, org_id, source_event_id),
        CHECK (action IN ('transfer', 'swap', 'approve', 'contract_call', 'wallet_created'))
      )
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
            FROM pg_constraint
           WHERE conname = 'console_usage_meter_events_action_check_v2'
        ) THEN
          ALTER TABLE console_usage_meter_events
            DROP CONSTRAINT IF EXISTS console_usage_meter_events_action_check;
          ALTER TABLE console_usage_meter_events
            ADD CONSTRAINT console_usage_meter_events_action_check_v2
            CHECK (action IN ('transfer', 'swap', 'approve', 'contract_call', 'wallet_created'));
        END IF;
      END
      $$;
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_usage_meter_events_org_month_idx
      ON console_usage_meter_events (namespace, org_id, month_utc, occurred_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_usage_meter_events_org_month_wallet_idx
      ON console_usage_meter_events (namespace, org_id, month_utc, wallet_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_usage_rollups_monthly (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        month_utc TEXT NOT NULL,
        monthly_active_wallets INTEGER NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, month_utc)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_invoices (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        status TEXT NOT NULL,
        currency TEXT NOT NULL,
        amount_due_minor BIGINT NOT NULL,
        amount_paid_minor BIGINT NOT NULL,
        rail_lock TEXT,
        period_month_utc TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        due_at_ms BIGINT,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE')),
        CHECK (currency IN ('USD')),
        CHECK (rail_lock IS NULL OR rail_lock IN ('CARD', 'STABLECOIN'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_invoices_org_created_idx
      ON console_invoices (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_invoices_org_status_idx
      ON console_invoices (namespace, org_id, status)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_invoice_line_items (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        period_month_utc TEXT NOT NULL,
        item_type TEXT NOT NULL,
        description TEXT NOT NULL,
        quantity BIGINT NOT NULL,
        unit_amount_minor BIGINT NOT NULL,
        amount_minor BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, invoice_id, item_type),
        CHECK (item_type IN ('PLAN_BASE_FEE', 'MAW_USAGE'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_invoice_line_items_org_invoice_idx
      ON console_invoice_line_items (namespace, org_id, invoice_id, item_type)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_payment_methods (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        type TEXT NOT NULL,
        provider_ref TEXT NOT NULL,
        brand TEXT NOT NULL,
        last4 TEXT NOT NULL,
        exp_month INTEGER NOT NULL,
        exp_year INTEGER NOT NULL,
        is_default BOOLEAN NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, org_id, provider_ref),
        CHECK (provider IN ('stripe')),
        CHECK (type IN ('card'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_payment_methods_org_created_idx
      ON console_payment_methods (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_payment_methods_org_default_idx
      ON console_payment_methods (namespace, org_id, is_default)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stripe_payment_intents (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        provider_ref TEXT NOT NULL,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency TEXT NOT NULL,
        payment_method_id TEXT,
        state TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        rail TEXT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (currency IN ('USD')),
        CHECK (rail IN ('CARD')),
        CHECK (state IN ('CREATED','ACTION_REQUIRED','PENDING','CONFIRMING','SETTLED','PARTIALLY_SETTLED','OVERPAID','FAILED','CANCELED','EXPIRED','REFUNDED','DISPUTED'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_stripe_payment_intents
      ADD COLUMN IF NOT EXISTS provider_ref TEXT
    `);
    await pool.query(`
      UPDATE console_stripe_payment_intents
         SET provider_ref = id
       WHERE provider_ref IS NULL OR provider_ref = ''
    `);
    await pool.query(`
      ALTER TABLE console_stripe_payment_intents
      ALTER COLUMN provider_ref SET NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stripe_payment_intents_org_invoice_idx
      ON console_stripe_payment_intents (namespace, org_id, invoice_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stripe_payment_intents_provider_ref_idx
      ON console_stripe_payment_intents (namespace, provider_ref)
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stripe_provider_refs (
        namespace TEXT NOT NULL,
        provider_ref TEXT NOT NULL,
        org_id TEXT NOT NULL,
        payment_intent_id TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, provider_ref),
        UNIQUE (namespace, payment_intent_id)
      )
    `);
    await pool.query(`
      INSERT INTO console_stripe_provider_refs
        (namespace, provider_ref, org_id, payment_intent_id, created_at_ms)
      SELECT DISTINCT ON (namespace, provider_ref)
        namespace,
        provider_ref,
        org_id,
        id,
        created_at_ms
      FROM console_stripe_payment_intents
      WHERE provider_ref IS NOT NULL AND provider_ref <> ''
      ORDER BY namespace, provider_ref, created_at_ms DESC, id DESC
      ON CONFLICT (namespace, provider_ref) DO UPDATE
        SET org_id = EXCLUDED.org_id,
            payment_intent_id = EXCLUDED.payment_intent_id,
            created_at_ms = EXCLUDED.created_at_ms
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stripe_provider_refs_org_idx
      ON console_stripe_provider_refs (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stripe_webhook_events (
        namespace TEXT NOT NULL,
        event_id TEXT NOT NULL,
        provider_ref TEXT NOT NULL,
        payment_intent_id TEXT,
        org_id TEXT,
        processed_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, event_id)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stripe_webhook_events_provider_ref_idx
      ON console_stripe_webhook_events (namespace, provider_ref, processed_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stripe_webhook_events_payment_intent_idx
      ON console_stripe_webhook_events (namespace, payment_intent_id)
      WHERE payment_intent_id IS NOT NULL
    `);
    await pool.query(`
      UPDATE console_stripe_webhook_events events
         SET org_id = refs.org_id,
             payment_intent_id = COALESCE(events.payment_intent_id, refs.payment_intent_id)
        FROM console_stripe_provider_refs refs
       WHERE events.namespace = refs.namespace
         AND events.provider_ref = refs.provider_ref
         AND (events.org_id IS NULL OR events.payment_intent_id IS NULL)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stablecoin_quotes (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        asset TEXT NOT NULL,
        chain TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        state TEXT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (asset IN ('USDC', 'USDT')),
        CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
        CHECK (state IN ('OPEN', 'EXPIRED'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stablecoin_quotes_org_invoice_idx
      ON console_stablecoin_quotes (namespace, org_id, invoice_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stablecoin_quotes_expires_idx
      ON console_stablecoin_quotes (namespace, expires_at_ms)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stablecoin_payment_intents (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        invoice_id TEXT NOT NULL,
        quote_id TEXT NOT NULL,
        asset TEXT NOT NULL,
        chain TEXT NOT NULL,
        expected_amount_minor BIGINT NOT NULL,
        destination_address TEXT NOT NULL,
        state TEXT NOT NULL,
        rail TEXT NOT NULL,
        required_confirmations INTEGER NOT NULL,
        confirmation_timeout_minutes INTEGER NOT NULL,
        reorg_risk_window_hours INTEGER NOT NULL,
        settled_at_ms BIGINT,
        reorg_risk_window_ends_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (asset IN ('USDC', 'USDT')),
        CHECK (chain IN ('Ethereum', 'Base', 'Tempo', 'Arc Circle', 'NEAR')),
        CHECK (rail IN ('STABLECOIN')),
        CHECK (state IN ('CREATED','ACTION_REQUIRED','PENDING','CONFIRMING','SETTLED','PARTIALLY_SETTLED','OVERPAID','FAILED','CANCELED','EXPIRED','REFUNDED','DISPUTED'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_stablecoin_payment_intents
      ADD COLUMN IF NOT EXISTS settled_at_ms BIGINT
    `);
    await pool.query(`
      ALTER TABLE console_stablecoin_payment_intents
      ADD COLUMN IF NOT EXISTS reorg_risk_window_ends_at_ms BIGINT
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stablecoin_payment_intents_org_invoice_idx
      ON console_stablecoin_payment_intents (namespace, org_id, invoice_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stablecoin_payment_intents_quote_idx
      ON console_stablecoin_payment_intents (namespace, quote_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_stablecoin_payment_intents_risk_window_idx
      ON console_stablecoin_payment_intents (namespace, reorg_risk_window_ends_at_ms)
      WHERE reorg_risk_window_ends_at_ms IS NOT NULL
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_payment_state_transitions (
        id BIGSERIAL PRIMARY KEY,
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        payment_id TEXT NOT NULL,
        from_state TEXT,
        to_state TEXT NOT NULL,
        changed_at_ms BIGINT NOT NULL,
        actor_type TEXT NOT NULL,
        actor_user_id TEXT,
        source_event_id TEXT,
        reason TEXT,
        CHECK (from_state IS NULL OR from_state IN ('CREATED','ACTION_REQUIRED','PENDING','CONFIRMING','SETTLED','PARTIALLY_SETTLED','OVERPAID','FAILED','CANCELED','EXPIRED','REFUNDED','DISPUTED')),
        CHECK (to_state IN ('CREATED','ACTION_REQUIRED','PENDING','CONFIRMING','SETTLED','PARTIALLY_SETTLED','OVERPAID','FAILED','CANCELED','EXPIRED','REFUNDED','DISPUTED')),
        CHECK (actor_type IN ('USER', 'SYSTEM', 'PROVIDER'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_payment_state_transitions
      ADD COLUMN IF NOT EXISTS org_id TEXT
    `);
    await pool.query(`
      CREATE OR REPLACE FUNCTION console_reject_payment_state_transition_mutation()
      RETURNS trigger AS $$
      BEGIN
        RAISE EXCEPTION 'console_payment_state_transitions is append-only';
      END;
      $$ LANGUAGE plpgsql
    `);
    // Existing deployments may already have the append-only trigger installed.
    // Drop it before one-time backfills so ensureSchema stays idempotent.
    await pool.query(`
      DROP TRIGGER IF EXISTS console_payment_state_transitions_no_update_delete
      ON console_payment_state_transitions
    `);
    await pool.query(`
      UPDATE console_payment_state_transitions transitions
         SET org_id = intents.org_id
        FROM console_stripe_payment_intents intents
       WHERE transitions.namespace = intents.namespace
         AND transitions.payment_id = intents.id
         AND transitions.org_id IS NULL
    `);
    await pool.query(`
      UPDATE console_payment_state_transitions transitions
         SET org_id = intents.org_id
        FROM console_stablecoin_payment_intents intents
       WHERE transitions.namespace = intents.namespace
         AND transitions.payment_id = intents.id
         AND transitions.org_id IS NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_payment_state_transitions_namespace_payment_idx
      ON console_payment_state_transitions (namespace, payment_id, changed_at_ms ASC, id ASC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_payment_state_transitions_namespace_org_payment_idx
      ON console_payment_state_transitions (namespace, org_id, payment_id, changed_at_ms ASC, id ASC)
    `);
    await pool.query(`
      CREATE TRIGGER console_payment_state_transitions_no_update_delete
      BEFORE UPDATE OR DELETE ON console_payment_state_transitions
      FOR EACH ROW EXECUTE FUNCTION console_reject_payment_state_transition_mutation()
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_accounts',
      policyName: 'console_billing_accounts_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_subscriptions',
      policyName: 'console_subscriptions_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_usage_meter_events',
      policyName: 'console_usage_meter_events_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_usage_rollups_monthly',
      policyName: 'console_usage_rollups_monthly_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_invoices',
      policyName: 'console_invoices_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_invoice_line_items',
      policyName: 'console_invoice_line_items_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_payment_methods',
      policyName: 'console_payment_methods_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_stripe_payment_intents',
      policyName: 'console_stripe_payment_intents_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_stripe_webhook_events',
      policyName: 'console_stripe_webhook_events_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_stablecoin_quotes',
      policyName: 'console_stablecoin_quotes_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_stablecoin_payment_intents',
      policyName: 'console_stablecoin_payment_intents_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_payment_state_transitions',
      policyName: 'console_payment_state_transitions_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_BILLING_MIGRATION_LOCK_ID]);
    } catch {}
  }
  options.logger.info('[console-billing][postgres] Schema ready');
}

export interface PostgresConsoleBillingServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
}

export interface PostgresConsoleBillingMonthlyFinalizationOptions {
  postgresUrl: string;
  namespace?: string;
  orgIds?: string[];
  periodMonthUtc?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export interface PostgresConsoleBillingMonthlyFinalizationResult {
  namespace: string;
  periodMonthUtc: string;
  orgCount: number;
  generatedCount: number;
  skippedCount: number;
  failures: Array<{
    orgId: string;
    code: string;
    message: string;
  }>;
}

export async function createPostgresConsoleBillingService(
  options: PostgresConsoleBillingServiceOptions,
): Promise<ConsoleBillingService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console billing service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  const providers = resolveBillingProviderAdapters(options.providers);
  if (options.ensureSchema !== false) {
    await ensureConsoleBillingPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);
  const withOrgTx = <T>(
    ctx: ConsoleBillingContext,
    fn: (q: Queryable, now: Date) => Promise<T>,
  ): Promise<T> =>
    withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) => {
      const now = nowFn();
      await ensureOrgBootstrap({ pool: q, namespace, orgId: ctx.orgId, now });
      return fn(q, now);
    });

  return {
    async getSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      return withOrgTx(ctx, async (q, now) => {
        const subscription = await refreshSubscriptionLifecycleIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          nowMs: nowMs(now),
        });
        if (!subscription) {
          throw new ConsoleBillingError(
            'subscription_not_found',
            404,
            `Subscription for org ${ctx.orgId} was not found`,
          );
        }
        return subscription;
      });
    },

    async cancelSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      return withOrgTx(ctx, async (q, now) => {
        const current = await refreshSubscriptionLifecycleIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          nowMs: nowMs(now),
        });
        if (!current) {
          throw new ConsoleBillingError(
            'subscription_not_found',
            404,
            `Subscription for org ${ctx.orgId} was not found`,
          );
        }
        if (current.status === 'CANCELED') {
          throw new ConsoleBillingError(
            'subscription_already_canceled',
            409,
            'Subscription is already canceled',
          );
        }
        if (current.cancelAtPeriodEnd) return current;

        const updated = await queryOne(
          q,
          `UPDATE console_subscriptions
              SET cancel_at_period_end = TRUE,
                  cancel_at_ms = current_period_end_ms,
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, current.id, nowMs(now)],
        );
        if (!updated) {
          throw new ConsoleBillingError(
            'subscription_update_failed',
            500,
            'Failed to schedule subscription cancellation',
          );
        }
        return parseSubscriptionRow(updated);
      });
    },

    async resumeSubscription(ctx: ConsoleBillingContext): Promise<BillingSubscription> {
      return withOrgTx(ctx, async (q, now) => {
        const current = await refreshSubscriptionLifecycleIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          nowMs: nowMs(now),
        });
        if (!current) {
          throw new ConsoleBillingError(
            'subscription_not_found',
            404,
            `Subscription for org ${ctx.orgId} was not found`,
          );
        }
        if (current.status === 'CANCELED') {
          throw new ConsoleBillingError(
            'subscription_not_resumable',
            409,
            'Subscription is already canceled and cannot be resumed',
          );
        }
        if (!current.cancelAtPeriodEnd) return current;

        const updated = await queryOne(
          q,
          `UPDATE console_subscriptions
              SET cancel_at_period_end = FALSE,
                  cancel_at_ms = NULL,
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, current.id, nowMs(now)],
        );
        if (!updated) {
          throw new ConsoleBillingError(
            'subscription_update_failed',
            500,
            'Failed to resume subscription',
          );
        }
        return parseSubscriptionRow(updated);
      });
    },

    async getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview> {
      return withOrgTx(ctx, async (q, now) => {
        const currentMonthUtc = monthUtc(now);

        const account = await queryOne(
          q,
          `SELECT *
             FROM console_billing_accounts
            WHERE namespace = $1 AND org_id = $2`,
          [namespace, ctx.orgId],
        );
        if (!account) {
          throw new ConsoleBillingError(
            'billing_account_not_found',
            404,
            `Billing account for org ${ctx.orgId} was not found`,
          );
        }

        const openStats = await queryOne(
          q,
          `SELECT
              COUNT(*)::BIGINT AS open_invoice_count,
              COALESCE(SUM(GREATEST(amount_due_minor - amount_paid_minor, 0)), 0)::BIGINT AS upcoming_charge_estimate_minor
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND status = 'OPEN'`,
          [namespace, ctx.orgId],
        );

        const monthlyActiveWallets = await countMonthlyActiveWallets(
          q,
          namespace,
          ctx.orgId,
          currentMonthUtc,
        );
        await upsertMonthlyActiveWalletRollup(q, {
          namespace,
          orgId: ctx.orgId,
          monthUtc: currentMonthUtc,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });
        await q.query(
          `UPDATE console_billing_accounts
              SET monthly_active_wallets = $3,
                  updated_at_ms = $4
            WHERE namespace = $1 AND org_id = $2`,
          [namespace, ctx.orgId, monthlyActiveWallets, nowMs(now)],
        );

        return {
          planId: String(account.plan_id || ''),
          planName: String(account.plan_name || ''),
          usageMetricVersion: 'maw_v1',
          currentMonthUtc,
          monthlyActiveWallets,
          creditBalanceMinor: toNumber(account.credit_balance_minor),
          upcomingChargeEstimateMinor: toNumber(openStats?.upcoming_charge_estimate_minor),
          openInvoiceCount: toNumber(openStats?.open_invoice_count),
        };
      });
    },

    async getMonthlyActiveWallets(
      ctx: ConsoleBillingContext,
      monthUtcInput?: string,
    ): Promise<BillingMonthlyActiveWallets> {
      return withOrgTx(ctx, async (q, now) => {
        const resolvedMonthUtc = monthUtcInput ? parseMonthUtcOrThrow(monthUtcInput) : monthUtc(now);
        const monthlyActiveWallets = await countMonthlyActiveWallets(
          q,
          namespace,
          ctx.orgId,
          resolvedMonthUtc,
        );
        await upsertMonthlyActiveWalletRollup(q, {
          namespace,
          orgId: ctx.orgId,
          monthUtc: resolvedMonthUtc,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });
        if (resolvedMonthUtc === monthUtc(now)) {
          await q.query(
            `UPDATE console_billing_accounts
                SET monthly_active_wallets = $3,
                    updated_at_ms = $4
              WHERE namespace = $1 AND org_id = $2`,
            [namespace, ctx.orgId, monthlyActiveWallets, nowMs(now)],
          );
        }
        return {
          usageMetricVersion: 'maw_v1',
          monthUtc: resolvedMonthUtc,
          monthlyActiveWallets,
        };
      });
    },

    async recordUsageEvent(
      ctx: ConsoleBillingContext,
      request: BillingUsageEventRequest,
    ): Promise<BillingUsageEventResult> {
      return withOrgTx(ctx, async (q, now) => {
        const occurredAtMs = request.occurredAt ? Date.parse(request.occurredAt) : nowMs(now);
        if (!Number.isFinite(occurredAtMs)) {
          throw new ConsoleBillingError('invalid_usage_event', 400, 'Invalid occurredAt value');
        }
        const eventMonthUtc = monthUtc(new Date(occurredAtMs));
        const counted =
          BILLABLE_USAGE_ACTIONS.has(request.action) &&
          request.succeeded &&
          !request.isSimulation &&
          !request.isInternalRetry;

        const eventId = makeId('ume', now);
        const inserted = await queryOne(
          q,
          `INSERT INTO console_usage_meter_events
            (namespace, id, org_id, wallet_id, action, succeeded, is_simulation, is_internal_retry, occurred_at_ms, month_utc, source_event_id)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (namespace, org_id, source_event_id) DO NOTHING
           RETURNING id`,
          [
            namespace,
            eventId,
            ctx.orgId,
            request.walletId,
            request.action,
            request.succeeded,
            Boolean(request.isSimulation),
            Boolean(request.isInternalRetry),
            occurredAtMs,
            eventMonthUtc,
            request.sourceEventId || null,
          ],
        );

        const monthlyActiveWallets = await countMonthlyActiveWallets(
          q,
          namespace,
          ctx.orgId,
          eventMonthUtc,
        );
        await upsertMonthlyActiveWalletRollup(q, {
          namespace,
          orgId: ctx.orgId,
          monthUtc: eventMonthUtc,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });

        if (eventMonthUtc === monthUtc(now)) {
          await q.query(
            `UPDATE console_billing_accounts
                SET monthly_active_wallets = $3,
                    updated_at_ms = $4
              WHERE namespace = $1 AND org_id = $2`,
            [namespace, ctx.orgId, monthlyActiveWallets, nowMs(now)],
          );
        }

        return {
          accepted: Boolean(inserted),
          counted: inserted ? counted : false,
          monthUtc: eventMonthUtc,
          monthlyActiveWallets,
        };
      });
    },

    async listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]> {
      return withOrgTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2
            ORDER BY created_at_ms DESC`,
          [namespace, ctx.orgId],
        );
        return out.rows.map((row) => parseInvoiceRow(row as PgRow));
      });
    },

    async getInvoice(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoice | null> {
      return withOrgTx(ctx, async (q) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, invoiceId],
        );
        return row ? parseInvoiceRow(row) : null;
      });
    },

    async listInvoiceLineItems(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceLineItem[]> {
      return withOrgTx(ctx, async (q) => {
        const invoice = await queryOne(
          q,
          `SELECT id
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, invoiceId],
        );
        if (!invoice) return [];
        return listInvoiceLineItemsByInvoice(q, namespace, ctx.orgId, invoiceId);
      });
    },

    async generateMonthlyInvoice(
      ctx: ConsoleBillingContext,
      request: GenerateMonthlyInvoiceRequest,
    ): Promise<GenerateMonthlyInvoiceResult> {
      return withOrgTx(ctx, async (q, now) => {
        const periodMonthUtc = parseMonthUtcOrThrow(request.periodMonthUtc);
        const monthlyActiveWallets = await countMonthlyActiveWallets(
          q,
          namespace,
          ctx.orgId,
          periodMonthUtc,
        );
        await upsertMonthlyActiveWalletRollup(q, {
          namespace,
          orgId: ctx.orgId,
          monthUtc: periodMonthUtc,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });

        let invoiceRow = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND period_month_utc = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, periodMonthUtc],
        );

        let created = false;
        if (!invoiceRow) {
          created = true;
          const invoiceId = makeBootstrapInvoiceId(ctx.orgId, periodMonthUtc);
          const dueAtMs = nowMs(now) + 14 * 24 * 60 * 60 * 1000;
          await q.query(
            `INSERT INTO console_invoices
              (namespace, id, org_id, status, currency, amount_due_minor, amount_paid_minor, rail_lock, period_month_utc, created_at_ms, due_at_ms)
             VALUES
              ($1, $2, $3, 'OPEN', 'USD', $4, 0, NULL, $5, $6, $7)
             ON CONFLICT (namespace, id) DO NOTHING`,
            [
              namespace,
              invoiceId,
              ctx.orgId,
              DEFAULT_MONTHLY_PLAN_AMOUNT_MINOR,
              periodMonthUtc,
              nowMs(now),
              dueAtMs,
            ],
          );
          invoiceRow = await queryOne(
            q,
            `SELECT *
               FROM console_invoices
              WHERE namespace = $1 AND org_id = $2 AND id = $3
              FOR UPDATE`,
            [namespace, ctx.orgId, invoiceId],
          );
        }

        if (!invoiceRow) {
          throw new ConsoleBillingError(
            'invoice_generate_failed',
            500,
            'Failed to load invoice for generation',
          );
        }
        const currentInvoice = parseInvoiceRow(invoiceRow);
        if (currentInvoice.status === 'VOID' || currentInvoice.status === 'UNCOLLECTIBLE') {
          throw new ConsoleBillingError(
            'invoice_not_billable',
            409,
            `Invoice ${currentInvoice.id} is ${currentInvoice.status} and cannot be regenerated`,
          );
        }

        const previousLineItems = await listInvoiceLineItemsByInvoice(
          q,
          namespace,
          ctx.orgId,
          currentInvoice.id,
        );
        const nextLineItems = buildInvoiceLineItems({
          orgId: ctx.orgId,
          invoiceId: currentInvoice.id,
          periodMonthUtc,
          monthlyActiveWallets,
          createdAtMs: nowMs(now),
        });

        for (const lineItem of nextLineItems) {
          await q.query(
            `INSERT INTO console_invoice_line_items
              (namespace, id, org_id, invoice_id, period_month_utc, item_type, description, quantity, unit_amount_minor, amount_minor, created_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             ON CONFLICT (namespace, invoice_id, item_type)
             DO UPDATE SET
               description = EXCLUDED.description,
               quantity = EXCLUDED.quantity,
               unit_amount_minor = EXCLUDED.unit_amount_minor,
               amount_minor = EXCLUDED.amount_minor,
               period_month_utc = EXCLUDED.period_month_utc`,
            [
              namespace,
              lineItem.id,
              ctx.orgId,
              currentInvoice.id,
              lineItem.periodMonthUtc,
              lineItem.itemType,
              lineItem.description,
              lineItem.quantity,
              lineItem.unitAmountMinor,
              lineItem.amountMinor,
              nowMs(now),
            ],
          );
        }

        const nextAmountDueMinor = sumLineItemAmounts(nextLineItems);
        const updatedInvoiceRow = await queryOne(
          q,
          `UPDATE console_invoices
              SET amount_due_minor = $4,
                  status = CASE
                    WHEN status IN ('VOID', 'UNCOLLECTIBLE') THEN status
                    WHEN amount_paid_minor >= $4 THEN 'PAID'
                    ELSE 'OPEN'
                  END
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, currentInvoice.id, nextAmountDueMinor],
        );
        if (!updatedInvoiceRow) {
          throw new ConsoleBillingError(
            'invoice_generate_failed',
            500,
            'Failed to update invoice amount',
          );
        }

        const updatedInvoice = parseInvoiceRow(updatedInvoiceRow);
        const updatedLineItems = await listInvoiceLineItemsByInvoice(
          q,
          namespace,
          ctx.orgId,
          currentInvoice.id,
        );
        const generated =
          created ||
          currentInvoice.amountDueMinor !== nextAmountDueMinor ||
          !lineItemsEquivalent(previousLineItems, nextLineItems);

        return {
          generated,
          invoice: updatedInvoice,
          lineItems: sortLineItems(updatedLineItems),
          monthlyActiveWallets,
          pricing: {
            baseFeeMinor: PLAN_BASE_FEE_MINOR,
            mawUnitPriceMinor: PLAN_MAW_UNIT_PRICE_MINOR,
          },
        };
      });
    },

    async listPaymentMethods(ctx: ConsoleBillingContext): Promise<BillingPaymentMethod[]> {
      return withOrgTx(ctx, async (q) => {
        const out = await q.query(
          `SELECT *
             FROM console_payment_methods
            WHERE namespace = $1 AND org_id = $2
            ORDER BY created_at_ms DESC`,
          [namespace, ctx.orgId],
        );
        return out.rows.map((row) => parsePaymentMethodRow(row as PgRow));
      });
    },

    async addCardPaymentMethod(
      ctx: ConsoleBillingContext,
      request: AddCardPaymentMethodRequest,
    ): Promise<BillingPaymentMethod> {
      requireAdminForCardActions(ctx);
      return withOrgTx(ctx, async (q, now) => {
        const id = makeId('pm', now);
        const createdAt = nowMs(now);

        const currentDefault = await queryOne(
          q,
          `SELECT id
             FROM console_payment_methods
            WHERE namespace = $1 AND org_id = $2 AND is_default = TRUE
            LIMIT 1`,
          [namespace, ctx.orgId],
        );
        const shouldBeDefault = !currentDefault;

        const inserted = await queryOne(
          q,
          `INSERT INTO console_payment_methods
            (namespace, id, org_id, provider, type, provider_ref, brand, last4, exp_month, exp_year, is_default, created_at_ms)
           VALUES
            ($1, $2, $3, 'stripe', 'card', $4, $5, $6, $7, $8, $9, $10)
           RETURNING *`,
          [
            namespace,
            id,
            ctx.orgId,
            request.providerRef,
            request.brand,
            request.last4,
            request.expMonth,
            request.expYear,
            shouldBeDefault,
            createdAt,
          ],
        );
        if (!inserted) {
          throw new ConsoleBillingError(
            'payment_method_create_failed',
            500,
            'Failed to create card payment method',
          );
        }
        return parsePaymentMethodRow(inserted);
      });
    },

    async removeCardPaymentMethod(
      ctx: ConsoleBillingContext,
      paymentMethodId: string,
    ): Promise<{ removed: boolean }> {
      requireAdminForCardActions(ctx);
      return withOrgTx(ctx, async (q) => {
        const removed = await queryOne(
          q,
          `DELETE FROM console_payment_methods
            WHERE namespace = $1 AND org_id = $2 AND id = $3
          RETURNING is_default`,
          [namespace, ctx.orgId, paymentMethodId],
        );
        if (!removed) return { removed: false };

        if (removed.is_default === true) {
          const fallback = await queryOne(
            q,
            `SELECT id
               FROM console_payment_methods
              WHERE namespace = $1 AND org_id = $2
              ORDER BY created_at_ms DESC
              LIMIT 1`,
            [namespace, ctx.orgId],
          );
          if (fallback?.id) {
            await q.query(
              `UPDATE console_payment_methods
                  SET is_default = TRUE
                WHERE namespace = $1 AND org_id = $2 AND id = $3`,
              [namespace, ctx.orgId, String(fallback.id)],
            );
          }
        }
        return { removed: true };
      });
    },

    async setDefaultCardPaymentMethod(
      ctx: ConsoleBillingContext,
      paymentMethodId: string,
    ): Promise<BillingPaymentMethod | null> {
      requireAdminForCardActions(ctx);
      return withOrgTx(ctx, async (q) => {
        const target = await queryOne(
          q,
          `SELECT *
             FROM console_payment_methods
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, paymentMethodId],
        );
        if (!target) return null;

        await q.query(
          `UPDATE console_payment_methods
              SET is_default = FALSE
            WHERE namespace = $1 AND org_id = $2`,
          [namespace, ctx.orgId],
        );
        const updated = await queryOne(
          q,
          `UPDATE console_payment_methods
              SET is_default = TRUE
            WHERE namespace = $1 AND org_id = $2 AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, paymentMethodId],
        );
        return updated ? parsePaymentMethodRow(updated) : null;
      });
    },

    async createStripeSetupIntent(
      ctx: ConsoleBillingContext,
      request: StripeSetupIntentRequest,
    ): Promise<StripeSetupIntent> {
      return withOrgTx(ctx, async (_q, now) => {
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
      });
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      return withOrgTx(ctx, async (_q, now) => {
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
      });
    },

    async createStripeCustomerPortalSession(
      ctx: ConsoleBillingContext,
      request: StripeCustomerPortalSessionRequest,
    ): Promise<StripeCustomerPortalSession> {
      return withOrgTx(ctx, async (_q, now) => {
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
      });
    },

    async createStripePaymentIntent(
      ctx: ConsoleBillingContext,
      request: StripePaymentIntentRequest,
    ): Promise<StripePaymentIntent> {
      return withOrgTx(ctx, async (q, now) => {
        const invoice = await lockInvoiceForPayment(q, namespace, ctx.orgId, request.invoiceId);
        ensureRailLock(invoice, 'CARD');
        const activeIntent = await queryOne(
          q,
          `SELECT id
             FROM console_stripe_payment_intents
            WHERE namespace = $1
              AND org_id = $2
              AND invoice_id = $3
              AND state IN ('CREATED', 'ACTION_REQUIRED', 'PENDING', 'CONFIRMING')
            ORDER BY created_at_ms DESC
            LIMIT 1
            FOR UPDATE`,
          [namespace, ctx.orgId, invoice.id],
        );
        if (activeIntent) {
          throw new ConsoleBillingError(
            'active_payment_intent_exists',
            409,
            `Invoice ${invoice.id} already has an active card payment intent (${String(activeIntent.id || '')})`,
          );
        }
        if (!invoice.railLock) {
          await setInvoiceRailLock(q, namespace, invoice.id, 'CARD');
        }

        let paymentMethodId: string | null = null;
        let paymentMethodProviderRef: string | null = null;
        if (request.paymentMethodId) {
          const requested = await queryOne(
            q,
            `SELECT id, provider_ref
               FROM console_payment_methods
              WHERE namespace = $1 AND org_id = $2 AND id = $3`,
            [namespace, ctx.orgId, request.paymentMethodId],
          );
          if (!requested) {
            throw new ConsoleBillingError(
              'payment_method_not_found',
              404,
              `Payment method ${request.paymentMethodId} was not found`,
            );
          }
          paymentMethodId = String(requested.id);
          paymentMethodProviderRef = String(requested.provider_ref || '').trim() || null;
        } else {
          const fallback = await queryOne(
            q,
            `SELECT id, provider_ref
               FROM console_payment_methods
              WHERE namespace = $1 AND org_id = $2 AND is_default = TRUE
              LIMIT 1`,
            [namespace, ctx.orgId],
          );
          paymentMethodId = fallback?.id ? String(fallback.id) : null;
          paymentMethodProviderRef = fallback?.provider_ref
            ? String(fallback.provider_ref).trim() || null
            : null;
        }

        const amountMinor = Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
        const providerPaymentIntent = await providers.stripe.createPaymentIntent({
          orgId: ctx.orgId,
          invoiceId: invoice.id,
          amountMinor,
          currency: 'USD',
          paymentMethodProviderRef,
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
        const intentId = makeId('pi', now);
        const row = await queryOne(
          q,
          `INSERT INTO console_stripe_payment_intents
            (namespace, id, provider_ref, org_id, invoice_id, amount_minor, currency, payment_method_id, state, client_secret, created_at_ms, rail)
           VALUES
            ($1, $2, $3, $4, $5, $6, 'USD', $7, 'CREATED', $8, $9, 'CARD')
           RETURNING *`,
          [
            namespace,
            intentId,
            providerRef,
            ctx.orgId,
            invoice.id,
            amountMinor,
            paymentMethodId,
            clientSecret,
            nowMs(now),
          ],
        );
        if (!row) {
          throw new ConsoleBillingError(
            'payment_intent_create_failed',
            500,
            'Failed to create Stripe payment intent',
          );
        }
        const providerRefBound = await queryOne(
          q,
          `INSERT INTO console_stripe_provider_refs
            (namespace, provider_ref, org_id, payment_intent_id, created_at_ms)
           VALUES
            ($1, $2, $3, $4, $5)
           ON CONFLICT (namespace, provider_ref) DO NOTHING
           RETURNING provider_ref`,
          [namespace, providerRef, ctx.orgId, intentId, nowMs(now)],
        );
        if (!providerRefBound) {
          throw new ConsoleBillingError(
            'duplicate_provider_reference',
            409,
            `Stripe provider reference ${providerRef} is already linked to another payment intent`,
          );
        }
        await appendPaymentStateTransition(q, {
          namespace,
          orgId: ctx.orgId,
          paymentId: intentId,
          fromState: null,
          toState: 'CREATED',
          changedAtMs: nowMs(now),
          actorType: 'USER',
          actorUserId: ctx.actorUserId,
          reason: 'payment_intent_created',
        });
        return parseStripePaymentIntentRow(row);
      });
    },

    async reconcileStripePaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
      request: StripePaymentIntentReconcileRequest,
    ): Promise<StripePaymentIntent | null> {
      return withOrgTx(ctx, async (q, now) => {
        if (request.settledAmountMinor !== undefined && request.settledAmountMinor < 0) {
          throw new ConsoleBillingError(
            'invalid_reconciliation_request',
            400,
            'settledAmountMinor must be >= 0',
          );
        }
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_stripe_payment_intents
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, paymentIntentId],
        );
        if (!row) return null;
        const current = parseStripePaymentIntentRow(row);
        if (isTerminalPaymentState(current.state)) return current;

        const settledAmountMinor = request.settledAmountMinor ?? current.amountMinor;
        const decision = decideStripeReconcileTransition({
          currentState: current.state,
          providerStatus: request.providerStatus,
          expectedAmountMinor: current.amountMinor,
          settledAmountMinor,
        });
        if (!decision.targetState) return current;

        let effectiveFromState = current.state;
        if (
          effectiveFromState === 'CREATED' &&
          SETTLEMENT_OUTCOME_STATES.has(decision.targetState)
        ) {
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
          await q.query(
            `UPDATE console_stripe_payment_intents
                SET state = 'PENDING'
              WHERE namespace = $1 AND org_id = $2 AND id = $3`,
            [namespace, ctx.orgId, paymentIntentId],
          );
          await appendPaymentStateTransition(q, {
            namespace,
            orgId: ctx.orgId,
            paymentId: paymentIntentId,
            fromState: effectiveFromState,
            toState: 'PENDING',
            changedAtMs: nowMs(now),
            actorType: 'PROVIDER',
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

        const updated = await queryOne(
          q,
          `UPDATE console_stripe_payment_intents
              SET state = $4
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, paymentIntentId, decision.targetState],
        );
        if (!updated) return null;

        await appendPaymentStateTransition(q, {
          namespace,
          orgId: ctx.orgId,
          paymentId: paymentIntentId,
          fromState: effectiveFromState,
          toState: decision.targetState,
          changedAtMs: nowMs(now),
          actorType: 'PROVIDER',
          sourceEventId: request.sourceEventId || null,
          reason: decision.reason,
        });

        if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
          await q.query(
            `UPDATE console_invoices
                SET amount_paid_minor = amount_paid_minor + $4,
                    status = CASE
                      WHEN amount_paid_minor + $4 >= amount_due_minor THEN 'PAID'
                      ELSE status
                    END
              WHERE namespace = $1 AND org_id = $2 AND id = $3`,
            [namespace, ctx.orgId, current.invoiceId, settledAmountMinor],
          );
        }

        return parseStripePaymentIntentRow(updated);
      });
    },

    async processStripeWebhookEvent(
      request: StripeWebhookEventRequest,
    ): Promise<StripeWebhookEventResult> {
      const now = nowFn();
      if (request.settledAmountMinor !== undefined && request.settledAmountMinor < 0) {
        throw new ConsoleBillingError(
          'invalid_reconciliation_request',
          400,
          'settledAmountMinor must be >= 0',
        );
      }
      const eventType = String(request.eventType || '').trim().toLowerCase();
      const paymentIntentProjection = !eventType || eventType.startsWith('payment_intent.');

      let currentOrgId: string | null = null;
      let matchedPaymentIntentId: string | null = null;
      let eventProviderRef = String(request.providerRef || '').trim();

      if (paymentIntentProjection) {
        const providerRef = String(request.providerRef || '').trim();
        const providerLink = await queryOne(
          pool,
          `SELECT org_id, payment_intent_id
             FROM console_stripe_provider_refs
            WHERE namespace = $1 AND provider_ref = $2`,
          [namespace, providerRef],
        );
        if (!providerLink) {
          return {
            accepted: true,
            paymentIntent: null,
            subscription: null,
            invoice: null,
            orgId: null,
          };
        }
        currentOrgId = String(providerLink.org_id || '').trim() || null;
        matchedPaymentIntentId = String(providerLink.payment_intent_id || '').trim() || null;
        if (!currentOrgId) {
          throw new ConsoleBillingError(
            'payment_provider_error',
            500,
            'Stripe provider reference mapping is missing org_id',
          );
        }
        if (!matchedPaymentIntentId) {
          throw new ConsoleBillingError(
            'payment_provider_error',
            500,
            'Stripe provider reference mapping is missing payment_intent_id',
          );
        }
      } else {
        currentOrgId = String(request.orgId || '').trim() || null;
        eventProviderRef =
          eventProviderRef ||
          String(request.providerSubscriptionRef || '').trim() ||
          String(request.providerCustomerRef || '').trim() ||
          String(request.invoiceId || '').trim() ||
          eventType ||
          'stripe_event';
      }

      if (!currentOrgId) {
        return {
          accepted: true,
          paymentIntent: null,
          subscription: null,
          invoice: null,
          orgId: null,
        };
      }

      return withConsoleTenantContextTx(
        pool,
        { namespace, orgId: currentOrgId },
        async (q) => {
          const inserted = await queryOne(
            q,
            `INSERT INTO console_stripe_webhook_events
              (namespace, event_id, provider_ref, payment_intent_id, org_id, processed_at_ms)
             VALUES
              ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (namespace, event_id) DO NOTHING
             RETURNING event_id`,
            [
              namespace,
              request.eventId,
              eventProviderRef,
              matchedPaymentIntentId,
              currentOrgId,
              nowMs(now),
            ],
          );
          if (!inserted) {
            const existingEvent = await queryOne(
              q,
              `SELECT payment_intent_id
                 FROM console_stripe_webhook_events
                WHERE namespace = $1 AND org_id = $2 AND event_id = $3`,
              [namespace, currentOrgId, request.eventId],
            );
            const existingPaymentIntentId =
              String(existingEvent?.payment_intent_id || '').trim() || matchedPaymentIntentId || '';
            const existingIntentRow = existingPaymentIntentId
              ? await queryOne(
                  q,
                  `SELECT *
                     FROM console_stripe_payment_intents
                    WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                  [namespace, currentOrgId, existingPaymentIntentId],
                )
              : null;
            const existingSubscriptionRow = await queryOne(
              q,
              `SELECT *
                 FROM console_subscriptions
                WHERE namespace = $1 AND org_id = $2`,
              [namespace, currentOrgId],
            );
            const existingInvoiceRow = request.invoiceId
              ? await queryOne(
                  q,
                  `SELECT *
                     FROM console_invoices
                    WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                  [namespace, currentOrgId, request.invoiceId],
                )
              : null;
            return {
              accepted: false,
              paymentIntent: existingIntentRow ? parseStripePaymentIntentRow(existingIntentRow) : null,
              subscription: existingSubscriptionRow
                ? parseSubscriptionRow(existingSubscriptionRow)
                : null,
              invoice: existingInvoiceRow ? parseInvoiceRow(existingInvoiceRow) : null,
              orgId: currentOrgId,
            };
          }

          let reconciled: StripePaymentIntent | null = null;
          let projectedSubscription: BillingSubscription | null = null;
          let projectedInvoice: BillingInvoice | null = null;

          if (paymentIntentProjection && matchedPaymentIntentId) {
            const currentLocked = await queryOne(
              q,
              `SELECT *
                 FROM console_stripe_payment_intents
                WHERE namespace = $1 AND org_id = $2 AND id = $3
                FOR UPDATE`,
              [namespace, currentOrgId, matchedPaymentIntentId],
            );
            if (currentLocked) {
              const current = parseStripePaymentIntentRow(currentLocked);
              reconciled = current;
              if (!isTerminalPaymentState(current.state) && request.providerStatus) {
                const settledAmountMinor = request.settledAmountMinor ?? current.amountMinor;
                const decision = decideStripeReconcileTransition({
                  currentState: current.state,
                  providerStatus: request.providerStatus,
                  expectedAmountMinor: current.amountMinor,
                  settledAmountMinor,
                });

                if (decision.targetState) {
                  let effectiveFromState = current.state;
                  if (
                    effectiveFromState === 'CREATED' &&
                    SETTLEMENT_OUTCOME_STATES.has(decision.targetState)
                  ) {
                    const toPending = canTransitionPaymentState({
                      from: effectiveFromState,
                      to: 'PENDING',
                    });
                    if (!toPending.ok) {
                      throw new ConsoleBillingError(
                        'invalid_payment_state',
                        409,
                        toPending.message,
                        {
                          fromState: effectiveFromState,
                          toState: 'PENDING',
                        },
                      );
                    }
                    await q.query(
                      `UPDATE console_stripe_payment_intents
                          SET state = 'PENDING'
                        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                      [namespace, currentOrgId, current.id],
                    );
                    await appendPaymentStateTransition(q, {
                      namespace,
                      orgId: currentOrgId,
                      paymentId: current.id,
                      fromState: effectiveFromState,
                      toState: 'PENDING',
                      changedAtMs: nowMs(now),
                      actorType: 'PROVIDER',
                      sourceEventId: request.eventId,
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

                  const updated = await queryOne(
                    q,
                    `UPDATE console_stripe_payment_intents
                        SET state = $4
                      WHERE namespace = $1 AND org_id = $2 AND id = $3
                      RETURNING *`,
                    [namespace, currentOrgId, current.id, decision.targetState],
                  );
                  if (!updated) {
                    throw new ConsoleBillingError(
                      'payment_intent_not_found',
                      404,
                      `Stripe payment intent ${current.id} was not found`,
                    );
                  }
                  reconciled = parseStripePaymentIntentRow(updated);

                  await appendPaymentStateTransition(q, {
                    namespace,
                    orgId: currentOrgId,
                    paymentId: current.id,
                    fromState: effectiveFromState,
                    toState: decision.targetState,
                    changedAtMs: nowMs(now),
                    actorType: 'PROVIDER',
                    sourceEventId: request.eventId,
                    reason: decision.reason,
                  });

                  if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
                    await q.query(
                      `UPDATE console_invoices
                          SET amount_paid_minor = amount_paid_minor + $4,
                              status = CASE
                                WHEN amount_paid_minor + $4 >= amount_due_minor THEN 'PAID'
                                ELSE status
                              END
                        WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                      [namespace, currentOrgId, current.invoiceId, settledAmountMinor],
                    );
                  }
                }
              }
            }
          } else {
            if (
              eventType === 'checkout.session.completed' ||
              eventType.startsWith('customer.subscription.')
            ) {
              const subRow = await queryOne(
                q,
                `SELECT *
                   FROM console_subscriptions
                  WHERE namespace = $1 AND org_id = $2
                  FOR UPDATE`,
                [namespace, currentOrgId],
              );
              if (subRow) {
                const existing = parseSubscriptionRow(subRow);
                const nextStatus =
                  request.subscriptionStatus ||
                  (eventType === 'checkout.session.completed' ? 'ACTIVE' : existing.status);
                const nextCancelAtPeriodEnd =
                  request.cancelAtPeriodEnd !== undefined
                    ? request.cancelAtPeriodEnd
                    : existing.cancelAtPeriodEnd;
                const nextCurrentPeriodStartMs = request.currentPeriodStart
                  ? Date.parse(request.currentPeriodStart)
                  : Date.parse(existing.currentPeriodStart);
                const nextCurrentPeriodEndMs = request.currentPeriodEnd
                  ? Date.parse(request.currentPeriodEnd)
                  : Date.parse(existing.currentPeriodEnd);
                const nextCancelAtMs =
                  request.cancelAt !== undefined
                    ? request.cancelAt === null
                      ? null
                      : Date.parse(request.cancelAt)
                    : nextCancelAtPeriodEnd
                      ? existing.cancelAt
                        ? Date.parse(existing.cancelAt)
                        : nextCurrentPeriodEndMs
                      : null;
                const nextCanceledAtMs =
                  request.canceledAt !== undefined
                    ? request.canceledAt === null
                      ? null
                      : Date.parse(request.canceledAt)
                    : nextStatus === 'CANCELED'
                      ? existing.canceledAt
                        ? Date.parse(existing.canceledAt)
                        : nowMs(now)
                      : null;

                const updatedSub = await queryOne(
                  q,
                  `UPDATE console_subscriptions
                      SET provider_customer_ref = COALESCE($4, provider_customer_ref),
                          provider_subscription_ref = COALESCE($5, provider_subscription_ref),
                          plan_id = COALESCE($6, plan_id),
                          plan_name = COALESCE($7, plan_name),
                          status = $8,
                          cancel_at_period_end = $9,
                          current_period_start_ms = $10,
                          current_period_end_ms = $11,
                          cancel_at_ms = $12,
                          canceled_at_ms = $13,
                          updated_at_ms = $14
                    WHERE namespace = $1 AND org_id = $2 AND id = $3
                    RETURNING *`,
                  [
                    namespace,
                    currentOrgId,
                    existing.id,
                    request.providerCustomerRef || null,
                    request.providerSubscriptionRef || null,
                    request.planId || null,
                    request.planName || null,
                    nextStatus,
                    nextCancelAtPeriodEnd,
                    nextCurrentPeriodStartMs,
                    nextCurrentPeriodEndMs,
                    nextCancelAtMs,
                    nextCanceledAtMs,
                    nowMs(now),
                  ],
                );
                projectedSubscription = updatedSub ? parseSubscriptionRow(updatedSub) : null;
              }
            }

            if (eventType.startsWith('invoice.') && request.invoiceId) {
              const invoiceRow = await queryOne(
                q,
                `SELECT *
                   FROM console_invoices
                  WHERE namespace = $1 AND org_id = $2 AND id = $3
                  FOR UPDATE`,
                [namespace, currentOrgId, request.invoiceId],
              );
              if (invoiceRow) {
                const currentInvoice = parseInvoiceRow(invoiceRow);
                const nextAmountDueMinor =
                  request.invoiceAmountDueMinor ?? currentInvoice.amountDueMinor;
                const nextAmountPaidMinor =
                  request.invoiceAmountPaidMinor ?? currentInvoice.amountPaidMinor;
                const nextStatus =
                  request.invoiceStatus ||
                  (nextAmountPaidMinor >= nextAmountDueMinor
                    ? 'PAID'
                    : currentInvoice.status === 'PAID'
                      ? 'OPEN'
                      : currentInvoice.status);
                const updatedInvoice = await queryOne(
                  q,
                  `UPDATE console_invoices
                      SET amount_due_minor = $4,
                          amount_paid_minor = $5,
                          status = $6
                    WHERE namespace = $1 AND org_id = $2 AND id = $3
                    RETURNING *`,
                  [
                    namespace,
                    currentOrgId,
                    currentInvoice.id,
                    nextAmountDueMinor,
                    nextAmountPaidMinor,
                    nextStatus,
                  ],
                );
                projectedInvoice = updatedInvoice ? parseInvoiceRow(updatedInvoice) : null;
              }
            }
          }

          if (!projectedSubscription) {
            const subRow = await queryOne(
              q,
              `SELECT *
                 FROM console_subscriptions
                WHERE namespace = $1 AND org_id = $2`,
              [namespace, currentOrgId],
            );
            projectedSubscription = subRow ? parseSubscriptionRow(subRow) : null;
          }
          if (!projectedInvoice && request.invoiceId) {
            const invoiceRow = await queryOne(
              q,
              `SELECT *
                 FROM console_invoices
                WHERE namespace = $1 AND org_id = $2 AND id = $3`,
              [namespace, currentOrgId, request.invoiceId],
            );
            projectedInvoice = invoiceRow ? parseInvoiceRow(invoiceRow) : null;
          }

          return {
            accepted: true,
            paymentIntent: reconciled,
            subscription: projectedSubscription,
            invoice: projectedInvoice,
            orgId: currentOrgId,
          };
        },
      );
    },

    async createStablecoinQuote(
      ctx: ConsoleBillingContext,
      request: StablecoinQuoteRequest,
    ): Promise<StablecoinPaymentQuote> {
      return withOrgTx(ctx, async (q, now) => {
        const invoiceRow = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, request.invoiceId],
        );
        if (!invoiceRow) {
          throw new ConsoleBillingError(
            'invoice_not_found',
            404,
            `Invoice ${request.invoiceId} was not found`,
          );
        }
        const invoice = parseInvoiceRow(invoiceRow);
        if (invoice.status !== 'OPEN') {
          throw new ConsoleBillingError('invoice_not_open', 409, `Invoice ${invoice.id} is not open`);
        }
        const amountMinor = Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
        if (amountMinor <= 0) {
          throw new ConsoleBillingError(
            'invoice_already_paid',
            409,
            `Invoice ${invoice.id} is already fully paid`,
          );
        }

        const quoteId = makeId('scq', now);
        const row = await queryOne(
          q,
          `INSERT INTO console_stablecoin_quotes
            (namespace, id, org_id, invoice_id, asset, chain, amount_minor, created_at_ms, expires_at_ms, state)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'OPEN')
           RETURNING *`,
          [
            namespace,
            quoteId,
            ctx.orgId,
            invoice.id,
            request.asset,
            request.chain,
            amountMinor,
            nowMs(now),
            nowMs(now) + 15 * 60 * 1000,
          ],
        );
        if (!row) {
          throw new ConsoleBillingError(
            'quote_create_failed',
            500,
            'Failed to create stablecoin quote',
          );
        }
        return parseStablecoinQuoteRow(row);
      });
    },

    async createStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      request: StablecoinPaymentIntentRequest,
    ): Promise<StablecoinPaymentIntent> {
      return withOrgTx(ctx, async (q, now) => {
        const invoice = await lockInvoiceForPayment(q, namespace, ctx.orgId, request.invoiceId);
        ensureRailLock(invoice, 'STABLECOIN');
        const activeStablecoinRows = await q.query(
          `SELECT *
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1
              AND org_id = $2
              AND invoice_id = $3
              AND state IN ('CREATED', 'ACTION_REQUIRED', 'PENDING', 'CONFIRMING')
            ORDER BY created_at_ms ASC
            FOR UPDATE`,
          [namespace, ctx.orgId, invoice.id],
        );
        for (const rawRow of activeStablecoinRows.rows) {
          const current = parseStablecoinIntentRow(rawRow as PgRow, nowMs(now));
          const normalized = await expireStablecoinIntentIfNeeded(q, {
            namespace,
            orgId: ctx.orgId,
            paymentIntentId: current.id,
            intent: current,
            changedAtMs: nowMs(now),
          });
          if (!isTerminalPaymentState(normalized.state)) {
            throw new ConsoleBillingError(
              'active_payment_intent_exists',
              409,
              `Invoice ${invoice.id} already has an active stablecoin payment intent (${normalized.id})`,
            );
          }
        }

        const quoteRow = await queryOne(
          q,
          `SELECT *
             FROM console_stablecoin_quotes
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, request.quoteId],
        );
        if (!quoteRow) {
          throw new ConsoleBillingError(
            'quote_not_found',
            404,
            `Stablecoin quote ${request.quoteId} was not found`,
          );
        }
        const quote = parseStablecoinQuoteRow(quoteRow);
        if (quote.invoiceId !== invoice.id) {
          throw new ConsoleBillingError(
            'quote_invoice_mismatch',
            409,
            'Quote does not belong to the specified invoice',
          );
        }
        const consumedQuote = await queryOne(
          q,
          `SELECT id
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1 AND org_id = $2 AND quote_id = $3
            LIMIT 1`,
          [namespace, ctx.orgId, quote.id],
        );
        if (consumedQuote) {
          throw new ConsoleBillingError(
            'quote_already_consumed',
            409,
            `Stablecoin quote ${quote.id} has already been used by payment intent ${String(consumedQuote.id || '')}`,
          );
        }
        const expiresAtMs = Date.parse(quote.expiresAt);
        if (!Number.isFinite(expiresAtMs) || nowMs(now) > expiresAtMs || quote.state !== 'OPEN') {
          await q.query(
            `UPDATE console_stablecoin_quotes
                SET state = 'EXPIRED'
              WHERE namespace = $1 AND id = $2`,
            [namespace, quote.id],
          );
          throw new ConsoleBillingError(
            'quote_expired',
            409,
            `Stablecoin quote ${quote.id} has expired`,
          );
        }
        const outstandingMinor = Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
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

        if (!invoice.railLock) {
          await setInvoiceRailLock(q, namespace, invoice.id, 'STABLECOIN');
        }

        const policy = getChainFinalityPolicy(quote.chain);
        if (!policy) {
          throw new ConsoleBillingError(
            'unsupported_chain',
            400,
            `Unsupported stablecoin settlement chain: ${quote.chain}`,
          );
        }

        const intentId = makeId('scpi', now);
        const destination = await providers.stablecoin.allocateDestination({
          orgId: ctx.orgId,
          chain: quote.chain,
          asset: quote.asset,
          now,
        });
        const destinationAddress = String(destination.destinationAddress || '').trim();
        if (!destinationAddress) {
          throw new ConsoleBillingError(
            'payment_provider_error',
            500,
            'Stablecoin destination provider returned invalid payload',
          );
        }
        const row = await queryOne(
          q,
          `INSERT INTO console_stablecoin_payment_intents
            (namespace, id, org_id, invoice_id, quote_id, asset, chain, expected_amount_minor, destination_address, state, rail,
             required_confirmations, confirmation_timeout_minutes, reorg_risk_window_hours, created_at_ms, expires_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'PENDING', 'STABLECOIN', $10, $11, $12, $13, $14)
           RETURNING *`,
          [
            namespace,
            intentId,
            ctx.orgId,
            invoice.id,
            quote.id,
            quote.asset,
            quote.chain,
            quote.amountMinor,
            destinationAddress,
            policy.requiredConfirmations,
            policy.confirmationTimeoutMinutes,
            policy.reorgRiskWindowHours,
            nowMs(now),
            Date.parse(quote.expiresAt),
          ],
        );
        if (!row) {
          throw new ConsoleBillingError(
            'payment_intent_create_failed',
            500,
            'Failed to create stablecoin payment intent',
          );
        }
        await appendPaymentStateTransition(q, {
          namespace,
          orgId: ctx.orgId,
          paymentId: intentId,
          fromState: null,
          toState: 'PENDING',
          changedAtMs: nowMs(now),
          actorType: 'USER',
          actorUserId: ctx.actorUserId,
          reason: 'payment_intent_created',
        });
        return parseStablecoinIntentRow(row, nowMs(now));
      });
    },

    async getStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
    ): Promise<StablecoinPaymentIntent | null> {
      return withOrgTx(ctx, async (q, now) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, paymentIntentId],
        );
        if (!row) return null;
        const current = parseStablecoinIntentRow(row, nowMs(now));
        return expireStablecoinIntentIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          paymentIntentId,
          intent: current,
          changedAtMs: nowMs(now),
        });
      });
    },

    async cancelStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
    ): Promise<StablecoinPaymentIntent | null> {
      return withOrgTx(ctx, async (q, now) => {
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, paymentIntentId],
        );
        if (!row) return null;
        let current = parseStablecoinIntentRow(row, nowMs(now));
        current = await expireStablecoinIntentIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          paymentIntentId,
          intent: current,
          changedAtMs: nowMs(now),
        });
        if (current.state === 'EXPIRED') {
          return current;
        }
        const transition = canTransitionPaymentState({
          from: current.state,
          to: 'CANCELED',
        });
        if (!transition.ok) {
          throw new ConsoleBillingError('invalid_payment_state', 409, transition.message, {
            fromState: current.state,
            toState: 'CANCELED',
          });
        }
        const updated = await queryOne(
          q,
          `UPDATE console_stablecoin_payment_intents
              SET state = 'CANCELED'
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [namespace, ctx.orgId, paymentIntentId],
        );
        if (!updated) return null;
        await appendPaymentStateTransition(q, {
          namespace,
          orgId: ctx.orgId,
          paymentId: paymentIntentId,
          fromState: current.state,
          toState: 'CANCELED',
          changedAtMs: nowMs(now),
          actorType: 'USER',
          actorUserId: ctx.actorUserId,
          reason: 'payment_intent_canceled',
        });
        return parseStablecoinIntentRow(updated, nowMs(now));
      });
    },

    async reconcileStablecoinPaymentIntent(
      ctx: ConsoleBillingContext,
      paymentIntentId: string,
      request: StablecoinPaymentIntentReconcileRequest,
    ): Promise<StablecoinPaymentIntent | null> {
      return withOrgTx(ctx, async (q, now) => {
        if (request.observedAmountMinor < 0 || request.observedConfirmations < 0) {
          throw new ConsoleBillingError(
            'invalid_reconciliation_request',
            400,
            'Observed amount and confirmations must be non-negative',
          );
        }
        const row = await queryOne(
          q,
          `SELECT *
             FROM console_stablecoin_payment_intents
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            FOR UPDATE`,
          [namespace, ctx.orgId, paymentIntentId],
        );
        if (!row) return null;
        let current = parseStablecoinIntentRow(row, nowMs(now));
        current = await expireStablecoinIntentIfNeeded(q, {
          namespace,
          orgId: ctx.orgId,
          paymentIntentId,
          intent: current,
          changedAtMs: nowMs(now),
        });
        if (isTerminalPaymentState(current.state)) return current;

        const decision = decideStablecoinReconcileTransition({
          currentState: current.state,
          expectedAmountMinor: current.expectedAmountMinor,
          observedAmountMinor: request.observedAmountMinor,
          observedConfirmations: request.observedConfirmations,
          requiredConfirmations: current.requiredConfirmations,
          confirmationTimedOut: Boolean(request.confirmationTimedOut),
        });
        if (!decision.targetState) return current;

        if (
          SETTLEMENT_OUTCOME_STATES.has(decision.targetState) &&
          request.observedConfirmations < current.requiredConfirmations
        ) {
          throw new ConsoleBillingError(
            'invalid_payment_state',
            409,
            'Cannot settle payment before chain confirmation threshold is met',
            {
              fromState: current.state,
              toState: decision.targetState,
            },
          );
        }

        const transition = canTransitionPaymentState({
          from: current.state,
          to: decision.targetState,
          observedConfirmations: request.observedConfirmations,
          requiredConfirmations: current.requiredConfirmations,
          confirmationTimedOut: Boolean(request.confirmationTimedOut),
        });
        if (!transition.ok) {
          throw new ConsoleBillingError('invalid_payment_state', 409, transition.message, {
            fromState: current.state,
            toState: decision.targetState,
          });
        }

        const settledAtMs = SETTLEMENT_OUTCOME_STATES.has(decision.targetState) ? nowMs(now) : null;
        const reorgRiskWindowEndsAtMs =
          settledAtMs == null ? null : settledAtMs + current.reorgRiskWindowHours * 60 * 60 * 1000;

        const updated = await queryOne(
          q,
          `UPDATE console_stablecoin_payment_intents
              SET state = $4,
                  settled_at_ms = COALESCE(settled_at_ms, $5),
                  reorg_risk_window_ends_at_ms = COALESCE(reorg_risk_window_ends_at_ms, $6)
            WHERE namespace = $1 AND org_id = $2 AND id = $3
            RETURNING *`,
          [
            namespace,
            ctx.orgId,
            paymentIntentId,
            decision.targetState,
            settledAtMs,
            reorgRiskWindowEndsAtMs,
          ],
        );
        if (!updated) return null;

        await appendPaymentStateTransition(q, {
          namespace,
          orgId: ctx.orgId,
          paymentId: paymentIntentId,
          fromState: current.state,
          toState: decision.targetState,
          changedAtMs: nowMs(now),
          actorType: 'SYSTEM',
          sourceEventId: request.sourceEventId || null,
          reason: decision.reason,
        });

        if (SETTLEMENT_OUTCOME_STATES.has(decision.targetState)) {
          await q.query(
            `UPDATE console_invoices
                SET amount_paid_minor = amount_paid_minor + $4,
                    status = CASE
                      WHEN amount_paid_minor + $4 >= amount_due_minor THEN 'PAID'
                      ELSE status
                    END
              WHERE namespace = $1 AND org_id = $2 AND id = $3`,
            [namespace, ctx.orgId, current.invoiceId, request.observedAmountMinor],
          );
        }

        return parseStablecoinIntentRow(updated, nowMs(now));
      });
    },
  };
}

export async function runPostgresConsoleBillingMonthlyFinalization(
  options: PostgresConsoleBillingMonthlyFinalizationOptions,
): Promise<PostgresConsoleBillingMonthlyFinalizationResult> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl)
    throw new Error('Missing POSTGRES_URL for Postgres console billing monthly finalization');
  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  const periodMonthUtc = options.periodMonthUtc
    ? parseMonthUtcOrThrow(options.periodMonthUtc)
    : previousMonthUtc(nowFn());
  const orgIds = Array.from(
    new Set(
      (Array.isArray(options.orgIds) ? options.orgIds : [])
        .map((orgId) => String(orgId || '').trim())
        .filter(Boolean),
    ),
  );
  if (orgIds.length === 0) {
    throw new Error('Billing monthly finalization requires at least one orgId');
  }

  if (options.ensureSchema !== false) {
    await ensureConsoleBillingPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const service = await createPostgresConsoleBillingService({
    postgresUrl,
    namespace,
    logger,
    ensureSchema: false,
    now: nowFn,
  });

  let generatedCount = 0;
  let skippedCount = 0;
  const failures: PostgresConsoleBillingMonthlyFinalizationResult['failures'] = [];

  for (const orgId of orgIds) {
    try {
      const out = await service.generateMonthlyInvoice(
        {
          orgId,
          actorUserId: 'system-billing-finalizer',
          roles: ['ops'],
        },
        {
          periodMonthUtc,
        },
      );
      if (out.generated) {
        generatedCount += 1;
      } else {
        skippedCount += 1;
      }
    } catch (error: unknown) {
      const code = error instanceof ConsoleBillingError ? error.code : 'internal';
      const message = error instanceof Error ? error.message : String(error);
      failures.push({ orgId, code, message });
      logger.error('[console-billing][postgres][monthly-finalization] failed', {
        namespace,
        periodMonthUtc,
        orgId,
        code,
        message,
      });
    }
  }

  return {
    namespace,
    periodMonthUtc,
    orgCount: orgIds.length,
    generatedCount,
    skippedCount,
    failures,
  };
}
