import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import { formatD1ExecStatement } from '../../storage/d1Sql';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../storage/tenantRoute';
import {
  normalizeManualAdjustmentRequest,
  requireBillingAdjustmentRole,
  requireLargeManualAdminDebitEscalationRole,
} from './adjustments';
import { resolveCreditPackAmountMinorOrThrow } from './creditPacks';
import { ConsoleBillingError } from './errors';
import {
  resolveBillingProviderAdapters,
  type BillingProviderAdapters,
} from './providers';
import { resolveBillingLiveEnvironmentState } from './readiness';
import type { ConsoleBillingContext, ConsoleBillingService } from './service';
import type {
  BillingAccountActivityRequest,
  BillingAccountActivityResult,
  BillingCreditPackId,
  BillingCreditPurchase,
  BillingCreditPurchaseStatus,
  BillingDocumentType,
  BillingInvoice,
  BillingInvoiceLineItemType,
  InvoiceStatus,
  BillingInvoiceActivity,
  BillingInvoiceActivityEntry,
  BillingInvoiceLineItem,
  BillingInvoiceListRequest,
  BillingInvoiceListResult,
  BillingInvoiceListSummary,
  BillingLedgerEntry,
  BillingManualAdjustmentRequest,
  BillingManualAdjustmentResult,
  BillingMonthlyActiveWallets,
  BillingOverview,
  BillingSponsoredExecutionDebitEntry,
  BillingSponsoredExecutionDebitRequest,
  BillingSponsoredExecutionDebitResult,
  BillingUsageAction,
  BillingUsageEventRequest,
  BillingUsageEventResult,
  GenerateMonthlyInvoiceRequest,
  GenerateMonthlyInvoiceResult,
  StripeCheckoutSession,
  StripeCheckoutSessionReconcileRequest,
  StripeCheckoutSessionReconcileResult,
  StripeCheckoutSessionRequest,
  StripeWebhookEventRequest,
  StripeWebhookEventResult,
} from './types';

type D1Row = Record<string, unknown>;
type BillingLedgerPostingDirection = 'DEBIT' | 'CREDIT';

const MAW_USAGE_DEBIT_MINOR = 300;
const DEFAULT_LOW_BALANCE_THRESHOLD_MINOR = 2000;
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;
const DEFAULT_ACCOUNT_ACTIVITY_LIMIT = 25;
const MAX_ACCOUNT_ACTIVITY_LIMIT = 100;
const BILLABLE_USAGE_ACTIONS = new Set<BillingUsageAction>([
  'transfer',
  'swap',
  'approve',
  'contract_call',
]);

export const CONSOLE_BILLING_D1_RUNTIME = Symbol('consoleBillingD1Runtime');

export interface ConsoleBillingD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleBillingD1Service = ConsoleBillingService & {
  [CONSOLE_BILLING_D1_RUNTIME]: ConsoleBillingD1Runtime;
};

export interface D1ConsoleBillingSchemaOptions {
  database: D1DatabaseLike;
}

export interface D1ConsoleBillingServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
}

export interface D1ConsoleBillingState {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

interface BillingAccountRow {
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
}

interface LedgerEntryInsertInput {
  namespace: string;
  orgId: string;
  entryId: string;
  type: BillingLedgerEntry['type'];
  amountMinor: number;
  description: string;
  monthUtc: string | null;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
  actorType: BillingLedgerEntry['actorType'];
  actorUserId: string | null;
  reasonCode: string | null;
  note: string | null;
  idempotencyKey: string | null;
  createdAtMs: number;
}

export const CONSOLE_BILLING_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS console_billing_accounts (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      credit_balance_minor INTEGER NOT NULL DEFAULT 0,
      low_balance_threshold_minor INTEGER NOT NULL DEFAULT 2000,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id),
      CHECK (low_balance_threshold_minor >= 0)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS console_billing_ledger_entries (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      entry_type TEXT NOT NULL,
      amount_minor INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      description TEXT NOT NULL,
      month_utc TEXT,
      related_invoice_id TEXT,
      related_purchase_id TEXT,
      source_event_id TEXT,
      actor_type TEXT NOT NULL,
      actor_user_id TEXT,
      reason_code TEXT,
      note TEXT,
      idempotency_key TEXT,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (entry_type IN ('CREDIT_PURCHASE', 'USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL')),
      CHECK (currency = 'USD'),
      CHECK (actor_type IN ('USER', 'SYSTEM', 'PROVIDER'))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_ledger_entries_idempotency_uidx
      ON console_billing_ledger_entries (namespace, org_id, idempotency_key)
      WHERE idempotency_key IS NOT NULL
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_ledger_entries_type_source_uidx
      ON console_billing_ledger_entries (namespace, org_id, entry_type, source_event_id)
      WHERE source_event_id IS NOT NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_created_idx
      ON console_billing_ledger_entries (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_month_idx
      ON console_billing_ledger_entries (namespace, org_id, month_utc, entry_type)
  `,
  `
    CREATE TABLE IF NOT EXISTS console_billing_ledger_postings (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      ledger_entry_id TEXT NOT NULL,
      account_code TEXT NOT NULL,
      direction TEXT NOT NULL,
      amount_minor INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      FOREIGN KEY (namespace, org_id, ledger_entry_id)
        REFERENCES console_billing_ledger_entries(namespace, org_id, id)
        ON DELETE CASCADE,
      CHECK (direction IN ('DEBIT', 'CREDIT')),
      CHECK (amount_minor >= 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_ledger_postings_entry_idx
      ON console_billing_ledger_postings (namespace, org_id, ledger_entry_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS console_billing_monthly_active_wallets (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      month_utc TEXT NOT NULL,
      wallet_id TEXT NOT NULL,
      source_event_id TEXT,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, month_utc, wallet_id)
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_monthly_active_wallets_source_uidx
      ON console_billing_monthly_active_wallets (namespace, org_id, source_event_id)
      WHERE source_event_id IS NOT NULL
  `,
  `
    CREATE TABLE IF NOT EXISTS console_billing_credit_purchases (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      credit_pack_id TEXT NOT NULL,
      status TEXT NOT NULL,
      amount_minor INTEGER NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      provider TEXT NOT NULL,
      provider_checkout_session_ref TEXT NOT NULL,
      provider_customer_ref TEXT,
      related_invoice_id TEXT,
      settled_at_ms INTEGER,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (status IN ('PENDING', 'SETTLED', 'CANCELED')),
      CHECK (amount_minor > 0),
      CHECK (currency = 'USD'),
      CHECK (provider = 'stripe')
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_credit_purchases_checkout_uidx
      ON console_billing_credit_purchases (namespace, org_id, provider_checkout_session_ref)
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_credit_purchases_namespace_checkout_idx
      ON console_billing_credit_purchases (namespace, provider_checkout_session_ref)
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_credit_purchases_namespace_customer_idx
      ON console_billing_credit_purchases (namespace, provider_customer_ref)
      WHERE provider_customer_ref IS NOT NULL
  `,
  `
    CREATE TABLE IF NOT EXISTS console_invoices (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      document_type TEXT NOT NULL,
      status TEXT NOT NULL,
      currency TEXT NOT NULL DEFAULT 'USD',
      amount_due_minor INTEGER NOT NULL,
      amount_paid_minor INTEGER NOT NULL,
      period_month_utc TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      due_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (document_type IN ('PURCHASE_RECEIPT', 'USAGE_STATEMENT')),
      CHECK (status IN ('OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE')),
      CHECK (currency = 'USD'),
      CHECK (amount_due_minor >= 0),
      CHECK (amount_paid_minor >= 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_invoices_org_created_idx
      ON console_invoices (namespace, org_id, created_at_ms DESC, id DESC)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_invoices_org_statement_month_uidx
      ON console_invoices (namespace, org_id, document_type, period_month_utc)
      WHERE document_type = 'USAGE_STATEMENT'
  `,
  `
    CREATE TABLE IF NOT EXISTS console_invoice_line_items (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      invoice_id TEXT NOT NULL,
      period_month_utc TEXT NOT NULL,
      item_type TEXT NOT NULL,
      description TEXT NOT NULL,
      quantity INTEGER NOT NULL,
      unit_amount_minor INTEGER NOT NULL,
      amount_minor INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      FOREIGN KEY (namespace, org_id, invoice_id)
        REFERENCES console_invoices(namespace, org_id, id)
        ON DELETE CASCADE,
      CHECK (item_type IN ('CREDIT_TOP_UP', 'MAW_USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT')),
      CHECK (quantity > 0),
      CHECK (unit_amount_minor >= 0),
      CHECK (amount_minor >= 0)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_invoice_line_items_invoice_idx
      ON console_invoice_line_items (namespace, org_id, invoice_id)
  `,
  `
    CREATE TABLE IF NOT EXISTS console_stripe_webhook_events (
      namespace TEXT NOT NULL,
      event_id TEXT NOT NULL,
      provider_ref TEXT NOT NULL,
      org_id TEXT NOT NULL,
      processed_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, event_id)
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_stripe_webhook_events_org_idx
      ON console_stripe_webhook_events (namespace, org_id, processed_at_ms DESC)
  `,
  `
    CREATE TRIGGER IF NOT EXISTS console_billing_ledger_entries_account_apply
    AFTER INSERT ON console_billing_ledger_entries
    BEGIN
      INSERT INTO console_billing_accounts
        (namespace, org_id, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
      VALUES
        (NEW.namespace, NEW.org_id, 0, 2000, NEW.created_at_ms, NEW.created_at_ms)
      ON CONFLICT(namespace, org_id) DO NOTHING;

      UPDATE console_billing_accounts
         SET credit_balance_minor = credit_balance_minor + NEW.amount_minor,
             updated_at_ms = NEW.created_at_ms
       WHERE namespace = NEW.namespace
         AND org_id = NEW.org_id;
    END
  `,
  `
    CREATE TRIGGER IF NOT EXISTS console_billing_ledger_entries_sponsored_postings
    AFTER INSERT ON console_billing_ledger_entries
    WHEN NEW.entry_type = 'SPONSORED_EXECUTION_DEBIT' AND ABS(NEW.amount_minor) > 0
    BEGIN
      INSERT INTO console_billing_ledger_postings
        (namespace, org_id, id, ledger_entry_id, account_code, direction, amount_minor, created_at_ms)
      VALUES
        (NEW.namespace, NEW.org_id, NEW.id || ':debit_prepaid_liability', NEW.id, 'org_prepaid_liability', 'DEBIT', ABS(NEW.amount_minor), NEW.created_at_ms),
        (NEW.namespace, NEW.org_id, NEW.id || ':credit_sponsored_revenue', NEW.id, 'revenue_sponsored_execution', 'CREDIT', ABS(NEW.amount_minor), NEW.created_at_ms);
    END
  `,
] as const);

export async function ensureConsoleBillingD1Schema(
  options: D1ConsoleBillingSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_BILLING_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleBillingD1Runtime(
  service: ConsoleBillingService | null | undefined,
): ConsoleBillingD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (service as Partial<ConsoleBillingD1Service>)[CONSOLE_BILLING_D1_RUNTIME] || null;
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNumber(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function normalizeOptionalString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function normalizeRequiredString(value: unknown, field: string): string {
  const normalized = String(value || '').trim();
  if (!normalized) {
    throw new ConsoleBillingError('invalid_body', 400, `${field} is required`);
  }
  return normalized;
}

function normalizePositiveInteger(value: unknown, field: string): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new ConsoleBillingError('invalid_body', 400, `${field} must be a positive integer`);
  }
  return parsed;
}

function normalizeMonthUtc(input: string): string {
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

function monthUtc(now: Date): string {
  const year = now.getUTCFullYear();
  const month = String(now.getUTCMonth() + 1).padStart(2, '0');
  return `${year}-${month}`;
}

function monthUtcFromMs(ms: number): string {
  return monthUtc(new Date(ms));
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}

function stableHash32(input: string): number {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function makeUsageStatementId(orgId: string, periodMonthUtc: string): string {
  const monthPart = periodMonthUtc.replace('-', '');
  const orgPrefix =
    orgId
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .slice(0, 8) || 'org';
  return `stmt_${monthPart}_${orgPrefix}_${stableHash32(orgId).toString(36)}`;
}

function makeStripeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

function normalizeListLimit(input: number | undefined, fallback: number, max: number): number {
  const parsed = Number(input);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.max(1, Math.min(max, Math.trunc(parsed)));
}

function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

function runChanges(result: D1ResultLike): number {
  const changes = Number(result.meta?.changes);
  return Number.isFinite(changes) ? Math.max(0, Math.trunc(changes)) : 0;
}

function parseLedgerActorType(value: unknown): BillingLedgerEntry['actorType'] {
  const normalized = String(value || 'SYSTEM')
    .trim()
    .toUpperCase();
  switch (normalized) {
    case 'USER':
    case 'PROVIDER':
    case 'SYSTEM':
      return normalized;
    default:
      return 'SYSTEM';
  }
}

function parseLedgerEntry(row: D1Row): BillingLedgerEntry {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    type: String(row.entry_type || 'MANUAL_ADJUSTMENT') as BillingLedgerEntry['type'],
    amountMinor: toNumber(row.amount_minor),
    currency: 'USD',
    description: String(row.description || ''),
    monthUtc: normalizeOptionalString(row.month_utc),
    relatedInvoiceId: normalizeOptionalString(row.related_invoice_id),
    relatedPurchaseId: normalizeOptionalString(row.related_purchase_id),
    sourceEventId: normalizeOptionalString(row.source_event_id),
    actorType: parseLedgerActorType(row.actor_type),
    actorUserId: normalizeOptionalString(row.actor_user_id),
    reasonCode: normalizeOptionalString(row.reason_code),
    note: normalizeOptionalString(row.note),
    idempotencyKey: normalizeOptionalString(row.idempotency_key),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

function parseBillingAccount(row: D1Row | null): BillingAccountRow {
  return {
    creditBalanceMinor: toNumber(row?.credit_balance_minor),
    lowBalanceThresholdMinor:
      toNumber(row?.low_balance_threshold_minor) || DEFAULT_LOW_BALANCE_THRESHOLD_MINOR,
  };
}

function parseCreditPackId(value: unknown): BillingCreditPackId {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'usd_10':
    case 'usd_25':
    case 'usd_50':
    case 'usd_custom':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing credit pack id row: ${normalized || 'empty'}`,
      );
  }
}

function parseCreditPurchaseStatus(value: unknown): BillingCreditPurchaseStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'PENDING':
    case 'SETTLED':
    case 'CANCELED':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing credit purchase status row: ${normalized || 'empty'}`,
      );
  }
}

function parseInvoiceDocumentType(value: unknown): BillingDocumentType {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'PURCHASE_RECEIPT':
    case 'USAGE_STATEMENT':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing invoice document type row: ${normalized || 'empty'}`,
      );
  }
}

function parseInvoiceStatus(value: unknown): InvoiceStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'OPEN':
    case 'PAID':
    case 'VOID':
    case 'UNCOLLECTIBLE':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing invoice status row: ${normalized || 'empty'}`,
      );
  }
}

function parseInvoiceLineItemType(value: unknown): BillingInvoiceLineItemType {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'CREDIT_TOP_UP':
    case 'MAW_USAGE_DEBIT':
    case 'SPONSORED_EXECUTION_DEBIT':
    case 'MANUAL_ADJUSTMENT':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing invoice line item type row: ${normalized || 'empty'}`,
      );
  }
}

function parseNullableIso(ms: unknown): string | null {
  if (ms == null) return null;
  const parsed = toNumber(ms);
  return parsed > 0 ? toIso(parsed) : null;
}

function parseCreditPurchase(row: D1Row): BillingCreditPurchase {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    creditPackId: parseCreditPackId(row.credit_pack_id),
    status: parseCreditPurchaseStatus(row.status),
    amountMinor: toNumber(row.amount_minor),
    currency: 'USD',
    provider: 'stripe',
    providerCheckoutSessionRef: String(row.provider_checkout_session_ref || '').trim(),
    providerCustomerRef: normalizeOptionalString(row.provider_customer_ref),
    relatedInvoiceId: normalizeOptionalString(row.related_invoice_id),
    settledAt: parseNullableIso(row.settled_at_ms),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseInvoice(row: D1Row): BillingInvoice {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    documentType: parseInvoiceDocumentType(row.document_type),
    status: parseInvoiceStatus(row.status),
    currency: 'USD',
    amountDueMinor: toNumber(row.amount_due_minor),
    amountPaidMinor: toNumber(row.amount_paid_minor),
    periodMonthUtc: String(row.period_month_utc || '').trim(),
    createdAt: toIso(toNumber(row.created_at_ms)),
    dueAt: parseNullableIso(row.due_at_ms),
  };
}

function parseInvoiceLineItem(row: D1Row): BillingInvoiceLineItem {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    invoiceId: String(row.invoice_id || '').trim(),
    periodMonthUtc: String(row.period_month_utc || '').trim(),
    itemType: parseInvoiceLineItemType(row.item_type),
    description: String(row.description || ''),
    quantity: toNumber(row.quantity),
    unitAmountMinor: toNumber(row.unit_amount_minor),
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

function makePurchaseReceiptInvoiceId(purchaseId: string): string {
  return `receipt_${purchaseId}`;
}

function statementInvoiceFromLedger(input: {
  orgId: string;
  monthUtcValue: string;
  entries: readonly BillingLedgerEntry[];
  createdAtMs: number;
}): BillingInvoice {
  const amountDueMinor = Math.abs(
    input.entries
      .filter((entry) => entry.monthUtc === input.monthUtcValue && entry.amountMinor < 0)
      .reduce((total, entry) => total + entry.amountMinor, 0),
  );
  return {
    id: makeUsageStatementId(input.orgId, input.monthUtcValue),
    orgId: input.orgId,
    documentType: 'USAGE_STATEMENT',
    status: 'OPEN',
    currency: 'USD',
    amountDueMinor,
    amountPaidMinor: 0,
    periodMonthUtc: input.monthUtcValue,
    createdAt: toIso(input.createdAtMs),
    dueAt: null,
  };
}

function invoiceLineItemsForStatement(input: {
  invoice: BillingInvoice;
  entries: readonly BillingLedgerEntry[];
}): BillingInvoiceLineItem[] {
  const sponsoredMinor = Math.abs(
    input.entries
      .filter(
        (entry) =>
          entry.monthUtc === input.invoice.periodMonthUtc &&
          entry.type === 'SPONSORED_EXECUTION_DEBIT',
      )
      .reduce((total, entry) => total + entry.amountMinor, 0),
  );
  const usageMinor = Math.abs(
    input.entries
      .filter((entry) => entry.monthUtc === input.invoice.periodMonthUtc && entry.type === 'USAGE_DEBIT')
      .reduce((total, entry) => total + entry.amountMinor, 0),
  );
  const items: BillingInvoiceLineItem[] = [];
  if (usageMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_maw_usage_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'MAW_USAGE_DEBIT',
      description: `Monthly Active Wallets (${input.invoice.periodMonthUtc})`,
      quantity: Math.max(1, Math.floor(usageMinor / MAW_USAGE_DEBIT_MINOR)),
      unitAmountMinor: MAW_USAGE_DEBIT_MINOR,
      amountMinor: usageMinor,
      createdAt: input.invoice.createdAt,
    });
  }
  if (sponsoredMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_sponsored_execution_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'SPONSORED_EXECUTION_DEBIT',
      description: `Sponsored execution spend (${input.invoice.periodMonthUtc})`,
      quantity: 1,
      unitAmountMinor: sponsoredMinor,
      amountMinor: sponsoredMinor,
      createdAt: input.invoice.createdAt,
    });
  }
  return items;
}

function activityEntryForLedger(entry: BillingLedgerEntry): BillingInvoiceActivityEntry {
  return {
    id: `activity_${entry.id}`,
    type: 'LEDGER',
    invoiceId: entry.relatedInvoiceId || '',
    fromState: null,
    toState: entry.type,
    occurredAt: entry.createdAt,
    actorType: entry.actorType,
    actorUserId: entry.actorUserId,
    reason: entry.reasonCode,
    sourceEventId: entry.sourceEventId,
    summary: entry.description,
    visibility: 'CUSTOMER',
  };
}

function buildInvoiceListSummary(invoices: readonly BillingInvoice[]): BillingInvoiceListSummary {
  const openCount = invoices.filter((invoice) => invoice.status === 'OPEN').length;
  const paidCount = invoices.filter((invoice) => invoice.status === 'PAID').length;
  return {
    totalCount: invoices.length,
    openCount,
    overdueCount: 0,
    paidCount,
    outstandingAmountMinor: invoices.reduce(
      (total, invoice) => total + Math.max(0, invoice.amountDueMinor - invoice.amountPaidMinor),
      0,
    ),
    latestPeriodMonthUtc: invoices[0]?.periodMonthUtc || null,
    receiptCount: invoices.filter((invoice) => invoice.documentType === 'PURCHASE_RECEIPT').length,
    statementCount: invoices.filter((invoice) => invoice.documentType === 'USAGE_STATEMENT').length,
  };
}

async function queryOne(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<D1Row | null> {
  return await database.prepare(text).bind(...values).first<D1Row>();
}

async function queryAll(
  database: D1DatabaseLike,
  text: string,
  values: readonly unknown[],
): Promise<readonly D1Row[]> {
  const result = await database.prepare(text).bind(...values).all<D1Row>();
  return result.results || [];
}

async function ensureBillingAccount(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  createdAtMs: number;
}): Promise<BillingAccountRow> {
  await input.database
    .prepare(
      `INSERT INTO console_billing_accounts
        (namespace, org_id, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, 0, ?, ?, ?)
       ON CONFLICT(namespace, org_id) DO NOTHING`,
    )
    .bind(
      input.namespace,
      input.orgId,
      DEFAULT_LOW_BALANCE_THRESHOLD_MINOR,
      input.createdAtMs,
      input.createdAtMs,
    )
    .run();
  return await loadBillingAccount(input);
}

async function loadBillingAccount(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  createdAtMs: number;
}): Promise<BillingAccountRow> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_billing_accounts
      WHERE namespace = ?
        AND org_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId],
  );
  if (row) return parseBillingAccount(row);
  return await ensureBillingAccount(input);
}

async function loadLedgerEntryBySourceEventAndType(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  sourceEventId: string;
  type: BillingLedgerEntry['type'];
}): Promise<BillingLedgerEntry | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND entry_type = ?
        AND source_event_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.type, input.sourceEventId],
  );
  return row ? parseLedgerEntry(row) : null;
}

async function loadLedgerEntryById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  ledgerEntryId: string;
}): Promise<BillingLedgerEntry | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.ledgerEntryId],
  );
  return row ? parseLedgerEntry(row) : null;
}

async function listLedgerEntries(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  limit: number;
  monthUtcValue?: string;
  type?: BillingLedgerEntry['type'];
}): Promise<BillingLedgerEntry[]> {
  const clauses = ['namespace = ?', 'org_id = ?'];
  const values: unknown[] = [input.namespace, input.orgId];
  if (input.monthUtcValue) {
    clauses.push('month_utc = ?');
    values.push(input.monthUtcValue);
  }
  if (input.type) {
    clauses.push('entry_type = ?');
    values.push(input.type);
  }
  values.push(input.limit);
  const rows = await queryAll(
    input.database,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE ${clauses.join(' AND ')}
      ORDER BY created_at_ms DESC, id DESC
      LIMIT ?`,
    values,
  );
  return rows.map(parseLedgerEntry);
}

async function listAllStatementLedgerEntries(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<BillingLedgerEntry[]> {
  const rows = await queryAll(
    input.database,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc IS NOT NULL
      ORDER BY month_utc DESC, created_at_ms DESC, id DESC`,
    [input.namespace, input.orgId],
  );
  return rows.map(parseLedgerEntry);
}

async function countMonthlyActiveWallets(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  monthUtcValue: string;
}): Promise<number> {
  const row = await queryOne(
    input.database,
    `SELECT COUNT(*) AS wallet_count
       FROM console_billing_monthly_active_wallets
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc = ?`,
    [input.namespace, input.orgId, input.monthUtcValue],
  );
  return Math.max(0, toNumber(row?.wallet_count));
}

async function listPersistedInvoices(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<BillingInvoice[]> {
  const rows = await queryAll(
    input.database,
    `SELECT *
       FROM console_invoices
      WHERE namespace = ?
        AND org_id = ?
      ORDER BY created_at_ms DESC, id DESC`,
    [input.namespace, input.orgId],
  );
  return rows.map(parseInvoice);
}

async function loadPersistedInvoiceById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  invoiceId: string;
}): Promise<BillingInvoice | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_invoices
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.invoiceId],
  );
  return row ? parseInvoice(row) : null;
}

async function listPersistedInvoiceLineItems(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  invoiceId: string;
}): Promise<BillingInvoiceLineItem[]> {
  const rows = await queryAll(
    input.database,
    `SELECT *
       FROM console_invoice_line_items
      WHERE namespace = ?
        AND org_id = ?
        AND invoice_id = ?
      ORDER BY item_type ASC, id ASC`,
    [input.namespace, input.orgId, input.invoiceId],
  );
  return rows.map(parseInvoiceLineItem);
}

async function loadCreditPurchaseByCheckoutSession(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  checkoutSessionId: string;
}): Promise<BillingCreditPurchase | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_billing_credit_purchases
      WHERE namespace = ?
        AND org_id = ?
        AND provider_checkout_session_ref = ?
      ORDER BY created_at_ms DESC, id DESC
      LIMIT 1`,
    [input.namespace, input.orgId, input.checkoutSessionId],
  );
  return row ? parseCreditPurchase(row) : null;
}

async function loadCreditPurchaseById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  purchaseId: string;
}): Promise<BillingCreditPurchase | null> {
  const row = await queryOne(
    input.database,
    `SELECT *
       FROM console_billing_credit_purchases
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.purchaseId],
  );
  return row ? parseCreditPurchase(row) : null;
}

async function findCreditPurchaseForStripeEvent(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string | null;
  checkoutSessionRef: string;
  providerCustomerRef: string;
}): Promise<{ orgId: string; purchase: BillingCreditPurchase | null } | null> {
  if (input.orgId) {
    const clauses = ['namespace = ?', 'org_id = ?'];
    const values: unknown[] = [input.namespace, input.orgId];
    if (input.checkoutSessionRef || input.providerCustomerRef) {
      clauses.push(
        `(provider_checkout_session_ref = ? OR (? <> '' AND provider_customer_ref = ?))`,
      );
      values.push(input.checkoutSessionRef, input.providerCustomerRef, input.providerCustomerRef);
    } else {
      return { orgId: input.orgId, purchase: null };
    }
    const rows = await queryAll(
      input.database,
      `SELECT *
         FROM console_billing_credit_purchases
        WHERE ${clauses.join(' AND ')}
        ORDER BY created_at_ms DESC, id DESC
        LIMIT 1`,
      values,
    );
    return {
      orgId: input.orgId,
      purchase: rows[0] ? parseCreditPurchase(rows[0]) : null,
    };
  }

  if (!input.checkoutSessionRef && !input.providerCustomerRef) return null;
  const rows = await queryAll(
    input.database,
    `SELECT *
       FROM console_billing_credit_purchases
      WHERE namespace = ?
        AND (
          provider_checkout_session_ref = ?
          OR (? <> '' AND provider_customer_ref = ?)
        )
      ORDER BY created_at_ms DESC, id DESC
      LIMIT 2`,
    [
      input.namespace,
      input.checkoutSessionRef,
      input.providerCustomerRef,
      input.providerCustomerRef,
    ],
  );
  if (rows.length === 0) return null;
  const first = parseCreditPurchase(rows[0]);
  const second = rows[1] ? parseCreditPurchase(rows[1]) : null;
  if (second && second.orgId !== first.orgId) {
    throw new ConsoleBillingError(
      'duplicate_provider_reference',
      409,
      'Stripe webhook event maps to multiple organizations',
    );
  }
  return { orgId: first.orgId, purchase: first };
}

function buildPurchaseReceiptStatements(input: {
  state: D1ConsoleBillingState;
  purchase: BillingCreditPurchase;
  createdAtMs: number;
}): readonly D1PreparedStatementLike[] {
  const invoiceId = makePurchaseReceiptInvoiceId(input.purchase.id);
  const periodMonthUtc = monthUtcFromMs(input.createdAtMs);
  return [
    input.state.database
      .prepare(
        `INSERT INTO console_invoices
          (namespace, org_id, id, document_type, status, currency, amount_due_minor, amount_paid_minor, period_month_utc, created_at_ms, due_at_ms)
         VALUES
          (?, ?, ?, 'PURCHASE_RECEIPT', 'PAID', 'USD', ?, ?, ?, ?, NULL)
         ON CONFLICT(namespace, org_id, id) DO UPDATE
           SET amount_due_minor = excluded.amount_due_minor,
               amount_paid_minor = excluded.amount_paid_minor,
               status = 'PAID'`,
      )
      .bind(
        input.state.namespace,
        input.purchase.orgId,
        invoiceId,
        input.purchase.amountMinor,
        input.purchase.amountMinor,
        periodMonthUtc,
        input.createdAtMs,
      ),
    input.state.database
      .prepare(
        `DELETE FROM console_invoice_line_items
          WHERE namespace = ?
            AND org_id = ?
            AND invoice_id = ?`,
      )
      .bind(input.state.namespace, input.purchase.orgId, invoiceId),
    input.state.database
      .prepare(
        `INSERT INTO console_invoice_line_items
          (namespace, org_id, id, invoice_id, period_month_utc, item_type, description, quantity, unit_amount_minor, amount_minor, created_at_ms)
         VALUES
          (?, ?, ?, ?, ?, 'CREDIT_TOP_UP', ?, 1, ?, ?, ?)`,
      )
      .bind(
        input.state.namespace,
        input.purchase.orgId,
        `ili_${invoiceId}_credit_top_up`,
        invoiceId,
        periodMonthUtc,
        `Prepaid credit top-up (${input.purchase.creditPackId})`,
        input.purchase.amountMinor,
        input.purchase.amountMinor,
        input.createdAtMs,
      ),
  ];
}

export function createD1BillingLedgerEntryInsertStatement(
  database: D1DatabaseLike,
  input: LedgerEntryInsertInput,
): D1PreparedStatementLike {
  return database
    .prepare(
      `INSERT INTO console_billing_ledger_entries
        (
          namespace,
          org_id,
          id,
          entry_type,
          amount_minor,
          currency,
          description,
          month_utc,
          related_invoice_id,
          related_purchase_id,
          source_event_id,
          actor_type,
          actor_user_id,
          reason_code,
          note,
          idempotency_key,
          created_at_ms
        )
       VALUES
        (?, ?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.orgId,
      input.entryId,
      input.type,
      input.amountMinor,
      input.description,
      input.monthUtc,
      input.relatedInvoiceId,
      input.relatedPurchaseId,
      input.sourceEventId,
      input.actorType,
      input.actorUserId,
      input.reasonCode,
      input.note,
      input.idempotencyKey,
      input.createdAtMs,
    );
}

function buildSponsoredExecutionDebitInsert(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingSponsoredExecutionDebitRequest;
  entryId: string;
  occurredAtMs: number;
}): D1PreparedStatementLike {
  const eventMonthUtc = monthUtcFromMs(input.occurredAtMs);
  const sourceEventId = normalizeRequiredString(input.request.sourceEventId, 'sourceEventId');
  return createD1BillingLedgerEntryInsertStatement(input.state.database, {
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    entryId: input.entryId,
    type: 'SPONSORED_EXECUTION_DEBIT',
    amountMinor: -input.request.amountMinor,
    description: `Sponsored execution debit for ${input.request.walletId}`,
    monthUtc: eventMonthUtc,
    relatedInvoiceId: makeUsageStatementId(input.ctx.orgId, eventMonthUtc),
    relatedPurchaseId: null,
    sourceEventId,
    actorType: 'SYSTEM',
    actorUserId: input.ctx.actorUserId,
    reasonCode: 'sponsored_execution_debit',
    note:
      normalizeOptionalString(input.request.note) ||
      [
        input.request.txOrExecutionRef ? `Ref ${input.request.txOrExecutionRef}` : '',
        input.request.pricingVersion ? `Pricing ${input.request.pricingVersion}` : '',
      ]
        .filter(Boolean)
        .join(' | ') ||
      `Sponsored execution debit recorded for ${input.request.walletId}`,
    idempotencyKey: `sponsored_execution_debit:${sourceEventId}`,
    createdAtMs: input.occurredAtMs,
  });
}

function normalizeSponsoredDebit(input: {
  now: Date;
  request: BillingSponsoredExecutionDebitRequest;
}): { sourceEventId: string; amountMinor: number; occurredAtMs: number } {
  const sourceEventId = normalizeRequiredString(input.request.sourceEventId, 'sourceEventId');
  const amountMinor = normalizePositiveInteger(input.request.amountMinor, 'amountMinor');
  const occurredAtMs = input.request.occurredAt
    ? Date.parse(input.request.occurredAt)
    : nowMs(input.now);
  if (!Number.isFinite(occurredAtMs)) {
    throw new ConsoleBillingError(
      'invalid_sponsored_execution_debit',
      400,
      'Invalid occurredAt value',
    );
  }
  return { sourceEventId, amountMinor, occurredAtMs };
}

export async function recordSponsoredExecutionDebitD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingSponsoredExecutionDebitRequest;
  entryId?: string;
}): Promise<{
  result: BillingSponsoredExecutionDebitResult;
  ledgerEntry: BillingLedgerEntry | null;
}> {
  const currentNow = input.state.now();
  const normalized = normalizeSponsoredDebit({ now: currentNow, request: input.request });
  const existing = await loadLedgerEntryBySourceEventAndType({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    sourceEventId: normalized.sourceEventId,
    type: 'SPONSORED_EXECUTION_DEBIT',
  });
  const eventMonthUtc = monthUtcFromMs(normalized.occurredAtMs);
  if (existing) {
    const account = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      createdAtMs: nowMs(currentNow),
    });
    return {
      result: {
        accepted: false,
        debitAppliedMinor: 0,
        ledgerEntryId: existing.id,
        creditBalanceMinor: account.creditBalanceMinor,
        monthUtc: eventMonthUtc,
        statementId: makeUsageStatementId(input.ctx.orgId, eventMonthUtc),
      },
      ledgerEntry: existing,
    };
  }

  const entryId = input.entryId || makeId('ble', new Date(normalized.occurredAtMs));
  try {
    await buildSponsoredExecutionDebitInsert({
      state: input.state,
      ctx: input.ctx,
      request: { ...input.request, amountMinor: normalized.amountMinor },
      entryId,
      occurredAtMs: normalized.occurredAtMs,
    }).run();
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
  }
  const ledgerEntry =
    (await loadLedgerEntryById({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      ledgerEntryId: entryId,
    })) ||
    (await loadLedgerEntryBySourceEventAndType({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      sourceEventId: normalized.sourceEventId,
      type: 'SPONSORED_EXECUTION_DEBIT',
    }));
  const account = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: nowMs(currentNow),
  });
  return {
    result: {
      accepted: ledgerEntry?.id === entryId,
      debitAppliedMinor: ledgerEntry?.id === entryId ? normalized.amountMinor : 0,
      ledgerEntryId: ledgerEntry?.id || null,
      creditBalanceMinor: account.creditBalanceMinor,
      monthUtc: eventMonthUtc,
      statementId: makeUsageStatementId(input.ctx.orgId, eventMonthUtc),
    },
    ledgerEntry,
  };
}

export function createSponsoredExecutionDebitD1InsertStatement(input: {
  runtime: ConsoleBillingD1Runtime;
  ctx: ConsoleBillingContext;
  request: BillingSponsoredExecutionDebitRequest;
  entryId: string;
  occurredAtMs: number;
}): D1PreparedStatementLike {
  return buildSponsoredExecutionDebitInsert({
    state: {
      database: input.runtime.database,
      namespace: input.runtime.namespace,
      now: input.runtime.now,
    },
    ctx: input.ctx,
    request: input.request,
    entryId: input.entryId,
    occurredAtMs: input.occurredAtMs,
  });
}

async function syncPurchaseReceiptD1(input: {
  state: D1ConsoleBillingState;
  purchase: BillingCreditPurchase;
  createdAtMs: number;
}): Promise<BillingInvoice> {
  await input.state.database.batch(
    buildPurchaseReceiptStatements({
      state: input.state,
      purchase: input.purchase,
      createdAtMs: input.createdAtMs,
    }),
  );
  const invoice = await loadPersistedInvoiceById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.purchase.orgId,
    invoiceId: makePurchaseReceiptInvoiceId(input.purchase.id),
  });
  if (!invoice) {
    throw new ConsoleBillingError(
      'invoice_generate_failed',
      500,
      'Failed to create purchase receipt',
    );
  }
  return invoice;
}

async function settleCreditPurchaseD1(input: {
  state: D1ConsoleBillingState;
  orgId: string;
  purchaseId: string;
  settledAtMs: number;
}): Promise<{ purchase: BillingCreditPurchase; invoice: BillingInvoice }> {
  const current = await loadCreditPurchaseById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    purchaseId: input.purchaseId,
  });
  if (!current) {
    throw new ConsoleBillingError(
      'purchase_not_found',
      404,
      `Credit purchase ${input.purchaseId} was not found`,
    );
  }

  const invoiceId = makePurchaseReceiptInvoiceId(current.id);
  if (current.status === 'SETTLED') {
    const receiptCreatedAtMs = current.settledAt ? Date.parse(current.settledAt) : input.settledAtMs;
    const invoice = await syncPurchaseReceiptD1({
      state: input.state,
      purchase: current,
      createdAtMs: Number.isFinite(receiptCreatedAtMs) ? receiptCreatedAtMs : input.settledAtMs,
    });
    if (current.relatedInvoiceId === invoice.id) {
      return { purchase: current, invoice };
    }
    await input.state.database
      .prepare(
        `UPDATE console_billing_credit_purchases
            SET related_invoice_id = ?,
                settled_at_ms = COALESCE(settled_at_ms, ?),
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(
        invoice.id,
        input.settledAtMs,
        input.settledAtMs,
        input.state.namespace,
        input.orgId,
        current.id,
      )
      .run();
    const updated = await loadCreditPurchaseById({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.orgId,
      purchaseId: current.id,
    });
    return { purchase: updated || current, invoice };
  }

  const settledPurchase: BillingCreditPurchase = {
    id: current.id,
    orgId: current.orgId,
    creditPackId: current.creditPackId,
    status: 'SETTLED',
    amountMinor: current.amountMinor,
    currency: 'USD',
    provider: 'stripe',
    providerCheckoutSessionRef: current.providerCheckoutSessionRef,
    providerCustomerRef: current.providerCustomerRef || makeStripeCustomerRef(input.orgId),
    relatedInvoiceId: invoiceId,
    settledAt: toIso(input.settledAtMs),
    createdAt: current.createdAt,
    updatedAt: toIso(input.settledAtMs),
  };
  const statements: D1PreparedStatementLike[] = [
    createD1BillingLedgerEntryInsertStatement(input.state.database, {
      namespace: input.state.namespace,
      orgId: input.orgId,
      entryId: makeId('ble', new Date(input.settledAtMs)),
      type: 'CREDIT_PURCHASE',
      amountMinor: current.amountMinor,
      description: `Credit pack ${current.creditPackId} settled`,
      monthUtc: monthUtcFromMs(input.settledAtMs),
      relatedInvoiceId: invoiceId,
      relatedPurchaseId: current.id,
      sourceEventId: current.providerCheckoutSessionRef,
      actorType: 'PROVIDER',
      actorUserId: null,
      reasonCode: 'stripe_checkout_settled',
      note: `Stripe checkout session ${current.providerCheckoutSessionRef} settled`,
      idempotencyKey: `credit_purchase_settlement:${current.id}`,
      createdAtMs: input.settledAtMs,
    }),
    ...buildPurchaseReceiptStatements({
      state: input.state,
      purchase: settledPurchase,
      createdAtMs: input.settledAtMs,
    }),
    input.state.database
      .prepare(
        `UPDATE console_billing_credit_purchases
            SET status = 'SETTLED',
                provider_customer_ref = COALESCE(provider_customer_ref, ?),
                related_invoice_id = ?,
                settled_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'PENDING'`,
      )
      .bind(
        settledPurchase.providerCustomerRef,
        invoiceId,
        input.settledAtMs,
        input.settledAtMs,
        input.state.namespace,
        input.orgId,
        current.id,
      ),
  ];

  try {
    await input.state.database.batch(statements);
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
  }

  const updated = await loadCreditPurchaseById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    purchaseId: current.id,
  });
  const invoice = await loadPersistedInvoiceById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    invoiceId,
  });
  if (!updated || updated.status !== 'SETTLED' || !invoice) {
    throw new ConsoleBillingError(
      'purchase_settlement_failed',
      500,
      'Failed to settle credit purchase',
    );
  }
  return { purchase: updated, invoice };
}

async function processStripeWebhookEventD1(input: {
  state: D1ConsoleBillingState;
  request: StripeWebhookEventRequest;
}): Promise<StripeWebhookEventResult> {
  const eventType = String(input.request.eventType || 'checkout.session.completed')
    .trim()
    .toLowerCase();
  if (eventType !== 'checkout.session.completed') {
    return { accepted: true, purchase: null, invoice: null, orgId: null };
  }

  const currentNow = input.state.now();
  const eventId = normalizeRequiredString(input.request.eventId, 'eventId');
  const requestedOrgId = normalizeOptionalString(input.request.orgId);
  const checkoutSessionRef = String(
    input.request.checkoutSessionId || input.request.providerRef || '',
  ).trim();
  const providerCustomerRef = normalizeOptionalString(input.request.providerCustomerRef) || '';
  const resolved = await findCreditPurchaseForStripeEvent({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: requestedOrgId,
    checkoutSessionRef,
    providerCustomerRef,
  });
  const currentOrgId = resolved?.orgId || requestedOrgId || null;
  if (!currentOrgId) {
    return { accepted: true, purchase: null, invoice: null, orgId: null };
  }

  const providerRef = checkoutSessionRef || providerCustomerRef || eventType || 'stripe_event';
  const insertResult = await input.state.database
    .prepare(
      `INSERT INTO console_stripe_webhook_events
        (namespace, event_id, provider_ref, org_id, processed_at_ms)
       VALUES
        (?, ?, ?, ?, ?)
       ON CONFLICT(namespace, event_id) DO NOTHING`,
    )
    .bind(input.state.namespace, eventId, providerRef, currentOrgId, nowMs(currentNow))
    .run();
  const existingPurchase = resolved?.purchase || null;
  const existingInvoice = existingPurchase?.relatedInvoiceId
    ? await loadPersistedInvoiceById({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: currentOrgId,
        invoiceId: existingPurchase.relatedInvoiceId,
      })
    : null;
  if (runChanges(insertResult) === 0) {
    return {
      accepted: false,
      purchase: existingPurchase,
      invoice: existingInvoice,
      orgId: currentOrgId,
    };
  }
  if (!existingPurchase) {
    return { accepted: true, purchase: null, invoice: null, orgId: currentOrgId };
  }
  const settled = await settleCreditPurchaseD1({
    state: input.state,
    orgId: currentOrgId,
    purchaseId: existingPurchase.id,
    settledAtMs: nowMs(currentNow),
  });
  return {
    accepted: true,
    purchase: settled.purchase,
    invoice: settled.invoice,
    orgId: currentOrgId,
  };
}

export async function createD1ConsoleBillingService(
  options: D1ConsoleBillingServiceOptions,
): Promise<ConsoleBillingService> {
  if (options.ensureSchema) {
    await ensureConsoleBillingD1Schema({ database: options.database });
  }
  const state: D1ConsoleBillingState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  const runtime: ConsoleBillingD1Runtime = {
    database: state.database,
    namespace: state.namespace,
    now: state.now,
  };
  const providers = resolveBillingProviderAdapters(options.providers);

  const service: ConsoleBillingD1Service = {
    async getOverview(ctx: ConsoleBillingContext): Promise<BillingOverview> {
      const currentNow = state.now();
      const currentMonthUtc = monthUtc(currentNow);
      const account = await loadBillingAccount({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        createdAtMs: nowMs(currentNow),
      });
      const monthlyActiveWallets = await countMonthlyActiveWallets({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: currentMonthUtc,
      });
      const ledger = await listLedgerEntries({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: currentMonthUtc,
        limit: 1000,
      });
      const recentUsageDebitMinor = Math.abs(
        ledger
          .filter((entry) => entry.type === 'USAGE_DEBIT')
          .reduce((total, entry) => total + entry.amountMinor, 0),
      );
      const recentCreditPurchasedMinor = ledger
        .filter((entry) => entry.type === 'CREDIT_PURCHASE')
        .reduce((total, entry) => total + entry.amountMinor, 0);
      return {
        usageMetricVersion: 'maw_v1',
        currentMonthUtc,
        monthlyActiveWallets,
        creditBalanceMinor: account.creditBalanceMinor,
        lowBalanceThresholdMinor: account.lowBalanceThresholdMinor,
        liveEnvironmentState: resolveBillingLiveEnvironmentState({
          creditBalanceMinor: account.creditBalanceMinor,
          lowBalanceThresholdMinor: account.lowBalanceThresholdMinor,
        }),
        recentUsageDebitMinor,
        recentCreditPurchasedMinor,
        documentCount: await countProjectedInvoices(state, ctx.orgId),
      };
    },

    async getSponsoredExecutionDebitsByIds(
      ctx: ConsoleBillingContext,
      ledgerEntryIds: string[],
    ): Promise<BillingSponsoredExecutionDebitEntry[]> {
      const ids = Array.from(
        new Set(ledgerEntryIds.map((entryId) => String(entryId || '').trim()).filter(Boolean)),
      );
      if (ids.length === 0) return [];
      const placeholders = ids.map(() => '?').join(', ');
      const rows = await queryAll(
        state.database,
        `SELECT *
           FROM console_billing_ledger_entries
          WHERE namespace = ?
            AND org_id = ?
            AND entry_type = 'SPONSORED_EXECUTION_DEBIT'
            AND id IN (${placeholders})
          ORDER BY created_at_ms DESC, id DESC`,
        [state.namespace, ctx.orgId, ...ids],
      );
      return rows.map(parseLedgerEntry) as BillingSponsoredExecutionDebitEntry[];
    },

    async listAccountActivity(
      ctx: ConsoleBillingContext,
      request: BillingAccountActivityRequest = {},
    ): Promise<BillingAccountActivityResult> {
      const entries = await listLedgerEntries({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        limit: normalizeListLimit(
          request.limit,
          DEFAULT_ACCOUNT_ACTIVITY_LIMIT,
          MAX_ACCOUNT_ACTIVITY_LIMIT,
        ),
        ...(request.periodMonthUtc
          ? { monthUtcValue: normalizeMonthUtc(request.periodMonthUtc) }
          : {}),
        ...(request.eventType ? { type: request.eventType } : {}),
      });
      return { entries };
    },

    async getMonthlyActiveWallets(
      ctx: ConsoleBillingContext,
      inputMonthUtc?: string,
    ): Promise<BillingMonthlyActiveWallets> {
      const monthUtcValue = inputMonthUtc ? normalizeMonthUtc(inputMonthUtc) : monthUtc(state.now());
      const monthlyActiveWallets = await countMonthlyActiveWallets({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue,
      });
      return {
        usageMetricVersion: 'maw_v1',
        monthUtc: monthUtcValue,
        monthlyActiveWallets,
      };
    },

    async recordUsageEvent(
      ctx: ConsoleBillingContext,
      request: BillingUsageEventRequest,
    ): Promise<BillingUsageEventResult> {
      return await recordUsageEventD1({ state, ctx, request });
    },

    async recordSponsoredExecutionDebit(
      ctx: ConsoleBillingContext,
      request: BillingSponsoredExecutionDebitRequest,
    ): Promise<BillingSponsoredExecutionDebitResult> {
      return (await recordSponsoredExecutionDebitD1({ state, ctx, request })).result;
    },

    async listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]> {
      return await listProjectedInvoices(state, ctx.orgId);
    },

    async listInvoicesPage(
      ctx: ConsoleBillingContext,
      request: BillingInvoiceListRequest = {},
    ): Promise<BillingInvoiceListResult> {
      const invoices = await listProjectedInvoices(state, ctx.orgId);
      const filtered = invoices.filter((invoice) => {
        if (request.status && invoice.status !== request.status) return false;
        if (request.periodMonthUtc && invoice.periodMonthUtc !== request.periodMonthUtc) return false;
        if (request.documentType && invoice.documentType !== request.documentType) return false;
        return true;
      });
      const limit = normalizeListLimit(
        request.limit,
        DEFAULT_INVOICE_LIST_LIMIT,
        MAX_INVOICE_LIST_LIMIT,
      );
      return {
        invoices: filtered.slice(0, limit),
        nextCursor: filtered.length > limit ? filtered[limit - 1]?.id || null : null,
        totalCount: filtered.length,
        summary: buildInvoiceListSummary(filtered),
      };
    },

    async getInvoice(ctx: ConsoleBillingContext, invoiceId: string): Promise<BillingInvoice | null> {
      const invoices = await listProjectedInvoices(state, ctx.orgId);
      return invoices.find((invoice) => invoice.id === invoiceId) || null;
    },

    async getInvoiceActivity(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceActivity | null> {
      const invoice = await this.getInvoice(ctx, invoiceId);
      if (!invoice) return null;
      const entries = await listLedgerEntries({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: invoice.periodMonthUtc,
        limit: 1000,
      });
      return {
        invoice,
        entries: [
          {
            id: `${invoice.id}:issued`,
            type: 'DOCUMENT',
            invoiceId: invoice.id,
            fromState: null,
            toState: invoice.status,
            occurredAt: invoice.createdAt,
            actorType: 'SYSTEM',
            actorUserId: null,
            reason:
              invoice.documentType === 'PURCHASE_RECEIPT'
                ? 'purchase_receipt_created'
                : 'usage_statement_created',
            sourceEventId: null,
            summary:
              invoice.documentType === 'PURCHASE_RECEIPT'
                ? `Purchase receipt ${invoice.id} recorded for ${invoice.periodMonthUtc}.`
                : `Usage statement ${invoice.id} recorded for ${invoice.periodMonthUtc}.`,
            visibility: 'CUSTOMER',
          },
          ...entries
            .filter((entry) => entry.relatedInvoiceId === invoice.id)
            .map(activityEntryForLedger),
        ],
      };
    },

    async listInvoiceLineItems(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceLineItem[]> {
      const invoice = await this.getInvoice(ctx, invoiceId);
      if (!invoice) return [];
      const persisted = await listPersistedInvoiceLineItems({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        invoiceId: invoice.id,
      });
      if (persisted.length > 0) return persisted;
      const entries = await listLedgerEntries({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: invoice.periodMonthUtc,
        limit: 1000,
      });
      return invoiceLineItemsForStatement({ invoice, entries });
    },

    async generateMonthlyInvoice(
      ctx: ConsoleBillingContext,
      request: GenerateMonthlyInvoiceRequest,
    ): Promise<GenerateMonthlyInvoiceResult> {
      const periodMonthUtc = normalizeMonthUtc(request.periodMonthUtc);
      const entries = await listLedgerEntries({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: periodMonthUtc,
        limit: 1000,
      });
      const invoice = statementInvoiceFromLedger({
        orgId: ctx.orgId,
        monthUtcValue: periodMonthUtc,
        entries,
        createdAtMs: nowMs(state.now()),
      });
      const monthlyActiveWallets = await countMonthlyActiveWallets({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue: periodMonthUtc,
      });
      return {
        generated: false,
        invoice,
        lineItems: invoiceLineItemsForStatement({ invoice, entries }),
        monthlyActiveWallets,
        pricing: { mawUnitPriceMinor: MAW_USAGE_DEBIT_MINOR },
      };
    },

    async grantManualSupportCredit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalized = normalizeManualAdjustmentRequest(request);
      return await appendManualAdjustmentD1({
        state,
        ctx,
        request: normalized,
        amountMinor: Math.abs(normalized.amountMinor),
        reasonCode: normalized.reasonCode,
        description: `Manual support credit (${normalized.reasonCode})`,
      });
    },

    async appendManualAdminDebit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalized = normalizeManualAdjustmentRequest(request);
      requireLargeManualAdminDebitEscalationRole(ctx, normalized.amountMinor);
      return await appendManualAdjustmentD1({
        state,
        ctx,
        request: normalized,
        amountMinor: -Math.abs(normalized.amountMinor),
        reasonCode: normalized.reasonCode,
        description: `Manual admin debit (${normalized.reasonCode})`,
      });
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      const currentNow = state.now();
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
        now: currentNow,
      });
      const id = normalizeRequiredString(providerCheckoutSession.id, 'provider checkout id');
      const url = normalizeRequiredString(providerCheckoutSession.url, 'provider checkout url');
      const customerRef = normalizeRequiredString(
        providerCheckoutSession.customerRef,
        'provider customer ref',
      );
      const expiresAt = normalizeRequiredString(
        providerCheckoutSession.expiresAt,
        'provider checkout expiration',
      );
      await state.database
        .prepare(
          `INSERT INTO console_billing_credit_purchases
            (namespace, org_id, id, credit_pack_id, status, amount_minor, currency, provider, provider_checkout_session_ref, provider_customer_ref, related_invoice_id, settled_at_ms, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, 'PENDING', ?, 'USD', 'stripe', ?, ?, NULL, NULL, ?, ?)`,
        )
        .bind(
          state.namespace,
          ctx.orgId,
          makeId('bcp', currentNow),
          request.creditPackId,
          amountMinor,
          id,
          customerRef,
          nowMs(currentNow),
          nowMs(currentNow),
        )
        .run();
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
      const checkoutSessionId = normalizeRequiredString(
        request.checkoutSessionId,
        'checkoutSessionId',
      );
      const purchase = await loadCreditPurchaseByCheckoutSession({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        checkoutSessionId,
      });
      if (!purchase) {
        throw new ConsoleBillingError(
          'purchase_not_found',
          404,
          `No credit purchase found for Stripe checkout session ${checkoutSessionId}`,
        );
      }
      const wasSettled = purchase.status === 'SETTLED';
      const checkoutSession = await providers.stripe.getCheckoutSession({ checkoutSessionId });
      const providerOrgId = normalizeOptionalString(checkoutSession.orgId);
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
        const invoice = purchase.relatedInvoiceId
          ? await loadPersistedInvoiceById({
              database: state.database,
              namespace: state.namespace,
              orgId: ctx.orgId,
              invoiceId: purchase.relatedInvoiceId,
            })
          : null;
        return {
          settled: purchase.status === 'SETTLED',
          settledNow: false,
          purchase,
          invoice,
          orgId: ctx.orgId,
          paymentStatus: paymentStatus || null,
          checkoutStatus: checkoutStatus || null,
        };
      }
      const result = await processStripeWebhookEventD1({
        state,
        request: {
          eventId: `stripe_checkout_reconcile:${checkoutSessionId}`,
          eventType: 'checkout.session.completed',
          orgId: ctx.orgId,
          checkoutSessionId,
          providerCustomerRef:
            normalizeOptionalString(checkoutSession.customerRef) ||
            purchase.providerCustomerRef ||
            undefined,
          providerRef: checkoutSessionId,
        },
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
      return await processStripeWebhookEventD1({ state, request });
    },

    [CONSOLE_BILLING_D1_RUNTIME]: runtime,
  };

  return service;
}

async function countStatementMonths(state: D1ConsoleBillingState, orgId: string): Promise<number> {
  const row = await queryOne(
    state.database,
    `SELECT COUNT(DISTINCT month_utc) AS statement_count
       FROM console_billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc IS NOT NULL`,
    [state.namespace, orgId],
  );
  return Math.max(0, toNumber(row?.statement_count));
}

async function countPersistedInvoices(state: D1ConsoleBillingState, orgId: string): Promise<number> {
  const row = await queryOne(
    state.database,
    `SELECT COUNT(*) AS invoice_count
       FROM console_invoices
      WHERE namespace = ?
        AND org_id = ?`,
    [state.namespace, orgId],
  );
  return Math.max(0, toNumber(row?.invoice_count));
}

async function countProjectedInvoices(state: D1ConsoleBillingState, orgId: string): Promise<number> {
  const persistedCount = await countPersistedInvoices(state, orgId);
  const statementCount = await countStatementMonths(state, orgId);
  return persistedCount + statementCount;
}

async function listProjectedInvoices(
  state: D1ConsoleBillingState,
  orgId: string,
): Promise<BillingInvoice[]> {
  const invoices = new Map<string, BillingInvoice>();
  const persisted = await listPersistedInvoices({
    database: state.database,
    namespace: state.namespace,
    orgId,
  });
  for (const invoice of persisted) {
    invoices.set(invoice.id, invoice);
  }
  const entries = await listAllStatementLedgerEntries({
    database: state.database,
    namespace: state.namespace,
    orgId,
  });
  const months = Array.from(new Set(entries.map((entry) => entry.monthUtc).filter(Boolean)));
  for (const monthUtcValue of months) {
    const invoice = statementInvoiceFromLedger({
      orgId,
      monthUtcValue: String(monthUtcValue || ''),
      entries,
      createdAtMs:
        Date.parse(entries.find((entry) => entry.monthUtc === monthUtcValue)?.createdAt || '') ||
        nowMs(state.now()),
    });
    if (!invoices.has(invoice.id)) {
      invoices.set(invoice.id, invoice);
    }
  }
  return Array.from(invoices.values()).sort((left, right) => {
    const tsDiff = Date.parse(right.createdAt) - Date.parse(left.createdAt);
    if (tsDiff !== 0) return tsDiff;
    return right.id.localeCompare(left.id);
  });
}

async function recordUsageEventD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingUsageEventRequest;
}): Promise<BillingUsageEventResult> {
  const occurredAtMs = input.request.occurredAt
    ? Date.parse(input.request.occurredAt)
    : nowMs(input.state.now());
  if (!Number.isFinite(occurredAtMs)) {
    throw new ConsoleBillingError('invalid_usage_event', 400, 'Invalid occurredAt value');
  }
  const monthUtcValue = monthUtcFromMs(occurredAtMs);
  const counted =
    BILLABLE_USAGE_ACTIONS.has(input.request.action) &&
    input.request.succeeded &&
    !input.request.isSimulation &&
    !input.request.isInternalRetry;
  let debitAppliedMinor = 0;
  if (counted) {
    const sourceEventId = normalizeOptionalString(input.request.sourceEventId);
    const existingWallet = await queryOne(
      input.state.database,
      `SELECT wallet_id
         FROM console_billing_monthly_active_wallets
        WHERE namespace = ?
          AND org_id = ?
          AND month_utc = ?
          AND wallet_id = ?
        LIMIT 1`,
      [input.state.namespace, input.ctx.orgId, monthUtcValue, input.request.walletId],
    );
    if (!existingWallet) {
      const entryId = makeId('ble', new Date(occurredAtMs));
      await input.state.database.batch([
        input.state.database
          .prepare(
            `INSERT INTO console_billing_monthly_active_wallets
              (namespace, org_id, month_utc, wallet_id, source_event_id, created_at_ms)
             VALUES
              (?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            input.state.namespace,
            input.ctx.orgId,
            monthUtcValue,
            input.request.walletId,
            sourceEventId,
            occurredAtMs,
          ),
        createD1BillingLedgerEntryInsertStatement(input.state.database, {
          namespace: input.state.namespace,
          orgId: input.ctx.orgId,
          entryId,
          type: 'USAGE_DEBIT',
          amountMinor: -MAW_USAGE_DEBIT_MINOR,
          description: `MAW usage debit for wallet ${input.request.walletId}`,
          monthUtc: monthUtcValue,
          relatedInvoiceId: makeUsageStatementId(input.ctx.orgId, monthUtcValue),
          relatedPurchaseId: null,
          sourceEventId,
          actorType: 'USER',
          actorUserId: input.ctx.actorUserId,
          reasonCode: 'usage_debit',
          note: `Usage debit recorded for wallet ${input.request.walletId}`,
          idempotencyKey: sourceEventId
            ? `usage_debit:${sourceEventId}`
            : `usage_debit:${monthUtcValue}:${input.request.walletId}:${occurredAtMs}`,
          createdAtMs: occurredAtMs,
        }),
      ]);
      debitAppliedMinor = MAW_USAGE_DEBIT_MINOR;
    }
  }
  const monthlyActiveWallets = await countMonthlyActiveWallets({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    monthUtcValue,
  });
  const account = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: occurredAtMs,
  });
  return {
    accepted: true,
    counted,
    monthUtc: monthUtcValue,
    monthlyActiveWallets,
    debitAppliedMinor,
    creditBalanceMinor: account.creditBalanceMinor,
    statementId: makeUsageStatementId(input.ctx.orgId, monthUtcValue),
  };
}

async function appendManualAdjustmentD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingManualAdjustmentRequest;
  amountMinor: number;
  reasonCode: string;
  description: string;
}): Promise<BillingManualAdjustmentResult> {
  const currentNow = input.state.now();
  const idempotencyKey = normalizeRequiredString(input.request.idempotencyKey, 'idempotencyKey');
  const existing = await queryOne(
    input.state.database,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND idempotency_key = ?
      LIMIT 1`,
    [input.state.namespace, input.ctx.orgId, idempotencyKey],
  );
  if (existing) {
    const adjustment = parseLedgerEntry(existing);
    const account = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      createdAtMs: nowMs(currentNow),
    });
    return { created: false, adjustment, creditBalanceMinor: account.creditBalanceMinor };
  }
  const entryId = makeId('ble', currentNow);
  await createD1BillingLedgerEntryInsertStatement(input.state.database, {
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    entryId,
    type: 'MANUAL_ADJUSTMENT',
    amountMinor: input.amountMinor,
    description: input.description,
    monthUtc: monthUtc(currentNow),
    relatedInvoiceId: normalizeOptionalString(input.request.relatedInvoiceId),
    relatedPurchaseId: null,
    sourceEventId: idempotencyKey,
    actorType: 'USER',
    actorUserId: input.ctx.actorUserId,
    reasonCode: input.reasonCode,
    note: input.request.note,
    idempotencyKey,
    createdAtMs: nowMs(currentNow),
  }).run();
  const adjustment = await loadLedgerEntryById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    ledgerEntryId: entryId,
  });
  if (!adjustment) {
    throw new ConsoleBillingError(
      'billing_ledger_write_failed',
      500,
      'Failed to append manual billing adjustment',
    );
  }
  const account = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: nowMs(currentNow),
  });
  return { created: true, adjustment, creditBalanceMinor: account.creditBalanceMinor };
}
