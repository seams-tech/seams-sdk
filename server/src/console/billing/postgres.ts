import { secureRandomBase36 } from '@shared/utils/secureRandomId';
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
import { BILLING_CREDIT_PACK_ID_SQL, resolveCreditPackAmountMinorOrThrow } from './creditPacks';
import { ConsoleBillingError } from './errors';
import { resolveBillingProviderAdapters, type BillingProviderAdapters } from './providers';
import { resolveBillingLiveEnvironmentState } from './readiness';
import {
  normalizeManualAdjustmentRequest,
  requireBillingAdjustmentRole,
  requireLargeManualAdminDebitEscalationRole,
} from './adjustments';
import type {
  BillingCreditPackId,
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
  BillingSponsoredExecutionDebitEntry,
  BillingSponsoredExecutionDebitRequest,
  BillingSponsoredExecutionDebitResult,
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
import type { ConsoleBillingContext, ConsoleBillingService } from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;
type BillingJournalActorType = 'USER' | 'SYSTEM' | 'PROVIDER';
type BillingLedgerPostingDirection = 'DEBIT' | 'CREDIT';

const CONSOLE_BILLING_MIGRATION_LOCK_ID = 9452360123582;
export const CONSOLE_BILLING_POSTGRES_RUNTIME = Symbol('consoleBillingPostgresRuntime');

export interface ConsoleBillingPostgresRuntime {
  pool: PgPool;
  namespace: string;
  now: () => Date;
}

export type ConsoleBillingPostgresService = ConsoleBillingService & {
  [CONSOLE_BILLING_POSTGRES_RUNTIME]: ConsoleBillingPostgresRuntime;
};

export function getConsoleBillingPostgresRuntime(
  service: ConsoleBillingService | null | undefined,
): ConsoleBillingPostgresRuntime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleBillingPostgresService>)[CONSOLE_BILLING_POSTGRES_RUNTIME] || null
  );
}
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

const PLATFORM_LEDGER_ACCOUNTS = [
  {
    id: 'acct:processor_clearing:stripe',
    scopeType: 'PLATFORM',
    scopeOrgId: null,
    accountCode: 'processor_clearing:stripe',
  },
  {
    id: 'acct:revenue_usage',
    scopeType: 'PLATFORM',
    scopeOrgId: null,
    accountCode: 'revenue_usage',
  },
  {
    id: 'acct:expense_support_credit',
    scopeType: 'PLATFORM',
    scopeOrgId: null,
    accountCode: 'expense_support_credit',
  },
  {
    id: 'acct:suspense_admin_debit',
    scopeType: 'PLATFORM',
    scopeOrgId: null,
    accountCode: 'suspense_admin_debit',
  },
  {
    id: 'acct:suspense_reconciliation',
    scopeType: 'PLATFORM',
    scopeOrgId: null,
    accountCode: 'suspense_reconciliation',
  },
] as const;

interface BillingLedgerPostingInput {
  id: string;
  accountId: string;
  orgId: string;
  direction: BillingLedgerPostingDirection;
  amountMinor: number;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
}

interface BillingLedgerEntryWriteInput {
  namespace: string;
  orgId: string;
  id: string;
  type: BillingLedgerEntry['type'];
  amountMinor: number;
  description: string;
  monthUtc: string | null;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
  createdAtMs: number;
  actorType?: BillingJournalActorType;
  actorUserId?: string | null;
  reasonCode?: string | null;
  note?: string | null;
  idempotencyKey?: string | null;
}

function getOrgPrepaidLiabilityAccountId(orgId: string): string {
  return `acct:org_prepaid_liability:${orgId}`;
}

function getOrgPrepaidLiabilityAccountCode(orgId: string): string {
  return `org_prepaid_liability:${orgId}`;
}

function makeLedgerPostingId(entryId: string, suffix: string): string {
  return `blp:${entryId}:${suffix}`;
}

function buildLedgerPostingsForEntry(input: {
  entryId: string;
  orgId: string;
  type: BillingLedgerEntry['type'];
  amountMinor: number;
  relatedInvoiceId: string | null;
  relatedPurchaseId: string | null;
  sourceEventId: string | null;
}): BillingLedgerPostingInput[] {
  const absoluteAmountMinor = Math.abs(input.amountMinor);
  if (absoluteAmountMinor <= 0) return [];
  const prepaidLiabilityAccountId = getOrgPrepaidLiabilityAccountId(input.orgId);

  switch (input.type) {
    case 'CREDIT_PURCHASE':
      if (input.amountMinor <= 0) {
        throw new ConsoleBillingError(
          'billing_ledger_write_failed',
          500,
          'Credit purchase journal entries must be positive',
        );
      }
      return [
        {
          id: makeLedgerPostingId(input.entryId, 'debit_processor_clearing'),
          accountId: 'acct:processor_clearing:stripe',
          orgId: input.orgId,
          direction: 'DEBIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
        {
          id: makeLedgerPostingId(input.entryId, 'credit_org_prepaid_liability'),
          accountId: prepaidLiabilityAccountId,
          orgId: input.orgId,
          direction: 'CREDIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
      ];
    case 'USAGE_DEBIT':
    case 'SPONSORED_EXECUTION_DEBIT':
      return [
        {
          id: makeLedgerPostingId(input.entryId, 'debit_org_prepaid_liability'),
          accountId: prepaidLiabilityAccountId,
          orgId: input.orgId,
          direction: 'DEBIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
        {
          id: makeLedgerPostingId(input.entryId, 'credit_revenue_usage'),
          accountId: 'acct:revenue_usage',
          orgId: input.orgId,
          direction: 'CREDIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
      ];
    case 'MANUAL_ADJUSTMENT':
      if (input.amountMinor >= 0) {
        return [
          {
            id: makeLedgerPostingId(input.entryId, 'debit_expense_support_credit'),
            accountId: 'acct:expense_support_credit',
            orgId: input.orgId,
            direction: 'DEBIT',
            amountMinor: absoluteAmountMinor,
            relatedInvoiceId: input.relatedInvoiceId,
            relatedPurchaseId: input.relatedPurchaseId,
            sourceEventId: input.sourceEventId,
          },
          {
            id: makeLedgerPostingId(input.entryId, 'credit_org_prepaid_liability'),
            accountId: prepaidLiabilityAccountId,
            orgId: input.orgId,
            direction: 'CREDIT',
            amountMinor: absoluteAmountMinor,
            relatedInvoiceId: input.relatedInvoiceId,
            relatedPurchaseId: input.relatedPurchaseId,
            sourceEventId: input.sourceEventId,
          },
        ];
      }
      return [
        {
          id: makeLedgerPostingId(input.entryId, 'debit_org_prepaid_liability'),
          accountId: prepaidLiabilityAccountId,
          orgId: input.orgId,
          direction: 'DEBIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
        {
          id: makeLedgerPostingId(input.entryId, 'credit_suspense_admin_debit'),
          accountId: 'acct:suspense_admin_debit',
          orgId: input.orgId,
          direction: 'CREDIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
      ];
    case 'REFUND':
    case 'REVERSAL':
      if (input.amountMinor >= 0) {
        return [
          {
            id: makeLedgerPostingId(input.entryId, 'debit_suspense_reconciliation'),
            accountId: 'acct:suspense_reconciliation',
            orgId: input.orgId,
            direction: 'DEBIT',
            amountMinor: absoluteAmountMinor,
            relatedInvoiceId: input.relatedInvoiceId,
            relatedPurchaseId: input.relatedPurchaseId,
            sourceEventId: input.sourceEventId,
          },
          {
            id: makeLedgerPostingId(input.entryId, 'credit_org_prepaid_liability'),
            accountId: prepaidLiabilityAccountId,
            orgId: input.orgId,
            direction: 'CREDIT',
            amountMinor: absoluteAmountMinor,
            relatedInvoiceId: input.relatedInvoiceId,
            relatedPurchaseId: input.relatedPurchaseId,
            sourceEventId: input.sourceEventId,
          },
        ];
      }
      return [
        {
          id: makeLedgerPostingId(input.entryId, 'debit_org_prepaid_liability'),
          accountId: prepaidLiabilityAccountId,
          orgId: input.orgId,
          direction: 'DEBIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
        {
          id: makeLedgerPostingId(input.entryId, 'credit_suspense_reconciliation'),
          accountId: 'acct:suspense_reconciliation',
          orgId: input.orgId,
          direction: 'CREDIT',
          amountMinor: absoluteAmountMinor,
          relatedInvoiceId: input.relatedInvoiceId,
          relatedPurchaseId: input.relatedPurchaseId,
          sourceEventId: input.sourceEventId,
        },
      ];
    default: {
      const exhaustive: never = input.type;
      throw new ConsoleBillingError(
        'billing_ledger_write_failed',
        500,
        `Unsupported billing ledger entry type: ${exhaustive as string}`,
      );
    }
  }
}

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
  const rand = secureRandomBase36(8, 'console IDs');
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

function makeBootstrapUsageStatementId(orgId: string, periodMonthUtc: string): string {
  const monthPart = periodMonthUtc.replace('-', '');
  const orgPrefix =
    orgId
      .toLowerCase()
      .replace(/[^a-z0-9]/g, '')
      .slice(0, 8) || 'org';
  const orgHashPart = stableHash32(orgId).toString(36);
  return `stmt_${monthPart}_${orgPrefix}_${orgHashPart}`;
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
    documentType:
      String(row.document_type || '').trim() === 'PURCHASE_RECEIPT'
        ? 'PURCHASE_RECEIPT'
        : 'USAGE_STATEMENT',
    status: String(row.status || 'OPEN') as BillingInvoice['status'],
    currency: 'USD',
    amountDueMinor: toNumber(row.amount_due_minor),
    amountPaidMinor: toNumber(row.amount_paid_minor),
    periodMonthUtc: String(row.period_month_utc || ''),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    dueAt: row.due_at_ms == null ? null : toIso(toNumber(row.due_at_ms)),
  };
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

function isInvoiceOverdueAt(invoice: BillingInvoice, referenceNowMs: number): boolean {
  if (invoice.status !== 'OPEN' || !invoice.dueAt) return false;
  const dueAtMs = Date.parse(invoice.dueAt);
  if (!Number.isFinite(dueAtMs)) return false;
  return dueAtMs < referenceNowMs;
}

function buildInvoiceListSummary(
  invoices: BillingInvoice[],
  referenceNowMs: number,
): BillingInvoiceListSummary {
  const openCount = invoices.filter((invoice) => invoice.status === 'OPEN').length;
  const overdueCount = invoices.filter((invoice) =>
    isInvoiceOverdueAt(invoice, referenceNowMs),
  ).length;
  const paidCount = invoices.filter((invoice) => invoice.status === 'PAID').length;
  const receiptCount = invoices.filter(
    (invoice) => invoice.documentType === 'PURCHASE_RECEIPT',
  ).length;
  const statementCount = invoices.filter(
    (invoice) => invoice.documentType === 'USAGE_STATEMENT',
  ).length;
  const outstandingAmountMinor = invoices.reduce((total, invoice) => {
    return total + Math.max(0, invoice.amountDueMinor - invoice.amountPaidMinor);
  }, 0);
  return {
    totalCount: invoices.length,
    openCount,
    overdueCount,
    paidCount,
    outstandingAmountMinor,
    latestPeriodMonthUtc: invoices[0]?.periodMonthUtc || null,
    receiptCount,
    statementCount,
  };
}

function parseInvoiceLineItemRow(row: PgRow): BillingInvoiceLineItem {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    invoiceId: String(row.invoice_id || ''),
    periodMonthUtc: String(row.period_month_utc || ''),
    itemType: String(row.item_type || 'MAW_USAGE_DEBIT') as BillingInvoiceLineItemType,
    description: String(row.description || ''),
    quantity: toNumber(row.quantity),
    unitAmountMinor: toNumber(row.unit_amount_minor),
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
  };
}

function parseCreditPurchaseRow(row: PgRow): BillingCreditPurchase {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    creditPackId: String(row.credit_pack_id || 'usd_10') as BillingCreditPackId,
    status: String(row.status || 'PENDING') as BillingCreditPurchase['status'],
    amountMinor: toNumber(row.amount_minor),
    currency: 'USD',
    provider: 'stripe',
    providerCheckoutSessionRef: String(row.provider_checkout_session_ref || ''),
    providerCustomerRef:
      row.provider_customer_ref == null ? null : String(row.provider_customer_ref || '').trim(),
    relatedInvoiceId:
      row.related_invoice_id == null ? null : String(row.related_invoice_id || '').trim(),
    settledAt: row.settled_at_ms == null ? null : toIso(toNumber(row.settled_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseLedgerEntryRow(row: PgRow): BillingLedgerEntry {
  const actorType = String(row.actor_type || 'SYSTEM')
    .trim()
    .toUpperCase();
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    type: String(row.entry_type || 'MANUAL_ADJUSTMENT') as BillingLedgerEntry['type'],
    amountMinor: toNumber(row.amount_minor),
    currency: 'USD',
    description: String(row.description || ''),
    monthUtc: row.month_utc == null ? null : String(row.month_utc || '').trim() || null,
    relatedInvoiceId:
      row.related_invoice_id == null ? null : String(row.related_invoice_id || '').trim() || null,
    relatedPurchaseId:
      row.related_purchase_id == null ? null : String(row.related_purchase_id || '').trim() || null,
    sourceEventId:
      row.source_event_id == null ? null : String(row.source_event_id || '').trim() || null,
    actorType: actorType === 'USER' || actorType === 'PROVIDER' ? actorType : 'SYSTEM',
    actorUserId: row.actor_user_id == null ? null : String(row.actor_user_id || '').trim() || null,
    reasonCode: row.reason_code == null ? null : String(row.reason_code || '').trim() || null,
    note: row.note == null ? null : String(row.note || '').trim() || null,
    idempotencyKey:
      row.idempotency_key == null ? null : String(row.idempotency_key || '').trim() || null,
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
  };
}

function makeStripeCustomerRef(orgId: string): string {
  return `cus_${orgId.replace(/[^a-zA-Z0-9]/g, '').slice(0, 12) || 'org'}`;
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function ensurePlatformLedgerAccounts(
  q: Queryable,
  namespace: string,
  createdAtMs: number,
): Promise<void> {
  for (const account of PLATFORM_LEDGER_ACCOUNTS) {
    await q.query(
      `INSERT INTO console_billing_ledger_accounts
        (namespace, id, scope_type, scope_org_id, account_code, currency, status, created_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, 'USD', 'ACTIVE', $6)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [
        namespace,
        account.id,
        account.scopeType,
        account.scopeOrgId,
        account.accountCode,
        createdAtMs,
      ],
    );
  }
}

async function ensureOrgPrepaidLiabilityLedgerAccount(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    createdAtMs: number;
  },
): Promise<void> {
  await q.query(
    `INSERT INTO console_billing_ledger_accounts
      (namespace, id, scope_type, scope_org_id, account_code, currency, status, created_at_ms)
     VALUES
      ($1, $2, 'ORG', $3, $4, 'USD', 'ACTIVE', $5)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [
      input.namespace,
      getOrgPrepaidLiabilityAccountId(input.orgId),
      input.orgId,
      getOrgPrepaidLiabilityAccountCode(input.orgId),
      input.createdAtMs,
    ],
  );
}

async function ensureCanonicalLedgerAccounts(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    createdAtMs: number;
  },
): Promise<void> {
  await ensurePlatformLedgerAccounts(q, input.namespace, input.createdAtMs);
  await ensureOrgPrepaidLiabilityLedgerAccount(q, input);
}

async function insertLedgerPostings(
  q: Queryable,
  input: {
    namespace: string;
    entryId: string;
    createdAtMs: number;
    postings: BillingLedgerPostingInput[];
  },
): Promise<void> {
  if (input.postings.length === 0) return;
  const debitTotal = input.postings
    .filter((posting) => posting.direction === 'DEBIT')
    .reduce((total, posting) => total + posting.amountMinor, 0);
  const creditTotal = input.postings
    .filter((posting) => posting.direction === 'CREDIT')
    .reduce((total, posting) => total + posting.amountMinor, 0);
  if (debitTotal <= 0 || creditTotal <= 0 || debitTotal !== creditTotal) {
    throw new ConsoleBillingError(
      'billing_ledger_write_failed',
      500,
      `Ledger postings must be balanced for entry ${input.entryId}`,
    );
  }
  for (const posting of input.postings) {
    await q.query(
      `INSERT INTO console_billing_ledger_postings
        (namespace, id, entry_id, account_id, org_id, direction, amount_minor, currency, related_invoice_id, related_purchase_id, source_event_id, created_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, 'USD', $8, $9, $10, $11)
       ON CONFLICT (namespace, id) DO NOTHING`,
      [
        input.namespace,
        posting.id,
        input.entryId,
        posting.accountId,
        posting.orgId,
        posting.direction,
        posting.amountMinor,
        posting.relatedInvoiceId,
        posting.relatedPurchaseId,
        posting.sourceEventId,
        input.createdAtMs,
      ],
    );
  }
}

async function getProjectedOrgBalanceMinor(
  q: Queryable,
  namespace: string,
  orgId: string,
): Promise<number> {
  const row = await queryOne(
    q,
    `SELECT COALESCE(
        SUM(
          CASE direction
            WHEN 'CREDIT' THEN amount_minor
            ELSE -amount_minor
          END
        ),
        0
      )::BIGINT AS balance_minor
       FROM console_billing_ledger_postings
      WHERE namespace = $1
        AND org_id = $2
        AND account_id = $3`,
    [namespace, orgId, getOrgPrepaidLiabilityAccountId(orgId)],
  );
  return toNumber(row?.balance_minor);
}

async function syncProjectedOrgBalance(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    updatedAtMs: number;
  },
): Promise<number> {
  const balanceMinor = await getProjectedOrgBalanceMinor(q, input.namespace, input.orgId);
  await q.query(
    `UPDATE console_billing_accounts
        SET credit_balance_minor = $3,
            updated_at_ms = $4
      WHERE namespace = $1 AND org_id = $2`,
    [input.namespace, input.orgId, balanceMinor, input.updatedAtMs],
  );
  return balanceMinor;
}

async function syncBillingAccountSnapshot(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    creditBalanceMinor: number;
    monthlyActiveWallets: number;
    updatedAtMs: number;
  },
): Promise<void> {
  await q.query(
    `UPDATE console_billing_accounts
        SET credit_balance_minor = $3,
            monthly_active_wallets = $4,
            updated_at_ms = $5
      WHERE namespace = $1 AND org_id = $2`,
    [
      input.namespace,
      input.orgId,
      input.creditBalanceMinor,
      input.monthlyActiveWallets,
      input.updatedAtMs,
    ],
  );
}

async function ensureOrgBootstrap(input: {
  pool: Queryable;
  namespace: string;
  orgId: string;
  now: Date;
}): Promise<void> {
  const { pool, namespace, orgId, now } = input;
  const createdAtMs = nowMs(now);
  const periodMonth = monthUtc(now);

  await pool.query(
    `INSERT INTO console_billing_accounts
      (namespace, org_id, usage_metric_version, monthly_active_wallets, credit_balance_minor, low_balance_threshold_minor, created_at_ms, updated_at_ms)
     VALUES
      ($1, $2, 'maw_v1', 0, 0, $4, $3, $3)
     ON CONFLICT (namespace, org_id) DO NOTHING`,
    [namespace, orgId, createdAtMs, DEFAULT_LOW_BALANCE_THRESHOLD_MINOR],
  );

  await ensureCanonicalLedgerAccounts(pool, {
    namespace,
    orgId,
    createdAtMs,
  });

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
  const invoiceId = makeBootstrapUsageStatementId(orgId, periodMonth);

  await pool.query(
    `INSERT INTO console_invoices
      (namespace, id, org_id, document_type, status, currency, amount_due_minor, amount_paid_minor, period_month_utc, created_at_ms, due_at_ms)
     VALUES
      ($1, $2, $3, 'USAGE_STATEMENT', 'PAID', 'USD', 0, 0, $4, $5, NULL)
     ON CONFLICT (namespace, id) DO NOTHING`,
    [namespace, invoiceId, orgId, periodMonth, createdAtMs],
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
  sponsoredExecutionDebitMinor: number;
  createdAtMs: number;
}): BillingInvoiceLineItem[] {
  const items: BillingInvoiceLineItem[] = [];
  if (input.monthlyActiveWallets > 0) {
    items.push(
      makeInvoiceLineItem({
        orgId: input.orgId,
        invoiceId: input.invoiceId,
        periodMonthUtc: input.periodMonthUtc,
        itemType: 'MAW_USAGE_DEBIT',
        description: `Monthly Active Wallet usage (${input.periodMonthUtc})`,
        quantity: input.monthlyActiveWallets,
        unitAmountMinor: MAW_USAGE_DEBIT_MINOR,
        createdAtMs: input.createdAtMs,
      }),
    );
  }
  if (input.sponsoredExecutionDebitMinor > 0) {
    items.push(
      makeInvoiceLineItem({
        orgId: input.orgId,
        invoiceId: input.invoiceId,
        periodMonthUtc: input.periodMonthUtc,
        itemType: 'SPONSORED_EXECUTION_DEBIT',
        description: `Sponsored execution spend (${input.periodMonthUtc})`,
        quantity: 1,
        unitAmountMinor: input.sponsoredExecutionDebitMinor,
        createdAtMs: input.createdAtMs,
      }),
    );
  }
  return items;
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

async function appendLedgerEntry(
  q: Queryable,
  input: BillingLedgerEntryWriteInput,
): Promise<BillingLedgerEntry> {
  await ensureCanonicalLedgerAccounts(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    createdAtMs: input.createdAtMs,
  });
  const postings = buildLedgerPostingsForEntry({
    entryId: input.id,
    orgId: input.orgId,
    type: input.type,
    amountMinor: input.amountMinor,
    relatedInvoiceId: input.relatedInvoiceId,
    relatedPurchaseId: input.relatedPurchaseId,
    sourceEventId: input.sourceEventId,
  });
  const row = await queryOne(
    q,
    `INSERT INTO console_billing_ledger_entries
      (
        namespace,
        id,
        org_id,
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
      ($1, $2, $3, $4, $5, 'USD', $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
     RETURNING *`,
    [
      input.namespace,
      input.id,
      input.orgId,
      input.type,
      input.amountMinor,
      input.description,
      input.monthUtc,
      input.relatedInvoiceId,
      input.relatedPurchaseId,
      input.sourceEventId,
      input.actorType || 'SYSTEM',
      input.actorUserId || null,
      input.reasonCode || null,
      input.note || null,
      input.idempotencyKey || null,
      input.createdAtMs,
    ],
  );
  if (!row) {
    throw new ConsoleBillingError(
      'billing_ledger_write_failed',
      500,
      'Failed to write ledger entry',
    );
  }
  await insertLedgerPostings(q, {
    namespace: input.namespace,
    entryId: input.id,
    createdAtMs: input.createdAtMs,
    postings,
  });
  return parseLedgerEntryRow(row);
}

async function findLedgerEntryByIdempotencyKey(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    idempotencyKey: string;
  },
): Promise<BillingLedgerEntry | null> {
  const key = String(input.idempotencyKey || '').trim();
  if (!key) return null;
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND idempotency_key = $3`,
    [input.namespace, input.orgId, key],
  );
  return row ? parseLedgerEntryRow(row) : null;
}

async function ensureManualAdjustmentRelatedInvoiceId(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    relatedInvoiceId: string | undefined;
  },
): Promise<string | null> {
  const relatedInvoiceId = String(input.relatedInvoiceId || '').trim();
  if (!relatedInvoiceId) return null;
  const linkedInvoice = await queryOne(
    q,
    `SELECT id
       FROM console_invoices
      WHERE namespace = $1 AND org_id = $2 AND id = $3`,
    [input.namespace, input.orgId, relatedInvoiceId],
  );
  if (!linkedInvoice) {
    throw new ConsoleBillingError(
      'invalid_manual_adjustment',
      400,
      `Manual adjustment relatedInvoiceId was not found: ${relatedInvoiceId}`,
    );
  }
  return relatedInvoiceId;
}

async function getCurrentMonthUsageDebitMinor(
  q: Queryable,
  namespace: string,
  orgId: string,
  monthUtc: string,
): Promise<number> {
  const row = await queryOne(
    q,
    `SELECT COALESCE(SUM(ABS(amount_minor)), 0)::BIGINT AS total_minor
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND entry_type = 'USAGE_DEBIT'
        AND month_utc = $3`,
    [namespace, orgId, monthUtc],
  );
  return toNumber(row?.total_minor);
}

async function getCurrentMonthPurchasedMinor(
  q: Queryable,
  namespace: string,
  orgId: string,
  monthUtc: string,
): Promise<number> {
  const row = await queryOne(
    q,
    `SELECT COALESCE(SUM(amount_minor), 0)::BIGINT AS total_minor
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND entry_type = 'CREDIT_PURCHASE'
        AND month_utc = $3`,
    [namespace, orgId, monthUtc],
  );
  return toNumber(row?.total_minor);
}

async function getUsageStatementProjectionTotals(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    periodMonthUtc: string;
  },
): Promise<{
  monthlyActiveWallets: number;
  amountDueMinor: number;
  sponsoredExecutionDebitMinor: number;
}> {
  const row = await queryOne(
    q,
    `SELECT
        COALESCE(SUM(CASE WHEN entry_type = 'USAGE_DEBIT' THEN ABS(amount_minor) ELSE 0 END), 0)::BIGINT AS maw_amount_due_minor,
        COALESCE(SUM(CASE WHEN entry_type = 'SPONSORED_EXECUTION_DEBIT' THEN ABS(amount_minor) ELSE 0 END), 0)::BIGINT AS sponsored_amount_due_minor
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND entry_type IN ('USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT')
        AND month_utc = $3`,
    [input.namespace, input.orgId, input.periodMonthUtc],
  );
  const mawAmountDueMinor = toNumber(row?.maw_amount_due_minor);
  const sponsoredExecutionDebitMinor = toNumber(row?.sponsored_amount_due_minor);
  return {
    monthlyActiveWallets:
      mawAmountDueMinor > 0
        ? Math.max(0, Math.round(mawAmountDueMinor / MAW_USAGE_DEBIT_MINOR))
        : 0,
    amountDueMinor: mawAmountDueMinor + sponsoredExecutionDebitMinor,
    sponsoredExecutionDebitMinor,
  };
}

async function reconcileUsageDebitCoverage(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    periodMonthUtc: string;
    monthlyActiveWallets: number;
    createdAtMs: number;
  },
): Promise<void> {
  const usageTotals = await getUsageStatementProjectionTotals(q, input);
  const targetAmountMinor = Math.max(0, input.monthlyActiveWallets) * MAW_USAGE_DEBIT_MINOR;
  if (usageTotals.amountDueMinor >= targetAmountMinor) return;

  const missingAmountMinor = targetAmountMinor - usageTotals.amountDueMinor;
  if (missingAmountMinor <= 0) return;

  await appendLedgerEntry(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    id: `ble_usage_reconcile_${input.orgId}_${input.periodMonthUtc.replace('-', '')}`,
    type: 'USAGE_DEBIT',
    amountMinor: -missingAmountMinor,
    description: `Reconciled MAW usage debit coverage (${input.periodMonthUtc})`,
    monthUtc: input.periodMonthUtc,
    relatedInvoiceId: makeBootstrapUsageStatementId(input.orgId, input.periodMonthUtc),
    relatedPurchaseId: null,
    sourceEventId: `usage_statement:${input.periodMonthUtc}`,
    actorType: 'SYSTEM',
    actorUserId: 'system-billing-finalizer',
    reasonCode: 'usage_statement_reconciliation',
    note: `Reconciled ${Math.round(missingAmountMinor / MAW_USAGE_DEBIT_MINOR)} missing MAW debit(s) into the monthly usage statement.`,
    idempotencyKey: `usage_statement:${input.orgId}:${input.periodMonthUtc}`,
    createdAtMs: input.createdAtMs,
  });
}

async function ensureUsageStatementProjection(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    periodMonthUtc: string;
    createdAtMs: number;
  },
): Promise<BillingInvoice> {
  const invoiceId = makeBootstrapUsageStatementId(input.orgId, input.periodMonthUtc);
  const existing = await queryOne(
    q,
    `SELECT *
       FROM console_invoices
      WHERE namespace = $1
        AND org_id = $2
        AND id = $3
      FOR UPDATE`,
    [input.namespace, input.orgId, invoiceId],
  );
  if (existing) return parseInvoiceRow(existing);

  const inserted = await queryOne(
    q,
    `INSERT INTO console_invoices
      (namespace, id, org_id, document_type, status, currency, amount_due_minor, amount_paid_minor, period_month_utc, created_at_ms, due_at_ms)
     VALUES
      ($1, $2, $3, 'USAGE_STATEMENT', 'PAID', 'USD', 0, 0, $4, $5, NULL)
     ON CONFLICT (namespace, id) DO UPDATE
       SET document_type = 'USAGE_STATEMENT'
     RETURNING *`,
    [input.namespace, invoiceId, input.orgId, input.periodMonthUtc, input.createdAtMs],
  );
  if (!inserted) {
    throw new ConsoleBillingError(
      'invoice_generate_failed',
      500,
      'Failed to create usage statement',
    );
  }
  return parseInvoiceRow(inserted);
}

async function syncUsageStatementProjection(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    periodMonthUtc: string;
    createdAtMs: number;
  },
): Promise<{ invoice: BillingInvoice; lineItems: BillingInvoiceLineItem[] }> {
  const invoice = await ensureUsageStatementProjection(q, input);
  const usageTotals = await getUsageStatementProjectionTotals(q, input);
  const nextLineItems = buildInvoiceLineItems({
    orgId: input.orgId,
    invoiceId: invoice.id,
    periodMonthUtc: input.periodMonthUtc,
    monthlyActiveWallets: usageTotals.monthlyActiveWallets,
    sponsoredExecutionDebitMinor: usageTotals.sponsoredExecutionDebitMinor,
    createdAtMs: input.createdAtMs,
  });
  await q.query(
    `DELETE FROM console_invoice_line_items
      WHERE namespace = $1 AND org_id = $2 AND invoice_id = $3`,
    [input.namespace, input.orgId, invoice.id],
  );
  for (const lineItem of nextLineItems) {
    await q.query(
      `INSERT INTO console_invoice_line_items
        (namespace, id, org_id, invoice_id, period_month_utc, item_type, description, quantity, unit_amount_minor, amount_minor, created_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        input.namespace,
        lineItem.id,
        input.orgId,
        invoice.id,
        lineItem.periodMonthUtc,
        lineItem.itemType,
        lineItem.description,
        lineItem.quantity,
        lineItem.unitAmountMinor,
        lineItem.amountMinor,
        input.createdAtMs,
      ],
    );
  }
  const updated = await queryOne(
    q,
    `UPDATE console_invoices
        SET amount_due_minor = $4,
            amount_paid_minor = $4,
            status = 'PAID',
            due_at_ms = NULL
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      RETURNING *`,
    [input.namespace, input.orgId, invoice.id, usageTotals.amountDueMinor],
  );
  if (!updated) {
    throw new ConsoleBillingError(
      'invoice_generate_failed',
      500,
      'Failed to update usage statement',
    );
  }
  return {
    invoice: parseInvoiceRow(updated),
    lineItems: nextLineItems,
  };
}

async function syncPurchaseReceiptProjection(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    purchaseId: string;
    amountMinor: number;
    creditPackId: BillingCreditPackId;
    createdAtMs: number;
  },
): Promise<BillingInvoice> {
  const invoiceId = `receipt_${input.purchaseId}`;
  const periodMonthUtc = monthUtc(new Date(input.createdAtMs));
  const invoiceRow = await queryOne(
    q,
    `INSERT INTO console_invoices
      (namespace, id, org_id, document_type, status, currency, amount_due_minor, amount_paid_minor, period_month_utc, created_at_ms, due_at_ms)
     VALUES
      ($1, $2, $3, 'PURCHASE_RECEIPT', 'PAID', 'USD', $4, $4, $5, $6, NULL)
     ON CONFLICT (namespace, id) DO UPDATE
       SET amount_due_minor = EXCLUDED.amount_due_minor,
           amount_paid_minor = EXCLUDED.amount_paid_minor
     RETURNING *`,
    [input.namespace, invoiceId, input.orgId, input.amountMinor, periodMonthUtc, input.createdAtMs],
  );
  if (!invoiceRow) {
    throw new ConsoleBillingError(
      'invoice_generate_failed',
      500,
      'Failed to create purchase receipt',
    );
  }
  await q.query(
    `DELETE FROM console_invoice_line_items
      WHERE namespace = $1 AND org_id = $2 AND invoice_id = $3`,
    [input.namespace, input.orgId, invoiceId],
  );
  await q.query(
    `INSERT INTO console_invoice_line_items
      (namespace, id, org_id, invoice_id, period_month_utc, item_type, description, quantity, unit_amount_minor, amount_minor, created_at_ms)
     VALUES
      ($1, $2, $3, $4, $5, 'CREDIT_TOP_UP', $6, 1, $7, $7, $8)`,
    [
      input.namespace,
      `ili_${invoiceId}_credit_top_up`,
      input.orgId,
      invoiceId,
      periodMonthUtc,
      `Prepaid credit top-up (${input.creditPackId})`,
      input.amountMinor,
      input.createdAtMs,
    ],
  );
  return parseInvoiceRow(invoiceRow);
}

async function syncBillingDocumentProjections(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    createdAtMs: number;
  },
): Promise<void> {
  const purchases = await q.query(
    `SELECT *
       FROM console_billing_credit_purchases
      WHERE namespace = $1
        AND org_id = $2
        AND status = 'SETTLED'
      ORDER BY settled_at_ms ASC NULLS LAST, created_at_ms ASC, id ASC`,
    [input.namespace, input.orgId],
  );
  for (const rawRow of purchases.rows) {
    const purchase = parseCreditPurchaseRow(rawRow as PgRow);
    await syncPurchaseReceiptProjection(q, {
      namespace: input.namespace,
      orgId: input.orgId,
      purchaseId: purchase.id,
      amountMinor: purchase.amountMinor,
      creditPackId: purchase.creditPackId,
      createdAtMs:
        purchase.settledAt == null
          ? Date.parse(purchase.createdAt)
          : Date.parse(purchase.settledAt),
    });
  }

  const statementMonths = new Map<string, number>();
  const ledgerMonths = await q.query(
    `SELECT month_utc, MIN(created_at_ms)::BIGINT AS first_created_at_ms
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND entry_type = 'USAGE_DEBIT'
        AND month_utc IS NOT NULL
      GROUP BY month_utc`,
    [input.namespace, input.orgId],
  );
  for (const row of ledgerMonths.rows) {
    const key = String((row as PgRow).month_utc || '').trim();
    if (!key) continue;
    statementMonths.set(key, toNumber((row as PgRow).first_created_at_ms));
  }
  const existingStatements = await q.query(
    `SELECT period_month_utc, created_at_ms
       FROM console_invoices
      WHERE namespace = $1
        AND org_id = $2
        AND document_type = 'USAGE_STATEMENT'`,
    [input.namespace, input.orgId],
  );
  for (const row of existingStatements.rows) {
    const key = String((row as PgRow).period_month_utc || '').trim();
    if (!key || statementMonths.has(key)) continue;
    statementMonths.set(key, toNumber((row as PgRow).created_at_ms));
  }
  for (const [periodMonthUtc, createdAtMs] of Array.from(statementMonths.entries()).sort()) {
    await syncUsageStatementProjection(q, {
      namespace: input.namespace,
      orgId: input.orgId,
      periodMonthUtc,
      createdAtMs: createdAtMs > 0 ? createdAtMs : input.createdAtMs,
    });
  }
}

async function settleCreditPurchase(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    purchaseId: string;
    settledAtMs: number;
  },
): Promise<{ purchase: BillingCreditPurchase; invoice: BillingInvoice }> {
  const purchaseRow = await queryOne(
    q,
    `SELECT *
       FROM console_billing_credit_purchases
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      FOR UPDATE`,
    [input.namespace, input.orgId, input.purchaseId],
  );
  if (!purchaseRow) {
    throw new ConsoleBillingError(
      'purchase_not_found',
      404,
      `Credit purchase ${input.purchaseId} was not found`,
    );
  }
  const current = parseCreditPurchaseRow(purchaseRow);
  const receiptInvoiceId = `receipt_${current.id}`;
  if (current.status === 'SETTLED') {
    const invoice = await syncPurchaseReceiptProjection(q, {
      namespace: input.namespace,
      orgId: input.orgId,
      purchaseId: current.id,
      amountMinor: current.amountMinor,
      creditPackId: current.creditPackId,
      createdAtMs: current.settledAt == null ? input.settledAtMs : Date.parse(current.settledAt),
    });
    const updatedRow =
      current.relatedInvoiceId === invoice.id
        ? purchaseRow
        : await queryOne(
            q,
            `UPDATE console_billing_credit_purchases
                SET related_invoice_id = $4,
                    settled_at_ms = COALESCE(settled_at_ms, $5),
                    updated_at_ms = $5
              WHERE namespace = $1 AND org_id = $2 AND id = $3
              RETURNING *`,
            [input.namespace, input.orgId, current.id, invoice.id, input.settledAtMs],
          );
    return {
      purchase: updatedRow ? parseCreditPurchaseRow(updatedRow) : current,
      invoice,
    };
  }

  await appendLedgerEntry(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    id: makeId('ble', new Date(input.settledAtMs)),
    type: 'CREDIT_PURCHASE',
    amountMinor: current.amountMinor,
    description: `Credit pack ${current.creditPackId} settled`,
    monthUtc: monthUtc(new Date(input.settledAtMs)),
    relatedInvoiceId: receiptInvoiceId,
    relatedPurchaseId: current.id,
    sourceEventId: current.providerCheckoutSessionRef,
    actorType: 'PROVIDER',
    reasonCode: 'stripe_checkout_settled',
    note: `Stripe checkout session ${current.providerCheckoutSessionRef} settled`,
    idempotencyKey: `credit_purchase_settlement:${current.id}`,
    createdAtMs: input.settledAtMs,
  });
  const invoice = await syncPurchaseReceiptProjection(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    purchaseId: current.id,
    amountMinor: current.amountMinor,
    creditPackId: current.creditPackId,
    createdAtMs: input.settledAtMs,
  });
  const updatedRow = await queryOne(
    q,
    `UPDATE console_billing_credit_purchases
        SET status = 'SETTLED',
            provider_customer_ref = COALESCE(provider_customer_ref, $4),
            related_invoice_id = $5,
            settled_at_ms = $6,
            updated_at_ms = $6
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      RETURNING *`,
    [
      input.namespace,
      input.orgId,
      current.id,
      current.providerCustomerRef || makeStripeCustomerRef(input.orgId),
      invoice.id,
      input.settledAtMs,
    ],
  );
  await syncProjectedOrgBalance(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    updatedAtMs: input.settledAtMs,
  });
  if (!updatedRow) {
    throw new ConsoleBillingError(
      'purchase_settlement_failed',
      500,
      'Failed to settle credit purchase',
    );
  }
  return {
    purchase: parseCreditPurchaseRow(updatedRow),
    invoice,
  };
}

function buildInvoiceListWhereClause(input: {
  namespace: string;
  orgId: string;
  request?: BillingInvoiceListRequest;
  referenceNowMs?: number;
  values?: unknown[];
}): { clause: string; values: unknown[] } {
  const values = input.values ? [...input.values] : [input.namespace, input.orgId];
  const clauses = ['namespace = $1', 'org_id = $2'];
  const request = input.request;
  if (request?.status) {
    values.push(request.status);
    clauses.push(`status = $${values.length}`);
  }
  if (request?.documentType) {
    values.push(request.documentType);
    clauses.push(`document_type = $${values.length}`);
  }
  if (request?.periodMonthUtc) {
    values.push(request.periodMonthUtc);
    clauses.push(`period_month_utc = $${values.length}`);
  }
  if (request?.overdueOnly) {
    clauses.push(`status = 'OPEN'`);
    clauses.push(`due_at_ms IS NOT NULL`);
    values.push(input.referenceNowMs ?? Date.now());
    clauses.push(`due_at_ms < $${values.length}`);
  }
  return {
    clause: clauses.join(' AND '),
    values,
  };
}

async function backfillLedgerAccountsAndPostings(q: Queryable): Promise<void> {
  await q.query(
    `INSERT INTO console_billing_ledger_accounts
      (namespace, id, scope_type, scope_org_id, account_code, currency, status, created_at_ms)
     SELECT DISTINCT namespace, platform_accounts.id, platform_accounts.scope_type, platform_accounts.scope_org_id, platform_accounts.account_code, 'USD', 'ACTIVE', 0
       FROM (
         SELECT namespace FROM console_billing_accounts
         UNION
         SELECT namespace FROM console_billing_ledger_entries
       ) namespaces
       CROSS JOIN (
         VALUES
           ('acct:processor_clearing:stripe', 'PLATFORM', NULL, 'processor_clearing:stripe'),
           ('acct:revenue_usage', 'PLATFORM', NULL, 'revenue_usage'),
           ('acct:expense_support_credit', 'PLATFORM', NULL, 'expense_support_credit'),
           ('acct:suspense_admin_debit', 'PLATFORM', NULL, 'suspense_admin_debit'),
           ('acct:suspense_reconciliation', 'PLATFORM', NULL, 'suspense_reconciliation')
       ) AS platform_accounts(id, scope_type, scope_org_id, account_code)
     ON CONFLICT (namespace, id) DO NOTHING`,
  );
  await q.query(
    `INSERT INTO console_billing_ledger_accounts
      (namespace, id, scope_type, scope_org_id, account_code, currency, status, created_at_ms)
     SELECT DISTINCT namespace,
       'acct:org_prepaid_liability:' || org_id,
       'ORG',
       org_id,
       'org_prepaid_liability:' || org_id,
       'USD',
       'ACTIVE',
       created_at_ms
      FROM (
        SELECT namespace, org_id, created_at_ms FROM console_billing_accounts
        UNION
        SELECT namespace, org_id, created_at_ms FROM console_billing_ledger_entries
      ) org_accounts
     ON CONFLICT (namespace, id) DO NOTHING`,
  );

  const rows = await q.query(
    `SELECT entry.*
       FROM console_billing_ledger_entries entry
      WHERE NOT EXISTS (
        SELECT 1
          FROM console_billing_ledger_postings posting
         WHERE posting.namespace = entry.namespace
           AND posting.entry_id = entry.id
      )
      ORDER BY entry.created_at_ms ASC, entry.id ASC`,
  );

  for (const rawRow of rows.rows) {
    const row = rawRow as PgRow;
    const entry = parseLedgerEntryRow(row);
    await ensureCanonicalLedgerAccounts(q, {
      namespace: String(row.namespace || ''),
      orgId: entry.orgId,
      createdAtMs: toNumber(row.created_at_ms),
    });
    await insertLedgerPostings(q, {
      namespace: String(row.namespace || ''),
      entryId: entry.id,
      createdAtMs: toNumber(row.created_at_ms),
      postings: buildLedgerPostingsForEntry({
        entryId: entry.id,
        orgId: entry.orgId,
        type: entry.type,
        amountMinor: entry.amountMinor,
        relatedInvoiceId: entry.relatedInvoiceId,
        relatedPurchaseId: entry.relatedPurchaseId,
        sourceEventId: entry.sourceEventId,
      }),
    });
  }

  await q.query(
    `UPDATE console_billing_accounts account
        SET credit_balance_minor = COALESCE(
              (
                SELECT SUM(
                  CASE posting.direction
                    WHEN 'CREDIT' THEN posting.amount_minor
                    ELSE -posting.amount_minor
                  END
                )::BIGINT
                  FROM console_billing_ledger_postings posting
                 WHERE posting.namespace = account.namespace
                   AND posting.org_id = account.org_id
                   AND posting.account_id = 'acct:org_prepaid_liability:' || account.org_id
              ),
              0
            )`,
  );
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
        usage_metric_version TEXT NOT NULL,
        monthly_active_wallets INTEGER NOT NULL,
        credit_balance_minor BIGINT NOT NULL,
        low_balance_threshold_minor BIGINT NOT NULL DEFAULT 2000,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id),
        CHECK (usage_metric_version IN ('maw_v1'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_billing_accounts
      DROP COLUMN IF EXISTS plan_id
    `);
    await pool.query(`
      ALTER TABLE console_billing_accounts
      DROP COLUMN IF EXISTS plan_name
    `);
    await pool.query(`
      ALTER TABLE console_billing_accounts
      ADD COLUMN IF NOT EXISTS low_balance_threshold_minor BIGINT NOT NULL DEFAULT 2000
    `);

    await pool.query(`
      DROP TABLE IF EXISTS console_subscriptions
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
        document_type TEXT NOT NULL DEFAULT 'USAGE_STATEMENT',
        status TEXT NOT NULL,
        currency TEXT NOT NULL,
        amount_due_minor BIGINT NOT NULL,
        amount_paid_minor BIGINT NOT NULL,
        period_month_utc TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        due_at_ms BIGINT,
        PRIMARY KEY (namespace, id),
        CHECK (document_type IN ('PURCHASE_RECEIPT', 'USAGE_STATEMENT')),
        CHECK (status IN ('OPEN', 'PAID', 'VOID', 'UNCOLLECTIBLE')),
        CHECK (currency IN ('USD'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_invoices
      ADD COLUMN IF NOT EXISTS document_type TEXT NOT NULL DEFAULT 'USAGE_STATEMENT'
    `);
    await pool.query(`
      ALTER TABLE console_invoices
      DROP COLUMN IF EXISTS rail_lock
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
      CREATE INDEX IF NOT EXISTS console_invoices_org_document_type_idx
      ON console_invoices (namespace, org_id, document_type, created_at_ms DESC)
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
        CHECK (item_type IN ('CREDIT_TOP_UP', 'MAW_USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT'))
      )
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_invoice_line_items
          DROP CONSTRAINT IF EXISTS console_invoice_line_items_item_type_check;
        ALTER TABLE console_invoice_line_items
          DROP CONSTRAINT IF EXISTS console_invoice_line_items_item_type_check_v2;
        ALTER TABLE console_invoice_line_items
          ADD CONSTRAINT console_invoice_line_items_item_type_check_v2
          CHECK (item_type IN ('CREDIT_TOP_UP', 'MAW_USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT'));
      END
      $$;
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_invoice_line_items_org_invoice_idx
      ON console_invoice_line_items (namespace, org_id, invoice_id, item_type)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_credit_purchases (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        credit_pack_id TEXT NOT NULL,
        status TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_checkout_session_ref TEXT NOT NULL,
        provider_customer_ref TEXT,
        related_invoice_id TEXT,
        settled_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, provider_checkout_session_ref),
        CHECK (credit_pack_id IN (${BILLING_CREDIT_PACK_ID_SQL})),
        CHECK (status IN ('PENDING', 'SETTLED', 'CANCELED')),
        CHECK (currency IN ('USD')),
        CHECK (provider IN ('stripe'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_billing_credit_purchases
      DROP CONSTRAINT IF EXISTS console_billing_credit_purchases_credit_pack_id_check
    `);
    await pool.query(`
      UPDATE console_billing_credit_purchases
      SET credit_pack_id = 'usd_custom'
      WHERE credit_pack_id IN ('usd_200', 'usd_500', 'usd_1000')
    `);
    await pool.query(`
      ALTER TABLE console_billing_credit_purchases
      ADD CONSTRAINT console_billing_credit_purchases_credit_pack_id_check
      CHECK (credit_pack_id IN (${BILLING_CREDIT_PACK_ID_SQL}))
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_credit_purchases_org_created_idx
      ON console_billing_credit_purchases (namespace, org_id, created_at_ms DESC)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_ledger_accounts (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        scope_type TEXT NOT NULL,
        scope_org_id TEXT,
        account_code TEXT NOT NULL,
        currency TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, account_code),
        CHECK (scope_type IN ('ORG', 'PLATFORM')),
        CHECK (currency IN ('USD')),
        CHECK (status IN ('ACTIVE'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_accounts_scope_idx
      ON console_billing_ledger_accounts (namespace, scope_type, scope_org_id)
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_ledger_entries (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        entry_type TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency TEXT NOT NULL,
        description TEXT NOT NULL,
        month_utc TEXT,
        related_invoice_id TEXT,
        related_purchase_id TEXT,
        source_event_id TEXT,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        UNIQUE (namespace, org_id, source_event_id),
        CHECK (entry_type IN ('CREDIT_PURCHASE', 'USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL')),
        CHECK (currency IN ('USD'))
      )
    `);
    await pool.query(`
      ALTER TABLE console_billing_ledger_entries
      ADD COLUMN IF NOT EXISTS actor_type TEXT NOT NULL DEFAULT 'SYSTEM'
    `);
    await pool.query(`
      ALTER TABLE console_billing_ledger_entries
      ADD COLUMN IF NOT EXISTS actor_user_id TEXT
    `);
    await pool.query(`
      ALTER TABLE console_billing_ledger_entries
      ADD COLUMN IF NOT EXISTS reason_code TEXT
    `);
    await pool.query(`
      ALTER TABLE console_billing_ledger_entries
      ADD COLUMN IF NOT EXISTS note TEXT
    `);
    await pool.query(`
      ALTER TABLE console_billing_ledger_entries
      ADD COLUMN IF NOT EXISTS idempotency_key TEXT
    `);
    await pool.query(`
      DO $$
      BEGIN
        ALTER TABLE console_billing_ledger_entries
          DROP CONSTRAINT IF EXISTS console_billing_ledger_entries_entry_type_check;
        ALTER TABLE console_billing_ledger_entries
          DROP CONSTRAINT IF EXISTS console_billing_ledger_entries_entry_type_check_v2;
        ALTER TABLE console_billing_ledger_entries
          ADD CONSTRAINT console_billing_ledger_entries_entry_type_check_v2
          CHECK (entry_type IN ('CREDIT_PURCHASE', 'USAGE_DEBIT', 'SPONSORED_EXECUTION_DEBIT', 'MANUAL_ADJUSTMENT', 'REFUND', 'REVERSAL'));
      END
      $$;
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_billing_ledger_entries_idempotency_key_idx
      ON console_billing_ledger_entries (namespace, idempotency_key)
      WHERE idempotency_key IS NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_created_idx
      ON console_billing_ledger_entries (namespace, org_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_entries_org_month_idx
      ON console_billing_ledger_entries (namespace, org_id, month_utc, created_at_ms DESC)
      WHERE month_utc IS NOT NULL
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_ledger_postings (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        entry_id TEXT NOT NULL,
        account_id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        direction TEXT NOT NULL,
        amount_minor BIGINT NOT NULL,
        currency TEXT NOT NULL,
        related_invoice_id TEXT,
        related_purchase_id TEXT,
        source_event_id TEXT,
        created_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (direction IN ('DEBIT', 'CREDIT')),
        CHECK (currency IN ('USD')),
        CHECK (amount_minor > 0)
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_postings_entry_idx
      ON console_billing_ledger_postings (namespace, entry_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_postings_org_account_idx
      ON console_billing_ledger_postings (namespace, org_id, account_id, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_ledger_postings_org_invoice_idx
      ON console_billing_ledger_postings (namespace, org_id, related_invoice_id, created_at_ms DESC)
      WHERE related_invoice_id IS NOT NULL
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_stripe_webhook_events (
        namespace TEXT NOT NULL,
        event_id TEXT NOT NULL,
        provider_ref TEXT NOT NULL,
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
      DROP INDEX IF EXISTS console_stripe_webhook_events_payment_intent_idx
    `);
    await pool.query(`
      ALTER TABLE console_stripe_webhook_events
      DROP COLUMN IF EXISTS payment_intent_id
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_payment_state_transitions
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_stablecoin_payment_intents
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_stablecoin_quotes
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_stripe_provider_refs
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_stripe_payment_intents
    `);
    await pool.query(`
      DROP TABLE IF EXISTS console_payment_methods
    `);
    await pool.query(`
      DROP FUNCTION IF EXISTS console_reject_payment_state_transition_mutation()
    `);

    await backfillLedgerAccountsAndPostings(pool);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_accounts',
      policyName: 'console_billing_accounts_tenant_rls',
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
      table: 'console_billing_credit_purchases',
      policyName: 'console_billing_credit_purchases_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_ledger_entries',
      policyName: 'console_billing_ledger_entries_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_ledger_postings',
      policyName: 'console_billing_ledger_postings_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_stripe_webhook_events',
      policyName: 'console_stripe_webhook_events_tenant_rls',
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

  async function processStripeWebhookEventInternal(
    request: StripeWebhookEventRequest,
  ): Promise<StripeWebhookEventResult> {
    const now = nowFn();
    const eventType = String(request.eventType || 'checkout.session.completed')
      .trim()
      .toLowerCase();
    if (eventType !== 'checkout.session.completed') {
      return {
        accepted: true,
        purchase: null,
        invoice: null,
        orgId: null,
      };
    }
    let currentOrgId: string | null = String(request.orgId || '').trim() || null;
    let matchedPurchaseId: string | null = null;
    let eventProviderRef = String(request.providerRef || '').trim();
    const checkoutSessionRef = String(
      request.checkoutSessionId || request.providerRef || '',
    ).trim();
    const providerCustomerRef = String(request.providerCustomerRef || '').trim();
    if (!currentOrgId && (checkoutSessionRef || providerCustomerRef)) {
      const purchaseMatch = await queryOne(
        pool,
        `SELECT org_id, id
           FROM console_billing_credit_purchases
          WHERE namespace = $1
            AND (
              provider_checkout_session_ref = $2
              OR ($3 <> '' AND provider_customer_ref = $3)
            )
          ORDER BY created_at_ms DESC
          LIMIT 1`,
        [namespace, checkoutSessionRef, providerCustomerRef],
      );
      currentOrgId = purchaseMatch?.org_id ? String(purchaseMatch.org_id || '').trim() : null;
      matchedPurchaseId = purchaseMatch?.id ? String(purchaseMatch.id || '').trim() : null;
    }
    eventProviderRef =
      eventProviderRef || checkoutSessionRef || providerCustomerRef || eventType || 'stripe_event';

    if (!currentOrgId) {
      return {
        accepted: true,
        purchase: null,
        invoice: null,
        orgId: null,
      };
    }

    return withConsoleTenantContextTx(pool, { namespace, orgId: currentOrgId }, async (q) => {
      const inserted = await queryOne(
        q,
        `INSERT INTO console_stripe_webhook_events
            (namespace, event_id, provider_ref, org_id, processed_at_ms)
           VALUES
            ($1, $2, $3, $4, $5)
           ON CONFLICT (namespace, event_id) DO NOTHING
           RETURNING event_id`,
        [namespace, request.eventId, eventProviderRef, currentOrgId, nowMs(now)],
      );
      if (!inserted) {
        const existingPurchaseRow = matchedPurchaseId
          ? await queryOne(
              q,
              `SELECT *
                 FROM console_billing_credit_purchases
                WHERE namespace = $1 AND org_id = $2 AND id = $3`,
              [namespace, currentOrgId, matchedPurchaseId],
            )
          : await queryOne(
              q,
              `SELECT *
                 FROM console_billing_credit_purchases
                WHERE namespace = $1
                  AND org_id = $2
                  AND provider_checkout_session_ref = $3
                ORDER BY created_at_ms DESC
                LIMIT 1`,
              [namespace, currentOrgId, checkoutSessionRef],
            );
        const existingInvoiceRow =
          existingPurchaseRow?.related_invoice_id == null
            ? null
            : await queryOne(
                q,
                `SELECT *
                   FROM console_invoices
                  WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                [namespace, currentOrgId, String(existingPurchaseRow.related_invoice_id || '')],
              );
        return {
          accepted: false,
          purchase: existingPurchaseRow ? parseCreditPurchaseRow(existingPurchaseRow) : null,
          invoice: existingInvoiceRow ? parseInvoiceRow(existingInvoiceRow) : null,
          orgId: currentOrgId,
        };
      }

      let projectedPurchase: BillingCreditPurchase | null = null;
      let projectedInvoice: BillingInvoice | null = null;
      const purchaseRow = matchedPurchaseId
        ? await queryOne(
            q,
            `SELECT *
               FROM console_billing_credit_purchases
              WHERE namespace = $1 AND org_id = $2 AND id = $3
              FOR UPDATE`,
            [namespace, currentOrgId, matchedPurchaseId],
          )
        : await queryOne(
            q,
            `SELECT *
               FROM console_billing_credit_purchases
              WHERE namespace = $1
                AND org_id = $2
                AND provider_checkout_session_ref = $3
              ORDER BY created_at_ms DESC
              LIMIT 1
              FOR UPDATE`,
            [namespace, currentOrgId, checkoutSessionRef],
          );
      if (purchaseRow) {
        const settled = await settleCreditPurchase(q, {
          namespace,
          orgId: currentOrgId,
          purchaseId: String(purchaseRow.id || ''),
          settledAtMs: nowMs(now),
        });
        projectedPurchase = settled.purchase;
        projectedInvoice = settled.invoice;
      }

      if (!projectedPurchase && matchedPurchaseId) {
        const currentPurchaseRow = await queryOne(
          q,
          `SELECT *
             FROM console_billing_credit_purchases
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, currentOrgId, matchedPurchaseId],
        );
        projectedPurchase = currentPurchaseRow ? parseCreditPurchaseRow(currentPurchaseRow) : null;
      }
      if (!projectedInvoice && projectedPurchase?.relatedInvoiceId) {
        const invoiceRow = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, currentOrgId, projectedPurchase.relatedInvoiceId],
        );
        projectedInvoice = invoiceRow ? parseInvoiceRow(invoiceRow) : null;
      }

      return {
        accepted: true,
        purchase: projectedPurchase,
        invoice: projectedInvoice,
        orgId: currentOrgId,
      };
    });
  }

  const runtime: ConsoleBillingPostgresRuntime = {
    pool,
    namespace,
    now: nowFn,
  };

  const service: ConsoleBillingPostgresService = {
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

        const documentStats = await queryOne(
          q,
          `SELECT
              COUNT(*)::BIGINT AS document_count
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2`,
          [namespace, ctx.orgId],
        );

        const monthlyActiveWallets = await countMonthlyActiveWallets(
          q,
          namespace,
          ctx.orgId,
          currentMonthUtc,
        );
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
        const creditBalanceMinor = await getProjectedOrgBalanceMinor(q, namespace, ctx.orgId);
        await upsertMonthlyActiveWalletRollup(q, {
          namespace,
          orgId: ctx.orgId,
          monthUtc: currentMonthUtc,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });
        await syncBillingAccountSnapshot(q, {
          namespace,
          orgId: ctx.orgId,
          creditBalanceMinor,
          monthlyActiveWallets,
          updatedAtMs: nowMs(now),
        });

        const recentUsageDebitMinor = await getCurrentMonthUsageDebitMinor(
          q,
          namespace,
          ctx.orgId,
          currentMonthUtc,
        );
        const recentCreditPurchasedMinor = await getCurrentMonthPurchasedMinor(
          q,
          namespace,
          ctx.orgId,
          currentMonthUtc,
        );

        return {
          usageMetricVersion: 'maw_v1',
          currentMonthUtc,
          monthlyActiveWallets,
          creditBalanceMinor,
          lowBalanceThresholdMinor: toNumber(account.low_balance_threshold_minor),
          liveEnvironmentState: resolveBillingLiveEnvironmentState({
            creditBalanceMinor,
            lowBalanceThresholdMinor: toNumber(account.low_balance_threshold_minor),
          }),
          recentUsageDebitMinor,
          recentCreditPurchasedMinor,
          documentCount: toNumber(documentStats?.document_count),
        };
      });
    },

    async getSponsoredExecutionDebitsByIds(
      ctx: ConsoleBillingContext,
      ledgerEntryIds: string[],
    ): Promise<BillingSponsoredExecutionDebitEntry[]> {
      return withOrgTx(ctx, async (q) => {
        const ids = Array.from(
          new Set(
            ledgerEntryIds
              .map((entryId) => String(entryId || '').trim())
              .filter((entryId) => entryId.length > 0),
          ),
        );
        if (ids.length === 0) return [];
        const rows = await q.query(
          `SELECT *
             FROM console_billing_ledger_entries
            WHERE namespace = $1
              AND org_id = $2
              AND entry_type = 'SPONSORED_EXECUTION_DEBIT'
              AND id = ANY($3::TEXT[])
            ORDER BY created_at_ms DESC, id DESC`,
          [namespace, ctx.orgId, ids],
        );
        return rows.rows.map(
          (row) => parseLedgerEntryRow(row as PgRow) as BillingSponsoredExecutionDebitEntry,
        );
      });
    },

    async listAccountActivity(
      ctx: ConsoleBillingContext,
      request: BillingAccountActivityRequest = {},
    ): Promise<BillingAccountActivityResult> {
      return withOrgTx(ctx, async (q) => {
        const limit = normalizeAccountActivityLimit(request.limit);
        const where: string[] = ['namespace = $1', 'org_id = $2'];
        const values: unknown[] = [namespace, ctx.orgId];
        if (request.periodMonthUtc) {
          values.push(parseMonthUtcOrThrow(request.periodMonthUtc));
          where.push(`month_utc = $${values.length}`);
        }
        if (request.eventType) {
          values.push(request.eventType);
          where.push(`entry_type = $${values.length}`);
        }
        values.push(limit);
        const rows = await q.query(
          `SELECT *
             FROM console_billing_ledger_entries
            WHERE ${where.join(' AND ')}
            ORDER BY created_at_ms DESC, id DESC
            LIMIT $${values.length}`,
          values,
        );
        return {
          entries: rows.rows.map((row) => parseLedgerEntryRow(row as PgRow)),
        };
      });
    },

    async getMonthlyActiveWallets(
      ctx: ConsoleBillingContext,
      monthUtcInput?: string,
    ): Promise<BillingMonthlyActiveWallets> {
      return withOrgTx(ctx, async (q, now) => {
        const resolvedMonthUtc = monthUtcInput
          ? parseMonthUtcOrThrow(monthUtcInput)
          : monthUtc(now);
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
        const walletWasAlreadyCounted = counted
          ? Boolean(
              await queryOne(
                q,
                `SELECT id
                   FROM console_usage_meter_events
                  WHERE namespace = $1
                    AND org_id = $2
                    AND month_utc = $3
                    AND wallet_id = $4
                    AND succeeded = TRUE
                    AND is_simulation = FALSE
                    AND is_internal_retry = FALSE
                    AND action IN ('transfer', 'swap', 'approve', 'contract_call')
                  LIMIT 1`,
                [namespace, ctx.orgId, eventMonthUtc, request.walletId],
              ),
            )
          : false;

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

        let debitAppliedMinor = 0;
        let statementId: string | null = null;

        if (inserted && counted && !walletWasAlreadyCounted) {
          const existingDebit = await queryOne(
            q,
            `SELECT id
               FROM console_billing_ledger_entries
              WHERE namespace = $1
                AND org_id = $2
                AND entry_type = 'USAGE_DEBIT'
                AND source_event_id = $3`,
            [namespace, ctx.orgId, request.sourceEventId || eventId],
          );
          if (!existingDebit) {
            debitAppliedMinor = MAW_USAGE_DEBIT_MINOR;
            await appendLedgerEntry(q, {
              namespace,
              orgId: ctx.orgId,
              id: makeId('ble', now),
              type: 'USAGE_DEBIT',
              amountMinor: -MAW_USAGE_DEBIT_MINOR,
              description: `MAW usage debit for ${request.walletId} (${eventMonthUtc})`,
              monthUtc: eventMonthUtc,
              relatedInvoiceId: makeBootstrapUsageStatementId(ctx.orgId, eventMonthUtc),
              relatedPurchaseId: null,
              sourceEventId: request.sourceEventId || eventId,
              actorType: 'USER',
              actorUserId: ctx.actorUserId,
              reasonCode: 'usage_debit',
              note: `Usage debit recorded for wallet ${request.walletId}`,
              idempotencyKey: `usage_debit:${request.sourceEventId || eventId}`,
              createdAtMs: nowMs(now),
            });
          }
        }

        const statement = await syncUsageStatementProjection(q, {
          namespace,
          orgId: ctx.orgId,
          periodMonthUtc: eventMonthUtc,
          createdAtMs: nowMs(now),
        });
        statementId = statement.invoice.id;

        const creditBalanceMinor = await syncProjectedOrgBalance(q, {
          namespace,
          orgId: ctx.orgId,
          updatedAtMs: nowMs(now),
        });

        return {
          accepted: Boolean(inserted),
          counted: inserted ? counted : false,
          monthUtc: eventMonthUtc,
          monthlyActiveWallets,
          debitAppliedMinor,
          creditBalanceMinor,
          statementId,
        };
      });
    },

    async recordSponsoredExecutionDebit(
      ctx: ConsoleBillingContext,
      request: BillingSponsoredExecutionDebitRequest,
    ): Promise<BillingSponsoredExecutionDebitResult> {
      return withOrgTx(
        ctx,
        async (q, currentNow) =>
          (
            await recordSponsoredExecutionDebitTx(q, {
              namespace,
              ctx,
              now: currentNow,
              request,
            })
          ).result,
      );
    },

    async listInvoices(ctx: ConsoleBillingContext): Promise<BillingInvoice[]> {
      return withOrgTx(ctx, async (q, now) => {
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
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

    async listInvoicesPage(
      ctx: ConsoleBillingContext,
      request: BillingInvoiceListRequest = {},
    ): Promise<BillingInvoiceListResult> {
      return withOrgTx(ctx, async (q, now) => {
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
        const limit = normalizeInvoiceListLimit(request.limit);
        const cursor = parseInvoiceCursor(request.cursor);
        const baseWhere = buildInvoiceListWhereClause({
          namespace,
          orgId: ctx.orgId,
          request,
          referenceNowMs: nowMs(now),
        });

        const pageValues = [...baseWhere.values];
        let cursorClause = '';
        if (cursor) {
          pageValues.push(cursor.createdAtMs, cursor.id);
          cursorClause = ` AND (created_at_ms < $${pageValues.length - 1} OR (created_at_ms = $${pageValues.length - 1} AND id < $${pageValues.length}))`;
        }
        pageValues.push(limit + 1);
        const pageRows = await q.query(
          `SELECT *
             FROM console_invoices
            WHERE ${baseWhere.clause}${cursorClause}
            ORDER BY created_at_ms DESC, id DESC
            LIMIT $${pageValues.length}`,
          pageValues,
        );

        const summaryRow = await queryOne(
          q,
          `SELECT
              COUNT(*)::BIGINT AS total_count,
              COUNT(*) FILTER (WHERE status = 'OPEN')::BIGINT AS open_count,
              COUNT(*) FILTER (WHERE status = 'OPEN' AND due_at_ms IS NOT NULL AND due_at_ms < $${baseWhere.values.length + 1})::BIGINT AS overdue_count,
              COUNT(*) FILTER (WHERE status = 'PAID')::BIGINT AS paid_count,
              COUNT(*) FILTER (WHERE document_type = 'PURCHASE_RECEIPT')::BIGINT AS receipt_count,
              COUNT(*) FILTER (WHERE document_type = 'USAGE_STATEMENT')::BIGINT AS statement_count,
              COALESCE(SUM(GREATEST(amount_due_minor - amount_paid_minor, 0)), 0)::BIGINT AS outstanding_amount_minor,
              (ARRAY_AGG(period_month_utc ORDER BY created_at_ms DESC, id DESC))[1] AS latest_period_month_utc
             FROM console_invoices
            WHERE ${baseWhere.clause}`,
          [...baseWhere.values, nowMs(now)],
        );
        const hasMore = pageRows.rows.length > limit;
        const invoices = (hasMore ? pageRows.rows.slice(0, limit) : pageRows.rows).map((row) =>
          parseInvoiceRow(row as PgRow),
        );
        return {
          invoices,
          nextCursor:
            hasMore && invoices.length > 0
              ? encodeInvoiceCursor(invoices[invoices.length - 1])
              : null,
          totalCount: Number(summaryRow?.total_count || 0),
          summary: {
            totalCount: Number(summaryRow?.total_count || 0),
            openCount: Number(summaryRow?.open_count || 0),
            overdueCount: Number(summaryRow?.overdue_count || 0),
            paidCount: Number(summaryRow?.paid_count || 0),
            outstandingAmountMinor: Number(summaryRow?.outstanding_amount_minor || 0),
            receiptCount: Number(summaryRow?.receipt_count || 0),
            statementCount: Number(summaryRow?.statement_count || 0),
            latestPeriodMonthUtc:
              summaryRow?.latest_period_month_utc == null
                ? null
                : String(summaryRow.latest_period_month_utc || '').trim() || null,
          },
        };
      });
    },

    async getInvoice(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoice | null> {
      return withOrgTx(ctx, async (q, now) => {
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
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

    async getInvoiceActivity(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceActivity | null> {
      return withOrgTx(ctx, async (q, now) => {
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
        const invoiceRow = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1 AND org_id = $2 AND id = $3`,
          [namespace, ctx.orgId, invoiceId],
        );
        if (!invoiceRow) return null;
        const invoice = parseInvoiceRow(invoiceRow);
        const ledgerRows = await q.query(
          `SELECT *
             FROM console_billing_ledger_entries
            WHERE namespace = $1 AND org_id = $2 AND related_invoice_id = $3
            ORDER BY created_at_ms DESC, id DESC`,
          [namespace, ctx.orgId, invoiceId],
        );

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
          } satisfies BillingInvoiceActivityEntry,
          ...ledgerRows.rows.map((rawRow) => {
            const row = parseLedgerEntryRow(rawRow as PgRow);
            const actorType = String((rawRow as PgRow).actor_type || 'SYSTEM')
              .trim()
              .toUpperCase();
            return {
              id: row.id,
              type: 'LEDGER',
              invoiceId: invoice.id,
              fromState: null,
              toState: row.type,
              occurredAt: row.createdAt,
              actorType: actorType === 'USER' || actorType === 'PROVIDER' ? actorType : 'SYSTEM',
              actorUserId:
                (rawRow as PgRow).actor_user_id == null
                  ? null
                  : String((rawRow as PgRow).actor_user_id || '').trim() || null,
              reason:
                (rawRow as PgRow).reason_code == null
                  ? row.type.toLowerCase()
                  : String((rawRow as PgRow).reason_code || '').trim() || row.type.toLowerCase(),
              sourceEventId: row.sourceEventId,
              summary: row.description,
              visibility: row.type === 'MANUAL_ADJUSTMENT' ? 'INTERNAL' : 'CUSTOMER',
            } satisfies BillingInvoiceActivityEntry;
          }),
        ].sort((left, right) => {
          const tsDiff = Date.parse(right.occurredAt) - Date.parse(left.occurredAt);
          if (tsDiff !== 0) return tsDiff;
          return right.id.localeCompare(left.id);
        });

        return {
          invoice,
          entries,
        };
      });
    },

    async listInvoiceLineItems(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoiceLineItem[]> {
      return withOrgTx(ctx, async (q, now) => {
        await syncBillingDocumentProjections(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(now),
        });
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
        await reconcileUsageDebitCoverage(q, {
          namespace,
          orgId: ctx.orgId,
          periodMonthUtc,
          monthlyActiveWallets,
          createdAtMs: nowMs(now),
        });

        const existingStatement = await queryOne(
          q,
          `SELECT *
             FROM console_invoices
            WHERE namespace = $1
              AND org_id = $2
              AND document_type = 'USAGE_STATEMENT'
              AND period_month_utc = $3`,
          [namespace, ctx.orgId, periodMonthUtc],
        );
        const previousInvoice = existingStatement ? parseInvoiceRow(existingStatement) : null;
        const previousLineItems = previousInvoice
          ? await listInvoiceLineItemsByInvoice(q, namespace, ctx.orgId, previousInvoice.id)
          : [];
        const synced = await syncUsageStatementProjection(q, {
          namespace,
          orgId: ctx.orgId,
          periodMonthUtc,
          createdAtMs: nowMs(now),
        });
        const generated =
          !previousInvoice ||
          previousInvoice.amountDueMinor !== synced.invoice.amountDueMinor ||
          !lineItemsEquivalent(previousLineItems, synced.lineItems);

        return {
          generated,
          invoice: synced.invoice,
          lineItems: sortLineItems(synced.lineItems),
          monthlyActiveWallets,
          pricing: {
            mawUnitPriceMinor: MAW_USAGE_DEBIT_MINOR,
          },
        };
      });
    },

    async grantManualSupportCredit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      return withOrgTx(ctx, async (q, now) => {
        const existing = await findLedgerEntryByIdempotencyKey(q, {
          namespace,
          orgId: ctx.orgId,
          idempotencyKey: normalizedRequest.idempotencyKey,
        });
        if (existing) {
          const creditBalanceMinor = await syncProjectedOrgBalance(q, {
            namespace,
            orgId: ctx.orgId,
            updatedAtMs: nowMs(now),
          });
          return {
            created: false,
            adjustment: existing,
            creditBalanceMinor,
          };
        }
        const relatedInvoiceId = await ensureManualAdjustmentRelatedInvoiceId(q, {
          namespace,
          orgId: ctx.orgId,
          relatedInvoiceId: normalizedRequest.relatedInvoiceId,
        });
        const adjustment = await appendLedgerEntry(q, {
          namespace,
          orgId: ctx.orgId,
          id: makeId('ble', now),
          type: 'MANUAL_ADJUSTMENT',
          amountMinor: normalizedRequest.amountMinor,
          description: `Manual support credit (${normalizedRequest.reasonCode})`,
          monthUtc: monthUtc(now),
          relatedInvoiceId,
          relatedPurchaseId: null,
          sourceEventId: null,
          actorType: 'USER',
          actorUserId: ctx.actorUserId,
          reasonCode: normalizedRequest.reasonCode,
          note: normalizedRequest.note,
          idempotencyKey: normalizedRequest.idempotencyKey,
          createdAtMs: nowMs(now),
        });
        const creditBalanceMinor = await syncProjectedOrgBalance(q, {
          namespace,
          orgId: ctx.orgId,
          updatedAtMs: nowMs(now),
        });
        return {
          created: true,
          adjustment,
          creditBalanceMinor,
        };
      });
    },

    async appendManualAdminDebit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
      requireBillingAdjustmentRole(ctx);
      const normalizedRequest = normalizeManualAdjustmentRequest(request);
      return withOrgTx(ctx, async (q, now) => {
        const existing = await findLedgerEntryByIdempotencyKey(q, {
          namespace,
          orgId: ctx.orgId,
          idempotencyKey: normalizedRequest.idempotencyKey,
        });
        if (existing) {
          requireLargeManualAdminDebitEscalationRole(ctx, Math.abs(existing.amountMinor));
          const creditBalanceMinor = await syncProjectedOrgBalance(q, {
            namespace,
            orgId: ctx.orgId,
            updatedAtMs: nowMs(now),
          });
          return {
            created: false,
            adjustment: existing,
            creditBalanceMinor,
          };
        }
        requireLargeManualAdminDebitEscalationRole(ctx, normalizedRequest.amountMinor);
        const relatedInvoiceId = await ensureManualAdjustmentRelatedInvoiceId(q, {
          namespace,
          orgId: ctx.orgId,
          relatedInvoiceId: normalizedRequest.relatedInvoiceId,
        });
        const adjustment = await appendLedgerEntry(q, {
          namespace,
          orgId: ctx.orgId,
          id: makeId('ble', now),
          type: 'MANUAL_ADJUSTMENT',
          amountMinor: -normalizedRequest.amountMinor,
          description: `Manual admin debit (${normalizedRequest.reasonCode})`,
          monthUtc: monthUtc(now),
          relatedInvoiceId,
          relatedPurchaseId: null,
          sourceEventId: null,
          actorType: 'USER',
          actorUserId: ctx.actorUserId,
          reasonCode: normalizedRequest.reasonCode,
          note: normalizedRequest.note,
          idempotencyKey: normalizedRequest.idempotencyKey,
          createdAtMs: nowMs(now),
        });
        const creditBalanceMinor = await syncProjectedOrgBalance(q, {
          namespace,
          orgId: ctx.orgId,
          updatedAtMs: nowMs(now),
        });
        return {
          created: true,
          adjustment,
          creditBalanceMinor,
        };
      });
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      return withOrgTx(ctx, async (q, now) => {
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
        const purchaseRow = await queryOne(
          q,
          `INSERT INTO console_billing_credit_purchases
            (namespace, id, org_id, credit_pack_id, status, amount_minor, currency, provider, provider_checkout_session_ref, provider_customer_ref, related_invoice_id, settled_at_ms, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, 'PENDING', $5, 'USD', 'stripe', $6, $7, NULL, NULL, $8, $8)
           RETURNING *`,
          [
            namespace,
            makeId('bcp', now),
            ctx.orgId,
            request.creditPackId,
            amountMinor,
            id,
            customerRef,
            nowMs(now),
          ],
        );
        if (!purchaseRow) {
          throw new ConsoleBillingError(
            'checkout_session_create_failed',
            500,
            'Failed to record checkout purchase',
          );
        }
        return {
          id,
          url,
          customerRef,
          creditPackId: request.creditPackId,
          amountMinor,
          expiresAt,
        };
      });
    },

    async reconcileStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionReconcileRequest,
    ): Promise<StripeCheckoutSessionReconcileResult> {
      const checkoutSessionId = String(request.checkoutSessionId || '').trim();
      if (!checkoutSessionId) {
        throw new ConsoleBillingError('invalid_body', 400, 'Field checkoutSessionId is required');
      }
      const existingPurchaseRow = await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: ctx.orgId },
        (q) =>
          queryOne(
            q,
            `SELECT *
               FROM console_billing_credit_purchases
              WHERE namespace = $1
                AND org_id = $2
                AND provider_checkout_session_ref = $3
              ORDER BY created_at_ms DESC
              LIMIT 1`,
            [namespace, ctx.orgId, checkoutSessionId],
          ),
      );
      if (!existingPurchaseRow) {
        throw new ConsoleBillingError(
          'purchase_not_found',
          404,
          `No credit purchase found for Stripe checkout session ${checkoutSessionId}`,
        );
      }
      const existingPurchase = parseCreditPurchaseRow(existingPurchaseRow);
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
        const invoiceRow =
          existingPurchase.relatedInvoiceId == null
            ? null
            : await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, (q) =>
                queryOne(
                  q,
                  `SELECT *
                     FROM console_invoices
                    WHERE namespace = $1 AND org_id = $2 AND id = $3`,
                  [namespace, ctx.orgId, existingPurchase.relatedInvoiceId],
                ),
              );
        return {
          settled: existingPurchase.status === 'SETTLED',
          settledNow: false,
          purchase: existingPurchase,
          invoice: invoiceRow ? parseInvoiceRow(invoiceRow) : null,
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
          String(existingPurchase.providerCustomerRef || '').trim() ||
          undefined,
        providerRef: checkoutSessionId,
      });
      return {
        settled: result.purchase?.status === 'SETTLED',
        settledNow: existingPurchase.status !== 'SETTLED' && result.purchase?.status === 'SETTLED',
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
    [CONSOLE_BILLING_POSTGRES_RUNTIME]: runtime,
  };

  return service;
}

export async function recordSponsoredExecutionDebitTx(
  q: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleBillingContext;
    now: Date;
    request: BillingSponsoredExecutionDebitRequest;
  },
): Promise<{
  result: BillingSponsoredExecutionDebitResult;
  ledgerEntry: BillingLedgerEntry | null;
}> {
  const sourceEventId = String(input.request.sourceEventId || '').trim();
  if (!sourceEventId) {
    throw new ConsoleBillingError(
      'invalid_sponsored_execution_debit',
      400,
      'sourceEventId is required',
    );
  }
  if (!Number.isInteger(input.request.amountMinor) || input.request.amountMinor <= 0) {
    throw new ConsoleBillingError(
      'invalid_sponsored_execution_debit',
      400,
      'amountMinor must be a positive integer',
    );
  }
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
  const eventMonthUtc = monthUtc(new Date(occurredAtMs));
  const existingDebit = await queryOne(
    q,
    `SELECT *
       FROM console_billing_ledger_entries
      WHERE namespace = $1
        AND org_id = $2
        AND entry_type = 'SPONSORED_EXECUTION_DEBIT'
        AND source_event_id = $3`,
    [input.namespace, input.ctx.orgId, sourceEventId],
  );
  let ledgerEntry: BillingLedgerEntry | null = existingDebit
    ? parseLedgerEntryRow(existingDebit)
    : null;
  if (!ledgerEntry) {
    ledgerEntry = await appendLedgerEntry(q, {
      namespace: input.namespace,
      orgId: input.ctx.orgId,
      id: makeId('ble', input.now),
      type: 'SPONSORED_EXECUTION_DEBIT',
      amountMinor: -input.request.amountMinor,
      description: `Sponsored execution debit for ${input.request.walletId}`,
      monthUtc: eventMonthUtc,
      relatedInvoiceId: makeBootstrapUsageStatementId(input.ctx.orgId, eventMonthUtc),
      relatedPurchaseId: null,
      sourceEventId,
      actorType: 'SYSTEM',
      actorUserId: input.ctx.actorUserId,
      reasonCode: 'sponsored_execution_debit',
      note:
        String(input.request.note || '').trim() ||
        [
          input.request.txOrExecutionRef ? `Ref ${input.request.txOrExecutionRef}` : '',
          input.request.pricingVersion ? `Pricing ${input.request.pricingVersion}` : '',
        ]
          .filter(Boolean)
          .join(' · ') ||
        `Sponsored execution debit recorded for ${input.request.walletId}`,
      idempotencyKey: `sponsored_execution_debit:${sourceEventId}`,
      createdAtMs: occurredAtMs,
    });
  }
  const statement = await syncUsageStatementProjection(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    periodMonthUtc: eventMonthUtc,
    createdAtMs: nowMs(input.now),
  });
  const creditBalanceMinor = await syncProjectedOrgBalance(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    updatedAtMs: nowMs(input.now),
  });
  return {
    result: {
      accepted: !existingDebit,
      debitAppliedMinor: existingDebit ? 0 : input.request.amountMinor,
      ledgerEntryId: ledgerEntry.id,
      creditBalanceMinor,
      monthUtc: eventMonthUtc,
      statementId: statement.invoice.id,
    },
    ledgerEntry,
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
