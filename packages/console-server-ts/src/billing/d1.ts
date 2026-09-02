import { secureRandomBase36 } from '../boundary';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  queryD1All,
  queryD1One,
  type D1Row,
} from '../boundary';
import type { D1DatabaseLike, D1PreparedStatementLike, D1ResultLike } from '../boundary';
import { normalizeManualAdjustmentRequest } from './adjustments';
import { resolveCreditPackAmountMinorOrThrow } from './creditPacks';
import { ConsoleBillingError } from './errors';
import { createConsoleEmailOutboxInsertStatement } from '../email/d1';
import {
  buildBillingRefundResultEmailV1,
  buildPrepaidTopUpReceiptEmailV1,
} from '../email/templates';
import type { ConsoleEmailNonInvitationTemplateV1 } from '../email/types';
import {
  resolveBillingProviderAdapters,
  type BillingProviderAdapters,
  type StripeRefundProviderOutput,
} from './providers';
import { resolveBillingLiveEnvironmentState } from './readiness';
import { assertBillingEntryBalances } from './ledger';
import {
  buildBillingStripePostProcessingPayload,
  parseBillingStripePostProcessingPayload,
  type BillingStripePostProcessingEffect,
  type BillingStripePostProcessingOutboxItem,
} from './stripePostProcessing';
import {
  encodeInvoiceCursor,
  buildStripeCheckoutReturnUrls,
  normalizeRefundRequest,
  parseInvoiceCursor,
  providerRefundTransitionAllowed,
  requireRefundSupportContext,
  type ConsoleBillingContext,
  type ConsoleBillingRefundSupportContext,
  type ConsoleBillingService,
} from './service';
import type {
  BillingAccountActivityRequest,
  BillingAccountActivityResult,
  BillingCreditPackId,
  BillingCreditPurchase,
  BillingCreditPurchaseStatus,
  BillingDispute,
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
  BillingLedgerAccountCode,
  BillingLedgerCreditPosting,
  BillingLedgerDebitPosting,
  BillingManualAdjustmentRequest,
  BillingManualAdjustmentResult,
  BillingMonthlyActiveResources,
  BillingOverview,
  BillingRefund,
  BillingRefundReconcileRequest,
  BillingRefundRequest,
  BillingRefundResult,
  BillingRefundStatus,
  BillingProductExecutionDebitEntry,
  BillingProductExecutionDebitRequest,
  BillingProductExecutionDebitResult,
  BillingUsageEventRequest,
  BillingUsageEventResult,
  GenerateMonthlyInvoiceRequest,
  GenerateMonthlyInvoiceResult,
  StripeCheckoutSession,
  StripeCheckoutSessionReconcileRequest,
  StripeCheckoutSessionReconcileResult,
  StripeCheckoutSessionRequest,
  StripeRefundEventItem,
  StripeWebhookEventRequest,
  StripeWebhookEventResult,
} from './types';

const ACTIVE_RESOURCE_USAGE_DEBIT_MINOR = 300;
const DEFAULT_LOW_BALANCE_THRESHOLD_MINOR = 2000;
const DEFAULT_INVOICE_LIST_LIMIT = 25;
const MAX_INVOICE_LIST_LIMIT = 100;
const DEFAULT_ACCOUNT_ACTIVITY_LIMIT = 25;
const MAX_ACCOUNT_ACTIVITY_LIMIT = 100;

export const CONSOLE_BILLING_D1_RUNTIME = Symbol('consoleBillingD1Runtime');

export interface ConsoleBillingD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
  emailConsoleBaseUrl?: string;
}

export type ConsoleBillingD1Service = ConsoleBillingService & {
  [CONSOLE_BILLING_D1_RUNTIME]: ConsoleBillingD1Runtime;
};

export interface D1ConsoleBillingServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  now?: () => Date;
  providers?: Partial<BillingProviderAdapters>;
  emailConsoleBaseUrl?: string;
  consoleBaseUrl?: string;
}

export interface D1ConsoleBillingMonthlyFinalizationOptions {
  database: D1DatabaseLike;
  namespace?: string;
  orgIds?: string[];
  periodMonthUtc?: string;
  now?: () => Date;
}

export interface D1ConsoleBillingMonthlyFinalizationResult {
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

export interface D1ConsoleBillingState {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
  emailConsoleBaseUrl?: string;
  consoleBaseUrl?: string;
}

interface BillingAccountRow {
  creditBalanceMinor: number;
  lowBalanceThresholdMinor: number;
}

interface BillingEmailOwnerRecipient {
  membershipId: string;
  organizationName: string;
  email: string;
  displayName: string;
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
  insertGuard?: D1LedgerEntryInsertGuard;
}

type D1LedgerEntryInsertGuard = {
  readonly kind: 'previous_statement_changed_one';
};

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

function normalizeEmailConsoleBaseUrl(value: string | undefined): string | undefined {
  const normalized = String(value || '').trim();
  if (!normalized) return undefined;
  const parsed = new URL(normalized);
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Billing email console base URL must use HTTP or HTTPS');
  }
  return parsed.toString();
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
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

function previousMonthUtc(now: Date): string {
  return monthUtc(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)));
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

function parseLedgerEntryType(value: unknown): BillingLedgerEntry['type'] {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'CREDIT_PURCHASE':
    case 'USAGE_DEBIT':
    case 'PRODUCT_EXECUTION_DEBIT':
    case 'MANUAL_ADJUSTMENT':
    case 'REFUND':
    case 'DISPUTE_OPENED':
    case 'DISPUTE_WON':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing ledger entry type row: ${normalized || 'empty'}`,
      );
  }
}

function parseLedgerAccountCode(value: unknown): BillingLedgerAccountCode {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'org_prepaid_liability':
    case 'stripe_cash_clearing':
    case 'revenue_usage':
    case 'revenue_product_execution':
    case 'manual_adjustment_clearing':
    case 'stripe_dispute_clearing':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing ledger account row: ${normalized || 'empty'}`,
      );
  }
}

type BillingLedgerEntryWithoutPostings = Omit<BillingLedgerEntry, 'postings'>;

function parseLedgerEntryRow(row: D1Row): BillingLedgerEntryWithoutPostings {
  return {
    id: String(row.id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    type: parseLedgerEntryType(row.entry_type),
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

function parseDebitPosting(row: D1Row): BillingLedgerDebitPosting {
  if (String(row.direction || '').trim() !== 'DEBIT') {
    throw new ConsoleBillingError(
      'corrupt_billing_ledger',
      500,
      'Billing debit posting has an invalid direction',
    );
  }
  return {
    id: String(row.id || '').trim(),
    ledgerEntryId: String(row.ledger_entry_id || '').trim(),
    accountCode: parseLedgerAccountCode(row.account_code),
    direction: 'DEBIT',
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

function parseCreditPosting(row: D1Row): BillingLedgerCreditPosting {
  if (String(row.direction || '').trim() !== 'CREDIT') {
    throw new ConsoleBillingError(
      'corrupt_billing_ledger',
      500,
      'Billing credit posting has an invalid direction',
    );
  }
  return {
    id: String(row.id || '').trim(),
    ledgerEntryId: String(row.ledger_entry_id || '').trim(),
    accountCode: parseLedgerAccountCode(row.account_code),
    direction: 'CREDIT',
    amountMinor: toNumber(row.amount_minor),
    createdAt: toIso(toNumber(row.created_at_ms)),
  };
}

async function hydrateLedgerEntryRows(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  rows: readonly D1Row[];
}): Promise<BillingLedgerEntry[]> {
  if (input.rows.length === 0) return [];
  const parsedEntries = input.rows.map(parseLedgerEntryRow);
  const ids = parsedEntries.map((entry) => entry.id);
  const placeholders = ids.map(() => '?').join(', ');
  const postingRows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_ledger_postings
      WHERE namespace = ?
        AND org_id = ?
        AND ledger_entry_id IN (${placeholders})
      ORDER BY ledger_entry_id ASC, direction DESC`,
    [input.namespace, input.orgId, ...ids],
  );
  const rowsByEntry = new Map<string, D1Row[]>();
  for (const row of postingRows) {
    const entryId = String(row.ledger_entry_id || '').trim();
    const existing = rowsByEntry.get(entryId) || [];
    existing.push(row);
    rowsByEntry.set(entryId, existing);
  }
  return parsedEntries.map((entry) => {
    const rows = rowsByEntry.get(entry.id) || [];
    const debitRow = rows.find((row) => String(row.direction || '').trim() === 'DEBIT');
    const creditRow = rows.find((row) => String(row.direction || '').trim() === 'CREDIT');
    if (!debitRow || !creditRow || rows.length !== 2) {
      throw new ConsoleBillingError(
        'corrupt_billing_ledger',
        500,
        `Billing ledger entry ${entry.id} must have exactly two postings`,
      );
    }
    const hydrated: BillingLedgerEntry = {
      id: entry.id,
      orgId: entry.orgId,
      type: entry.type,
      amountMinor: entry.amountMinor,
      currency: entry.currency,
      description: entry.description,
      monthUtc: entry.monthUtc,
      relatedInvoiceId: entry.relatedInvoiceId,
      relatedPurchaseId: entry.relatedPurchaseId,
      sourceEventId: entry.sourceEventId,
      actorType: entry.actorType,
      actorUserId: entry.actorUserId,
      reasonCode: entry.reasonCode,
      note: entry.note,
      idempotencyKey: entry.idempotencyKey,
      postings: [parseDebitPosting(debitRow), parseCreditPosting(creditRow)],
      createdAt: entry.createdAt,
    };
    assertBillingEntryBalances(hydrated);
    return hydrated;
  });
}

function parseBillingAccount(row: D1Row | null): BillingAccountRow {
  return {
    creditBalanceMinor: toNumber(row?.credit_balance_minor),
    lowBalanceThresholdMinor:
      toNumber(row?.low_balance_threshold_minor) || DEFAULT_LOW_BALANCE_THRESHOLD_MINOR,
  };
}

async function loadBillingEmailOwnerRecipients(
  state: D1ConsoleBillingState,
  orgId: string,
): Promise<BillingEmailOwnerRecipient[]> {
  if (!state.emailConsoleBaseUrl) return [];
  const rows = await queryD1All(
    state.database,
    `SELECT
        membership.id AS membership_id,
        organization.name AS organization_name,
        membership.email AS email,
        COALESCE(NULLIF(TRIM(membership.display_name), ''), membership.email) AS display_name
       FROM organizations AS organization
       JOIN organization_memberships AS membership
         ON membership.namespace = organization.namespace
        AND membership.org_id = organization.id
      WHERE organization.namespace = ?
        AND organization.id = ?
        AND membership.kind = 'ACTIVE'
        AND membership.role = 'OWNER'
      ORDER BY membership.created_at_ms ASC, membership.id ASC`,
    [state.namespace, orgId],
  );
  const recipients: BillingEmailOwnerRecipient[] = [];
  for (const row of rows) {
    const membershipId = String(row.membership_id || '').trim();
    const organizationName = String(row.organization_name || '').trim();
    const email = String(row.email || '')
      .trim()
      .toLowerCase();
    const displayName = String(row.display_name || '').trim();
    if (!membershipId || !organizationName || !email || !displayName) continue;
    recipients.push({ membershipId, organizationName, email, displayName });
  }
  return recipients;
}

async function buildBillingOwnerEmailOutboxStatements(input: {
  state: D1ConsoleBillingState;
  orgId: string;
  eventKey: string;
  template: ConsoleEmailNonInvitationTemplateV1;
  recipients: readonly BillingEmailOwnerRecipient[];
  createdAtMs: number;
  insertGuard?: 'PREVIOUS_STATEMENT_CHANGED_ONE';
}): Promise<D1PreparedStatementLike[]> {
  const statements: D1PreparedStatementLike[] = [];
  const createdAt = new Date(input.createdAtMs);
  for (const recipient of input.recipients) {
    const dedupeKey = `${input.eventKey}:owner:${recipient.membershipId}`;
    statements.push(
      await createConsoleEmailOutboxInsertStatement({
        database: input.state.database,
        namespace: input.state.namespace,
        email: {
          outboxId: `email:${dedupeKey}`,
          dedupeKey,
          orgId: input.orgId,
          recipient: {
            email: recipient.email,
            displayName: recipient.displayName,
          },
          template: input.template,
          createdAt,
          availableAt: createdAt,
        },
        ...(input.insertGuard ? { insertGuard: input.insertGuard } : {}),
      }),
    );
  }
  return statements;
}

async function buildTopUpReceiptEmailStatements(input: {
  state: D1ConsoleBillingState;
  purchase: BillingCreditPurchase;
  balanceAfterMinor: number;
  createdAtMs: number;
  insertGuard?: 'PREVIOUS_STATEMENT_CHANGED_ONE';
}): Promise<D1PreparedStatementLike[]> {
  const recipients = await loadBillingEmailOwnerRecipients(input.state, input.purchase.orgId);
  const recipient = recipients[0];
  if (!recipient || !input.state.emailConsoleBaseUrl) return [];
  return await buildBillingOwnerEmailOutboxStatements({
    state: input.state,
    orgId: input.purchase.orgId,
    eventKey: `billing:top-up:${input.purchase.id}`,
    template: buildPrepaidTopUpReceiptEmailV1({
      organizationName: recipient.organizationName,
      purchaseId: input.purchase.id,
      amountMinor: input.purchase.amountMinor,
      balanceAfterMinor: input.balanceAfterMinor,
      purchasedAt: toIso(input.createdAtMs),
      consoleBaseUrl: input.state.emailConsoleBaseUrl,
    }),
    recipients,
    createdAtMs: input.createdAtMs,
    ...(input.insertGuard ? { insertGuard: input.insertGuard } : {}),
  });
}

type BillingRefundResultEmailStatementInput =
  | {
      state: D1ConsoleBillingState;
      refund: BillingRefund;
      outcome: 'SUCCEEDED';
      balanceAfterMinor: number;
      createdAtMs: number;
      insertGuard?: 'PREVIOUS_STATEMENT_CHANGED_ONE';
      failureCode?: never;
    }
  | {
      state: D1ConsoleBillingState;
      refund: BillingRefund;
      outcome: 'FAILED';
      failureCode: string;
      createdAtMs: number;
      insertGuard?: 'PREVIOUS_STATEMENT_CHANGED_ONE';
      balanceAfterMinor?: never;
    };

async function buildRefundResultEmailStatements(
  input: BillingRefundResultEmailStatementInput,
): Promise<D1PreparedStatementLike[]> {
  const recipients = await loadBillingEmailOwnerRecipients(input.state, input.refund.orgId);
  const recipient = recipients[0];
  if (!recipient || !input.state.emailConsoleBaseUrl) return [];
  const common = {
    organizationName: recipient.organizationName,
    refundId: input.refund.id,
    amountMinor: input.refund.amountMinor,
    consoleBaseUrl: input.state.emailConsoleBaseUrl,
  };
  const template =
    input.outcome === 'SUCCEEDED'
      ? buildBillingRefundResultEmailV1({
          ...common,
          outcome: 'SUCCEEDED',
          balanceAfterMinor: input.balanceAfterMinor,
        })
      : buildBillingRefundResultEmailV1({
          ...common,
          outcome: 'FAILED',
          failureCode: input.failureCode,
        });
  return await buildBillingOwnerEmailOutboxStatements({
    state: input.state,
    orgId: input.refund.orgId,
    eventKey: `billing:refund:${input.refund.id}:${input.outcome.toLowerCase()}`,
    template,
    recipients,
    createdAtMs: input.createdAtMs,
    ...(input.insertGuard ? { insertGuard: input.insertGuard } : {}),
  });
}

async function buildLowBalanceStateStatements(input: {
  state: D1ConsoleBillingState;
  orgId: string;
  ledgerEntryId: string;
  createdAtMs: number;
}): Promise<D1PreparedStatementLike[]> {
  const committedBalanceSql = `COALESCE(
    (
      SELECT SUM(
        CASE low_balance_posting.direction
          WHEN 'CREDIT' THEN low_balance_posting.amount_minor
          ELSE -low_balance_posting.amount_minor
        END
      )
        FROM billing_ledger_postings AS low_balance_posting
       WHERE low_balance_posting.namespace = billing_accounts.namespace
         AND low_balance_posting.org_id = billing_accounts.org_id
         AND low_balance_posting.account_code = 'org_prepaid_liability'
    ),
    0
  )`;
  const resetStatement = input.state.database
    .prepare(
      `UPDATE billing_accounts
          SET low_balance_warning_active = 0,
              updated_at_ms = MAX(updated_at_ms, ?)
        WHERE namespace = ?
          AND org_id = ?
          AND low_balance_warning_active = 1
          AND ${committedBalanceSql} >= low_balance_threshold_minor
          AND EXISTS (
            SELECT 1
              FROM billing_ledger_entries AS entry
             WHERE entry.namespace = billing_accounts.namespace
               AND entry.org_id = billing_accounts.org_id
               AND entry.id = ?
          )`,
    )
    .bind(input.createdAtMs, input.state.namespace, input.orgId, input.ledgerEntryId);
  const armStatement = input.state.database
    .prepare(
      `UPDATE billing_accounts
          SET low_balance_warning_active = 1,
              updated_at_ms = MAX(updated_at_ms, ?)
        WHERE namespace = ?
          AND org_id = ?
          AND low_balance_warning_active = 0
          AND ${committedBalanceSql} < low_balance_threshold_minor
          AND EXISTS (
            SELECT 1
              FROM billing_ledger_entries AS entry
             WHERE entry.namespace = billing_accounts.namespace
               AND entry.org_id = billing_accounts.org_id
               AND entry.id = ?
          )`,
    )
    .bind(input.createdAtMs, input.state.namespace, input.orgId, input.ledgerEntryId);
  const recipients = await loadBillingEmailOwnerRecipients(input.state, input.orgId);
  if (recipients.length === 0 || !input.state.emailConsoleBaseUrl) {
    return [resetStatement, armStatement];
  }
  const emailStatements = recipients.map((recipient) => {
    const dedupeKey = `billing:low-balance:${input.ledgerEntryId}:owner:${recipient.membershipId}`;
    return input.state.database
      .prepare(
        `INSERT INTO console_email_outbox
          (
            namespace,
            org_id,
            id,
            dedupe_key,
            recipient_email,
            recipient_display_name,
            template_family,
            template_version,
            template_payload_json,
            invitation_id,
            invitation_secret_ciphertext_b64u,
            invitation_secret_key_id,
            invitation_secret_envelope_version,
            status,
            total_attempt_count,
            cycle_attempt_count,
            available_at_ms,
            claimed_by,
            claim_expires_at_ms,
            last_error_code,
            created_at_ms,
            updated_at_ms,
            sent_at_ms,
            canceled_at_ms
          )
        SELECT
          ?,
          billing_accounts.org_id,
          ?,
          ?,
          ?,
          ?,
          'LOW_BALANCE_WARNING',
          1,
          json_object(
            'family', 'LOW_BALANCE_WARNING',
            'version', 1,
            'organizationName', ?,
            'balanceMinor', ${committedBalanceSql},
            'thresholdMinor', billing_accounts.low_balance_threshold_minor,
            'currency', 'USD',
            'consoleBaseUrl', ?
          ),
          NULL,
          NULL,
          NULL,
          NULL,
          'PENDING',
          0,
          0,
          ?,
          NULL,
          NULL,
          NULL,
          ?,
          ?,
          NULL,
          NULL
        FROM billing_accounts
        WHERE namespace = ?
          AND org_id = ?
          AND changes() = 1`,
      )
      .bind(
        input.state.namespace,
        `email:${dedupeKey}`,
        dedupeKey,
        recipient.email,
        recipient.displayName,
        recipient.organizationName,
        input.state.emailConsoleBaseUrl,
        input.createdAtMs,
        input.createdAtMs,
        input.createdAtMs,
        input.state.namespace,
        input.orgId,
      );
  });
  return [resetStatement, armStatement, ...emailStatements];
}

function parseCreditPackId(value: unknown): BillingCreditPackId {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'usd_10':
    case 'usd_25':
    case 'usd_50':
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
    case 'ACTIVE_RESOURCE_USAGE_DEBIT':
    case 'PRODUCT_EXECUTION_DEBIT':
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
  const id = String(row.id || '').trim();
  const orgId = String(row.org_id || '').trim();
  const creditPackId = parseCreditPackId(row.credit_pack_id);
  const amountMinor = toNumber(row.amount_minor);
  const createdAt = toIso(toNumber(row.created_at_ms));
  const updatedAt = toIso(toNumber(row.updated_at_ms));
  const status = parseCreditPurchaseStatus(row.status);
  const providerCheckoutSessionRef = normalizeOptionalString(row.provider_checkout_session_ref);
  const providerCustomerRef = normalizeOptionalString(row.provider_customer_ref);
  if (status === 'SETTLED') {
    const providerPaymentRef = normalizeOptionalString(row.provider_payment_ref);
    const relatedInvoiceId = normalizeOptionalString(row.related_invoice_id);
    const settledAt = parseNullableIso(row.settled_at_ms);
    if (
      !providerCheckoutSessionRef ||
      !providerCustomerRef ||
      !providerPaymentRef ||
      !relatedInvoiceId ||
      !settledAt
    ) {
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Settled billing purchase ${id} is missing provider or receipt fields`,
      );
    }
    return {
      id,
      orgId,
      creditPackId,
      amountMinor,
      currency: 'USD',
      provider: 'stripe',
      status,
      providerCheckoutSessionRef,
      providerCustomerRef,
      providerPaymentRef,
      relatedInvoiceId,
      settledAt,
      createdAt,
      updatedAt,
    };
  }
  return {
    id,
    orgId,
    creditPackId,
    amountMinor,
    currency: 'USD',
    provider: 'stripe',
    status,
    providerCheckoutSessionRef,
    providerCustomerRef,
    providerPaymentRef: null,
    relatedInvoiceId: null,
    settledAt: null,
    createdAt,
    updatedAt,
  };
}

function parseRefundStatus(value: unknown): BillingRefundStatus {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'requested':
    case 'provider_pending':
    case 'succeeded':
    case 'failed':
    case 'canceled':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing refund status row: ${normalized || 'empty'}`,
      );
  }
}

function parseRefundOrigin(value: unknown): BillingRefund['origin'] {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'console':
    case 'provider':
      return normalized;
    default:
      throw new ConsoleBillingError(
        'corrupt_billing_row',
        500,
        `Invalid billing refund origin row: ${normalized || 'empty'}`,
      );
  }
}

function parseRefund(row: D1Row): BillingRefund {
  const id = String(row.id || '').trim();
  const orgId = String(row.org_id || '').trim();
  const purchaseId = String(row.purchase_id || '').trim();
  const amountMinor = toNumber(row.amount_minor);
  const reason = String(row.reason || '').trim();
  const origin = parseRefundOrigin(row.origin);
  const requesterUserId = String(row.requester_user_id || '').trim();
  const idempotencyKey = String(row.idempotency_key || '').trim();
  const createdAt = toIso(toNumber(row.created_at_ms));
  const updatedAt = toIso(toNumber(row.updated_at_ms));
  const status = parseRefundStatus(row.status);
  const providerRefundId = normalizeOptionalString(row.provider_refund_id);
  const failureCode = normalizeOptionalString(row.failure_code);
  const journalEntryId = normalizeOptionalString(row.journal_entry_id);
  switch (status) {
    case 'requested':
      return {
        id,
        orgId,
        purchaseId,
        amountMinor,
        currency: 'USD',
        reason,
        origin,
        requesterUserId,
        idempotencyKey,
        status,
        providerRefundId: null,
        failureCode: null,
        journalEntryId: null,
        createdAt,
        updatedAt,
      };
    case 'provider_pending':
      if (!providerRefundId) break;
      return {
        id,
        orgId,
        purchaseId,
        amountMinor,
        currency: 'USD',
        reason,
        origin,
        requesterUserId,
        idempotencyKey,
        status,
        providerRefundId,
        failureCode: null,
        journalEntryId: null,
        createdAt,
        updatedAt,
      };
    case 'succeeded':
      if (!providerRefundId || !journalEntryId) break;
      return {
        id,
        orgId,
        purchaseId,
        amountMinor,
        currency: 'USD',
        reason,
        origin,
        requesterUserId,
        idempotencyKey,
        status,
        providerRefundId,
        failureCode: null,
        journalEntryId,
        createdAt,
        updatedAt,
      };
    case 'failed':
      if (!failureCode) break;
      return {
        id,
        orgId,
        purchaseId,
        amountMinor,
        currency: 'USD',
        reason,
        origin,
        requesterUserId,
        idempotencyKey,
        status,
        providerRefundId,
        failureCode,
        journalEntryId: null,
        createdAt,
        updatedAt,
      };
    case 'canceled':
      if (!providerRefundId) break;
      return {
        id,
        orgId,
        purchaseId,
        amountMinor,
        currency: 'USD',
        reason,
        origin,
        requesterUserId,
        idempotencyKey,
        status,
        providerRefundId,
        failureCode: null,
        journalEntryId: null,
        createdAt,
        updatedAt,
      };
  }
  throw new ConsoleBillingError(
    'corrupt_billing_row',
    500,
    `Billing refund ${id} fields do not match status ${status}`,
  );
}

function parseDispute(row: D1Row): BillingDispute {
  const id = String(row.id || '').trim();
  const orgId = String(row.org_id || '').trim();
  const purchaseId = String(row.purchase_id || '').trim();
  const providerDisputeId = String(row.provider_dispute_id || '').trim();
  const amountMinor = toNumber(row.amount_minor);
  const openedJournalEntryId = String(row.opened_journal_entry_id || '').trim();
  const createdAt = toIso(toNumber(row.created_at_ms));
  const updatedAt = toIso(toNumber(row.updated_at_ms));
  const status = String(row.status || '').trim();
  const resolutionJournalEntryId = normalizeOptionalString(row.resolution_journal_entry_id);
  if (status === 'open') {
    return {
      id,
      orgId,
      purchaseId,
      providerDisputeId,
      amountMinor,
      status,
      openedJournalEntryId,
      resolutionJournalEntryId: null,
      createdAt,
      updatedAt,
    };
  }
  if (status === 'lost') {
    return {
      id,
      orgId,
      purchaseId,
      providerDisputeId,
      amountMinor,
      status,
      openedJournalEntryId,
      resolutionJournalEntryId: null,
      createdAt,
      updatedAt,
    };
  }
  if (status === 'won' && resolutionJournalEntryId) {
    return {
      id,
      orgId,
      purchaseId,
      providerDisputeId,
      amountMinor,
      status,
      openedJournalEntryId,
      resolutionJournalEntryId,
      createdAt,
      updatedAt,
    };
  }
  throw new ConsoleBillingError(
    'corrupt_billing_row',
    500,
    `Billing dispute ${id} has an invalid lifecycle state`,
  );
}

function parseStripePostProcessingOutboxItem(row: D1Row): BillingStripePostProcessingOutboxItem {
  let rawPayload: unknown;
  try {
    rawPayload = JSON.parse(String(row.payload_json || ''));
  } catch {
    throw new ConsoleBillingError(
      'corrupt_billing_row',
      500,
      `Stripe post-processing outbox event ${String(row.event_id || '')} has invalid JSON`,
    );
  }
  let payload;
  try {
    payload = parseBillingStripePostProcessingPayload(rawPayload);
  } catch (error: unknown) {
    throw new ConsoleBillingError(
      'corrupt_billing_row',
      500,
      error instanceof Error ? error.message : 'Stripe post-processing payload is invalid',
    );
  }
  return {
    eventId: String(row.event_id || '').trim(),
    orgId: String(row.org_id || '').trim(),
    payload,
    auditCompletedAt: parseNullableIso(row.audit_completed_at_ms),
    customerWebhookCompletedAt: parseNullableIso(row.customer_webhook_completed_at_ms),
    attemptCount: toNumber(row.attempt_count),
    lastError: normalizeOptionalString(row.last_error),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

async function loadStripePostProcessingOutboxItem(input: {
  database: D1DatabaseLike;
  namespace: string;
  eventId: string;
}): Promise<BillingStripePostProcessingOutboxItem | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_stripe_post_processing_outbox
      WHERE namespace = ?
        AND event_id = ?
      LIMIT 1`,
    [input.namespace, input.eventId],
  );
  return row ? parseStripePostProcessingOutboxItem(row) : null;
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
  const productExecutionMinor = Math.abs(
    input.entries
      .filter(
        (entry) =>
          entry.monthUtc === input.invoice.periodMonthUtc &&
          entry.type === 'PRODUCT_EXECUTION_DEBIT',
      )
      .reduce((total, entry) => total + entry.amountMinor, 0),
  );
  const usageMinor = Math.abs(
    input.entries
      .filter(
        (entry) => entry.monthUtc === input.invoice.periodMonthUtc && entry.type === 'USAGE_DEBIT',
      )
      .reduce((total, entry) => total + entry.amountMinor, 0),
  );
  const items: BillingInvoiceLineItem[] = [];
  if (usageMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_maw_usage_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'ACTIVE_RESOURCE_USAGE_DEBIT',
      description: `Monthly Active Resources (${input.invoice.periodMonthUtc})`,
      quantity: Math.max(1, Math.floor(usageMinor / ACTIVE_RESOURCE_USAGE_DEBIT_MINOR)),
      unitAmountMinor: ACTIVE_RESOURCE_USAGE_DEBIT_MINOR,
      amountMinor: usageMinor,
      createdAt: input.invoice.createdAt,
    });
  }
  if (productExecutionMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_product_execution_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'PRODUCT_EXECUTION_DEBIT',
      description: `Product execution spend (${input.invoice.periodMonthUtc})`,
      quantity: 1,
      unitAmountMinor: productExecutionMinor,
      amountMinor: productExecutionMinor,
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

function sortLineItems(items: BillingInvoiceLineItem[]): BillingInvoiceLineItem[] {
  return [...items].sort((left, right) => {
    const typeDiff = left.itemType.localeCompare(right.itemType);
    if (typeDiff !== 0) return typeDiff;
    return left.id.localeCompare(right.id);
  });
}

function lineItemsEquivalent(
  leftInput: readonly BillingInvoiceLineItem[],
  rightInput: readonly BillingInvoiceLineItem[],
): boolean {
  const left = sortLineItems([...leftInput]);
  const right = sortLineItems([...rightInput]);
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    const leftItem = left[index];
    const rightItem = right[index];
    if (!leftItem || !rightItem) return false;
    if (leftItem.itemType !== rightItem.itemType) return false;
    if (leftItem.quantity !== rightItem.quantity) return false;
    if (leftItem.unitAmountMinor !== rightItem.unitAmountMinor) return false;
    if (leftItem.amountMinor !== rightItem.amountMinor) return false;
    if (leftItem.periodMonthUtc !== rightItem.periodMonthUtc) return false;
  }
  return true;
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

async function ensureBillingAccount(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  createdAtMs: number;
}): Promise<BillingAccountRow> {
  await input.database
    .prepare(
      `INSERT INTO billing_accounts
        (namespace, org_id, low_balance_threshold_minor, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?)
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
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM (
         SELECT
           account.*,
           COALESCE(
             (
               SELECT SUM(
                 CASE posting.direction
                   WHEN 'CREDIT' THEN posting.amount_minor
                   ELSE -posting.amount_minor
                 END
               )
                 FROM billing_ledger_postings posting
                WHERE posting.namespace = account.namespace
                  AND posting.org_id = account.org_id
                  AND posting.account_code = 'org_prepaid_liability'
             ),
             0
           ) AS credit_balance_minor
           FROM billing_accounts account
       )
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
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND entry_type = ?
        AND source_event_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.type, input.sourceEventId],
  );
  if (!row) return null;
  return (
    (
      await hydrateLedgerEntryRows({
        database: input.database,
        namespace: input.namespace,
        orgId: input.orgId,
        rows: [row],
      })
    )[0] || null
  );
}

async function loadLedgerEntryById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  ledgerEntryId: string;
}): Promise<BillingLedgerEntry | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.ledgerEntryId],
  );
  if (!row) return null;
  return (
    (
      await hydrateLedgerEntryRows({
        database: input.database,
        namespace: input.namespace,
        orgId: input.orgId,
        rows: [row],
      })
    )[0] || null
  );
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
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_ledger_entries
      WHERE ${clauses.join(' AND ')}
      ORDER BY created_at_ms DESC, id DESC
      LIMIT ?`,
    values,
  );
  return await hydrateLedgerEntryRows({
    database: input.database,
    namespace: input.namespace,
    orgId: input.orgId,
    rows,
  });
}

async function listAllStatementLedgerEntries(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<BillingLedgerEntry[]> {
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc IS NOT NULL
      ORDER BY month_utc DESC, created_at_ms DESC, id DESC`,
    [input.namespace, input.orgId],
  );
  return await hydrateLedgerEntryRows({
    database: input.database,
    namespace: input.namespace,
    orgId: input.orgId,
    rows,
  });
}

async function countMonthlyActiveResources(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  monthUtcValue: string;
}): Promise<number> {
  const row = await queryD1One(
    input.database,
    `SELECT COUNT(*) AS resource_count
       FROM billing_monthly_active_resources
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc = ?`,
    [input.namespace, input.orgId, input.monthUtcValue],
  );
  return Math.max(0, toNumber(row?.resource_count));
}

async function listPersistedInvoices(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<BillingInvoice[]> {
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM invoices
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
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM invoices
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
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM invoice_line_items
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
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_credit_purchases
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
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_credit_purchases
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.purchaseId],
  );
  return row ? parseCreditPurchase(row) : null;
}

async function loadCreditPurchaseForProviderEvent(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string | null;
  purchaseId: string | null;
  providerPaymentRef: string;
}): Promise<BillingCreditPurchase | null> {
  const clauses = ['namespace = ?', "status = 'SETTLED'"];
  const values: unknown[] = [input.namespace];
  if (input.orgId) {
    clauses.push('org_id = ?');
    values.push(input.orgId);
  }
  if (input.purchaseId) {
    clauses.push('(id = ? OR provider_payment_ref = ?)');
    values.push(input.purchaseId, input.providerPaymentRef);
  } else {
    clauses.push('provider_payment_ref = ?');
    values.push(input.providerPaymentRef);
  }
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_credit_purchases
      WHERE ${clauses.join(' AND ')}
      ORDER BY created_at_ms DESC
      LIMIT 2`,
    values,
  );
  if (rows.length > 1) {
    throw new ConsoleBillingError(
      'duplicate_provider_reference',
      409,
      'Stripe payment reference maps to multiple purchases',
    );
  }
  return rows[0] ? parseCreditPurchase(rows[0]) : null;
}

async function loadRefundById(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  refundId: string;
}): Promise<BillingRefund | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_refunds
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.refundId],
  );
  return row ? parseRefund(row) : null;
}

async function loadRefundByIdempotencyKey(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  idempotencyKey: string;
}): Promise<BillingRefund | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_refunds
      WHERE namespace = ?
        AND org_id = ?
        AND idempotency_key = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.idempotencyKey],
  );
  return row ? parseRefund(row) : null;
}

async function loadRefundForProviderEvent(input: {
  database: D1DatabaseLike;
  namespace: string;
  refundId: string | null;
  providerRefundId: string;
}): Promise<BillingRefund | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_refunds
      WHERE namespace = ?
        AND (
          provider_refund_id = ?
          OR (? <> '' AND id = ?)
        )
      LIMIT 1`,
    [input.namespace, input.providerRefundId, input.refundId || '', input.refundId || ''],
  );
  return row ? parseRefund(row) : null;
}

async function listRefundsD1(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<BillingRefund[]> {
  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_refunds
      WHERE namespace = ?
        AND org_id = ?
      ORDER BY created_at_ms DESC, id DESC`,
    [input.namespace, input.orgId],
  );
  return rows.map(parseRefund);
}

async function activeRefundAmountForPurchaseD1(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  purchaseId: string;
}): Promise<number> {
  const row = await queryD1One(
    input.database,
    `SELECT COALESCE(SUM(amount_minor), 0) AS amount_minor
       FROM billing_refunds
      WHERE namespace = ?
        AND org_id = ?
        AND purchase_id = ?
        AND status IN ('requested', 'provider_pending', 'succeeded')`,
    [input.namespace, input.orgId, input.purchaseId],
  );
  return Math.max(0, toNumber(row?.amount_minor));
}

async function pendingConsoleRefundAmountD1(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
}): Promise<number> {
  const row = await queryD1One(
    input.database,
    `SELECT COALESCE(SUM(amount_minor), 0) AS amount_minor
       FROM billing_refunds
      WHERE namespace = ?
        AND org_id = ?
        AND origin = 'console'
        AND status IN ('requested', 'provider_pending')`,
    [input.namespace, input.orgId],
  );
  return Math.max(0, toNumber(row?.amount_minor));
}

async function loadDisputeByProviderId(input: {
  database: D1DatabaseLike;
  namespace: string;
  providerDisputeId: string;
}): Promise<BillingDispute | null> {
  const row = await queryD1One(
    input.database,
    `SELECT *
       FROM billing_disputes
      WHERE namespace = ?
        AND provider_dispute_id = ?
      LIMIT 1`,
    [input.namespace, input.providerDisputeId],
  );
  return row ? parseDispute(row) : null;
}

async function findCreditPurchaseForStripeEvent(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string | null;
  checkoutSessionRef: string;
}): Promise<{ orgId: string; purchase: BillingCreditPurchase | null } | null> {
  if (!input.checkoutSessionRef) {
    return input.orgId ? { orgId: input.orgId, purchase: null } : null;
  }
  if (input.orgId) {
    const rows = await queryD1All(
      input.database,
      `SELECT *
         FROM billing_credit_purchases
        WHERE namespace = ?
          AND org_id = ?
          AND provider_checkout_session_ref = ?
        ORDER BY created_at_ms DESC, id DESC
        LIMIT 1`,
      [input.namespace, input.orgId, input.checkoutSessionRef],
    );
    return {
      orgId: input.orgId,
      purchase: rows[0] ? parseCreditPurchase(rows[0]) : null,
    };
  }

  const rows = await queryD1All(
    input.database,
    `SELECT *
       FROM billing_credit_purchases
      WHERE namespace = ?
        AND provider_checkout_session_ref = ?
      ORDER BY created_at_ms DESC, id DESC
      LIMIT 2`,
    [input.namespace, input.checkoutSessionRef],
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
        `INSERT INTO invoices
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
        `DELETE FROM invoice_line_items
          WHERE namespace = ?
            AND org_id = ?
            AND invoice_id = ?`,
      )
      .bind(input.state.namespace, input.purchase.orgId, invoiceId),
    input.state.database
      .prepare(
        `INSERT INTO invoice_line_items
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

function buildUsageStatementLineItems(input: {
  invoice: BillingInvoice;
  usageDebitMinor: number;
  productExecutionDebitMinor: number;
  createdAtMs: number;
}): BillingInvoiceLineItem[] {
  const items: BillingInvoiceLineItem[] = [];
  if (input.usageDebitMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_maw_usage_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'ACTIVE_RESOURCE_USAGE_DEBIT',
      description: `Monthly Active Resource usage (${input.invoice.periodMonthUtc})`,
      quantity: Math.max(1, Math.round(input.usageDebitMinor / ACTIVE_RESOURCE_USAGE_DEBIT_MINOR)),
      unitAmountMinor: ACTIVE_RESOURCE_USAGE_DEBIT_MINOR,
      amountMinor: input.usageDebitMinor,
      createdAt: toIso(input.createdAtMs),
    });
  }
  if (input.productExecutionDebitMinor > 0) {
    items.push({
      id: `ili_${input.invoice.id}_product_execution_debit`,
      orgId: input.invoice.orgId,
      invoiceId: input.invoice.id,
      periodMonthUtc: input.invoice.periodMonthUtc,
      itemType: 'PRODUCT_EXECUTION_DEBIT',
      description: `Product execution spend (${input.invoice.periodMonthUtc})`,
      quantity: 1,
      unitAmountMinor: input.productExecutionDebitMinor,
      amountMinor: input.productExecutionDebitMinor,
      createdAt: toIso(input.createdAtMs),
    });
  }
  return sortLineItems(items);
}

function buildUsageStatementLineItemStatements(input: {
  state: D1ConsoleBillingState;
  lineItems: readonly BillingInvoiceLineItem[];
  createdAtMs: number;
}): readonly D1PreparedStatementLike[] {
  return input.lineItems.map((lineItem) =>
    input.state.database
      .prepare(
        `INSERT INTO invoice_line_items
          (namespace, org_id, id, invoice_id, period_month_utc, item_type, description, quantity, unit_amount_minor, amount_minor, created_at_ms)
         VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        input.state.namespace,
        lineItem.orgId,
        lineItem.id,
        lineItem.invoiceId,
        lineItem.periodMonthUtc,
        lineItem.itemType,
        lineItem.description,
        lineItem.quantity,
        lineItem.unitAmountMinor,
        lineItem.amountMinor,
        input.createdAtMs,
      ),
  );
}

export function createD1BillingLedgerEntryInsertStatement(
  database: D1DatabaseLike,
  input: LedgerEntryInsertInput,
): D1PreparedStatementLike {
  const sourceSql = d1LedgerEntryInsertSourceSql(input.insertGuard);
  return database
    .prepare(
      `INSERT INTO billing_ledger_entries
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
       ${sourceSql}`,
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

function d1LedgerEntryInsertSourceSql(insertGuard: LedgerEntryInsertInput['insertGuard']): string {
  const sourceSql = "SELECT ?, ?, ?, ?, ?, 'USD', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?";
  if (!insertGuard) return sourceSql;
  return `${sourceSql} WHERE changes() = 1`;
}

function buildProductExecutionDebitInsert(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingProductExecutionDebitRequest;
  entryId: string;
  occurredAtMs: number;
  insertGuard?: LedgerEntryInsertInput['insertGuard'];
}): D1PreparedStatementLike {
  const eventMonthUtc = monthUtcFromMs(input.occurredAtMs);
  const sourceEventId = normalizeRequiredString(input.request.sourceEventId, 'sourceEventId');
  return createD1BillingLedgerEntryInsertStatement(input.state.database, {
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    entryId: input.entryId,
    type: 'PRODUCT_EXECUTION_DEBIT',
    amountMinor: -input.request.amountMinor,
    description: `Product execution debit for ${input.request.resourceId}`,
    monthUtc: eventMonthUtc,
    relatedInvoiceId: makeUsageStatementId(input.ctx.orgId, eventMonthUtc),
    relatedPurchaseId: null,
    sourceEventId,
    actorType: 'SYSTEM',
    actorUserId: input.ctx.actorUserId,
    reasonCode: 'product_execution_debit',
    note:
      normalizeOptionalString(input.request.note) ||
      [
        input.request.txOrExecutionRef ? `Ref ${input.request.txOrExecutionRef}` : '',
        input.request.pricingVersion ? `Pricing ${input.request.pricingVersion}` : '',
      ]
        .filter(Boolean)
        .join(' | ') ||
      `Product execution debit recorded for ${input.request.resourceId}`,
    idempotencyKey: `product_execution_debit:${sourceEventId}`,
    createdAtMs: input.occurredAtMs,
    insertGuard: input.insertGuard,
  });
}

async function buildProductExecutionDebitStatements(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingProductExecutionDebitRequest;
  entryId: string;
  occurredAtMs: number;
  insertGuard?: LedgerEntryInsertInput['insertGuard'];
}): Promise<{
  ledgerStatement: D1PreparedStatementLike;
  notificationStatements: D1PreparedStatementLike[];
}> {
  return {
    ledgerStatement: buildProductExecutionDebitInsert(input),
    notificationStatements: await buildLowBalanceStateStatements({
      state: input.state,
      orgId: input.ctx.orgId,
      ledgerEntryId: input.entryId,
      createdAtMs: input.occurredAtMs,
    }),
  };
}

function normalizeProductDebit(input: {
  now: Date;
  request: BillingProductExecutionDebitRequest;
}): { sourceEventId: string; amountMinor: number; occurredAtMs: number } {
  const sourceEventId = normalizeRequiredString(input.request.sourceEventId, 'sourceEventId');
  const amountMinor = normalizePositiveInteger(input.request.amountMinor, 'amountMinor');
  const occurredAtMs = input.request.occurredAt
    ? Date.parse(input.request.occurredAt)
    : nowMs(input.now);
  if (!Number.isFinite(occurredAtMs)) {
    throw new ConsoleBillingError(
      'invalid_product_execution_debit',
      400,
      'Invalid occurredAt value',
    );
  }
  return { sourceEventId, amountMinor, occurredAtMs };
}

export async function recordProductExecutionDebitD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  request: BillingProductExecutionDebitRequest;
  entryId?: string;
}): Promise<{
  result: BillingProductExecutionDebitResult;
  ledgerEntry: BillingLedgerEntry | null;
}> {
  const currentNow = input.state.now();
  const normalized = normalizeProductDebit({ now: currentNow, request: input.request });
  const existing = await loadLedgerEntryBySourceEventAndType({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    sourceEventId: normalized.sourceEventId,
    type: 'PRODUCT_EXECUTION_DEBIT',
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
  const statements = await buildProductExecutionDebitStatements({
    state: input.state,
    ctx: input.ctx,
    request: { ...input.request, amountMinor: normalized.amountMinor },
    entryId,
    occurredAtMs: normalized.occurredAtMs,
  });
  try {
    await input.state.database.batch([
      statements.ledgerStatement,
      ...statements.notificationStatements,
    ]);
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
      type: 'PRODUCT_EXECUTION_DEBIT',
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

export async function createProductExecutionDebitD1Statements(input: {
  runtime: ConsoleBillingD1Runtime;
  ctx: ConsoleBillingContext;
  request: BillingProductExecutionDebitRequest;
  entryId: string;
  occurredAtMs: number;
  insertGuard?: LedgerEntryInsertInput['insertGuard'];
}): Promise<{
  ledgerStatement: D1PreparedStatementLike;
  notificationStatements: D1PreparedStatementLike[];
}> {
  return await buildProductExecutionDebitStatements({
    state: {
      database: input.runtime.database,
      namespace: input.runtime.namespace,
      now: input.runtime.now,
      ...(input.runtime.emailConsoleBaseUrl
        ? { emailConsoleBaseUrl: input.runtime.emailConsoleBaseUrl }
        : {}),
    },
    ctx: input.ctx,
    request: input.request,
    entryId: input.entryId,
    occurredAtMs: input.occurredAtMs,
    insertGuard: input.insertGuard,
  });
}

async function getUsageStatementTotals(input: {
  state: D1ConsoleBillingState;
  orgId: string;
  periodMonthUtc: string;
}): Promise<{
  usageDebitMinor: number;
  productExecutionDebitMinor: number;
  amountDueMinor: number;
}> {
  const row = await queryD1One(
    input.state.database,
    `SELECT
        COALESCE(SUM(CASE WHEN entry_type = 'USAGE_DEBIT' THEN ABS(amount_minor) ELSE 0 END), 0) AS usage_debit_minor,
        COALESCE(SUM(CASE WHEN entry_type = 'PRODUCT_EXECUTION_DEBIT' THEN ABS(amount_minor) ELSE 0 END), 0) AS product_execution_debit_minor
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND entry_type IN ('USAGE_DEBIT', 'PRODUCT_EXECUTION_DEBIT')
        AND month_utc = ?`,
    [input.state.namespace, input.orgId, input.periodMonthUtc],
  );
  const usageDebitMinor = Math.max(0, toNumber(row?.usage_debit_minor));
  const productExecutionDebitMinor = Math.max(0, toNumber(row?.product_execution_debit_minor));
  return {
    usageDebitMinor,
    productExecutionDebitMinor,
    amountDueMinor: usageDebitMinor + productExecutionDebitMinor,
  };
}

async function reconcileUsageDebitCoverageD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  periodMonthUtc: string;
  monthlyActiveResources: number;
  createdAtMs: number;
}): Promise<void> {
  const totals = await getUsageStatementTotals({
    state: input.state,
    orgId: input.ctx.orgId,
    periodMonthUtc: input.periodMonthUtc,
  });
  const targetUsageDebitMinor =
    Math.max(0, Math.trunc(input.monthlyActiveResources)) * ACTIVE_RESOURCE_USAGE_DEBIT_MINOR;
  const missingAmountMinor = Math.max(0, targetUsageDebitMinor - totals.usageDebitMinor);
  if (missingAmountMinor <= 0) return;

  const entryId = `ble_usage_reconcile_${input.ctx.orgId}_${input.periodMonthUtc.replace('-', '')}`;
  const notificationStatements = await buildLowBalanceStateStatements({
    state: input.state,
    orgId: input.ctx.orgId,
    ledgerEntryId: entryId,
    createdAtMs: input.createdAtMs,
  });
  try {
    await input.state.database.batch([
      createD1BillingLedgerEntryInsertStatement(input.state.database, {
        namespace: input.state.namespace,
        orgId: input.ctx.orgId,
        entryId,
        type: 'USAGE_DEBIT',
        amountMinor: -missingAmountMinor,
        description: `Reconciled active-resource usage debit coverage (${input.periodMonthUtc})`,
        monthUtc: input.periodMonthUtc,
        relatedInvoiceId: makeUsageStatementId(input.ctx.orgId, input.periodMonthUtc),
        relatedPurchaseId: null,
        sourceEventId: `usage_statement:${input.periodMonthUtc}`,
        actorType: 'SYSTEM',
        actorUserId: input.ctx.actorUserId,
        reasonCode: 'usage_statement_reconciliation',
        note: `Reconciled ${Math.round(missingAmountMinor / ACTIVE_RESOURCE_USAGE_DEBIT_MINOR)} missing active-resource debit(s) into the monthly usage statement.`,
        idempotencyKey: `usage_statement:${input.ctx.orgId}:${input.periodMonthUtc}`,
        createdAtMs: input.createdAtMs,
      }),
      ...notificationStatements,
    ]);
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
  }
}

async function syncUsageStatementD1(input: {
  state: D1ConsoleBillingState;
  orgId: string;
  periodMonthUtc: string;
  createdAtMs: number;
}): Promise<{
  invoice: BillingInvoice;
  lineItems: BillingInvoiceLineItem[];
}> {
  const invoiceId = makeUsageStatementId(input.orgId, input.periodMonthUtc);
  const existingInvoice = await loadPersistedInvoiceById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    invoiceId,
  });
  const seedInvoice: BillingInvoice = existingInvoice || {
    id: invoiceId,
    orgId: input.orgId,
    documentType: 'USAGE_STATEMENT',
    status: 'PAID',
    currency: 'USD',
    amountDueMinor: 0,
    amountPaidMinor: 0,
    periodMonthUtc: input.periodMonthUtc,
    createdAt: toIso(input.createdAtMs),
    dueAt: null,
  };
  const totals = await getUsageStatementTotals({
    state: input.state,
    orgId: input.orgId,
    periodMonthUtc: input.periodMonthUtc,
  });
  const lineItems = buildUsageStatementLineItems({
    invoice: seedInvoice,
    usageDebitMinor: totals.usageDebitMinor,
    productExecutionDebitMinor: totals.productExecutionDebitMinor,
    createdAtMs: input.createdAtMs,
  });
  await input.state.database.batch([
    input.state.database
      .prepare(
        `INSERT INTO invoices
          (namespace, org_id, id, document_type, status, currency, amount_due_minor, amount_paid_minor, period_month_utc, created_at_ms, due_at_ms)
         VALUES
          (?, ?, ?, 'USAGE_STATEMENT', 'PAID', 'USD', ?, ?, ?, ?, NULL)
         ON CONFLICT(namespace, org_id, id) DO UPDATE
           SET amount_due_minor = excluded.amount_due_minor,
               amount_paid_minor = excluded.amount_paid_minor,
               status = 'PAID',
               due_at_ms = NULL`,
      )
      .bind(
        input.state.namespace,
        input.orgId,
        invoiceId,
        totals.amountDueMinor,
        totals.amountDueMinor,
        input.periodMonthUtc,
        input.createdAtMs,
      ),
    input.state.database
      .prepare(
        `DELETE FROM invoice_line_items
          WHERE namespace = ?
            AND org_id = ?
            AND invoice_id = ?`,
      )
      .bind(input.state.namespace, input.orgId, invoiceId),
    ...buildUsageStatementLineItemStatements({
      state: input.state,
      lineItems,
      createdAtMs: input.createdAtMs,
    }),
  ]);
  const invoice = await loadPersistedInvoiceById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    invoiceId,
  });
  if (!invoice) {
    throw new ConsoleBillingError(
      'invoice_generate_failed',
      500,
      'Failed to create usage statement',
    );
  }
  return { invoice, lineItems };
}

async function generateMonthlyInvoiceD1(input: {
  state: D1ConsoleBillingState;
  ctx: ConsoleBillingContext;
  periodMonthUtc: string;
}): Promise<GenerateMonthlyInvoiceResult> {
  const createdAtMs = nowMs(input.state.now());
  const monthlyActiveResources = await countMonthlyActiveResources({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    monthUtcValue: input.periodMonthUtc,
  });
  await reconcileUsageDebitCoverageD1({
    state: input.state,
    ctx: input.ctx,
    periodMonthUtc: input.periodMonthUtc,
    monthlyActiveResources,
    createdAtMs,
  });
  const invoiceId = makeUsageStatementId(input.ctx.orgId, input.periodMonthUtc);
  const previousInvoice = await loadPersistedInvoiceById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    invoiceId,
  });
  const previousLineItems = previousInvoice
    ? await listPersistedInvoiceLineItems({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.ctx.orgId,
        invoiceId,
      })
    : [];
  const synced = await syncUsageStatementD1({
    state: input.state,
    orgId: input.ctx.orgId,
    periodMonthUtc: input.periodMonthUtc,
    createdAtMs,
  });
  const generated =
    !previousInvoice ||
    previousInvoice.amountDueMinor !== synced.invoice.amountDueMinor ||
    !lineItemsEquivalent(previousLineItems, synced.lineItems);
  return {
    generated,
    invoice: synced.invoice,
    lineItems: sortLineItems(synced.lineItems),
    monthlyActiveResources,
    pricing: { activeResourceUnitPriceMinor: ACTIVE_RESOURCE_USAGE_DEBIT_MINOR },
  };
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
  providerPaymentRef: string;
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
    const receiptCreatedAtMs = current.settledAt
      ? Date.parse(current.settledAt)
      : input.settledAtMs;
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
        `UPDATE billing_credit_purchases
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
  if (!current.providerCheckoutSessionRef) {
    throw new ConsoleBillingError(
      'purchase_not_ready',
      409,
      `Credit purchase ${current.id} has no Stripe checkout session`,
    );
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
    providerPaymentRef: input.providerPaymentRef,
    relatedInvoiceId: invoiceId,
    settledAt: toIso(input.settledAtMs),
    createdAt: current.createdAt,
    updatedAt: toIso(input.settledAtMs),
  };
  const accountBeforeSettlement = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.orgId,
    createdAtMs: input.settledAtMs,
  });
  const ledgerEntryId = makeId('ble', new Date(input.settledAtMs));
  const balanceAfterMinor = accountBeforeSettlement.creditBalanceMinor + current.amountMinor;
  const topUpEmailStatements = await buildTopUpReceiptEmailStatements({
    state: input.state,
    purchase: settledPurchase,
    balanceAfterMinor,
    createdAtMs: input.settledAtMs,
    insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
  });
  const lowBalanceStateStatements = await buildLowBalanceStateStatements({
    state: input.state,
    orgId: input.orgId,
    ledgerEntryId,
    createdAtMs: input.settledAtMs,
  });
  const statements: D1PreparedStatementLike[] = [
    createD1BillingLedgerEntryInsertStatement(input.state.database, {
      namespace: input.state.namespace,
      orgId: input.orgId,
      entryId: ledgerEntryId,
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
        `UPDATE billing_credit_purchases
            SET status = 'SETTLED',
                provider_customer_ref = COALESCE(provider_customer_ref, ?),
                provider_payment_ref = ?,
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
        settledPurchase.providerPaymentRef,
        invoiceId,
        input.settledAtMs,
        input.settledAtMs,
        input.state.namespace,
        input.orgId,
        current.id,
      ),
    ...topUpEmailStatements,
    ...lowBalanceStateStatements,
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

async function finalizeRefundD1(input: {
  state: D1ConsoleBillingState;
  refund: BillingRefund;
  provider: StripeRefundProviderOutput;
  updatedAtMs: number;
}): Promise<BillingRefund> {
  const providerRefundId = normalizeRequiredString(input.provider.id, 'provider refund id');
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

  if (input.provider.status === 'succeeded') {
    const ledgerEntryId = `ble_${input.refund.id}`;
    const accountBeforeRefund = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.refund.orgId,
      createdAtMs: input.updatedAtMs,
    });
    const balanceAfterMinor = accountBeforeRefund.creditBalanceMinor - input.refund.amountMinor;
    const refundEmailStatements = await buildRefundResultEmailStatements({
      state: input.state,
      refund: input.refund,
      outcome: 'SUCCEEDED',
      balanceAfterMinor,
      createdAtMs: input.updatedAtMs,
      insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
    });
    const lowBalanceStateStatements = await buildLowBalanceStateStatements({
      state: input.state,
      orgId: input.refund.orgId,
      ledgerEntryId,
      createdAtMs: input.updatedAtMs,
    });
    try {
      await input.state.database.batch([
        createD1BillingLedgerEntryInsertStatement(input.state.database, {
          namespace: input.state.namespace,
          orgId: input.refund.orgId,
          entryId: ledgerEntryId,
          type: 'REFUND',
          amountMinor: -input.refund.amountMinor,
          description: `Stripe refund ${providerRefundId}`,
          monthUtc: monthUtcFromMs(input.updatedAtMs),
          relatedInvoiceId: null,
          relatedPurchaseId: input.refund.purchaseId,
          sourceEventId: providerRefundId,
          actorType: 'PROVIDER',
          actorUserId: null,
          reasonCode: input.refund.reason,
          note: `Refund ${input.refund.id} succeeded`,
          idempotencyKey: `refund:${input.refund.id}`,
          createdAtMs: input.updatedAtMs,
        }),
        input.state.database
          .prepare(
            `UPDATE billing_refunds
                SET status = 'succeeded',
                    provider_refund_id = ?,
                    failure_code = NULL,
                    journal_entry_id = ?,
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?
                AND status IN ('requested', 'provider_pending')`,
          )
          .bind(
            providerRefundId,
            ledgerEntryId,
            input.updatedAtMs,
            input.state.namespace,
            input.refund.orgId,
            input.refund.id,
          ),
        ...refundEmailStatements,
        ...lowBalanceStateStatements,
      ]);
    } catch (error: unknown) {
      if (!isD1ConstraintError(error)) throw error;
    }
  } else {
    const nextStatus =
      input.provider.status === 'pending' ? 'provider_pending' : input.provider.status;
    const failureCode =
      input.provider.status === 'failed' ? input.provider.failureCode || 'provider_failed' : null;
    const transitionStatement = input.state.database
      .prepare(
        `UPDATE billing_refunds
            SET status = ?,
                provider_refund_id = ?,
                failure_code = ?,
                journal_entry_id = NULL,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status IN ('requested', 'provider_pending')`,
      )
      .bind(
        nextStatus,
        providerRefundId,
        failureCode,
        input.updatedAtMs,
        input.state.namespace,
        input.refund.orgId,
        input.refund.id,
      );
    if (nextStatus === 'failed' && failureCode) {
      const emailStatements = await buildRefundResultEmailStatements({
        state: input.state,
        refund: input.refund,
        outcome: 'FAILED',
        failureCode,
        createdAtMs: input.updatedAtMs,
        insertGuard: 'PREVIOUS_STATEMENT_CHANGED_ONE',
      });
      await input.state.database.batch([transitionStatement, ...emailStatements]);
    } else {
      await transitionStatement.run();
    }
  }

  const updated = await loadRefundById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.refund.orgId,
    refundId: input.refund.id,
  });
  if (!updated) {
    throw new ConsoleBillingError(
      'refund_persistence_failed',
      500,
      `Refund ${input.refund.id} disappeared during provider reconciliation`,
    );
  }
  return updated;
}

async function createRefundD1(input: {
  state: D1ConsoleBillingState;
  providers: BillingProviderAdapters;
  ctx: ConsoleBillingRefundSupportContext;
  request: BillingRefundRequest;
}): Promise<BillingRefundResult> {
  requireRefundSupportContext(input.ctx);
  const request = normalizeRefundRequest(input.request);
  const existing = await loadRefundByIdempotencyKey({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    idempotencyKey: request.idempotencyKey,
  });
  if (existing) {
    if (
      existing.purchaseId !== request.purchaseId ||
      existing.amountMinor !== request.amountMinor ||
      existing.reason !== request.reason
    ) {
      throw new ConsoleBillingError(
        'refund_idempotency_conflict',
        409,
        'Refund idempotency key was already used for a different request',
      );
    }
    if (existing.status === 'requested' && !existing.providerRefundId) {
      const purchase = await loadCreditPurchaseById({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.ctx.orgId,
        purchaseId: existing.purchaseId,
      });
      if (!purchase || purchase.status !== 'SETTLED') {
        throw new ConsoleBillingError(
          'purchase_not_refundable',
          409,
          'Only settled credit purchases can be refunded',
        );
      }
      let providerRefund: StripeRefundProviderOutput;
      try {
        providerRefund = await input.providers.stripe.createRefund({
          refundId: existing.id,
          orgId: input.ctx.orgId,
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
      const refund = await finalizeRefundD1({
        state: input.state,
        refund: existing,
        provider: providerRefund,
        updatedAtMs: nowMs(input.state.now()),
      });
      const account = await loadBillingAccount({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.ctx.orgId,
        createdAtMs: nowMs(input.state.now()),
      });
      return { created: false, refund, creditBalanceMinor: account.creditBalanceMinor };
    }
    const account = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      createdAtMs: nowMs(input.state.now()),
    });
    return { created: false, refund: existing, creditBalanceMinor: account.creditBalanceMinor };
  }
  const purchase = await loadCreditPurchaseById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    purchaseId: request.purchaseId,
  });
  if (!purchase || purchase.status !== 'SETTLED') {
    throw new ConsoleBillingError(
      'purchase_not_refundable',
      409,
      'Only settled credit purchases can be refunded',
    );
  }
  const activeRefundAmount = await activeRefundAmountForPurchaseD1({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    purchaseId: purchase.id,
  });
  if (request.amountMinor > purchase.amountMinor - activeRefundAmount) {
    throw new ConsoleBillingError(
      'refund_amount_exceeds_purchase',
      409,
      'Refund amount exceeds the unrefunded purchase amount',
    );
  }
  const currentNow = input.state.now();
  const account = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: nowMs(currentNow),
  });
  const pendingRefundAmount = await pendingConsoleRefundAmountD1({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
  });
  if (request.amountMinor > account.creditBalanceMinor - pendingRefundAmount) {
    throw new ConsoleBillingError(
      'refund_amount_exceeds_credit',
      409,
      'Console refund amount exceeds unused prepaid credit',
    );
  }
  const refundId = makeId('brf', currentNow);
  let insertResult;
  try {
    insertResult = await input.state.database
      .prepare(
        `INSERT INTO billing_refunds (
        namespace,
        org_id,
        id,
        purchase_id,
        amount_minor,
        currency,
        reason,
        origin,
        requester_user_id,
        idempotency_key,
        status,
        provider_refund_id,
        failure_code,
        journal_entry_id,
        created_at_ms,
        updated_at_ms
      )
      SELECT
        ?,
        purchase.org_id,
        ?,
        purchase.id,
        ?,
        'USD',
        ?,
        'console',
        ?,
        ?,
        'requested',
        NULL,
        NULL,
        NULL,
        ?,
        ?
      FROM billing_credit_purchases purchase
      WHERE purchase.namespace = ?
        AND purchase.org_id = ?
        AND purchase.id = ?
        AND purchase.status = 'SETTLED'
        AND ? <= purchase.amount_minor - COALESCE(
          (
            SELECT SUM(refund.amount_minor)
              FROM billing_refunds refund
             WHERE refund.namespace = purchase.namespace
               AND refund.org_id = purchase.org_id
               AND refund.purchase_id = purchase.id
               AND refund.status IN ('requested', 'provider_pending', 'succeeded')
          ),
          0
        )
        AND ? <= COALESCE(
          (
            SELECT SUM(
              CASE posting.direction
                WHEN 'CREDIT' THEN posting.amount_minor
                ELSE -posting.amount_minor
              END
            )
              FROM billing_ledger_postings posting
             WHERE posting.namespace = purchase.namespace
               AND posting.org_id = purchase.org_id
               AND posting.account_code = 'org_prepaid_liability'
          ),
          0
        ) - COALESCE(
          (
            SELECT SUM(pending_refund.amount_minor)
              FROM billing_refunds pending_refund
             WHERE pending_refund.namespace = purchase.namespace
               AND pending_refund.org_id = purchase.org_id
               AND pending_refund.origin = 'console'
               AND pending_refund.status IN ('requested', 'provider_pending')
          ),
          0
        )`,
      )
      .bind(
        input.state.namespace,
        refundId,
        request.amountMinor,
        request.reason,
        input.ctx.actorUserId,
        request.idempotencyKey,
        nowMs(currentNow),
        nowMs(currentNow),
        input.state.namespace,
        input.ctx.orgId,
        purchase.id,
        request.amountMinor,
        request.amountMinor,
      )
      .run();
  } catch (error: unknown) {
    if (!isD1ConstraintError(error)) throw error;
    const concurrent = await loadRefundByIdempotencyKey({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      idempotencyKey: request.idempotencyKey,
    });
    if (!concurrent) throw error;
    return await createRefundD1(input);
  }
  if (d1ChangedRows(insertResult) === 0) {
    const latestActiveRefundAmount = await activeRefundAmountForPurchaseD1({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      purchaseId: purchase.id,
    });
    if (request.amountMinor > purchase.amountMinor - latestActiveRefundAmount) {
      throw new ConsoleBillingError(
        'refund_amount_exceeds_purchase',
        409,
        'Refund amount exceeds the unrefunded purchase amount',
      );
    }
    const latestAccount = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      createdAtMs: nowMs(currentNow),
    });
    const latestPendingRefundAmount = await pendingConsoleRefundAmountD1({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
    });
    if (request.amountMinor > latestAccount.creditBalanceMinor - latestPendingRefundAmount) {
      throw new ConsoleBillingError(
        'refund_amount_exceeds_credit',
        409,
        'Console refund amount exceeds unused prepaid credit',
      );
    }
    throw new ConsoleBillingError(
      'refund_reservation_conflict',
      409,
      'Refund capacity changed while the request was being reserved',
    );
  }
  const requested = await loadRefundById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    refundId,
  });
  if (!requested) {
    throw new ConsoleBillingError(
      'refund_persistence_failed',
      500,
      'Failed to persist refund request',
    );
  }
  let providerRefund: StripeRefundProviderOutput;
  try {
    providerRefund = await input.providers.stripe.createRefund({
      refundId,
      orgId: input.ctx.orgId,
      purchaseId: purchase.id,
      providerPaymentRef: purchase.providerPaymentRef,
      amountMinor: request.amountMinor,
      reason: request.reason,
    });
  } catch (error: unknown) {
    throw new ConsoleBillingError(
      'refund_provider_error',
      502,
      error instanceof Error ? error.message : 'Stripe refund request failed',
    );
  }
  const refund = await finalizeRefundD1({
    state: input.state,
    refund: requested,
    provider: providerRefund,
    updatedAtMs: nowMs(input.state.now()),
  });
  const updatedAccount = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: nowMs(input.state.now()),
  });
  return { created: true, refund, creditBalanceMinor: updatedAccount.creditBalanceMinor };
}

async function reconcileRefundD1(input: {
  state: D1ConsoleBillingState;
  providers: BillingProviderAdapters;
  ctx: ConsoleBillingRefundSupportContext;
  request: BillingRefundReconcileRequest;
}): Promise<BillingRefundResult> {
  requireRefundSupportContext(input.ctx);
  const refundId = normalizeRequiredString(input.request.refundId, 'refundId');
  const refund = await loadRefundById({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    refundId,
  });
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
  const provider = await input.providers.stripe.getRefund({
    providerRefundId: refund.providerRefundId,
  });
  const reconciled = await finalizeRefundD1({
    state: input.state,
    refund,
    provider,
    updatedAtMs: nowMs(input.state.now()),
  });
  const account = await loadBillingAccount({
    database: input.state.database,
    namespace: input.state.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: nowMs(input.state.now()),
  });
  return { created: false, refund: reconciled, creditBalanceMinor: account.creditBalanceMinor };
}

async function applyRefundEventD1(input: {
  state: D1ConsoleBillingState;
  item: StripeRefundEventItem;
}): Promise<BillingRefund | null> {
  let refund = await loadRefundForProviderEvent({
    database: input.state.database,
    namespace: input.state.namespace,
    refundId: input.item.refundId,
    providerRefundId: input.item.providerRefundId,
  });
  if (refund) {
    if (
      refund.amountMinor !== input.item.amountMinor ||
      (input.item.purchaseId && refund.purchaseId !== input.item.purchaseId)
    ) {
      throw new ConsoleBillingError(
        'refund_provider_mismatch',
        409,
        `Stripe refund ${input.item.providerRefundId} does not match the persisted refund`,
      );
    }
  } else {
    const purchase = await loadCreditPurchaseForProviderEvent({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.item.orgId,
      purchaseId: input.item.purchaseId,
      providerPaymentRef: input.item.providerPaymentRef,
    });
    if (!purchase) return null;
    const activeAmount = await activeRefundAmountForPurchaseD1({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: purchase.orgId,
      purchaseId: purchase.id,
    });
    if (input.item.amountMinor > purchase.amountMinor - activeAmount) {
      throw new ConsoleBillingError(
        'refund_amount_exceeds_purchase',
        409,
        'Stripe refund exceeds the unrefunded purchase amount',
      );
    }
    const createdAtMs = nowMs(input.state.now());
    const refundId = `brf_ext_${input.item.providerRefundId}`;
    await input.state.database
      .prepare(
        `INSERT INTO billing_refunds (
          namespace,
          org_id,
          id,
          purchase_id,
          amount_minor,
          currency,
          reason,
          origin,
          requester_user_id,
          idempotency_key,
          status,
          provider_refund_id,
          failure_code,
          journal_entry_id,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, 'USD', ?, 'provider', 'stripe', ?, 'provider_pending', ?, NULL, NULL, ?, ?)
        ON CONFLICT DO NOTHING`,
      )
      .bind(
        input.state.namespace,
        purchase.orgId,
        refundId,
        purchase.id,
        input.item.amountMinor,
        input.item.reason,
        `stripe:${input.item.providerRefundId}`,
        input.item.providerRefundId,
        createdAtMs,
        createdAtMs,
      )
      .run();
    refund = await loadRefundForProviderEvent({
      database: input.state.database,
      namespace: input.state.namespace,
      refundId,
      providerRefundId: input.item.providerRefundId,
    });
  }
  if (!refund) {
    throw new ConsoleBillingError(
      'refund_persistence_failed',
      500,
      'Failed to import Stripe refund',
    );
  }
  return await finalizeRefundD1({
    state: input.state,
    refund,
    provider: {
      id: input.item.providerRefundId,
      status: input.item.status,
      failureCode: input.item.failureCode,
    },
    updatedAtMs: nowMs(input.state.now()),
  });
}

async function applyDisputeOpenedD1(input: {
  state: D1ConsoleBillingState;
  purchase: BillingCreditPurchase;
  providerDisputeId: string;
  amountMinor: number;
}): Promise<BillingDispute> {
  const existing = await loadDisputeByProviderId({
    database: input.state.database,
    namespace: input.state.namespace,
    providerDisputeId: input.providerDisputeId,
  });
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
  const createdAtMs = nowMs(input.state.now());
  const ledgerEntryId = `ble_dispute_open_${input.providerDisputeId}`;
  const disputeId = `bds_${input.providerDisputeId}`;
  const notificationStatements = await buildLowBalanceStateStatements({
    state: input.state,
    orgId: input.purchase.orgId,
    ledgerEntryId,
    createdAtMs,
  });
  await input.state.database.batch([
    createD1BillingLedgerEntryInsertStatement(input.state.database, {
      namespace: input.state.namespace,
      orgId: input.purchase.orgId,
      entryId: ledgerEntryId,
      type: 'DISPUTE_OPENED',
      amountMinor: -input.amountMinor,
      description: `Stripe dispute ${input.providerDisputeId} opened`,
      monthUtc: monthUtcFromMs(createdAtMs),
      relatedInvoiceId: input.purchase.relatedInvoiceId,
      relatedPurchaseId: input.purchase.id,
      sourceEventId: input.providerDisputeId,
      actorType: 'PROVIDER',
      actorUserId: null,
      reasonCode: 'stripe_dispute_opened',
      note: `Stripe dispute ${input.providerDisputeId} debited prepaid credit`,
      idempotencyKey: `dispute_opened:${input.providerDisputeId}`,
      createdAtMs,
    }),
    input.state.database
      .prepare(
        `INSERT INTO billing_disputes (
          namespace,
          org_id,
          id,
          purchase_id,
          provider_dispute_id,
          amount_minor,
          status,
          opened_journal_entry_id,
          resolution_journal_entry_id,
          created_at_ms,
          updated_at_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, 'open', ?, NULL, ?, ?)`,
      )
      .bind(
        input.state.namespace,
        input.purchase.orgId,
        disputeId,
        input.purchase.id,
        input.providerDisputeId,
        input.amountMinor,
        ledgerEntryId,
        createdAtMs,
        createdAtMs,
      ),
    ...notificationStatements,
  ]);
  const created = await loadDisputeByProviderId({
    database: input.state.database,
    namespace: input.state.namespace,
    providerDisputeId: input.providerDisputeId,
  });
  if (!created) {
    throw new ConsoleBillingError(
      'dispute_persistence_failed',
      500,
      'Failed to persist Stripe dispute',
    );
  }
  return created;
}

async function applyDisputeClosedD1(input: {
  state: D1ConsoleBillingState;
  dispute: BillingDispute;
  outcome: 'won' | 'lost';
}): Promise<BillingDispute> {
  if (input.dispute.status !== 'open') return input.dispute;
  const updatedAtMs = nowMs(input.state.now());
  if (input.outcome === 'lost') {
    await input.state.database
      .prepare(
        `UPDATE billing_disputes
            SET status = 'lost',
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'open'`,
      )
      .bind(updatedAtMs, input.state.namespace, input.dispute.orgId, input.dispute.id)
      .run();
  } else {
    const ledgerEntryId = `ble_dispute_won_${input.dispute.providerDisputeId}`;
    const notificationStatements = await buildLowBalanceStateStatements({
      state: input.state,
      orgId: input.dispute.orgId,
      ledgerEntryId,
      createdAtMs: updatedAtMs,
    });
    await input.state.database.batch([
      createD1BillingLedgerEntryInsertStatement(input.state.database, {
        namespace: input.state.namespace,
        orgId: input.dispute.orgId,
        entryId: ledgerEntryId,
        type: 'DISPUTE_WON',
        amountMinor: input.dispute.amountMinor,
        description: `Stripe dispute ${input.dispute.providerDisputeId} won`,
        monthUtc: monthUtcFromMs(updatedAtMs),
        relatedInvoiceId: null,
        relatedPurchaseId: input.dispute.purchaseId,
        sourceEventId: `won:${input.dispute.providerDisputeId}`,
        actorType: 'PROVIDER',
        actorUserId: null,
        reasonCode: 'stripe_dispute_won',
        note: `Stripe dispute ${input.dispute.providerDisputeId} restored prepaid credit`,
        idempotencyKey: `dispute_won:${input.dispute.providerDisputeId}`,
        createdAtMs: updatedAtMs,
      }),
      input.state.database
        .prepare(
          `UPDATE billing_disputes
              SET status = 'won',
                  resolution_journal_entry_id = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND status = 'open'`,
        )
        .bind(
          ledgerEntryId,
          updatedAtMs,
          input.state.namespace,
          input.dispute.orgId,
          input.dispute.id,
        ),
      ...notificationStatements,
    ]);
  }
  const resolved = await loadDisputeByProviderId({
    database: input.state.database,
    namespace: input.state.namespace,
    providerDisputeId: input.dispute.providerDisputeId,
  });
  if (!resolved) {
    throw new ConsoleBillingError(
      'dispute_persistence_failed',
      500,
      'Failed to persist Stripe dispute resolution',
    );
  }
  return resolved;
}

async function processStripeWebhookEventD1(input: {
  state: D1ConsoleBillingState;
  request: StripeWebhookEventRequest;
  enqueuePostProcessing: boolean;
}): Promise<StripeWebhookEventResult> {
  const currentNow = input.state.now();
  const eventId = normalizeRequiredString(input.request.eventId, 'eventId');
  const processed = await queryD1One(
    input.state.database,
    `SELECT org_id
       FROM stripe_webhook_events
      WHERE namespace = ?
        AND event_id = ?
      LIMIT 1`,
    [input.state.namespace, eventId],
  );
  if (processed) {
    if (
      input.request.eventType === 'checkout.session.completed' ||
      input.request.eventType === 'checkout.session.expired'
    ) {
      const resolved = await findCreditPurchaseForStripeEvent({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.request.orgId,
        checkoutSessionRef: input.request.checkoutSessionId,
      });
      const purchase = resolved?.purchase || null;
      const invoice =
        resolved && purchase?.relatedInvoiceId
          ? await loadPersistedInvoiceById({
              database: input.state.database,
              namespace: input.state.namespace,
              orgId: resolved.orgId,
              invoiceId: purchase.relatedInvoiceId,
            })
          : null;
      return {
        accepted: false,
        purchase,
        invoice,
        refunds: [],
        dispute: null,
        orgId: resolved?.orgId || normalizeOptionalString(processed.org_id),
      };
    }
    return {
      accepted: false,
      purchase: null,
      invoice: null,
      refunds: [],
      dispute: null,
      orgId: normalizeOptionalString(processed.org_id),
    };
  }

  let result: StripeWebhookEventResult;
  let providerRef: string;
  switch (input.request.eventType) {
    case 'checkout.session.completed': {
      providerRef = input.request.providerRef;
      const resolved = await findCreditPurchaseForStripeEvent({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.request.orgId,
        checkoutSessionRef: input.request.checkoutSessionId,
      });
      const currentOrgId = resolved?.orgId || input.request.orgId;
      if (!currentOrgId || !resolved?.purchase) {
        result = {
          accepted: true,
          purchase: null,
          invoice: null,
          refunds: [],
          dispute: null,
          orgId: currentOrgId,
        };
        break;
      }
      assertStripeCheckoutMatchesPurchase(input.request, resolved.purchase);
      const settled = await settleCreditPurchaseD1({
        state: input.state,
        orgId: currentOrgId,
        purchaseId: resolved.purchase.id,
        providerPaymentRef: input.request.providerPaymentRef,
        settledAtMs: nowMs(currentNow),
      });
      result = {
        accepted: true,
        purchase: settled.purchase,
        invoice: settled.invoice,
        refunds: [],
        dispute: null,
        orgId: currentOrgId,
      };
      break;
    }
    case 'checkout.session.expired': {
      providerRef = input.request.providerRef;
      const resolved = await findCreditPurchaseForStripeEvent({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.request.orgId,
        checkoutSessionRef: input.request.checkoutSessionId,
      });
      const currentOrgId = resolved?.orgId || input.request.orgId;
      if (!currentOrgId || !resolved?.purchase) {
        result = {
          accepted: true,
          purchase: null,
          invoice: null,
          refunds: [],
          dispute: null,
          orgId: currentOrgId,
        };
        break;
      }
      if (resolved.purchase.id !== input.request.purchaseId) {
        throw new ConsoleBillingError(
          'checkout_session_mismatch',
          409,
          'Expired Stripe Checkout session does not match the pending credit purchase',
        );
      }
      await input.state.database
        .prepare(
          `UPDATE billing_credit_purchases
              SET status = 'CANCELED',
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND status = 'PENDING'`,
        )
        .bind(nowMs(currentNow), input.state.namespace, currentOrgId, resolved.purchase.id)
        .run();
      const purchase = await loadCreditPurchaseById({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: currentOrgId,
        purchaseId: resolved.purchase.id,
      });
      result = {
        accepted: true,
        purchase,
        invoice: null,
        refunds: [],
        dispute: null,
        orgId: currentOrgId,
      };
      break;
    }
    case 'refund.created':
    case 'refund.updated': {
      providerRef = input.request.refund.providerRefundId;
      const refund = await applyRefundEventD1({
        state: input.state,
        item: input.request.refund,
      });
      result = {
        accepted: true,
        purchase: null,
        invoice: null,
        refunds: refund ? [refund] : [],
        dispute: null,
        orgId: refund?.orgId || input.request.refund.orgId,
      };
      break;
    }
    case 'charge.refunded': {
      providerRef = input.request.providerPaymentRef;
      const refunds: BillingRefund[] = [];
      for (const item of input.request.refunds) {
        const refund = await applyRefundEventD1({ state: input.state, item });
        if (refund) refunds.push(refund);
      }
      result = {
        accepted: true,
        purchase: null,
        invoice: null,
        refunds,
        dispute: null,
        orgId: refunds[0]?.orgId || input.request.orgId,
      };
      break;
    }
    case 'charge.dispute.created':
    case 'charge.dispute.closed': {
      providerRef = input.request.providerDisputeId;
      const purchase = await loadCreditPurchaseForProviderEvent({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.request.orgId,
        purchaseId: input.request.purchaseId,
        providerPaymentRef: input.request.providerPaymentRef,
      });
      let dispute: BillingDispute | null = null;
      if (purchase) {
        const opened = await applyDisputeOpenedD1({
          state: input.state,
          purchase,
          providerDisputeId: input.request.providerDisputeId,
          amountMinor: input.request.amountMinor,
        });
        dispute =
          input.request.eventType === 'charge.dispute.closed'
            ? await applyDisputeClosedD1({
                state: input.state,
                dispute: opened,
                outcome: input.request.outcome,
              })
            : opened;
      }
      result = {
        accepted: true,
        purchase,
        invoice: null,
        refunds: [],
        dispute,
        orgId: purchase?.orgId || input.request.orgId,
      };
      break;
    }
  }

  if (!result.orgId) return result;
  const statements: D1PreparedStatementLike[] = [
    input.state.database
      .prepare(
        `INSERT INTO stripe_webhook_events
        (namespace, event_id, provider_ref, org_id, processed_at_ms)
       VALUES
        (?, ?, ?, ?, ?)
       ON CONFLICT(namespace, event_id) DO NOTHING`,
      )
      .bind(input.state.namespace, eventId, providerRef, result.orgId, nowMs(currentNow)),
  ];
  if (input.enqueuePostProcessing && result.purchase?.status === 'SETTLED') {
    const payload = buildBillingStripePostProcessingPayload({
      eventId,
      purchase: result.purchase,
      invoice: result.invoice,
    });
    statements.push(
      input.state.database
        .prepare(
          `INSERT INTO billing_stripe_post_processing_outbox
            (namespace, event_id, org_id, payload_json, audit_completed_at_ms,
             customer_webhook_completed_at_ms, attempt_count, last_error,
             created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, NULL, NULL, 0, NULL, ?, ?)
           ON CONFLICT(namespace, event_id) DO NOTHING`,
        )
        .bind(
          input.state.namespace,
          eventId,
          result.orgId,
          JSON.stringify(payload),
          nowMs(currentNow),
          nowMs(currentNow),
        ),
    );
  }
  const [insertResult] = await input.state.database.batch<D1ResultLike>(statements);
  if (!insertResult) {
    throw new ConsoleBillingError(
      'stripe_webhook_persistence_failed',
      500,
      'Stripe webhook event persistence returned no result',
    );
  }
  return d1ChangedRows(insertResult) === 0 ? { ...result, accepted: false } : result;
}

export async function createD1ConsoleBillingService(
  options: D1ConsoleBillingServiceOptions,
): Promise<ConsoleBillingService> {
  const emailConsoleBaseUrl = normalizeEmailConsoleBaseUrl(options.emailConsoleBaseUrl);
  const consoleBaseUrl = normalizeEmailConsoleBaseUrl(
    options.consoleBaseUrl || emailConsoleBaseUrl,
  );
  const state: D1ConsoleBillingState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
    ...(emailConsoleBaseUrl ? { emailConsoleBaseUrl } : {}),
    ...(consoleBaseUrl ? { consoleBaseUrl } : {}),
  };
  const runtime: ConsoleBillingD1Runtime = {
    database: state.database,
    namespace: state.namespace,
    now: state.now,
    ...(state.emailConsoleBaseUrl ? { emailConsoleBaseUrl: state.emailConsoleBaseUrl } : {}),
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
      const monthlyActiveResources = await countMonthlyActiveResources({
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
        usageMetricVersion: 'active_resource_v1',
        currentMonthUtc,
        monthlyActiveResources,
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

    async getProductExecutionDebitsByIds(
      ctx: ConsoleBillingContext,
      ledgerEntryIds: string[],
    ): Promise<BillingProductExecutionDebitEntry[]> {
      const ids = Array.from(
        new Set(ledgerEntryIds.map((entryId) => String(entryId || '').trim()).filter(Boolean)),
      );
      if (ids.length === 0) return [];
      const placeholders = ids.map(() => '?').join(', ');
      const rows = await queryD1All(
        state.database,
        `SELECT *
           FROM billing_ledger_entries
          WHERE namespace = ?
            AND org_id = ?
            AND entry_type = 'PRODUCT_EXECUTION_DEBIT'
            AND id IN (${placeholders})
          ORDER BY created_at_ms DESC, id DESC`,
        [state.namespace, ctx.orgId, ...ids],
      );
      const entries = await hydrateLedgerEntryRows({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        rows,
      });
      return entries.filter(
        (entry): entry is BillingProductExecutionDebitEntry =>
          entry.type === 'PRODUCT_EXECUTION_DEBIT',
      );
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

    async getMonthlyActiveResources(
      ctx: ConsoleBillingContext,
      inputMonthUtc?: string,
    ): Promise<BillingMonthlyActiveResources> {
      const monthUtcValue = inputMonthUtc
        ? normalizeMonthUtc(inputMonthUtc)
        : monthUtc(state.now());
      const monthlyActiveResources = await countMonthlyActiveResources({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
        monthUtcValue,
      });
      return {
        usageMetricVersion: 'active_resource_v1',
        monthUtc: monthUtcValue,
        monthlyActiveResources,
      };
    },

    async recordUsageEvent(
      ctx: ConsoleBillingContext,
      request: BillingUsageEventRequest,
    ): Promise<BillingUsageEventResult> {
      return await recordUsageEventD1({ state, ctx, request });
    },

    async recordProductExecutionDebit(
      ctx: ConsoleBillingContext,
      request: BillingProductExecutionDebitRequest,
    ): Promise<BillingProductExecutionDebitResult> {
      return (await recordProductExecutionDebitD1({ state, ctx, request })).result;
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
        if (request.periodMonthUtc && invoice.periodMonthUtc !== request.periodMonthUtc)
          return false;
        if (request.documentType && invoice.documentType !== request.documentType) return false;
        return true;
      });
      const limit = normalizeListLimit(
        request.limit,
        DEFAULT_INVOICE_LIST_LIMIT,
        MAX_INVOICE_LIST_LIMIT,
      );
      const cursor = parseInvoiceCursor(request.cursor);
      const cursorAware = cursor
        ? filtered.filter((invoice) => {
            const createdAtMs = Date.parse(invoice.createdAt);
            const safeCreatedAtMs = Number.isFinite(createdAtMs) ? createdAtMs : 0;
            if (safeCreatedAtMs < cursor.createdAtMs) return true;
            if (safeCreatedAtMs > cursor.createdAtMs) return false;
            return invoice.id < cursor.id;
          })
        : filtered;
      const page = cursorAware.slice(0, limit);
      return {
        invoices: page,
        nextCursor:
          cursorAware.length > limit && page.length > 0
            ? encodeInvoiceCursor(page[page.length - 1])
            : null,
        totalCount: filtered.length,
        summary: buildInvoiceListSummary(filtered),
      };
    },

    async getInvoice(
      ctx: ConsoleBillingContext,
      invoiceId: string,
    ): Promise<BillingInvoice | null> {
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
      return await generateMonthlyInvoiceD1({
        state,
        ctx,
        periodMonthUtc,
      });
    },

    async grantManualSupportCredit(
      ctx: ConsoleBillingContext,
      request: BillingManualAdjustmentRequest,
    ): Promise<BillingManualAdjustmentResult> {
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
      const normalized = normalizeManualAdjustmentRequest(request);
      return await appendManualAdjustmentD1({
        state,
        ctx,
        request: normalized,
        amountMinor: -Math.abs(normalized.amountMinor),
        reasonCode: normalized.reasonCode,
        description: `Manual admin debit (${normalized.reasonCode})`,
      });
    },

    async listRefunds(ctx: ConsoleBillingContext): Promise<BillingRefund[]> {
      return await listRefundsD1({
        database: state.database,
        namespace: state.namespace,
        orgId: ctx.orgId,
      });
    },

    async createRefund(
      ctx: ConsoleBillingRefundSupportContext,
      request: BillingRefundRequest,
    ): Promise<BillingRefundResult> {
      return await createRefundD1({ state, providers, ctx, request });
    },

    async reconcileRefund(
      ctx: ConsoleBillingRefundSupportContext,
      request: BillingRefundReconcileRequest,
    ): Promise<BillingRefundResult> {
      return await reconcileRefundD1({ state, providers, ctx, request });
    },

    async createStripeCheckoutSession(
      ctx: ConsoleBillingContext,
      request: StripeCheckoutSessionRequest,
    ): Promise<StripeCheckoutSession> {
      const currentNow = state.now();
      const amountMinor = resolveCreditPackAmountMinorOrThrow(request.creditPackId);
      const checkoutReturnUrls = buildStripeCheckoutReturnUrls(state.consoleBaseUrl);
      const purchaseId = makeId('bcp', currentNow);
      await state.database
        .prepare(
          `INSERT INTO billing_credit_purchases
            (namespace, org_id, id, credit_pack_id, status, amount_minor, currency, provider, provider_checkout_session_ref, provider_customer_ref, provider_payment_ref, related_invoice_id, settled_at_ms, created_at_ms, updated_at_ms)
           VALUES
            (?, ?, ?, ?, 'PENDING', ?, 'USD', 'stripe', NULL, NULL, NULL, NULL, NULL, ?, ?)`,
        )
        .bind(
          state.namespace,
          ctx.orgId,
          purchaseId,
          request.creditPackId,
          amountMinor,
          nowMs(currentNow),
          nowMs(currentNow),
        )
        .run();
      const providerCheckoutSession = await providers.stripe.createCheckoutSession({
        purchaseId,
        orgId: ctx.orgId,
        ...checkoutReturnUrls,
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
          `UPDATE billing_credit_purchases
              SET provider_checkout_session_ref = ?,
                  provider_customer_ref = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND status = 'PENDING'
              AND provider_checkout_session_ref IS NULL`,
        )
        .bind(id, customerRef, nowMs(currentNow), state.namespace, ctx.orgId, purchaseId)
        .run();
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
        if (checkoutStatus === 'expired') {
          const result = await processStripeWebhookEventD1({
            state,
            enqueuePostProcessing: false,
            request: {
              eventId: `stripe_checkout_expired:${checkoutSessionId}`,
              eventType: 'checkout.session.expired',
              orgId: ctx.orgId,
              checkoutSessionId,
              providerRef: checkoutSessionId,
              purchaseId: checkoutSession.purchaseId,
            },
          });
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
      const providerPaymentRef = normalizeOptionalString(checkoutSession.paymentIntentRef);
      if (!providerPaymentRef) {
        throw new ConsoleBillingError(
          'payment_provider_error',
          502,
          'Paid Stripe checkout session is missing its payment intent',
        );
      }
      const result = await processStripeWebhookEventD1({
        state,
        enqueuePostProcessing: false,
        request: {
          eventId: `stripe_checkout_reconcile:${checkoutSessionId}`,
          eventType: 'checkout.session.completed',
          orgId: ctx.orgId,
          checkoutSessionId,
          providerCustomerRef:
            normalizeOptionalString(checkoutSession.customerRef) ||
            purchase.providerCustomerRef ||
            null,
          providerPaymentRef,
          providerRef: checkoutSessionId,
          purchaseId: checkoutSession.purchaseId,
          creditPackId: checkoutSession.creditPackId,
          amountMinor: checkoutSession.amountMinor,
          currency: checkoutSession.currency,
          paymentStatus: 'paid',
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
      return await processStripeWebhookEventD1({
        state,
        request,
        enqueuePostProcessing: true,
      });
    },

    async getStripePostProcessingOutboxItem(
      eventId: string,
    ): Promise<BillingStripePostProcessingOutboxItem | null> {
      return await loadStripePostProcessingOutboxItem({
        database: state.database,
        namespace: state.namespace,
        eventId: normalizeRequiredString(eventId, 'eventId'),
      });
    },

    async listPendingStripePostProcessingOutboxItems(
      limit: number,
    ): Promise<BillingStripePostProcessingOutboxItem[]> {
      const normalizedLimit = normalizeListLimit(limit, 25, 100);
      const rows = await queryD1All(
        state.database,
        `SELECT *
           FROM billing_stripe_post_processing_outbox
          WHERE namespace = ?
            AND (
              audit_completed_at_ms IS NULL
              OR customer_webhook_completed_at_ms IS NULL
            )
          ORDER BY created_at_ms ASC, event_id ASC
          LIMIT ?`,
        [state.namespace, normalizedLimit],
      );
      return rows.map(parseStripePostProcessingOutboxItem);
    },

    async completeStripePostProcessingEffect(input: {
      eventId: string;
      effect: BillingStripePostProcessingEffect;
    }): Promise<BillingStripePostProcessingOutboxItem | null> {
      const eventId = normalizeRequiredString(input.eventId, 'eventId');
      const completedAtMs = nowMs(state.now());
      const column =
        input.effect === 'audit' ? 'audit_completed_at_ms' : 'customer_webhook_completed_at_ms';
      await state.database
        .prepare(
          `UPDATE billing_stripe_post_processing_outbox
              SET ${column} = COALESCE(${column}, ?),
                  last_error = NULL,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND event_id = ?`,
        )
        .bind(completedAtMs, completedAtMs, state.namespace, eventId)
        .run();
      return await loadStripePostProcessingOutboxItem({
        database: state.database,
        namespace: state.namespace,
        eventId,
      });
    },

    async recordStripePostProcessingFailure(input: {
      eventId: string;
      error: string;
    }): Promise<BillingStripePostProcessingOutboxItem | null> {
      const eventId = normalizeRequiredString(input.eventId, 'eventId');
      const updatedAtMs = nowMs(state.now());
      await state.database
        .prepare(
          `UPDATE billing_stripe_post_processing_outbox
              SET attempt_count = attempt_count + 1,
                  last_error = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND event_id = ?`,
        )
        .bind(
          normalizeRequiredString(input.error, 'error').slice(0, 1000),
          updatedAtMs,
          state.namespace,
          eventId,
        )
        .run();
      return await loadStripePostProcessingOutboxItem({
        database: state.database,
        namespace: state.namespace,
        eventId,
      });
    },

    [CONSOLE_BILLING_D1_RUNTIME]: runtime,
  };

  return service;
}

export async function runD1ConsoleBillingMonthlyFinalization(
  options: D1ConsoleBillingMonthlyFinalizationOptions,
): Promise<D1ConsoleBillingMonthlyFinalizationResult> {
  const namespace = ensureNamespace(options.namespace);
  const now = options.now || defaultNow;
  const periodMonthUtc = options.periodMonthUtc
    ? normalizeMonthUtc(options.periodMonthUtc)
    : previousMonthUtc(now());
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
  const service = await createD1ConsoleBillingService({
    database: options.database,
    namespace,
    now,
  });

  let generatedCount = 0;
  let skippedCount = 0;
  const failures: D1ConsoleBillingMonthlyFinalizationResult['failures'] = [];

  for (const orgId of orgIds) {
    try {
      const out = await service.generateMonthlyInvoice(
        {
          orgId,
          actorUserId: 'system-billing-finalizer',
        },
        { periodMonthUtc },
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

async function countStatementMonths(state: D1ConsoleBillingState, orgId: string): Promise<number> {
  const row = await queryD1One(
    state.database,
    `SELECT COUNT(DISTINCT month_utc) AS statement_count
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND month_utc IS NOT NULL`,
    [state.namespace, orgId],
  );
  return Math.max(0, toNumber(row?.statement_count));
}

async function countPersistedInvoices(
  state: D1ConsoleBillingState,
  orgId: string,
): Promise<number> {
  const row = await queryD1One(
    state.database,
    `SELECT COUNT(*) AS invoice_count
       FROM invoices
      WHERE namespace = ?
        AND org_id = ?`,
    [state.namespace, orgId],
  );
  return Math.max(0, toNumber(row?.invoice_count));
}

async function countProjectedInvoices(
  state: D1ConsoleBillingState,
  orgId: string,
): Promise<number> {
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
  const counted = input.request.shouldCount;
  let debitAppliedMinor = 0;
  if (counted) {
    const sourceEventId = normalizeOptionalString(input.request.sourceEventId);
    const existingResource = await queryD1One(
      input.state.database,
      `SELECT resource_id
         FROM billing_monthly_active_resources
        WHERE namespace = ?
          AND org_id = ?
          AND month_utc = ?
          AND resource_id = ?
        LIMIT 1`,
      [input.state.namespace, input.ctx.orgId, monthUtcValue, input.request.resourceId],
    );
    if (!existingResource) {
      const entryId = makeId('ble', new Date(occurredAtMs));
      const notificationStatements = await buildLowBalanceStateStatements({
        state: input.state,
        orgId: input.ctx.orgId,
        ledgerEntryId: entryId,
        createdAtMs: occurredAtMs,
      });
      await input.state.database.batch([
        input.state.database
          .prepare(
            `INSERT INTO billing_monthly_active_resources
              (namespace, org_id, month_utc, resource_id, source_event_id, created_at_ms)
             VALUES
              (?, ?, ?, ?, ?, ?)`,
          )
          .bind(
            input.state.namespace,
            input.ctx.orgId,
            monthUtcValue,
            input.request.resourceId,
            sourceEventId,
            occurredAtMs,
          ),
        createD1BillingLedgerEntryInsertStatement(input.state.database, {
          namespace: input.state.namespace,
          orgId: input.ctx.orgId,
          entryId,
          type: 'USAGE_DEBIT',
          amountMinor: -ACTIVE_RESOURCE_USAGE_DEBIT_MINOR,
          description: `active-resource usage debit for resource ${input.request.resourceId}`,
          monthUtc: monthUtcValue,
          relatedInvoiceId: makeUsageStatementId(input.ctx.orgId, monthUtcValue),
          relatedPurchaseId: null,
          sourceEventId,
          actorType: 'USER',
          actorUserId: input.ctx.actorUserId,
          reasonCode: 'usage_debit',
          note: `Usage debit recorded for resource ${input.request.resourceId}`,
          idempotencyKey: sourceEventId
            ? `usage_debit:${sourceEventId}`
            : `usage_debit:${monthUtcValue}:${input.request.resourceId}:${occurredAtMs}`,
          createdAtMs: occurredAtMs,
        }),
        ...notificationStatements,
      ]);
      debitAppliedMinor = ACTIVE_RESOURCE_USAGE_DEBIT_MINOR;
    }
  }
  const monthlyActiveResources = await countMonthlyActiveResources({
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
    monthlyActiveResources,
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
  const existing = await queryD1One(
    input.state.database,
    `SELECT *
       FROM billing_ledger_entries
      WHERE namespace = ?
        AND org_id = ?
        AND idempotency_key = ?
      LIMIT 1`,
    [input.state.namespace, input.ctx.orgId, idempotencyKey],
  );
  if (existing) {
    const adjustment = (
      await hydrateLedgerEntryRows({
        database: input.state.database,
        namespace: input.state.namespace,
        orgId: input.ctx.orgId,
        rows: [existing],
      })
    )[0];
    if (!adjustment) {
      throw new ConsoleBillingError(
        'corrupt_billing_ledger',
        500,
        'Billing adjustment exists without postings',
      );
    }
    const account = await loadBillingAccount({
      database: input.state.database,
      namespace: input.state.namespace,
      orgId: input.ctx.orgId,
      createdAtMs: nowMs(currentNow),
    });
    return { created: false, adjustment, creditBalanceMinor: account.creditBalanceMinor };
  }
  const entryId = makeId('ble', currentNow);
  const notificationStatements = await buildLowBalanceStateStatements({
    state: input.state,
    orgId: input.ctx.orgId,
    ledgerEntryId: entryId,
    createdAtMs: nowMs(currentNow),
  });
  await input.state.database.batch([
    createD1BillingLedgerEntryInsertStatement(input.state.database, {
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
    }),
    ...notificationStatements,
  ]);
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
