import { secureRandomBase36 } from '../boundary';
import {
  d1ChangedRows,
  d1Integer,
  formatD1ExecStatement,
  queryD1All,
  queryD1One,
  type D1Row,
} from '../boundary';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../boundary';
import {
  parseConsoleEmailTemplate,
  renderConsoleEmailV1,
  renderOrganizationInvitationEmailV1,
} from './templates';
import {
  CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION,
  type ConsoleInvitationSecretCipher,
  type SealedConsoleInvitationSecret,
} from './secrets';
import type {
  ConsoleEmailDelivery,
  ConsoleEmailDeliveryOutcome,
  ConsoleEmailDispatchResult,
  ConsoleEmailFinalFailure,
  ConsoleEmailOutboxInsert,
  ConsoleEmailOutboxRecord,
  ConsoleEmailOutboxStatus,
  ConsoleEmailProvider,
  ConsoleEmailProviderSendResult,
  ConsoleEmailRecipient,
  ConsoleEmailTemplateFamily,
  ConsoleEmailTemplateV1,
  RenderedConsoleEmail,
} from './types';

const DEFAULT_DISPATCH_LIMIT = 100;
const MAX_DISPATCH_LIMIT = 200;
const DEFAULT_CLAIM_TTL_MS = 60_000;
const DEFAULT_MAX_ATTEMPTS_PER_CYCLE = 5;
const DEFAULT_INITIAL_BACKOFF_MS = 30_000;
const DEFAULT_MAX_BACKOFF_MS = 30 * 60_000;

export const CONSOLE_EMAIL_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS console_email_outbox (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      dedupe_key TEXT NOT NULL,
      recipient_email TEXT NOT NULL,
      recipient_display_name TEXT NOT NULL,
      template_family TEXT NOT NULL,
      template_version INTEGER NOT NULL,
      template_payload_json TEXT NOT NULL,
      invitation_id TEXT,
      invitation_secret_ciphertext_b64u TEXT,
      invitation_secret_key_id TEXT,
      invitation_secret_envelope_version TEXT,
      status TEXT NOT NULL,
      total_attempt_count INTEGER NOT NULL DEFAULT 0,
      cycle_attempt_count INTEGER NOT NULL DEFAULT 0,
      available_at_ms INTEGER,
      claimed_by TEXT,
      claim_expires_at_ms INTEGER,
      last_error_code TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      sent_at_ms INTEGER,
      canceled_at_ms INTEGER,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, dedupe_key),
      FOREIGN KEY (namespace, org_id)
        REFERENCES organizations(namespace, id)
        ON DELETE CASCADE,
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(id) > 0),
      CHECK (length(dedupe_key) > 0),
      CHECK (length(recipient_email) > 3),
      CHECK (instr(recipient_email, '@') > 1),
      CHECK (length(recipient_display_name) > 0),
      CHECK (
        template_family IN (
          'ORGANIZATION_INVITATION',
          'ACCOUNT_WELCOME',
          'OWNER_MEMBERSHIP_CHANGED',
          'MEMBERSHIP_ACCESS_CHANGED',
          'PREPAID_TOP_UP_RECEIPT',
          'BILLING_REFUND_RESULT',
          'LOW_BALANCE_WARNING'
        )
      ),
      CHECK (template_version = 1),
      CHECK (json_valid(template_payload_json)),
      CHECK (status IN ('PENDING', 'SENT', 'FINAL_FAILED', 'CANCELED')),
      CHECK (total_attempt_count >= 0),
      CHECK (cycle_attempt_count >= 0),
      CHECK (cycle_attempt_count <= total_attempt_count),
      CHECK (created_at_ms > 0),
      CHECK (updated_at_ms >= created_at_ms),
      CHECK (last_error_code IS NULL OR length(last_error_code) > 0),
      CHECK (
        (
          invitation_secret_ciphertext_b64u IS NULL
          AND invitation_secret_key_id IS NULL
          AND invitation_secret_envelope_version IS NULL
        )
        OR
        (
          invitation_secret_ciphertext_b64u IS NOT NULL
          AND length(invitation_secret_ciphertext_b64u) > 0
          AND invitation_secret_ciphertext_b64u NOT GLOB '*[^A-Za-z0-9_-]*'
          AND invitation_secret_key_id IS NOT NULL
          AND length(invitation_secret_key_id) > 0
          AND invitation_secret_envelope_version IS NOT NULL
          AND length(invitation_secret_envelope_version) > 0
        )
      ),
      CHECK (
        (
          template_family = 'ORGANIZATION_INVITATION'
          AND invitation_id IS NOT NULL
          AND length(invitation_id) > 0
          AND (
            invitation_secret_ciphertext_b64u IS NOT NULL
            OR status IN ('SENT', 'CANCELED')
          )
        )
        OR
        (
          template_family != 'ORGANIZATION_INVITATION'
          AND invitation_id IS NULL
          AND invitation_secret_ciphertext_b64u IS NULL
        )
      ),
      CHECK (
        (claimed_by IS NULL AND claim_expires_at_ms IS NULL)
        OR
        (
          claimed_by IS NOT NULL
          AND length(claimed_by) > 0
          AND claim_expires_at_ms IS NOT NULL
          AND claim_expires_at_ms > updated_at_ms
        )
      ),
      CHECK (
        (
          status = 'PENDING'
          AND available_at_ms IS NOT NULL
          AND available_at_ms >= created_at_ms
          AND sent_at_ms IS NULL
          AND canceled_at_ms IS NULL
        )
        OR
        (
          status = 'SENT'
          AND available_at_ms IS NULL
          AND claimed_by IS NULL
          AND claim_expires_at_ms IS NULL
          AND last_error_code IS NULL
          AND sent_at_ms IS NOT NULL
          AND sent_at_ms >= created_at_ms
          AND canceled_at_ms IS NULL
          AND total_attempt_count >= 1
        )
        OR
        (
          status = 'FINAL_FAILED'
          AND available_at_ms IS NULL
          AND claimed_by IS NULL
          AND claim_expires_at_ms IS NULL
          AND last_error_code IS NOT NULL
          AND sent_at_ms IS NULL
          AND canceled_at_ms IS NULL
          AND total_attempt_count >= 1
        )
        OR
        (
          status = 'CANCELED'
          AND available_at_ms IS NULL
          AND claimed_by IS NULL
          AND claim_expires_at_ms IS NULL
          AND last_error_code IS NULL
          AND sent_at_ms IS NULL
          AND canceled_at_ms IS NOT NULL
          AND canceled_at_ms >= created_at_ms
        )
      )
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_email_outbox_dispatch_idx
      ON console_email_outbox (
        namespace,
        status,
        available_at_ms ASC,
        created_at_ms ASC,
        id ASC
      )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_email_outbox_invitation_idx
      ON console_email_outbox (
        namespace,
        org_id,
        invitation_id,
        status
      )
      WHERE invitation_id IS NOT NULL
  `,
  `
    CREATE INDEX IF NOT EXISTS console_email_outbox_final_failure_idx
      ON console_email_outbox (
        namespace,
        org_id,
        status,
        updated_at_ms DESC,
        id DESC
      )
  `,
  `
    CREATE TABLE IF NOT EXISTS console_email_deliveries (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      outbox_id TEXT NOT NULL,
      attempt_number INTEGER NOT NULL,
      outcome TEXT NOT NULL,
      provider TEXT NOT NULL,
      provider_message_id TEXT,
      provider_status_code INTEGER,
      error_code TEXT,
      attempted_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      UNIQUE (namespace, org_id, outbox_id, attempt_number),
      FOREIGN KEY (namespace, org_id, outbox_id)
        REFERENCES console_email_outbox(namespace, org_id, id)
        ON DELETE CASCADE,
      CHECK (length(namespace) > 0),
      CHECK (length(org_id) > 0),
      CHECK (length(id) > 0),
      CHECK (length(outbox_id) > 0),
      CHECK (attempt_number > 0),
      CHECK (outcome IN ('SENT', 'RETRYABLE_FAILED', 'FINAL_FAILED')),
      CHECK (provider IN ('capture', 'resend')),
      CHECK (provider_message_id IS NULL OR length(provider_message_id) > 0),
      CHECK (provider_status_code IS NULL OR provider_status_code >= 100),
      CHECK (error_code IS NULL OR length(error_code) > 0),
      CHECK (attempted_at_ms > 0),
      CHECK (
        (
          outcome = 'SENT'
          AND provider_message_id IS NOT NULL
          AND error_code IS NULL
        )
        OR
        (
          outcome IN ('RETRYABLE_FAILED', 'FINAL_FAILED')
          AND provider_message_id IS NULL
          AND error_code IS NOT NULL
        )
      )
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS console_email_deliveries_outbox_idx
      ON console_email_deliveries (
        namespace,
        org_id,
        outbox_id,
        attempt_number DESC
      )
  `,
] as const);

export interface EnsureConsoleEmailD1SchemaOptions {
  readonly database: D1DatabaseLike;
}

export type ConsoleEmailOutboxInsertGuard = 'PREVIOUS_STATEMENT_CHANGED_ONE';

export interface CreateConsoleEmailOutboxInsertStatementOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly email: ConsoleEmailOutboxInsert;
  readonly invitationSecretCipher?: ConsoleInvitationSecretCipher;
  readonly insertGuard?: ConsoleEmailOutboxInsertGuard;
  readonly conflictPolicy?: 'ERROR' | 'IGNORE_DEDUPE';
}

export interface CreateConsoleInvitationEmailCancellationStatementOptions {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly orgId: string;
  readonly invitationId: string;
  readonly canceledAt: Date;
  readonly cancellationGuard?: ConsoleEmailOutboxInsertGuard;
}

export interface D1ConsoleEmailDispatcherOptions {
  readonly database: D1DatabaseLike;
  readonly provider: ConsoleEmailProvider;
  readonly invitationSecretCipher?: ConsoleInvitationSecretCipher;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
  readonly workerId?: string;
  readonly limit?: number;
  readonly claimTtlMs?: number;
  readonly maxAttemptsPerCycle?: number;
  readonly initialBackoffMs?: number;
  readonly maxBackoffMs?: number;
}

export interface ListD1ConsoleEmailFinalFailuresOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly orgId: string;
  readonly limit?: number;
}

export interface RetryD1ConsoleEmailFinalFailureOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly orgId: string;
  readonly outboxId: string;
  readonly now?: () => Date;
}

export interface GetD1ConsoleEmailOutboxOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly orgId: string;
  readonly outboxId: string;
}

export interface ListD1ConsoleEmailDeliveriesOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly orgId: string;
  readonly outboxId: string;
}

interface D1ConsoleEmailDispatcherState {
  readonly database: D1DatabaseLike;
  readonly provider: ConsoleEmailProvider;
  readonly invitationSecretCipher?: ConsoleInvitationSecretCipher;
  readonly namespace: string;
  readonly now: () => Date;
  readonly workerId: string;
  readonly limit: number;
  readonly claimTtlMs: number;
  readonly maxAttemptsPerCycle: number;
  readonly initialBackoffMs: number;
  readonly maxBackoffMs: number;
}

interface ClaimedConsoleEmailRow {
  readonly row: D1Row;
  readonly outboxId: string;
  readonly orgId: string;
  readonly claimToken: string;
  readonly totalAttemptCount: number;
  readonly cycleAttemptCount: number;
}

interface ClaimedConsoleEmail {
  readonly outboxId: string;
  readonly orgId: string;
  readonly recipient: ConsoleEmailRecipient;
  readonly template: ConsoleEmailTemplateV1;
  readonly invitationId: string | null;
  readonly sealedInvitationSecret: SealedConsoleInvitationSecret | null;
  readonly claimToken: string;
  readonly totalAttemptCount: number;
  readonly cycleAttemptCount: number;
}

interface PersistDeliveryInput {
  readonly state: D1ConsoleEmailDispatcherState;
  readonly claimed: ClaimedConsoleEmailRow;
  readonly outcome: ConsoleEmailDeliveryOutcome;
  readonly providerMessageId: string | null;
  readonly providerStatusCode: number | null;
  readonly errorCode: string | null;
  readonly nextStatus: ConsoleEmailOutboxStatus;
  readonly availableAtMs: number | null;
  readonly attemptedAtMs: number;
  readonly eraseInvitationSecret: boolean;
}

interface MutableDispatchResult {
  claimedCount: number;
  sentCount: number;
  retryScheduledCount: number;
  finalFailureCount: number;
  canceledCount: number;
  failures: {
    outboxId: string;
    orgId: string;
    code: string;
  }[];
}

export async function ensureConsoleEmailD1Schema(
  options: EnsureConsoleEmailD1SchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_EMAIL_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export async function createConsoleEmailOutboxInsertStatement(
  options: CreateConsoleEmailOutboxInsertStatementOptions,
): Promise<D1PreparedStatementLike> {
  const namespace = requiredText(options.namespace, 'namespace');
  const email = validateOutboxInsert(options.email);
  const sealedSecret = await sealOutboxInvitationSecret({
    namespace,
    email,
    invitationSecretCipher: options.invitationSecretCipher,
  });
  const templateJson = JSON.stringify(email.template);
  const invitationId =
    email.template.family === 'ORGANIZATION_INVITATION' ? email.template.invitationId : null;
  const sourceSql =
    options.insertGuard === 'PREVIOUS_STATEMENT_CHANGED_ONE'
      ? 'SELECT ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, NULL, ?, ?, NULL, NULL WHERE changes() = 1'
      : 'VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, 0, ?, NULL, NULL, NULL, ?, ?, NULL, NULL)';
  if (
    options.insertGuard === 'PREVIOUS_STATEMENT_CHANGED_ONE' &&
    options.conflictPolicy === 'IGNORE_DEDUPE'
  ) {
    throw new Error('IGNORE_DEDUPE cannot be combined with an insert guard');
  }
  const conflictSql =
    options.conflictPolicy === 'IGNORE_DEDUPE'
      ? ' ON CONFLICT(namespace, org_id, dedupe_key) DO NOTHING'
      : '';
  return options.database
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
       ${sourceSql}${conflictSql}`,
    )
    .bind(
      namespace,
      email.orgId,
      email.outboxId,
      email.dedupeKey,
      email.recipient.email,
      email.recipient.displayName,
      email.template.family,
      templateJson,
      invitationId,
      sealedSecret?.ciphertextB64u || null,
      sealedSecret?.keyId || null,
      sealedSecret?.envelopeVersion || null,
      'PENDING',
      email.availableAt.getTime(),
      email.createdAt.getTime(),
      email.createdAt.getTime(),
    );
}

export function createConsoleInvitationEmailCancellationStatement(
  options: CreateConsoleInvitationEmailCancellationStatementOptions,
): D1PreparedStatementLike {
  const canceledAtMs = validDate(options.canceledAt, 'canceledAt').getTime();
  const guardSql =
    options.cancellationGuard === 'PREVIOUS_STATEMENT_CHANGED_ONE'
      ? '\n          AND changes() = 1'
      : '';
  return options.database
    .prepare(
      `UPDATE console_email_outbox
          SET status = 'CANCELED',
              available_at_ms = NULL,
              claimed_by = NULL,
              claim_expires_at_ms = NULL,
              last_error_code = NULL,
              invitation_secret_ciphertext_b64u = NULL,
              invitation_secret_key_id = NULL,
              invitation_secret_envelope_version = NULL,
              updated_at_ms = ?,
              canceled_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND invitation_id = ?
          AND status IN ('PENDING', 'FINAL_FAILED')${guardSql}`,
    )
    .bind(
      canceledAtMs,
      canceledAtMs,
      normalizeNamespace(options.namespace),
      requiredText(options.orgId, 'orgId'),
      requiredText(options.invitationId, 'invitationId'),
    );
}

export async function runD1ConsoleEmailDispatcher(
  options: D1ConsoleEmailDispatcherOptions,
): Promise<ConsoleEmailDispatchResult> {
  if (options.ensureSchema) {
    await ensureConsoleEmailD1Schema({ database: options.database });
  }
  const state = createDispatcherState(options);
  const claimed = await claimPendingConsoleEmails(state);
  const result = emptyDispatchResult(claimed.length);
  for (const claimedRow of claimed) {
    await processClaimedConsoleEmail(state, claimedRow, result);
  }
  return freezeDispatchResult(result);
}

export async function listD1ConsoleEmailFinalFailures(
  options: ListD1ConsoleEmailFinalFailuresOptions,
): Promise<readonly ConsoleEmailFinalFailure[]> {
  const rows = await queryD1All(
    options.database,
    `SELECT *
       FROM console_email_outbox
      WHERE namespace = ?
        AND org_id = ?
        AND status = 'FINAL_FAILED'
      ORDER BY updated_at_ms DESC, id DESC
      LIMIT ?`,
    [
      normalizeNamespace(options.namespace),
      requiredText(options.orgId, 'orgId'),
      positiveInteger(options.limit, 50, 100),
    ],
  );
  const failures: ConsoleEmailFinalFailure[] = [];
  for (const row of rows) failures.push(parseFinalFailureRow(row));
  return failures;
}

export async function retryD1ConsoleEmailFinalFailure(
  options: RetryD1ConsoleEmailFinalFailureOptions,
): Promise<boolean> {
  const now = options.now || defaultNow;
  const nowValueMs = validDate(now(), 'now').getTime();
  const update = await options.database
    .prepare(
      `UPDATE console_email_outbox
          SET status = 'PENDING',
              cycle_attempt_count = 0,
              available_at_ms = ?,
              last_error_code = NULL,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'FINAL_FAILED'`,
    )
    .bind(
      nowValueMs,
      nowValueMs,
      normalizeNamespace(options.namespace),
      requiredText(options.orgId, 'orgId'),
      requiredText(options.outboxId, 'outboxId'),
    )
    .run();
  return d1ChangedRows(update) === 1;
}

export async function getD1ConsoleEmailOutbox(
  options: GetD1ConsoleEmailOutboxOptions,
): Promise<ConsoleEmailOutboxRecord | null> {
  const row = await queryD1One(
    options.database,
    `SELECT *
       FROM console_email_outbox
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [
      normalizeNamespace(options.namespace),
      requiredText(options.orgId, 'orgId'),
      requiredText(options.outboxId, 'outboxId'),
    ],
  );
  return row ? parseOutboxRecordRow(row) : null;
}

export async function listD1ConsoleEmailDeliveries(
  options: ListD1ConsoleEmailDeliveriesOptions,
): Promise<readonly ConsoleEmailDelivery[]> {
  const rows = await queryD1All(
    options.database,
    `SELECT *
       FROM console_email_deliveries
      WHERE namespace = ?
        AND org_id = ?
        AND outbox_id = ?
      ORDER BY attempt_number DESC`,
    [
      normalizeNamespace(options.namespace),
      requiredText(options.orgId, 'orgId'),
      requiredText(options.outboxId, 'outboxId'),
    ],
  );
  const deliveries: ConsoleEmailDelivery[] = [];
  for (const row of rows) deliveries.push(parseDeliveryRow(row));
  return deliveries;
}

function createDispatcherState(
  options: D1ConsoleEmailDispatcherOptions,
): D1ConsoleEmailDispatcherState {
  const now = options.now || defaultNow;
  return {
    database: options.database,
    provider: options.provider,
    invitationSecretCipher: options.invitationSecretCipher,
    namespace: normalizeNamespace(options.namespace),
    now,
    workerId:
      optionalText(options.workerId) ||
      `console_email_worker_${validDate(now(), 'now').getTime().toString(36)}_${secureRandomBase36(
        8,
        'console IDs',
      )}`,
    limit: positiveInteger(options.limit, DEFAULT_DISPATCH_LIMIT, MAX_DISPATCH_LIMIT),
    claimTtlMs: positiveInteger(options.claimTtlMs, DEFAULT_CLAIM_TTL_MS),
    maxAttemptsPerCycle: positiveInteger(
      options.maxAttemptsPerCycle,
      DEFAULT_MAX_ATTEMPTS_PER_CYCLE,
    ),
    initialBackoffMs: positiveInteger(options.initialBackoffMs, DEFAULT_INITIAL_BACKOFF_MS),
    maxBackoffMs: positiveInteger(options.maxBackoffMs, DEFAULT_MAX_BACKOFF_MS),
  };
}

async function claimPendingConsoleEmails(
  state: D1ConsoleEmailDispatcherState,
): Promise<ClaimedConsoleEmailRow[]> {
  const current = validDate(state.now(), 'now');
  const nowValueMs = current.getTime();
  const candidateRows = await queryD1All(
    state.database,
    `SELECT org_id, id
       FROM console_email_outbox
      WHERE namespace = ?
        AND status = 'PENDING'
        AND available_at_ms <= ?
        AND (claimed_by IS NULL OR claim_expires_at_ms <= ?)
      ORDER BY available_at_ms ASC, created_at_ms ASC, id ASC
      LIMIT ?`,
    [state.namespace, nowValueMs, nowValueMs, state.limit],
  );
  const claimed: ClaimedConsoleEmailRow[] = [];
  for (const candidate of candidateRows) {
    const orgId = rawRequiredText(candidate.org_id, 'org_id');
    const outboxId = rawRequiredText(candidate.id, 'id');
    const claimToken = makeClaimToken(state.workerId, outboxId, current);
    const claimExpiresAtMs = nowValueMs + state.claimTtlMs;
    const update = await state.database
      .prepare(
        `UPDATE console_email_outbox
            SET claimed_by = ?,
                claim_expires_at_ms = ?,
                total_attempt_count = total_attempt_count + 1,
                cycle_attempt_count = cycle_attempt_count + 1,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'PENDING'
            AND available_at_ms <= ?
            AND (claimed_by IS NULL OR claim_expires_at_ms <= ?)`,
      )
      .bind(
        claimToken,
        claimExpiresAtMs,
        nowValueMs,
        state.namespace,
        orgId,
        outboxId,
        nowValueMs,
        nowValueMs,
      )
      .run();
    if (d1ChangedRows(update) !== 1) continue;
    const row = await queryD1One(
      state.database,
      `SELECT *
         FROM console_email_outbox
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'PENDING'
          AND claimed_by = ?
          AND claim_expires_at_ms = ?
        LIMIT 1`,
      [state.namespace, orgId, outboxId, claimToken, claimExpiresAtMs],
    );
    if (!row) continue;
    claimed.push({
      row,
      outboxId,
      orgId,
      claimToken,
      totalAttemptCount: positiveRowInteger(row.total_attempt_count, 'total_attempt_count'),
      cycleAttemptCount: positiveRowInteger(row.cycle_attempt_count, 'cycle_attempt_count'),
    });
  }
  return claimed;
}

async function processClaimedConsoleEmail(
  state: D1ConsoleEmailDispatcherState,
  claimedRow: ClaimedConsoleEmailRow,
  result: MutableDispatchResult,
): Promise<void> {
  let claimed: ClaimedConsoleEmail;
  try {
    claimed = parseClaimedConsoleEmail(claimedRow);
  } catch {
    await persistFinalFailure(
      state,
      claimedRow,
      'invalid_outbox_record',
      null,
      validDate(state.now(), 'now').getTime(),
    );
    recordFinalFailure(result, claimedRow, 'invalid_outbox_record');
    return;
  }
  if (isExpiredInvitation(claimed, state.now())) {
    const canceled = await cancelClaimedInvitation(
      state,
      claimedRow,
      validDate(state.now(), 'now').getTime(),
    );
    if (canceled) result.canceledCount += 1;
    return;
  }
  let rendered: RenderedConsoleEmail;
  try {
    rendered = await renderClaimedConsoleEmail(state, claimed);
  } catch {
    await persistFinalFailure(
      state,
      claimedRow,
      'email_render_failed',
      null,
      validDate(state.now(), 'now').getTime(),
    );
    recordFinalFailure(result, claimedRow, 'email_render_failed');
    return;
  }
  const providerResult = await safeProviderSend(state, claimed, rendered);
  await persistProviderResult(state, claimedRow, providerResult, result);
}

async function renderClaimedConsoleEmail(
  state: D1ConsoleEmailDispatcherState,
  claimed: ClaimedConsoleEmail,
): Promise<RenderedConsoleEmail> {
  switch (claimed.template.family) {
    case 'ORGANIZATION_INVITATION': {
      if (
        !claimed.invitationId ||
        !claimed.sealedInvitationSecret ||
        !state.invitationSecretCipher
      ) {
        throw new Error('Invitation email is missing encrypted secret material');
      }
      const invitationSecret = await state.invitationSecretCipher.open({
        namespace: state.namespace,
        orgId: claimed.orgId,
        outboxId: claimed.outboxId,
        invitationId: claimed.invitationId,
        sealedSecret: claimed.sealedInvitationSecret,
      });
      return renderOrganizationInvitationEmailV1(claimed.template, invitationSecret);
    }
    case 'OWNER_MEMBERSHIP_CHANGED':
    case 'ACCOUNT_WELCOME':
    case 'MEMBERSHIP_ACCESS_CHANGED':
    case 'PREPAID_TOP_UP_RECEIPT':
    case 'BILLING_REFUND_RESULT':
    case 'LOW_BALANCE_WARNING':
      return renderConsoleEmailV1(claimed.template);
    default:
      return assertNever(claimed.template);
  }
}

async function safeProviderSend(
  state: D1ConsoleEmailDispatcherState,
  claimed: ClaimedConsoleEmail,
  rendered: RenderedConsoleEmail,
): Promise<ConsoleEmailProviderSendResult> {
  try {
    return await state.provider.send({
      outboxId: claimed.outboxId,
      recipient: claimed.recipient,
      subject: rendered.subject,
      text: rendered.text,
      html: rendered.html,
    });
  } catch {
    return {
      kind: 'RETRYABLE_FAILURE',
      errorCode: 'email_provider_exception',
      statusCode: null,
    };
  }
}

async function persistProviderResult(
  state: D1ConsoleEmailDispatcherState,
  claimed: ClaimedConsoleEmailRow,
  providerResult: ConsoleEmailProviderSendResult,
  result: MutableDispatchResult,
): Promise<void> {
  const attemptedAtMs = validDate(state.now(), 'now').getTime();
  switch (providerResult.kind) {
    case 'SENT': {
      const persisted = await persistDelivery({
        state,
        claimed,
        outcome: 'SENT',
        providerMessageId: requiredText(providerResult.providerMessageId, 'providerMessageId'),
        providerStatusCode: providerResult.statusCode,
        errorCode: null,
        nextStatus: 'SENT',
        availableAtMs: null,
        attemptedAtMs,
        eraseInvitationSecret: true,
      });
      if (persisted) result.sentCount += 1;
      return;
    }
    case 'RETRYABLE_FAILURE': {
      const errorCode = safeErrorCode(providerResult.errorCode);
      if (claimed.cycleAttemptCount >= state.maxAttemptsPerCycle) {
        await persistFinalFailure(
          state,
          claimed,
          errorCode,
          providerResult.statusCode,
          attemptedAtMs,
        );
        recordFinalFailure(result, claimed, errorCode);
        return;
      }
      const availableAtMs = attemptedAtMs + retryBackoffMs(state, claimed.cycleAttemptCount);
      const persisted = await persistDelivery({
        state,
        claimed,
        outcome: 'RETRYABLE_FAILED',
        providerMessageId: null,
        providerStatusCode: providerResult.statusCode,
        errorCode,
        nextStatus: 'PENDING',
        availableAtMs,
        attemptedAtMs,
        eraseInvitationSecret: false,
      });
      if (persisted) result.retryScheduledCount += 1;
      result.failures.push({
        outboxId: claimed.outboxId,
        orgId: claimed.orgId,
        code: errorCode,
      });
      return;
    }
    case 'FINAL_FAILURE': {
      const errorCode = safeErrorCode(providerResult.errorCode);
      await persistFinalFailure(
        state,
        claimed,
        errorCode,
        providerResult.statusCode,
        attemptedAtMs,
      );
      recordFinalFailure(result, claimed, errorCode);
      return;
    }
    default:
      return assertNever(providerResult);
  }
}

async function persistFinalFailure(
  state: D1ConsoleEmailDispatcherState,
  claimed: ClaimedConsoleEmailRow,
  errorCode: string,
  providerStatusCode: number | null,
  attemptedAtMs: number,
): Promise<boolean> {
  return await persistDelivery({
    state,
    claimed,
    outcome: 'FINAL_FAILED',
    providerMessageId: null,
    providerStatusCode,
    errorCode: safeErrorCode(errorCode),
    nextStatus: 'FINAL_FAILED',
    availableAtMs: null,
    attemptedAtMs,
    eraseInvitationSecret: false,
  });
}

async function persistDelivery(input: PersistDeliveryInput): Promise<boolean> {
  const update = buildOutboxResultUpdate(input);
  const insertDelivery = buildDeliveryInsert(input);
  const batchResults = await input.state.database.batch<D1ResultLike>([update, insertDelivery]);
  const updateResult = batchResults[0];
  return updateResult ? d1ChangedRows(updateResult) === 1 : false;
}

function buildOutboxResultUpdate(input: PersistDeliveryInput): D1PreparedStatementLike {
  const isSent = input.nextStatus === 'SENT';
  const lastErrorCode =
    input.nextStatus === 'PENDING' || input.nextStatus === 'FINAL_FAILED' ? input.errorCode : null;
  return input.state.database
    .prepare(
      `UPDATE console_email_outbox
          SET status = ?,
              available_at_ms = ?,
              claimed_by = NULL,
              claim_expires_at_ms = NULL,
              last_error_code = ?,
              invitation_secret_ciphertext_b64u =
                CASE WHEN ? = 1 THEN NULL ELSE invitation_secret_ciphertext_b64u END,
              invitation_secret_key_id =
                CASE WHEN ? = 1 THEN NULL ELSE invitation_secret_key_id END,
              invitation_secret_envelope_version =
                CASE WHEN ? = 1 THEN NULL ELSE invitation_secret_envelope_version END,
              updated_at_ms = ?,
              sent_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'PENDING'
          AND claimed_by = ?`,
    )
    .bind(
      input.nextStatus,
      input.availableAtMs,
      lastErrorCode,
      input.eraseInvitationSecret ? 1 : 0,
      input.eraseInvitationSecret ? 1 : 0,
      input.eraseInvitationSecret ? 1 : 0,
      input.attemptedAtMs,
      isSent ? input.attemptedAtMs : null,
      input.state.namespace,
      input.claimed.orgId,
      input.claimed.outboxId,
      input.claimed.claimToken,
    );
}

function buildDeliveryInsert(input: PersistDeliveryInput): D1PreparedStatementLike {
  return input.state.database
    .prepare(
      `INSERT INTO console_email_deliveries
        (
          namespace,
          org_id,
          id,
          outbox_id,
          attempt_number,
          outcome,
          provider,
          provider_message_id,
          provider_status_code,
          error_code,
          attempted_at_ms
        )
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE changes() = 1`,
    )
    .bind(
      input.state.namespace,
      input.claimed.orgId,
      deliveryId(input.claimed.outboxId, input.claimed.totalAttemptCount),
      input.claimed.outboxId,
      input.claimed.totalAttemptCount,
      input.outcome,
      input.state.provider.provider,
      input.providerMessageId,
      input.providerStatusCode,
      input.errorCode,
      input.attemptedAtMs,
    );
}

async function cancelClaimedInvitation(
  state: D1ConsoleEmailDispatcherState,
  claimed: ClaimedConsoleEmailRow,
  canceledAtMs: number,
): Promise<boolean> {
  const update = await state.database
    .prepare(
      `UPDATE console_email_outbox
          SET status = 'CANCELED',
              available_at_ms = NULL,
              claimed_by = NULL,
              claim_expires_at_ms = NULL,
              last_error_code = NULL,
              invitation_secret_ciphertext_b64u = NULL,
              invitation_secret_key_id = NULL,
              invitation_secret_envelope_version = NULL,
              updated_at_ms = ?,
              canceled_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'PENDING'
          AND claimed_by = ?`,
    )
    .bind(
      canceledAtMs,
      canceledAtMs,
      state.namespace,
      claimed.orgId,
      claimed.outboxId,
      claimed.claimToken,
    )
    .run();
  return d1ChangedRows(update) === 1;
}

function parseClaimedConsoleEmail(row: ClaimedConsoleEmailRow): ClaimedConsoleEmail {
  const template = parseStoredTemplate(row.row.template_payload_json);
  const recipient = {
    email: emailAddress(rawRequiredText(row.row.recipient_email, 'recipient_email')),
    displayName: rawRequiredText(row.row.recipient_display_name, 'recipient_display_name'),
  };
  const invitationId = nullableRawText(row.row.invitation_id);
  const sealedInvitationSecret = parseSealedInvitationSecret(row.row);
  validateStoredSecretState(template, invitationId, sealedInvitationSecret);
  return {
    outboxId: row.outboxId,
    orgId: row.orgId,
    recipient,
    template,
    invitationId,
    sealedInvitationSecret,
    claimToken: row.claimToken,
    totalAttemptCount: row.totalAttemptCount,
    cycleAttemptCount: row.cycleAttemptCount,
  };
}

function parseStoredTemplate(rawJson: unknown): ConsoleEmailTemplateV1 {
  if (typeof rawJson !== 'string') throw new Error('template payload must be JSON text');
  let parsed: unknown;
  try {
    parsed = JSON.parse(rawJson);
  } catch {
    throw new Error('template payload must be valid JSON');
  }
  return parseConsoleEmailTemplate(parsed);
}

function parseSealedInvitationSecret(row: D1Row): SealedConsoleInvitationSecret | null {
  const ciphertextB64u = nullableRawText(row.invitation_secret_ciphertext_b64u);
  const keyId = nullableRawText(row.invitation_secret_key_id);
  const envelopeVersion = nullableRawText(row.invitation_secret_envelope_version);
  if (!ciphertextB64u && !keyId && !envelopeVersion) return null;
  if (!ciphertextB64u || !keyId || !envelopeVersion) {
    throw new Error('Invitation secret envelope columns are incomplete');
  }
  if (envelopeVersion !== CONSOLE_INVITATION_SECRET_ENVELOPE_VERSION) {
    throw new Error('Unsupported invitation secret envelope version');
  }
  return {
    ciphertextB64u,
    keyId,
    envelopeVersion,
  };
}

function validateStoredSecretState(
  template: ConsoleEmailTemplateV1,
  invitationId: string | null,
  sealedSecret: SealedConsoleInvitationSecret | null,
): void {
  if (template.family === 'ORGANIZATION_INVITATION') {
    if (invitationId !== template.invitationId || !sealedSecret) {
      throw new Error('Invitation email secret binding is invalid');
    }
    return;
  }
  if (invitationId || sealedSecret) {
    throw new Error('Non-invitation email contains invitation secret material');
  }
}

function isExpiredInvitation(claimed: ClaimedConsoleEmail, now: Date): boolean {
  if (claimed.template.family !== 'ORGANIZATION_INVITATION') return false;
  return new Date(claimed.template.expiresAt).getTime() <= validDate(now, 'now').getTime();
}

async function sealOutboxInvitationSecret(input: {
  readonly namespace: string;
  readonly email: ConsoleEmailOutboxInsert;
  readonly invitationSecretCipher?: ConsoleInvitationSecretCipher;
}): Promise<SealedConsoleInvitationSecret | null> {
  if (input.email.template.family !== 'ORGANIZATION_INVITATION') return null;
  if (!input.invitationSecretCipher) {
    throw new Error('invitationSecretCipher is required for invitation email');
  }
  const invitationSecret = input.email.invitationSecret;
  if (typeof invitationSecret !== 'string' || !invitationSecret.trim()) {
    throw new Error('invitationSecret is required for invitation email');
  }
  return await input.invitationSecretCipher.seal({
    namespace: input.namespace,
    orgId: input.email.orgId,
    outboxId: input.email.outboxId,
    invitationId: input.email.template.invitationId,
    plaintextSecret: invitationSecret,
  });
}

function validateOutboxInsert(email: ConsoleEmailOutboxInsert): ConsoleEmailOutboxInsert {
  const createdAt = validDate(email.createdAt, 'createdAt');
  const availableAt = validDate(email.availableAt, 'availableAt');
  if (availableAt.getTime() < createdAt.getTime()) {
    throw new Error('availableAt must be at or after createdAt');
  }
  const template = parseConsoleEmailTemplate(JSON.parse(JSON.stringify(email.template)));
  const common = {
    outboxId: requiredText(email.outboxId, 'outboxId'),
    dedupeKey: requiredText(email.dedupeKey, 'dedupeKey'),
    orgId: requiredText(email.orgId, 'orgId'),
    recipient: {
      email: emailAddress(email.recipient.email),
      displayName: requiredText(email.recipient.displayName, 'recipient displayName'),
    },
    createdAt,
    availableAt,
  };
  if (template.family === 'ORGANIZATION_INVITATION') {
    const invitationSecret = inputInvitationSecret(email);
    return {
      ...common,
      template,
      invitationSecret,
    };
  }
  return {
    ...common,
    template,
  };
}

function inputInvitationSecret(email: ConsoleEmailOutboxInsert): string {
  if (email.template.family !== 'ORGANIZATION_INVITATION') {
    throw new Error('Invitation secret requested for non-invitation email');
  }
  if (typeof email.invitationSecret !== 'string') {
    throw new Error('invitationSecret is required');
  }
  return requiredText(email.invitationSecret, 'invitationSecret');
}

function parseOutboxRecordRow(row: D1Row): ConsoleEmailOutboxRecord {
  const common = {
    id: rawRequiredText(row.id, 'id'),
    orgId: rawRequiredText(row.org_id, 'org_id'),
    recipient: {
      email: emailAddress(rawRequiredText(row.recipient_email, 'recipient_email')),
      displayName: rawRequiredText(row.recipient_display_name, 'recipient_display_name'),
    },
    templateFamily: parseTemplateFamily(row.template_family),
    templateVersion: 1 as const,
    totalAttemptCount: nonNegativeRowInteger(row.total_attempt_count, 'total_attempt_count'),
    createdAt: isoFromRowMs(row.created_at_ms, 'created_at_ms'),
    updatedAt: isoFromRowMs(row.updated_at_ms, 'updated_at_ms'),
  };
  const status = parseOutboxStatus(row.status);
  switch (status) {
    case 'PENDING':
      return {
        ...common,
        status,
        availableAt: isoFromRowMs(row.available_at_ms, 'available_at_ms'),
        sentAt: null,
        canceledAt: null,
        lastErrorCode: nullableRawText(row.last_error_code),
      };
    case 'SENT':
      return {
        ...common,
        status,
        availableAt: null,
        sentAt: isoFromRowMs(row.sent_at_ms, 'sent_at_ms'),
        canceledAt: null,
        lastErrorCode: null,
      };
    case 'FINAL_FAILED':
      return {
        ...common,
        status,
        availableAt: null,
        sentAt: null,
        canceledAt: null,
        lastErrorCode: rawRequiredText(row.last_error_code, 'last_error_code'),
      };
    case 'CANCELED':
      return {
        ...common,
        status,
        availableAt: null,
        sentAt: null,
        canceledAt: isoFromRowMs(row.canceled_at_ms, 'canceled_at_ms'),
        lastErrorCode: null,
      };
    default:
      return assertNever(status);
  }
}

function parseFinalFailureRow(row: D1Row): ConsoleEmailFinalFailure {
  return {
    outboxId: rawRequiredText(row.id, 'id'),
    orgId: rawRequiredText(row.org_id, 'org_id'),
    recipient: {
      email: emailAddress(rawRequiredText(row.recipient_email, 'recipient_email')),
      displayName: rawRequiredText(row.recipient_display_name, 'recipient_display_name'),
    },
    templateFamily: parseTemplateFamily(row.template_family),
    totalAttemptCount: positiveRowInteger(row.total_attempt_count, 'total_attempt_count'),
    lastErrorCode: rawRequiredText(row.last_error_code, 'last_error_code'),
    failedAt: isoFromRowMs(row.updated_at_ms, 'updated_at_ms'),
  };
}

function parseDeliveryRow(row: D1Row): ConsoleEmailDelivery {
  return {
    id: rawRequiredText(row.id, 'id'),
    outboxId: rawRequiredText(row.outbox_id, 'outbox_id'),
    orgId: rawRequiredText(row.org_id, 'org_id'),
    attemptNumber: positiveRowInteger(row.attempt_number, 'attempt_number'),
    outcome: parseDeliveryOutcome(row.outcome),
    provider: parseProvider(row.provider),
    providerMessageId: nullableRawText(row.provider_message_id),
    providerStatusCode:
      row.provider_status_code === null || row.provider_status_code === undefined
        ? null
        : positiveRowInteger(row.provider_status_code, 'provider_status_code'),
    errorCode: nullableRawText(row.error_code),
    attemptedAt: isoFromRowMs(row.attempted_at_ms, 'attempted_at_ms'),
  };
}

function parseOutboxStatus(value: unknown): ConsoleEmailOutboxStatus {
  switch (value) {
    case 'PENDING':
    case 'SENT':
    case 'FINAL_FAILED':
    case 'CANCELED':
      return value;
    default:
      throw new Error('Invalid console email outbox status');
  }
}

function parseDeliveryOutcome(value: unknown): ConsoleEmailDeliveryOutcome {
  switch (value) {
    case 'SENT':
    case 'RETRYABLE_FAILED':
    case 'FINAL_FAILED':
      return value;
    default:
      throw new Error('Invalid console email delivery outcome');
  }
}

function parseProvider(value: unknown): 'capture' | 'resend' {
  switch (value) {
    case 'capture':
    case 'resend':
      return value;
    default:
      throw new Error('Invalid console email delivery provider');
  }
}

function parseTemplateFamily(value: unknown): ConsoleEmailTemplateFamily {
  switch (value) {
    case 'ACCOUNT_WELCOME':
    case 'ORGANIZATION_INVITATION':
    case 'OWNER_MEMBERSHIP_CHANGED':
    case 'MEMBERSHIP_ACCESS_CHANGED':
    case 'PREPAID_TOP_UP_RECEIPT':
    case 'BILLING_REFUND_RESULT':
    case 'LOW_BALANCE_WARNING':
      return value;
    default:
      throw new Error('Invalid console email template family');
  }
}

function emptyDispatchResult(claimedCount: number): MutableDispatchResult {
  return {
    claimedCount,
    sentCount: 0,
    retryScheduledCount: 0,
    finalFailureCount: 0,
    canceledCount: 0,
    failures: [],
  };
}

function freezeDispatchResult(result: MutableDispatchResult): ConsoleEmailDispatchResult {
  return {
    claimedCount: result.claimedCount,
    sentCount: result.sentCount,
    retryScheduledCount: result.retryScheduledCount,
    finalFailureCount: result.finalFailureCount,
    canceledCount: result.canceledCount,
    failures: result.failures,
  };
}

function recordFinalFailure(
  result: MutableDispatchResult,
  claimed: ClaimedConsoleEmailRow,
  errorCode: string,
): void {
  result.finalFailureCount += 1;
  result.failures.push({
    outboxId: claimed.outboxId,
    orgId: claimed.orgId,
    code: safeErrorCode(errorCode),
  });
}

function retryBackoffMs(state: D1ConsoleEmailDispatcherState, cycleAttemptCount: number): number {
  const exponent = Math.max(0, Math.min(20, cycleAttemptCount - 1));
  return Math.min(state.maxBackoffMs, state.initialBackoffMs * 2 ** exponent);
}

function deliveryId(outboxId: string, attemptNumber: number): string {
  return `email_delivery_${outboxId}_${attemptNumber}`;
}

function makeClaimToken(workerId: string, outboxId: string, now: Date): string {
  return `${workerId}:${outboxId}:${now.getTime().toString(36)}:${secureRandomBase36(
    8,
    'console IDs',
  )}`;
}

function normalizeNamespace(value: string | undefined): string {
  return optionalText(value) || 'default';
}

function emailAddress(value: string): string {
  const normalized = requiredText(value, 'recipient email').toLowerCase();
  if (normalized.includes(' ') || !/^[^@]+@[^@]+\.[^@]+$/.test(normalized)) {
    throw new Error('recipient email is invalid');
  }
  return normalized;
}

function safeErrorCode(value: string): string {
  const normalized = requiredText(value, 'errorCode')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]/g, '_')
    .slice(0, 120);
  return normalized || 'email_delivery_failed';
}

function validDate(value: Date, field: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new Error(`${field} must be a valid Date`);
  }
  if (value.getTime() <= 0) throw new Error(`${field} must be after the Unix epoch`);
  return new Date(value.getTime());
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0 || value > maximum) {
    throw new Error(`Expected a positive integer no greater than ${maximum}`);
  }
  return value;
}

function positiveRowInteger(value: unknown, field: string): number {
  const parsed = d1Integer(value, 0);
  if (parsed <= 0) throw new Error(`${field} must be positive`);
  return parsed;
}

function nonNegativeRowInteger(value: unknown, field: string): number {
  const parsed = d1Integer(value, -1);
  if (parsed < 0) throw new Error(`${field} must be non-negative`);
  return parsed;
}

function isoFromRowMs(value: unknown, field: string): string {
  const parsed = positiveRowInteger(value, field);
  return new Date(parsed).toISOString();
}

function rawRequiredText(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new Error(`${field} must be text`);
  return requiredText(value, field);
}

function nullableRawText(value: unknown): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw new Error('Expected nullable text');
  const normalized = value.trim();
  return normalized || null;
}

function requiredText(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) throw new Error(`${field} is required`);
  return normalized;
}

function optionalText(value: string | undefined): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function defaultNow(): Date {
  return new Date();
}

function assertNever(value: never): never {
  throw new Error(`Unhandled console email state: ${JSON.stringify(value)}`);
}
