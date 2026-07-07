import { secureRandomBase36 } from '@seams-internal/shared-ts/utils/secureRandomId';
import { d1Integer as toNumber, d1ChangedRows, formatD1ExecStatement, queryD1One, type D1Row } from '@seams/sdk-server/internal/storage/d1Sql';
import type { D1DatabaseLike } from '@seams/sdk-server/internal/storage/tenantRoute';
import { ConsoleSponsorshipSpendCapError } from './errors';
import {
  buildConsoleSponsorshipSpendCapWindowUsage,
  createSpendCapExceededError,
  fromStoredAccountRef,
  normalizeReleaseRequest,
  normalizeReserveRequest,
  normalizeSettleRequest,
  normalizeWindowUsageRequest,
} from './shared';
import type {
  ConsoleSponsorshipSpendCapContext,
  ConsoleSponsorshipSpendCapService,
} from './service';
import type {
  ConsoleSponsorshipSpendCapMode,
  ConsoleSponsorshipSpendCapPeriod,
  ConsoleSponsorshipSpendCapReservation,
  ConsoleSponsorshipSpendCapReservationOutcome,
  ConsoleSponsorshipSpendCapReservationStatus,
  ConsoleSponsorshipSpendCapWindowUsage,
} from './types';

interface D1ConsoleSponsorshipSpendCapState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

interface SpendCapBucketKey {
  readonly namespace: string;
  readonly orgId: string;
  readonly environmentId: string;
  readonly policyId: string;
  readonly accountRef: string;
  readonly chainId: number;
  readonly mode: ConsoleSponsorshipSpendCapMode;
  readonly period: ConsoleSponsorshipSpendCapPeriod;
  readonly windowStartMs: number;
}

export const CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME = Symbol(
  'consoleSponsorshipSpendCapD1Runtime',
);

export interface ConsoleSponsorshipSpendCapD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleSponsorshipSpendCapD1Service =
  ConsoleSponsorshipSpendCapService & {
    readonly [CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME]: ConsoleSponsorshipSpendCapD1Runtime;
  };

export interface D1ConsoleSponsorshipSpendCapSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleSponsorshipSpendCapServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_SPONSORSHIP_SPEND_CAP_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS sponsorship_spend_cap_windows (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      account_ref TEXT NOT NULL DEFAULT '',
      chain_id INTEGER NOT NULL,
      mode TEXT NOT NULL,
      period TEXT NOT NULL,
      window_start_ms INTEGER NOT NULL,
      window_end_ms INTEGER NOT NULL,
      cap_minor INTEGER NOT NULL,
      reserved_minor INTEGER NOT NULL DEFAULT 0,
      settled_minor INTEGER NOT NULL DEFAULT 0,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (
        namespace,
        org_id,
        environment_id,
        policy_id,
        account_ref,
        chain_id,
        mode,
        period,
        window_start_ms
      ),
      CHECK (chain_id > 0),
      CHECK (mode IN ('CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL')),
      CHECK (period IN ('WEEKLY', 'MONTHLY')),
      CHECK (window_end_ms > window_start_ms),
      CHECK (cap_minor >= 0),
      CHECK (reserved_minor >= 0),
      CHECK (settled_minor >= 0)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS sponsorship_spend_cap_reservations (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      policy_id TEXT NOT NULL,
      account_ref TEXT NOT NULL DEFAULT '',
      chain_id INTEGER NOT NULL,
      mode TEXT NOT NULL,
      period TEXT NOT NULL,
      window_start_ms INTEGER NOT NULL,
      window_end_ms INTEGER NOT NULL,
      cap_minor INTEGER NOT NULL,
      requested_minor INTEGER NOT NULL,
      settled_minor INTEGER NOT NULL DEFAULT 0,
      released_minor INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      source_event_id TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (chain_id > 0),
      CHECK (mode IN ('CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL')),
      CHECK (period IN ('WEEKLY', 'MONTHLY')),
      CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED')),
      CHECK (window_end_ms > window_start_ms),
      CHECK (cap_minor >= 0),
      CHECK (requested_minor >= 0),
      CHECK (settled_minor >= 0),
      CHECK (released_minor >= 0)
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS sponsorship_spend_cap_source_event_idx
      ON sponsorship_spend_cap_reservations (namespace, org_id, source_event_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS sponsorship_spend_cap_windows_updated_idx
      ON sponsorship_spend_cap_windows (namespace, org_id, updated_at_ms DESC)
  `,
  `
    CREATE TRIGGER IF NOT EXISTS sponsorship_spend_cap_reservations_reserve_insert
    BEFORE INSERT ON sponsorship_spend_cap_reservations
    WHEN NEW.status = 'RESERVED'
    BEGIN
      INSERT INTO sponsorship_spend_cap_windows (
        namespace,
        org_id,
        environment_id,
        policy_id,
        account_ref,
        chain_id,
        mode,
        period,
        window_start_ms,
        window_end_ms,
        cap_minor,
        reserved_minor,
        settled_minor,
        created_at_ms,
        updated_at_ms
      )
      VALUES (
        NEW.namespace,
        NEW.org_id,
        NEW.environment_id,
        NEW.policy_id,
        NEW.account_ref,
        NEW.chain_id,
        NEW.mode,
        NEW.period,
        NEW.window_start_ms,
        NEW.window_end_ms,
        NEW.cap_minor,
        0,
        0,
        NEW.created_at_ms,
        NEW.created_at_ms
      )
      ON CONFLICT (
        namespace,
        org_id,
        environment_id,
        policy_id,
        account_ref,
        chain_id,
        mode,
        period,
        window_start_ms
      ) DO NOTHING;

      SELECT CASE
        WHEN (
          SELECT reserved_minor + settled_minor
            FROM sponsorship_spend_cap_windows
           WHERE namespace = NEW.namespace
             AND org_id = NEW.org_id
             AND environment_id = NEW.environment_id
             AND policy_id = NEW.policy_id
             AND account_ref = NEW.account_ref
             AND chain_id = NEW.chain_id
             AND mode = NEW.mode
             AND period = NEW.period
             AND window_start_ms = NEW.window_start_ms
        ) + NEW.requested_minor > NEW.cap_minor
        THEN RAISE(ABORT, 'sponsorship_spend_cap_exceeded')
      END;

      UPDATE sponsorship_spend_cap_windows
         SET window_end_ms = NEW.window_end_ms,
             cap_minor = NEW.cap_minor,
             reserved_minor = reserved_minor + NEW.requested_minor,
             updated_at_ms = NEW.created_at_ms
       WHERE namespace = NEW.namespace
         AND org_id = NEW.org_id
         AND environment_id = NEW.environment_id
         AND policy_id = NEW.policy_id
         AND account_ref = NEW.account_ref
         AND chain_id = NEW.chain_id
         AND mode = NEW.mode
         AND period = NEW.period
         AND window_start_ms = NEW.window_start_ms;
    END
  `,
  `
    CREATE TRIGGER IF NOT EXISTS sponsorship_spend_cap_reservations_settle_update
    BEFORE UPDATE OF status ON sponsorship_spend_cap_reservations
    WHEN OLD.status = 'RESERVED' AND NEW.status = 'SETTLED'
    BEGIN
      SELECT CASE
        WHEN NOT EXISTS (
          SELECT 1
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        )
        THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
      END;

      SELECT CASE
        WHEN (
          SELECT reserved_minor
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        ) < OLD.requested_minor
        THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
      END;

      SELECT CASE
        WHEN (
          SELECT reserved_minor + settled_minor - OLD.requested_minor + NEW.settled_minor
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        ) > (
          SELECT cap_minor
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        )
        THEN RAISE(ABORT, 'sponsorship_spend_cap_exceeded')
      END;

      UPDATE sponsorship_spend_cap_windows
         SET reserved_minor = reserved_minor - OLD.requested_minor,
             settled_minor = settled_minor + NEW.settled_minor,
             updated_at_ms = NEW.updated_at_ms
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms;
    END
  `,
  `
    CREATE TRIGGER IF NOT EXISTS sponsorship_spend_cap_reservations_release_update
    BEFORE UPDATE OF status ON sponsorship_spend_cap_reservations
    WHEN OLD.status = 'RESERVED' AND NEW.status = 'RELEASED'
    BEGIN
      SELECT CASE
        WHEN NOT EXISTS (
          SELECT 1
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        )
        THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
      END;

      SELECT CASE
        WHEN (
          SELECT reserved_minor
            FROM sponsorship_spend_cap_windows
           WHERE namespace = OLD.namespace
             AND org_id = OLD.org_id
             AND environment_id = OLD.environment_id
             AND policy_id = OLD.policy_id
             AND account_ref = OLD.account_ref
             AND chain_id = OLD.chain_id
             AND mode = OLD.mode
             AND period = OLD.period
             AND window_start_ms = OLD.window_start_ms
        ) < OLD.requested_minor
        THEN RAISE(ABORT, 'sponsorship_spend_cap_inconsistent')
      END;

      UPDATE sponsorship_spend_cap_windows
         SET reserved_minor = reserved_minor - OLD.requested_minor,
             updated_at_ms = NEW.updated_at_ms
       WHERE namespace = OLD.namespace
         AND org_id = OLD.org_id
         AND environment_id = OLD.environment_id
         AND policy_id = OLD.policy_id
         AND account_ref = OLD.account_ref
         AND chain_id = OLD.chain_id
         AND mode = OLD.mode
         AND period = OLD.period
         AND window_start_ms = OLD.window_start_ms;
    END
  `,
] as const);

export async function ensureConsoleSponsorshipSpendCapD1Schema(
  options: D1ConsoleSponsorshipSpendCapSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_SPONSORSHIP_SPEND_CAP_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleSponsorshipSpendCapD1Runtime(
  service: ConsoleSponsorshipSpendCapService | null | undefined,
): ConsoleSponsorshipSpendCapD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleSponsorshipSpendCapD1Service>)[
      CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME
    ] || null
  );
}

export async function createD1ConsoleSponsorshipSpendCapService(
  options: D1ConsoleSponsorshipSpendCapServiceOptions,
): Promise<ConsoleSponsorshipSpendCapD1Service> {
  const state: D1ConsoleSponsorshipSpendCapState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleSponsorshipSpendCapD1Schema({ database: state.database });
  }
  return new D1ConsoleSponsorshipSpendCapServiceImpl(state) as ConsoleSponsorshipSpendCapD1Service;
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


function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}


function parseMode(value: unknown): ConsoleSponsorshipSpendCapMode {
  const normalized = String(value || '').trim();
  if (normalized === 'CHAIN_TOTAL' || normalized === 'WALLET_CHAIN_TOTAL') {
    return normalized;
  }
  throw new Error(`Invalid spend cap mode row: ${normalized || 'empty'}`);
}

function parsePeriod(value: unknown): ConsoleSponsorshipSpendCapPeriod {
  const normalized = String(value || '').trim();
  if (normalized === 'WEEKLY' || normalized === 'MONTHLY') return normalized;
  throw new Error(`Invalid spend cap period row: ${normalized || 'empty'}`);
}

function parseStatus(value: unknown): ConsoleSponsorshipSpendCapReservationStatus {
  const normalized = String(value || '').trim();
  if (normalized === 'RESERVED' || normalized === 'SETTLED' || normalized === 'RELEASED') {
    return normalized;
  }
  throw new Error(`Invalid spend cap reservation status row: ${normalized || 'empty'}`);
}

function parseReservation(row: D1Row): ConsoleSponsorshipSpendCapReservation {
  const mode = parseMode(row.mode);
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    policyId: String(row.policy_id || ''),
    accountRef: fromStoredAccountRef(mode, row.account_ref),
    chainId: Math.max(0, toNumber(row.chain_id)),
    mode,
    period: parsePeriod(row.period),
    capMinor: Math.max(0, toNumber(row.cap_minor)),
    requestedMinor: Math.max(0, toNumber(row.requested_minor)),
    settledMinor: Math.max(0, toNumber(row.settled_minor)),
    releasedMinor: Math.max(0, toNumber(row.released_minor)),
    status: parseStatus(row.status),
    sourceEventId: String(row.source_event_id || ''),
    windowStartAt: toIso(toNumber(row.window_start_ms)),
    windowEndAt: toIso(toNumber(row.window_end_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseUsage(row: D1Row): ConsoleSponsorshipSpendCapWindowUsage {
  const mode = parseMode(row.mode);
  const windowStartMs = Math.max(0, toNumber(row.window_start_ms));
  const windowEndMs = Math.max(windowStartMs, toNumber(row.window_end_ms));
  return buildConsoleSponsorshipSpendCapWindowUsage({
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    policyId: String(row.policy_id || ''),
    accountRef: fromStoredAccountRef(mode, row.account_ref),
    chainId: Math.max(0, toNumber(row.chain_id)),
    mode,
    period: parsePeriod(row.period),
    capMinor: Math.max(0, toNumber(row.cap_minor)),
    reservedMinor: Math.max(0, toNumber(row.reserved_minor)),
    settledMinor: Math.max(0, toNumber(row.settled_minor)),
    windowStartMs,
    windowEndMs,
    windowStartAt: toIso(windowStartMs),
    windowEndAt: toIso(windowEndMs),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  });
}

function bucketFromReservation(input: {
  readonly namespace: string;
  readonly reservation: ConsoleSponsorshipSpendCapReservation;
}): SpendCapBucketKey {
  return {
    namespace: input.namespace,
    orgId: input.reservation.orgId,
    environmentId: input.reservation.environmentId,
    policyId: input.reservation.policyId,
    accountRef: input.reservation.mode === 'CHAIN_TOTAL' ? '' : input.reservation.accountRef || '',
    chainId: input.reservation.chainId,
    mode: input.reservation.mode,
    period: input.reservation.period,
    windowStartMs: Date.parse(input.reservation.windowStartAt),
  };
}

async function loadReservationBySourceEventId(
  database: D1DatabaseLike,
  input: {
    readonly namespace: string;
    readonly orgId: string;
    readonly sourceEventId: string;
  },
): Promise<ConsoleSponsorshipSpendCapReservation | null> {
  const row = await queryD1One(
    database,
    `SELECT *
       FROM sponsorship_spend_cap_reservations
      WHERE namespace = ?
        AND org_id = ?
        AND source_event_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.sourceEventId],
  );
  return row ? parseReservation(row) : null;
}

async function loadUsageByBucket(
  database: D1DatabaseLike,
  bucket: SpendCapBucketKey,
): Promise<ConsoleSponsorshipSpendCapWindowUsage | null> {
  const row = await queryD1One(
    database,
    `SELECT *
       FROM sponsorship_spend_cap_windows
      WHERE namespace = ?
        AND org_id = ?
        AND environment_id = ?
        AND policy_id = ?
        AND account_ref = ?
        AND chain_id = ?
        AND mode = ?
        AND period = ?
        AND window_start_ms = ?
      LIMIT 1`,
    [
      bucket.namespace,
      bucket.orgId,
      bucket.environmentId,
      bucket.policyId,
      bucket.accountRef,
      bucket.chainId,
      bucket.mode,
      bucket.period,
      bucket.windowStartMs,
    ],
  );
  return row ? parseUsage(row) : null;
}

async function loadUsageForReservation(
  database: D1DatabaseLike,
  input: {
    readonly namespace: string;
    readonly reservation: ConsoleSponsorshipSpendCapReservation;
  },
): Promise<ConsoleSponsorshipSpendCapWindowUsage> {
  const usage = await loadUsageByBucket(
    database,
    bucketFromReservation({
      namespace: input.namespace,
      reservation: input.reservation,
    }),
  );
  if (usage) return usage;
  const windowStartMs = Date.parse(input.reservation.windowStartAt);
  const windowEndMs = Date.parse(input.reservation.windowEndAt);
  return buildConsoleSponsorshipSpendCapWindowUsage({
    orgId: input.reservation.orgId,
    environmentId: input.reservation.environmentId,
    policyId: input.reservation.policyId,
    accountRef: input.reservation.accountRef,
    chainId: input.reservation.chainId,
    mode: input.reservation.mode,
    period: input.reservation.period,
    capMinor: input.reservation.capMinor,
    reservedMinor: input.reservation.status === 'RESERVED' ? input.reservation.requestedMinor : 0,
    settledMinor: input.reservation.status === 'SETTLED' ? input.reservation.settledMinor : 0,
    windowStartMs,
    windowEndMs,
    windowStartAt: input.reservation.windowStartAt,
    windowEndAt: input.reservation.windowEndAt,
    createdAt: input.reservation.createdAt,
    updatedAt: input.reservation.updatedAt,
  });
}

function buildOutcome(input: {
  readonly reservation: ConsoleSponsorshipSpendCapReservation;
  readonly usage: ConsoleSponsorshipSpendCapWindowUsage;
}): ConsoleSponsorshipSpendCapReservationOutcome {
  return {
    reservation: { ...input.reservation },
    usage: { ...input.usage },
  };
}

function isSpendCapExceededError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('sponsorship_spend_cap_exceeded');
}

function isSpendCapInconsistentError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('sponsorship_spend_cap_inconsistent');
}

function isD1ConstraintError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('UNIQUE constraint failed') || message.includes('constraint failed');
}

async function throwSpendCapExceededFromBucket(input: {
  readonly database: D1DatabaseLike;
  readonly bucket: SpendCapBucketKey;
  readonly capMinor: number;
  readonly requestedMinor: number;
}): Promise<never> {
  const usage = await loadUsageByBucket(input.database, input.bucket);
  throw createSpendCapExceededError({
    capMinor: usage?.capMinor ?? input.capMinor,
    reservedMinor: usage?.reservedMinor ?? 0,
    settledMinor: usage?.settledMinor ?? 0,
    requestedMinor: input.requestedMinor,
  });
}

async function throwSpendCapExceededFromReservation(input: {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly reservation: ConsoleSponsorshipSpendCapReservation;
  readonly requestedMinor: number;
}): Promise<never> {
  const usage = await loadUsageForReservation(input.database, {
    namespace: input.namespace,
    reservation: input.reservation,
  });
  throw createSpendCapExceededError({
    capMinor: usage.capMinor,
    reservedMinor: Math.max(0, usage.reservedMinor - input.reservation.requestedMinor),
    settledMinor: usage.settledMinor,
    requestedMinor: input.requestedMinor,
  });
}

function throwSpendCapInconsistent(): never {
  throw new ConsoleSponsorshipSpendCapError(
    'invalid_state',
    409,
    'Spend cap window usage is inconsistent with the reservation',
  );
}

class D1ConsoleSponsorshipSpendCapServiceImpl
  implements ConsoleSponsorshipSpendCapService
{
  readonly [CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME]: ConsoleSponsorshipSpendCapD1Runtime;

  private readonly state: D1ConsoleSponsorshipSpendCapState;

  constructor(state: D1ConsoleSponsorshipSpendCapState) {
    this.state = state;
    this[CONSOLE_SPONSORSHIP_SPEND_CAP_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.getReservationBySourceEventId = this.getReservationBySourceEventId.bind(this);
    this.getWindowUsage = this.getWindowUsage.bind(this);
    this.reserve = this.reserve.bind(this);
    this.settle = this.settle.bind(this);
    this.release = this.release.bind(this);
  }

  async getReservationBySourceEventId(
    ctx: ConsoleSponsorshipSpendCapContext,
    sourceEventId: string,
  ): Promise<ConsoleSponsorshipSpendCapReservation | null> {
    const normalized = normalizeString(sourceEventId);
    if (!normalized) return null;
    return await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized,
    });
  }

  async getWindowUsage(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: Parameters<ConsoleSponsorshipSpendCapService['getWindowUsage']>[1],
  ): Promise<ConsoleSponsorshipSpendCapWindowUsage | null> {
    const normalized = normalizeWindowUsageRequest(request);
    return await loadUsageByBucket(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      environmentId: normalized.environmentId,
      policyId: normalized.policyId,
      accountRef: normalized.storedAccountRef,
      chainId: normalized.chainId,
      mode: normalized.mode,
      period: normalized.period,
      windowStartMs: normalized.windowStartMs,
    });
  }

  async reserve(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: Parameters<ConsoleSponsorshipSpendCapService['reserve']>[1],
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome> {
    const currentNow = this.state.now();
    const createdAtMs = nowMs(currentNow);
    const normalized = normalizeReserveRequest(request, currentNow);
    const existing = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (existing) {
      return buildOutcome({
        reservation: existing,
        usage: await loadUsageForReservation(this.state.database, {
          namespace: this.state.namespace,
          reservation: existing,
        }),
      });
    }
    try {
      await this.state.database
        .prepare(
          `INSERT INTO sponsorship_spend_cap_reservations (
             namespace,
             org_id,
             id,
             environment_id,
             policy_id,
             account_ref,
             chain_id,
             mode,
             period,
             window_start_ms,
             window_end_ms,
             cap_minor,
             requested_minor,
             settled_minor,
             released_minor,
             status,
             source_event_id,
             created_at_ms,
             updated_at_ms
           )
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'RESERVED', ?, ?, ?)`,
        )
        .bind(
          this.state.namespace,
          ctx.orgId,
          makeId('sscr', currentNow),
          normalized.environmentId,
          normalized.policyId,
          normalized.storedAccountRef,
          normalized.chainId,
          normalized.mode,
          normalized.period,
          normalized.windowStartMs,
          normalized.windowEndMs,
          normalized.capMinor,
          normalized.estimatedSpendMinor,
          normalized.sourceEventId,
          createdAtMs,
          createdAtMs,
        )
        .run();
    } catch (error: unknown) {
      const existingAfterConflict = await loadReservationBySourceEventId(this.state.database, {
        namespace: this.state.namespace,
        orgId: ctx.orgId,
        sourceEventId: normalized.sourceEventId,
      });
      if (existingAfterConflict) {
        return buildOutcome({
          reservation: existingAfterConflict,
          usage: await loadUsageForReservation(this.state.database, {
            namespace: this.state.namespace,
            reservation: existingAfterConflict,
          }),
        });
      }
      if (isSpendCapExceededError(error) || isD1ConstraintError(error)) {
        await throwSpendCapExceededFromBucket({
          database: this.state.database,
          bucket: {
            namespace: this.state.namespace,
            orgId: ctx.orgId,
            environmentId: normalized.environmentId,
            policyId: normalized.policyId,
            accountRef: normalized.storedAccountRef,
            chainId: normalized.chainId,
            mode: normalized.mode,
            period: normalized.period,
            windowStartMs: normalized.windowStartMs,
          },
          capMinor: normalized.capMinor,
          requestedMinor: normalized.estimatedSpendMinor,
        });
      }
      throw error;
    }
    const reservation = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (!reservation) {
      throw new ConsoleSponsorshipSpendCapError(
        'reservation_failed',
        500,
        'Failed to create sponsorship spend-cap reservation',
      );
    }
    return buildOutcome({
      reservation,
      usage: await loadUsageForReservation(this.state.database, {
        namespace: this.state.namespace,
        reservation,
      }),
    });
  }

  async settle(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: Parameters<ConsoleSponsorshipSpendCapService['settle']>[1],
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome | null> {
    const updatedAtMs = nowMs(this.state.now());
    const normalized = normalizeSettleRequest(request);
    const reservation = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (!reservation) return null;
    if (reservation.status === 'SETTLED') {
      if (reservation.settledMinor !== normalized.settledSpendMinor) {
        throw new ConsoleSponsorshipSpendCapError(
          'invalid_state',
          409,
          'Spend cap reservation is already settled with a different amount',
        );
      }
      return buildOutcome({
        reservation,
        usage: await loadUsageForReservation(this.state.database, {
          namespace: this.state.namespace,
          reservation,
        }),
      });
    }
    if (reservation.status === 'RELEASED') {
      throw new ConsoleSponsorshipSpendCapError(
        'invalid_state',
        409,
        'Released spend cap reservations cannot be settled',
      );
    }
    try {
      const result = await this.state.database
        .prepare(
          `UPDATE sponsorship_spend_cap_reservations
              SET settled_minor = ?,
                  released_minor = ?,
                  status = 'SETTLED',
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND status = 'RESERVED'`,
        )
        .bind(
          normalized.settledSpendMinor,
          Math.max(reservation.requestedMinor - normalized.settledSpendMinor, 0),
          updatedAtMs,
          this.state.namespace,
          ctx.orgId,
          reservation.id,
        )
        .run();
      if (d1ChangedRows(result) !== 1) {
        throw new Error(`Failed to update spend-cap reservation ${reservation.id}`);
      }
    } catch (error: unknown) {
      if (isSpendCapExceededError(error)) {
        await throwSpendCapExceededFromReservation({
          database: this.state.database,
          namespace: this.state.namespace,
          reservation,
          requestedMinor: normalized.settledSpendMinor,
        });
      }
      if (isSpendCapInconsistentError(error)) throwSpendCapInconsistent();
      throw error;
    }
    const updated = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (!updated) {
      throw new ConsoleSponsorshipSpendCapError(
        'settlement_failed',
        500,
        'Failed to settle sponsorship spend-cap reservation',
      );
    }
    return buildOutcome({
      reservation: updated,
      usage: await loadUsageForReservation(this.state.database, {
        namespace: this.state.namespace,
        reservation: updated,
      }),
    });
  }

  async release(
    ctx: ConsoleSponsorshipSpendCapContext,
    request: Parameters<ConsoleSponsorshipSpendCapService['release']>[1],
  ): Promise<ConsoleSponsorshipSpendCapReservationOutcome | null> {
    const updatedAtMs = nowMs(this.state.now());
    const normalized = normalizeReleaseRequest(request);
    const reservation = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (!reservation) return null;
    if (reservation.status !== 'RESERVED') {
      return buildOutcome({
        reservation,
        usage: await loadUsageForReservation(this.state.database, {
          namespace: this.state.namespace,
          reservation,
        }),
      });
    }
    try {
      const result = await this.state.database
        .prepare(
          `UPDATE sponsorship_spend_cap_reservations
              SET released_minor = requested_minor,
                  status = 'RELEASED',
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?
              AND status = 'RESERVED'`,
        )
        .bind(updatedAtMs, this.state.namespace, ctx.orgId, reservation.id)
        .run();
      if (d1ChangedRows(result) !== 1) {
        throw new Error(`Failed to update spend-cap reservation ${reservation.id}`);
      }
    } catch (error: unknown) {
      if (isSpendCapInconsistentError(error)) throwSpendCapInconsistent();
      throw error;
    }
    const updated = await loadReservationBySourceEventId(this.state.database, {
      namespace: this.state.namespace,
      orgId: ctx.orgId,
      sourceEventId: normalized.sourceEventId,
    });
    if (!updated) {
      throw new ConsoleSponsorshipSpendCapError(
        'release_failed',
        500,
        'Failed to release sponsorship spend-cap reservation',
      );
    }
    return buildOutcome({
      reservation: updated,
      usage: await loadUsageForReservation(this.state.database, {
        namespace: this.state.namespace,
        reservation: updated,
      }),
    });
  }
}
