import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import { formatD1ExecStatement } from '../../storage/d1Sql';
import type { D1DatabaseLike, D1ResultLike } from '../../storage/tenantRoute';
import { ConsoleBillingPrepaidReservationError } from './errors';
import {
  buildEmptySummary,
  cloneReservation,
  cloneSummary,
  createInsufficientAvailableBalanceError,
  normalizeExpireRequest,
  normalizeReleaseRequest,
  normalizeReserveRequest,
  normalizeSettleRequest,
} from './shared';
import type {
  ConsoleBillingPrepaidReservation,
  ConsoleBillingPrepaidReservationMutationOutcome,
  ConsoleBillingPrepaidReservationReserveOutcome,
  ConsoleBillingPrepaidReservationSummary,
  ExpireConsoleBillingPrepaidReservationsRequest,
  ExpireConsoleBillingPrepaidReservationsResult,
} from './types';
import type {
  ConsoleBillingPrepaidReservationContext,
  ConsoleBillingPrepaidReservationService,
} from './service';

type D1Row = Record<string, unknown>;

const DEFAULT_RESERVATION_TTL_MS = 5 * 60_000;
const D1_EXPIRE_BATCH_SIZE = 80;

export const CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME = Symbol(
  'consoleBillingPrepaidReservationD1Runtime',
);

export interface ConsoleBillingPrepaidReservationD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
  defaultReservationTtlMs: number;
}

export type ConsoleBillingPrepaidReservationD1Service =
  ConsoleBillingPrepaidReservationService & {
    [CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME]: ConsoleBillingPrepaidReservationD1Runtime;
  };

export interface D1ConsoleBillingPrepaidReservationServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
  defaultReservationTtlMs?: number;
}

export interface D1ConsoleBillingPrepaidReservationSchemaOptions {
  database: D1DatabaseLike;
}

export const CONSOLE_BILLING_PREPAID_RESERVATION_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS console_billing_prepaid_reservation_summaries (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      reserved_minor INTEGER NOT NULL DEFAULT 0,
      active_reservation_count INTEGER NOT NULL DEFAULT 0,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id),
      CHECK (reserved_minor >= 0),
      CHECK (active_reservation_count >= 0)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS console_billing_prepaid_reservations (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      policy_id TEXT,
      source_event_id TEXT NOT NULL,
      requested_minor INTEGER NOT NULL,
      posted_balance_minor INTEGER NOT NULL,
      settled_minor INTEGER NOT NULL DEFAULT 0,
      released_minor INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      tx_or_execution_ref TEXT,
      pricing_version TEXT,
      expires_at_ms INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (requested_minor >= 0),
      CHECK (posted_balance_minor >= 0),
      CHECK (settled_minor >= 0),
      CHECK (released_minor >= 0),
      CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED'))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_prepaid_reservations_source_event_idx
      ON console_billing_prepaid_reservations (namespace, org_id, source_event_id)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS console_billing_prepaid_reservations_namespace_id_idx
      ON console_billing_prepaid_reservations (namespace, id)
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_prepaid_reservations_org_status_idx
      ON console_billing_prepaid_reservations (namespace, org_id, status, expires_at_ms ASC)
  `,
  `
    CREATE INDEX IF NOT EXISTS console_billing_prepaid_reservations_status_idx
      ON console_billing_prepaid_reservations (namespace, status, expires_at_ms ASC)
  `,
  `
    CREATE TRIGGER IF NOT EXISTS console_billing_prepaid_reservations_reserve_insert
    BEFORE INSERT ON console_billing_prepaid_reservations
    WHEN NEW.status = 'RESERVED'
    BEGIN
      INSERT INTO console_billing_prepaid_reservation_summaries
        (namespace, org_id, reserved_minor, active_reservation_count, created_at_ms, updated_at_ms)
      VALUES
        (NEW.namespace, NEW.org_id, 0, 0, NEW.created_at_ms, NEW.created_at_ms)
      ON CONFLICT(namespace, org_id) DO NOTHING;

      SELECT CASE
        WHEN (
          SELECT reserved_minor
          FROM console_billing_prepaid_reservation_summaries
          WHERE namespace = NEW.namespace AND org_id = NEW.org_id
        ) + NEW.requested_minor > NEW.posted_balance_minor
        THEN RAISE(ABORT, 'prepaid_balance_insufficient')
      END;

      UPDATE console_billing_prepaid_reservation_summaries
         SET reserved_minor = reserved_minor + NEW.requested_minor,
             active_reservation_count = active_reservation_count + 1,
             updated_at_ms = NEW.created_at_ms
       WHERE namespace = NEW.namespace AND org_id = NEW.org_id;
    END
  `,
  `
    CREATE TRIGGER IF NOT EXISTS console_billing_prepaid_reservations_reserved_exit_update
    AFTER UPDATE OF status ON console_billing_prepaid_reservations
    WHEN OLD.status = 'RESERVED' AND NEW.status IN ('SETTLED', 'RELEASED', 'EXPIRED')
    BEGIN
      UPDATE console_billing_prepaid_reservation_summaries
         SET reserved_minor = MAX(0, reserved_minor - OLD.requested_minor),
             active_reservation_count = MAX(0, active_reservation_count - 1),
             updated_at_ms = NEW.updated_at_ms
       WHERE namespace = NEW.namespace AND org_id = NEW.org_id;
    END
  `,
] as const);

export async function ensureConsoleBillingPrepaidReservationD1Schema(
  options: D1ConsoleBillingPrepaidReservationSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_BILLING_PREPAID_RESERVATION_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleBillingPrepaidReservationD1Runtime(
  service: ConsoleBillingPrepaidReservationService | null | undefined,
): ConsoleBillingPrepaidReservationD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleBillingPrepaidReservationD1Service>)[
      CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME
    ] || null
  );
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  if (!normalized) return 'default';
  return normalized;
}

function defaultNow(): Date {
  return new Date();
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}

function toNumber(value: unknown): number {
  const parsed = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
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

function placeholder(): string {
  return '?';
}

function rowId(row: D1Row): string {
  return String(row.id || '').trim();
}

function runChanges(result: D1ResultLike): number {
  const changes = Number(result.meta?.changes);
  return Number.isFinite(changes) ? Math.max(0, Math.trunc(changes)) : 0;
}

function parseStatus(value: unknown): ConsoleBillingPrepaidReservation['status'] {
  const normalized = String(value || '').trim();
  switch (normalized) {
    case 'RESERVED':
    case 'SETTLED':
    case 'RELEASED':
    case 'EXPIRED':
      return normalized;
    default:
      throw new Error(`Invalid prepaid reservation status row: ${normalized || 'empty'}`);
  }
}

function parseReservation(row: D1Row): ConsoleBillingPrepaidReservation {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    environmentId: String(row.environment_id || ''),
    policyId: normalizeString(row.policy_id),
    sourceEventId: String(row.source_event_id || ''),
    requestedMinor: Math.max(0, toNumber(row.requested_minor)),
    settledMinor: Math.max(0, toNumber(row.settled_minor)),
    releasedMinor: Math.max(0, toNumber(row.released_minor)),
    status: parseStatus(row.status),
    txOrExecutionRef: normalizeString(row.tx_or_execution_ref),
    pricingVersion: normalizeString(row.pricing_version),
    expiresAt: toIso(toNumber(row.expires_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function parseSummary(row: D1Row): ConsoleBillingPrepaidReservationSummary {
  return {
    orgId: String(row.org_id || ''),
    reservedMinor: Math.max(0, toNumber(row.reserved_minor)),
    activeReservationCount: Math.max(0, toNumber(row.active_reservation_count)),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
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

async function ensureSummaryRow(
  database: D1DatabaseLike,
  input: {
    namespace: string;
    orgId: string;
    createdAtMs: number;
  },
): Promise<ConsoleBillingPrepaidReservationSummary> {
  await database
    .prepare(
      `INSERT INTO console_billing_prepaid_reservation_summaries
        (namespace, org_id, reserved_minor, active_reservation_count, created_at_ms, updated_at_ms)
       VALUES (?, ?, 0, 0, ?, ?)
       ON CONFLICT(namespace, org_id) DO NOTHING`,
    )
    .bind(input.namespace, input.orgId, input.createdAtMs, input.createdAtMs)
    .run();
  const row = await queryOne(
    database,
    `SELECT *
       FROM console_billing_prepaid_reservation_summaries
      WHERE namespace = ? AND org_id = ?`,
    [input.namespace, input.orgId],
  );
  if (!row) return buildEmptySummary(input.orgId, toIso(input.createdAtMs));
  return parseSummary(row);
}

async function loadReservationBySourceEventId(
  database: D1DatabaseLike,
  input: {
    namespace: string;
    orgId: string;
    sourceEventId: string;
  },
): Promise<ConsoleBillingPrepaidReservation | null> {
  const row = await queryOne(
    database,
    `SELECT *
       FROM console_billing_prepaid_reservations
      WHERE namespace = ?
        AND org_id = ?
        AND source_event_id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.sourceEventId],
  );
  return row ? parseReservation(row) : null;
}

async function loadReservationById(
  database: D1DatabaseLike,
  input: {
    namespace: string;
    orgId: string;
    id: string;
  },
): Promise<ConsoleBillingPrepaidReservation | null> {
  const row = await queryOne(
    database,
    `SELECT *
       FROM console_billing_prepaid_reservations
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.namespace, input.orgId, input.id],
  );
  return row ? parseReservation(row) : null;
}

function buildReserveOutcome(input: {
  reservation: ConsoleBillingPrepaidReservation;
  summary: ConsoleBillingPrepaidReservationSummary;
  postedBalanceMinor: number;
}): ConsoleBillingPrepaidReservationReserveOutcome {
  return {
    reservation: cloneReservation(input.reservation),
    summary: cloneSummary(input.summary),
    postedBalanceMinor: input.postedBalanceMinor,
    availableBalanceMinor: input.postedBalanceMinor - input.summary.reservedMinor,
  };
}

function buildMutationOutcome(input: {
  reservation: ConsoleBillingPrepaidReservation;
  summary: ConsoleBillingPrepaidReservationSummary;
}): ConsoleBillingPrepaidReservationMutationOutcome {
  return {
    reservation: cloneReservation(input.reservation),
    summary: cloneSummary(input.summary),
  };
}

function isD1InsufficientBalanceError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  return message.includes('prepaid_balance_insufficient');
}

async function expireReservedForOrg(input: {
  database: D1DatabaseLike;
  namespace: string;
  orgId: string;
  atMs: number;
  limit: number;
}): Promise<readonly string[]> {
  if (input.limit <= 0) return [];
  const rows = await queryAll(
    input.database,
    `SELECT id
       FROM console_billing_prepaid_reservations
      WHERE namespace = ?
        AND org_id = ?
        AND status = 'RESERVED'
        AND expires_at_ms <= ?
      ORDER BY expires_at_ms ASC
      LIMIT ?`,
    [input.namespace, input.orgId, input.atMs, Math.min(input.limit, D1_EXPIRE_BATCH_SIZE)],
  );
  const ids = rows.map(rowId).filter(Boolean);
  if (ids.length === 0) return [];
  const placeholders = ids.map(placeholder).join(', ');
  await input.database
    .prepare(
      `UPDATE console_billing_prepaid_reservations
          SET status = 'EXPIRED',
              released_minor = requested_minor,
              updated_at_ms = ?
        WHERE namespace = ?
          AND id IN (${placeholders})
          AND status = 'RESERVED'`,
    )
    .bind(input.atMs, input.namespace, ...ids)
    .run();
  return ids;
}

async function expireReservedAcrossNamespace(input: {
  database: D1DatabaseLike;
  namespace: string;
  atMs: number;
  limit: number;
}): Promise<readonly string[]> {
  const expiredIds: string[] = [];
  while (expiredIds.length < input.limit) {
    const rows = await queryAll(
      input.database,
      `SELECT org_id
         FROM console_billing_prepaid_reservations
        WHERE namespace = ?
          AND status = 'RESERVED'
          AND expires_at_ms <= ?
        GROUP BY org_id
        ORDER BY org_id ASC
        LIMIT 1`,
      [input.namespace, input.atMs],
    );
    const orgId = String(rows[0]?.org_id || '').trim();
    if (!orgId) break;
    const ids = await expireReservedForOrg({
      database: input.database,
      namespace: input.namespace,
      orgId,
      atMs: input.atMs,
      limit: input.limit - expiredIds.length,
    });
    if (ids.length === 0) break;
    expiredIds.push(...ids);
  }
  return expiredIds;
}

async function reserveWithD1(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleBillingPrepaidReservationContext;
  reservationId: string;
  environmentId: string;
  policyId: string | null;
  sourceEventId: string;
  requestedMinor: number;
  postedBalanceMinor: number;
  expiresAtMs: number;
  createdAtMs: number;
}): Promise<void> {
  await input.database
    .prepare(
      `INSERT INTO console_billing_prepaid_reservations
        (namespace, org_id, id, environment_id, policy_id, source_event_id, requested_minor, posted_balance_minor, settled_minor, released_minor, status, tx_or_execution_ref, pricing_version, expires_at_ms, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 'RESERVED', NULL, NULL, ?, ?, ?)`,
    )
    .bind(
      input.namespace,
      input.ctx.orgId,
      input.reservationId,
      input.environmentId,
      input.policyId,
      input.sourceEventId,
      input.requestedMinor,
      input.postedBalanceMinor,
      input.expiresAtMs,
      input.createdAtMs,
      input.createdAtMs,
    )
    .run();
}

async function settleReservedReservation(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleBillingPrepaidReservationContext;
  reservation: ConsoleBillingPrepaidReservation;
  settledSpendMinor: number;
  txOrExecutionRef: string | null;
  pricingVersion: string | null;
  updatedAtMs: number;
}): Promise<ConsoleBillingPrepaidReservation | null> {
  const releasedMinor = Math.max(input.reservation.requestedMinor - input.settledSpendMinor, 0);
  const result = await input.database
    .prepare(
      `UPDATE console_billing_prepaid_reservations
          SET status = 'SETTLED',
              settled_minor = ?,
              tx_or_execution_ref = ?,
              pricing_version = ?,
              released_minor = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'RESERVED'`,
    )
    .bind(
      input.settledSpendMinor,
      input.txOrExecutionRef,
      input.pricingVersion,
      releasedMinor,
      input.updatedAtMs,
      input.namespace,
      input.ctx.orgId,
      input.reservation.id,
    )
    .run();
  if (runChanges(result) !== 1) return null;
  return loadReservationById(input.database, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    id: input.reservation.id,
  });
}

async function releaseReservedReservation(input: {
  database: D1DatabaseLike;
  namespace: string;
  ctx: ConsoleBillingPrepaidReservationContext;
  reservation: ConsoleBillingPrepaidReservation;
  updatedAtMs: number;
}): Promise<ConsoleBillingPrepaidReservation | null> {
  const result = await input.database
    .prepare(
      `UPDATE console_billing_prepaid_reservations
          SET status = 'RELEASED',
              released_minor = requested_minor,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?
          AND status = 'RESERVED'`,
    )
    .bind(input.updatedAtMs, input.namespace, input.ctx.orgId, input.reservation.id)
    .run();
  if (runChanges(result) !== 1) return null;
  return loadReservationById(input.database, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    id: input.reservation.id,
  });
}

export async function createD1ConsoleBillingPrepaidReservationService(
  options: D1ConsoleBillingPrepaidReservationServiceOptions,
): Promise<ConsoleBillingPrepaidReservationService> {
  if (options.ensureSchema) {
    await ensureConsoleBillingPrepaidReservationD1Schema({ database: options.database });
  }
  const database = options.database;
  const namespace = ensureNamespace(options.namespace);
  const now = options.now || defaultNow;
  const defaultReservationTtlMs = Math.max(
    1,
    Math.trunc(options.defaultReservationTtlMs || DEFAULT_RESERVATION_TTL_MS),
  );
  const runtime: ConsoleBillingPrepaidReservationD1Runtime = {
    database,
    namespace,
    now,
    defaultReservationTtlMs,
  };

  const service: ConsoleBillingPrepaidReservationD1Service = {
    async getReservationBySourceEventId(ctx, sourceEventId) {
      return loadReservationBySourceEventId(database, {
        namespace,
        orgId: ctx.orgId,
        sourceEventId: String(sourceEventId || '').trim(),
      });
    },

    async getSummary(ctx) {
      return ensureSummaryRow(database, {
        namespace,
        orgId: ctx.orgId,
        createdAtMs: nowMs(now()),
      });
    },

    async reserve(ctx, request) {
      const currentNow = now();
      const currentNowMs = nowMs(currentNow);
      const normalized = normalizeReserveRequest(request, currentNow, defaultReservationTtlMs);
      await expireReservedForOrg({
        database,
        namespace,
        orgId: ctx.orgId,
        atMs: currentNowMs,
        limit: 1000,
      });
      const existing = await loadReservationBySourceEventId(database, {
        namespace,
        orgId: ctx.orgId,
        sourceEventId: normalized.sourceEventId,
      });
      if (existing) {
        const summary = await ensureSummaryRow(database, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: currentNowMs,
        });
        return buildReserveOutcome({
          reservation: existing,
          summary,
          postedBalanceMinor: normalized.postedBalanceMinor,
        });
      }
      try {
        await reserveWithD1({
          database,
          namespace,
          ctx,
          reservationId: makeId('bpr', currentNow),
          environmentId: normalized.environmentId,
          policyId: normalized.policyId,
          sourceEventId: normalized.sourceEventId,
          requestedMinor: normalized.estimatedSpendMinor,
          postedBalanceMinor: normalized.postedBalanceMinor,
          expiresAtMs: normalized.expiresAtMs,
          createdAtMs: currentNowMs,
        });
      } catch (error) {
        const existingAfterConflict = await loadReservationBySourceEventId(database, {
          namespace,
          orgId: ctx.orgId,
          sourceEventId: normalized.sourceEventId,
        });
        if (existingAfterConflict) {
          const summary = await ensureSummaryRow(database, {
            namespace,
            orgId: ctx.orgId,
            createdAtMs: currentNowMs,
          });
          return buildReserveOutcome({
            reservation: existingAfterConflict,
            summary,
            postedBalanceMinor: normalized.postedBalanceMinor,
          });
        }
        if (isD1InsufficientBalanceError(error)) {
          const summary = await ensureSummaryRow(database, {
            namespace,
            orgId: ctx.orgId,
            createdAtMs: currentNowMs,
          });
          throw createInsufficientAvailableBalanceError({
            postedBalanceMinor: normalized.postedBalanceMinor,
            reservedMinor: summary.reservedMinor,
            requestedMinor: normalized.estimatedSpendMinor,
          });
        }
        throw error;
      }
      const reservation = await loadReservationBySourceEventId(database, {
        namespace,
        orgId: ctx.orgId,
        sourceEventId: normalized.sourceEventId,
      });
      if (!reservation) {
        throw new ConsoleBillingPrepaidReservationError(
          'reservation_failed',
          500,
          'Failed to create prepaid reservation',
        );
      }
      const summary = await ensureSummaryRow(database, {
        namespace,
        orgId: ctx.orgId,
        createdAtMs: currentNowMs,
      });
      return buildReserveOutcome({
        reservation,
        summary,
        postedBalanceMinor: normalized.postedBalanceMinor,
      });
    },

    async settle(ctx, request) {
      const currentNowMs = nowMs(now());
      const normalized = normalizeSettleRequest(request);
      const reservation = await loadReservationBySourceEventId(database, {
        namespace,
        orgId: ctx.orgId,
        sourceEventId: normalized.sourceEventId,
      });
      if (!reservation) return null;
      if (reservation.status === 'SETTLED') {
        if (reservation.settledMinor !== normalized.settledSpendMinor) {
          throw new ConsoleBillingPrepaidReservationError(
            'invalid_state',
            409,
            'Prepaid reservation is already settled with a different amount',
          );
        }
        const summary = await ensureSummaryRow(database, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: currentNowMs,
        });
        return buildMutationOutcome({ reservation, summary });
      }
      if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
        throw new ConsoleBillingPrepaidReservationError(
          'invalid_state',
          409,
          'Released or expired prepaid reservations cannot be settled',
        );
      }
      const updated = await settleReservedReservation({
        database,
        namespace,
        ctx,
        reservation,
        settledSpendMinor: normalized.settledSpendMinor,
        txOrExecutionRef: normalized.txOrExecutionRef,
        pricingVersion: normalized.pricingVersion,
        updatedAtMs: currentNowMs,
      });
      if (!updated) {
        throw new ConsoleBillingPrepaidReservationError(
          'settlement_failed',
          500,
          'Failed to settle prepaid reservation',
        );
      }
      const summary = await ensureSummaryRow(database, {
        namespace,
        orgId: ctx.orgId,
        createdAtMs: currentNowMs,
      });
      return buildMutationOutcome({ reservation: updated, summary });
    },

    async release(ctx, request) {
      const currentNowMs = nowMs(now());
      const normalized = normalizeReleaseRequest(request);
      const reservation = await loadReservationBySourceEventId(database, {
        namespace,
        orgId: ctx.orgId,
        sourceEventId: normalized.sourceEventId,
      });
      if (!reservation) return null;
      if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
        const summary = await ensureSummaryRow(database, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: currentNowMs,
        });
        return buildMutationOutcome({ reservation, summary });
      }
      if (reservation.status === 'SETTLED') {
        throw new ConsoleBillingPrepaidReservationError(
          'invalid_state',
          409,
          'Settled prepaid reservations cannot be released',
        );
      }
      const updated = await releaseReservedReservation({
        database,
        namespace,
        ctx,
        reservation,
        updatedAtMs: currentNowMs,
      });
      if (!updated) {
        throw new ConsoleBillingPrepaidReservationError(
          'release_failed',
          500,
          'Failed to release prepaid reservation',
        );
      }
      const summary = await ensureSummaryRow(database, {
        namespace,
        orgId: ctx.orgId,
        createdAtMs: currentNowMs,
      });
      return buildMutationOutcome({ reservation: updated, summary });
    },

    async expireStaleReservations(request?: ExpireConsoleBillingPrepaidReservationsRequest) {
      const normalized = normalizeExpireRequest(request, now());
      const expiredReservationIds = await expireReservedAcrossNamespace({
        database,
        namespace,
        atMs: normalized.atMs,
        limit: normalized.limit,
      });
      return {
        expiredCount: expiredReservationIds.length,
        reservationIds: [...expiredReservationIds],
      } satisfies ExpireConsoleBillingPrepaidReservationsResult;
    },

    [CONSOLE_BILLING_PREPAID_RESERVATION_D1_RUNTIME]: runtime,
  };

  return service;
}
