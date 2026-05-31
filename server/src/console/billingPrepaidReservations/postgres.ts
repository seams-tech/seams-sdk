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
  ReleaseConsoleBillingPrepaidReservationRequest,
  SettleConsoleBillingPrepaidReservationRequest,
} from './types';
import type {
  ConsoleBillingPrepaidReservationContext,
  ConsoleBillingPrepaidReservationService,
} from './service';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_BILLING_PREPAID_RESERVATION_MIGRATION_LOCK_ID = 9452360123583;
const DEFAULT_RESERVATION_TTL_MS = 5 * 60_000;
export const CONSOLE_BILLING_PREPAID_RESERVATION_POSTGRES_RUNTIME = Symbol(
  'consoleBillingPrepaidReservationPostgresRuntime',
);

export interface ConsoleBillingPrepaidReservationPostgresRuntime {
  pool: PgPool;
  namespace: string;
  now: () => Date;
  defaultReservationTtlMs: number;
}

export type ConsoleBillingPrepaidReservationPostgresService =
  ConsoleBillingPrepaidReservationService & {
    [CONSOLE_BILLING_PREPAID_RESERVATION_POSTGRES_RUNTIME]: ConsoleBillingPrepaidReservationPostgresRuntime;
  };

export function getConsoleBillingPrepaidReservationPostgresRuntime(
  service: ConsoleBillingPrepaidReservationService | null | undefined,
): ConsoleBillingPrepaidReservationPostgresRuntime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleBillingPrepaidReservationPostgresService>)[
      CONSOLE_BILLING_PREPAID_RESERVATION_POSTGRES_RUNTIME
    ] || null
  );
}

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = secureRandomBase36(8, 'console IDs');
  return `${prefix}_${ts}_${rand}`;
}

function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function parseStatus(value: unknown): ConsoleBillingPrepaidReservation['status'] {
  const normalized = String(value || '').trim();
  if (
    normalized === 'RESERVED' ||
    normalized === 'SETTLED' ||
    normalized === 'RELEASED' ||
    normalized === 'EXPIRED'
  ) {
    return normalized;
  }
  throw new Error(`Invalid prepaid reservation status row: ${normalized || 'empty'}`);
}

function parseReservation(row: PgRow): ConsoleBillingPrepaidReservation {
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
    expiresAt: toIso(toNumber(row.expires_at_ms)) || new Date(0).toISOString(),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseSummary(row: PgRow): ConsoleBillingPrepaidReservationSummary {
  return {
    orgId: String(row.org_id || ''),
    reservedMinor: Math.max(0, toNumber(row.reserved_minor)),
    activeReservationCount: Math.max(0, toNumber(row.active_reservation_count)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const result = await q.query(text, values);
  return (result.rows[0] as PgRow) || null;
}

async function ensureSummaryRowLocked(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    createdAtMs: number;
  },
): Promise<ConsoleBillingPrepaidReservationSummary> {
  let row = await queryOne(
    q,
    `SELECT *
       FROM console_billing_prepaid_reservation_summaries
      WHERE namespace = $1 AND org_id = $2
      FOR UPDATE`,
    [input.namespace, input.orgId],
  );
  if (!row) {
    await q.query(
      `INSERT INTO console_billing_prepaid_reservation_summaries
        (namespace, org_id, reserved_minor, active_reservation_count, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, 0, 0, $3, $3)
       ON CONFLICT (namespace, org_id) DO NOTHING`,
      [input.namespace, input.orgId, input.createdAtMs],
    );
    row = await queryOne(
      q,
      `SELECT *
         FROM console_billing_prepaid_reservation_summaries
        WHERE namespace = $1 AND org_id = $2
        FOR UPDATE`,
      [input.namespace, input.orgId],
    );
  }
  if (!row) {
    return buildEmptySummary(input.orgId, toIso(input.createdAtMs) || new Date(0).toISOString());
  }
  return parseSummary(row);
}

async function loadReservationBySourceEventId(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    sourceEventId: string;
    forUpdate?: boolean;
  },
): Promise<ConsoleBillingPrepaidReservation | null> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_billing_prepaid_reservations
      WHERE namespace = $1
        AND org_id = $2
        AND source_event_id = $3
      LIMIT 1
      ${input.forUpdate ? 'FOR UPDATE' : ''}`,
    [input.namespace, input.orgId, input.sourceEventId],
  );
  return row ? parseReservation(row) : null;
}

async function persistSummary(
  q: Queryable,
  input: {
    namespace: string;
    summary: ConsoleBillingPrepaidReservationSummary;
    updatedAtMs: number;
  },
): Promise<ConsoleBillingPrepaidReservationSummary> {
  const row = await queryOne(
    q,
    `UPDATE console_billing_prepaid_reservation_summaries
        SET reserved_minor = $3,
            active_reservation_count = $4,
            updated_at_ms = $5
      WHERE namespace = $1 AND org_id = $2
      RETURNING *`,
    [
      input.namespace,
      input.summary.orgId,
      input.summary.reservedMinor,
      input.summary.activeReservationCount,
      input.updatedAtMs,
    ],
  );
  if (!row) return input.summary;
  return parseSummary(row);
}

async function expireStaleReservationsForOrgTx(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    atMs: number;
    limit: number;
  },
): Promise<string[]> {
  if (input.limit <= 0) return [];
  const staleRows = await q.query(
    `SELECT *
       FROM console_billing_prepaid_reservations
      WHERE namespace = $1
        AND org_id = $2
        AND status = 'RESERVED'
        AND expires_at_ms <= $3
      ORDER BY expires_at_ms ASC
      LIMIT $4
      FOR UPDATE`,
    [input.namespace, input.orgId, input.atMs, input.limit],
  );
  if (staleRows.rows.length === 0) return [];
  const summary = await ensureSummaryRowLocked(q, {
    namespace: input.namespace,
    orgId: input.orgId,
    createdAtMs: input.atMs,
  });
  const reservationIds: string[] = [];
  let reservedMinorDelta = 0;
  let activeCountDelta = 0;
  for (const rawRow of staleRows.rows as PgRow[]) {
    const reservation = parseReservation(rawRow);
    if (reservation.status !== 'RESERVED') continue;
    reservationIds.push(reservation.id);
    reservedMinorDelta += reservation.requestedMinor;
    activeCountDelta += 1;
  }
  if (reservationIds.length > 0) {
    await q.query(
      `UPDATE console_billing_prepaid_reservations
          SET status = 'EXPIRED',
              released_minor = requested_minor,
              updated_at_ms = $4
        WHERE namespace = $1
          AND org_id = $2
          AND id = ANY($3::text[])`,
      [input.namespace, input.orgId, reservationIds, input.atMs],
    );
    summary.reservedMinor = Math.max(0, summary.reservedMinor - reservedMinorDelta);
    summary.activeReservationCount = Math.max(0, summary.activeReservationCount - activeCountDelta);
    summary.updatedAt = toIso(input.atMs) || new Date(0).toISOString();
    await persistSummary(q, {
      namespace: input.namespace,
      summary,
      updatedAtMs: input.atMs,
    });
  }
  return reservationIds;
}

export interface PostgresConsoleBillingPrepaidReservationSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleBillingPrepaidReservationPostgresSchema(
  options: PostgresConsoleBillingPrepaidReservationSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [
    CONSOLE_BILLING_PREPAID_RESERVATION_MIGRATION_LOCK_ID,
  ]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_prepaid_reservation_summaries (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        reserved_minor BIGINT NOT NULL DEFAULT 0,
        active_reservation_count BIGINT NOT NULL DEFAULT 0,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id),
        CHECK (reserved_minor >= 0),
        CHECK (active_reservation_count >= 0)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_billing_prepaid_reservations (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        policy_id TEXT,
        source_event_id TEXT NOT NULL,
        requested_minor BIGINT NOT NULL,
        settled_minor BIGINT NOT NULL DEFAULT 0,
        released_minor BIGINT NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        tx_or_execution_ref TEXT,
        pricing_version TEXT,
        expires_at_ms BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, org_id, id),
        CHECK (requested_minor >= 0),
        CHECK (settled_minor >= 0),
        CHECK (released_minor >= 0),
        CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED', 'EXPIRED'))
      )
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_billing_prepaid_reservations_source_event_idx
      ON console_billing_prepaid_reservations (namespace, org_id, source_event_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_billing_prepaid_reservations_org_status_idx
      ON console_billing_prepaid_reservations (namespace, org_id, status, expires_at_ms ASC)
    `);
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_prepaid_reservation_summaries',
      policyName: 'console_billing_prepaid_reservation_summaries_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_billing_prepaid_reservations',
      policyName: 'console_billing_prepaid_reservations_tenant_rls',
    });
  } finally {
    await pool.query('SELECT pg_advisory_unlock($1)', [
      CONSOLE_BILLING_PREPAID_RESERVATION_MIGRATION_LOCK_ID,
    ]);
  }
}

export interface PostgresConsoleBillingPrepaidReservationServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  defaultReservationTtlMs?: number;
}

export async function createPostgresConsoleBillingPrepaidReservationService(
  options: PostgresConsoleBillingPrepaidReservationServiceOptions,
): Promise<ConsoleBillingPrepaidReservationService> {
  if (options.ensureSchema) {
    await ensureConsoleBillingPrepaidReservationPostgresSchema({
      postgresUrl: options.postgresUrl,
      logger: options.logger,
    });
  }
  const pool = await getPostgresPool(options.postgresUrl);
  const namespace = ensureNamespace(options.namespace);
  const now = options.now || (() => new Date());
  const defaultReservationTtlMs = Math.max(
    1,
    Math.trunc(options.defaultReservationTtlMs || DEFAULT_RESERVATION_TTL_MS),
  );

  async function withOrgTx<T>(
    ctx: ConsoleBillingPrepaidReservationContext,
    handler: (q: Queryable, currentNow: Date) => Promise<T>,
  ): Promise<T> {
    return withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (q) =>
      handler(q, now()),
    );
  }

  const runtime: ConsoleBillingPrepaidReservationPostgresRuntime = {
    pool,
    namespace,
    now,
    defaultReservationTtlMs,
  };

  const service: ConsoleBillingPrepaidReservationPostgresService = {
    async getReservationBySourceEventId(ctx, sourceEventId) {
      return withOrgTx(ctx, async (q) =>
        loadReservationBySourceEventId(q, {
          namespace,
          orgId: ctx.orgId,
          sourceEventId: String(sourceEventId || '').trim(),
        }),
      );
    },

    async getSummary(ctx) {
      return withOrgTx(ctx, async (q, currentNow) =>
        ensureSummaryRowLocked(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: nowMs(currentNow),
        }),
      );
    },

    async reserve(ctx, request) {
      return withOrgTx(ctx, async (q, currentNow) => {
        const currentNowMs = nowMs(currentNow);
        const normalized = normalizeReserveRequest(request, currentNow, defaultReservationTtlMs);
        await expireStaleReservationsForOrgTx(q, {
          namespace,
          orgId: ctx.orgId,
          atMs: currentNowMs,
          limit: 1000,
        });
        const existing = await loadReservationBySourceEventId(q, {
          namespace,
          orgId: ctx.orgId,
          sourceEventId: normalized.sourceEventId,
          forUpdate: true,
        });
        const summary = await ensureSummaryRowLocked(q, {
          namespace,
          orgId: ctx.orgId,
          createdAtMs: currentNowMs,
        });
        if (existing) {
          return {
            reservation: cloneReservation(existing),
            summary: cloneSummary(summary),
            postedBalanceMinor: normalized.postedBalanceMinor,
            availableBalanceMinor: normalized.postedBalanceMinor - summary.reservedMinor,
          } satisfies ConsoleBillingPrepaidReservationReserveOutcome;
        }
        if (
          summary.reservedMinor + normalized.estimatedSpendMinor >
          normalized.postedBalanceMinor
        ) {
          throw createInsufficientAvailableBalanceError({
            postedBalanceMinor: normalized.postedBalanceMinor,
            reservedMinor: summary.reservedMinor,
            requestedMinor: normalized.estimatedSpendMinor,
          });
        }
        const row = await queryOne(
          q,
          `INSERT INTO console_billing_prepaid_reservations
            (namespace, org_id, id, environment_id, policy_id, source_event_id, requested_minor, settled_minor, released_minor, status, tx_or_execution_ref, pricing_version, expires_at_ms, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $6, $7, 0, 0, 'RESERVED', NULL, NULL, $8, $9, $9)
           RETURNING *`,
          [
            namespace,
            ctx.orgId,
            makeId('bpr', currentNow),
            normalized.environmentId,
            normalized.policyId,
            normalized.sourceEventId,
            normalized.estimatedSpendMinor,
            normalized.expiresAtMs,
            currentNowMs,
          ],
        );
        if (!row) {
          throw new ConsoleBillingPrepaidReservationError(
            'reservation_failed',
            500,
            'Failed to create prepaid reservation',
          );
        }
        summary.reservedMinor += normalized.estimatedSpendMinor;
        summary.activeReservationCount += 1;
        summary.updatedAt = toIso(currentNowMs) || new Date(0).toISOString();
        const persistedSummary = await persistSummary(q, {
          namespace,
          summary,
          updatedAtMs: currentNowMs,
        });
        return {
          reservation: parseReservation(row),
          summary: persistedSummary,
          postedBalanceMinor: normalized.postedBalanceMinor,
          availableBalanceMinor: normalized.postedBalanceMinor - persistedSummary.reservedMinor,
        };
      });
    },

    async settle(ctx, request) {
      return withOrgTx(ctx, async (q, currentNow) =>
        settleConsoleBillingPrepaidReservationTx(q, {
          namespace,
          ctx,
          now: currentNow,
          request,
        }),
      );
    },

    async release(ctx, request) {
      return withOrgTx(ctx, async (q, currentNow) =>
        releaseConsoleBillingPrepaidReservationTx(q, {
          namespace,
          ctx,
          now: currentNow,
          request,
        }),
      );
    },

    async expireStaleReservations(request?: ExpireConsoleBillingPrepaidReservationsRequest) {
      const normalized = normalizeExpireRequest(request, now());
      const expiredReservationIds: string[] = [];
      const staleRows = await pool.query(
        `SELECT DISTINCT org_id
           FROM console_billing_prepaid_reservations
          WHERE namespace = $1
            AND status = 'RESERVED'
            AND expires_at_ms <= $2
          ORDER BY org_id ASC`,
        [namespace, normalized.atMs],
      );
      for (const row of staleRows.rows as PgRow[]) {
        if (expiredReservationIds.length >= normalized.limit) break;
        const orgId = String(row.org_id || '').trim();
        if (!orgId) continue;
        const ids = await withConsoleTenantContextTx(pool, { namespace, orgId }, async (q) =>
          expireStaleReservationsForOrgTx(q, {
            namespace,
            orgId,
            atMs: normalized.atMs,
            limit: normalized.limit - expiredReservationIds.length,
          }),
        );
        expiredReservationIds.push(...ids);
      }
      return {
        expiredCount: expiredReservationIds.length,
        reservationIds: expiredReservationIds,
      } satisfies ExpireConsoleBillingPrepaidReservationsResult;
    },
    [CONSOLE_BILLING_PREPAID_RESERVATION_POSTGRES_RUNTIME]: runtime,
  };

  return service;
}

export async function settleConsoleBillingPrepaidReservationTx(
  q: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleBillingPrepaidReservationContext;
    now: Date;
    request: SettleConsoleBillingPrepaidReservationRequest;
  },
): Promise<ConsoleBillingPrepaidReservationMutationOutcome | null> {
  const normalized = normalizeSettleRequest(input.request);
  const currentNowMs = nowMs(input.now);
  const reservation = await loadReservationBySourceEventId(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    sourceEventId: normalized.sourceEventId,
    forUpdate: true,
  });
  if (!reservation) return null;
  const summary = await ensureSummaryRowLocked(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: currentNowMs,
  });
  if (reservation.status === 'SETTLED') {
    if (reservation.settledMinor !== normalized.settledSpendMinor) {
      throw new ConsoleBillingPrepaidReservationError(
        'invalid_state',
        409,
        'Prepaid reservation is already settled with a different amount',
      );
    }
    return {
      reservation: cloneReservation(reservation),
      summary: cloneSummary(summary),
    };
  }
  if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_state',
      409,
      'Released or expired prepaid reservations cannot be settled',
    );
  }
  const row = await queryOne(
    q,
    `UPDATE console_billing_prepaid_reservations
        SET status = 'SETTLED',
            settled_minor = $4,
            tx_or_execution_ref = $5,
            pricing_version = $6,
            released_minor = $7,
            updated_at_ms = $8
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      RETURNING *`,
    [
      input.namespace,
      input.ctx.orgId,
      reservation.id,
      normalized.settledSpendMinor,
      normalized.txOrExecutionRef,
      normalized.pricingVersion,
      Math.max(reservation.requestedMinor - normalized.settledSpendMinor, 0),
      currentNowMs,
    ],
  );
  if (!row) {
    throw new ConsoleBillingPrepaidReservationError(
      'settlement_failed',
      500,
      'Failed to settle prepaid reservation',
    );
  }
  summary.reservedMinor = Math.max(0, summary.reservedMinor - reservation.requestedMinor);
  summary.activeReservationCount = Math.max(0, summary.activeReservationCount - 1);
  summary.updatedAt = toIso(currentNowMs) || new Date(0).toISOString();
  const persistedSummary = await persistSummary(q, {
    namespace: input.namespace,
    summary,
    updatedAtMs: currentNowMs,
  });
  return {
    reservation: parseReservation(row),
    summary: persistedSummary,
  };
}

export async function releaseConsoleBillingPrepaidReservationTx(
  q: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleBillingPrepaidReservationContext;
    now: Date;
    request: ReleaseConsoleBillingPrepaidReservationRequest;
  },
): Promise<ConsoleBillingPrepaidReservationMutationOutcome | null> {
  const normalized = normalizeReleaseRequest(input.request);
  const currentNowMs = nowMs(input.now);
  const reservation = await loadReservationBySourceEventId(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    sourceEventId: normalized.sourceEventId,
    forUpdate: true,
  });
  if (!reservation) return null;
  const summary = await ensureSummaryRowLocked(q, {
    namespace: input.namespace,
    orgId: input.ctx.orgId,
    createdAtMs: currentNowMs,
  });
  if (reservation.status === 'RELEASED' || reservation.status === 'EXPIRED') {
    return {
      reservation: cloneReservation(reservation),
      summary: cloneSummary(summary),
    };
  }
  if (reservation.status === 'SETTLED') {
    throw new ConsoleBillingPrepaidReservationError(
      'invalid_state',
      409,
      'Settled prepaid reservations cannot be released',
    );
  }
  const row = await queryOne(
    q,
    `UPDATE console_billing_prepaid_reservations
        SET status = 'RELEASED',
            released_minor = requested_minor,
            updated_at_ms = $4
      WHERE namespace = $1 AND org_id = $2 AND id = $3
      RETURNING *`,
    [input.namespace, input.ctx.orgId, reservation.id, currentNowMs],
  );
  if (!row) {
    throw new ConsoleBillingPrepaidReservationError(
      'release_failed',
      500,
      'Failed to release prepaid reservation',
    );
  }
  summary.reservedMinor = Math.max(0, summary.reservedMinor - reservation.requestedMinor);
  summary.activeReservationCount = Math.max(0, summary.activeReservationCount - 1);
  summary.updatedAt = toIso(currentNowMs) || new Date(0).toISOString();
  const persistedSummary = await persistSummary(q, {
    namespace: input.namespace,
    summary,
    updatedAtMs: currentNowMs,
  });
  return {
    reservation: parseReservation(row),
    summary: persistedSummary,
  };
}
