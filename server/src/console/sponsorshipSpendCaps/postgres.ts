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
  ConsoleSponsorshipSpendCapReservation,
  ConsoleSponsorshipSpendCapWindowUsage,
} from './types';
import type { ConsoleSponsorshipSpendCapService } from './service';
import type {
  ConsoleSponsorshipSpendCapMode,
  ConsoleSponsorshipSpendCapPeriod,
  ConsoleSponsorshipSpendCapReservationStatus,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_SPEND_CAP_MIGRATION_LOCK_ID = 9452360123991;

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  const ts = now.getTime().toString(36);
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}_${ts}_${rand}`;
}

function normalizeString(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return normalized || null;
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

function parseReservation(row: PgRow): ConsoleSponsorshipSpendCapReservation {
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
    windowStartAt: toIso(toNumber(row.window_start_ms)) || new Date(0).toISOString(),
    windowEndAt: toIso(toNumber(row.window_end_ms)) || new Date(0).toISOString(),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

function parseUsage(row: PgRow): ConsoleSponsorshipSpendCapWindowUsage {
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
    windowStartAt: toIso(windowStartMs) || new Date(0).toISOString(),
    windowEndAt: toIso(windowEndMs) || new Date(0).toISOString(),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  });
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const result = await q.query(text, values);
  return (result.rows[0] as PgRow) || null;
}

async function loadUsageForReservation(
  q: Queryable,
  input: {
    namespace: string;
    orgId: string;
    reservation: ConsoleSponsorshipSpendCapReservation;
  },
): Promise<ConsoleSponsorshipSpendCapWindowUsage> {
  const row = await queryOne(
    q,
    `
      SELECT *
      FROM console_sponsorship_spend_cap_windows
      WHERE namespace = $1
        AND org_id = $2
        AND environment_id = $3
        AND policy_id = $4
        AND account_ref = $5
        AND chain_id = $6
        AND mode = $7
        AND period = $8
        AND window_start_ms = $9
      LIMIT 1
    `,
    [
      input.namespace,
      input.orgId,
      input.reservation.environmentId,
      input.reservation.policyId,
      input.reservation.mode === 'CHAIN_TOTAL' ? '' : input.reservation.accountRef || '',
      input.reservation.chainId,
      input.reservation.mode,
      input.reservation.period,
      Date.parse(input.reservation.windowStartAt),
    ],
  );
  if (!row) {
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
  return parseUsage(row);
}

export interface PostgresConsoleSponsorshipSpendCapSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleSponsorshipSpendCapPostgresSchema(
  options: PostgresConsoleSponsorshipSpendCapSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_SPEND_CAP_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_sponsorship_spend_cap_windows (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        account_ref TEXT NOT NULL DEFAULT '',
        chain_id INTEGER NOT NULL,
        mode TEXT NOT NULL,
        period TEXT NOT NULL,
        window_start_ms BIGINT NOT NULL,
        window_end_ms BIGINT NOT NULL,
        cap_minor BIGINT NOT NULL,
        reserved_minor BIGINT NOT NULL DEFAULT 0,
        settled_minor BIGINT NOT NULL DEFAULT 0,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
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
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_sponsorship_spend_cap_reservations (
        namespace TEXT NOT NULL,
        org_id TEXT NOT NULL,
        id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        account_ref TEXT NOT NULL DEFAULT '',
        chain_id INTEGER NOT NULL,
        mode TEXT NOT NULL,
        period TEXT NOT NULL,
        window_start_ms BIGINT NOT NULL,
        window_end_ms BIGINT NOT NULL,
        cap_minor BIGINT NOT NULL,
        requested_minor BIGINT NOT NULL,
        settled_minor BIGINT NOT NULL DEFAULT 0,
        released_minor BIGINT NOT NULL DEFAULT 0,
        status TEXT NOT NULL,
        source_event_id TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
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
    `);
    await pool.query(`
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
            FROM information_schema.columns
           WHERE table_name = 'console_sponsorship_spend_cap_windows'
             AND column_name = 'sponsorship_config_id'
        ) AND NOT EXISTS (
          SELECT 1
            FROM information_schema.columns
           WHERE table_name = 'console_sponsorship_spend_cap_windows'
             AND column_name = 'policy_id'
        ) THEN
          ALTER TABLE console_sponsorship_spend_cap_windows
          RENAME COLUMN sponsorship_config_id TO policy_id;
        END IF;
        IF EXISTS (
          SELECT 1
            FROM information_schema.columns
           WHERE table_name = 'console_sponsorship_spend_cap_reservations'
             AND column_name = 'sponsorship_config_id'
        ) AND NOT EXISTS (
          SELECT 1
            FROM information_schema.columns
           WHERE table_name = 'console_sponsorship_spend_cap_reservations'
             AND column_name = 'policy_id'
        ) THEN
          ALTER TABLE console_sponsorship_spend_cap_reservations
          RENAME COLUMN sponsorship_config_id TO policy_id;
        END IF;
      END $$;
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_sponsorship_spend_cap_source_event_idx
      ON console_sponsorship_spend_cap_reservations (namespace, org_id, source_event_id)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_sponsorship_spend_cap_windows_updated_idx
      ON console_sponsorship_spend_cap_windows (namespace, org_id, updated_at_ms DESC)
    `);
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_sponsorship_spend_cap_windows',
      policyName: 'console_sponsorship_spend_cap_windows_tenant_rls',
    });
    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_sponsorship_spend_cap_reservations',
      policyName: 'console_sponsorship_spend_cap_reservations_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_SPEND_CAP_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-sponsorship-spend-caps][postgres] Schema ready');
}

export interface PostgresConsoleSponsorshipSpendCapServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleSponsorshipSpendCapService(
  options: PostgresConsoleSponsorshipSpendCapServiceOptions,
): Promise<ConsoleSponsorshipSpendCapService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres sponsorship spend-cap service');
  }
  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const now = options.now || (() => new Date());
  if (options.ensureSchema !== false) {
    await ensureConsoleSponsorshipSpendCapPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);

  return {
    async getReservationBySourceEventId(ctx, sourceEventId) {
      const normalized = normalizeString(sourceEventId);
      if (!normalized) return null;
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx) => {
        const row = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsorship_spend_cap_reservations
            WHERE namespace = $1
              AND org_id = $2
              AND source_event_id = $3
            LIMIT 1
          `,
          [namespace, ctx.orgId, normalized],
        );
        return row ? parseReservation(row) : null;
      });
    },

    async getWindowUsage(ctx, request) {
      const normalized = normalizeWindowUsageRequest(request);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx) => {
        const row = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsorship_spend_cap_windows
            WHERE namespace = $1
              AND org_id = $2
              AND environment_id = $3
              AND policy_id = $4
              AND account_ref = $5
              AND chain_id = $6
              AND mode = $7
              AND period = $8
              AND window_start_ms = $9
            LIMIT 1
          `,
          [
            namespace,
            ctx.orgId,
            normalized.environmentId,
            normalized.policyId,
            normalized.storedAccountRef,
            normalized.chainId,
            normalized.mode,
            normalized.period,
            normalized.windowStartMs,
          ],
        );
        return row ? parseUsage(row) : null;
      });
    },

    async reserve(ctx, request) {
      const createdAt = now();
      const createdAtMs = nowMs(createdAt);
      const normalized = normalizeReserveRequest(request, createdAt);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx) => {
        const insertedReservation = await queryOne(
          tx,
          `
            INSERT INTO console_sponsorship_spend_cap_reservations (
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
            VALUES (
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 0, 0, 'RESERVED', $14, $15, $15
            )
            ON CONFLICT (namespace, org_id, source_event_id)
            DO NOTHING
            RETURNING *
          `,
          [
            namespace,
            ctx.orgId,
            makeId('sscr', createdAt),
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
          ],
        );
        if (!insertedReservation) {
          const existingRow = await queryOne(
            tx,
            `
              SELECT *
              FROM console_sponsorship_spend_cap_reservations
              WHERE namespace = $1
                AND org_id = $2
                AND source_event_id = $3
              LIMIT 1
            `,
            [namespace, ctx.orgId, normalized.sourceEventId],
          );
          if (!existingRow) {
            throw new Error('Spend-cap reservation conflict without an existing row');
          }
          const reservation = parseReservation(existingRow);
          const usage = await loadUsageForReservation(tx, { namespace, orgId: ctx.orgId, reservation });
          return { reservation, usage };
        }

        const usageRow = await queryOne(
          tx,
          `
            INSERT INTO console_sponsorship_spend_cap_windows (
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
              $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0, $13, $13
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
            )
            DO UPDATE SET
              window_end_ms = EXCLUDED.window_end_ms,
              cap_minor = EXCLUDED.cap_minor,
              reserved_minor = console_sponsorship_spend_cap_windows.reserved_minor + EXCLUDED.reserved_minor,
              updated_at_ms = EXCLUDED.updated_at_ms
            WHERE
              console_sponsorship_spend_cap_windows.reserved_minor
                + console_sponsorship_spend_cap_windows.settled_minor
                + EXCLUDED.reserved_minor
                <= EXCLUDED.cap_minor
            RETURNING *
          `,
          [
            namespace,
            ctx.orgId,
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
            createdAtMs,
          ],
        );
        if (!usageRow) {
          throw createSpendCapExceededError({
            capMinor: normalized.capMinor,
            reservedMinor: 0,
            settledMinor: 0,
            requestedMinor: normalized.estimatedSpendMinor,
          });
        }
        return {
          reservation: parseReservation(insertedReservation),
          usage: parseUsage(usageRow),
        };
      });
    },

    async settle(ctx, request) {
      const updatedAt = now();
      const updatedAtMs = nowMs(updatedAt);
      const normalized = normalizeSettleRequest(request);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx) => {
        const reservationRow = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsorship_spend_cap_reservations
            WHERE namespace = $1
              AND org_id = $2
              AND source_event_id = $3
            FOR UPDATE
          `,
          [namespace, ctx.orgId, normalized.sourceEventId],
        );
        if (!reservationRow) return null;
        const reservation = parseReservation(reservationRow);
        if (reservation.status === 'SETTLED') {
          if (reservation.settledMinor !== normalized.settledSpendMinor) {
            throw new ConsoleSponsorshipSpendCapError(
              'invalid_state',
              409,
              'Spend cap reservation is already settled with a different amount',
            );
          }
          const usage = await loadUsageForReservation(tx, { namespace, orgId: ctx.orgId, reservation });
          return { reservation, usage };
        }
        if (reservation.status === 'RELEASED') {
          throw new ConsoleSponsorshipSpendCapError(
            'invalid_state',
            409,
            'Released spend cap reservations cannot be settled',
          );
        }

        const usageRow = await queryOne(
          tx,
          `
            UPDATE console_sponsorship_spend_cap_windows
               SET reserved_minor = reserved_minor - $1,
                   settled_minor = settled_minor + $2,
                   updated_at_ms = $3
             WHERE namespace = $4
               AND org_id = $5
               AND environment_id = $6
               AND policy_id = $7
               AND account_ref = $8
               AND chain_id = $9
               AND mode = $10
               AND period = $11
               AND window_start_ms = $12
               AND reserved_minor >= $1
               AND reserved_minor + settled_minor - $1 + $2 <= cap_minor
            RETURNING *
          `,
          [
            reservation.requestedMinor,
            normalized.settledSpendMinor,
            updatedAtMs,
            namespace,
            ctx.orgId,
            reservation.environmentId,
            reservation.policyId,
            reservation.mode === 'CHAIN_TOTAL' ? '' : reservation.accountRef || '',
            reservation.chainId,
            reservation.mode,
            reservation.period,
            Date.parse(reservation.windowStartAt),
          ],
        );
        if (!usageRow) {
          const currentUsage = await loadUsageForReservation(tx, { namespace, orgId: ctx.orgId, reservation });
          throw createSpendCapExceededError({
            capMinor: currentUsage.capMinor,
            reservedMinor: currentUsage.reservedMinor - reservation.requestedMinor,
            settledMinor: currentUsage.settledMinor,
            requestedMinor: normalized.settledSpendMinor,
          });
        }
        const updatedReservationRow = await queryOne(
          tx,
          `
            UPDATE console_sponsorship_spend_cap_reservations
               SET settled_minor = $1,
                   released_minor = $2,
                   status = 'SETTLED',
                   updated_at_ms = $3
             WHERE namespace = $4
               AND org_id = $5
               AND id = $6
            RETURNING *
          `,
          [
            normalized.settledSpendMinor,
            Math.max(reservation.requestedMinor - normalized.settledSpendMinor, 0),
            updatedAtMs,
            namespace,
            ctx.orgId,
            reservation.id,
          ],
        );
        if (!updatedReservationRow) {
          throw new Error(`Failed to update spend-cap reservation ${reservation.id}`);
        }
        return {
          reservation: parseReservation(updatedReservationRow),
          usage: parseUsage(usageRow),
        };
      });
    },

    async release(ctx, request) {
      const updatedAt = now();
      const updatedAtMs = nowMs(updatedAt);
      const normalized = normalizeReleaseRequest(request);
      return await withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, async (tx) => {
        const reservationRow = await queryOne(
          tx,
          `
            SELECT *
            FROM console_sponsorship_spend_cap_reservations
            WHERE namespace = $1
              AND org_id = $2
              AND source_event_id = $3
            FOR UPDATE
          `,
          [namespace, ctx.orgId, normalized.sourceEventId],
        );
        if (!reservationRow) return null;
        const reservation = parseReservation(reservationRow);
        if (reservation.status !== 'RESERVED') {
          const usage = await loadUsageForReservation(tx, { namespace, orgId: ctx.orgId, reservation });
          return { reservation, usage };
        }

        const usageRow = await queryOne(
          tx,
          `
            UPDATE console_sponsorship_spend_cap_windows
               SET reserved_minor = reserved_minor - $1,
                   updated_at_ms = $2
             WHERE namespace = $3
               AND org_id = $4
               AND environment_id = $5
               AND policy_id = $6
               AND account_ref = $7
               AND chain_id = $8
               AND mode = $9
               AND period = $10
               AND window_start_ms = $11
               AND reserved_minor >= $1
            RETURNING *
          `,
          [
            reservation.requestedMinor,
            updatedAtMs,
            namespace,
            ctx.orgId,
            reservation.environmentId,
            reservation.policyId,
            reservation.mode === 'CHAIN_TOTAL' ? '' : reservation.accountRef || '',
            reservation.chainId,
            reservation.mode,
            reservation.period,
            Date.parse(reservation.windowStartAt),
          ],
        );
        if (!usageRow) {
          throw new ConsoleSponsorshipSpendCapError(
            'invalid_state',
            409,
            'Spend cap window usage is inconsistent with the reservation',
          );
        }
        const updatedReservationRow = await queryOne(
          tx,
          `
            UPDATE console_sponsorship_spend_cap_reservations
               SET released_minor = requested_minor,
                   status = 'RELEASED',
                   updated_at_ms = $1
             WHERE namespace = $2
               AND org_id = $3
               AND id = $4
            RETURNING *
          `,
          [updatedAtMs, namespace, ctx.orgId, reservation.id],
        );
        if (!updatedReservationRow) {
          throw new Error(`Failed to update spend-cap reservation ${reservation.id}`);
        }
        return {
          reservation: parseReservation(updatedReservationRow),
          usage: parseUsage(usageRow),
        };
      });
    },
  };
}
