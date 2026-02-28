import { getPostgresPool } from '../../../../storage/postgres';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  PrfSessionSealIdempotencyBeginResult,
  PrfSessionSealIdempotencyStore,
  PrfSessionSealRouteResult,
} from '../types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
const TABLE_NAME = 'threshold_prf_session_seal_idempotency';
const DEFAULT_NAMESPACE = 'threshold-prf-seal';

function parseRouteResult(value: unknown): PrfSessionSealRouteResult | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if (record.ok === true) {
    const ciphertext = String(record.ciphertext || '').trim();
    if (!ciphertext) return null;
    return {
      ok: true,
      ciphertext,
      ...(typeof record.keyVersion === 'string' && record.keyVersion.trim()
        ? { keyVersion: record.keyVersion.trim() }
        : {}),
      ...(Number.isFinite(Number(record.expiresAtMs))
        ? { expiresAtMs: Math.max(0, Math.floor(Number(record.expiresAtMs))) }
        : {}),
      ...(Number.isFinite(Number(record.remainingUses))
        ? { remainingUses: Math.max(0, Math.floor(Number(record.remainingUses))) }
        : {}),
    };
  }
  if (record.ok === false) {
    const code = String(record.code || '').trim();
    const message = String(record.message || '').trim();
    if (!code || !message) return null;
    return { ok: false, code, message };
  }
  return null;
}

export class PostgresPrfSessionSealIdempotencyStore implements PrfSessionSealIdempotencyStore {
  private readonly poolPromise: Promise<PgPool>;
  private readonly namespace: string;
  private readonly ready: Promise<void>;

  constructor(input: { postgresUrl: string; namespace?: string }) {
    const postgresUrl = String(input.postgresUrl || '').trim();
    if (!postgresUrl) throw new Error('postgresUrl is required for PRF seal idempotency');
    this.poolPromise = getPostgresPool(postgresUrl);
    this.namespace = toOptionalTrimmedString(input.namespace) || DEFAULT_NAMESPACE;
    this.ready = this.ensureSchema();
  }

  private async ensureSchema(): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
        namespace TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        state TEXT NOT NULL,
        result_json JSONB,
        expires_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, idempotency_key),
        CHECK (state IN ('pending', 'done'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS ${TABLE_NAME}_expires_idx
      ON ${TABLE_NAME} (expires_at_ms)
    `);
  }

  private async getPool(): Promise<PgPool> {
    await this.ready;
    return await this.poolPromise;
  }

  async begin(input: {
    key: string;
    nowMs: number;
    pendingTtlMs: number;
  }): Promise<PrfSessionSealIdempotencyBeginResult> {
    const key = String(input.key || '').trim();
    if (!key) return { acquired: true };

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    const pendingTtlMs = Math.max(1, Math.floor(Number(input.pendingTtlMs) || 0));
    const pendingExpiresAtMs = nowMs + pendingTtlMs;
    const pool = await this.getPool();

    const inserted = await pool.query(
      `
        INSERT INTO ${TABLE_NAME} (
          namespace,
          idempotency_key,
          state,
          result_json,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, 'pending', NULL, $3, $4)
        ON CONFLICT (namespace, idempotency_key) DO NOTHING
      `,
      [this.namespace, key, pendingExpiresAtMs, nowMs],
    );
    if ((inserted.rowCount || 0) > 0) return { acquired: true };

    const existing = await pool.query(
      `
        SELECT state, result_json, expires_at_ms
        FROM ${TABLE_NAME}
        WHERE namespace = $1 AND idempotency_key = $2
      `,
      [this.namespace, key],
    );
    const row = existing.rows[0] as
      | {
          state?: unknown;
          result_json?: unknown;
          expires_at_ms?: unknown;
        }
      | undefined;
    if (!row) return { acquired: true };

    const expiresAtMs = Math.max(0, Math.floor(Number(row.expires_at_ms) || 0));
    if (expiresAtMs <= nowMs) {
      const takenOver = await pool.query(
        `
          UPDATE ${TABLE_NAME}
          SET state = 'pending', result_json = NULL, expires_at_ms = $3, updated_at_ms = $4
          WHERE namespace = $1 AND idempotency_key = $2 AND expires_at_ms <= $4
        `,
        [this.namespace, key, pendingExpiresAtMs, nowMs],
      );
      if ((takenOver.rowCount || 0) > 0) return { acquired: true };
    }

    const state = String(row.state || '').trim();
    if (state === 'done') {
      const result = parseRouteResult(row.result_json);
      if (result) return { acquired: false, result };
    }
    return { acquired: false, pending: true };
  }

  async getResult(input: { key: string; nowMs: number }): Promise<PrfSessionSealRouteResult | null> {
    const key = String(input.key || '').trim();
    if (!key) return null;

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    const pool = await this.getPool();
    const existing = await pool.query(
      `
        SELECT state, result_json, expires_at_ms
        FROM ${TABLE_NAME}
        WHERE namespace = $1 AND idempotency_key = $2
      `,
      [this.namespace, key],
    );
    const row = existing.rows[0] as
      | {
          state?: unknown;
          result_json?: unknown;
          expires_at_ms?: unknown;
        }
      | undefined;
    if (!row) return null;

    const expiresAtMs = Math.max(0, Math.floor(Number(row.expires_at_ms) || 0));
    if (expiresAtMs <= nowMs) {
      await pool
        .query(
          `DELETE FROM ${TABLE_NAME} WHERE namespace = $1 AND idempotency_key = $2 AND expires_at_ms <= $3`,
          [this.namespace, key, nowMs],
        )
        .catch(() => undefined);
      return null;
    }
    const state = String(row.state || '').trim();
    if (state !== 'done') return null;
    return parseRouteResult(row.result_json);
  }

  async complete(input: {
    key: string;
    nowMs: number;
    resultTtlMs: number;
    result: PrfSessionSealRouteResult;
  }): Promise<void> {
    const key = String(input.key || '').trim();
    if (!key) return;

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    const resultTtlMs = Math.max(1, Math.floor(Number(input.resultTtlMs) || 0));
    const expiresAtMs = nowMs + resultTtlMs;
    const pool = await this.getPool();
    await pool.query(
      `
        INSERT INTO ${TABLE_NAME} (
          namespace,
          idempotency_key,
          state,
          result_json,
          expires_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, 'done', $3::jsonb, $4, $5)
        ON CONFLICT (namespace, idempotency_key)
        DO UPDATE SET
          state = 'done',
          result_json = EXCLUDED.result_json,
          expires_at_ms = EXCLUDED.expires_at_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [this.namespace, key, JSON.stringify(input.result), expiresAtMs, nowMs],
    );
  }
}

export function createPostgresPrfSessionSealIdempotencyStore(input: {
  postgresUrl: string;
  namespace?: string;
}): PrfSessionSealIdempotencyStore {
  return new PostgresPrfSessionSealIdempotencyStore(input);
}

