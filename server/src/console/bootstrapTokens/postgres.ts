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
import {
  hashBootstrapToken,
  makeBootstrapToken,
  makeBootstrapTokenLookupPrefix,
  parseBootstrapToken,
} from './secret';
import type {
  ConsoleBootstrapTokenRecord,
  CountConsoleBootstrapTokensRequest,
  CreateConsoleBootstrapTokenRequest,
  CreateConsoleBootstrapTokenResult,
  RedeemConsoleBootstrapTokenRequest,
  RedeemConsoleBootstrapTokenResult,
} from './types';
import type { ConsoleBootstrapTokenService, ConsoleBootstrapTokensContext } from './service';
import { makeId } from '../apiKeys/secret';
import { normalizeCorsOrigin } from '../../core/SessionService';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_BOOTSTRAP_TOKENS_MIGRATION_LOCK_ID = 9452360123587;

function nowMs(now: Date): number {
  return now.getTime();
}

function normalizeMethod(method: string): string {
  return String(method || '').trim().toUpperCase();
}

function normalizePath(path: string): string {
  const trimmed = String(path || '').trim();
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function normalizeOrigin(origin: string): string {
  return normalizeCorsOrigin(origin) || '';
}

function parseRow(row: PgRow): ConsoleBootstrapTokenRecord {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    projectId: String(row.project_id || ''),
    environmentId: String(row.environment_id || ''),
    publishableKeyId: String(row.publishable_key_id || ''),
    tokenPrefix: String(row.token_prefix || ''),
    tokenHash: String(row.token_hash || ''),
    method: String(row.method || 'POST'),
    path: String(row.path || '/registration/bootstrap'),
    origin: String(row.origin || ''),
    requestHashSha256: String(row.request_hash_sha256 || ''),
    status: String(row.status || 'issued') as ConsoleBootstrapTokenRecord['status'],
    riskDecision: String(row.risk_decision || ''),
    paymentReference:
      row.payment_reference == null ? null : String(row.payment_reference || '').trim(),
    replacementForTokenId:
      row.replacement_for_token_id == null
        ? null
        : String(row.replacement_for_token_id || '').trim(),
    issuedAt: toIso(toNumber(row.issued_at_ms)) || new Date(0).toISOString(),
    expiresAt: toIso(toNumber(row.expires_at_ms)) || new Date(0).toISOString(),
    redeemedAt: toIso(row.redeemed_at_ms == null ? null : toNumber(row.redeemed_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

export interface PostgresConsoleBootstrapTokenSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleBootstrapTokensPostgresSchema(
  options: PostgresConsoleBootstrapTokenSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_BOOTSTRAP_TOKENS_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_bootstrap_tokens (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        project_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        publishable_key_id TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        method TEXT NOT NULL,
        path TEXT NOT NULL,
        origin TEXT NOT NULL,
        request_hash_sha256 TEXT NOT NULL,
        status TEXT NOT NULL,
        risk_decision TEXT NOT NULL,
        payment_reference TEXT,
        replacement_for_token_id TEXT,
        issued_at_ms BIGINT NOT NULL,
        expires_at_ms BIGINT NOT NULL,
        redeemed_at_ms BIGINT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('issued', 'redeemed', 'expired', 'canceled'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_bootstrap_tokens_org_publishable_idx
      ON console_bootstrap_tokens (namespace, org_id, publishable_key_id, issued_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_bootstrap_tokens_org_status_idx
      ON console_bootstrap_tokens (namespace, org_id, status, expires_at_ms)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_bootstrap_tokens_org_prefix_idx
      ON console_bootstrap_tokens (namespace, org_id, token_prefix, id)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_bootstrap_tokens',
      policyName: 'console_bootstrap_tokens_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_BOOTSTRAP_TOKENS_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-bootstrap-tokens][postgres] Schema ready');
}

export interface PostgresConsoleBootstrapTokenServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleBootstrapTokenService(
  options: PostgresConsoleBootstrapTokenServiceOptions,
): Promise<ConsoleBootstrapTokenService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) {
    throw new Error('Missing POSTGRES_URL for Postgres console bootstrap token service');
  }
  const namespace = ensureNamespace(options.namespace || 'relay-console');
  const logger = (options.logger || console) as NormalizedLogger;
  if (options.ensureSchema !== false) {
    await ensureConsoleBootstrapTokensPostgresSchema({
      postgresUrl,
      logger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);
  const now = options.now || (() => new Date());

  const withTenantTx = <T>(
    ctx: ConsoleBootstrapTokensContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> =>
    withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async createToken(ctx, request): Promise<CreateConsoleBootstrapTokenResult> {
      return await withTenantTx(ctx, async (q) => {
        const currentNow = now();
        const issuedAtMs = nowMs(currentNow);
        const expiresAtMs = issuedAtMs + Math.max(1_000, Math.floor(request.ttlMs || 60_000));
        const tokenId = makeId('tbt', currentNow);
        const token = makeBootstrapToken({ orgId: ctx.orgId, tokenId });
        const row = await queryOne(
          q,
          `INSERT INTO console_bootstrap_tokens (
             namespace,
             id,
             org_id,
             project_id,
             environment_id,
             publishable_key_id,
             token_hash,
             token_prefix,
             method,
             path,
             origin,
             request_hash_sha256,
             status,
             risk_decision,
             payment_reference,
             replacement_for_token_id,
             issued_at_ms,
             expires_at_ms,
             redeemed_at_ms,
             created_at_ms,
             updated_at_ms
           )
           VALUES (
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
             $11, $12, 'issued', $13, $14, $15, $16, $17, NULL, $16, $16
           )
           RETURNING *`,
          [
            namespace,
            tokenId,
            ctx.orgId,
            String(request.projectId || '').trim(),
            String(request.environmentId || '').trim(),
            String(request.publishableKeyId || '').trim(),
            await hashBootstrapToken(token),
            makeBootstrapTokenLookupPrefix(token),
            normalizeMethod(request.method),
            normalizePath(request.path),
            normalizeOrigin(request.origin),
            String(request.requestHashSha256 || '').trim(),
            String(request.riskDecision || '').trim() || 'allow',
            request.paymentReference == null ? null : String(request.paymentReference || '').trim(),
            request.replacementForTokenId == null
              ? null
              : String(request.replacementForTokenId || '').trim(),
            issuedAtMs,
            expiresAtMs,
          ],
        );
        if (!row) {
          throw new Error('Failed to persist bootstrap token');
        }
        return {
          token,
          record: parseRow(row),
        };
      });
    },

    async countIssued(ctx, request): Promise<number> {
      return await withTenantTx(ctx, async (q) => {
        const values: unknown[] = [namespace, request.publishableKeyId];
        let where = `namespace = $1 AND publishable_key_id = $2`;
        if (request.issuedSince) {
          values.push(new Date(request.issuedSince).getTime());
          where += ` AND issued_at_ms >= $3`;
        }
        const row = await queryOne(
          q,
          `SELECT COUNT(*)::BIGINT AS count
             FROM console_bootstrap_tokens
            WHERE ${where}`,
          values,
        );
        return Number((row as { count?: unknown } | null)?.count || 0);
      });
    },

    async redeemToken(request): Promise<RedeemConsoleBootstrapTokenResult> {
      const parsed = parseBootstrapToken(request.token);
      if (!parsed) {
        return {
          ok: false,
          status: 401,
          code: 'bootstrap_token_invalid',
          message: 'Invalid bootstrap token',
        };
      }

      return await withConsoleTenantContextTx(
        pool,
        { namespace, orgId: parsed.orgId },
        async (q) => {
          const row = await queryOne(
            q,
            `SELECT *
               FROM console_bootstrap_tokens
              WHERE namespace = $1
                AND id = $2
              FOR UPDATE`,
            [namespace, parsed.tokenId],
          );
          if (!row) {
            return {
              ok: false,
              status: 401,
              code: 'bootstrap_token_invalid',
              message: 'Invalid bootstrap token',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }
          const record = parseRow(row);
          if (
            record.tokenPrefix !== makeBootstrapTokenLookupPrefix(request.token) ||
            record.tokenHash !== (await hashBootstrapToken(request.token))
          ) {
            return {
              ok: false,
              status: 401,
              code: 'bootstrap_token_invalid',
              message: 'Invalid bootstrap token',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }

          const currentNow = now();
          const currentNowMs = nowMs(currentNow);
          if (record.status === 'redeemed') {
            return {
              ok: false,
              status: 409,
              code: 'bootstrap_token_already_used',
              message: 'Bootstrap token has already been used',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }
          if (record.status === 'expired' || currentNowMs >= new Date(record.expiresAt).getTime()) {
            await q.query(
              `UPDATE console_bootstrap_tokens
                  SET status = 'expired',
                      updated_at_ms = $3
                WHERE namespace = $1
                  AND id = $2
                  AND status = 'issued'`,
              [namespace, record.id, currentNowMs],
            );
            return {
              ok: false,
              status: 401,
              code: 'bootstrap_token_expired',
              message: 'Bootstrap token has expired',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }

          const normalizedOrigin = normalizeOrigin(request.origin);
          if (!normalizedOrigin || record.origin !== normalizedOrigin) {
            return {
              ok: false,
              status: 403,
              code: 'bootstrap_token_origin_mismatch',
              message: 'Bootstrap token origin does not match this request',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }
          if (
            record.method !== normalizeMethod(request.method) ||
            record.path !== normalizePath(request.path) ||
            record.requestHashSha256 !== String(request.requestHashSha256 || '').trim()
          ) {
            return {
              ok: false,
              status: 409,
              code: 'bootstrap_token_request_mismatch',
              message: 'Bootstrap token is not valid for this request payload',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }

          const redeemedAtMs = currentNowMs;
          const redeemedRow = await queryOne(
            q,
            `UPDATE console_bootstrap_tokens
                SET status = 'redeemed',
                    redeemed_at_ms = $3,
                    updated_at_ms = $3
              WHERE namespace = $1
                AND id = $2
                AND status = 'issued'
            RETURNING *`,
            [namespace, record.id, redeemedAtMs],
          );
          if (!redeemedRow) {
            return {
              ok: false,
              status: 409,
              code: 'bootstrap_token_already_used',
              message: 'Bootstrap token has already been used',
            } satisfies RedeemConsoleBootstrapTokenResult;
          }
          return {
            ok: true,
            record: parseRow(redeemedRow),
          } satisfies RedeemConsoleBootstrapTokenResult;
        },
      );
    },
  };
}

