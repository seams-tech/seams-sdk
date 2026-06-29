import { normalizeCorsOrigin } from '../../core/SessionService';
import {
  d1Integer as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonArrayColumn as parseJsonArray,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { makeId } from '../apiKeys/secret';
import {
  hashBootstrapToken,
  makeBootstrapToken,
  makeBootstrapTokenLookupPrefix,
  parseBootstrapToken,
} from './secret';
import type {
  ConsoleBootstrapTokenRecord,
  ConsoleBootstrapTokenStatus,
  CountConsoleBootstrapTokensRequest,
  CreateConsoleBootstrapTokenRequest,
  CreateConsoleBootstrapTokenResult,
  RedeemConsoleBootstrapTokenRequest,
  RedeemConsoleBootstrapTokenResult,
} from './types';
import type {
  ConsoleBootstrapTokensContext,
  ConsoleBootstrapTokenService,
} from './service';


interface D1ConsoleBootstrapTokenState {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

type ParsedBootstrapToken = {
  readonly orgId: string;
  readonly tokenId: string;
};

export const CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME = Symbol(
  'consoleBootstrapTokensD1Runtime',
);

export interface ConsoleBootstrapTokensD1Runtime {
  readonly database: D1DatabaseLike;
  readonly namespace: string;
  readonly now: () => Date;
}

export type ConsoleBootstrapTokensD1Service = ConsoleBootstrapTokenService & {
  readonly [CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME]: ConsoleBootstrapTokensD1Runtime;
};

export interface D1ConsoleBootstrapTokenSchemaOptions {
  readonly database: D1DatabaseLike;
}

export interface D1ConsoleBootstrapTokenServiceOptions {
  readonly database: D1DatabaseLike;
  readonly namespace?: string;
  readonly ensureSchema?: boolean;
  readonly now?: () => Date;
}

export const CONSOLE_BOOTSTRAP_TOKENS_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS bootstrap_tokens (
      namespace TEXT NOT NULL,
      org_id TEXT NOT NULL,
      id TEXT NOT NULL,
      project_id TEXT NOT NULL,
      environment_id TEXT NOT NULL,
      publishable_key_id TEXT NOT NULL,
      new_account_id TEXT NOT NULL,
      rp_id TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      token_prefix TEXT NOT NULL,
      method TEXT NOT NULL,
      path TEXT NOT NULL,
      allowed_paths_json TEXT NOT NULL,
      origin TEXT NOT NULL,
      request_hash_sha256 TEXT NOT NULL,
      max_uses INTEGER NOT NULL,
      used_count INTEGER NOT NULL DEFAULT 0,
      status TEXT NOT NULL,
      risk_decision TEXT NOT NULL,
      payment_reference TEXT,
      replacement_for_token_id TEXT,
      issued_at_ms INTEGER NOT NULL,
      expires_at_ms INTEGER NOT NULL,
      redeemed_at_ms INTEGER,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, org_id, id),
      CHECK (status IN ('issued', 'redeemed', 'expired', 'canceled')),
      CHECK (json_valid(allowed_paths_json)),
      CHECK (max_uses >= 1),
      CHECK (used_count >= 0),
      CHECK (used_count <= max_uses)
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS bootstrap_tokens_namespace_id_uidx
      ON bootstrap_tokens (namespace, id)
  `,
  `
    CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_publishable_idx
      ON bootstrap_tokens (namespace, org_id, publishable_key_id, issued_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_status_idx
      ON bootstrap_tokens (namespace, org_id, status, expires_at_ms)
  `,
  `
    CREATE INDEX IF NOT EXISTS bootstrap_tokens_org_prefix_idx
      ON bootstrap_tokens (namespace, org_id, token_prefix, id)
  `,
] as const);

export async function ensureConsoleBootstrapTokensD1Schema(
  options: D1ConsoleBootstrapTokenSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_BOOTSTRAP_TOKENS_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleBootstrapTokensD1Runtime(
  service: ConsoleBootstrapTokenService | null | undefined,
): ConsoleBootstrapTokensD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleBootstrapTokensD1Service>)[
      CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME
    ] || null
  );
}

export async function createD1ConsoleBootstrapTokenService(
  options: D1ConsoleBootstrapTokenServiceOptions,
): Promise<ConsoleBootstrapTokensD1Service> {
  const state: D1ConsoleBootstrapTokenState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  if (options.ensureSchema !== false) {
    await ensureConsoleBootstrapTokensD1Schema({ database: state.database });
  }
  return new D1ConsoleBootstrapTokenServiceImpl(state) as ConsoleBootstrapTokensD1Service;
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

function nullableIso(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  const parsed = toNumber(value, 0);
  return parsed > 0 ? toIso(parsed) : null;
}


function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function normalizeMethod(method: string): string {
  return normalizeString(method).toUpperCase();
}

function normalizePath(path: string): string {
  const trimmed = normalizeString(path);
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

function normalizeOrigin(origin: string): string {
  return normalizeCorsOrigin(origin) || '';
}

function normalizeAllowedPaths(paths: readonly string[] | undefined, fallbackPath: string): string[] {
  const normalized = Array.isArray(paths)
    ? Array.from(
        new Set(paths.map((entry) => normalizePath(entry)).filter(Boolean)),
      )
    : [];
  if (normalized.length > 0) return normalized;
  return [normalizePath(fallbackPath)];
}

function parseAllowedPathsJson(input: unknown, fallbackPath: string): string[] {
  const parsedPaths = parseJsonArray(input).map((entry) => normalizeString(entry));
  return normalizeAllowedPaths(parsedPaths, fallbackPath);
}

function parseStatus(value: unknown): ConsoleBootstrapTokenStatus {
  const normalized = normalizeString(value);
  switch (normalized) {
    case 'issued':
    case 'redeemed':
    case 'expired':
    case 'canceled':
      return normalized;
    default:
      throw new Error(`Invalid console bootstrap token status row: ${normalized || 'empty'}`);
  }
}

function parseRow(row: D1Row): ConsoleBootstrapTokenRecord {
  const path = normalizeString(row.path) || '/wallets/register/intent';
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    projectId: normalizeString(row.project_id),
    environmentId: normalizeString(row.environment_id),
    publishableKeyId: normalizeString(row.publishable_key_id),
    newAccountId: normalizeString(row.new_account_id),
    rpId: normalizeString(row.rp_id),
    tokenPrefix: normalizeString(row.token_prefix),
    tokenHash: normalizeString(row.token_hash),
    method: normalizeString(row.method) || 'POST',
    path,
    allowedPaths: parseAllowedPathsJson(row.allowed_paths_json, path),
    origin: normalizeString(row.origin),
    requestHashSha256: normalizeString(row.request_hash_sha256) || null,
    maxUses: Math.max(1, toNumber(row.max_uses, 1)),
    usedCount: Math.max(0, toNumber(row.used_count, 0)),
    status: parseStatus(row.status || 'issued'),
    riskDecision: normalizeString(row.risk_decision),
    paymentReference: row.payment_reference == null ? null : normalizeString(row.payment_reference),
    replacementForTokenId:
      row.replacement_for_token_id == null
        ? null
        : normalizeString(row.replacement_for_token_id),
    issuedAt: toIso(toNumber(row.issued_at_ms)),
    expiresAt: toIso(toNumber(row.expires_at_ms)),
    redeemedAt: nullableIso(row.redeemed_at_ms),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
  };
}

function cloneRecord(record: ConsoleBootstrapTokenRecord): ConsoleBootstrapTokenRecord {
  return {
    ...record,
    allowedPaths: [...record.allowedPaths],
  };
}


function invalidTokenResult(): RedeemConsoleBootstrapTokenResult {
  return {
    ok: false,
    status: 401,
    code: 'bootstrap_token_invalid',
    message: 'Invalid bootstrap token',
  };
}

function alreadyUsedResult(): RedeemConsoleBootstrapTokenResult {
  return {
    ok: false,
    status: 409,
    code: 'bootstrap_token_already_used',
    message: 'Bootstrap token has already been used',
  };
}

function expiredResult(): RedeemConsoleBootstrapTokenResult {
  return {
    ok: false,
    status: 401,
    code: 'bootstrap_token_expired',
    message: 'Bootstrap token has expired',
  };
}

function originMismatchResult(): RedeemConsoleBootstrapTokenResult {
  return {
    ok: false,
    status: 403,
    code: 'bootstrap_token_origin_mismatch',
    message: 'Bootstrap token origin does not match this request',
  };
}

function requestMismatchResult(): RedeemConsoleBootstrapTokenResult {
  return {
    ok: false,
    status: 409,
    code: 'bootstrap_token_request_mismatch',
    message: 'Bootstrap token is not valid for this request payload',
  };
}

function tokenFingerprintMatches(input: {
  readonly record: ConsoleBootstrapTokenRecord;
  readonly token: string;
  readonly tokenHash: string;
}): boolean {
  return (
    input.record.tokenPrefix === makeBootstrapTokenLookupPrefix(input.token) &&
    input.record.tokenHash === input.tokenHash
  );
}

class D1ConsoleBootstrapTokenServiceImpl implements ConsoleBootstrapTokenService {
  readonly [CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME]: ConsoleBootstrapTokensD1Runtime;

  private readonly state: D1ConsoleBootstrapTokenState;

  constructor(state: D1ConsoleBootstrapTokenState) {
    this.state = state;
    this[CONSOLE_BOOTSTRAP_TOKENS_D1_RUNTIME] = {
      database: state.database,
      namespace: state.namespace,
      now: state.now,
    };
    this.createToken = this.createToken.bind(this);
    this.countIssued = this.countIssued.bind(this);
    this.peekTokenRecord = this.peekTokenRecord.bind(this);
    this.redeemToken = this.redeemToken.bind(this);
  }

  async createToken(
    ctx: ConsoleBootstrapTokensContext,
    request: CreateConsoleBootstrapTokenRequest,
  ): Promise<CreateConsoleBootstrapTokenResult> {
    const currentNow = this.state.now();
    const issuedAtMs = nowMs(currentNow);
    const expiresAtMs = issuedAtMs + Math.max(1_000, Math.floor(request.ttlMs || 60_000));
    const tokenId = makeId('tbt', currentNow);
    const token = makeBootstrapToken({ orgId: ctx.orgId, tokenId });
    const record = await this.buildRecord({
      ctx,
      request,
      tokenId,
      token,
      issuedAtMs,
      expiresAtMs,
    });
    await this.insertRecord(record);
    return {
      token,
      record: cloneRecord(record),
    };
  }

  async countIssued(
    ctx: ConsoleBootstrapTokensContext,
    request: CountConsoleBootstrapTokensRequest,
  ): Promise<number> {
    const parsedIssuedSinceMs = request.issuedSince ? Date.parse(request.issuedSince) : NaN;
    const issuedSinceMs = Number.isFinite(parsedIssuedSinceMs)
      ? Math.floor(parsedIssuedSinceMs)
      : null;
    const row = await this.state.database
      .prepare(
        `SELECT COUNT(*) AS count
           FROM bootstrap_tokens
          WHERE namespace = ?
            AND org_id = ?
            AND publishable_key_id = ?
            AND (? IS NULL OR issued_at_ms >= ?)`,
      )
      .bind(
        this.state.namespace,
        ctx.orgId,
        request.publishableKeyId,
        issuedSinceMs,
        issuedSinceMs,
      )
      .first<{ readonly count?: unknown }>();
    return toNumber(row?.count, 0);
  }

  async peekTokenRecord(token: string): Promise<ConsoleBootstrapTokenRecord | null> {
    const parsed = parseBootstrapToken(token);
    if (!parsed) return null;
    const record = await this.findTokenRecord(parsed);
    if (!record) return null;
    const tokenHash = await hashBootstrapToken(token);
    if (!tokenFingerprintMatches({ record, token, tokenHash })) return null;
    return cloneRecord(record);
  }

  async redeemToken(
    request: RedeemConsoleBootstrapTokenRequest,
  ): Promise<RedeemConsoleBootstrapTokenResult> {
    const parsed = parseBootstrapToken(request.token);
    if (!parsed) return invalidTokenResult();

    const record = await this.findTokenRecord(parsed);
    if (!record) return invalidTokenResult();

    const tokenHash = await hashBootstrapToken(request.token);
    if (!tokenFingerprintMatches({ record, token: request.token, tokenHash })) {
      return invalidTokenResult();
    }

    const currentNowMs = nowMs(this.state.now());
    if (record.status === 'redeemed' || record.usedCount >= record.maxUses) {
      return alreadyUsedResult();
    }
    if (record.status === 'expired' || currentNowMs >= Date.parse(record.expiresAt)) {
      await this.markExpired(record, currentNowMs);
      return expiredResult();
    }

    if (!this.originMatches(record, request)) return originMismatchResult();
    if (!this.requestMatches(record, request)) return requestMismatchResult();

    const redeemed = await this.redeemIssuedToken(record, currentNowMs);
    if (!redeemed) return alreadyUsedResult();
    return {
      ok: true,
      record: cloneRecord(redeemed),
    };
  }

  private async buildRecord(input: {
    readonly ctx: ConsoleBootstrapTokensContext;
    readonly request: CreateConsoleBootstrapTokenRequest;
    readonly tokenId: string;
    readonly token: string;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<ConsoleBootstrapTokenRecord> {
    const request = input.request;
    const issuedAt = toIso(input.issuedAtMs);
    return {
      id: input.tokenId,
      orgId: input.ctx.orgId,
      projectId: normalizeString(request.projectId),
      environmentId: normalizeString(request.environmentId),
      publishableKeyId: normalizeString(request.publishableKeyId),
      newAccountId: normalizeString(request.newAccountId),
      rpId: normalizeString(request.rpId),
      tokenPrefix: makeBootstrapTokenLookupPrefix(input.token),
      tokenHash: await hashBootstrapToken(input.token),
      method: normalizeMethod(request.method),
      path: normalizePath(request.path),
      allowedPaths: normalizeAllowedPaths(request.allowedPaths, request.path),
      origin: normalizeOrigin(request.origin),
      requestHashSha256: normalizeString(request.requestHashSha256) || null,
      maxUses: Math.max(1, Math.floor(Number(request.maxUses) || 1)),
      usedCount: 0,
      status: 'issued',
      riskDecision: normalizeString(request.riskDecision) || 'allow',
      paymentReference:
        request.paymentReference == null ? null : normalizeString(request.paymentReference),
      replacementForTokenId:
        request.replacementForTokenId == null
          ? null
          : normalizeString(request.replacementForTokenId),
      issuedAt,
      expiresAt: toIso(input.expiresAtMs),
      redeemedAt: null,
      createdAt: issuedAt,
      updatedAt: issuedAt,
    };
  }

  private async insertRecord(record: ConsoleBootstrapTokenRecord): Promise<void> {
    await this.state.database
      .prepare(
        `INSERT INTO bootstrap_tokens (
           namespace, org_id, id, project_id, environment_id, publishable_key_id,
           new_account_id, rp_id, token_hash, token_prefix, method, path,
           allowed_paths_json, origin, request_hash_sha256, max_uses, used_count,
           status, risk_decision, payment_reference, replacement_for_token_id,
           issued_at_ms, expires_at_ms, redeemed_at_ms, created_at_ms, updated_at_ms
         )
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      )
      .bind(
        this.state.namespace,
        record.orgId,
        record.id,
        record.projectId,
        record.environmentId,
        record.publishableKeyId,
        record.newAccountId,
        record.rpId,
        record.tokenHash,
        record.tokenPrefix,
        record.method,
        record.path,
        JSON.stringify(record.allowedPaths),
        record.origin,
        record.requestHashSha256 || '',
        record.maxUses,
        record.usedCount,
        record.status,
        record.riskDecision,
        record.paymentReference,
        record.replacementForTokenId,
        Date.parse(record.issuedAt),
        Date.parse(record.expiresAt),
        Date.parse(record.createdAt),
        Date.parse(record.updatedAt),
      )
      .run();
  }

  private async findTokenRecord(
    parsed: ParsedBootstrapToken,
  ): Promise<ConsoleBootstrapTokenRecord | null> {
    const row = await this.state.database
      .prepare(
        `SELECT *
           FROM bootstrap_tokens
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?`,
      )
      .bind(this.state.namespace, parsed.orgId, parsed.tokenId)
      .first<D1Row>();
    return row ? parseRow(row) : null;
  }

  private async markExpired(
    record: ConsoleBootstrapTokenRecord,
    currentNowMs: number,
  ): Promise<void> {
    await this.state.database
      .prepare(
        `UPDATE bootstrap_tokens
            SET status = 'expired',
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'issued'`,
      )
      .bind(currentNowMs, this.state.namespace, record.orgId, record.id)
      .run();
  }

  private originMatches(
    record: ConsoleBootstrapTokenRecord,
    request: RedeemConsoleBootstrapTokenRequest,
  ): boolean {
    const normalizedOrigin = normalizeOrigin(request.origin);
    return Boolean(normalizedOrigin && record.origin === normalizedOrigin);
  }

  private requestMatches(
    record: ConsoleBootstrapTokenRecord,
    request: RedeemConsoleBootstrapTokenRequest,
  ): boolean {
    if (record.method !== normalizeMethod(request.method)) return false;
    if (!record.allowedPaths.includes(normalizePath(request.path))) return false;
    if (!record.requestHashSha256) return true;
    return record.requestHashSha256 === normalizeString(request.requestHashSha256);
  }

  private async redeemIssuedToken(
    record: ConsoleBootstrapTokenRecord,
    redeemedAtMs: number,
  ): Promise<ConsoleBootstrapTokenRecord | null> {
    const result = await this.state.database
      .prepare(
        `UPDATE bootstrap_tokens
            SET used_count = used_count + 1,
                status = CASE
                  WHEN used_count + 1 >= max_uses THEN 'redeemed'
                  ELSE 'issued'
                END,
                redeemed_at_ms = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND id = ?
            AND status = 'issued'
            AND used_count < max_uses`,
      )
      .bind(redeemedAtMs, redeemedAtMs, this.state.namespace, record.orgId, record.id)
      .run();
    if (d1ChangedRows(result) < 1) return null;
    return await this.findTokenRecord({ orgId: record.orgId, tokenId: record.id });
  }
}
