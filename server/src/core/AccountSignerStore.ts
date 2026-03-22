import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type AccountSignerStatus = 'active' | 'pending' | 'revoked';

export type AccountSignerRecord = {
  version: 'account_signer_v1';
  userId: string;
  chainIdKey: string;
  accountAddress: string;
  signerType: string;
  signerId: string;
  status: AccountSignerStatus;
  createdAtMs: number;
  updatedAtMs: number;
  removedAtMs?: number;
  metadata?: Record<string, unknown>;
};

export interface AccountSignerStore {
  put(record: AccountSignerRecord): Promise<void>;
  listByUserId(userId: string): Promise<AccountSignerRecord[]>;
  listByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<AccountSignerRecord[]>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function normalizeHexLike(value: string): string {
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeAccountSignerStatus(value: unknown): AccountSignerStatus | null {
  const normalized = toOptionalTrimmedString(value);
  if (normalized === 'active' || normalized === 'pending' || normalized === 'revoked') {
    return normalized;
  }
  return null;
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  return { ...raw };
}

function parseAccountSignerRecord(raw: unknown): AccountSignerRecord | null {
  if (!isObject(raw)) return null;

  const version = toOptionalTrimmedString(raw.version);
  const userId = toOptionalTrimmedString(raw.userId);
  const chainIdKey = toOptionalTrimmedString(raw.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeHexLike(toOptionalTrimmedString(raw.accountAddress) || '');
  const signerType = toOptionalTrimmedString(raw.signerType);
  const signerId = normalizeHexLike(toOptionalTrimmedString(raw.signerId) || '');
  const status = normalizeAccountSignerStatus((raw as { status?: unknown }).status);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  const removedAtMsRaw = (raw as { removedAtMs?: unknown }).removedAtMs;
  const removedAtMs = typeof removedAtMsRaw === 'number' ? removedAtMsRaw : Number(removedAtMsRaw);

  if (version !== 'account_signer_v1') return null;
  if (!userId || !chainIdKey || !accountAddress || !signerType || !signerId || !status) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  const metadata = parseMetadata((raw as { metadata?: unknown }).metadata);

  return {
    version: 'account_signer_v1',
    userId,
    chainIdKey,
    accountAddress,
    signerType,
    signerId,
    status,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(Number.isFinite(removedAtMs) && removedAtMs > 0
      ? { removedAtMs: Math.floor(removedAtMs) }
      : {}),
    ...(metadata ? { metadata } : {}),
  };
}

class InMemoryAccountSignerStore implements AccountSignerStore {
  private readonly byAccount = new Map<string, AccountSignerRecord>();

  private key(record: {
    userId: string;
    chainIdKey: string;
    accountAddress: string;
    signerId: string;
  }): string {
    return `${record.userId}::${record.chainIdKey}::${record.accountAddress}::${record.signerId}`;
  }

  async put(record: AccountSignerRecord): Promise<void> {
    const parsed = parseAccountSignerRecord(record);
    if (!parsed) throw new Error('Invalid account signer record');
    this.byAccount.set(this.key(parsed), parsed);
  }

  async listByUserId(userId: string): Promise<AccountSignerRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const out: AccountSignerRecord[] = [];
    for (const value of this.byAccount.values()) {
      const parsed = parseAccountSignerRecord(value);
      if (!parsed || parsed.userId !== uid) continue;
      out.push(parsed);
    }
    out.sort((a, b) =>
      `${a.chainIdKey}:${a.accountAddress}:${a.signerId}`.localeCompare(
        `${b.chainIdKey}:${b.accountAddress}:${b.signerId}`,
      ),
    );
    return out;
  }

  async listByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<AccountSignerRecord[]> {
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeHexLike(toOptionalTrimmedString(input.accountAddress) || '');
    if (!chainIdKey || !accountAddress) return [];
    const out: AccountSignerRecord[] = [];
    for (const value of this.byAccount.values()) {
      const parsed = parseAccountSignerRecord(value);
      if (!parsed) continue;
      if (parsed.chainIdKey !== chainIdKey || parsed.accountAddress !== accountAddress) continue;
      out.push(parsed);
    }
    out.sort((a, b) => a.signerId.localeCompare(b.signerId));
    return out;
  }
}

class PostgresAccountSignerStore implements AccountSignerStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: AccountSignerRecord): Promise<void> {
    const parsed = parseAccountSignerRecord(record);
    if (!parsed) throw new Error('Invalid account signer record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO account_signers (
          namespace,
          user_id,
          chain_id_key,
          account_address,
          signer_id,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (namespace, user_id, chain_id_key, account_address, signer_id)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.userId,
        parsed.chainIdKey,
        parsed.accountAddress,
        parsed.signerId,
        parsed,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async listByUserId(userId: string): Promise<AccountSignerRecord[]> {
    const uid = toOptionalTrimmedString(userId);
    if (!uid) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM account_signers
        WHERE namespace = $1 AND user_id = $2
        ORDER BY chain_id_key ASC, account_address ASC, signer_id ASC
      `,
      [this.namespace, uid],
    );
    return rows
      .map((row) => parseAccountSignerRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as AccountSignerRecord[];
  }

  async listByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<AccountSignerRecord[]> {
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeHexLike(toOptionalTrimmedString(input.accountAddress) || '');
    if (!chainIdKey || !accountAddress) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM account_signers
        WHERE namespace = $1 AND chain_id_key = $2 AND account_address = $3
        ORDER BY signer_id ASC
      `,
      [this.namespace, chainIdKey, accountAddress],
    );
    return rows
      .map((row) => parseAccountSignerRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as AccountSignerRecord[];
  }
}

export function createAccountSignerStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): AccountSignerStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.ACCOUNT_SIGNER_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[account-signers] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[account-signers] Using Postgres store for canonical account signer state');
    return new PostgresAccountSignerStore({ postgresUrl, namespace });
  }

  input.logger.info('[account-signers] Using in-memory store for canonical account signer state');
  return new InMemoryAccountSignerStore();
}
