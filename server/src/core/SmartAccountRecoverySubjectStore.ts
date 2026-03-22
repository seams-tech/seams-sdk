import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type SmartAccountRecoverySubjectRecord = {
  version: 'smart_account_recovery_subject_v1';
  userId: string;
  nearAccountId: string;
  chainIdKey: string;
  accountAddress: string;
  createdAtMs: number;
  updatedAtMs: number;
  metadata?: Record<string, unknown>;
};

export interface SmartAccountRecoverySubjectStore {
  put(record: SmartAccountRecoverySubjectRecord): Promise<void>;
  getByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<SmartAccountRecoverySubjectRecord | null>;
  listByNearAccountId(nearAccountId: string): Promise<SmartAccountRecoverySubjectRecord[]>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function normalizeHexLike(value: string): string {
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  return { ...raw };
}

function parseSmartAccountRecoverySubjectRecord(
  raw: unknown,
): SmartAccountRecoverySubjectRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const userId = toOptionalTrimmedString(raw.userId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const chainIdKey = toOptionalTrimmedString(raw.chainIdKey)?.toLowerCase() || '';
  const accountAddress = normalizeHexLike(toOptionalTrimmedString(raw.accountAddress) || '');
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  if (version !== 'smart_account_recovery_subject_v1') return null;
  if (!userId || !nearAccountId || !chainIdKey || !accountAddress) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  const metadata = parseMetadata((raw as { metadata?: unknown }).metadata);

  return {
    version: 'smart_account_recovery_subject_v1',
    userId,
    nearAccountId,
    chainIdKey,
    accountAddress,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    ...(metadata ? { metadata } : {}),
  };
}

class InMemorySmartAccountRecoverySubjectStore implements SmartAccountRecoverySubjectStore {
  private readonly byAccount = new Map<string, SmartAccountRecoverySubjectRecord>();

  private key(input: { chainIdKey: string; accountAddress: string }): string {
    return `${input.chainIdKey}::${input.accountAddress}`;
  }

  async put(record: SmartAccountRecoverySubjectRecord): Promise<void> {
    const parsed = parseSmartAccountRecoverySubjectRecord(record);
    if (!parsed) throw new Error('Invalid smart-account recovery subject record');
    this.byAccount.set(this.key(parsed), parsed);
  }

  async getByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<SmartAccountRecoverySubjectRecord | null> {
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeHexLike(toOptionalTrimmedString(input.accountAddress) || '');
    if (!chainIdKey || !accountAddress) return null;
    return this.byAccount.get(this.key({ chainIdKey, accountAddress })) || null;
  }

  async listByNearAccountId(nearAccountId: string): Promise<SmartAccountRecoverySubjectRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const out: SmartAccountRecoverySubjectRecord[] = [];
    for (const value of this.byAccount.values()) {
      const parsed = parseSmartAccountRecoverySubjectRecord(value);
      if (!parsed || parsed.nearAccountId !== accountId) continue;
      out.push(parsed);
    }
    out.sort((a, b) => `${a.chainIdKey}:${a.accountAddress}`.localeCompare(`${b.chainIdKey}:${b.accountAddress}`));
    return out;
  }
}

class PostgresSmartAccountRecoverySubjectStore implements SmartAccountRecoverySubjectStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async put(record: SmartAccountRecoverySubjectRecord): Promise<void> {
    const parsed = parseSmartAccountRecoverySubjectRecord(record);
    if (!parsed) throw new Error('Invalid smart-account recovery subject record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO smart_account_recovery_subjects (
          namespace,
          user_id,
          near_account_id,
          chain_id_key,
          account_address,
          record_json,
          created_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (namespace, chain_id_key, account_address)
        DO UPDATE SET
          record_json = EXCLUDED.record_json,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.userId,
        parsed.nearAccountId,
        parsed.chainIdKey,
        parsed.accountAddress,
        parsed,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async getByAccount(input: {
    chainIdKey: string;
    accountAddress: string;
  }): Promise<SmartAccountRecoverySubjectRecord | null> {
    const chainIdKey = toOptionalTrimmedString(input.chainIdKey)?.toLowerCase() || '';
    const accountAddress = normalizeHexLike(toOptionalTrimmedString(input.accountAddress) || '');
    if (!chainIdKey || !accountAddress) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM smart_account_recovery_subjects
        WHERE namespace = $1 AND chain_id_key = $2 AND account_address = $3
      `,
      [this.namespace, chainIdKey, accountAddress],
    );
    return parseSmartAccountRecoverySubjectRecord((rows[0] as { record_json?: unknown } | undefined)?.record_json);
  }

  async listByNearAccountId(nearAccountId: string): Promise<SmartAccountRecoverySubjectRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM smart_account_recovery_subjects
        WHERE namespace = $1 AND near_account_id = $2
        ORDER BY chain_id_key ASC, account_address ASC
      `,
      [this.namespace, accountId],
    );
    return rows
      .map((row) =>
        parseSmartAccountRecoverySubjectRecord((row as { record_json?: unknown }).record_json),
      )
      .filter(Boolean) as SmartAccountRecoverySubjectRecord[];
  }
}

export function createSmartAccountRecoverySubjectStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): SmartAccountRecoverySubjectStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.SMART_ACCOUNT_RECOVERY_SUBJECT_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[smart-account-recovery-subjects] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info(
      '[smart-account-recovery-subjects] Using Postgres store for smart-account recovery subjects',
    );
    return new PostgresSmartAccountRecoverySubjectStore({ postgresUrl, namespace });
  }

  input.logger.info(
    '[smart-account-recovery-subjects] Using in-memory store for smart-account recovery subjects',
  );
  return new InMemorySmartAccountRecoverySubjectStore();
}
