import type { NormalizedLogger } from './logger';
import { isObject as isObjectLoose, toOptionalTrimmedString } from '@shared/utils/validation';
import { getPostgresPool, getPostgresUrlFromConfig } from '../storage/postgres';

export type RecoverySessionStatus =
  | 'prepared'
  | 'verified'
  | 'near_recovered'
  | 'evm_recovering'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type RecoverySessionRecord = {
  version: 'recovery_session_v1';
  sessionId: string;
  userId: string;
  nearAccountId: string;
  signerSlot: number;
  status: RecoverySessionStatus;
  createdAtMs: number;
  updatedAtMs: number;
  expiresAtMs: number;
  newNearPublicKey: string;
  newEvmOwnerAddress: string;
  recoveryDeadlineEpochSeconds: number;
  recoveryEmailPayloadHash: string;
  verifiedRecoveryPayloadHash?: string;
  verifiedRecoveryArtifactHash?: string;
  scope?: string;
  metadata?: Record<string, unknown>;
};

export interface RecoverySessionStore {
  get(sessionId: string): Promise<RecoverySessionRecord | null>;
  put(record: RecoverySessionRecord): Promise<void>;
  listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]>;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return isObjectLoose(v);
}

function normalizeHexLike(value: string): string {
  return value.startsWith('0x') ? value.toLowerCase() : value;
}

function normalizeRecoverySessionStatus(value: unknown): RecoverySessionStatus | null {
  const normalized = toOptionalTrimmedString(value);
  if (
    normalized === 'prepared' ||
    normalized === 'verified' ||
    normalized === 'near_recovered' ||
    normalized === 'evm_recovering' ||
    normalized === 'completed' ||
    normalized === 'failed' ||
    normalized === 'cancelled'
  ) {
    return normalized;
  }
  return null;
}

function parseMetadata(raw: unknown): Record<string, unknown> | undefined {
  if (!isObject(raw)) return undefined;
  return { ...raw };
}

function parseRecoverySessionRecord(raw: unknown): RecoverySessionRecord | null {
  if (!isObject(raw)) return null;
  const version = toOptionalTrimmedString(raw.version);
  const sessionId = toOptionalTrimmedString(raw.sessionId);
  const userId = toOptionalTrimmedString(raw.userId);
  const nearAccountId = toOptionalTrimmedString(raw.nearAccountId);
  const status = normalizeRecoverySessionStatus((raw as { status?: unknown }).status);
  const signerSlotRaw = (raw as { signerSlot?: unknown }).signerSlot;
  const signerSlot =
    typeof signerSlotRaw === 'number' ? signerSlotRaw : Number(signerSlotRaw);
  const createdAtMsRaw = (raw as { createdAtMs?: unknown }).createdAtMs;
  const updatedAtMsRaw = (raw as { updatedAtMs?: unknown }).updatedAtMs;
  const expiresAtMsRaw = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  const createdAtMs = typeof createdAtMsRaw === 'number' ? createdAtMsRaw : Number(createdAtMsRaw);
  const updatedAtMs = typeof updatedAtMsRaw === 'number' ? updatedAtMsRaw : Number(updatedAtMsRaw);
  const expiresAtMs = typeof expiresAtMsRaw === 'number' ? expiresAtMsRaw : Number(expiresAtMsRaw);
  const newNearPublicKey = toOptionalTrimmedString((raw as { newNearPublicKey?: unknown }).newNearPublicKey);
  const newEvmOwnerAddress = normalizeHexLike(
    toOptionalTrimmedString((raw as { newEvmOwnerAddress?: unknown }).newEvmOwnerAddress) || '',
  );
  const recoveryDeadlineEpochSecondsRaw = (raw as { recoveryDeadlineEpochSeconds?: unknown })
    .recoveryDeadlineEpochSeconds;
  const recoveryDeadlineEpochSeconds =
    typeof recoveryDeadlineEpochSecondsRaw === 'number'
      ? recoveryDeadlineEpochSecondsRaw
      : Number(recoveryDeadlineEpochSecondsRaw);
  const recoveryEmailPayloadHash = toOptionalTrimmedString(
    (raw as { recoveryEmailPayloadHash?: unknown }).recoveryEmailPayloadHash,
  );
  const verifiedRecoveryPayloadHash = toOptionalTrimmedString(
    (raw as { verifiedRecoveryPayloadHash?: unknown }).verifiedRecoveryPayloadHash,
  );
  const verifiedRecoveryArtifactHash = toOptionalTrimmedString(
    (raw as { verifiedRecoveryArtifactHash?: unknown }).verifiedRecoveryArtifactHash,
  );
  const scope = toOptionalTrimmedString((raw as { scope?: unknown }).scope);
  const metadata = parseMetadata((raw as { metadata?: unknown }).metadata);

  if (version !== 'recovery_session_v1') return null;
  if (
    !sessionId ||
    !userId ||
    !nearAccountId ||
    !status ||
    !newNearPublicKey ||
    !newEvmOwnerAddress ||
    !recoveryEmailPayloadHash
  ) {
    return null;
  }
  if (!Number.isFinite(signerSlot) || signerSlot < 1) return null;
  if (!Number.isFinite(createdAtMs) || createdAtMs <= 0) return null;
  if (!Number.isFinite(updatedAtMs) || updatedAtMs <= 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  if (!Number.isFinite(recoveryDeadlineEpochSeconds) || recoveryDeadlineEpochSeconds <= 0) {
    return null;
  }

  return {
    version: 'recovery_session_v1',
    sessionId,
    userId,
    nearAccountId,
    signerSlot: Math.floor(signerSlot),
    status,
    createdAtMs: Math.floor(createdAtMs),
    updatedAtMs: Math.floor(updatedAtMs),
    expiresAtMs: Math.floor(expiresAtMs),
    newNearPublicKey,
    newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: Math.floor(recoveryDeadlineEpochSeconds),
    recoveryEmailPayloadHash,
    ...(verifiedRecoveryPayloadHash ? { verifiedRecoveryPayloadHash } : {}),
    ...(verifiedRecoveryArtifactHash ? { verifiedRecoveryArtifactHash } : {}),
    ...(scope ? { scope } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

class InMemoryRecoverySessionStore implements RecoverySessionStore {
  private readonly map = new Map<string, RecoverySessionRecord>();

  async get(sessionId: string): Promise<RecoverySessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const parsed = parseRecoverySessionRecord(this.map.get(id));
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: RecoverySessionRecord): Promise<void> {
    const parsed = parseRecoverySessionRecord(record);
    if (!parsed) throw new Error('Invalid recovery session record');
    this.map.set(parsed.sessionId, parsed);
  }

  async listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const out: RecoverySessionRecord[] = [];
    for (const value of this.map.values()) {
      const parsed = parseRecoverySessionRecord(value);
      if (!parsed || parsed.nearAccountId !== accountId) continue;
      out.push(parsed);
    }
    out.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
    return out;
  }
}

class PostgresRecoverySessionStore implements RecoverySessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  async get(sessionId: string): Promise<RecoverySessionRecord | null> {
    const id = toOptionalTrimmedString(sessionId);
    if (!id) return null;
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_sessions
        WHERE namespace = $1 AND session_id = $2
      `,
      [this.namespace, id],
    );
    const parsed = parseRecoverySessionRecord((rows[0] as { record_json?: unknown } | undefined)?.record_json);
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) return null;
    return parsed;
  }

  async put(record: RecoverySessionRecord): Promise<void> {
    const parsed = parseRecoverySessionRecord(record);
    if (!parsed) throw new Error('Invalid recovery session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO recovery_sessions (
          namespace,
          session_id,
          near_account_id,
          record_json,
          expires_at_ms,
          created_at_ms,
          updated_at_ms
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (namespace, session_id)
        DO UPDATE SET
          near_account_id = EXCLUDED.near_account_id,
          record_json = EXCLUDED.record_json,
          expires_at_ms = EXCLUDED.expires_at_ms,
          updated_at_ms = EXCLUDED.updated_at_ms
      `,
      [
        this.namespace,
        parsed.sessionId,
        parsed.nearAccountId,
        parsed,
        parsed.expiresAtMs,
        parsed.createdAtMs,
        parsed.updatedAtMs,
      ],
    );
  }

  async listByNearAccountId(nearAccountId: string): Promise<RecoverySessionRecord[]> {
    const accountId = toOptionalTrimmedString(nearAccountId);
    if (!accountId) return [];
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT record_json
        FROM recovery_sessions
        WHERE namespace = $1 AND near_account_id = $2
        ORDER BY updated_at_ms DESC
      `,
      [this.namespace, accountId],
    );
    return rows
      .map((row) => parseRecoverySessionRecord((row as { record_json?: unknown }).record_json))
      .filter(Boolean) as RecoverySessionRecord[];
  }
}

export function createRecoverySessionStore(input: {
  config?: Record<string, unknown> | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): RecoverySessionStore {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const postgresUrl = getPostgresUrlFromConfig(config);
  const namespace =
    toOptionalTrimmedString(config.RECOVERY_SESSION_NAMESPACE) ||
    toOptionalTrimmedString(config.THRESHOLD_PREFIX) ||
    '';

  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[recovery-sessions] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[recovery-sessions] Using Postgres store for recovery sessions');
    return new PostgresRecoverySessionStore({ postgresUrl, namespace });
  }

  input.logger.info('[recovery-sessions] Using in-memory store for recovery sessions');
  return new InMemoryRecoverySessionStore();
}
