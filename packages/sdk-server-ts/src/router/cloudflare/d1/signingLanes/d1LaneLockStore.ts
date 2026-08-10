import { d1ChangedRows } from '../../../../storage/d1Sql';
import type { LaneEnrollmentId, WalletKeyId } from '@shared/signing-lanes';
import { parseLaneEnrollmentId, parseWalletKeyId } from '@shared/utils/domainIds';
import type {
  LaneLock,
  LaneLockResult,
  LaneLockStore,
} from '../../../../core/signingLanes/LaneLifecycleStore';
import {
  requireD1LaneStoreOptions,
  scopeValues,
  type CloudflareD1LaneStoreOptions,
} from './d1LaneRecords';

const LOCK_TABLE = 'lane_locks';

export type CloudflareD1LaneLockStoreOptions = CloudflareD1LaneStoreOptions;

export class CloudflareD1LaneLockStore implements LaneLockStore {
  private readonly database: CloudflareD1LaneStoreOptions['database'];
  private readonly scope: CloudflareD1LaneStoreOptions['scope'];

  constructor(options: CloudflareD1LaneLockStoreOptions) {
    const normalized = requireD1LaneStoreOptions(options);
    this.database = normalized.database;
    this.scope = normalized.scope;
  }

  async acquireWalletKeyLock(input: {
    readonly walletKeyId: WalletKeyId;
    readonly lockId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
  }): Promise<LaneLockResult> {
    return await this.acquire({
      lockKey: `wallet-key:${String(input.walletKeyId)}`,
      lockKind: 'wallet_key',
      walletKeyId: input.walletKeyId,
      lockId: input.lockId,
      ttlMs: input.ttlMs,
      nowMs: input.nowMs,
    });
  }

  async acquireEnrollmentLock(input: {
    readonly enrollmentId: LaneEnrollmentId;
    readonly lockId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
  }): Promise<LaneLockResult> {
    return await this.acquire({
      lockKey: `enrollment:${String(input.enrollmentId)}`,
      lockKind: 'enrollment',
      enrollmentId: input.enrollmentId,
      lockId: input.lockId,
      ttlMs: input.ttlMs,
      nowMs: input.nowMs,
    });
  }

  async releaseLock(input: {
    readonly lockKey: string;
    readonly lockId: string;
  }): Promise<boolean> {
    const result = await this.database
      .prepare(
        `DELETE FROM ${LOCK_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND lock_key = ?5 AND lock_id = ?6`,
      )
      .bind(...scopeValues(this.scope), input.lockKey, input.lockId)
      .run();
    return d1ChangedRows(result) === 1;
  }

  private async acquire(input: {
    readonly lockKey: string;
    readonly lockKind: 'wallet_key' | 'enrollment';
    readonly enrollmentId?: LaneEnrollmentId;
    readonly walletKeyId?: WalletKeyId;
    readonly lockId: string;
    readonly ttlMs: number;
    readonly nowMs: number;
  }): Promise<LaneLockResult> {
    if (!input.lockId.trim()) throw new Error('lane lockId is required');
    if (!Number.isSafeInteger(input.ttlMs) || input.ttlMs <= 0)
      throw new Error('lane lock ttlMs must be positive');
    const current = await this.read(input.lockKey);
    if (current && current.expiresAtMs > input.nowMs) {
      return current.lockId === input.lockId
        ? { outcome: 'replayed', lock: current }
        : { outcome: 'conflict', actual: current };
    }
    const expiresAtMs = input.nowMs + input.ttlMs;
    const result = await this.database
      .prepare(
        `INSERT INTO ${LOCK_TABLE} (namespace, org_id, project_id, env_id, lock_key, lock_kind, enrollment_id, wallet_key_id, lane_id, lock_id, expires_at_ms, acquired_at_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11) ON CONFLICT(namespace, org_id, project_id, env_id, lock_key) DO UPDATE SET lock_kind = excluded.lock_kind, enrollment_id = excluded.enrollment_id, wallet_key_id = excluded.wallet_key_id, lock_id = excluded.lock_id, expires_at_ms = excluded.expires_at_ms, acquired_at_ms = excluded.acquired_at_ms WHERE lane_locks.expires_at_ms <= excluded.acquired_at_ms`,
      )
      .bind(
        ...scopeValues(this.scope),
        input.lockKey,
        input.lockKind,
        input.enrollmentId ? String(input.enrollmentId) : null,
        input.walletKeyId ? String(input.walletKeyId) : null,
        input.lockId,
        expiresAtMs,
        input.nowMs,
      )
      .run();
    if (d1ChangedRows(result) !== 1) {
      const raced = await this.read(input.lockKey);
      return raced && raced.lockId === input.lockId
        ? { outcome: 'replayed', lock: raced }
        : { outcome: 'conflict', actual: raced };
    }
    const lock: LaneLock =
      input.lockKind === 'wallet_key'
        ? {
            lockKey: input.lockKey,
            lockKind: 'wallet_key',
            walletKeyId: requireId(parseWalletKeyId, input.walletKeyId, 'wallet key'),
            lockId: input.lockId,
            acquiredAtMs: input.nowMs,
            expiresAtMs,
          }
        : {
            lockKey: input.lockKey,
            lockKind: 'enrollment',
            enrollmentId: requireId(parseLaneEnrollmentId, input.enrollmentId, 'enrollment'),
            lockId: input.lockId,
            acquiredAtMs: input.nowMs,
            expiresAtMs,
          };
    return { outcome: 'applied', lock };
  }

  private async read(lockKey: string): Promise<LaneLock | null> {
    const row = await this.database
      .prepare(
        `SELECT lock_key, lock_kind, enrollment_id, wallet_key_id, lane_id, lock_id, expires_at_ms, acquired_at_ms FROM ${LOCK_TABLE} WHERE namespace = ?1 AND org_id = ?2 AND project_id = ?3 AND env_id = ?4 AND lock_key = ?5`,
      )
      .bind(...scopeValues(this.scope), lockKey)
      .first<{
        readonly lock_key?: unknown;
        readonly lock_kind?: unknown;
        readonly enrollment_id?: unknown;
        readonly wallet_key_id?: unknown;
        readonly lane_id?: unknown;
        readonly lock_id?: unknown;
        readonly expires_at_ms?: unknown;
        readonly acquired_at_ms?: unknown;
      }>();
    if (!row) return null;
    const lockKind =
      row.lock_kind === 'wallet_key' || row.lock_kind === 'enrollment' ? row.lock_kind : null;
    if (!lockKind || typeof row.lock_key !== 'string' || typeof row.lock_id !== 'string')
      throw new Error('stored lane lock is invalid');
    const expiresAtMs = Number(row.expires_at_ms);
    const acquiredAtMs = Number(row.acquired_at_ms);
    if (!Number.isSafeInteger(expiresAtMs) || !Number.isSafeInteger(acquiredAtMs))
      throw new Error('stored lane lock times are invalid');
    if (lockKind === 'wallet_key') {
      if (typeof row.wallet_key_id !== 'string')
        throw new Error('stored wallet-key lock is missing wallet key');
      return {
        lockKey: row.lock_key,
        lockKind,
        walletKeyId: requireId(parseWalletKeyId, row.wallet_key_id, 'stored wallet key'),
        lockId: row.lock_id,
        acquiredAtMs,
        expiresAtMs,
      };
    }
    if (typeof row.enrollment_id !== 'string')
      throw new Error('stored enrollment lock is missing enrollment');
    return {
      lockKey: row.lock_key,
      lockKind,
      enrollmentId: requireId(parseLaneEnrollmentId, row.enrollment_id, 'stored enrollment'),
      lockId: row.lock_id,
      acquiredAtMs,
      expiresAtMs,
    };
  }
}

function requireId<T>(
  parser: (
    raw: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  raw: unknown,
  label: string,
): T {
  const result = parser(raw);
  if (!result.ok) throw new Error(`${label} is invalid: ${result.error.message}`);
  return result.value;
}
