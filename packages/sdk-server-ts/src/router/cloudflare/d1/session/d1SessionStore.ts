import type { RecoveryExecutionRecord } from '../../../../core/RecoveryExecutionStore';
import type { RecoverySessionRecord } from '../../../../core/RecoverySessionStore';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import {
  parseRecoveryExecutionRecord,
  parseRecoverySessionRecord,
  type D1RecoveryExecutionRow,
  type D1RecoverySessionRow,
} from './d1SessionRecords';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

export class CloudflareD1SessionStore {
  private readonly prepare: ScopedD1Prepare;

  constructor(input: { readonly prepare: ScopedD1Prepare }) {
    this.prepare = input.prepare;
  }

  async readRecoverySessionRecord(sessionId: string): Promise<RecoverySessionRecord | null> {
    const row = await this.prepare(
      `SELECT record_json
         FROM recovery_sessions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
        LIMIT 1`,
      [sessionId],
    ).first<D1RecoverySessionRow>();
    const record = parseRecoverySessionRecord(row?.record_json);
    if (!record) return null;
    if (Date.now() > record.expiresAtMs) return null;
    return record;
  }

  async putRecoverySessionRecord(record: RecoverySessionRecord): Promise<void> {
    await this.prepare(
      `INSERT INTO recovery_sessions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        near_account_id,
        record_json,
        expires_at_ms,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, session_id)
      DO UPDATE SET
        near_account_id = EXCLUDED.near_account_id,
        record_json = EXCLUDED.record_json,
        expires_at_ms = EXCLUDED.expires_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.nearAccountId,
        JSON.stringify(record),
        record.expiresAtMs,
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

  async readRecoveryExecutionRecord(input: {
    readonly sessionId: string;
    readonly chainIdKey: string;
    readonly accountAddress: string;
    readonly action: string;
  }): Promise<RecoveryExecutionRecord | null> {
    const row = await this.prepare(
      `SELECT record_json
         FROM recovery_executions
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND session_id = ?
          AND chain_id_key = ?
          AND account_address = ?
          AND action = ?
        LIMIT 1`,
      [input.sessionId, input.chainIdKey, input.accountAddress, input.action],
    ).first<D1RecoveryExecutionRow>();
    return parseRecoveryExecutionRecord(row?.record_json);
  }

  async putRecoveryExecutionRecord(record: RecoveryExecutionRecord): Promise<void> {
    await this.prepare(
      `INSERT INTO recovery_executions (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action,
        status,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (
        namespace,
        org_id,
        project_id,
        env_id,
        session_id,
        chain_id_key,
        account_address,
        action
      )
      DO UPDATE SET
        status = EXCLUDED.status,
        record_json = EXCLUDED.record_json,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.sessionId,
        record.chainIdKey,
        record.accountAddress,
        record.action,
        record.status,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    ).run();
  }

}
