import type {
  EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../core/EmailOtpStores';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import {
  consumedEmailOtpRecoveryEscrowRecord,
  emailOtpRecoveryEscrowMatchesEnrollment,
  parseEmailOtpRecoveryEscrowRow,
  type D1EmailOtpRecoveryEscrowRow,
} from './d1EmailOtpRecords';

export class CloudflareD1EmailOtpRecoveryEscrowStore {
  private readonly database: D1DatabaseLike;
  private readonly namespace: string;
  private readonly orgId: string;
  private readonly projectId: string;
  private readonly envId: string;

  constructor(input: {
    readonly database: D1DatabaseLike;
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  }) {
    this.database = input.database;
    this.namespace = input.namespace;
    this.orgId = input.orgId;
    this.projectId = input.projectId;
    this.envId = input.envId;
  }

  async listForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]> {
    const result = await this.prepare(
      `SELECT record_json, updated_at_ms
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        ORDER BY issued_at_ms ASC, recovery_key_id ASC`,
      [enrollment.walletId],
    ).all<D1EmailOtpRecoveryEscrowRow>();
    const records: EmailOtpRecoveryWrappedEnrollmentEscrowRecord[] = [];
    for (const row of result.results || []) {
      const escrow = parseEmailOtpRecoveryEscrowRow(row);
      if (!escrow) continue;
      if (!emailOtpRecoveryEscrowMatchesEnrollment({ escrow, enrollment })) continue;
      records.push(escrow);
    }
    return records;
  }

  async read(input: {
    readonly walletId: string;
    readonly recoveryKeyId: string;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, updated_at_ms
         FROM email_otp_recovery_wrapped_enrollment_escrows
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND recovery_key_id = ?
        LIMIT 1`,
      [input.walletId, input.recoveryKeyId],
    ).first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  async consume(input: {
    readonly record: Extract<
      EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
      { readonly recoveryKeyStatus: 'active' }
    >;
    readonly consumedAtMs: number;
  }): Promise<EmailOtpRecoveryWrappedEnrollmentEscrowRecord | null> {
    const consumedRecord = consumedEmailOtpRecoveryEscrowRecord(input);
    const row = await this.database
      .prepare(
        `UPDATE email_otp_recovery_wrapped_enrollment_escrows
            SET recovery_key_status = ?,
                record_json = ?,
                updated_at_ms = ?
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
            AND recovery_key_status = 'active'
        RETURNING record_json, updated_at_ms`,
      )
      .bind(
        consumedRecord.recoveryKeyStatus,
        JSON.stringify(consumedRecord),
        consumedRecord.updatedAtMs,
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        consumedRecord.walletId,
        consumedRecord.recoveryKeyId,
      )
      .first<D1EmailOtpRecoveryEscrowRow>();
    return parseEmailOtpRecoveryEscrowRow(row);
  }

  async putMany(records: readonly EmailOtpRecoveryWrappedEnrollmentEscrowRecord[]): Promise<void> {
    if (records.length === 0) return;
    const statements: D1PreparedStatementLike[] = [];
    for (const record of records) {
      statements.push(this.putStatement(record));
    }
    await this.database.batch(statements);
  }

  private putStatement(
    record: EmailOtpRecoveryWrappedEnrollmentEscrowRecord,
  ): D1PreparedStatementLike {
    return this.prepare(
      `INSERT INTO email_otp_recovery_wrapped_enrollment_escrows (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        recovery_key_id,
        recovery_key_status,
        record_json,
        issued_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id, recovery_key_id)
      DO UPDATE SET
        recovery_key_status = EXCLUDED.recovery_key_status,
        record_json = EXCLUDED.record_json,
        issued_at_ms = EXCLUDED.issued_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.recoveryKeyId,
        record.recoveryKeyStatus,
        JSON.stringify(record),
        record.issuedAtMs,
        record.updatedAtMs,
      ],
    );
  }

  private prepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [this.namespace, this.orgId, this.projectId, this.envId, ...values];
  }
}
