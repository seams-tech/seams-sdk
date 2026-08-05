import type { EmailOtpGrantRecord } from '../../core/EmailOtpStores';
import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import { parseEmailOtpGrantRow, type D1EmailOtpGrantRow } from './d1EmailOtpRecords';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

export class CloudflareD1EmailOtpGrantStore {
  private readonly prepare: ScopedD1Prepare;

  constructor(input: { readonly prepare: ScopedD1Prepare }) {
    this.prepare = input.prepare;
  }

  async put(record: EmailOtpGrantRecord): Promise<void> {
    await this.prepare(
      `INSERT INTO email_otp_grants (
        namespace,
        org_id,
        project_id,
        env_id,
        grant_token,
        user_id,
        wallet_id,
        record_org_id,
        challenge_id,
        action,
        record_json,
        issued_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.grantToken,
        record.userId,
        record.walletId,
        record.orgId || '',
        record.challengeId,
        record.action,
        JSON.stringify(record),
        record.issuedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  async consume(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const row = await this.prepare(
      `DELETE FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
      RETURNING record_json, expires_at_ms`,
      [grantToken],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  async read(grantToken: string): Promise<EmailOtpGrantRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms
         FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?
        LIMIT 1`,
      [grantToken],
    ).first<D1EmailOtpGrantRow>();
    return parseEmailOtpGrantRow(row);
  }

  async delete(grantToken: string): Promise<void> {
    await this.prepare(
      `DELETE FROM email_otp_grants
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND grant_token = ?`,
      [grantToken],
    ).run();
  }
}
