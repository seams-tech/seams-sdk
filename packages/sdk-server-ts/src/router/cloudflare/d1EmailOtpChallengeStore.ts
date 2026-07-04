import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpUnlockChallengeRecord,
} from '../../core/EmailOtpStores';
import type { D1DatabaseLike, D1PreparedStatementLike } from '../../storage/tenantRoute';
import { parseD1NonNegativeCount } from './d1RouterApiAuthBoundary';
import {
  emailOtpChallengeContextValues,
  emailOtpChallengeWithAttemptCount,
  parseEmailOtpChallengeRow,
  parseEmailOtpUnlockChallengeRow,
  type D1EmailOtpChallengeRow,
  type D1EmailOtpUnlockChallengeRow,
  type EmailOtpChallengeIssueAction,
} from './d1EmailOtpRecords';

export type EmailOtpChallengeContextInput = {
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly sessionHash: string;
  readonly appSessionVersion: string;
  readonly action: EmailOtpChallengeIssueAction;
  readonly operation: EmailOtpChallengeOperation;
  readonly nowMs: number;
};

export class CloudflareD1EmailOtpChallengeStore {
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

  async pruneExpired(nowMs: number): Promise<string[]> {
    const result = await this.prepare(
      `DELETE FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND expires_at_ms <= ?
      RETURNING challenge_id`,
      [nowMs],
    ).all<D1EmailOtpChallengeRow>();
    const challengeIds: string[] = [];
    for (const row of result.results || []) {
      const challengeId = typeof row.challenge_id === 'string' ? row.challenge_id.trim() : '';
      if (challengeId) challengeIds.push(challengeId);
    }
    return challengeIds;
  }

  async read(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
        LIMIT 1`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  async readLatestActiveForSubjectWallet(input: {
    readonly challengeSubjectId: string;
    readonly walletId: string;
    readonly nowMs: number;
  }): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND expires_at_ms > ?
        ORDER BY created_at_ms DESC
        LIMIT 1`,
      [input.challengeSubjectId, input.walletId, input.nowMs],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  async findLatestActive(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?
        ORDER BY created_at_ms DESC
        LIMIT 1`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  async deleteActiveOverflow(
    input: EmailOtpChallengeContextInput & {
      readonly maxActiveChallenges: number;
    },
  ): Promise<EmailOtpChallengeRecord[]> {
    const deletedRecords: EmailOtpChallengeRecord[] = [];
    let count = await this.countActive(input);
    while (count >= input.maxActiveChallenges) {
      const deleted = await this.deleteOldestActive(input);
      if (!deleted) return deletedRecords;
      deletedRecords.push(deleted);
      count -= 1;
    }
    return deletedRecords;
  }

  async put(record: EmailOtpChallengeRecord): Promise<void> {
    await this.prepare(
      `INSERT INTO email_otp_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        challenge_subject_id,
        wallet_id,
        record_org_id,
        otp_channel,
        session_hash,
        app_session_version,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.challengeSubjectId,
        record.walletId,
        record.orgId || '',
        EMAIL_OTP_CHANNEL,
        record.sessionHash,
        record.appSessionVersion,
        record.action,
        record.operation,
        record.otpCode,
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  async updateAttemptCount(record: EmailOtpChallengeRecord, attemptCount: number): Promise<void> {
    const next = emailOtpChallengeWithAttemptCount(record, attemptCount);
    await this.prepare(
      `UPDATE email_otp_challenges
          SET record_json = ?,
              otp_code = ?,
              expires_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [JSON.stringify(next), next.otpCode, next.expiresAtMs, next.challengeId],
    ).run();
  }

  async delete(challengeId: string): Promise<void> {
    await this.prepare(
      `DELETE FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?`,
      [challengeId],
    ).run();
  }

  async consume(challengeId: string): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.prepare(
      `DELETE FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  async putUnlock(record: EmailOtpUnlockChallengeRecord): Promise<void> {
    await this.prepare(
      `INSERT INTO email_otp_unlock_challenges (
        namespace,
        org_id,
        project_id,
        env_id,
        challenge_id,
        wallet_id,
        user_id,
        record_org_id,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.walletId,
        record.userId,
        record.orgId || '',
        JSON.stringify(record),
        record.createdAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  async consumeUnlock(challengeId: string): Promise<EmailOtpUnlockChallengeRecord | null> {
    const row = await this.prepare(
      `DELETE FROM email_otp_unlock_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_id = ?
      RETURNING record_json, expires_at_ms`,
      [challengeId],
    ).first<D1EmailOtpUnlockChallengeRow>();
    return parseEmailOtpUnlockChallengeRow(row);
  }

  private async countActive(input: EmailOtpChallengeContextInput): Promise<number> {
    const row = await this.prepare(
      `SELECT COUNT(*) AS subject_count
         FROM email_otp_challenges
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND challenge_subject_id = ?
          AND wallet_id = ?
          AND record_org_id = ?
          AND otp_channel = ?
          AND session_hash = ?
          AND app_session_version = ?
          AND action = ?
          AND operation = ?
          AND expires_at_ms > ?`,
      [...emailOtpChallengeContextValues(input), input.nowMs],
    ).first<{ readonly subject_count?: unknown }>();
    return parseD1NonNegativeCount(row?.subject_count);
  }

  private async deleteOldestActive(
    input: EmailOtpChallengeContextInput,
  ): Promise<EmailOtpChallengeRecord | null> {
    const row = await this.database
      .prepare(
        `DELETE FROM email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND challenge_id = (
              SELECT challenge_id
                FROM email_otp_challenges
               WHERE namespace = ?
                 AND org_id = ?
                 AND project_id = ?
                 AND env_id = ?
                 AND challenge_subject_id = ?
                 AND wallet_id = ?
                 AND record_org_id = ?
                 AND otp_channel = ?
                 AND session_hash = ?
                 AND app_session_version = ?
                 AND action = ?
                 AND operation = ?
                 AND expires_at_ms > ?
               ORDER BY created_at_ms ASC
               LIMIT 1
            )
        RETURNING record_json, expires_at_ms`,
      )
      .bind(
        ...this.scopeValues([]),
        ...this.scopeValues([...emailOtpChallengeContextValues(input), input.nowMs]),
      )
      .first<D1EmailOtpChallengeRow>();
    return parseEmailOtpChallengeRow(row);
  }

  private prepare(sql: string, values: readonly unknown[]): D1PreparedStatementLike {
    return this.database.prepare(sql).bind(...this.scopeValues(values));
  }

  private scopeValues(values: readonly unknown[]): readonly unknown[] {
    return [this.namespace, this.orgId, this.projectId, this.envId, ...values];
  }
}
