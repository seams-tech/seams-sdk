import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import type {
  EmailOtpChallengeOperation,
  EmailOtpChallengeRecord,
  EmailOtpUnlockChallengeRecord,
} from '../../../../core/EmailOtpStores';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
  D1ResultLike,
} from '../../../../storage/tenantRoute';
import { parseD1NonNegativeCount } from '../auth/d1RouterApiAuthBoundary';
import {
  emailOtpChallengeContextValues,
  emailOtpChallengeWithAttemptCount,
  parseEmailOtpChallengeRow,
  parseEmailOtpRegistrationVerificationReceiptV1,
  parseEmailOtpUnlockChallengeRow,
  type D1EmailOtpChallengeRow,
  type D1EmailOtpUnlockChallengeRow,
  type EmailOtpRegistrationVerificationReceiptV1,
  type EmailOtpChallengeIssueAction,
} from './d1EmailOtpRecords';

const REGISTRATION_VERIFICATION_RECEIPT_SCOPE = 'email-otp-registration-verification-v1';
const REGISTRATION_CEREMONY_CAS_GUARD_SQL = `INSERT INTO registration_ceremony_cas_guard (guard_id)
SELECT 1
 WHERE changes() = 0`;

type D1EmailOtpRegistrationVerificationReceiptRow = {
  readonly version?: unknown;
  readonly record_json?: unknown;
  readonly expires_at_ms?: unknown;
};

export type EmailOtpRegistrationVerificationReceiptConsumeResult =
  | { readonly kind: 'stored'; readonly receipt: EmailOtpRegistrationVerificationReceiptV1 }
  | { readonly kind: 'exact_replay'; readonly receipt: EmailOtpRegistrationVerificationReceiptV1 }
  | { readonly kind: 'conflict' }
  | { readonly kind: 'challenge_missing' };

export type EmailOtpChallengeContextInput = {
  readonly challengeSubjectId: string;
  readonly walletId: string;
  readonly orgId: string;
  readonly ownerProofBindingDigest: string;
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
          AND owner_proof_binding_digest = ?
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
        owner_proof_binding_digest,
        action,
        operation,
        otp_code,
        record_json,
        created_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.challengeId,
        record.challengeSubjectId,
        record.walletId,
        record.orgId || '',
        EMAIL_OTP_CHANNEL,
        record.ownerProofBindingDigest,
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

  async readRegistrationVerificationReceipt(
    challengeId: string,
    nowMs: number,
  ): Promise<EmailOtpRegistrationVerificationReceiptV1 | null> {
    const row = await this.database
      .prepare(
        `SELECT version, record_json, expires_at_ms
           FROM registration_ceremony_records
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND record_scope = ?5
            AND record_id = ?6
          LIMIT 1`,
      )
      .bind(
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        REGISTRATION_VERIFICATION_RECEIPT_SCOPE,
        challengeId,
      )
      .first<D1EmailOtpRegistrationVerificationReceiptRow>();
    if (!row) return null;
    const version = Number(row.version);
    const expiresAtMs = Number(row.expires_at_ms);
    if (!Number.isSafeInteger(version) || version !== 1 || !Number.isSafeInteger(expiresAtMs)) {
      throw new Error('Stored Email OTP registration verification receipt envelope is invalid');
    }
    if (expiresAtMs <= nowMs) {
      await this.database
        .prepare(
          `DELETE FROM registration_ceremony_records
            WHERE namespace = ?1
              AND org_id = ?2
              AND project_id = ?3
              AND env_id = ?4
              AND record_scope = ?5
              AND record_id = ?6
              AND version = ?7`,
        )
        .bind(
          this.namespace,
          this.orgId,
          this.projectId,
          this.envId,
          REGISTRATION_VERIFICATION_RECEIPT_SCOPE,
          challengeId,
          version,
        )
        .run();
      return null;
    }
    if (typeof row.record_json !== 'string') {
      throw new Error('Stored Email OTP registration verification receipt JSON is invalid');
    }
    let raw: unknown;
    try {
      raw = JSON.parse(row.record_json) as unknown;
    } catch {
      throw new Error('Stored Email OTP registration verification receipt JSON is malformed');
    }
    const receipt = parseEmailOtpRegistrationVerificationReceiptV1(raw);
    if (!receipt || receipt.expiresAtMs !== expiresAtMs) {
      throw new Error('Stored Email OTP registration verification receipt is invalid');
    }
    return receipt;
  }

  async consumeRegistrationWithReceipt(input: {
    readonly challenge: EmailOtpChallengeRecord;
    readonly receipt: EmailOtpRegistrationVerificationReceiptV1;
  }): Promise<EmailOtpRegistrationVerificationReceiptConsumeResult> {
    requireReceiptMatchesChallenge(input);
    const existing = await this.readRegistrationVerificationReceipt(
      input.challenge.challengeId,
      input.receipt.verifiedAtMs,
    );
    if (existing) return registrationVerificationReceiptDisposition(existing, input.receipt);
    const receiptJson = JSON.stringify(input.receipt);
    const challengeJson = JSON.stringify(input.challenge);
    const insertReceipt = this.database
      .prepare(
        `INSERT OR IGNORE INTO registration_ceremony_records (
           namespace, org_id, project_id, env_id, record_scope, record_id,
           version, record_json, expires_at_ms, updated_at_ms
         )
         SELECT ?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8, ?9
           FROM email_otp_challenges
          WHERE namespace = ?10
            AND org_id = ?11
            AND project_id = ?12
            AND env_id = ?13
            AND challenge_id = ?14
            AND record_json = ?15
            AND otp_code = ?16
            AND expires_at_ms > ?17`,
      )
      .bind(
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        REGISTRATION_VERIFICATION_RECEIPT_SCOPE,
        input.challenge.challengeId,
        receiptJson,
        input.receipt.expiresAtMs,
        input.receipt.verifiedAtMs,
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        input.challenge.challengeId,
        challengeJson,
        input.challenge.otpCode,
        input.receipt.verifiedAtMs,
      );
    const deleteChallenge = this.database
      .prepare(
        `DELETE FROM email_otp_challenges
          WHERE namespace = ?1
            AND org_id = ?2
            AND project_id = ?3
            AND env_id = ?4
            AND challenge_id = ?5
            AND record_json = ?6
            AND otp_code = ?7
            AND expires_at_ms > ?8`,
      )
      .bind(
        this.namespace,
        this.orgId,
        this.projectId,
        this.envId,
        input.challenge.challengeId,
        challengeJson,
        input.challenge.otpCode,
        input.receipt.verifiedAtMs,
      );
    const statements = [
      insertReceipt,
      this.database.prepare(REGISTRATION_CEREMONY_CAS_GUARD_SQL),
      deleteChallenge,
      this.database.prepare(REGISTRATION_CEREMONY_CAS_GUARD_SQL),
    ];
    try {
      const results = await this.database.batch<D1ResultLike>(statements);
      if (results.length !== statements.length || results.some((result) => !result.success)) {
        throw new Error('Email OTP registration verification batch returned an invalid result');
      }
      return { kind: 'stored', receipt: input.receipt };
    } catch (error: unknown) {
      const reconciled = await this.readRegistrationVerificationReceipt(
        input.challenge.challengeId,
        input.receipt.verifiedAtMs,
      );
      if (reconciled) return registrationVerificationReceiptDisposition(reconciled, input.receipt);
      if (!(await this.read(input.challenge.challengeId))) return { kind: 'challenge_missing' };
      throw error;
    }
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
          AND owner_proof_binding_digest = ?
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
                 AND owner_proof_binding_digest = ?
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

function requireReceiptMatchesChallenge(input: {
  readonly challenge: EmailOtpChallengeRecord;
  readonly receipt: EmailOtpRegistrationVerificationReceiptV1;
}): void {
  const verified = input.receipt.verified;
  if (
    verified.challengeId !== input.challenge.challengeId ||
    verified.challengeSubjectId !== input.challenge.challengeSubjectId ||
    verified.walletId !== input.challenge.walletId ||
    verified.orgId !== input.challenge.orgId ||
    verified.email !== input.challenge.email ||
    verified.otpChannel !== input.challenge.otpChannel ||
    input.receipt.expiresAtMs <= input.receipt.verifiedAtMs
  ) {
    throw new Error('Email OTP registration verification receipt does not match its challenge');
  }
}

function registrationVerificationReceiptDisposition(
  stored: EmailOtpRegistrationVerificationReceiptV1,
  expected: EmailOtpRegistrationVerificationReceiptV1,
): EmailOtpRegistrationVerificationReceiptConsumeResult {
  if (
    stored.requestFingerprint === expected.requestFingerprint &&
    stored.expiresAtMs === expected.expiresAtMs &&
    JSON.stringify(stored.verified) === JSON.stringify(expected.verified)
  ) {
    return { kind: 'exact_replay', receipt: stored };
  }
  return { kind: 'conflict' };
}
