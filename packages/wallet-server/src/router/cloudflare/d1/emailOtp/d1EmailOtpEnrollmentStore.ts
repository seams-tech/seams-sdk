import type {
  EmailOtpAuthStateRecord,
  EmailOtpWalletEnrollmentRecord,
} from '../../../../core/EmailOtpStores';
import type { D1PreparedStatementLike } from '../../../../storage/tenantRoute';
import {
  emailOtpAuthStateRecord,
  parseEmailOtpAuthStateRow,
  parseEmailOtpWalletEnrollmentRow,
  type D1EmailOtpAuthStateRow,
  type D1EmailOtpEnrollmentRow,
  type EmailOtpAuthStatePatch,
} from './d1EmailOtpRecords';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

export type EmailOtpAuthStateReadResult =
  | {
      readonly ok: true;
      readonly state: EmailOtpAuthStateRecord | null;
    }
  | {
      readonly ok: false;
      readonly code: string;
      readonly message: string;
    };

export class CloudflareD1EmailOtpEnrollmentStore {
  private readonly prepare: ScopedD1Prepare;

  constructor(input: { readonly prepare: ScopedD1Prepare }) {
    this.prepare = input.prepare;
  }

  async readEnrollment(walletId: string): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, updated_at_ms
         FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  async readEnrollmentByProviderUserId(input: {
    readonly providerUserId: string;
    readonly orgId: string;
  }): Promise<EmailOtpWalletEnrollmentRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, updated_at_ms
         FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_user_id = ?
          AND record_org_id = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [input.providerUserId, input.orgId],
    ).first<D1EmailOtpEnrollmentRow>();
    return parseEmailOtpWalletEnrollmentRow(row);
  }

  async signerWalletExists(walletId: string): Promise<boolean> {
    const row = await this.prepare(
      `SELECT 1 AS found
         FROM wallets
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<{ readonly found?: unknown }>();
    return Boolean(row);
  }

  async deleteEnrollment(walletId: string): Promise<void> {
    await this.prepareDeleteEnrollmentStatement(walletId).run();
  }

  /**
   * Deletes the shared provider enrollment only once nothing references it.
   *
   * The enrollment is deliberately shared: every Email method on a wallet
   * unwraps through it, and R109D keeps active and pending methods pointing at
   * one row. So revoking a method must not remove it — only the disappearance
   * of its last reference may.
   *
   * The count is a predicate inside the statement rather than a read taken
   * beforehand, so a method activating concurrently cannot lose its enrollment
   * between the check and the delete. Sequenced after the method revocation in
   * the same batch, the revoked method already reads as revoked here.
   */
  prepareDeleteEnrollmentIfUnreferencedStatement(walletId: string): D1PreparedStatementLike {
    return this.prepare(
      `DELETE FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
          AND NOT EXISTS (
            SELECT 1
              FROM wallet_auth_methods
             WHERE wallet_auth_methods.namespace = email_otp_wallet_enrollments.namespace
               AND wallet_auth_methods.org_id = email_otp_wallet_enrollments.org_id
               AND wallet_auth_methods.project_id = email_otp_wallet_enrollments.project_id
               AND wallet_auth_methods.env_id = email_otp_wallet_enrollments.env_id
               AND wallet_auth_methods.wallet_id = email_otp_wallet_enrollments.wallet_id
               AND wallet_auth_methods.kind = 'email_otp'
               AND wallet_auth_methods.status <> 'revoked'
          )`,
      [walletId],
    );
  }

  prepareDeleteEnrollmentStatement(walletId: string): D1PreparedStatementLike {
    return this.prepare(
      `DELETE FROM email_otp_wallet_enrollments
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?`,
      [walletId],
    );
  }

  async putEnrollment(record: EmailOtpWalletEnrollmentRecord): Promise<void> {
    await this.preparePutEnrollmentStatement(record).run();
  }

  preparePutEnrollmentStatement(
    record: EmailOtpWalletEnrollmentRecord,
  ): D1PreparedStatementLike {
    return this.prepare(
      `INSERT INTO email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        verified_email,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        verified_email = EXCLUDED.verified_email,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.providerUserId,
        record.orgId,
        record.verifiedEmail,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    );
  }

  /** Inserts the first enrollment without turning a concurrent winner into an update. */
  prepareInsertEnrollmentStatement(
    record: EmailOtpWalletEnrollmentRecord,
  ): D1PreparedStatementLike {
    return this.prepare(
      `INSERT INTO email_otp_wallet_enrollments (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        verified_email,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        record.walletId,
        record.providerUserId,
        record.orgId,
        record.verifiedEmail,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    );
  }

  async readAuthState(walletId: string): Promise<EmailOtpAuthStateRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, updated_at_ms
         FROM email_otp_auth_states
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND wallet_id = ?
        LIMIT 1`,
      [walletId],
    ).first<D1EmailOtpAuthStateRow>();
    return parseEmailOtpAuthStateRow(row);
  }

  async readAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
  ): Promise<EmailOtpAuthStateReadResult> {
    const state = await this.readAuthState(enrollment.walletId);
    if (!state) return { ok: true, state: null };
    if (state.orgId !== enrollment.orgId || state.providerUserId !== enrollment.providerUserId) {
      return {
        ok: false,
        code: 'auth_state_enrollment_mismatch',
        message: 'Email OTP auth state does not match the active enrollment',
      };
    }
    return { ok: true, state };
  }

  async putAuthStateForEnrollment(
    enrollment: EmailOtpWalletEnrollmentRecord,
    patch: EmailOtpAuthStatePatch,
  ): Promise<EmailOtpAuthStateRecord> {
    const nowMs = Date.now();
    const existing = await this.readAuthState(enrollment.walletId);
    if (
      existing &&
      (existing.orgId !== enrollment.orgId || existing.providerUserId !== enrollment.providerUserId)
    ) {
      throw new Error('Email OTP auth state does not match the active enrollment');
    }
    const next = emailOtpAuthStateRecord({
      enrollment,
      existing,
      updatedAtMs: nowMs,
      patch,
    });
    await this.putAuthState(next);
    return next;
  }

  async resetAuthStateForEnrollment(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly existingState: EmailOtpAuthStateRecord | null;
    readonly updatedAtMs: number;
  }): Promise<EmailOtpAuthStateRecord> {
    const prepared = this.prepareResetAuthStateForEnrollment(input);
    await prepared.statement.run();
    return prepared.record;
  }

  prepareResetAuthStateForEnrollment(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly existingState: EmailOtpAuthStateRecord | null;
    readonly updatedAtMs: number;
  }): {
    readonly record: EmailOtpAuthStateRecord;
    readonly statement: D1PreparedStatementLike;
  } {
    const reusableExisting =
      input.existingState &&
      input.existingState.providerUserId === input.enrollment.providerUserId &&
      input.existingState.orgId === input.enrollment.orgId
        ? input.existingState
        : null;
    const next = emailOtpAuthStateRecord({
      enrollment: input.enrollment,
      existing: reusableExisting,
      updatedAtMs: input.updatedAtMs,
      patch: {
        otpFailureCount: 0,
        lastOtpFailureAtMs: null,
        otpLockedUntilMs: null,
      },
    });
    return {
      record: next,
      statement: this.preparePutAuthStateStatement(next),
    };
  }

  async resetFailureState(input: {
    readonly enrollment: EmailOtpWalletEnrollmentRecord;
    readonly authState: EmailOtpAuthStateRecord | null;
  }): Promise<void> {
    const hasFailureState =
      Number(input.authState?.otpFailureCount || 0) > 0 ||
      input.authState?.lastOtpFailureAtMs != null ||
      input.authState?.otpLockedUntilMs != null;
    if (!hasFailureState) return;
    await this.putAuthStateForEnrollment(input.enrollment, {
      otpFailureCount: 0,
      lastOtpFailureAtMs: null,
      otpLockedUntilMs: null,
    });
  }

  private async putAuthState(record: EmailOtpAuthStateRecord): Promise<void> {
    await this.preparePutAuthStateStatement(record).run();
  }

  private preparePutAuthStateStatement(record: EmailOtpAuthStateRecord): D1PreparedStatementLike {
    return this.prepare(
      `INSERT INTO email_otp_auth_states (
        namespace,
        org_id,
        project_id,
        env_id,
        wallet_id,
        provider_user_id,
        record_org_id,
        record_json,
        created_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, wallet_id)
      DO UPDATE SET
        provider_user_id = EXCLUDED.provider_user_id,
        record_org_id = EXCLUDED.record_org_id,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms`,
      [
        record.walletId,
        record.providerUserId,
        record.orgId,
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
      ],
    );
  }
}
