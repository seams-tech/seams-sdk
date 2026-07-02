import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  GoogleEmailOtpRegistrationAttemptRecord,
  NonEmptyGoogleEmailOtpRegistrationOfferCandidates,
  PendingGoogleEmailOtpRegistrationAttemptRecord,
} from '../../core/EmailOtpStores';
import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import { d1MutationChanges } from './d1RouterApiAuthBoundary';
import {
  abandonedGoogleEmailOtpRegistrationAttemptRecord,
  googleEmailOtpRegistrationOfferWalletIdsJson,
  parseGoogleEmailOtpRegistrationAttemptRow,
  pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt,
  registrationAttemptMatchesReplacementScope,
  registrationAttemptMatchesStartedScope,
  runtimePolicyScopeKey,
  type D1EmailOtpRegistrationAttemptRow,
} from './d1GoogleEmailOtpRegistrationRecords';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

export class CloudflareD1GoogleEmailOtpRegistrationAttemptStore {
  private readonly prepare: ScopedD1Prepare;
  private readonly orgId: string;

  constructor(input: { readonly prepare: ScopedD1Prepare; readonly orgId: string }) {
    this.prepare = input.prepare;
    this.orgId = input.orgId;
  }

  async cleanupExpired(nowMs: number): Promise<number> {
    return d1MutationChanges(
      await this.prepare(
        `DELETE FROM email_otp_registration_attempts
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND (expires_at_ms <= ? OR state = 'expired')`,
        [nowMs],
      ).run(),
    );
  }

  async create(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly walletId: string;
    readonly offerId: string;
    readonly offerCandidates: NonEmptyGoogleEmailOtpRegistrationOfferCandidates;
    readonly selectedCandidateId: string;
    readonly appSessionVersion: string;
    readonly authProvider: string;
    readonly walletIdDerivationNonce: string;
    readonly collisionCounter: number;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord> {
    const nowMs = Date.now();
    await this.cleanupExpired(nowMs);
    const attempt: PendingGoogleEmailOtpRegistrationAttemptRecord = {
      version: 'google_email_otp_registration_attempt_v1',
      attemptId: secureRandomBase64Url(18, 'google email otp registration attempt ids'),
      providerSubject: input.providerSubject,
      email: input.email,
      walletId: input.walletId,
      offerId: input.offerId,
      offerCandidates: input.offerCandidates,
      selectedCandidateId: input.selectedCandidateId,
      appSessionVersion: input.appSessionVersion,
      authProvider: input.authProvider,
      accountIdSlugVersion: 'hmac_readable_v1',
      walletIdDerivationNonce: input.walletIdDerivationNonce,
      collisionCounter: input.collisionCounter,
      state: 'started',
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      expiresAtMs: nowMs + 30 * 60_000,
      runtimePolicyScope: input.runtimePolicyScope,
    };
    await this.put(attempt);
    return attempt;
  }

  async findStarted(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
  }): Promise<PendingGoogleEmailOtpRegistrationAttemptRecord | null> {
    const nowMs = Date.now();
    await this.cleanupExpired(nowMs);
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND app_session_version = ?
          AND runtime_org_id = ?
          AND runtime_policy_key = ?
        ORDER BY updated_at_ms DESC
        LIMIT 1`,
      [
        input.providerSubject,
        input.email,
        nowMs,
        input.appSessionVersion,
        input.orgId,
        runtimePolicyScopeKey(input.runtimePolicyScope),
      ],
    ).first<D1EmailOtpRegistrationAttemptRow>();
    const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
    if (!parsed) {
      const malformedAttemptId = toOptionalTrimmedString(row?.attempt_id);
      if (malformedAttemptId) await this.delete(malformedAttemptId);
      return null;
    }
    if (
      !registrationAttemptMatchesStartedScope(parsed, {
        providerSubject: input.providerSubject,
        email: input.email,
        orgId: input.orgId,
        appSessionVersion: input.appSessionVersion,
        runtimePolicyScope: input.runtimePolicyScope,
        nowMs,
      })
    ) {
      return null;
    }
    const refreshed = pendingGoogleEmailOtpRegistrationAttemptWithUpdatedAt(parsed, nowMs);
    await this.put(refreshed);
    return refreshed;
  }

  async abandonStartedExceptAppSession(input: {
    readonly providerSubject: string;
    readonly email: string;
    readonly orgId: string;
    readonly appSessionVersion: string;
    readonly runtimePolicyScope: RuntimePolicyScope;
    readonly nowMs: number;
    readonly failureCode: 'app_session_version_replaced';
  }): Promise<void> {
    const result = await this.prepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND provider_subject = ?
          AND email = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?`,
      [input.providerSubject, input.email, input.nowMs],
    ).all<D1EmailOtpRegistrationAttemptRow>();
    for (const row of result.results || []) {
      const parsed = parseGoogleEmailOtpRegistrationAttemptRow(row);
      if (!parsed) {
        const malformedAttemptId = toOptionalTrimmedString(row.attempt_id);
        if (malformedAttemptId) await this.delete(malformedAttemptId);
        continue;
      }
      if (!registrationAttemptMatchesReplacementScope(parsed, input)) continue;
      await this.put(
        abandonedGoogleEmailOtpRegistrationAttemptRecord({
          record: parsed,
          failureCode: input.failureCode,
          updatedAtMs: input.nowMs,
        }),
      );
    }
  }

  async hasLiveStartedWalletAttempt(input: {
    readonly walletId: string;
    readonly nowMs: number;
  }): Promise<boolean> {
    const row = await this.prepare(
      `SELECT 1 AS found
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND state IN ('started', 'key_finalized')
          AND expires_at_ms > ?
          AND (
            wallet_id = ?
            OR EXISTS (
              SELECT 1
                FROM json_each(offer_wallet_ids_json)
               WHERE value = ?
            )
          )
        LIMIT 1`,
      [input.nowMs, input.walletId, input.walletId],
    ).first<{ readonly found?: unknown }>();
    return Boolean(row);
  }

  async read(attemptId: string): Promise<GoogleEmailOtpRegistrationAttemptRecord | null> {
    const row = await this.prepare(
      `SELECT record_json, expires_at_ms, updated_at_ms, attempt_id
         FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?
        LIMIT 1`,
      [attemptId],
    ).first<D1EmailOtpRegistrationAttemptRow>();
    return parseGoogleEmailOtpRegistrationAttemptRow(row);
  }

  async put(record: GoogleEmailOtpRegistrationAttemptRecord): Promise<void> {
    if (record.runtimePolicyScope?.orgId !== this.orgId) {
      throw new Error('Google Email OTP registration attempt org scope mismatch');
    }
    await this.prepare(
      `INSERT INTO email_otp_registration_attempts (
        namespace,
        org_id,
        project_id,
        env_id,
        attempt_id,
        provider_subject,
        email,
        wallet_id,
        state,
        app_session_version,
        runtime_org_id,
        runtime_policy_key,
        offer_wallet_ids_json,
        record_json,
        created_at_ms,
        updated_at_ms,
        expires_at_ms
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, attempt_id)
      DO UPDATE SET
        provider_subject = EXCLUDED.provider_subject,
        email = EXCLUDED.email,
        wallet_id = EXCLUDED.wallet_id,
        state = EXCLUDED.state,
        app_session_version = EXCLUDED.app_session_version,
        runtime_org_id = EXCLUDED.runtime_org_id,
        runtime_policy_key = EXCLUDED.runtime_policy_key,
        offer_wallet_ids_json = EXCLUDED.offer_wallet_ids_json,
        record_json = EXCLUDED.record_json,
        created_at_ms = EXCLUDED.created_at_ms,
        updated_at_ms = EXCLUDED.updated_at_ms,
        expires_at_ms = EXCLUDED.expires_at_ms`,
      [
        record.attemptId,
        record.providerSubject,
        record.email,
        record.walletId,
        record.state,
        record.appSessionVersion,
        record.runtimePolicyScope?.orgId || '',
        runtimePolicyScopeKey(record.runtimePolicyScope),
        googleEmailOtpRegistrationOfferWalletIdsJson(record.offerCandidates),
        JSON.stringify(record),
        record.createdAtMs,
        record.updatedAtMs,
        record.expiresAtMs,
      ],
    ).run();
  }

  async delete(attemptId: string): Promise<void> {
    await this.prepare(
      `DELETE FROM email_otp_registration_attempts
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND attempt_id = ?`,
      [attemptId],
    ).run();
  }
}
