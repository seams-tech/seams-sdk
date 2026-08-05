import type { D1PreparedStatementLike } from '../../storage/tenantRoute';
import type { EmailOtpRateLimitPolicy } from './d1RouterApiAuthConfig';
import {
  emailOtpRateLimitExceeded,
  emailOtpRateLimitKeys,
  type D1EmailOtpRateLimitRow,
  type EmailOtpRateLimitScope,
} from './d1EmailOtpRecords';

type ScopedD1Prepare = (sql: string, values: readonly unknown[]) => D1PreparedStatementLike;

type EmailOtpRateLimitPolicies = {
  readonly [K in EmailOtpRateLimitScope]: EmailOtpRateLimitPolicy;
};

export type EmailOtpRateLimitConsumeInput = {
  readonly scope: EmailOtpRateLimitScope;
  readonly action?: string;
  readonly userId?: string;
  readonly walletId?: string;
  readonly providerSubject?: string;
  readonly orgId?: string;
  readonly clientIp?: string;
};

export type EmailOtpRateLimitConsumeResult =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly code: 'rate_limited';
      readonly message: string;
      readonly retryAfterMs?: number;
      readonly resetAtMs?: number;
    };

export class CloudflareD1EmailOtpRateLimitStore {
  private readonly prepare: ScopedD1Prepare;
  private readonly rateLimits: EmailOtpRateLimitPolicies;

  constructor(input: {
    readonly prepare: ScopedD1Prepare;
    readonly rateLimits: EmailOtpRateLimitPolicies;
  }) {
    this.prepare = input.prepare;
    this.rateLimits = input.rateLimits;
  }

  async consume(input: EmailOtpRateLimitConsumeInput): Promise<EmailOtpRateLimitConsumeResult> {
    const policy = this.rateLimits[input.scope];
    const keys = emailOtpRateLimitKeys({ ...input, policy });
    for (const key of keys) {
      const consumed = await this.consumeKey({
        key,
        policy,
        nowMs: Date.now(),
      });
      if (!consumed.ok) return consumed;
    }
    return { ok: true };
  }

  private async consumeKey(input: {
    readonly key: string;
    readonly policy: EmailOtpRateLimitPolicy;
    readonly nowMs: number;
  }): Promise<EmailOtpRateLimitConsumeResult> {
    const resetAtMs = input.nowMs + input.policy.windowMs;
    const row = await this.prepare(
      `INSERT INTO email_otp_rate_limits (
        namespace,
        org_id,
        project_id,
        env_id,
        rate_key,
        consumed_count,
        reset_at_ms,
        updated_at_ms
      )
      VALUES (?, ?, ?, ?, ?, 1, ?, ?)
      ON CONFLICT (namespace, org_id, project_id, env_id, rate_key)
      DO UPDATE SET
        consumed_count = CASE
          WHEN email_otp_rate_limits.reset_at_ms <= ?
            THEN 1
          ELSE email_otp_rate_limits.consumed_count + 1
        END,
        reset_at_ms = CASE
          WHEN email_otp_rate_limits.reset_at_ms <= ?
            THEN ?
          ELSE email_otp_rate_limits.reset_at_ms
        END,
        updated_at_ms = ?
      WHERE email_otp_rate_limits.reset_at_ms <= ?
         OR email_otp_rate_limits.consumed_count < ?
      RETURNING consumed_count, reset_at_ms`,
      [
        input.key,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.nowMs,
        resetAtMs,
        input.nowMs,
        input.nowMs,
        input.policy.limit,
      ],
    ).first<D1EmailOtpRateLimitRow>();
    if (row) return { ok: true };
    const existing = await this.prepare(
      `SELECT consumed_count, reset_at_ms
         FROM email_otp_rate_limits
        WHERE namespace = ?
          AND org_id = ?
          AND project_id = ?
          AND env_id = ?
          AND rate_key = ?
        LIMIT 1`,
      [input.key],
    ).first<D1EmailOtpRateLimitRow>();
    return emailOtpRateLimitExceeded(existing);
  }
}
