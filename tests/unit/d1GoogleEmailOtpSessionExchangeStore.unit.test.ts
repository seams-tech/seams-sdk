import { expect, test } from '@playwright/test';
import { CloudflareD1GoogleEmailOtpSessionExchangeStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/session/d1GoogleEmailOtpSessionExchangeStore';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';

const SCOPE = ['session-exchange-test', 'org-a', 'project-a', 'env-a'] as const;

function scopedPrepare(
  database: D1DatabaseLike,
  sql: string,
  values: readonly unknown[],
): D1PreparedStatementLike {
  return database.prepare(sql).bind(...SCOPE, ...values);
}

test('Google Email OTP exchange replays one completed response for the same request', async () => {
  const temporary = createTemporaryD1Database();
  try {
    await applySignerMigrations(temporary.database);
    const prepare = scopedPrepare.bind(undefined, temporary.database);
    const store = new CloudflareD1GoogleEmailOtpSessionExchangeStore({ prepare });
    const nowMs = Date.now() - 1_000;
    const claimed = await store.claimGoogleEmailOtp({
      idempotencyKey: 'google-email-otp-session-exchange:test-1',
      requestFingerprint: 'request-fingerprint-1',
      accountMode: 'login',
      nowMs,
    });
    expect(claimed.kind).toBe('claimed');
    if (claimed.kind !== 'claimed') throw new Error('expected a claimed exchange');

    const checkpoint = await store.checkpoint({
      key: claimed.journal.idempotencyKey,
      expectedVersion: claimed.journal.version,
      phase: 'session_prepared',
      data: { jwt: 'jwt-1', sessionExpiresAtMs: nowMs + 3_600_000 },
    });
    expect(checkpoint.kind).toBe('stored');
    if (checkpoint.kind !== 'stored') throw new Error('expected a stored checkpoint');

    const completed = await store.complete({
      key: checkpoint.journal.idempotencyKey,
      expectedVersion: checkpoint.journal.version,
      response: { status: 200, bodyText: '{"ok":true}', setCookie: 'session=jwt-1' },
      expiresAtMs: nowMs + 900_000,
    });
    expect(completed.kind).toBe('stored');

    const replay = await store.claimGoogleEmailOtp({
      idempotencyKey: 'google-email-otp-session-exchange:test-1',
      requestFingerprint: 'request-fingerprint-1',
      accountMode: 'login',
      nowMs: nowMs + 100,
    });
    expect(replay).toMatchObject({
      kind: 'replayed',
      journal: {
        prepared: claimed.journal.prepared,
        phaseData: { jwt: 'jwt-1', sessionExpiresAtMs: nowMs + 3_600_000 },
        response: { status: 200, bodyText: '{"ok":true}', setCookie: 'session=jwt-1' },
      },
    });

    const conflict = await store.claimGoogleEmailOtp({
      idempotencyKey: 'google-email-otp-session-exchange:test-1',
      requestFingerprint: 'different-request-fingerprint',
      accountMode: 'login',
      nowMs: nowMs + 200,
    });
    expect(conflict.kind).toBe('conflict');
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
