import { expect, test } from '@playwright/test';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const REPO_ROOT = new URL('../..', import.meta.url).pathname;
const FORBIDDEN_COMPAT_TERMS =
  /\b(backfill|backfilled|backfilling|fallback|fallbacks|legacy|compatibility|compat|alias|aliases|deprecated|repair|repairs|repaired)\b/i;

function listFiles(path: string): string[] {
  if (!existsSync(path)) return [];
  const stat = statSync(path);
  if (stat.isFile()) return [path];
  if (!stat.isDirectory()) return [];
  return readdirSync(path).flatMap((entry) => listFiles(join(path, entry)));
}

test.describe('Email OTP and signing-session persistence no compatibility paths guard', () => {
  test('forbids backfill and fallback language in scoped source surfaces', () => {
    const sources = [
      'server/src/router/emailOtpRouteHandlers.ts',
      'server/src/router/emailOtpSessionRouteHelpers.ts',
      'server/src/core/EmailOtpStores.ts',
      'server/src/threshold/session/signingSessionSeal',
      'client/src/core/signingEngine/emailOtp',
      'client/src/core/signingEngine/api/session/signingSessionSealedStore.ts',
      'client/src/core/signingEngine/session/WarmSessionStore.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts',
      'client/src/core/signingEngine/workerManager/workers/email-otp',
    ].flatMap((path) => listFiles(join(REPO_ROOT, path)));

    const violations = sources
      .filter((path) => /\.(ts|tsx)$/.test(path))
      .filter((path) => FORBIDDEN_COMPAT_TERMS.test(readFileSync(path, 'utf8')))
      .map((path) => relative(REPO_ROOT, path));

    expect(violations).toEqual([]);
  });

  test('forbids AuthService Email OTP identity repair and seal key defaults', () => {
    const authService = readFileSync(join(REPO_ROOT, 'server/src/core/AuthService.ts'), 'utf8');

    expect(authService).not.toContain('shouldBackfill');
    expect(authService).not.toContain('backfillVerifiedEmail');
    expect(authService).not.toContain('verifiedChallengeEmail');
    expect(authService).not.toContain('existingEnrollmentEmail');
    expect(authService).not.toContain("SIGNING_SESSION_SEAL_KEY_VERSION') ||");
    expect(authService).not.toContain('"SIGNING_SESSION_SEAL_KEY_VERSION") ||');
    expect(authService).not.toContain("'kek-s-2026-02'");
    expect(authService).not.toContain('"kek-s-2026-02"');
    expect(authService).not.toContain("this.readEmailOtpConfigValue('UPSTASH_REDIS_REST_URL')");
    expect(authService).not.toContain("this.readEmailOtpConfigValue('UPSTASH_REDIS_REST_TOKEN')");
    expect(authService).not.toContain("this.readEmailOtpConfigValue('REDIS_URL')");
    expect(authService).not.toContain('useSharedBackendConfig');
    expect(authService).not.toContain('challengeFallback');
    expect(authService).not.toContain('verifyFallback');
    expect(authService).not.toContain('grantFallback');
    const emailOtpConfigAndSealSlice = authService.slice(
      authService.indexOf('  private getEmailOtpRateLimiter()'),
      authService.indexOf('  private async deliverEmailOtpCode('),
    );
    expect(FORBIDDEN_COMPAT_TERMS.test(emailOtpConfigAndSealSlice)).toBe(false);
  });

  test('normal Email OTP login requires device-local enc_s(S)', () => {
    const workerSource = readFileSync(
      join(REPO_ROOT, 'client/src/core/signingEngine/workerManager/workers/email-otp.worker.ts'),
      'utf8',
    );
    const loginSlice = workerSource.slice(
      workerSource.indexOf('async function loginWithEmailOtpAndRecoverClientRootShare'),
      workerSource.indexOf('async function loginWithEmailOtpAndBootstrapEcdsaSession'),
    );

    expect(loginSlice).toContain('readEmailOtpDeviceEnrollmentEscrowRecord');
    expect(loginSlice).toContain('Email OTP device-local enc_s(S) is missing');
    expect(loginSlice).toContain('localEnrollmentEscrow.encSB64u');
    expect(loginSlice).not.toContain('verified.enrollmentEscrowCiphertextB64u');
  });
});
