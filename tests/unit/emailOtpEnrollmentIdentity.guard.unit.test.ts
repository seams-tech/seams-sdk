import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';

const AUTH_SERVICE_SOURCE = new URL('../../server/src/core/AuthService.ts', import.meta.url);
const ROUTE_HANDLERS_SOURCE = new URL(
  '../../server/src/router/emailOtpRouteHandlers.ts',
  import.meta.url,
);

test.describe('Email OTP enrollment identity guard', () => {
  test('login request paths do not repair or infer enrollment email identity', () => {
    const authService = readFileSync(AUTH_SERVICE_SOURCE, 'utf8');
    const routeHandlers = readFileSync(ROUTE_HANDLERS_SOURCE, 'utf8');

    expect(authService).not.toContain('shouldBackfillVerifiedEmail');
    expect(authService).not.toContain('backfillVerifiedEmail');
    expect(authService).not.toMatch(/email:\s*verifiedChallengeEmail/);
    expect(authService).not.toMatch(/existingEnrollmentEmail\s*\|\|\s*email/);

    expect(routeHandlers).not.toContain('appSessionEmail');
    expect(routeHandlers).not.toMatch(/claims\.email[\s\S]{0,300}login\/challenge/);
  });
});
