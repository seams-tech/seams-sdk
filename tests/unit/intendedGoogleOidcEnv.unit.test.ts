import { expect, test } from '@playwright/test';

import {
  defaultGoogleTokenMinimumTtlSeconds,
  describeUsableGoogleIdToken,
  intendedIsolatedCaseMaximumRuntimeSeconds,
  intendedIsolatedGoogleTokenMinimumTtlSeconds,
  resolveGoogleIdToken,
} from '../scripts/intended-google-oidc-env.mjs';

const CLIENT_ID = 'intended-google-client';
const NOW_MS = Date.UTC(2026, 8, 2, 0, 0, 0);

function tokenExpiringIn(ttlSeconds: number): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({ aud: CLIENT_ID, exp: Math.floor(NOW_MS / 1000) + ttlSeconds }),
  ).toString('base64url');
  return `${header}.${payload}.signature`;
}

test('isolated cases reserve the harness TTL for the complete case runtime', () => {
  expect(intendedIsolatedGoogleTokenMinimumTtlSeconds).toBe(
    defaultGoogleTokenMinimumTtlSeconds + intendedIsolatedCaseMaximumRuntimeSeconds,
  );

  const tokenThatOnlyPassesTheHarnessPreflight = tokenExpiringIn(
    defaultGoogleTokenMinimumTtlSeconds + 60,
  );
  expect(
    describeUsableGoogleIdToken({
      token: tokenThatOnlyPassesTheHarnessPreflight,
      clientId: CLIENT_ID,
      minimumTtlSeconds: intendedIsolatedGoogleTokenMinimumTtlSeconds,
      nowMs: NOW_MS,
    }),
  ).toMatchObject({ status: 'unusable', reason: 'expired or near expiry' });
});

test('later-expiring file token replaces a usable inherited token for an isolated case', () => {
  const staleInheritedToken = tokenExpiringIn(intendedIsolatedGoogleTokenMinimumTtlSeconds + 60);
  const freshFileToken = tokenExpiringIn(intendedIsolatedGoogleTokenMinimumTtlSeconds + 600);

  expect(
    resolveGoogleIdToken({
      processToken: staleInheritedToken,
      fileToken: freshFileToken,
      clientId: CLIENT_ID,
      minimumTtlSeconds: intendedIsolatedGoogleTokenMinimumTtlSeconds,
      nowMs: NOW_MS,
    }),
  ).toBe(freshFileToken);
});

test('isolated cases retain a usable token supplied only by the process environment', () => {
  const processToken = tokenExpiringIn(intendedIsolatedGoogleTokenMinimumTtlSeconds + 600);

  expect(
    resolveGoogleIdToken({
      processToken,
      clientId: CLIENT_ID,
      minimumTtlSeconds: intendedIsolatedGoogleTokenMinimumTtlSeconds,
      nowMs: NOW_MS,
    }),
  ).toBe(processToken);
});
