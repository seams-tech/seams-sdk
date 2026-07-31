import { expect, test } from '@playwright/test';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

function passkeyStatusFixture() {
  const record = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('expected exact Ed25519 runtime fixture');
  return {
    runtime,
    authorization: buildPasskeyEd25519AuthorizationProjectionFixture(record),
  };
}

test('reads active Ed25519 status from exact runtime and active authorization', async () => {
  const fixture = passkeyStatusFixture();
  const reader = createWarmSessionStatusReader({
    touchConfirm: {
      getWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 2,
        expiresAtMs: fixture.runtime.expiresAtMs,
      }),
    },
    getEmailOtpWarmSessionStatus: async () => ({
      ok: false,
      code: 'not_found',
      message: 'unused',
    }),
  });

  await expect(
    reader.getEd25519SigningSessionStatus({
      ...fixture,
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({
    sessionId: fixture.runtime.thresholdSessionId,
    status: 'active',
    authMethod: 'passkey',
    remainingUses: 2,
  });
});

test('rejects missing Ed25519 authorization before reading worker state', async () => {
  const fixture = passkeyStatusFixture();
  let statusReads = 0;
  const reader = createWarmSessionStatusReader({
    touchConfirm: {
      getWarmSessionStatus: async () => {
        statusReads += 1;
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: fixture.runtime.expiresAtMs,
        };
      },
    },
    getEmailOtpWarmSessionStatus: async () => ({
      ok: false,
      code: 'not_found',
      message: 'unused',
    }),
  });

  await expect(
    reader.getEd25519SigningSessionStatus({
      runtime: fixture.runtime,
      authorization: null,
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({
    status: 'unavailable',
    statusCode: 'auth_missing',
    authMethod: 'passkey',
  });
  expect(statusReads).toBe(0);
});

test('preserves expiry precedence and falls back to sealed allowance on worker absence', async () => {
  const fixture = passkeyStatusFixture();
  const reader = createWarmSessionStatusReader({
    touchConfirm: {
      getWarmSessionStatus: async () => ({
        ok: false,
        code: 'not_found',
        message: 'missing',
      }),
    },
    getEmailOtpWarmSessionStatus: async () => ({
      ok: false,
      code: 'not_found',
      message: 'unused',
    }),
  });

  await expect(
    reader.getEd25519SigningSessionStatus({
      ...fixture,
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({
    status: 'active',
    remainingUses: fixture.runtime.remainingUses,
    expiresAtMs: fixture.runtime.expiresAtMs,
  });
  await expect(
    reader.getEd25519SigningSessionStatus({
      ...fixture,
      nowMs: fixture.runtime.expiresAtMs,
    }),
  ).resolves.toMatchObject({
    status: 'expired',
  });
});
