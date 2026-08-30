import { expect, test } from '@playwright/test';
import { createWarmSessionStatusReader } from '@/core/signingEngine/session/warmCapabilities/statusReader';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { buildActiveNearEd25519WalletSessionAuthorization } from '@/core/signingEngine/session/material/nearEd25519YaoSigningPreparation';
import {
  buildEmailOtpExactEd25519AuthorizationFixture,
  buildEmailOtpEd25519SealedSessionRecordFixture,
  buildPasskeyExactEd25519AuthorizationFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';
import {
  buildPromotedActiveWalletSessionFixture,
  extendFixtureAuthorityWithEcdsaSigner,
} from './helpers/linkedDeviceManagement.fixtures';

function passkeyStatusFixture() {
  const record = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('expected exact Ed25519 runtime fixture');
  return {
    runtime,
    authorization: buildPasskeyExactEd25519AuthorizationFixture(record),
  };
}

test('addresses Email OTP warm material by threshold session and exact activation', async () => {
  const record = buildEmailOtpEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('expected exact Email OTP Ed25519 runtime fixture');
  const targets: unknown[] = [];
  const reader = createWarmSessionStatusReader({
    touchConfirm: null,
    getEmailOtpWarmSessionStatus: async (target) => {
      targets.push(target);
      return {
        ok: true,
        remainingUses: 2,
        expiresAtMs: runtime.expiresAtMs,
      };
    },
  });

  await expect(
    reader.getEd25519SigningSessionStatus({
      runtime,
      authorization: buildEmailOtpExactEd25519AuthorizationFixture(record),
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({ status: 'active', remainingUses: 2 });
  expect(targets).toEqual([
    {
      kind: 'ed25519_yao',
      thresholdSessionId: runtime.thresholdSessionId,
      materialActivation: record.ed25519Restore.materialActivation,
    },
  ]);
});

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

test('reads active status from canonical authorization identity', async () => {
  const record = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('expected exact Ed25519 runtime fixture');
  const authorization = buildPasskeyExactEd25519AuthorizationFixture(record);
  const reader = createWarmSessionStatusReader({
    touchConfirm: {
      getWarmSessionStatus: async () => ({
        ok: true,
        remainingUses: 2,
        expiresAtMs: runtime.expiresAtMs,
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
      runtime,
      authorization,
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({
    sessionId: runtime.thresholdSessionId,
    status: 'active',
    authMethod: 'passkey',
    remainingUses: 2,
  });
});

test('reads warm status for Ed25519 material under a promoted full authority', async () => {
  const record = buildPasskeyEd25519SealedSessionRecordFixture();
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('expected exact Ed25519 runtime fixture');
  const authorization = buildPasskeyExactEd25519AuthorizationFixture(record);
  const promotedAuthority = await extendFixtureAuthorityWithEcdsaSigner(
    authorization.selectedAuthority,
  );
  const promotedSession = buildPromotedActiveWalletSessionFixture({
    source: authorization.session,
    authority: promotedAuthority,
  });
  const promotedAuthorization = buildActiveNearEd25519WalletSessionAuthorization({
    selectedAuthority: promotedAuthority,
    selectedAuthMethod: authorization.selectedAuthMethod,
    selectedFactorAuthority: authorization.selectedFactorAuthority,
    session: promotedSession,
    operationCredential: authorization.operationCredential,
    status: {
      status: 'active',
      walletSessionId: authorization.status.walletSessionId,
      quotaId: authorization.status.quotaId,
      remainingUses: authorization.status.remainingUses,
      expiresAtMs: authorization.status.expiresAtMs,
      quotaLifecycle: 'active',
      authorization: promotedSession,
    },
    nowMs: 1_800_000_000_000,
  });
  let statusReads = 0;
  const reader = createWarmSessionStatusReader({
    touchConfirm: {
      getWarmSessionStatus: async () => {
        statusReads += 1;
        return {
          ok: true,
          remainingUses: 2,
          expiresAtMs: runtime.expiresAtMs,
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
      runtime,
      authorization: promotedAuthorization,
      nowMs: 1_800_000_000_000,
    }),
  ).resolves.toMatchObject({
    sessionId: runtime.thresholdSessionId,
    status: 'active',
    authMethod: 'passkey',
    remainingUses: 2,
  });
  expect(statusReads).toBe(1);
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
