import { expect, test } from '@playwright/test';
import { resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime } from '@/core/signingEngine/session/emailOtp/ecdsaSigningSessionAuthority';
import { resolveExactEcdsaSealedRuntime } from '@/core/signingEngine/session/material/ecdsaSealedRuntime';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { ecdsaCapabilityHydrationLookupFixture } from './helpers/ecdsaCapabilityManifest.fixtures';
import { buildEmailOtpEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';
import {
  refreshEmailOtpSigningSession,
  type EmailOtpEcdsaSigningSessionDeps,
} from '@/core/signingEngine/flows/signEvmFamily/emailOtpSigningSession';
import { resolveThresholdEcdsaSigningQueueKey } from '@/core/signingEngine/threshold/ecdsa/signingQueue';

// Email OTP refresh renews authorization over material that already exists. It
// resolves the exact manifest plus sealed runtime, takes the Email OTP binding
// from the runtime, and completes the signing-session lane with the reusable
// Wallet Session resolved independently. Refresh must not move the material
// activation, and must never reach for recovery or device linking.

function resolvedRuntime(overrides: { thresholdSessionId?: string } = {}) {
  const manifest = ecdsaCapabilityHydrationLookupFixture().active.manifest;
  const record = buildEmailOtpEcdsaSealedRuntimeRecordFixture({
    manifest,
    ...(overrides.thresholdSessionId
      ? { thresholdSessionId: overrides.thresholdSessionId }
      : {}),
  });
  const walletId = toWalletId(String(manifest.signer.walletId));
  const resolution = resolveExactEcdsaSealedRuntime({
    manifest,
    walletId,
    chainTarget: record.ecdsaRestore.chainTarget,
    sealedRecords: [record],
  });
  if (resolution.kind !== 'resolved') {
    throw new Error(`sealed runtime fixture did not resolve: ${resolution.reason}`);
  }
  return { manifest, walletId, runtime: resolution.runtime, record };
}

function activeAuthorization(walletSessionId: string, walletSessionJwt = 'wallet-session-jwt') {
  return { walletSessionId, walletSessionJwt } as Parameters<
    typeof resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime
  >[0]['authorization'];
}

test.describe('Email OTP ECDSA refresh canonical authority', () => {
  test('builds the signing-session lane from runtime binding and active authorization', () => {
    const { runtime } = resolvedRuntime();
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime,
      authorization: activeAuthorization('wallet-session-refresh'),
    });

    expect(resolution.kind).toBe('ready');
    if (resolution.kind !== 'ready') return;
    const authLane = resolution.authority.authLane;
    expect(authLane.kind).toBe('signing_session');
    expect(authLane.curve).toBe('ecdsa');
    // The Email OTP lane names the sealed threshold session. Reusable Wallet
    // Session identity remains on the independent authorization projection.
    expect(authLane.thresholdSessionId).toBe(runtime.sealedRecord.thresholdSessionId);
    expect(authLane.authorizingSigningGrantId).toBeUndefined();
    expect(authLane.jwt).toBe('wallet-session-jwt');
  });

  test('an absent Wallet Session is a typed unavailable, not a throw', () => {
    const { runtime } = resolvedRuntime();
    const resolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime,
      authorization: activeAuthorization('wallet-session-refresh', ''),
    });

    expect(resolution.kind).toBe('wallet_session_auth_unavailable');
  });

  test('refresh keeps the same material activation across a rotated session id', () => {
    const before = resolvedRuntime({ thresholdSessionId: 'ec-session-before' });
    const after = resolvedRuntime({ thresholdSessionId: 'ec-session-after' });

    // A refresh rotates session identity while the material underneath is
    // unchanged; that is exactly what the post-refresh activation check allows.
    expect(after.runtime.sealedRecord.thresholdSessionId).not.toBe(
      before.runtime.sealedRecord.thresholdSessionId,
    );
    expect(after.runtime.materialActivation.activationId).toBe(
      before.runtime.materialActivation.activationId,
    );
    expect(String(after.runtime.roleLocalMaterialRef.durableMaterialRef)).toBe(
      String(before.runtime.roleLocalMaterialRef.durableMaterialRef),
    );
  });

  test('rechecks the exact activation inside its owner queue before consuming refresh', async () => {
    const initial = resolvedRuntime();
    const authorityResolution = resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime({
      runtime: initial.runtime,
      authorization: activeAuthorization('wallet-session-refresh'),
    });
    if (authorityResolution.kind !== 'ready') {
      throw new Error('refresh fixture requires an active Email OTP authority');
    }
    let resolutionCalls = 0;
    let queueCalls = 0;
    let loginCalls = 0;
    const deps: EmailOtpEcdsaSigningSessionDeps = {
      resolveSigningSessionAuth: async () => {
        resolutionCalls += 1;
        if (resolutionCalls === 1) {
          return {
            manifest: initial.manifest,
            runtime: initial.runtime,
            authority: authorityResolution.authority,
          };
        }
        throw new Error('capability disappeared while queued');
      },
      withThresholdEcdsaSigningQueue: async (queueArgs) => {
        queueCalls += 1;
        expect(queueArgs.queueKey).toBe(
          resolveThresholdEcdsaSigningQueueKey({
            materialActivation: initial.runtime.materialActivation,
          }),
        );
        return await queueArgs.task();
      },
      emailOtpSessions: {
        requestTransactionSigningChallenge: async () => {
          throw new Error('challenge is not part of refresh fencing');
        },
        loginWithEcdsaCapabilityInternal: async () => {
          loginCalls += 1;
          throw new Error('refresh must not consume after supersession');
        },
      },
    };

    await expect(
      refreshEmailOtpSigningSession(deps, {
        walletSession: {
          walletId: initial.walletId,
          walletSessionUserId: String(initial.walletId),
        },
        chainTarget: initial.runtime.chainTarget,
        challengeId: 'challenge-refresh-fence',
        otpCode: '123456',
      }),
    ).rejects.toThrow('superseded before use');
    expect(queueCalls).toBe(1);
    expect(resolutionCalls).toBe(2);
    expect(loginCalls).toBe(0);
  });
});
