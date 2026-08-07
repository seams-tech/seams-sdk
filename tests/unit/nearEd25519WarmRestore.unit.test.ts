import { expect, test } from '@playwright/test';
import { ensurePasskeyEd25519WarmSessionForSigning } from '@/SeamsWeb/signingSurface/BrowserSigningSurface';
import type { PasskeyMpcSessionPort } from '@/core/signingEngine/uiConfirm/uiConfirm.types';
import { parseExactEd25519SealedSessionRuntime } from '@/core/signingEngine/session/warmCapabilities/ed25519SealedSessionRuntime';
import { rebindRouterAbEd25519WalletSessionStateFromExactRuntime } from '@/core/signingEngine/session/warmCapabilities/routerAbEd25519WalletSessionState';
import {
  buildPasskeyEd25519AuthorizationProjectionFixture,
  buildPasskeyEd25519SealedSessionRecordFixture,
} from './helpers/sealedSigningSession.fixtures';

test('restores the passkey Ed25519 warm session after a refreshed worker loses its cache', async () => {
  const record = buildPasskeyEd25519SealedSessionRecordFixture({
    thresholdSessionId: 'threshold-session-before-refresh',
  });
  const runtime = parseExactEd25519SealedSessionRuntime(record);
  if (!runtime) throw new Error('passkey Ed25519 sealed runtime fixture is invalid');
  const renewedAuthorization = buildPasskeyEd25519AuthorizationProjectionFixture(
    buildPasskeyEd25519SealedSessionRecordFixture({
      walletId: record.walletId,
      nearAccountId: record.ed25519Restore.nearAccountId,
      nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
      thresholdSessionId: 'threshold-session-after-refresh',
      materialActivation: record.ed25519Restore.materialActivation,
    }),
  );
  const walletSessionJwt = renewedAuthorization.walletSessionTokens.ed25519.walletSessionJwt;
  const walletSessionState = await rebindRouterAbEd25519WalletSessionStateFromExactRuntime({
    runtime,
    authorization: renewedAuthorization,
    nowMs: runtime.expiresAtMs - 1,
  });
  const operations: string[] = [];
  let claimCount = 0;
  const claimWarmSessionMaterial: PasskeyMpcSessionPort['claimWarmSessionMaterial'] = async (
    input,
  ) => {
    operations.push('claim');
    expect(input.thresholdSessionId).toBe(walletSessionState.thresholdSessionId);
    expect(input.purpose).toEqual({
      curve: 'ed25519',
      materialActivation: record.ed25519Restore.materialActivation,
    });
    claimCount += 1;
    return claimCount === 1
      ? {
          ok: false,
          code: 'not_found',
          message: 'Warm-session material is not available for threshold session',
        }
      : {
          ok: true,
          prfFirstB64u: 'restored-prf-first',
          remainingUses: 2,
          expiresAtMs: runtime.expiresAtMs,
        };
  };
  const rehydrateWarmSessionMaterial: PasskeyMpcSessionPort['rehydrateWarmSessionMaterial'] =
    async (input) => {
      operations.push('rehydrate');
      expect(input.thresholdSessionId).toBe(walletSessionState.thresholdSessionId);
      expect(input.sealedSecretB64u).toBe(record.sealedSecretB64u);
      expect(input.transport).toMatchObject({
        curve: 'ed25519',
        authMethod: 'passkey',
        walletId: record.walletId,
        relayerUrl: record.relayerUrl,
        walletSessionJwt,
        ed25519Restore: {
          nearAccountId: record.ed25519Restore.nearAccountId,
          nearEd25519SigningKeyId: record.ed25519Restore.nearEd25519SigningKeyId,
          signerSlot: record.ed25519Restore.signerSlot,
          credentialIdB64u: record.ed25519Restore.credentialIdB64u,
          materialActivation: record.ed25519Restore.materialActivation,
        },
      });
      return {
        ok: true,
        remainingUses: 2,
        expiresAtMs: runtime.expiresAtMs,
      };
    };

  const result = await ensurePasskeyEd25519WarmSessionForSigning({
    claimWarmSessionMaterial,
    rehydrateWarmSessionMaterial,
    runtime,
    walletSessionState,
    materialActivation: record.ed25519Restore.materialActivation,
  });

  expect(operations).toEqual(['claim', 'rehydrate', 'claim']);
  expect(result).toEqual({
    ok: true,
    prfFirstB64u: 'restored-prf-first',
    remainingUses: 2,
    expiresAtMs: runtime.expiresAtMs,
  });
});
