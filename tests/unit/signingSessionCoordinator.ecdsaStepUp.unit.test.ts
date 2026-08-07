import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildNearTransactionSigningLane } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import {
  SigningSessionIds,
  SigningSessionPlanKind,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const walletId = toWalletId('ed25519-step-up-status.testnet');
const passkeyAuth = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-ed25519-step-up',
};
const nearAccountId = toAccountId('ed25519-step-up-status.testnet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('scope-ed25519-step-up-status');

function makeNearPasskeyLane() {
  return buildNearTransactionSigningLane({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    auth: passkeyAuth,
    walletSessionId: SigningSessionIds.walletSession('wsess-step-up-near-passkey'),
    quotaId: SigningSessionIds.walletSessionQuota('quota-step-up-near-passkey'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('ted25519-step-up-passkey'),
    storageSource: 'registration',
  });
}

test.describe('SigningSessionCoordinator NEAR Ed25519 Wallet Session status', () => {
  test('uses trusted status auth when planning a ready passkey Ed25519 lane', async () => {
    const lane = makeNearPasskeyLane();
    const trustedStatusAuth = {
      walletSessionId: 'wallet-session-status-id',
      quotaId: 'quota-status-id',
    };
    let observedKind = '';
    let observedWalletSessionId = '';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async (statusArgs) => {
        observedKind = statusArgs.kind;
        observedWalletSessionId = String(statusArgs.authorization.walletSessionId);
        return {
          sessionId: trustedStatusAuth.walletSessionId,
          status: 'active',
          remainingUses: 3,
          committedRemainingUses: 3,
          inFlightReservedUses: 0,
          availableUses: 3,
          expiresAtMs: Date.now() + 60_000,
          projectionVersion: 'projection-v1',
        };
      },
    });

    const resolved = await coordinator.resolveAuthPlanFromReadiness({
      lane,
      readiness: {
        curve: 'ed25519',
        status: 'ready',
        thresholdSessionId: lane.thresholdSessionId,
        remainingUses: 3,
        expiresAtMs: Date.now() + 60_000,
      },
      remainingUses: 3,
      expiresAtMs: Date.now() + 60_000,
      usesNeeded: 1,
      trustedStatusAuth,
    });

    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.WarmSession);
    expect(observedKind).toBe('wallet_session_status_check');
    expect(observedWalletSessionId).toBe(trustedStatusAuth.walletSessionId);
  });

  test('keeps a ready passkey Ed25519 session when canonical status is unreadable', async () => {
    const lane = makeNearPasskeyLane();
    const trustedStatusAuth = {
      walletSessionId: 'wallet-session-unreadable-status',
      quotaId: 'quota-unreadable-status',
    };
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: trustedStatusAuth.walletSessionId,
        status: 'status_unknown',
        statusCode: 'status_unavailable',
      }),
    });

    const resolved = await coordinator.resolveAuthPlanFromReadiness({
      lane,
      readiness: {
        curve: 'ed25519',
        status: 'ready',
        thresholdSessionId: lane.thresholdSessionId,
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      },
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
      usesNeeded: 1,
      trustedStatusAuth,
    });

    expect(resolved.readiness.status).toBe('ready');
    expect(resolved.remainingUses).toBe(1);
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.WarmSession);
  });

  test('requires same-method reauthorization when reusable authorization is absent', async () => {
    const lane = makeNearPasskeyLane();
    let statusReads = 0;
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => {
        statusReads += 1;
        throw new Error('status must not be read without reusable authorization');
      },
    });

    const resolved = await coordinator.resolveAuthPlanFromReadiness({
      lane,
      readiness: {
        curve: 'ed25519',
        status: 'ready',
        thresholdSessionId: lane.thresholdSessionId,
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      },
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
      usesNeeded: 1,
    });

    expect(statusReads).toBe(0);
    expect(resolved.readiness.status).toBe('missing_session');
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
  });
});
