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

const walletId = toWalletId('ed25519-step-up-budget.testnet');
const passkeyAuth = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-ed25519-step-up',
};
const nearAccountId = toAccountId('ed25519-step-up-budget.testnet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(
  'scope-ed25519-step-up-budget',
);

function makeNearPasskeyLane() {
  return buildNearTransactionSigningLane({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    auth: passkeyAuth,
    signingGrantId: SigningSessionIds.signingGrant('wsess-step-up-near-passkey'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session('ted25519-step-up-passkey'),
    storageSource: 'registration',
  });
}

test.describe('SigningSessionCoordinator NEAR Ed25519 budget preflight', () => {
  test('uses trusted status auth when planning a ready passkey Ed25519 lane', async () => {
    const lane = makeNearPasskeyLane();
    const trustedStatusAuth = {
      relayerUrl: 'https://router.example',
      thresholdSessionId: String(lane.thresholdSessionId),
      walletSessionJwt: 'wallet-session-jwt',
    };
    let observedKind = '';
    let observedWalletSessionJwt = '';
    const coordinator = new SigningSessionCoordinator({
      getStatus: async (statusArgs) => {
        observedKind = statusArgs.kind;
        observedWalletSessionJwt = statusArgs.trustedStatusAuth?.walletSessionJwt || '';
        return {
          sessionId: lane.signingGrantId,
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
    expect(observedKind).toBe('authenticated_threshold_budget_status_check');
    expect(observedWalletSessionJwt).toBe('wallet-session-jwt');
  });

  test('keeps a ready passkey Ed25519 session when budget preflight is unreadable', async () => {
    const lane = makeNearPasskeyLane();
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: lane.signingGrantId,
        status: 'budget_unknown',
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
    });

    expect(resolved.readiness.status).toBe('ready');
    expect(resolved.remainingUses).toBe(1);
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.WarmSession);
  });
});
