import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  deriveEvmFamilySigningKeySlotId,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildEcdsaPasskeySigningLane,
  buildNearTransactionSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import {
  SigningSessionIds,
  SigningSessionPlanKind,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

const walletId = toWalletId('ecdsa-step-up-budget.testnet');
const passkeyAuth = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-ecdsa-step-up',
};
const emailOtpAuth = {
  kind: 'email_otp' as const,
  providerSubjectId: 'google:ecdsa-step-up',
};
const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});
const signingRootId = 'project:dev';
const signingRootVersion = 'default';
const ecdsaKey = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
    walletId,
    signingRootId,
    signingRootVersion,
  }),
  ecdsaThresholdKeyId: 'ehss-step-up-key',
  signingRootId,
  signingRootVersion,
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
});
const nearAccountId = toAccountId('ed25519-step-up-budget.testnet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(
  'scope-ed25519-step-up-budget',
);

function makePasskeyLane() {
  return buildEcdsaPasskeySigningLane({
    key: ecdsaKey,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-key-step-up-passkey'),
    walletId,
    auth: passkeyAuth,
    chainTarget,
    signingGrantId: SigningSessionIds.signingGrant('wsess-step-up-passkey'),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tehss-step-up-passkey'),
    storageSource: 'login',
  });
}

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

function makeEmailOtpLane() {
  return buildEcdsaEmailOtpSigningLane({
    key: ecdsaKey,
    keyHandle: toEvmFamilyEcdsaKeyHandle('ehss-key-step-up-email-otp'),
    walletId,
    auth: emailOtpAuth,
    chainTarget,
    signingGrantId: SigningSessionIds.signingGrant('wsess-step-up-email-otp'),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession('tehss-step-up-email-otp'),
  });
}

test.describe('SigningSessionCoordinator ECDSA step-up preflight', () => {
  test('keeps warm passkey ECDSA plan when a ready lane has an unreadable budget preflight', async () => {
    const lane = makePasskeyLane();
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

  test('keeps warm Email OTP ECDSA plan when a ready lane has an unavailable budget preflight', async () => {
    const lane = makeEmailOtpLane();
    const coordinator = new SigningSessionCoordinator({
      getStatus: async () => ({
        sessionId: lane.signingGrantId,
        status: 'unavailable',
      }),
    });

    const resolved = await coordinator.resolveAuthPlanFromReadiness({
      lane,
      readiness: {
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

  test('plans passkey reauth when a ready Ed25519 lane has unreadable budget status', async () => {
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
        status: 'ready',
        thresholdSessionId: lane.thresholdSessionId,
        remainingUses: 1,
        expiresAtMs: Date.now() + 60_000,
      },
      remainingUses: 1,
      expiresAtMs: Date.now() + 60_000,
      usesNeeded: 1,
    });

    expect(resolved.readiness.status).toBe('missing_session');
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
  });
});
