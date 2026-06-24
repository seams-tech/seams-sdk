import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  toWalletId,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildEcdsaPasskeySigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import {
  SigningSessionIds,
  SigningSessionPlanKind,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import { SigningSessionCoordinator } from '../../packages/sdk-web/src/core/signingEngine/session/SigningSessionCoordinator';

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
const ecdsaKey = buildBaseEvmFamilyEcdsaKeyIdentity({
  walletId,
  walletKeyId: 'wallet-key-ecdsa-step-up',
  ecdsaThresholdKeyId: 'ehss-step-up-key',
  signingRootId: 'project:dev',
  signingRootVersion: 'default',
  participantIds: [1, 2],
  thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
});

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
  test('plans passkey reauth when a ready ECDSA lane has an unreadable budget status', async () => {
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

    expect(resolved.readiness.status).toBe('missing_session');
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.PasskeyReauth);
  });

  test('plans Email OTP reauth when a ready ECDSA lane has an unavailable budget status', async () => {
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

    expect(resolved.readiness.status).toBe('missing_session');
    expect(resolved.signingSessionPlan.kind).toBe(SigningSessionPlanKind.EmailOtpReauth);
  });
});
