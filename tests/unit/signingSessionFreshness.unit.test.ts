import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildNearTransactionSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import { SigningSessionIds } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  assertFreshnessMatchesLane,
  buildFreshStepUpRequired,
  buildFreshStepUpSatisfied,
  buildStepUpFreshnessFromRestoredSealedRecord,
  buildStepUpFreshnessFromTrustedSessionStatus,
  stepUpFreshnessDiagnostics,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { deriveEvmFamilySigningKeySlotId } from '../../packages/shared-ts/src/signing-lanes/evmFamilySigningKeySlotId';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const tempoChainTarget = { kind: 'tempo', chainId: 4242, networkSlug: 'tempo-test' } as const;
const NEAR_WALLET_ID = toWalletId('frost-vermillion-k7p9m2');
const NEAR_ACCOUNT_ID = toAccountId('freshness-alice.testnet');
const ED25519_KEY_SCOPE_ID = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
const PASSKEY_AUTH = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-freshness',
};
const EMAIL_OTP_AUTH = {
  kind: 'email_otp' as const,
  providerSubjectId: 'google:freshness',
};

function makeNearLane(args?: { thresholdSessionId?: string }) {
  return buildNearTransactionSigningLane({
    walletId: NEAR_WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    auth: PASSKEY_AUTH,
    walletSessionId: SigningSessionIds.walletSession('wallet-session-near'),
    quotaId: SigningSessionIds.walletSessionQuota('quota-near'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args?.thresholdSessionId || 'threshold-session-near',
    ),
    storageSource: 'login',
  });
}

function makeEcdsaKey() {
  const walletId = toWalletId('freshness-wallet.testnet');
  const signingRootId = 'proj_test:dev';
  const signingRootVersion = '1';
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId,
    evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
      walletId,
      signingRootId,
      signingRootVersion,
      chainTargetKey: thresholdEcdsaChainTargetKey(tempoChainTarget),
    }),
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    signingRootId,
    signingRootVersion,
    participantIds: [1, 2],
    thresholdOwnerAddress: '0x0000000000000000000000000000000000000042',
  });
}

function makeEcdsaLane(args?: { thresholdSessionId?: string }) {
  const key = makeEcdsaKey();
  return buildEcdsaEmailOtpSigningLane({
    key,
    materialActivation: buildMpcMaterialActivationRefFixture('freshness-ecdsa', key.walletId),
    keyHandle: toEvmFamilyEcdsaKeyHandle('tempo:4242:ecdsa-threshold-key'),
    walletId: key.walletId,
    auth: EMAIL_OTP_AUTH,
    chainTarget: tempoChainTarget,
    walletSessionId: SigningSessionIds.walletSession('wallet-session-ecdsa'),
    quotaId: SigningSessionIds.walletSessionQuota('quota-ecdsa'),
    thresholdSessionId: SigningSessionIds.thresholdEcdsaSession(
      args?.thresholdSessionId || 'threshold-session-ecdsa',
    ),
  });
}

function makeOperation() {
  return {
    operationId: SigningSessionIds.signingOperation('operation-1'),
    operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  };
}

test.describe('step-up freshness identity', () => {
  test('builds Ed25519 freshness with a known projection', () => {
    const lane = makeNearLane();
    const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
    const operation = makeOperation();

    const satisfied = buildFreshStepUpSatisfied({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity,
      projection: { kind: 'known', version: 'projection-1' },
      expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
      provenance: {
        kind: 'trusted_server_budget_status',
        projectionVersion: 'projection-1',
        observedAtMs: 1_800_000_000_000,
      },
      remainingUses: 1,
    });

    expect(satisfied.kind).toBe('fresh_step_up_satisfied');
    expect(satisfied.laneIdentityKey).toBe(exactSigningLaneIdentityKey(laneIdentity));
    expect(stepUpFreshnessDiagnostics(satisfied)).toMatchObject({
      kind: 'fresh_step_up_satisfied',
      laneIdentityKey: exactSigningLaneIdentityKey(laneIdentity),
      remainingUses: 1,
      projection: { kind: 'known', version: 'projection-1' },
    });
  });

  test('prevents freshness from one exact lane satisfying another lane', () => {
    const sourceLane = makeNearLane({ thresholdSessionId: 'threshold-source' });
    const targetLane = makeNearLane({ thresholdSessionId: 'threshold-target' });
    const operation = makeOperation();

    const required = buildFreshStepUpRequired({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity: exactSigningLaneIdentityFromSelectedLane(sourceLane),
      projection: { kind: 'known', version: 'projection-1' },
      expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
      provenance: {
        kind: 'trusted_server_budget_status',
        projectionVersion: 'projection-1',
        observedAtMs: 1_800_000_000_000,
      },
      reason: 'wallet_budget_exhausted',
    });

    expect(() =>
      assertFreshnessMatchesLane({
        freshness: required,
        laneIdentity: exactSigningLaneIdentityFromSelectedLane(targetLane),
      }),
    ).toThrow('[StepUpFreshness] freshness does not match exact lane identity');
  });

  test('builds satisfied and required freshness from trusted budget status', () => {
    const lane = makeNearLane();
    const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
    const operation = makeOperation();

    const satisfied = buildStepUpFreshnessFromTrustedSessionStatus({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity,
      observedAtMs: 1_800_000_000_000,
      status: {
        sessionId: String(lane.walletSessionId),
        status: 'active',
        remainingUses: 2,
        expiresAtMs: 1_900_000_000_000,
        projectionVersion: 'projection-1',
      },
    });
    const required = buildStepUpFreshnessFromTrustedSessionStatus({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity,
      observedAtMs: 1_800_000_000_000,
      status: {
        sessionId: String(lane.walletSessionId),
        status: 'exhausted',
        remainingUses: 0,
        projectionVersion: 'projection-2',
      },
    });

    expect(satisfied).toMatchObject({
      kind: 'fresh_step_up_satisfied',
      projection: { kind: 'known', version: 'projection-1' },
      expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
      remainingUses: 2,
    });
    expect(required).toMatchObject({
      kind: 'fresh_step_up_required',
      reason: 'threshold_session_exhausted',
      projection: { kind: 'known', version: 'projection-2' },
      expiry: { kind: 'unavailable', reason: 'budget_status_unavailable' },
    });
  });

  test('builds restored-record freshness with unavailable projection', () => {
    const lane = makeEcdsaLane();
    const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
    const operation = makeOperation();

    const restored = buildStepUpFreshnessFromRestoredSealedRecord({
      walletId: lane.identity.signer.walletId,
      ...operation,
      laneIdentity,
      recordVersion: 'sealed-v1',
      updatedAtMs: 1_800_000_000_000,
      remainingUses: 1,
      expiresAtMs: 1_900_000_000_000,
      nowMs: 1_800_000_000_000,
    });
    const expired = buildStepUpFreshnessFromRestoredSealedRecord({
      walletId: lane.identity.signer.walletId,
      ...operation,
      laneIdentity,
      recordVersion: 'sealed-v1',
      updatedAtMs: 1_800_000_000_000,
      remainingUses: 1,
      expiresAtMs: 1_700_000_000_000,
      nowMs: 1_800_000_000_000,
    });

    expect(restored).toMatchObject({
      kind: 'fresh_step_up_satisfied',
      projection: { kind: 'unavailable', reason: 'restored_record_has_no_projection' },
      expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
    });
    expect(expired).toMatchObject({
      kind: 'fresh_step_up_required',
      reason: 'threshold_session_expired',
      projection: { kind: 'unavailable', reason: 'restored_record_has_no_projection' },
    });
  });
});
