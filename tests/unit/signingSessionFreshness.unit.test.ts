import { expect, test } from '@playwright/test';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import { toWalletId } from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildVerifiedEcdsaPublicFacts,
  toRpId,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { buildReauthAnchorIdentityFromAvailableLane } from '../../packages/sdk-web/src/core/signingEngine/session/availability/availableSigningLanes';
import {
  exactSigningLaneIdentityFromSelectedLane,
  exactSigningLaneIdentityKey,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/exactSigningLaneIdentity';
import {
  buildEcdsaEmailOtpSigningLane,
  buildNearTransactionSigningLane,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/lanes';
import {
  SigningOperationIntent,
  SigningSessionIds,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/types';
import {
  assertFreshnessMatchesLane,
  buildFreshStepUpRequired,
  buildFreshStepUpSatisfied,
  buildFreshStepUpSatisfiedForAdmission,
  buildStepUpFreshnessFromRestoredSealedRecord,
  buildStepUpFreshnessFromTrustedBudgetStatus,
  stepUpFreshnessDiagnostics,
} from '../../packages/sdk-web/src/core/signingEngine/session/operationState/stepUpFreshness';
import { buildReauthAnchorIdentity } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/transactionState';
import { recordPreparedTransactionBudgetAdmissionFromFreshness } from '../../packages/sdk-web/src/core/signingEngine/session/operationState/transactionState';
import {
  buildSigningBudgetReservationIdentity,
  signingBudgetReservationKey,
} from '../../packages/sdk-web/src/core/signingEngine/session/budget/budget';
import { nearEd25519SigningKeyIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';

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
    signingGrantId: SigningSessionIds.signingGrant('wallet-session-near'),
    thresholdSessionId: SigningSessionIds.thresholdEd25519Session(
      args?.thresholdSessionId || 'threshold-session-near',
    ),
    storageSource: 'login',
  });
}

function makeEcdsaKey() {
  return buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: toWalletId('freshness-wallet.testnet'),
    walletKeyId: 'wallet-key-freshness',
    ecdsaThresholdKeyId: 'ecdsa-threshold-key',
    signingRootId: 'proj_test:dev',
    signingRootVersion: '1',
    participantIds: [1, 2],
    thresholdOwnerAddress: '0x0000000000000000000000000000000000000042',
  });
}

function makeEcdsaLane(args?: { thresholdSessionId?: string }) {
  const key = makeEcdsaKey();
  return buildEcdsaEmailOtpSigningLane({
    key,
    keyHandle: toEvmFamilyEcdsaKeyHandle('tempo:4242:ecdsa-threshold-key'),
    walletId: key.walletId,
    auth: EMAIL_OTP_AUTH,
    chainTarget: tempoChainTarget,
    signingGrantId: SigningSessionIds.signingGrant('wallet-session-ecdsa'),
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
  test('builds an admission-ready Ed25519 freshness state only with a known projection', () => {
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

    const admission = buildFreshStepUpSatisfiedForAdmission(satisfied);

    expect(admission.kind).toBe('fresh_step_up_satisfied_for_admission');
    expect(admission.laneIdentityKey).toBe(exactSigningLaneIdentityKey(laneIdentity));
    expect(admission.thresholdSessionIds.map(String)).toEqual(['threshold-session-near']);
    expect(stepUpFreshnessDiagnostics(admission)).toMatchObject({
      kind: 'fresh_step_up_satisfied_for_admission',
      laneIdentityKey: exactSigningLaneIdentityKey(laneIdentity),
      remainingUses: 1,
      projection: { kind: 'known', version: 'projection-1' },
    });
  });

  test('rejects admission when ECDSA freshness has no projection', () => {
    const lane = makeEcdsaLane();
    const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
    const operation = makeOperation();

    const satisfied = buildFreshStepUpSatisfied({
      walletId: lane.identity.signer.walletId,
      ...operation,
      laneIdentity,
      projection: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
      expiry: { kind: 'unavailable', reason: 'email_otp_refresh_rejected' },
      provenance: {
        kind: 'email_otp_refresh_boundary',
        httpStatus: 401,
        observedAtMs: 1_800_000_000_000,
      },
      remainingUses: 1,
    });

    expect(() => buildFreshStepUpSatisfiedForAdmission(satisfied)).toThrow(
      '[StepUpFreshness] admission requires a known projection',
    );
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

  test('builds reauth anchors from required freshness without ready material', () => {
    const lane = makeEcdsaLane();
    const operation = makeOperation();
    const required = buildFreshStepUpRequired({
      walletId: lane.identity.signer.walletId,
      ...operation,
      laneIdentity: exactSigningLaneIdentityFromSelectedLane(lane),
      projection: { kind: 'unavailable', reason: 'budget_status_unavailable' },
      expiry: { kind: 'unavailable', reason: 'budget_status_unavailable' },
      provenance: {
        kind: 'trusted_server_budget_status',
        projectionVersion: 'projection-1',
        observedAtMs: 1_800_000_000_000,
      },
      reason: 'threshold_session_exhausted',
    });

    const anchor = buildReauthAnchorIdentity({
      freshness: required,
      sourceState: {
        kind: 'reauth_anchor_source_state',
        availabilitySource: 'durable_sealed_record',
        storeSource: 'email_otp',
        retention: 'single_use',
        remainingUses: 0,
        expiry: required.expiry,
        projection: required.projection,
      },
    });

    expect(anchor.laneIdentityKey).toBe(required.laneIdentityKey);
    expect('readyLane' in anchor).toBe(false);
    expect('budget' in anchor).toBe(false);
    expect(stepUpFreshnessDiagnostics(anchor.freshness)).toMatchObject({
      kind: 'fresh_step_up_required',
      laneIdentityKey: required.laneIdentityKey,
      reason: 'threshold_session_exhausted',
      projection: { kind: 'unavailable', reason: 'budget_status_unavailable' },
    });
  });

  test('builds an ECDSA reauth anchor from an exhausted available lane', () => {
    const key = makeEcdsaKey();
    const keyHandle = toEvmFamilyEcdsaKeyHandle('tempo:4242:ecdsa-threshold-key');
    const anchor = buildReauthAnchorIdentityFromAvailableLane({
      walletId: key.walletId,
      ...makeOperation(),
      lane: {
        key,
        publicFacts: buildVerifiedEcdsaPublicFacts({
          keyHandle,
          publicKeyB64u: 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          participantIds: [1, 2],
          thresholdOwnerAddress: key.thresholdOwnerAddress,
        }),
        auth: EMAIL_OTP_AUTH,
        curve: 'ecdsa',
        chainTarget: tempoChainTarget,
        state: 'exhausted',
        source: 'runtime_and_durable',
        signingGrantId: 'wallet-session-ecdsa',
        thresholdSessionId: 'threshold-session-ecdsa',
        remainingUses: 0,
        updatedAtMs: 1_800_000_000_000,
      },
      nowMs: 1_800_000_000_001,
    });

    expect(anchor).toMatchObject({
      kind: 'reauth_anchor_identity',
      sourceState: {
        availabilitySource: 'runtime_and_durable',
        storeSource: 'email_otp',
        retention: 'single_use',
        remainingUses: 0,
      },
      freshness: {
        kind: 'fresh_step_up_required',
        reason: 'threshold_session_exhausted',
      },
    });
  });

  test('builds an Ed25519 reauth anchor from an expired available lane', () => {
    const anchor = buildReauthAnchorIdentityFromAvailableLane({
      walletId: NEAR_WALLET_ID,
      ...makeOperation(),
      lane: {
        auth: PASSKEY_AUTH,
        curve: 'ed25519',
        chain: 'near',
        walletId: NEAR_WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
        signerSlot: 1,
        state: 'expired',
        source: 'durable_sealed_record',
        signingGrantId: 'wallet-session-near',
        thresholdSessionId: 'threshold-session-near',
        remainingUses: 1,
        expiresAtMs: 1_700_000_000_000,
        updatedAtMs: 1_700_000_000_001,
      },
      nowMs: 1_800_000_000_000,
    });

    expect(anchor).toMatchObject({
      kind: 'reauth_anchor_identity',
      sourceState: {
        availabilitySource: 'durable_sealed_record',
        storeSource: 'login',
        retention: 'session',
        remainingUses: 1,
      },
      freshness: {
        kind: 'fresh_step_up_required',
        reason: 'threshold_session_expired',
      },
    });
  });

  test('builds satisfied and required freshness from trusted budget status', () => {
    const lane = makeNearLane();
    const laneIdentity = exactSigningLaneIdentityFromSelectedLane(lane);
    const operation = makeOperation();

    const satisfied = buildStepUpFreshnessFromTrustedBudgetStatus({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity,
      observedAtMs: 1_800_000_000_000,
      status: {
        sessionId: String(lane.signingGrantId),
        status: 'active',
        remainingUses: 2,
        expiresAtMs: 1_900_000_000_000,
        projectionVersion: 'projection-1',
      },
    });
    const required = buildStepUpFreshnessFromTrustedBudgetStatus({
      walletId: NEAR_WALLET_ID,
      ...operation,
      laneIdentity,
      observedAtMs: 1_800_000_000_000,
      status: {
        sessionId: String(lane.signingGrantId),
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

  test('admits transaction budget only from matching admission freshness', () => {
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
    const budgetAdmission = {
      budgetIdentity: {
        signingGrantId: String(lane.signingGrantId),
        projectionVersion: 'projection-1',
        status: {
          sessionId: String(lane.signingGrantId),
          status: 'active' as const,
          projectionVersion: 'projection-1',
          remainingUses: 1,
          expiresAtMs: 1_900_000_000_000,
        },
      },
    };

    const lifecycle = recordPreparedTransactionBudgetAdmissionFromFreshness(
      {
        intent: {
          curve: 'ed25519',
          chain: 'near',
          walletId: NEAR_WALLET_ID,
          authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
          operationUsesNeeded: 1,
        },
        lane,
        readiness: { status: 'ready', remainingUses: 1, expiresAtMs: 1_900_000_000_000 },
      },
      budgetAdmission,
      buildFreshStepUpSatisfiedForAdmission(satisfied),
    );

    expect(lifecycle.kind).toBe('BudgetAdmitted');
    expect(() =>
      recordPreparedTransactionBudgetAdmissionFromFreshness(
        lifecycle.operation,
        {
          budgetIdentity: {
            ...budgetAdmission.budgetIdentity,
            projectionVersion: 'projection-2',
            status: {
              ...budgetAdmission.budgetIdentity.status,
              projectionVersion: 'projection-2',
            },
          },
        },
        buildFreshStepUpSatisfiedForAdmission(satisfied),
      ),
    ).toThrow('[SigningSession] admission freshness projection does not match budget');
  });
});

test.describe('budget reservation identity', () => {
  test('keys reservations by operation, exact lane, projection, and session ids', () => {
    const lane = makeNearLane({ thresholdSessionId: 'threshold-reservation-a' });
    const nextLane = makeNearLane({ thresholdSessionId: 'threshold-reservation-b' });
    const operation = makeOperation();
    const baseSpend = {
      ...operation,
      backingMaterialSessionIds: [],
      uses: 1 as const,
      reason: SigningOperationIntent.TransactionSign,
    };

    const first = buildSigningBudgetReservationIdentity({
      spend: { ...baseSpend, lane },
      projectionVersion: 'projection-1',
    });
    const same = buildSigningBudgetReservationIdentity({
      spend: { ...baseSpend, lane },
      projectionVersion: 'projection-1',
    });
    const differentLane = buildSigningBudgetReservationIdentity({
      spend: {
        ...baseSpend,
        lane: nextLane,
      },
      projectionVersion: 'projection-1',
    });

    expect(signingBudgetReservationKey(first)).toBe(signingBudgetReservationKey(same));
    expect(signingBudgetReservationKey(first)).not.toBe(signingBudgetReservationKey(differentLane));
  });
});
