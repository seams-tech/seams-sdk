import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import {
  toWalletSubjectId,
  type EvmEip155ChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  clearAllThresholdEcdsaSessionRecords,
  listThresholdEcdsaSessionRecordsForTarget,
  markThresholdEcdsaEmailOtpSessionConsumedForLane,
  upsertStoredThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../client/src/core/signingEngine/session/persistence/records';

const WALLET_ID = toAccountId('alice.testnet');
const SUBJECT_ID = toWalletSubjectId(WALLET_ID);
const EVM_TARGET: EvmEip155ChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

function createStore(nowRef: { value: number } | number): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
    now: () => (typeof nowRef === 'number' ? nowRef : nowRef.value),
  };
}

function ecdsaEmailOtpRecord(args: {
  walletSigningSessionId: string;
  thresholdSessionId: string;
  remainingUses: number;
  updatedAtMs: number;
}): ThresholdEcdsaSessionRecord {
  return {
    walletId: WALLET_ID,
    subjectId: SUBJECT_ID,
    rpId: 'localhost',
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.example',
    ecdsaThresholdKeyId: 'ecdsa-key-1',
    signingRootId: 'signing-root',
    signingRootVersion: 'v1',
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [1, 2],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionAuthToken: `jwt-${args.thresholdSessionId}`,
    expiresAtMs: 2_000_000_000_000,
    remainingUses: args.remainingUses,
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    updatedAtMs: args.updatedAtMs,
    source: 'email_otp',
    emailOtpAuthContext: {
      authMethod: 'email_otp',
      policy: 'per_operation',
      reason: 'sign',
      retention: 'single_use',
    },
  };
}

test.describe('Threshold ECDSA Email OTP consumption', () => {
  test.beforeEach(() => {
    clearAllThresholdEcdsaSessionRecords(createStore(0));
  });

  test.afterEach(() => {
    clearAllThresholdEcdsaSessionRecords(createStore(0));
  });

  test('marks only the exact consumed ECDSA lane', () => {
    const nowMs = { value: 1_800_000_000_000 };
    const store = createStore(nowMs);
    upsertStoredThresholdEcdsaSessionRecord(
      store,
      ecdsaEmailOtpRecord({
        walletSigningSessionId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    upsertStoredThresholdEcdsaSessionRecord(
      store,
      ecdsaEmailOtpRecord({
        walletSigningSessionId: 'wallet-session-b',
        thresholdSessionId: 'threshold-session-b',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );

    nowMs.value = 1_800_000_001_000;
    const consumed = markThresholdEcdsaEmailOtpSessionConsumedForLane(store, {
      subjectId: SUBJECT_ID,
      chainTarget: EVM_TARGET,
      walletSigningSessionId: 'wallet-session-a',
      thresholdSessionId: 'threshold-session-a',
      uses: 1,
    });

    expect(consumed?.remainingUses).toBe(0);
    const records = listThresholdEcdsaSessionRecordsForTarget(store, {
      subjectId: SUBJECT_ID,
      chainTarget: EVM_TARGET,
      source: 'email_otp',
    });
    const recordsBySession = new Map(records.map((record) => [record.thresholdSessionId, record]));
    expect(recordsBySession.get('threshold-session-a')?.remainingUses).toBe(0);
    expect(recordsBySession.get('threshold-session-a')?.updatedAtMs).toBe(1_800_000_001_000);
    expect(recordsBySession.get('threshold-session-b')?.remainingUses).toBe(1);
    expect(recordsBySession.get('threshold-session-b')?.updatedAtMs).toBe(1_800_000_000_000);
  });
});
