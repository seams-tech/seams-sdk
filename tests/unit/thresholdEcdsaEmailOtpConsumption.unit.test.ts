import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { toAccountId } from '../../packages/sdk-web/src/core/types/accountIds';
import {
  toWalletId,
  type EvmEip155ChainTarget,
} from '../../packages/sdk-web/src/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildEmailOtpAuthContextForWalletAuthMethod } from '../../packages/sdk-web/src/core/signingEngine/session/identity/laneIdentity';
import {
  clearAllThresholdEcdsaSessionRecords,
  consumeSingleUseEmailOtpEcdsaLane,
  emailOtpEcdsaPostSignMaterialFromRecord,
  listThresholdEcdsaSessionRecordsForWalletTarget,
  readExactThresholdEcdsaSessionRecord,
  toExactEcdsaSigningLaneIdentity,
  upsertRestoredThresholdEcdsaSessionRecord,
  upsertThresholdEcdsaSessionFact,
  type ConsumableEmailOtpEcdsaLane,
  type ConsumeSingleUseEmailOtpEcdsaLaneCommand,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/records';
import {
  buildVerifiedEcdsaPublicFacts,
  toEvmFamilyEcdsaKeyHandle,
} from '../../packages/sdk-web/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  buildEcdsaRoleLocalEmailOtpAuthMethod,
  buildEcdsaRoleLocalPublicFacts,
  buildEcdsaRoleLocalReadyRecord,
} from '../../packages/sdk-web/src/core/signingEngine/session/persistence/ecdsaRoleLocalRecords';

const WALLET_ID = toWalletId('alice.testnet');
const EVM_TARGET: EvmEip155ChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};
const SECOND_EVM_TARGET: EvmEip155ChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 1,
  networkSlug: 'ethereum',
};
const VALID_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_RELAYER_PUBLIC_KEY_B64U = 'AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const VALID_STATE_BLOB_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const SIGNING_ROOT_ID = 'signing-root';
const SIGNING_ROOT_VERSION = 'v1';
const EVM_FAMILY_SIGNING_KEY_SLOT_ID = deriveEvmFamilySigningKeySlotId({
  walletId: WALLET_ID,
  signingRootId: SIGNING_ROOT_ID,
  signingRootVersion: SIGNING_ROOT_VERSION,
});

function createStore(nowRef: { value: number } | number): ThresholdEcdsaSessionStoreDeps {
  return {
    recordsByLane: new Map(),
    exportArtifactsByLane: new Map(),
    now: () => (typeof nowRef === 'number' ? nowRef : nowRef.value),
  };
}

function ecdsaEmailOtpRecord(args: {
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses: number;
  updatedAtMs: number;
  chainTarget?: EvmEip155ChainTarget;
  ecdsaThresholdKeyId?: string;
}): ThresholdEcdsaSessionRecord {
  const keyHandle = toEvmFamilyEcdsaKeyHandle(
    `key-handle-${args.ecdsaThresholdKeyId || 'ecdsa-key-1'}`,
  );
  const participantIds = [1, 2];
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId || 'ecdsa-key-1';
  const chainTarget = args.chainTarget || EVM_TARGET;
  return {
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    chainTarget,
    relayerUrl: 'https://relay.example',
    keyHandle,
    ecdsaThresholdKeyId,
    signingRootId: SIGNING_ROOT_ID,
    signingRootVersion: SIGNING_ROOT_VERSION,
    relayerKeyId: 'relayer-key-1',
    clientVerifyingShareB64u: 'client-verifying-share',
    ecdsaRoleLocalReadyRecord: buildEcdsaRoleLocalReadyRecord({
      stateBlob: {
        kind: 'ecdsa_role_local_state_blob_v1',
        curve: 'secp256k1',
        encoding: 'base64url',
        producer: 'signer_core',
        stateBlobB64u: VALID_STATE_BLOB_B64U,
      },
      publicFacts: buildEcdsaRoleLocalPublicFacts({
        walletId: WALLET_ID,
        evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
        chainTarget,
        keyHandle,
        ecdsaThresholdKeyId,
        signingRootId: SIGNING_ROOT_ID,
        signingRootVersion: SIGNING_ROOT_VERSION,
        applicationBindingDigestB64u: VALID_STATE_BLOB_B64U,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds,
        contextBinding32B64u: VALID_STATE_BLOB_B64U,
        hssClientSharePublicKey33B64u: VALID_PUBLIC_KEY_B64U,
        relayerPublicKey33B64u: VALID_RELAYER_PUBLIC_KEY_B64U,
        groupPublicKey33B64u: VALID_PUBLIC_KEY_B64U,
        ethereumAddress: OWNER_ADDRESS,
      }),
      authMethod: buildEcdsaRoleLocalEmailOtpAuthMethod({
        authSubjectId: 'google:alice',
      }),
    }),
    participantIds,
    thresholdSessionKind: 'jwt',
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    walletSessionJwt: `jwt-${args.thresholdSessionId}`,
    expiresAtMs: 2_000_000_000_000,
    remainingUses: args.remainingUses,
    thresholdEcdsaPublicKeyB64u: VALID_PUBLIC_KEY_B64U,
    verifiedPublicFacts: buildVerifiedEcdsaPublicFacts({
      keyHandle,
      publicKeyB64u: VALID_PUBLIC_KEY_B64U,
      participantIds,
      thresholdOwnerAddress: OWNER_ADDRESS,
    }),
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: args.updatedAtMs,
    source: 'email_otp',
    emailOtpAuthContext: buildEmailOtpAuthContextForWalletAuthMethod({
      policy: 'per_operation',      provider: 'google',
      providerUserId: 'google:alice',
    }),
  };
}

function requireConsumableLane(record: ThresholdEcdsaSessionRecord): ConsumableEmailOtpEcdsaLane {
  const material = emailOtpEcdsaPostSignMaterialFromRecord(record);
  if (material?.kind !== 'consumable_email_otp_ecdsa_lane') {
    throw new Error(`expected consumable Email OTP ECDSA lane, got ${material?.kind || 'null'}`);
  }
  return material;
}

function consumeCommand(
  lane: ConsumableEmailOtpEcdsaLane,
): ConsumeSingleUseEmailOtpEcdsaLaneCommand {
  return {
    kind: 'consume_single_use_email_otp_ecdsa_lane',
    lane,
    uses: 1,
  };
}

function withSigningRootVersion(
  record: ThresholdEcdsaSessionRecord,
  signingRootVersion: string,
): ThresholdEcdsaSessionRecord {
  const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
    walletId: record.walletId,
    signingRootId: record.signingRootId,
    signingRootVersion,
  });
  const publicFacts = record.ecdsaRoleLocalReadyRecord.publicFacts;
  const readyRecord = buildEcdsaRoleLocalReadyRecord({
    stateBlob: record.ecdsaRoleLocalReadyRecord.stateBlob,
    publicFacts: buildEcdsaRoleLocalPublicFacts({
      walletId: publicFacts.walletId,
      evmFamilySigningKeySlotId,
      chainTarget: publicFacts.chainTarget,
      keyHandle: publicFacts.keyHandle,
      ecdsaThresholdKeyId: publicFacts.ecdsaThresholdKeyId,
      signingRootId: publicFacts.signingRootId,
      signingRootVersion,
      applicationBindingDigestB64u: publicFacts.applicationBindingDigestB64u,
      clientParticipantId: publicFacts.clientParticipantId,
      relayerParticipantId: publicFacts.relayerParticipantId,
      participantIds: publicFacts.participantIds,
      contextBinding32B64u: publicFacts.contextBinding32B64u,
      hssClientSharePublicKey33B64u: publicFacts.hssClientSharePublicKey33B64u,
      relayerPublicKey33B64u: publicFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: publicFacts.groupPublicKey33B64u,
      ethereumAddress: publicFacts.ethereumAddress,
    }),
    authMethod: record.ecdsaRoleLocalReadyRecord.authMethod,
  });
  return {
    ...record,
    evmFamilySigningKeySlotId,
    signingRootVersion,
    ecdsaRoleLocalReadyRecord: readyRecord,
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
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-b',
        thresholdSessionId: 'threshold-session-b',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );

    nowMs.value = 1_800_000_001_000;
    const consumed = consumeSingleUseEmailOtpEcdsaLane(
      store,
      consumeCommand(requireConsumableLane(selectedRecord)),
    );

    expect(consumed.kind).toBe('consumed');
    const records = listThresholdEcdsaSessionRecordsForWalletTarget(store, {
      walletId: WALLET_ID,
      chainTarget: EVM_TARGET,
      source: 'email_otp',
    });
    const recordsBySession = new Map(records.map((record) => [record.thresholdSessionId, record]));
    const consumedRecord = recordsBySession.get('threshold-session-a');
    if (!consumedRecord || consumedRecord.source !== 'email_otp') {
      throw new Error('expected consumed Email OTP ECDSA record');
    }
    expect(recordsBySession.get('threshold-session-a')?.remainingUses).toBe(0);
    expect(consumedRecord.emailOtpAuthContext.use).toEqual({
      kind: 'single_use_consumed',
      consumedAtMs: 1_800_000_001_000,
    });
    expect(recordsBySession.get('threshold-session-a')?.updatedAtMs).toBe(1_800_000_001_000);
    expect(recordsBySession.get('threshold-session-b')?.remainingUses).toBe(1);
    expect(recordsBySession.get('threshold-session-b')?.updatedAtMs).toBe(1_800_000_000_000);
  });

  test('returns missing_lane for an exact lane key that is absent', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    const command = consumeCommand(requireConsumableLane(selectedRecord));
    store.recordsByLane.delete(command.lane.laneRef.laneKey);

    expect(consumeSingleUseEmailOtpEcdsaLane(store, command)).toEqual({
      kind: 'missing_lane',
      laneKey: command.lane.laneRef.laneKey,
    });
  });

  test('returns already_consumed when the exact lane was consumed by an earlier call', () => {
    const nowMs = { value: 1_800_000_000_000 };
    const store = createStore(nowMs);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    const command = consumeCommand(requireConsumableLane(selectedRecord));

    nowMs.value = 1_800_000_001_000;
    expect(consumeSingleUseEmailOtpEcdsaLane(store, command).kind).toBe('consumed');
    expect(consumeSingleUseEmailOtpEcdsaLane(store, command)).toEqual({
      kind: 'already_consumed',
      laneKey: command.lane.laneRef.laneKey,
      consumedAtMs: 1_800_000_001_000,
    });
  });

  test('returns stale_record for updated-at mismatch before consumption', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    const command = consumeCommand(requireConsumableLane(selectedRecord));
    store.recordsByLane.set(command.lane.laneRef.laneKey, {
      ...selectedRecord,
      updatedAtMs: 1_800_000_000_123,
    });

    expect(consumeSingleUseEmailOtpEcdsaLane(store, command)).toEqual({
      kind: 'stale_record',
      laneKey: command.lane.laneRef.laneKey,
      reason: 'updated_at_mismatch',
    });
  });

  test('returns stale_record when stored single-use remainingUses is not exactly one', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    const command = consumeCommand(requireConsumableLane(selectedRecord));
    store.recordsByLane.set(command.lane.laneRef.laneKey, {
      ...selectedRecord,
      remainingUses: 2,
    });

    expect(consumeSingleUseEmailOtpEcdsaLane(store, command)).toEqual({
      kind: 'stale_record',
      laneKey: command.lane.laneRef.laneKey,
      reason: 'remaining_uses_mismatch',
    });
  });

  test('returns stale_record for chain target and key identity command mismatches', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    const selectedLane = requireConsumableLane(selectedRecord);
    const otherKeyRecord = ecdsaEmailOtpRecord({
      signingGrantId: 'wallet-session-b',
      thresholdSessionId: 'threshold-session-b',
      remainingUses: 1,
      updatedAtMs: 1_800_000_000_000,
      chainTarget: SECOND_EVM_TARGET,
      ecdsaThresholdKeyId: 'ecdsa-key-2',
    });
    const otherLane = requireConsumableLane(otherKeyRecord);

    const chainMismatchLane: ConsumableEmailOtpEcdsaLane = {
      ...selectedLane,
      laneRef: {
        ...selectedLane.laneRef,
        exactIdentity: {
          ...selectedLane.laneRef.exactIdentity,
          signer: {
            ...selectedLane.laneRef.exactIdentity.signer,
            chainTarget: SECOND_EVM_TARGET,
          },
        },
      },
    };
    expect(consumeSingleUseEmailOtpEcdsaLane(store, consumeCommand(chainMismatchLane))).toEqual({
      kind: 'stale_record',
      laneKey: selectedLane.laneRef.laneKey,
      reason: 'chain_target_mismatch',
    });

    const keyHandleMismatchLane: ConsumableEmailOtpEcdsaLane = {
      ...selectedLane,
      laneRef: {
        ...selectedLane.laneRef,
        exactIdentity: {
          ...selectedLane.laneRef.exactIdentity,
          signer: {
            ...selectedLane.laneRef.exactIdentity.signer,
            keyHandle: otherLane.laneRef.exactIdentity.signer.keyHandle,
          },
        },
      },
    };
    expect(
      consumeSingleUseEmailOtpEcdsaLane(store, consumeCommand(keyHandleMismatchLane)),
    ).toEqual({
      kind: 'stale_record',
      laneKey: selectedLane.laneRef.laneKey,
      reason: 'key_handle_mismatch',
    });

    const keyMismatchLane: ConsumableEmailOtpEcdsaLane = {
      ...selectedLane,
      laneRef: {
        ...selectedLane.laneRef,
        exactIdentity: {
          ...selectedLane.laneRef.exactIdentity,
          signer: {
            ...selectedLane.laneRef.exactIdentity.signer,
            key: otherLane.laneRef.exactIdentity.signer.key,
          },
        },
      },
    };
    expect(consumeSingleUseEmailOtpEcdsaLane(store, consumeCommand(keyMismatchLane))).toEqual({
      kind: 'stale_record',
      laneKey: selectedLane.laneRef.laneKey,
      reason: 'key_identity_mismatch',
    });
  });

  test('reads the exact ECDSA session record without treating mirrored runtime memory as a duplicate', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );

    const read = readExactThresholdEcdsaSessionRecord(
      store,
      toExactEcdsaSigningLaneIdentity(selectedRecord),
    );

    expect(read.kind).toBe('found');
    if (read.kind !== 'found') {
      throw new Error(`expected exact ECDSA record, got ${read.kind}`);
    }
    expect(read.record.thresholdSessionId).toBe('threshold-session-a');
  });

  test('reads the intended exact ECDSA record when unrelated lanes share a threshold session id', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-shared',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-b',
        thresholdSessionId: 'threshold-session-shared',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_123,
        chainTarget: SECOND_EVM_TARGET,
      }),
    );

    const read = readExactThresholdEcdsaSessionRecord(
      store,
      toExactEcdsaSigningLaneIdentity(selectedRecord),
    );

    expect(read.kind).toBe('found');
    if (read.kind !== 'found') {
      throw new Error(`expected exact ECDSA record, got ${read.kind}`);
    }
    expect(read.record.signingGrantId).toBe('wallet-session-a');
    expect(read.record.chainTarget).toEqual(EVM_TARGET);
  });

  test('ignores broad ECDSA lanes with conflicting key identity facts during exact lookup', () => {
    const store = createStore(1_800_000_000_000);
    const selectedRecord = upsertThresholdEcdsaSessionFact(
      store,
      ecdsaEmailOtpRecord({
        signingGrantId: 'wallet-session-a',
        thresholdSessionId: 'threshold-session-a',
        remainingUses: 1,
        updatedAtMs: 1_800_000_000_000,
      }),
    );
    upsertRestoredThresholdEcdsaSessionRecord(withSigningRootVersion(selectedRecord, 'v2'));

    const read = readExactThresholdEcdsaSessionRecord(
      store,
      toExactEcdsaSigningLaneIdentity(selectedRecord),
    );

    expect(read.kind).toBe('found');
    if (read.kind !== 'found') {
      throw new Error(`expected exact ECDSA record, got ${read.kind}`);
    }
    expect(read.record.signingRootVersion).toBe('v1');
  });
});
