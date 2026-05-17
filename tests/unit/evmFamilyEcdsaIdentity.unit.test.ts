import { expect, test } from '@playwright/test';
import { toAccountId } from '../../client/src/core/types/accountIds';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../client/src/core/signingEngine/interfaces/signing';
import {
  buildEvmFamilyEcdsaKeyIdentityFromKeyRef,
  buildEvmFamilyEcdsaKeyIdentityFromRecord,
  deriveEvmFamilyKeyFingerprint,
  resolveReadyEvmFamilyEcdsaMaterial,
} from '../../client/src/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  toWalletSubjectId,
  type ThresholdEcdsaChainTarget,
} from '../../client/src/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  getThresholdEcdsaKeyRefByKey,
  getThresholdEcdsaSessionRecordByKey,
  listThresholdEcdsaRuntimeLanesForSubject,
  thresholdEcdsaSessionRecordReadModel,
  upsertStoredThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionRecord,
  type ThresholdEcdsaSessionStoreDeps,
} from '../../client/src/core/signingEngine/session/persistence/records';
import { selectedEcdsaLane } from '../../client/src/core/signingEngine/session/identity/laneIdentity';

const WALLET_ID = toAccountId('alice.testnet');
const SUBJECT_ID = toWalletSubjectId('wallet-subject-alice');
const OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const OTHER_OWNER_ADDRESS = '0x2222222222222222222222222222222222222222';
const RP_ID = 'localhost';

const EVM_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};

const TEMPO_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
};

function makeRecord(
  overrides: Partial<ThresholdEcdsaSessionRecord> = {},
): ThresholdEcdsaSessionRecord {
  return {
    walletId: WALLET_ID,
    subjectId: SUBJECT_ID,
    rpId: RP_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-shared-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    relayerKeyId: 'relayer-key',
    clientVerifyingShareB64u: 'client-verifying-share',
    participantIds: [2, 1],
    thresholdSessionKind: 'jwt',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    thresholdSessionAuthToken: 'threshold-auth-token',
    expiresAtMs: 1_900_000_000_000,
    remainingUses: 3,
    thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
    ethereumAddress: OWNER_ADDRESS,
    updatedAtMs: 1_800_000_000_000,
    source: 'login',
    ...overrides,
  };
}

function makeKeyRef(
  overrides: Partial<ThresholdEcdsaSecp256k1KeyRef> = {},
): ThresholdEcdsaSecp256k1KeyRef {
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: WALLET_ID,
    subjectId: SUBJECT_ID,
    chainTarget: EVM_TARGET,
    relayerUrl: 'https://relay.localhost',
    ecdsaThresholdKeyId: 'ehss-shared-key',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    backendBinding: {
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
    },
    participantIds: [1, 2],
    thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
    ethereumAddress: OWNER_ADDRESS,
    thresholdSessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-auth-token',
    thresholdSessionId: 'threshold-session-1',
    walletSigningSessionId: 'wallet-signing-session-1',
    ...overrides,
  };
}

test.describe('EVM-family ECDSA identity', () => {
  test('derives one shared fingerprint across Tempo and Arc/EVM session lanes', () => {
    const evmKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm',
        walletSigningSessionId: 'wallet-session-evm',
      }),
      rpId: RP_ID,
    });
    const tempoKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'threshold-session-tempo',
        walletSigningSessionId: 'wallet-session-tempo',
      }),
      rpId: RP_ID,
    });

    expect(evmKey.ecdsaThresholdKeyId).toBe(tempoKey.ecdsaThresholdKeyId);
    expect(evmKey.thresholdOwnerAddress).toBe(tempoKey.thresholdOwnerAddress);
    expect(deriveEvmFamilyKeyFingerprint(evmKey)).toBe(
      deriveEvmFamilyKeyFingerprint(tempoKey),
    );
  });

  test('normalizes participant order before fingerprinting shared key identity', () => {
    const recordKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord({ participantIds: [2, 1] }),
      rpId: RP_ID,
    });
    const keyRefKey = buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
      keyRef: makeKeyRef({ participantIds: [1, 2] }),
      rpId: RP_ID,
    });

    expect(recordKey.participantIds.map(Number)).toEqual([1, 2]);
    expect(deriveEvmFamilyKeyFingerprint(recordKey)).toBe(
      deriveEvmFamilyKeyFingerprint(keyRefKey),
    );
  });

  test('changes the shared fingerprint when stable EVM-family key fields change', () => {
    const baseKey = buildEvmFamilyEcdsaKeyIdentityFromRecord({
      record: makeRecord(),
      rpId: RP_ID,
    });
    const baseFingerprint = deriveEvmFamilyKeyFingerprint(baseKey);
    const variants = [
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord(),
        rpId: 'wallet.other.test',
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ signingRootId: 'project:other' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ signingRootVersion: 'v2' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ participantIds: [1, 2, 3] }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ecdsaThresholdKeyId: 'ehss-other-key' }),
        rpId: RP_ID,
      }),
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
      }),
    ];

    for (const variant of variants) {
      expect(deriveEvmFamilyKeyFingerprint(variant)).not.toBe(baseFingerprint);
    }
  });

  test('rejects ready material when record and keyRef owner addresses drift', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef({ ethereumAddress: OTHER_OWNER_ADDRESS }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('owner_address_mismatch');
  });

  test('rejects ready material when record and keyRef wallet ids drift', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef({ userId: toAccountId('mallory.testnet') }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('wallet_mismatch');
  });

  test('rejects ready material when paired material belongs to another wallet', () => {
    const otherWallet = toAccountId('mallory.testnet');
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord({ walletId: otherWallet }),
      keyRef: makeKeyRef({ userId: otherWallet }),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'identity_mismatch') {
      throw new Error(`expected identity_mismatch, got ${result.kind}`);
    }
    expect(result.reason.kind).toBe('wallet_mismatch');
    expect(result.reason.expected).toBe(WALLET_ID);
    expect(result.reason.actual).toBe(otherWallet);
  });

  test('record builder rejects persisted owner address when trusted key-ref owner disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/persisted owner address mismatches trusted EVM-family key material/);
  });

  test('key-ref builder rejects owner address when trusted key material disagrees', () => {
    expect(() =>
      buildEvmFamilyEcdsaKeyIdentityFromKeyRef({
        keyRef: makeKeyRef({ ethereumAddress: OTHER_OWNER_ADDRESS }),
        rpId: RP_ID,
        trustedOwnerAddress: OWNER_ADDRESS,
      }),
    ).toThrow(/key ref owner address mismatches trusted EVM-family key material/);
  });

  test('returns stale before ready material can reach signing', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord({ remainingUses: 0 }),
      keyRef: makeKeyRef(),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'stale') {
      throw new Error(`expected stale, got ${result.kind}`);
    }
    expect(result.reason.reason).toBe('exhausted');
  });

  test('resolves ready material only for the exact concrete session lane', () => {
    const result = resolveReadyEvmFamilyEcdsaMaterial({
      record: makeRecord(),
      keyRef: makeKeyRef(),
      rpId: RP_ID,
      expected: {
        walletId: WALLET_ID,
        subjectId: SUBJECT_ID,
        chainTarget: EVM_TARGET,
        authMethod: 'passkey',
        source: 'login',
        thresholdSessionId: 'threshold-session-1',
        walletSigningSessionId: 'wallet-signing-session-1',
      },
      nowMs: 1_800_000_000_000,
    });

    if (result.kind !== 'ready') {
      throw new Error(`expected ready, got ${result.kind}`);
    }
    expect(result.material.key.thresholdOwnerAddress).toBe(OWNER_ADDRESS);
    expect(result.material.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(result.material.lane.chainTarget).toEqual(EVM_TARGET);
  });

  test('normalizes persisted ECDSA reads into shared key identity plus concrete lane', () => {
    const readModel = thresholdEcdsaSessionRecordReadModel(
      makeRecord({
        participantIds: [2, 1],
        ethereumAddress: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }),
    );

    expect(readModel.key.rpId).toBe(RP_ID);
    expect(readModel.key.keyScope).toBe('evm-family');
    expect(readModel.key.participantIds.map(Number)).toEqual([1, 2]);
    expect(readModel.key.thresholdOwnerAddress).toBe(
      '0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    );
    expect(readModel.lane.key).toBe(readModel.key);
    expect(readModel.lane.chainTarget).toEqual(EVM_TARGET);
    expect(readModel.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(readModel.lane.walletSigningSessionId).toBe('wallet-signing-session-1');
  });

  test('runtime ECDSA lane listing returns the canonical record read model', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        participantIds: [2, 1],
        ethereumAddress: '0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB',
      }),
    );

    const [lane] = listThresholdEcdsaRuntimeLanesForSubject(deps, {
      subjectId: SUBJECT_ID,
    });

    expect(lane).toBeDefined();
    expect(lane?.key.thresholdOwnerAddress).toBe(
      '0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    );
    expect(lane?.key.participantIds.map(Number)).toEqual([1, 2]);
    expect(lane?.lane.key).toBe(lane?.key);
    expect(lane?.lane.thresholdSessionId).toBe('threshold-session-1');
    expect(lane?.key.rpId).toBe(RP_ID);
  });

  test('client store allows one shared key identity across EVM-family concrete lanes', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        signingRootId: 'project:client-shared-key',
        chainTarget: EVM_TARGET,
        thresholdSessionId: 'threshold-session-evm-shared',
        walletSigningSessionId: 'wallet-session-evm-shared',
      }),
    );

    expect(() =>
      upsertStoredThresholdEcdsaSessionRecord(
        deps,
        makeRecord({
          signingRootId: 'project:client-shared-key',
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'threshold-session-tempo-shared',
          walletSigningSessionId: 'wallet-session-tempo-shared',
        }),
      ),
    ).not.toThrow();
  });

  test('client store rejects a second key identity for the same EVM-family signing root', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    upsertStoredThresholdEcdsaSessionRecord(
      deps,
      makeRecord({
        signingRootId: 'project:client-conflict-key',
        thresholdSessionId: 'threshold-session-first-key',
        walletSigningSessionId: 'wallet-session-first-key',
      }),
    );

    expect(() =>
      upsertStoredThresholdEcdsaSessionRecord(
        deps,
        makeRecord({
          signingRootId: 'project:client-conflict-key',
          chainTarget: TEMPO_TARGET,
          ecdsaThresholdKeyId: 'ehss-conflicting-key',
          thresholdSessionId: 'threshold-session-second-key',
          walletSigningSessionId: 'wallet-session-second-key',
        }),
      ),
    ).toThrow(/EVM-family ECDSA key identity/);
  });

  test('exact ECDSA lookup rejects a selected lane with the wrong wallet identity', () => {
    const deps: ThresholdEcdsaSessionStoreDeps = {
      recordsByLane: new Map(),
      now: () => 1_800_000_000_000,
    };
    const record = makeRecord();
    const key = buildEvmFamilyEcdsaKeyIdentityFromRecord({ record, rpId: RP_ID });
    upsertStoredThresholdEcdsaSessionRecord(deps, record);
    const matchingLane = selectedEcdsaLane({
      key,
      walletId: WALLET_ID,
      authMethod: 'passkey',
      walletSigningSessionId: 'wallet-signing-session-1',
      thresholdSessionId: 'threshold-session-1',
      subjectId: SUBJECT_ID,
      chainTarget: EVM_TARGET,
      ecdsaThresholdKeyId: 'ehss-shared-key',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
    });
    const wrongWalletLane = selectedEcdsaLane({
      ...matchingLane,
      key: buildEvmFamilyEcdsaKeyIdentityFromRecord({
        record: makeRecord({ walletId: toAccountId('mallory.testnet') }),
        rpId: RP_ID,
      }),
      walletId: toAccountId('mallory.testnet'),
    });

    expect(getThresholdEcdsaSessionRecordByKey(deps, matchingLane)?.walletId).toBe(WALLET_ID);
    expect(getThresholdEcdsaKeyRefByKey(deps, matchingLane)?.keyRef.userId).toBe(WALLET_ID);
    expect(getThresholdEcdsaSessionRecordByKey(deps, wrongWalletLane)).toBeNull();
    expect(getThresholdEcdsaKeyRefByKey(deps, wrongWalletLane)).toBeNull();
  });
});
