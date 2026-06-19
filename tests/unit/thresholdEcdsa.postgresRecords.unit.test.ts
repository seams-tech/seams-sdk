import { expect, test } from '@playwright/test';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseCurrentRouterAbEcdsaHssPoolFillSessionRow,
  parseCurrentRouterAbEcdsaHssServerPresignatureRecord,
  parseCurrentThresholdEd25519KeyRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/postgresRecords';
import { createThresholdEcdsaKeyStore } from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore';
import { parseEcdsaHssRoleLocalKeyRecord } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaHssRoleLocalKeyRecord,
} from '../../packages/sdk-server-ts/src/core/types';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';

type TestDurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction<T>(fn: (txn: TestDurableObjectStorageLike) => Promise<T>): Promise<T>;
};

function b64uBytes(length: number, lastByte: number, firstByte = 0): string {
  const bytes = Buffer.alloc(length, 0);
  bytes[0] = firstByte;
  bytes[length - 1] = lastByte;
  return bytes.toString('base64url');
}

function publicKey33B64u(lastByte: number, prefix: 0x02 | 0x03 = 0x02): string {
  return b64uBytes(33, lastByte, prefix);
}

async function makeRoleLocalKeyRecord(
  overrides: Partial<EcdsaHssRoleLocalKeyRecord> = {},
): Promise<EcdsaHssRoleLocalKeyRecord> {
  const base = {
    version: 'threshold_ecdsa_hss_role_local_v2',
    ecdsaThresholdKeyId: 'threshold-key',
    walletId: 'alice.testnet',
    rpId: 'example.localhost',
    signingRootId: 'signing-root',
    signingRootVersion: 'default',
    keyScope: 'evm-family',
    relayerKeyId: 'relayer-key',
    contextBinding32B64u: b64uBytes(32, 1),
    relayerShare32B64u: b64uBytes(32, 2),
    relayerPublicKey33B64u: publicKey33B64u(3),
    clientPublicKey33B64u: publicKey33B64u(4, 0x03),
    groupPublicKey33B64u: publicKey33B64u(5),
    ethereumAddress: '0x1111111111111111111111111111111111111111',
    relayerCaitSithInput: {
      participantId: 2,
      mappedPrivateShare32B64u: b64uBytes(32, 6),
      verifyingShare33B64u: publicKey33B64u(7, 0x03),
    },
    publicTranscriptDigest32B64u: b64uBytes(32, 8),
    createdAtMs: 100,
    updatedAtMs: 200,
    ...overrides,
  } satisfies Omit<EcdsaHssRoleLocalKeyRecord, 'keyHandle'> & { keyHandle?: string };
  const keyHandle =
    overrides.keyHandle ??
    String(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId: base.ecdsaThresholdKeyId,
        signingRootId: base.signingRootId,
        signingRootVersion: base.signingRootVersion,
      }),
    );
  const parsed = parseEcdsaHssRoleLocalKeyRecord({ ...base, keyHandle });
  if (!parsed) throw new Error('test fixture must be a role-local threshold ECDSA key record');
  return parsed;
}

function createMemoryDurableObjectNamespace(): CloudflareDurableObjectNamespaceLike {
  const objects = new Map<string, CloudflareDurableObjectStubLike>();
  return {
    idFromName: (name: string) => name,
    get: (id: unknown) => {
      const key = String(id);
      const existing = objects.get(key);
      if (existing) return existing;

      const storageMap = new Map<string, unknown>();
      const storage: TestDurableObjectStorageLike = {
        get: async (storageKey) => storageMap.get(storageKey) ?? null,
        put: async (storageKey, value) => {
          storageMap.set(storageKey, value);
        },
        delete: async (storageKey) => storageMap.delete(storageKey),
        transaction: async (fn) => await fn(storage),
      };
      const durableObject = new ThresholdStoreDurableObject({ storage }, {});
      const stub: CloudflareDurableObjectStubLike = {
        fetch: async (request, init) =>
          durableObject.fetch(request instanceof Request ? request : new Request(request, init)),
      };
      objects.set(key, stub);
      return stub;
    },
  };
}

test.describe('threshold ecdsa postgres records', () => {
  test('parses current Ed25519 records and role-local ECDSA HSS records', async () => {
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        nearAccountId: 'alice.testnet',
        rpId: 'example.localhost',
        publicKey: 'ed25519:public',
        relayerSigningShareB64u: 'signing-share',
        relayerVerifyingShareB64u: 'verifying-share',
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toEqual({
      nearAccountId: 'alice.testnet',
      rpId: 'example.localhost',
      publicKey: 'ed25519:public',
      relayerSigningShareB64u: 'signing-share',
      relayerVerifyingShareB64u: 'verifying-share',
      keyVersion: 'key-v1',
      recoveryExportCapable: true,
    });

    const roleLocalRecord = await makeRoleLocalKeyRecord({
      relayerCaitSithInput: {
        participantId: 2,
        mappedPrivateShare32B64u: b64uBytes(32, 9),
        verifyingShare33B64u: publicKey33B64u(10, 0x03),
      },
    });
    expect(parseEcdsaHssRoleLocalKeyRecord(roleLocalRecord)).toEqual(roleLocalRecord);
    for (const field of [
      'subjectId',
      'walletSessionUserId',
      'subject_id',
      'wallet_session_user_id',
    ] as const) {
      expect(parseEcdsaHssRoleLocalKeyRecord({ ...roleLocalRecord, [field]: 'stale' })).toBeNull();
    }
    expect(
      parseEcdsaHssRoleLocalKeyRecord({
        ...roleLocalRecord,
        relayerCaitSithInput: { ...roleLocalRecord.relayerCaitSithInput, participantId: 1 },
      }),
    ).toBeNull();
    expect(
      parseEcdsaHssRoleLocalKeyRecord({
        version: 'threshold_ecdsa_hss_key_v1',
        ecdsaThresholdKeyId: 'threshold-key',
        relayerRootShare32B64u: b64uBytes(32, 11),
        relayerBackendInputB64u: b64uBytes(32, 12),
      }),
    ).toBeNull();
  });

  test('rejects malformed presign session rows and presignatures', () => {
    expect(
      parseCurrentRouterAbEcdsaHssPoolFillSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerKeyId: 'relayer-key',
          presignPoolKey: 'keyHandle:threshold-key',
          poolFill: { kind: 'local_threshold_ecdsa_presignature_pool' },
          participantIds: [2, 1],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 150,
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toEqual({
      record: {
        expiresAtMs: 999_999,
        walletSessionUserId: 'alice.testnet',
        rpId: 'example.localhost',
        relayerKeyId: 'relayer-key',
        presignPoolKey: 'keyHandle:threshold-key',
        poolFill: { kind: 'local_threshold_ecdsa_presignature_pool' },
        participantIds: [1, 2],
        clientParticipantId: 1,
        relayerParticipantId: 2,
        stage: 'triples',
        version: 1,
        createdAtMs: 100,
        updatedAtMs: 150,
        signingRootId: 'signing-root',
        walletKeyVersion: 'wallet-key-v1',
        derivationVersion: 1,
      },
      expiresAtMs: 999_999,
    });

    expect(
      parseCurrentRouterAbEcdsaHssPoolFillSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          userId: 'alice.testnet',
          rpId: 'example.localhost',
          relayerKeyId: 'relayer-key',
          presignPoolKey: 'keyHandle:threshold-key',
          participantIds: [1, 2],
          clientParticipantId: 1,
          relayerParticipantId: 2,
          stage: 'triples',
          version: 1,
          createdAtMs: 100,
          updatedAtMs: 99,
          signingRootId: 'signing-root',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toBeNull();

    expect(
      parseCurrentRouterAbEcdsaHssServerPresignatureRecord({
        relayerKeyId: 'relayer-key',
        presignatureId: 'presignature',
        bigRB64u: 'big-r',
        kShareB64u: 'k-share',
        sigmaShareB64u: 'sigma-share',
        createdAtMs: 123,
      }),
    ).toEqual({
      relayerKeyId: 'relayer-key',
      presignatureId: 'presignature',
      bigRB64u: 'big-r',
      kShareB64u: 'k-share',
      sigmaShareB64u: 'sigma-share',
      createdAtMs: 123,
    });

    expect(
      parseCurrentRouterAbEcdsaHssServerPresignatureRecord({
        relayerKeyId: 'relayer-key',
        presignatureId: 'presignature',
        bigRB64u: 'big-r',
        kShareB64u: 'k-share',
        sigmaShareB64u: 'sigma-share',
        createdAtMs: 0,
      }),
    ).toBeNull();
  });

  test('server key store rejects a second shared EVM-family role-local key identity', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: { kind: 'in-memory' },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const first = await makeRoleLocalKeyRecord({
      signingRootId: 'server-shared-root',
    });
    await store.putRoleLocalByKeyHandle(first);

    const conflicting = await makeRoleLocalKeyRecord({
      ecdsaThresholdKeyId: 'threshold-key-conflict',
      relayerKeyId: 'relayer-key-conflict',
      signingRootId: 'server-shared-root',
      updatedAtMs: 201,
    });
    await expect(store.putRoleLocalByKeyHandle(conflicting)).rejects.toThrow(
      /EVM-family key identity/,
    );
  });

  test('server key store persists canonical role-local key handles', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: { kind: 'in-memory' },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const first = await makeRoleLocalKeyRecord({
      signingRootId: 'server-handle-root',
    });
    await store.putRoleLocalByKeyHandle(first);

    const expectedHandle = String(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
        signingRootId: first.signingRootId,
        signingRootVersion: first.signingRootVersion,
      }),
    );
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toMatchObject({
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      keyHandle: expectedHandle,
    });

    await store.deleteByKeyHandle(expectedHandle);
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toBeNull();

    await store.putRoleLocalByKeyHandle(first);
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toMatchObject({
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      keyHandle: expectedHandle,
    });
  });

  test('server key store rejects role-local key handles that do not match key identity', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: { kind: 'in-memory' },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const record = await makeRoleLocalKeyRecord({
      keyHandle: 'ehss-key-wrong',
    });

    await expect(store.putRoleLocalByKeyHandle(record)).rejects.toThrow(
      /key handle does not match threshold key identity/,
    );
  });

  test('Cloudflare Durable Object server key store guards canonical role-local key handles', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: {
        kind: 'cloudflare-do',
        namespace: createMemoryDurableObjectNamespace(),
        name: 'ecdsa-key-handle-test',
      },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const first = await makeRoleLocalKeyRecord({
      ecdsaThresholdKeyId: 'cloudflare-threshold-key',
      relayerKeyId: 'cloudflare-relayer-key',
      signingRootId: 'cloudflare-server-handle-root',
    });
    await store.putRoleLocalByKeyHandle(first);

    const expectedHandle = String(
      await deriveThresholdEcdsaKeyHandle({
        ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
        signingRootId: first.signingRootId,
        signingRootVersion: first.signingRootVersion,
      }),
    );
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toMatchObject({
      ecdsaThresholdKeyId: first.ecdsaThresholdKeyId,
      keyHandle: expectedHandle,
    });

    await store.deleteByKeyHandle(expectedHandle);
    await expect(
      store.putRoleLocalByKeyHandle({
        ...first,
        updatedAtMs: 203,
      }),
    ).resolves.toBeUndefined();
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toMatchObject({
      keyHandle: expectedHandle,
    });

    await store.deleteByKeyHandle(expectedHandle);
    await expect(store.getRoleLocalByKeyHandle(expectedHandle)).resolves.toBeNull();
  });
});
