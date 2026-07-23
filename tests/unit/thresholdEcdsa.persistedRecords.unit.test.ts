import { expect, test } from '@playwright/test';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import {
  parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow,
  parseCurrentThresholdEd25519KeyRecord,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/persistedRecords';
import {
  createThresholdEcdsaKeyStore,
  createThresholdEd25519KeyStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/KeyStore';
import { parseEcdsaDerivationRoleLocalKeyRecord } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../packages/sdk-server-ts/src/core/types';
import { ThresholdStoreDurableObject } from '../../packages/sdk-server-ts/src/router/cloudflare/durableObjects/thresholdStore';
import { makeEcdsaDerivationRoleLocalKeyRecord } from './helpers/signingSessionRecord.fixtures';

const ed25519AuthorityScope = { kind: 'passkey_rp' as const, rpId: 'example.localhost' };

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

test.describe('threshold ecdsa persisted records', () => {
  test('parses current Ed25519 records and role-local ECDSA derivation records', async () => {
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        kind: 'ready',
        walletId: 'frost-vermillion-k7p9m2',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
        authorityScope: ed25519AuthorityScope,
        publicKey: 'ed25519:public',
        routerMaterial: {
          signingShareB64u: 'signing-share',
          verifyingShareB64u: 'verifying-share',
        },
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toEqual({
      kind: 'ready',
      walletId: 'frost-vermillion-k7p9m2',
      nearAccountId: 'alice.testnet',
      nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
      authorityScope: ed25519AuthorityScope,
      publicKey: 'ed25519:public',
      routerMaterial: {
        signingShareB64u: 'signing-share',
        verifyingShareB64u: 'verifying-share',
      },
      keyVersion: 'key-v1',
      recoveryExportCapable: true,
    });
    expect(
      parseCurrentThresholdEd25519KeyRecord({
        kind: 'ready',
        walletId: 'frost-vermillion-k7p9m2',
        nearAccountId: 'alice.testnet',
        nearEd25519SigningKeyId: 'near-ed25519-frost-vermillion-k7p9m2',
        rpId: 'example.localhost',
        publicKey: 'ed25519:public',
        routerMaterial: {
          signingShareB64u: 'signing-share',
          verifyingShareB64u: 'verifying-share',
        },
        keyVersion: 'key-v1',
        recoveryExportCapable: true,
      }),
    ).toBeNull();

    const roleLocalRecord = await makeEcdsaDerivationRoleLocalKeyRecord();
    expect(parseEcdsaDerivationRoleLocalKeyRecord(roleLocalRecord)).toEqual(roleLocalRecord);
    expect(
      parseEcdsaDerivationRoleLocalKeyRecord({
        ...roleLocalRecord,
        unexpectedField: 'rejected',
      }),
    ).toBeNull();
    expect(
      parseEcdsaDerivationRoleLocalKeyRecord({
        version: 'threshold_ecdsa_derivation_key_v1',
        ecdsaThresholdKeyId: 'threshold-key',
        relayerRootShare32B64u: b64uBytes(32, 11),
        relayerBackendInputB64u: b64uBytes(32, 12),
      }),
    ).toBeNull();
  });

  test('rejects obsolete or malformed presign session rows', () => {
    const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
      walletId: 'alice.testnet',
      signingRootId: 'signing-root',
      signingRootVersion: 'default',
    });
    expect(
      parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow({
        recordJson: {
          expiresAtMs: 999_999,
          walletId: 'alice.testnet',
          evmFamilySigningKeySlotId,
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
          signingRootVersion: 'default',
          walletKeyVersion: 'wallet-key-v1',
          derivationVersion: 1,
        },
        expiresAtMs: 999_999,
      }),
    ).toBeNull();

    expect(
      parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow({
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

  });

  test('server key store rejects a second shared EVM-family role-local key identity', async () => {
    const store = createThresholdEcdsaKeyStore({
      config: { kind: 'in-memory' },
      logger: normalizeLogger(null),
      isNode: true,
    });
    const first = await makeEcdsaDerivationRoleLocalKeyRecord({
      signingRootId: 'server-shared-root',
    });
    await store.putRoleLocalByKeyHandle(first);

    const conflicting = await makeEcdsaDerivationRoleLocalKeyRecord({
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
    const first = await makeEcdsaDerivationRoleLocalKeyRecord({
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
    const record = await makeEcdsaDerivationRoleLocalKeyRecord({
      keyHandle: 'ederivation-key-wrong',
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
    const first = await makeEcdsaDerivationRoleLocalKeyRecord({
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
