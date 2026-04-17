import { expect, test } from '@playwright/test';
import type { AuthService } from '../../server/src/core/AuthService';
import {
  createConfiguredSigningRootShareResolver,
  createThresholdSigningService,
} from '../../server/src/core/ThresholdService';
import { createConfiguredSigningRootSecretResolver } from '../../server/src/core/ThresholdService/signingRootSecretConfig';
import type { SigningRootSecretShareKekResolutionInput } from '../../server/src/core/ThresholdService/signingRootSecretSealing';
import { InMemorySigningRootSecretStore } from '../../server/src/core/ThresholdService/stores/SigningRootSecretStore';
import type { ThresholdStoreConfigInput } from '../../server/src/core/types';

function createAuthServiceMock(): AuthService {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
    viewAccessKeyList: async () => ({ keys: [] }),
  } as unknown as AuthService;
}

test('signing-root resolver config composes store and KEK resolver', async () => {
  const store = new InMemorySigningRootSecretStore();
  const resolverCalls: string[] = [];
  const resolver = createConfiguredSigningRootSecretResolver({
    signingRootSecretShareStore: store,
    signingRootSecretShareKekResolver: async (input: SigningRootSecretShareKekResolutionInput) => {
      resolverCalls.push(input.kekId);
      return new Uint8Array(32).fill(0x42);
    },
  });

  expect(resolver).not.toBeNull();
  expect(await resolver!.listSealedSigningRootSecretShares({ signingRootId: 'missing' })).toEqual([]);
  await expect(
    resolver!.decryptSigningRootSecretShare({
      signingRootId: 'project-alpha',
      shareId: 1,
      kekId: 'kek-v1',
      sealedShare: new Uint8Array([0x00]),
    }),
  ).rejects.toThrow();
  expect(resolverCalls).toEqual([]);
});

test('signing-root resolver config composes storage and decrypt adapters', async () => {
  const store = new InMemorySigningRootSecretStore();
  const decryptCalls: number[] = [];
  const resolver = createConfiguredSigningRootSecretResolver({
    signingRootSecretResolverAdapters: {
      storageAdapter: store,
      decryptAdapter: {
        adapterKind: 'aws-kms',
        decryptSigningRootSecretShare: async (record) => {
          decryptCalls.push(record.shareId);
          return new Uint8Array([record.shareId, ...new Uint8Array(32)]);
        },
      },
    },
  });

  expect(resolver).not.toBeNull();
  expect(await resolver!.listSealedSigningRootSecretShares({ signingRootId: 'missing' })).toEqual([]);
  const decrypted = await resolver!.decryptSigningRootSecretShare({
    signingRootId: 'project-alpha',
    shareId: 1,
    kekId: 'kms-key-v1',
    sealedShare: new Uint8Array([0x00]),
  });
  expect(decrypted[0]).toBe(1);
  expect(decrypted.length).toBe(33);
  expect(decryptCalls).toEqual([1]);
});

test('signing-root resolver config accepts store plus external decrypt adapter', async () => {
  const store = new InMemorySigningRootSecretStore();
  const resolver = createConfiguredSigningRootSecretResolver({
    signingRootSecretShareStore: store,
    signingRootSecretShareDecryptAdapter: {
      adapterKind: 'tee',
      decryptSigningRootSecretShare: async (record) =>
        new Uint8Array([record.shareId, ...new Uint8Array(32)]),
    },
  });

  expect(resolver).not.toBeNull();
  const decrypted = await resolver!.decryptSigningRootSecretShare({
    signingRootId: 'project-alpha',
    shareId: 2,
    kekId: 'tee-key-v1',
    sealedShare: new Uint8Array([0x00]),
  });
  expect(decrypted[0]).toBe(2);
  expect(decrypted.length).toBe(33);
});

test('threshold signing service reports signing-root resolver configured from server SDK config', () => {
  const thresholdConfig: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    signingRootSecretStore: new InMemorySigningRootSecretStore(),
    signingRootSecretShareKekResolver: async () => new Uint8Array(32).fill(0x42),
  };

  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: thresholdConfig,
    isNode: true,
  });

  expect(service.hasSigningRootShareResolver()).toBe(true);
});

test('signing-root share resolver config composes storage and decrypt adapters', async () => {
  const store = new InMemorySigningRootSecretStore();
  const decryptCalls: number[] = [];
  const resolver = createConfiguredSigningRootShareResolver({
    signingRootSecretResolverAdapters: {
      storageAdapter: store,
      decryptAdapter: {
        adapterKind: 'aws-kms',
        decryptSigningRootSecretShare: async (record) => {
          decryptCalls.push(record.shareId);
          return new Uint8Array([record.shareId, ...new Uint8Array(32)]);
        },
      },
    },
  });

  expect(resolver).not.toBeNull();
  await expect(
    resolver!.resolveSigningRootSharePair({
      signingRootId: 'project-alpha',
      preferredShareIds: [1, 2],
    }),
  ).rejects.toThrow(/requested signing-root shares are not available/);
  expect(decryptCalls).toEqual([]);
});
