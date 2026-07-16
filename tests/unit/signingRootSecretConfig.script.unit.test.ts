import { expect, test } from '@playwright/test';
import {
  createConfiguredSigningRootShareResolver,
} from '../../packages/sdk-server-ts/src/core/ThresholdService';
import { createRouterAbSigningRuntimes } from '../../packages/sdk-server-ts/src/core/routerAbSigning/createRouterAbSigningRuntimes';
import type { ThresholdStoreConfigInput } from '../../packages/sdk-server-ts/src/core/types';

function createAuthServiceMock(): { getRelayerAccount(): Promise<string> } {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
  };
}

test('Router A/B ECDSA bootstrap runtime is configured from server SDK signing-root config', () => {
  const thresholdConfig: ThresholdStoreConfigInput = {
    kind: 'in-memory',
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'signing-worker.local',
    signingRootShareResolverAdapters: {
      policy: {
        protocol: 'threshold-prf',
        threshold: 2,
        shareCount: 3,
      },
      storageAdapter: {
        listSealedSigningRootShares: async () => [],
      },
      decryptAdapter: {
        decryptSigningRootShare: async () => new Uint8Array(34),
      },
    },
  };

  const runtimes = createRouterAbSigningRuntimes({
    authService: createAuthServiceMock(),
    thresholdStore: thresholdConfig,
    isNode: true,
  });

  expect(runtimes.ecdsaBootstrapExport.kind).toBe('configured');
});

test('signing-root share resolver config composes storage and decrypt adapters', async () => {
  const decryptCalls: number[] = [];
  const resolver = createConfiguredSigningRootShareResolver({
    signingRootShareResolverAdapters: {
      policy: {
        protocol: 'threshold-prf',
        threshold: 2,
        shareCount: 3,
      },
      storageAdapter: {
        listSealedSigningRootShares: async (input: {
          signingRootId: string;
          signingRootVersion?: string;
        }) => [
          {
            signingRootId: input.signingRootId,
            ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
            shareId: 1,
            sealedShare: new Uint8Array([1]),
          },
          {
            signingRootId: input.signingRootId,
            ...(input.signingRootVersion ? { signingRootVersion: input.signingRootVersion } : {}),
            shareId: 2,
            sealedShare: new Uint8Array([2]),
          },
        ],
      },
      decryptAdapter: {
        decryptSigningRootShare: async (record: any) => {
          decryptCalls.push(record.shareId);
          return new Uint8Array([0, record.shareId, ...new Uint8Array(32).fill(record.shareId)]);
        },
      },
    },
  });

  expect(resolver).not.toBeNull();
  const shares = await resolver!.resolveSigningRootShareSet({ signingRootId: 'project-alpha' });
  expect(shares.map((share) => share[1])).toEqual([1, 2]);
  expect(decryptCalls).toEqual([1, 2]);
});
