import { expect, test } from '@playwright/test';
import type { AuthService } from '../../packages/sdk-server-ts/src/core/AuthService';
import {
  createConfiguredSigningRootShareResolver,
  createThresholdSigningService,
} from '../../packages/sdk-server-ts/src/core/ThresholdService';
import type { ThresholdStoreConfigInput } from '../../packages/sdk-server-ts/src/core/types';

function createAuthServiceMock(): AuthService {
  return {
    getRelayerAccount: async () => 'relayer.testnet',
    verifyWebAuthnAuthenticationLite: async () => ({ success: true, verified: true }),
    viewAccessKeyList: async () => ({ keys: [] }),
  } as unknown as AuthService;
}

test('threshold signing service reports signing-root resolver configured from server SDK config', () => {
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

  const service = createThresholdSigningService({
    authService: createAuthServiceMock(),
    thresholdStore: thresholdConfig,
    isNode: true,
  });

  expect(service.hasSigningRootShareResolver()).toBe(true);
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
