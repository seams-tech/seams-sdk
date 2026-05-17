import { expect, test } from '@playwright/test';
import { resolveManagedEvmNonceReservationInput } from '@/core/signingEngine/flows/signEvmFamily/evmNonceLifecycle';
import {
  chainAccountNonceSenderIdentity,
  resolveManagedNonceSender,
  resolveProfileChainAccountNonceSenderIdentity,
  thresholdOwnerNonceSenderIdentity,
} from '@/core/signingEngine/flows/signEvmFamily/nonceResolution';
import { reserveManagedTempoNonceForRequest } from '@/core/signingEngine/flows/signEvmFamily/tempoNonceLifecycle';
import { thresholdEcdsaChainTargetFromChainFamily } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const THRESHOLD_OWNER = `0x${'11'.repeat(20)}` as `0x${string}`;
const CHAIN_ACCOUNT = `0x${'22'.repeat(20)}` as `0x${string}`;

const evmTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 11155111,
  networkSlug: 'arc-testnet',
});

const tempoTarget = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
});

function depsWithProfileRows(rows: Array<Record<string, unknown>>) {
  return {
    seamsPasskeyConfigs: {
      network: {
        chains: [
          {
            network: 'arc-testnet',
            rpcUrl: 'https://arc.example',
            explorerUrl: 'https://arc.example/explorer',
            chainId: evmTarget.chainId,
          },
          {
            network: 'tempo-testnet',
            rpcUrl: 'https://tempo.example',
            explorerUrl: 'https://tempo.example/explorer',
            chainId: tempoTarget.chainId,
          },
        ],
      },
    },
    indexedDB: {
      clientDB: {
        resolveProfileAccountContext: async () => ({
          profileId: 'profile-alice',
          accountRef: {
            chainIdKey: 'near:testnet',
            accountAddress: 'alice.testnet',
          },
        }),
        listChainAccountsByProfileAndChain: async (_profileId: string, chainIdKey: string) =>
          rows.filter((row) => row.chainIdKey === chainIdKey),
      },
    },
    nonceCoordinator: {
      reserve: async (input: any) => ({
        lane: input.lane,
        nonce: 7n,
        leaseId: 'lease-1',
        operationId: 'operation-1',
        operationFingerprint: 'sha256:nonce-sender',
        state: 'reserved',
        reservedAtMs: 1,
        expiresAtMs: 2,
      }),
    },
  } as any;
}

test.describe('EVM-family nonce sender identity', () => {
  test('EVM managed nonce reservation uses explicit threshold owner identity', async () => {
    const reservationInput = await resolveManagedEvmNonceReservationInput({
      deps: depsWithProfileRows([
        {
          profileId: 'profile-alice',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: CHAIN_ACCOUNT,
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        },
      ]),
      walletId: 'alice.testnet',
      request: {
        chain: 'evm',
        kind: 'eip1559',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: evmTarget.chainId,
          nonce: 0n,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          to: `0x${'33'.repeat(20)}`,
          value: 0n,
          data: '0x',
          accessList: [],
        },
      },
      senderIdentity: thresholdOwnerNonceSenderIdentity(THRESHOLD_OWNER),
    });

    expect(reservationInput.sender).toBe(THRESHOLD_OWNER);
  });

  test('Tempo managed nonce reservation uses explicit threshold owner identity', async () => {
    const result = await reserveManagedTempoNonceForRequest({
      deps: depsWithProfileRows([
        {
          profileId: 'profile-alice',
          chainIdKey: 'tempo:42431',
          accountAddress: CHAIN_ACCOUNT,
          accountModel: 'tempo-native',
          isPrimary: true,
        },
      ]),
      walletId: 'alice.testnet',
      request: {
        chain: 'tempo',
        kind: 'tempoTransaction',
        senderSignatureAlgorithm: 'secp256k1',
        tx: {
          chainId: tempoTarget.chainId,
          nonce: 0n,
          nonceKey: 99n,
          maxPriorityFeePerGas: 1n,
          maxFeePerGas: 2n,
          gasLimit: 21_000n,
          calls: [{ to: `0x${'33'.repeat(20)}`, value: 0n, input: '0x' }],
        },
      },
      operation: {
        operationId: 'operation-1',
        operationFingerprint: 'sha256:nonce-sender',
        intent: 'transaction_sign',
        accountId: 'alice.testnet',
        chainFamily: 'tempo',
      } as any,
      senderIdentity: thresholdOwnerNonceSenderIdentity(THRESHOLD_OWNER),
    });

    expect(result.reservation.sender).toBe(THRESHOLD_OWNER);
  });

  test('non-threshold fallback is an explicit chain-account sender identity', async () => {
    const senderIdentity = await resolveProfileChainAccountNonceSenderIdentity({
      deps: depsWithProfileRows([
        {
          profileId: 'profile-alice',
          chainIdKey: 'evm:eip155:11155111',
          accountAddress: CHAIN_ACCOUNT,
          accountModel: 'threshold-ecdsa',
          isPrimary: true,
        },
      ]),
      walletId: 'alice.testnet',
      chainTarget: evmTarget,
    });

    expect(senderIdentity).toEqual(chainAccountNonceSenderIdentity(CHAIN_ACCOUNT));
    await expect(resolveManagedNonceSender({ senderIdentity })).resolves.toBe(CHAIN_ACCOUNT);
  });
});
