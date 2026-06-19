import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfiguredRequest,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  thresholdEcdsaSessionRecordKeysEqual,
  thresholdEcdsaLaneKey,
  type ThresholdEcdsaSessionRecordKey,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

function makeLane(overrides: Partial<ThresholdEcdsaSessionRecordKey> = {}): ThresholdEcdsaSessionRecordKey {
  return {
    walletId: toAccountId('wallet-1.testnet'),
    keyHandle: 'ehss-key-arc',
    authMethod: 'email_otp',
    curve: 'ecdsa',
    chainTarget: {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 5_042_002,
      networkSlug: 'arc-testnet',
    },
    signingGrantId: 'wsess-arc',
    thresholdSessionId: 'tsess-arc',
    ...overrides,
  };
}

test.describe('threshold ECDSA concrete chain targets', () => {
  test('normalizes Arc and Tempo requests into concrete canonical targets', () => {
    const arc = thresholdEcdsaChainTargetFromRequest({
      chain: 'evm',
      chainId: 5_042_002,
      networkSlug: 'arc-testnet',
    });
    const tempo = thresholdEcdsaChainTargetFromRequest({
      kind: 'tempo',
      chainId: 42_431,
      networkSlug: 'tempo-moderato',
    });

    expect(arc).toEqual({
      kind: 'evm',
      namespace: 'eip155',
      chainId: 5_042_002,
      networkSlug: 'arc-testnet',
    });
    expect(tempo).toEqual({
      kind: 'tempo',
      chainId: 42_431,
      networkSlug: 'tempo-moderato',
    });
    expect(thresholdEcdsaChainTargetKey(arc)).toBe('evm:eip155:5042002');
    expect(thresholdEcdsaChainTargetKey(tempo)).toBe('tempo:42431');
  });

  test('distinguishes Tempo and EVM even when numeric chainId matches', () => {
    const evm = thresholdEcdsaChainTargetFromRequest({
      chain: 'evm',
      chainId: 42_431,
      networkSlug: 'evm-42431',
    });
    const tempo = thresholdEcdsaChainTargetFromRequest({
      chain: 'tempo',
      chainId: 42_431,
      networkSlug: 'tempo-moderato',
    });

    expect(thresholdEcdsaChainTargetKey(evm)).toBe('evm:eip155:42431');
    expect(thresholdEcdsaChainTargetKey(tempo)).toBe('tempo:42431');
    expect(thresholdEcdsaChainTargetsEqual(evm, tempo)).toBe(false);
  });

  test('uses config network slug as metadata and not equality', () => {
    const configured = thresholdEcdsaChainTargetFromConfiguredRequest({
      chain: 'evm',
      explicitChainId: 5_042_002,
      chains: [
        {
          network: 'arc-testnet',
          rpcUrl: 'https://rpc.testnet.arc.network',
          explorerUrl: 'https://explorer.testnet.arc.network',
          chainId: 5_042_002,
        },
      ],
    });
    const request = thresholdEcdsaChainTargetFromRequest({
      chain: 'evm',
      chainId: 5_042_002,
      networkSlug: 'custom-label',
    });

    expect(configured.networkSlug).toBe('arc-testnet');
    expect(thresholdEcdsaChainTargetsEqual(configured, request)).toBe(true);
  });

  test('requires a numeric chainId at the boundary', () => {
    expect(() => thresholdEcdsaChainTargetFromRequest({ chain: 'evm' })).toThrow(
      'chainId must be a positive safe integer',
    );
    expect(() =>
      thresholdEcdsaChainTargetFromRequest({ chain: 'evm', namespace: 'cosmos', chainId: 1 }),
    ).toThrow('namespace must be eip155');
  });

  test('canonical lane identity includes wallet, key handle, chain target, and session ids', () => {
    const arc = makeLane();
    const ethereum = makeLane({
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 1,
        networkSlug: 'ethereum-mainnet',
      },
    });
    const otherKey = makeLane({ keyHandle: 'ehss-key-ethereum' });

    expect(thresholdEcdsaLaneKey(arc)).toBe(
      [
        'wallet-1.testnet',
        'ehss-key-arc',
        'email_otp',
        'ecdsa',
        'evm%3Aeip155%3A5042002',
        'wsess-arc',
        'tsess-arc',
      ].join(':'),
    );
    expect(thresholdEcdsaSessionRecordKeysEqual(arc, ethereum)).toBe(false);
    expect(thresholdEcdsaSessionRecordKeysEqual(arc, otherKey)).toBe(false);
  });

  test('keeps multiple EVM networks with the same wallet and key handle as separate lanes', () => {
    const megaEthTestnet = makeLane({
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 6_345,
        networkSlug: 'megaeth-testnet',
      },
      keyHandle: 'ehss-shared',
    });
    const polygonMainnet = makeLane({
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 137,
        networkSlug: 'polygon-mainnet',
      },
      keyHandle: 'ehss-shared',
    });

    expect(thresholdEcdsaSessionRecordKeysEqual(megaEthTestnet, polygonMainnet)).toBe(false);
    expect(thresholdEcdsaLaneKey(megaEthTestnet)).toContain('evm%3Aeip155%3A6345');
    expect(thresholdEcdsaLaneKey(polygonMainnet)).toContain('evm%3Aeip155%3A137');
  });

  test('classifies named and implicit NEAR account refs without using them as ECDSA subject ids', () => {
    expect(nearAccountRefFromAccountId('alice.testnet')).toEqual({
      kind: 'named',
      accountId: 'alice.testnet',
    });
    expect(
      nearAccountRefFromAccountId(
        '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
      ),
    ).toEqual({
      kind: 'implicit',
      accountId: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    });
  });
});
