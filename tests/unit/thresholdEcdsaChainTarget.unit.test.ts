import { expect, test } from '@playwright/test';
import {
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromConfiguredRequest,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
