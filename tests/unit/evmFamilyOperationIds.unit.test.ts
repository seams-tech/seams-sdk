import { expect, test } from '@playwright/test';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
} from '@/core/signingEngine/api/evmFamily/operationIds';
import { computeSigningOperationFingerprint } from '@/core/signingEngine/session/SigningOperationFingerprint';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSessionTypes';

test.describe('EVM-family signing operation ids', () => {
  test('binds caller-provided operation ids to the canonical operation fingerprint', async () => {
    const operationId = SigningSessionIds.signingOperation(
      `op-evm-family-fingerprint-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    );
    const firstFingerprint = await computeSigningOperationFingerprint({
      kind: 'evm-family:evm',
      payload: {
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'evm',
          kind: 'evmTransaction',
          tx: { chainId: 1, to: '0x0000000000000000000000000000000000000001', value: '1' },
        },
      },
    });
    const secondFingerprint = await computeSigningOperationFingerprint({
      kind: 'evm-family:evm',
      payload: {
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'evm',
          kind: 'evmTransaction',
          tx: { chainId: 1, to: '0x0000000000000000000000000000000000000002', value: '2' },
        },
      },
    });
    const crossChainFingerprint = await computeSigningOperationFingerprint({
      kind: 'evm-family:tempo',
      payload: {
        nearAccountId: 'alice.testnet',
        request: {
          chain: 'tempo',
          kind: 'tempoTransaction',
          tx: { chainId: 42431, to: '0x0000000000000000000000000000000000000001' },
        },
      },
    });

    bindEvmFamilyCallerProvidedOperationIdToFingerprint(
      createEvmFamilySigningOperationIds(operationId),
      firstFingerprint,
    );
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        firstFingerprint,
      ),
    ).not.toThrow();
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        secondFingerprint,
      ),
    ).toThrow('caller-provided signingOperationId reused for a different operation');
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        crossChainFingerprint,
      ),
    ).toThrow('caller-provided signingOperationId reused for a different operation');
  });

  test('does not bind internally generated operation ids across requests', async () => {
    const firstFingerprint = SigningSessionIds.signingOperationFingerprint('sha256:first');
    const secondFingerprint = SigningSessionIds.signingOperationFingerprint('sha256:second');

    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(),
        firstFingerprint,
      ),
    ).not.toThrow();
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(),
        secondFingerprint,
      ),
    ).not.toThrow();
  });
});
