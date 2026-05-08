import { expect, test } from '@playwright/test';
import {
  bindEvmFamilyCallerProvidedOperationIdToFingerprint,
  createEvmFamilySigningOperationIds,
} from '@/core/signingEngine/flows/signEvmFamily/operationIds';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { computeSigningOperationFingerprint } from '@/core/signingEngine/session/planning/operationFingerprint';
import { SigningSessionIds } from '@/core/signingEngine/session/signingSession/types';

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
    const signingSessionCoordinator = new SigningSessionCoordinator();

    bindEvmFamilyCallerProvidedOperationIdToFingerprint(
      createEvmFamilySigningOperationIds(operationId),
      firstFingerprint,
      signingSessionCoordinator,
    );
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        firstFingerprint,
        signingSessionCoordinator,
      ),
    ).not.toThrow();
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        secondFingerprint,
        signingSessionCoordinator,
      ),
    ).toThrow('caller-provided signingOperationId reused for a different operation');
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(operationId),
        crossChainFingerprint,
        signingSessionCoordinator,
      ),
    ).toThrow('caller-provided signingOperationId reused for a different operation');
  });

  test('does not bind internally generated operation ids across requests', async () => {
    const firstFingerprint = SigningSessionIds.signingOperationFingerprint('sha256:first');
    const secondFingerprint = SigningSessionIds.signingOperationFingerprint('sha256:second');
    const signingSessionCoordinator = new SigningSessionCoordinator();

    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(),
        firstFingerprint,
        signingSessionCoordinator,
      ),
    ).not.toThrow();
    expect(() =>
      bindEvmFamilyCallerProvidedOperationIdToFingerprint(
        createEvmFamilySigningOperationIds(),
        secondFingerprint,
        signingSessionCoordinator,
      ),
    ).not.toThrow();
  });
});
