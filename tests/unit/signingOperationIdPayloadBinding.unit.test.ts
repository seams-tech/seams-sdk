import { expect, test } from '@playwright/test';
import { SigningSessionCoordinator } from '@/core/signingEngine/session/SigningSessionCoordinator';
import { computeSigningOperationFingerprint } from '@/core/signingEngine/session/planning/operationFingerprint';
import { SigningSessionIds } from '@/core/signingEngine/session/operationState/types';

test.describe('SigningOperationIdPayloadBinding', () => {
  test('rejects a caller-provided NEAR operation id reused for different transactions', async () => {
    const operationId = SigningSessionIds.signingOperation(
      `op-near-fingerprint-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    );
    const firstFingerprint = await computeSigningOperationFingerprint({
      kind: 'near:transactions_with_actions',
      payload: {
        nearAccountId: 'alice.testnet',
        transactions: [
          {
            receiverId: 'bob.testnet',
            actions: [{ type: 'Transfer', params: { deposit: '1' } }],
          },
        ],
      },
    });
    const secondFingerprint = await computeSigningOperationFingerprint({
      kind: 'near:transactions_with_actions',
      payload: {
        nearAccountId: 'alice.testnet',
        transactions: [
          {
            receiverId: 'carol.testnet',
            actions: [{ type: 'Transfer', params: { deposit: '2' } }],
          },
        ],
      },
    });
    const signingSessionCoordinator = new SigningSessionCoordinator();

    signingSessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
      operationId,
      operationFingerprint: firstFingerprint,
    });
    expect(() =>
      signingSessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
        operationId,
        operationFingerprint: firstFingerprint,
      }),
    ).not.toThrow();
    expect(() =>
      signingSessionCoordinator.bindCallerProvidedOperationIdToFingerprint({
        operationId,
        operationFingerprint: secondFingerprint,
      }),
    ).toThrow('caller-provided signingOperationId reused for a different operation');
  });
});
