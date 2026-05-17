import { expect, test } from '@playwright/test';
import { resolveTrackedNearRecoveryExecution } from '../../server/src/router/recoveryExecutionTracking';
import {
  buildRecoveryEmailPayload,
  hashRecoveryEmailPayload,
} from '../../shared/src/utils/recoveryEmail';

test.describe('recovery execution session reconciliation', () => {
  test('resolves tracked recovery only when the canonical payload matches the pending session', async () => {
    const payload = buildRecoveryEmailPayload({
      nearAccountId: 'alice.testnet',
      recoverySessionId: 'ABC123',
      newNearPublicKey: 'ed25519:recovery-key',
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
      deadlineEpochSeconds: 1_893_456_000,
    });
    const payloadHash = await hashRecoveryEmailPayload(payload);
    const baseRecord = {
      version: 'recovery_session_v1' as const,
      sessionId: 'ABC123',
      userId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      signerSlot: 7,
      status: 'prepared' as const,
      createdAtMs: 1,
      updatedAtMs: 1,
      expiresAtMs: Date.now() + 60_000,
      newNearPublicKey: payload.newNearPublicKey,
      newEvmOwnerAddress: payload.newEvmOwnerAddress,
      recoveryDeadlineEpochSeconds: payload.deadlineEpochSeconds,
      recoveryEmailPayloadHash: payloadHash,
    };

    const matching = await resolveTrackedNearRecoveryExecution(
      {
        getRecoverySession: async () => ({ ok: true as const, record: baseRecord }),
      } as any,
      { accountId: 'alice.testnet', recoveryPayload: payload },
    );
    const mismatchedOwner = await resolveTrackedNearRecoveryExecution(
      {
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            ...baseRecord,
            newEvmOwnerAddress: `0x${'22'.repeat(20)}`,
          },
        }),
      } as any,
      { accountId: 'alice.testnet', recoveryPayload: payload },
    );
    const expired = await resolveTrackedNearRecoveryExecution(
      {
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            ...baseRecord,
            recoveryDeadlineEpochSeconds: 1,
          },
        }),
      } as any,
      {
        accountId: 'alice.testnet',
        recoveryPayload: {
          ...payload,
          deadlineEpochSeconds: 1,
        },
      },
    );

    expect(matching).toEqual(
      expect.objectContaining({
        sessionId: 'ABC123',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        expectedNewNearPublicKey: 'ed25519:recovery-key',
        expectedNewEvmOwnerAddress: `0x${'11'.repeat(20)}`,
        recoveryEmailPayloadHash: payloadHash,
      }),
    );
    expect(mismatchedOwner).toBeNull();
    expect(expired).toBeNull();
  });
});
