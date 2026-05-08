import { expect, test } from '@playwright/test';
import {
  buildPreparedRecoverySessionRecord,
  DEFAULT_RECOVERY_SESSION_TTL_MS,
} from '../../server/src/core/recoverySessionRecords';
import { createRecoverySessionStore } from '../../server/src/core/RecoverySessionStore';

test.describe('recovery session canonical store', () => {
  test('builds and round-trips prepared recovery sessions in the in-memory store', async () => {
    const nowMs = Date.now();
    const record = buildPreparedRecoverySessionRecord({
      sessionId: 'ABC123',
      userId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      signerSlot: 7,
      newNearPublicKey: 'ed25519:recovery-key',
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
      recoveryDeadlineEpochSeconds: 1_893_456_000,
      recoveryEmailPayloadHash: 'sha256:payload-hash',
      scope: 'all-linked-evm-accounts',
      nowMs,
      metadata: {
        rpId: 'wallet.example.test',
      },
    });
    if (!record) throw new Error('failed to build recovery session record');

    const store = createRecoverySessionStore({
      config: null,
      logger: console,
      isNode: false,
    });
    await store.put(record);
    const fetched = await store.get('ABC123');
    const listed = await store.listByNearAccountId('alice.testnet');

    expect(record.status).toBe('prepared');
    expect(record.expiresAtMs - record.createdAtMs).toBe(DEFAULT_RECOVERY_SESSION_TTL_MS);
    expect(fetched?.newNearPublicKey).toBe('ed25519:recovery-key');
    expect(fetched?.newEvmOwnerAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(listed).toHaveLength(1);
    expect(listed[0]?.scope).toBe('all-linked-evm-accounts');
  });
});
