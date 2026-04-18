import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('recovery session canonical store', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('builds and round-trips prepared recovery sessions in the in-memory store', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const {
        buildPreparedRecoverySessionRecord,
        createRecoverySessionStore,
        DEFAULT_RECOVERY_SESSION_TTL_MS,
      } = await import(paths.server);

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

      return {
        record,
        fetched,
        listed,
        ttlMs: DEFAULT_RECOVERY_SESSION_TTL_MS,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.record.status).toBe('prepared');
    expect(result.record.expiresAtMs - result.record.createdAtMs).toBe(result.ttlMs);
    expect(result.fetched?.newNearPublicKey).toBe('ed25519:recovery-key');
    expect(result.fetched?.newEvmOwnerAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0]?.scope).toBe('all-linked-evm-accounts');
  });
});
