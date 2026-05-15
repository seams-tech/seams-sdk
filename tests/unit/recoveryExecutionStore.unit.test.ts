import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  store: '/sdk/esm/server/core/RecoveryExecutionStore.js',
  records: '/sdk/esm/server/core/recoveryExecutionRecords.js',
} as const;

test.describe('recovery execution canonical store', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('builds and round-trips recovery execution records in the in-memory store', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createRecoveryExecutionStore } = await import(paths.store);
      const { buildRecoveryExecutionRecord } = await import(paths.records);

      const nowMs = Date.now();
      const record = buildRecoveryExecutionRecord({
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        action: 'near_email_recovery',
        status: 'submitted',
        nowMs,
        transactionHash: '7XyTxHash',
        metadata: {
          expectedNewNearPublicKey: 'ed25519:recovery-key',
        },
      });
      if (!record) throw new Error('failed to build recovery execution record');

      const store = createRecoveryExecutionStore({
        config: null,
        logger: console,
        isNode: false,
      });
      await store.put(record);
      const fetched = await store.get({
        sessionId: 'ABC123',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        action: 'near_email_recovery',
      });
      const listed = await store.listBySessionId('ABC123');

      return {
        record,
        fetched,
        listed,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.record.status).toBe('submitted');
    expect(result.fetched?.transactionHash).toBe('7XyTxHash');
    expect(result.fetched?.chainIdKey).toBe('near:testnet');
    expect(result.listed).toHaveLength(1);
    expect(result.listed[0]?.metadata?.expectedNewNearPublicKey).toBe('ed25519:recovery-key');
  });

  test('lists recovery executions by status and action in created order', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createRecoveryExecutionStore } = await import(paths.store);
      const { buildRecoveryExecutionRecord } = await import(paths.records);

      const store = createRecoveryExecutionStore({
        config: null,
        logger: console,
        isNode: false,
      });
      const baseNow = Date.now();
      const records = [
        buildRecoveryExecutionRecord({
          sessionId: 'ABC123',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'11'.repeat(20)}`,
          action: 'recover_add_owner',
          status: 'pending',
          createdAtMs: baseNow,
          nowMs: baseNow,
        }),
        buildRecoveryExecutionRecord({
          sessionId: 'ABC123',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'22'.repeat(20)}`,
          action: 'recover_add_owner',
          status: 'failed',
          createdAtMs: baseNow + 1,
          nowMs: baseNow + 1,
        }),
        buildRecoveryExecutionRecord({
          sessionId: 'ABC124',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'33'.repeat(20)}`,
          action: 'recover_add_owner',
          status: 'pending',
          createdAtMs: baseNow + 2,
          nowMs: baseNow + 2,
        }),
        buildRecoveryExecutionRecord({
          sessionId: 'ABC125',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
          action: 'near_email_recovery',
          status: 'pending',
          createdAtMs: baseNow + 3,
          nowMs: baseNow + 3,
        }),
      ].filter(Boolean);
      for (const record of records) {
        await store.put(record!);
      }

      const recoverAddOwnerPending = await store.listByStatus({
        status: 'pending',
        action: 'recover_add_owner',
      });
      const recoverAddOwnerSubmitted = await store.listByStatus({
        status: 'submitted',
        action: 'recover_add_owner',
      });
      const limited = await store.listByStatus({
        status: 'pending',
        action: 'recover_add_owner',
        limit: 1,
      });
      const staleOnly = await store.listByStatus({
        status: 'pending',
        action: 'recover_add_owner',
        updatedBeforeMs: baseNow + 1,
      });

      return {
        recoverAddOwnerPending,
        recoverAddOwnerSubmitted,
        limited,
        staleOnly,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.recoverAddOwnerPending).toHaveLength(2);
    expect(result.recoverAddOwnerPending[0]?.accountAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(result.recoverAddOwnerPending[1]?.accountAddress).toBe(`0x${'33'.repeat(20)}`);
    expect(result.recoverAddOwnerSubmitted).toHaveLength(0);
    expect(result.limited).toHaveLength(1);
    expect(result.limited[0]?.accountAddress).toBe(`0x${'11'.repeat(20)}`);
    expect(result.staleOnly).toHaveLength(1);
    expect(result.staleOnly[0]?.accountAddress).toBe(`0x${'11'.repeat(20)}`);
  });
});
