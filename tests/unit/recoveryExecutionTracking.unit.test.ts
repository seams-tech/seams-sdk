import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
  recoveryEmail: '/sdk/esm/server/shared/src/utils/recoveryEmail.js',
} as const;

test.describe('recovery execution session reconciliation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('marks the session completed when all smart-account recovery executions settle', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { reconcileRecoverySessionExecutionState } = await import(paths.server);
      const updates: Array<Record<string, unknown>> = [];
      const reconciled = await reconcileRecoverySessionExecutionState(
        {
          getRecoverySession: async () => ({
            ok: true as const,
            record: {
              version: 'recovery_session_v1' as const,
              sessionId: 'ABC123',
              userId: 'alice.testnet',
              nearAccountId: 'alice.testnet',
              deviceNumber: 7,
              status: 'evm_recovering' as const,
              createdAtMs: 1,
              updatedAtMs: 1,
              expiresAtMs: Date.now() + 60_000,
              newNearPublicKey: 'ed25519:recovery-key',
              newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
            },
          }),
          listRecoveryExecutions: async () => ({
            ok: true as const,
            records: [
              {
                action: 'near_email_recovery',
                status: 'submitted',
              },
              {
                action: 'recover_add_owner',
                status: 'confirmed',
              },
              {
                action: 'recover_add_owner',
                status: 'skipped',
              },
            ],
          }),
          updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
            updates.push(input);
            return {
              ok: true as const,
              record: input,
            };
          },
        } as any,
        { sessionId: 'ABC123' },
      );
      return { reconciled, updates };
    }, { paths: IMPORT_PATHS });

    expect(result.reconciled.ok).toBe(true);
    expect((result.reconciled as any).status).toBe('completed');
    expect((result.reconciled as any).summary).toEqual({
      total: 2,
      pending: 0,
      submitted: 0,
      confirmed: 1,
      failed: 0,
      skipped: 1,
    });
    expect(result.updates).toEqual([
      expect.objectContaining({
        sessionId: 'ABC123',
        status: 'completed',
        metadataPatch: expect.objectContaining({
          evmRecoveryExecutionSummary: {
            total: 2,
            pending: 0,
            submitted: 0,
            confirmed: 1,
            failed: 0,
            skipped: 1,
          },
        }),
      }),
    ]);
  });

  test('marks the session failed when any smart-account recovery execution fails', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { reconcileRecoverySessionExecutionState } = await import(paths.server);
      const updates: Array<Record<string, unknown>> = [];
      const reconciled = await reconcileRecoverySessionExecutionState(
        {
          getRecoverySession: async () => ({
            ok: true as const,
            record: {
              version: 'recovery_session_v1' as const,
              sessionId: 'ABC123',
              userId: 'alice.testnet',
              nearAccountId: 'alice.testnet',
              deviceNumber: 7,
              status: 'evm_recovering' as const,
              createdAtMs: 1,
              updatedAtMs: 1,
              expiresAtMs: Date.now() + 60_000,
              newNearPublicKey: 'ed25519:recovery-key',
              newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
            },
          }),
          listRecoveryExecutions: async () => ({
            ok: true as const,
            records: [
              {
                action: 'recover_add_owner',
                status: 'submitted',
              },
              {
                action: 'recover_add_owner',
                status: 'failed',
              },
            ],
          }),
          updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
            updates.push(input);
            return {
              ok: true as const,
              record: input,
            };
          },
        } as any,
        { sessionId: 'ABC123' },
      );
      return { reconciled, updates };
    }, { paths: IMPORT_PATHS });

    expect(result.reconciled.ok).toBe(true);
    expect((result.reconciled as any).status).toBe('failed');
    expect((result.reconciled as any).summary).toEqual({
      total: 2,
      pending: 0,
      submitted: 1,
      confirmed: 0,
      failed: 1,
      skipped: 0,
    });
    expect(result.updates[0]?.status).toBe('failed');
  });

  test('resolves tracked recovery only when the canonical payload matches the pending session', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { resolveTrackedNearRecoveryExecution } = await import(paths.server);
      const { buildRecoveryEmailPayload, hashRecoveryEmailPayload } = await import(paths.recoveryEmail);

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
        deviceNumber: 7,
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

      return {
        matching,
        mismatchedOwner,
        expired,
        payloadHash,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.matching).toEqual(
      expect.objectContaining({
        sessionId: 'ABC123',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        expectedNewNearPublicKey: 'ed25519:recovery-key',
        expectedNewEvmOwnerAddress: `0x${'11'.repeat(20)}`,
        recoveryEmailPayloadHash: result.payloadHash,
      }),
    );
    expect(result.mismatchedOwner).toBeNull();
    expect(result.expired).toBeNull();
  });
});
