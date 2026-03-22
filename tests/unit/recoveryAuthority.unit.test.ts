import { expect, test } from '@playwright/test';
import { injectImportMap } from '../setup/bootstrap';

const IMPORT_PATHS = {
  server: '/sdk/esm/server/index.js',
} as const;

test.describe('recovery authority executor', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await injectImportMap(page);
  });

  test('confirms undeployed recovery by activating the canonical signer immediately', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { executePendingSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const signerWrites: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const pendingExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'pending',
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          linkedAccount: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 11155111,
            deployed: false,
            counterfactualAddress: `0x${'22'.repeat(20)}`,
          },
        },
      };
      const key = `${pendingExecution.sessionId}:${pendingExecution.chainIdKey}:${pendingExecution.accountAddress}:${pendingExecution.action}`;
      executionState.set(key, pendingExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => {
          signerWrites.push(record);
          return { ok: true as const, record };
        },
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          executionState.set(key, {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: pendingExecution.createdAtMs,
            updatedAtMs: Date.now(),
          });
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'evm_recovering',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const executed = await executePendingSmartAccountRecoveryExecutions(service as any, {});

      return {
        executed,
        signerWrites,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.executed.ok).toBe(true);
    expect((result.executed as any).result).toEqual({
      processed: 1,
      confirmed: 1,
      submitted: 0,
      skipped: 0,
      failed: 0,
    });
    expect(result.signerWrites).toHaveLength(1);
    expect(result.signerWrites[0]?.signerId).toBe(`0x${'11'.repeat(20)}`);
    expect(result.signerWrites[0]?.status).toBe('active');
    expect(result.finalExecution?.status).toBe('confirmed');
    expect(result.finalExecution?.metadata?.recoveryTargetMode).toBe('undeployed');
    expect(result.sessionUpdates.at(-1)?.status).toBe('completed');
  });

  test('marks deployed recovery as submitted without activating the signer before confirmation', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { executePendingSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const signerWrites: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const pendingExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'pending',
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          linkedAccount: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 11155111,
            deployed: true,
          },
        },
      };
      const key = `${pendingExecution.sessionId}:${pendingExecution.chainIdKey}:${pendingExecution.accountAddress}:${pendingExecution.action}`;
      executionState.set(key, pendingExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => {
          signerWrites.push(record);
          return { ok: true as const, record };
        },
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          executionState.set(key, {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: pendingExecution.createdAtMs,
            updatedAtMs: Date.now(),
          });
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'evm_recovering',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const executed = await executePendingSmartAccountRecoveryExecutions(service as any, {
        executeDeployedRecovery: async () => ({
          status: 'submitted',
          transactionHash: `0x${'aa'.repeat(32)}`,
        }),
      });

      return {
        executed,
        signerWrites,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.executed.ok).toBe(true);
    expect((result.executed as any).result).toEqual({
      processed: 1,
      confirmed: 0,
      submitted: 1,
      skipped: 0,
      failed: 0,
    });
    expect(result.signerWrites).toHaveLength(0);
    expect(result.finalExecution?.status).toBe('submitted');
    expect(result.finalExecution?.transactionHash).toBe(`0x${'aa'.repeat(32)}`);
    expect(result.finalExecution?.metadata?.recoveryTargetMode).toBe('deployed');
    expect(result.sessionUpdates.at(-1)?.status).toBe('evm_recovering');
  });

  test('leaves deployed recovery pending when no deployed executor is configured', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { executePendingSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const pendingExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'pending',
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          recoveryTargetMode: 'deployed',
          linkedAccount: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 11155111,
            deployed: true,
          },
        },
      };
      const key = `${pendingExecution.sessionId}:${pendingExecution.chainIdKey}:${pendingExecution.accountAddress}:${pendingExecution.action}`;
      executionState.set(key, pendingExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          executionState.set(key, {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: pendingExecution.createdAtMs,
            updatedAtMs: Date.now(),
          });
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'evm_recovering',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const executed = await executePendingSmartAccountRecoveryExecutions(service as any, {});

      return {
        executed,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.executed.ok).toBe(true);
    expect((result.executed as any).result).toEqual({
      processed: 1,
      confirmed: 0,
      submitted: 0,
      skipped: 1,
      failed: 0,
    });
    expect(result.finalExecution?.status).toBe('pending');
    expect(result.sessionUpdates).toEqual([]);
  });

  test('requeues retryable failed recovery executions and reopens the session', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { retryFailedSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const failedExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'failed',
        createdAtMs: Date.now() - 60_000,
        updatedAtMs: Date.now() - 10 * 60_000,
        errorCode: 'recovery_executor_threw',
        errorMessage: 'temporary signer worker outage',
        transactionHash: `0x${'aa'.repeat(32)}`,
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          recoveryTargetMode: 'deployed',
        },
      };
      const key = `${failedExecution.sessionId}:${failedExecution.chainIdKey}:${failedExecution.accountAddress}:${failedExecution.action}`;
      executionState.set(key, failedExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          const next = {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: failedExecution.createdAtMs,
            updatedAtMs: Date.now(),
          } as Record<string, unknown>;
          if (!('transactionHash' in input)) delete next.transactionHash;
          if (!('errorCode' in input)) delete next.errorCode;
          if (!('errorMessage' in input)) delete next.errorMessage;
          executionState.set(key, next);
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'failed',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const retried = await retryFailedSmartAccountRecoveryExecutions(service as any, {
        retryAfterMs: 60_000,
      });

      return {
        retried,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.retried.ok).toBe(true);
    expect((result.retried as any).result).toEqual({
      processed: 1,
      retried: 1,
      skipped: 0,
      failed: 0,
    });
    expect(result.finalExecution?.status).toBe('pending');
    expect(result.finalExecution?.transactionHash).toBeUndefined();
    expect(result.finalExecution?.errorCode).toBeUndefined();
    expect(result.finalExecution?.metadata?.retryCount).toBe(1);
    expect(result.finalExecution?.metadata?.lastErrorCode).toBe('recovery_executor_threw');
    expect(result.finalExecution?.metadata?.retryState).toBe('requeued');
    expect(result.sessionUpdates.at(-1)?.status).toBe('evm_recovering');
  });

  test('keeps terminal failed recovery executions failed', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { retryFailedSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const failedExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'failed',
        createdAtMs: Date.now() - 60_000,
        updatedAtMs: Date.now() - 10 * 60_000,
        errorCode: 'missing_new_evm_owner',
        errorMessage: 'Recovery execution metadata is missing newEvmOwnerAddress',
        metadata: {},
      };
      const key = `${failedExecution.sessionId}:${failedExecution.chainIdKey}:${failedExecution.accountAddress}:${failedExecution.action}`;
      executionState.set(key, failedExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          const next = {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: failedExecution.createdAtMs,
            updatedAtMs: Date.now(),
          } as Record<string, unknown>;
          if (!('transactionHash' in input)) delete next.transactionHash;
          if (!('errorCode' in input)) delete next.errorCode;
          if (!('errorMessage' in input)) delete next.errorMessage;
          executionState.set(key, next);
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'failed',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const retried = await retryFailedSmartAccountRecoveryExecutions(service as any, {
        retryAfterMs: 60_000,
      });

      return {
        retried,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.retried.ok).toBe(true);
    expect((result.retried as any).result).toEqual({
      processed: 1,
      retried: 0,
      skipped: 1,
      failed: 0,
    });
    expect(result.finalExecution?.status).toBe('failed');
    expect(result.finalExecution?.errorCode).toBe('missing_new_evm_owner');
    expect(result.sessionUpdates).toEqual([]);
  });

  test('builds a sponsored addOwner call for deployed recovery execution', async ({ page }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createSponsoredRecoveryDeployedExecutor } = await import(paths.server);
      const executedAdapters: Array<Record<string, unknown>> = [];
      const run = createSponsoredRecoveryDeployedExecutor({
        sponsorship: {
          logger: console as any,
          billing: {} as any,
          ledger: {} as any,
          runtimeSnapshots: {
            getLatestSnapshot: async () => ({
              payload: {
                policy: {},
                smartWallets: {},
                gasSponsorship: {
                  resolvedPolicies: [
                    {
                      kind: 'evm_call',
                      policyId: 'policy_recovery',
                      policyName: 'Recovery addOwner',
                      environmentId: 'env_recovery',
                      allowedCalls: [
                        {
                          chainId: 11155111,
                          to: `0x${'22'.repeat(20)}`,
                          functionSignature:
                            'verifyAndRecover(bytes32,bytes32,address,bytes32,uint256,uint256,bytes)',
                          maxGasLimit: '250000',
                          maxValueWei: '0',
                        },
                      ],
                      spendCap: {
                        mode: 'NONE',
                        period: 'MONTHLY',
                        capsByChain: [],
                      },
                    },
                  ],
                },
              },
            }),
          } as any,
          config: {
            executorsByChain: new Map([
              [
                11155111,
                {
                  chainId: 11155111,
                  rpcUrl: 'https://rpc.example.test',
                  sponsorAddress: `0x${'99'.repeat(20)}`,
                  sponsorPrivateKeyHex: `0x${'88'.repeat(32)}`,
                  maxPriorityFeePerGasFloor: 1n,
                  maxFeePerGasFloor: 2n,
                },
              ],
            ]),
          },
          spendCaps: null,
          pricing: null,
          prepaidReservations: null,
          observabilityIngestion: null,
          webhooks: null,
        },
        executeAdapter: async (adapter: any) => {
          executedAdapters.push({
            executorKind: adapter.executorKind,
            meta: adapter.meta,
          });
          return {
            txHash: `0x${'aa'.repeat(32)}`,
            gasUsed: '12345',
            effectiveGasPrice: '67890',
            feeAmount: '42',
          };
        },
        readBalanceSnapshot: async () => null,
        reserveSpendCap: async () => null,
        reservePrepaidBalance: async () => ({
          sourceEventId: 'prepaid_source_1',
          estimatedSpendMinor: 7,
          estimatedPricingVersion: 'pricing_v1',
        }),
        settleSpendCap: async () => null,
        recordExecution: async () => ({
          id: 'scr_recovery_1',
        }),
      });

      const execution = await run({
        execution: {
          version: 'recovery_execution_v1',
          sessionId: 'ABC123',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'22'.repeat(20)}`,
          action: 'recover_add_owner',
          status: 'pending',
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            expectedNewNearPublicKey: 'ed25519:recovery-key',
            recoveryDeadlineEpochSeconds: 1_893_456_000,
            sponsorshipScope: {
              orgId: 'org_recovery',
              environmentId: 'env_recovery',
            },
          },
        },
        newOwnerAddress: `0x${'11'.repeat(20)}`,
      });

      return {
        execution,
        executedAdapters,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.execution?.status).toBe('confirmed');
    expect(result.execution?.transactionHash).toBe(`0x${'aa'.repeat(32)}`);
    expect(result.execution?.metadataPatch?.sponsoredExecutorKind).toBe('evm_eoa');
    expect(result.execution?.metadataPatch?.sponsoredChainId).toBe(11155111);
    expect(result.execution?.metadataPatch?.sponsorAddress).toBe(`0x${'99'.repeat(20)}`);
    expect(result.execution?.metadataPatch?.sponsoredPolicyId).toBe('policy_recovery');
    expect(result.execution?.metadataPatch?.sponsoredRecordId).toBe('scr_recovery_1');
    expect(result.execution?.metadataPatch?.sponsoredReceiptStatus).toBe('success');
    expect(result.execution?.metadataPatch?.sponsoredGasUsed).toBe('12345');
    expect(result.execution?.metadataPatch?.sponsoredEffectiveGasPrice).toBe('67890');
    expect(result.execution?.metadataPatch?.sponsoredFeeAmount).toBe('42');
    expect(result.executedAdapters).toEqual([
      {
        executorKind: 'evm_eoa',
        meta: {
          chainId: 11155111,
          sponsorAddress: `0x${'99'.repeat(20)}`,
        },
      },
    ]);
  });

  test('confirms submitted deployed recovery and activates the canonical signer after receipt confirmation', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { confirmSubmittedSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const signerWrites: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const submittedExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'submitted',
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        transactionHash: `0x${'aa'.repeat(32)}`,
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          recoveryTargetMode: 'deployed',
          linkedAccount: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 11155111,
          },
        },
      };
      const key = `${submittedExecution.sessionId}:${submittedExecution.chainIdKey}:${submittedExecution.accountAddress}:${submittedExecution.action}`;
      executionState.set(key, submittedExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => {
          signerWrites.push(record);
          return { ok: true as const, record };
        },
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          executionState.set(key, {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: submittedExecution.createdAtMs,
            updatedAtMs: Date.now(),
          });
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'evm_recovering',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const executed = await confirmSubmittedSmartAccountRecoveryExecutions(service as any, {
        confirmSubmittedRecovery: async ({ transactionHash }: { transactionHash: string }) => ({
          status: 'confirmed',
          transactionHash,
          metadataPatch: {
            sponsoredGasUsed: '12345',
          },
        }),
      });

      return {
        executed,
        signerWrites,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.executed.ok).toBe(true);
    expect((result.executed as any).result).toEqual({
      processed: 1,
      confirmed: 1,
      submitted: 0,
      skipped: 0,
      failed: 0,
    });
    expect(result.signerWrites).toHaveLength(1);
    expect(result.signerWrites[0]?.status).toBe('active');
    expect(result.finalExecution?.status).toBe('confirmed');
    expect(result.finalExecution?.transactionHash).toBe(`0x${'aa'.repeat(32)}`);
    expect(result.finalExecution?.metadata?.sponsoredGasUsed).toBe('12345');
    expect(result.sessionUpdates.at(-1)?.status).toBe('completed');
  });

  test('leaves submitted deployed recovery submitted when no confirmer is configured', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { confirmSubmittedSmartAccountRecoveryExecutions } = await import(paths.server);
      const sessionUpdates: Array<Record<string, unknown>> = [];
      const executionState = new Map<string, Record<string, unknown>>();
      const submittedExecution = {
        version: 'recovery_execution_v1',
        sessionId: 'ABC123',
        userId: 'alice.testnet',
        nearAccountId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'22'.repeat(20)}`,
        action: 'recover_add_owner',
        status: 'submitted',
        createdAtMs: Date.now(),
        updatedAtMs: Date.now(),
        transactionHash: `0x${'aa'.repeat(32)}`,
        metadata: {
          newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          recoveryTargetMode: 'deployed',
        },
      };
      const key = `${submittedExecution.sessionId}:${submittedExecution.chainIdKey}:${submittedExecution.accountAddress}:${submittedExecution.action}`;
      executionState.set(key, submittedExecution);

      const service = {
        listRecoveryExecutionsByStatus: async ({ status }: { status: string }) => ({
          ok: true as const,
          records: Array.from(executionState.values()).filter((record) => record.status === status),
        }),
        listAccountSignersByAccount: async () => ({ ok: true as const, records: [] }),
        putAccountSigner: async (record: Record<string, unknown>) => ({ ok: true as const, record }),
        recordRecoveryExecution: async (input: Record<string, unknown>) => {
          executionState.set(key, {
            ...(executionState.get(key) || {}),
            ...input,
            version: 'recovery_execution_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            createdAtMs: submittedExecution.createdAtMs,
            updatedAtMs: Date.now(),
          });
          return { ok: true as const, record: executionState.get(key) };
        },
        getRecoverySession: async () => ({
          ok: true as const,
          record: {
            version: 'recovery_session_v1',
            sessionId: 'ABC123',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            deviceNumber: 7,
            status: 'evm_recovering',
            createdAtMs: 1,
            updatedAtMs: 1,
            expiresAtMs: Date.now() + 60_000,
            newNearPublicKey: 'ed25519:recovery-key',
            newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
          },
        }),
        listRecoveryExecutions: async () => ({
          ok: true as const,
          records: Array.from(executionState.values()),
        }),
        updateRecoverySessionStatus: async (input: Record<string, unknown>) => {
          sessionUpdates.push(input);
          return { ok: true as const, record: input };
        },
      };

      const executed = await confirmSubmittedSmartAccountRecoveryExecutions(service as any, {});

      return {
        executed,
        finalExecution: executionState.get(key),
        sessionUpdates,
      };
    }, { paths: IMPORT_PATHS });

    expect(result.executed.ok).toBe(true);
    expect((result.executed as any).result).toEqual({
      processed: 1,
      confirmed: 0,
      submitted: 0,
      skipped: 1,
      failed: 0,
    });
    expect(result.finalExecution?.status).toBe('submitted');
    expect(result.sessionUpdates).toEqual([]);
  });

  test('keeps submitted sponsored recovery in submitted state when receipt confirmation times out', async ({
    page,
  }) => {
    const result = await page.evaluate(async ({ paths }) => {
      const { createSponsoredRecoverySubmittedConfirmer } = await import(paths.server);
      const confirm = createSponsoredRecoverySubmittedConfirmer({
        config: {
          executorsByChain: new Map([
            [
              11155111,
              {
                chainId: 11155111,
                rpcUrl: 'https://rpc.example.test',
                sponsorAddress: `0x${'99'.repeat(20)}`,
                sponsorPrivateKeyHex: `0x${'88'.repeat(32)}`,
                maxPriorityFeePerGasFloor: 1n,
                maxFeePerGasFloor: 2n,
              },
            ],
          ]),
        },
        createClient: () =>
          ({
            request: async () => null,
            getTransactionReceipt: async () => null,
            getBlockByNumber: async () => null,
            getTransactionByHash: async () => null,
            getTransactionCount: async () => 0n,
            waitForTransactionReceipt: async () => {
              const error = new Error('Timed out waiting for tx receipt after 90000ms') as Error & {
                finalizationBranch?: string;
              };
              error.finalizationBranch = 'timeout';
              throw error;
            },
          }) as any,
      });
      return await confirm({
        execution: {
          version: 'recovery_execution_v1',
          sessionId: 'ABC123',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: `0x${'22'.repeat(20)}`,
          action: 'recover_add_owner',
          status: 'submitted',
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {},
        },
        newOwnerAddress: `0x${'11'.repeat(20)}`,
        transactionHash: `0x${'aa'.repeat(32)}`,
      });
    }, { paths: IMPORT_PATHS });

    expect(result.status).toBe('submitted');
    expect(result.transactionHash).toBe(`0x${'aa'.repeat(32)}`);
    expect(result.metadataPatch?.confirmationPendingReason).toContain('Timed out waiting for tx receipt');
    expect(result.metadataPatch?.confirmationFinalizationBranch).toBe('timeout');
  });
});
