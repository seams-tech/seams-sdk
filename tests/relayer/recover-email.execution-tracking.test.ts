import { test, expect } from '@playwright/test';
import {
  confirmSubmittedSmartAccountRecoveryExecutions,
  executePendingSmartAccountRecoveryExecutions,
  retryFailedSmartAccountRecoveryExecutions,
} from '@server/core/recoveryAuthority';
import {
  getRecoveryAuthorityFunctionSelector,
  getRecoveryAuthorityFunctionSignature,
} from '@server/core/recoveryAuthorityAuthorization';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  buildRecoveryEmailBody,
  buildRecoveryEmailPayload,
  buildRecoveryEmailSubject,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';
import { callCf, fetchJson, makeCfCtx, makeFakeAuthService, startExpressRouter } from './helpers';

async function makeRecoveryEmailFixture(input?: {
  nowMs?: number;
  newEvmOwnerAddress?: string;
}): Promise<{
  payload: RecoveryEmailPayload;
  payloadHash: string;
  subject: string;
  raw: string;
  sessionRecord: Record<string, unknown>;
}> {
  const nowMs = input?.nowMs ?? Date.now();
  const payload = buildRecoveryEmailPayload({
    nearAccountId: 'alice.testnet',
    recoverySessionId: 'ABC123',
    newNearPublicKey: 'ed25519:recovery-key',
    newEvmOwnerAddress: input?.newEvmOwnerAddress || `0x${'11'.repeat(20)}`,
    deadlineEpochSeconds: 1_893_456_000,
  });
  const payloadHash = await hashRecoveryEmailPayload(payload);
  const subject = buildRecoveryEmailSubject(payload);
  const raw = [
    `Subject: ${subject}`,
    'From: sender@example.com',
    '',
    buildRecoveryEmailBody(payload),
  ].join('\r\n');

  return {
    payload,
    payloadHash,
    subject,
    raw,
    sessionRecord: makeRecoverySessionRecord({
      nowMs,
      payload,
      payloadHash,
    }),
  };
}

function makeRecoverySessionRecord(input: {
  nowMs?: number;
  payload: RecoveryEmailPayload;
  payloadHash: string;
}) {
  const nowMs = input.nowMs ?? Date.now();
  return {
    version: 'recovery_session_v1' as const,
    sessionId: input.payload.recoverySessionId,
    userId: 'alice.testnet',
    nearAccountId: input.payload.nearAccountId,
    signerSlot: 7,
    status: 'prepared' as const,
    createdAtMs: nowMs,
    updatedAtMs: nowMs,
    expiresAtMs: nowMs + 30 * 60_000,
    newNearPublicKey: input.payload.newNearPublicKey,
    newEvmOwnerAddress: input.payload.newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: input.payload.deadlineEpochSeconds,
    recoveryEmailPayloadHash: input.payloadHash,
  };
}

function makeExecutionKey(input: {
  sessionId: unknown;
  chainIdKey: unknown;
  accountAddress: unknown;
  action: unknown;
}): string {
  return `${String(input.sessionId)}:${String(input.chainIdKey)}:${String(input.accountAddress)}:${String(input.action)}`;
}

function makeSignerKey(input: {
  chainIdKey: unknown;
  accountAddress: unknown;
  signerId: unknown;
}): string {
  return `${String(input.chainIdKey)}:${String(input.accountAddress)}:${String(input.signerId)}`;
}

function buildRecoverySpecFixture(input?: {
  newOwnerAddress?: `0x${string}`;
  accountAddress?: `0x${string}`;
}) {
  const contractMethod = 'verifyAndRecover' as const;
  const newOwnerAddress = input?.newOwnerAddress || (`0x${'11'.repeat(20)}` as const);
  const accountAddress = input?.accountAddress || (`0x${'22'.repeat(20)}` as const);
  const selector = getRecoveryAuthorityFunctionSelector(contractMethod);
  const functionSignature = getRecoveryAuthorityFunctionSignature(contractMethod);
  return {
    version: 'seams_evm_recovery_spec_v1' as const,
    newOwnerAddress,
    call: {
      to: accountAddress,
      data: selector,
      gasLimit: '250000',
      valueWei: '0' as const,
      contractMethod,
      functionSignature,
      selector,
    },
    authorization: {
      version: 'recovery_authority_authorization_v1' as const,
      contractMethod,
      authorityAddress: `0x${'99'.repeat(20)}` as const,
      domain: {
        name: 'SeamsSmartAccountRecovery',
        version: '1',
        chainId: 11155111,
        verifyingContract: accountAddress,
      },
      payload: {
        nearAccountIdHash: `0x${'11'.repeat(32)}` as const,
        newNearKeyHash: `0x${'22'.repeat(32)}` as const,
        newOwner: newOwnerAddress,
        recoverySessionHash: `0x${'33'.repeat(32)}` as const,
        nonce: `0x${'44'.repeat(32)}` as const,
        deadline: `0x${'55'.repeat(32)}` as const,
      },
      digest: `0x${'66'.repeat(32)}` as const,
      signature: `0x${'77'.repeat(65)}` as const,
    },
  };
}

test.describe('recover-email execution tracking', () => {
  test('express route rejects tampered recovery email payload before NEAR or EVM continuation runs', async () => {
    const recovery = await makeRecoveryEmailFixture({
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    });
    const tamperedPayload = buildRecoveryEmailPayload({
      nearAccountId: recovery.payload.nearAccountId,
      recoverySessionId: recovery.payload.recoverySessionId,
      newNearPublicKey: recovery.payload.newNearPublicKey,
      newEvmOwnerAddress: `0x${'aa'.repeat(20)}`,
      deadlineEpochSeconds: recovery.payload.deadlineEpochSeconds,
    });
    const tamperedRaw = [
      `Subject: ${recovery.subject}`,
      'From: sender@example.com',
      '',
      buildRecoveryEmailBody(tamperedPayload),
    ].join('\r\n');
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
    };
    const executionHistory: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: { ...sessionRecord } as any,
      }),
      recordRecoveryExecution: async (input) => {
        executionHistory.push(input as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: {
            version: 'recovery_execution_v1',
            sessionId: String((input as any).sessionId),
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: String((input as any).chainIdKey),
            accountAddress: String((input as any).accountAddress),
            action: String((input as any).action),
            status: String((input as any).status),
            createdAtMs: Date.now(),
            updatedAtMs: Date.now(),
          } as any,
        };
      },
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: {
            ...sessionRecord,
            status: String((input as any).status),
          } as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: true,
          transactionHash: 'near-tx-should-not-run',
          message: 'submitted',
        }),
      },
    });
    const router = createRelayRouter(service);
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/recover-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'sender@example.com',
          to: 'recover@wallet.example.test',
          headers: { Subject: recovery.subject },
          raw: tamperedRaw,
          rawSize: 1,
        }),
      });

      expect(res.status).toBe(400);
      expect(res.json?.code).toBe('invalid_recovery_session');
      expect(executionHistory).toHaveLength(0);
      expect(sessionUpdates).toHaveLength(0);
    } finally {
      await srv.close();
    }
  });

  test('express route records pending and submitted NEAR recovery execution state', async () => {
    const recovery = await makeRecoveryEmailFixture({
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    });
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
    };
    const recorded: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: { ...sessionRecord } as any,
      }),
      listSmartAccountRecoverySubjects: async () => ({
        ok: true,
        records: [
          {
            version: 'smart_account_recovery_subject_v1' as const,
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            createdAtMs: Date.now(),
            updatedAtMs: Date.now(),
            metadata: {
              accountModel: 'erc4337',
              chain: 'evm',
              chainId: 11155111,
              deployed: true,
              sponsorshipScope: {
                orgId: 'org_recovery',
                environmentId: 'env_recovery',
              },
            },
          },
        ],
      }),
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        sessionRecord.status = String((input as any).status);
        sessionRecord.updatedAtMs = Date.now();
        sessionRecord.metadata = {
          ...(sessionRecord.metadata || {}),
          ...(((input as any).metadataPatch || {}) as Record<string, unknown>),
        };
        return {
          ok: true,
          record: {
            ...sessionRecord,
          } as any,
        };
      },
      recordRecoveryExecution: async (input) => {
        recorded.push(input as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: {
            version: 'recovery_execution_v1',
            sessionId: String((input as any).sessionId),
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: String((input as any).chainIdKey),
            accountAddress: String((input as any).accountAddress),
            action: String((input as any).action),
            status: String((input as any).status),
            createdAtMs: Date.now(),
            updatedAtMs: Date.now(),
          } as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: true,
          transactionHash: 'near-tx-1',
          message: 'submitted',
        }),
      },
    });
    const router = createRelayRouter(service);
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/recover-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'sender@example.com',
          to: 'recover@wallet.example.test',
          headers: { Subject: recovery.subject },
          raw: recovery.raw,
          rawSize: 1,
        }),
      });

      expect(res.status).toBe(202);
      expect(recorded).toHaveLength(3);
      expect(recorded[0]?.status).toBe('pending');
      expect(recorded[1]?.status).toBe('submitted');
      expect(recorded[1]?.transactionHash).toBe('near-tx-1');
      expect(recorded[1]?.chainIdKey).toBe('near:testnet');
      expect(recorded[2]?.status).toBe('pending');
      expect(recorded[2]?.action).toBe('recover_add_owner');
      expect(recorded[2]?.chainIdKey).toBe('evm:11155111');
      expect(recorded[2]?.accountAddress).toBe(`0x${'22'.repeat(20)}`);
      expect((recorded[2]?.metadata as any)?.newEvmOwnerAddress).toBe(`0x${'11'.repeat(20)}`);
      expect((recorded[2]?.metadata as any)?.nearRecoveryTransactionHash).toBe('near-tx-1');
      expect((recorded[2]?.metadata as any)?.recoveryTargetMode).toBe('deployed');
      expect((recorded[2]?.metadata as any)?.sponsorshipScope).toEqual({
        orgId: 'org_recovery',
        environmentId: 'env_recovery',
      });
      expect(sessionUpdates).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            sessionId: 'ABC123',
            status: 'verified',
            metadataPatch: expect.objectContaining({
              verifiedRecoveryPayloadHash: recovery.payloadHash,
              verifiedNearSuccessGate: 'pending',
            }),
          }),
          expect.objectContaining({
            sessionId: 'ABC123',
            status: 'evm_recovering',
            metadataPatch: expect.objectContaining({
              nearRecoveryTransactionHash: 'near-tx-1',
              queuedEvmRecoveryCount: 1,
            }),
          }),
        ]),
      );
    } finally {
      await srv.close();
    }
  });

  test('cloudflare route records pending and failed NEAR recovery execution state', async () => {
    const recovery = await makeRecoveryEmailFixture();
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
    };
    const recorded: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const { ctx } = makeCfCtx();
    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: { ...sessionRecord } as any,
      }),
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        sessionRecord.status = String((input as any).status);
        sessionRecord.updatedAtMs = Date.now();
        sessionRecord.metadata = {
          ...(sessionRecord.metadata || {}),
          ...(((input as any).metadataPatch || {}) as Record<string, unknown>),
        };
        return {
          ok: true,
          record: {
            ...sessionRecord,
          } as any,
        };
      },
      recordRecoveryExecution: async (input) => {
        recorded.push(input as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: {
            version: 'recovery_execution_v1',
            sessionId: String((input as any).sessionId),
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: String((input as any).chainIdKey),
            accountAddress: String((input as any).accountAddress),
            action: String((input as any).action),
            status: String((input as any).status),
            createdAtMs: Date.now(),
            updatedAtMs: Date.now(),
          } as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: false,
          error: 'relay submission failed',
          message: 'relay submission failed',
        }),
      },
    });
    const handler = createCloudflareRouter(service);

    const res = await callCf(handler, {
      method: 'POST',
      path: '/recover-email',
      headers: { 'Content-Type': 'application/json' },
      ctx,
      body: {
        from: 'sender@example.com',
        to: 'recover@wallet.example.test',
        headers: { Subject: recovery.subject },
        raw: recovery.raw,
        rawSize: 1,
      },
    });

    expect(res.status).toBe(400);
    expect(recorded).toHaveLength(2);
    expect(recorded[0]?.status).toBe('pending');
    expect(recorded[1]?.status).toBe('failed');
    expect(recorded[1]?.errorCode).toBe('near_email_recovery_submit_failed');
    expect(sessionUpdates).toEqual([
      expect.objectContaining({
        sessionId: 'ABC123',
        status: 'verified',
        metadataPatch: expect.objectContaining({
          verifiedRecoveryPayloadHash: recovery.payloadHash,
          verifiedNearSuccessGate: 'pending',
        }),
      }),
      expect.objectContaining({
        sessionId: 'ABC123',
        status: 'failed',
        metadataPatch: expect.objectContaining({
          recoveryFailureCode: 'near_email_recovery_submit_failed',
        }),
      }),
    ]);
  });

  test('express route auto-dispatches undeployed smart-account recovery continuation', async () => {
    const recovery = await makeRecoveryEmailFixture({
      nowMs: Date.now(),
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    });
    const executionHistory: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const signerWrites: Array<Record<string, unknown>> = [];
    const nowMs = Date.now();
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
      status: 'prepared' as const,
    };
    const executionState = new Map<string, Record<string, unknown>>();
    const signerState = new Map<string, Record<string, unknown>>();

    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: sessionRecord as any,
      }),
      listSmartAccountRecoverySubjects: async () => ({
        ok: true,
        records: [
          {
            version: 'smart_account_recovery_subject_v1' as const,
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey: 'evm:11155111',
            accountAddress: `0x${'22'.repeat(20)}`,
            createdAtMs: nowMs,
            updatedAtMs: nowMs,
            metadata: {
              accountModel: 'erc4337',
              chain: 'evm',
              chainId: 11155111,
              deployed: false,
              counterfactualAddress: `0x${'22'.repeat(20)}`,
            },
          },
        ],
      }),
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        (sessionRecord as any).status = String((input as any).status);
        (sessionRecord as any).updatedAtMs = Date.now();
        (sessionRecord as any).metadata = {
          ...((sessionRecord as any).metadata || {}),
          ...(((input as any).metadataPatch || {}) as Record<string, unknown>),
        };
        return {
          ok: true,
          record: { ...(sessionRecord as any) },
        };
      },
      recordRecoveryExecution: async (input) => {
        executionHistory.push(input as unknown as Record<string, unknown>);
        const nextRecord = {
          ...(executionState.get(makeExecutionKey(input as any)) || {}),
          ...(input as any as Record<string, unknown>),
          version: 'recovery_execution_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          createdAtMs:
            executionState.get(makeExecutionKey(input as any))?.createdAtMs || Date.now(),
          updatedAtMs: Date.now(),
        };
        executionState.set(makeExecutionKey(nextRecord as any), nextRecord);
        return {
          ok: true,
          record: nextRecord as any,
        };
      },
      listRecoveryExecutions: async () => ({
        ok: true,
        records: Array.from(executionState.values()) as any,
      }),
      listRecoveryExecutionsByStatus: async (input) => ({
        ok: true,
        records: Array.from(executionState.values()).filter((record) => {
          if (String(record.status) !== String((input as any).status)) return false;
          if ((input as any).action && String(record.action) !== String((input as any).action)) {
            return false;
          }
          return true;
        }) as any,
      }),
      listAccountSignersByAccount: async (input) => ({
        ok: true,
        records: Array.from(signerState.values()).filter(
          (record) =>
            String(record.chainIdKey) === String((input as any).chainIdKey) &&
            String(record.accountAddress) === String((input as any).accountAddress),
        ) as any,
      }),
      putAccountSigner: async (record) => {
        signerWrites.push(record as unknown as Record<string, unknown>);
        signerState.set(makeSignerKey(record as any), record as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: record as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: true,
          transactionHash: 'near-tx-undeployed',
          message: 'submitted',
        }),
      },
    });
    const router = createRelayRouter(service);
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/recover-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'sender@example.com',
          to: 'recover@wallet.example.test',
          headers: { Subject: recovery.subject },
          raw: recovery.raw,
          rawSize: 1,
        }),
      });

      expect(res.status).toBe(202);
      expect(executionHistory).toEqual([
        expect.objectContaining({
          action: 'near_email_recovery',
          status: 'pending',
        }),
        expect.objectContaining({
          action: 'near_email_recovery',
          status: 'submitted',
          transactionHash: 'near-tx-undeployed',
        }),
        expect.objectContaining({
          action: 'recover_add_owner',
          status: 'pending',
          metadata: expect.objectContaining({
            recoveryTargetMode: 'undeployed',
          }),
        }),
        expect.objectContaining({
          action: 'recover_add_owner',
          status: 'confirmed',
          metadata: expect.objectContaining({
            recoveryTargetMode: 'undeployed',
          }),
        }),
      ]);
      expect(signerWrites).toHaveLength(1);
      expect(signerWrites[0]?.signerId).toBe(`0x${'11'.repeat(20)}`);
      expect(signerWrites[0]?.status).toBe('active');
      expect(Array.from(executionState.values())).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            action: 'recover_add_owner',
            status: 'confirmed',
          }),
        ]),
      );
      expect(sessionUpdates.at(-1)).toEqual(
        expect.objectContaining({
          sessionId: 'ABC123',
          status: 'completed',
          metadataPatch: expect.objectContaining({
            evmRecoveryExecutionSummary: expect.objectContaining({
              total: 1,
              confirmed: 1,
              failed: 0,
            }),
          }),
        }),
      );
    } finally {
      await srv.close();
    }
  });

  test('one verified recovery email drives NEAR key recovery and deployed EVM owner recovery', async () => {
    const recovery = await makeRecoveryEmailFixture({
      nowMs: Date.now(),
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    });
    const executionHistory: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const signerWrites: Array<Record<string, unknown>> = [];
    const nowMs = Date.now();
    const accountAddress = `0x${'22'.repeat(20)}` as `0x${string}`;
    const newOwnerAddress = `0x${'11'.repeat(20)}` as `0x${string}`;
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
      status: 'prepared' as const,
    };
    const executionState = new Map<string, Record<string, unknown>>();
    const signerState = new Map<string, Record<string, unknown>>();
    const recoverySubject = {
      version: 'smart_account_recovery_subject_v1' as const,
      userId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      chainIdKey: 'evm:11155111',
      accountAddress,
      createdAtMs: nowMs,
      updatedAtMs: nowMs,
      metadata: {
        accountModel: 'erc4337',
        chain: 'evm',
        chainId: 11155111,
        deployed: true,
        factory: `0x${'33'.repeat(20)}`,
        entryPoint: `0x${'44'.repeat(20)}`,
        counterfactualAddress: accountAddress,
        sponsorshipScope: {
          orgId: 'org_recovery',
          environmentId: 'env_recovery',
        },
      },
    };

    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: sessionRecord as any,
      }),
      listSmartAccountRecoverySubjects: async () => ({
        ok: true,
        records: [recoverySubject],
      }),
      getSmartAccountRecoverySubjectByAccount: async () => ({
        ok: true,
        record: recoverySubject as any,
      }),
      putSmartAccountRecoverySubject: async (record) => {
        recoverySubject.updatedAtMs = Number((record as any).updatedAtMs || Date.now());
        recoverySubject.metadata = { ...((record as any).metadata || {}) };
        return {
          ok: true,
          record: {
            ...recoverySubject,
          } as any,
        };
      },
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        (sessionRecord as any).status = String((input as any).status);
        (sessionRecord as any).updatedAtMs = Date.now();
        (sessionRecord as any).metadata = {
          ...((sessionRecord as any).metadata || {}),
          ...(((input as any).metadataPatch || {}) as Record<string, unknown>),
        };
        return {
          ok: true,
          record: { ...(sessionRecord as any) },
        };
      },
      recordRecoveryExecution: async (input) => {
        executionHistory.push(input as unknown as Record<string, unknown>);
        const nextRecord = {
          ...(executionState.get(makeExecutionKey(input as any)) || {}),
          ...(input as any as Record<string, unknown>),
          version: 'recovery_execution_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          createdAtMs:
            executionState.get(makeExecutionKey(input as any))?.createdAtMs || Date.now(),
          updatedAtMs: Date.now(),
        };
        executionState.set(makeExecutionKey(nextRecord as any), nextRecord);
        return {
          ok: true,
          record: nextRecord as any,
        };
      },
      listRecoveryExecutions: async () => ({
        ok: true,
        records: Array.from(executionState.values()) as any,
      }),
      listRecoveryExecutionsByStatus: async (input) => ({
        ok: true,
        records: Array.from(executionState.values()).filter((record) => {
          if (String(record.status) !== String((input as any).status)) return false;
          if ((input as any).action && String(record.action) !== String((input as any).action)) {
            return false;
          }
          return true;
        }) as any,
      }),
      listAccountSignersByAccount: async (input) => ({
        ok: true,
        records: Array.from(signerState.values()).filter(
          (record) =>
            String(record.chainIdKey) === String((input as any).chainIdKey) &&
            String(record.accountAddress) === String((input as any).accountAddress),
        ) as any,
      }),
      putAccountSigner: async (record) => {
        signerWrites.push(record as unknown as Record<string, unknown>);
        signerState.set(makeSignerKey(record as any), record as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: record as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: true,
          transactionHash: 'near-tx-deployed',
          message: 'submitted',
        }),
      },
    });
    const router = createRelayRouter(service);
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/recover-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'sender@example.com',
          to: 'recover@wallet.example.test',
          headers: { Subject: recovery.subject },
          raw: recovery.raw,
          rawSize: 1,
        }),
      });

      expect(res.status).toBe(202);
      expect(executionHistory).toEqual([
        expect.objectContaining({
          action: 'near_email_recovery',
          status: 'pending',
          metadata: expect.objectContaining({
            expectedNewNearPublicKey: recovery.payload.newNearPublicKey,
            expectedNewEvmOwnerAddress: newOwnerAddress,
            recoveryEmailPayloadHash: recovery.payloadHash,
          }),
        }),
        expect.objectContaining({
          action: 'near_email_recovery',
          status: 'submitted',
          transactionHash: 'near-tx-deployed',
          metadata: expect.objectContaining({
            expectedNewNearPublicKey: recovery.payload.newNearPublicKey,
            expectedNewEvmOwnerAddress: newOwnerAddress,
            recoveryEmailPayloadHash: recovery.payloadHash,
          }),
        }),
        expect.objectContaining({
          action: 'recover_add_owner',
          status: 'pending',
          metadata: expect.objectContaining({
            expectedNewNearPublicKey: recovery.payload.newNearPublicKey,
            newEvmOwnerAddress: newOwnerAddress,
            nearRecoveryTransactionHash: 'near-tx-deployed',
            recoveryEmailPayloadHash: recovery.payloadHash,
            recoveryTargetMode: 'deployed',
            sponsorshipScope: {
              orgId: 'org_recovery',
              environmentId: 'env_recovery',
            },
          }),
        }),
      ]);

      const submittedExecution = await executePendingSmartAccountRecoveryExecutions(
        service as any,
        {
          executeDeployedRecovery: async () => ({
            status: 'submitted',
            transactionHash: `0x${'aa'.repeat(32)}`,
            metadataPatch: {
              recoverySpec: buildRecoverySpecFixture({
                newOwnerAddress,
                accountAddress,
              }),
              sponsoredPolicyId: 'policy_recovery',
            },
          }),
        },
      );
      expect(submittedExecution).toEqual({
        ok: true,
        result: {
          processed: 1,
          confirmed: 0,
          submitted: 1,
          skipped: 0,
          failed: 0,
        },
      });

      const confirmedExecution = await confirmSubmittedSmartAccountRecoveryExecutions(
        service as any,
        {
          confirmSubmittedRecovery: async ({ transactionHash }) => ({
            status: 'confirmed',
            transactionHash,
            metadataPatch: {
              sponsoredGasUsed: '12345',
              sponsoredEffectiveGasPrice: '67890',
              sponsoredFeeAmount: '838102050',
            },
          }),
        },
      );
      expect(confirmedExecution).toEqual({
        ok: true,
        result: {
          processed: 1,
          confirmed: 1,
          submitted: 0,
          skipped: 0,
          failed: 0,
        },
      });

      const finalExecution = Array.from(executionState.values()).find(
        (record) => record.action === 'recover_add_owner',
      );
      expect(finalExecution).toEqual(
        expect.objectContaining({
          action: 'recover_add_owner',
          status: 'confirmed',
          transactionHash: `0x${'aa'.repeat(32)}`,
          metadata: expect.objectContaining({
            recoveryTargetMode: 'deployed',
            sponsoredGasUsed: '12345',
            sponsoredEffectiveGasPrice: '67890',
            sponsoredFeeAmount: '838102050',
            recoverySpec: expect.objectContaining({
              version: 'seams_evm_recovery_spec_v1',
              newOwnerAddress,
              call: expect.objectContaining({
                to: accountAddress,
                selector: getRecoveryAuthorityFunctionSelector('verifyAndRecover'),
              }),
            }),
          }),
        }),
      );
      expect(signerWrites).toHaveLength(1);
      expect(signerWrites[0]?.signerId).toBe(newOwnerAddress);
      expect(signerWrites[0]?.status).toBe('active');
      expect(sessionUpdates).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            sessionId: 'ABC123',
            status: 'verified',
            metadataPatch: expect.objectContaining({
              verifiedRecoveryPayloadHash: recovery.payloadHash,
            }),
          }),
          expect.objectContaining({
            sessionId: 'ABC123',
            status: 'evm_recovering',
            metadataPatch: expect.objectContaining({
              nearRecoveryTransactionHash: 'near-tx-deployed',
              queuedEvmRecoveryCount: 1,
              verifiedNearSuccessGate: 'passed',
            }),
          }),
        ]),
      );
      expect(sessionUpdates.at(-1)).toEqual(
        expect.objectContaining({
          sessionId: 'ABC123',
          status: 'completed',
          metadataPatch: expect.objectContaining({
            evmRecoveryExecutionSummary: expect.objectContaining({
              total: 1,
              pending: 0,
              submitted: 0,
              confirmed: 1,
              failed: 0,
              skipped: 0,
            }),
          }),
        }),
      );
      expect(sessionRecord.newNearPublicKey).toBe(recovery.payload.newNearPublicKey);
      expect(sessionRecord.newEvmOwnerAddress).toBe(newOwnerAddress);
    } finally {
      await srv.close();
    }
  });

  test('partial deployed EVM recovery failure preserves per-target state and retries deterministically', async () => {
    const nowMs = Date.now();
    const recovery = await makeRecoveryEmailFixture({
      nowMs,
      newEvmOwnerAddress: `0x${'11'.repeat(20)}`,
    });
    const executionHistory: Array<Record<string, unknown>> = [];
    const sessionUpdates: Array<Record<string, unknown>> = [];
    const signerWrites: Array<Record<string, unknown>> = [];
    const newOwnerAddress = `0x${'11'.repeat(20)}` as `0x${string}`;
    const accountAddressA = `0x${'22'.repeat(20)}` as `0x${string}`;
    const accountAddressB = `0x${'33'.repeat(20)}` as `0x${string}`;
    const sessionRecord = {
      ...(recovery.sessionRecord as any),
      status: 'prepared' as const,
    };
    const executionState = new Map<string, Record<string, unknown>>();
    const signerState = new Map<string, Record<string, unknown>>();
    const recoverySubjects = new Map<string, Record<string, unknown>>([
      [
        `evm:11155111:${accountAddressA}`,
        {
          version: 'smart_account_recovery_subject_v1' as const,
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: accountAddressA,
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
          metadata: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 11155111,
            deployed: true,
            factory: `0x${'44'.repeat(20)}`,
            entryPoint: `0x${'55'.repeat(20)}`,
            counterfactualAddress: accountAddressA,
            sponsorshipScope: {
              orgId: 'org_recovery',
              environmentId: 'env_recovery',
            },
          },
        },
      ],
      [
        `evm:1:${accountAddressB}`,
        {
          version: 'smart_account_recovery_subject_v1' as const,
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:1',
          accountAddress: accountAddressB,
          createdAtMs: nowMs,
          updatedAtMs: nowMs,
          metadata: {
            accountModel: 'erc4337',
            chain: 'evm',
            chainId: 1,
            deployed: true,
            factory: `0x${'66'.repeat(20)}`,
            entryPoint: `0x${'77'.repeat(20)}`,
            counterfactualAddress: accountAddressB,
            sponsorshipScope: {
              orgId: 'org_recovery',
              environmentId: 'env_recovery',
            },
          },
        },
      ],
    ]);

    const service = makeFakeAuthService({
      getRecoverySession: async () => ({
        ok: true,
        record: sessionRecord as any,
      }),
      listSmartAccountRecoverySubjects: async () => ({
        ok: true,
        records: Array.from(recoverySubjects.values()) as any,
      }),
      getSmartAccountRecoverySubjectByAccount: async (input) => ({
        ok: true,
        record:
          (recoverySubjects.get(
            `${String((input as any).chainIdKey)}:${String((input as any).accountAddress)}`,
          ) as any) || null,
      }),
      putSmartAccountRecoverySubject: async (record) => {
        const key = `${String((record as any).chainIdKey)}:${String((record as any).accountAddress)}`;
        recoverySubjects.set(key, record as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: record as any,
        };
      },
      updateRecoverySessionStatus: async (input) => {
        sessionUpdates.push(input as unknown as Record<string, unknown>);
        (sessionRecord as any).status = String((input as any).status);
        (sessionRecord as any).updatedAtMs = Date.now();
        (sessionRecord as any).metadata = {
          ...((sessionRecord as any).metadata || {}),
          ...(((input as any).metadataPatch || {}) as Record<string, unknown>),
        };
        return {
          ok: true,
          record: { ...(sessionRecord as any) },
        };
      },
      recordRecoveryExecution: async (input) => {
        executionHistory.push(input as unknown as Record<string, unknown>);
        const key = makeExecutionKey(input as any);
        const nextRecord = {
          ...(executionState.get(key) || {}),
          ...(input as any as Record<string, unknown>),
          version: 'recovery_execution_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          createdAtMs: executionState.get(key)?.createdAtMs || Date.now(),
          updatedAtMs: Date.now(),
        };
        executionState.set(key, nextRecord);
        return {
          ok: true,
          record: nextRecord as any,
        };
      },
      listRecoveryExecutions: async () => ({
        ok: true,
        records: Array.from(executionState.values()) as any,
      }),
      listRecoveryExecutionsByStatus: async (input) => ({
        ok: true,
        records: Array.from(executionState.values()).filter((record) => {
          if (String(record.status) !== String((input as any).status)) return false;
          if ((input as any).action && String(record.action) !== String((input as any).action)) {
            return false;
          }
          return true;
        }) as any,
      }),
      listAccountSignersByAccount: async (input) => ({
        ok: true,
        records: Array.from(signerState.values()).filter(
          (record) =>
            String(record.chainIdKey) === String((input as any).chainIdKey) &&
            String(record.accountAddress) === String((input as any).accountAddress),
        ) as any,
      }),
      putAccountSigner: async (record) => {
        signerWrites.push(record as unknown as Record<string, unknown>);
        signerState.set(makeSignerKey(record as any), record as unknown as Record<string, unknown>);
        return {
          ok: true,
          record: record as any,
        };
      },
      emailRecovery: {
        requestEmailRecovery: async () => ({
          success: true,
          transactionHash: 'near-tx-partial',
          message: 'submitted',
        }),
      },
    });
    const router = createRelayRouter(service);
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/recover-email`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from: 'sender@example.com',
          to: 'recover@wallet.example.test',
          headers: { Subject: recovery.subject },
          raw: recovery.raw,
          rawSize: 1,
        }),
      });

      expect(res.status).toBe(202);
      const queuedExecutions = Array.from(executionState.values()).filter(
        (record) => record.action === 'recover_add_owner',
      );
      expect(queuedExecutions).toHaveLength(2);

      const firstAttempt = await executePendingSmartAccountRecoveryExecutions(service as any, {
        executeDeployedRecovery: async ({ execution }) => {
          if (execution.accountAddress === accountAddressA) {
            return {
              status: 'confirmed',
              transactionHash: `0x${'aa'.repeat(32)}`,
              metadataPatch: {
                recoverySpec: buildRecoverySpecFixture({
                  newOwnerAddress,
                  accountAddress: accountAddressA,
                }),
              },
            };
          }
          return {
            status: 'failed',
            errorCode: 'temporary_rpc_error',
            errorMessage: 'temporary relay outage',
            metadataPatch: {
              retryEligible: true,
              failurePhase: 'submission',
            },
          };
        },
      });

      expect(firstAttempt).toEqual({
        ok: true,
        result: {
          processed: 2,
          confirmed: 1,
          submitted: 0,
          skipped: 0,
          failed: 1,
        },
      });

      const firstA = executionState.get(
        makeExecutionKey({
          sessionId: 'ABC123',
          chainIdKey: 'evm:11155111',
          accountAddress: accountAddressA,
          action: 'recover_add_owner',
        }),
      );
      const firstB = executionState.get(
        makeExecutionKey({
          sessionId: 'ABC123',
          chainIdKey: 'evm:1',
          accountAddress: accountAddressB,
          action: 'recover_add_owner',
        }),
      );
      expect(firstA).toEqual(
        expect.objectContaining({
          status: 'confirmed',
          transactionHash: `0x${'aa'.repeat(32)}`,
        }),
      );
      expect(firstB).toEqual(
        expect.objectContaining({
          status: 'failed',
          errorCode: 'temporary_rpc_error',
          errorMessage: 'temporary relay outage',
          metadata: expect.objectContaining({
            retryEligible: true,
            failurePhase: 'submission',
          }),
        }),
      );
      expect(sessionRecord.status).toBe('failed');
      expect((sessionRecord as any).metadata?.evmRecoveryExecutionSummary).toEqual({
        total: 2,
        pending: 0,
        submitted: 0,
        confirmed: 1,
        failed: 1,
        skipped: 0,
      });
      expect(signerWrites).toHaveLength(1);
      expect(
        signerState.get(
          makeSignerKey({
            chainIdKey: 'evm:11155111',
            accountAddress: accountAddressA,
            signerId: newOwnerAddress,
          }),
        )?.status,
      ).toBe('active');
      expect(
        signerState.get(
          makeSignerKey({
            chainIdKey: 'evm:1',
            accountAddress: accountAddressB,
            signerId: newOwnerAddress,
          }),
        ),
      ).toBeUndefined();
      expect(
        executionHistory.filter((record) => record.action === 'near_email_recovery'),
      ).toHaveLength(2);

      const retried = await retryFailedSmartAccountRecoveryExecutions(service as any, {
        nowMs: nowMs + 60_000,
        retryAfterMs: 1,
        maxRetryCount: 3,
      });
      expect(retried).toEqual({
        ok: true,
        result: {
          processed: 1,
          retried: 1,
          skipped: 0,
          failed: 0,
        },
      });

      const retriedB = executionState.get(
        makeExecutionKey({
          sessionId: 'ABC123',
          chainIdKey: 'evm:1',
          accountAddress: accountAddressB,
          action: 'recover_add_owner',
        }),
      );
      expect(retriedB).toEqual(
        expect.objectContaining({
          status: 'pending',
          metadata: expect.objectContaining({
            retryCount: 1,
            retryState: 'requeued',
            lastErrorCode: 'temporary_rpc_error',
          }),
        }),
      );
      expect(sessionRecord.status).toBe('evm_recovering');
      expect((sessionRecord as any).metadata?.evmRecoveryExecutionSummary).toEqual({
        total: 2,
        pending: 1,
        submitted: 0,
        confirmed: 1,
        failed: 0,
        skipped: 0,
      });
      expect(
        executionHistory.filter((record) => record.action === 'near_email_recovery'),
      ).toHaveLength(2);

      const secondAttempt = await executePendingSmartAccountRecoveryExecutions(service as any, {
        executeDeployedRecovery: async ({ execution }) => {
          expect(execution.accountAddress).toBe(accountAddressB);
          return {
            status: 'confirmed',
            transactionHash: `0x${'bb'.repeat(32)}`,
            metadataPatch: {
              recoverySpec: buildRecoverySpecFixture({
                newOwnerAddress,
                accountAddress: accountAddressB,
              }),
            },
          };
        },
      });
      expect(secondAttempt).toEqual({
        ok: true,
        result: {
          processed: 1,
          confirmed: 1,
          submitted: 0,
          skipped: 0,
          failed: 0,
        },
      });

      const finalA = executionState.get(
        makeExecutionKey({
          sessionId: 'ABC123',
          chainIdKey: 'evm:11155111',
          accountAddress: accountAddressA,
          action: 'recover_add_owner',
        }),
      );
      const finalB = executionState.get(
        makeExecutionKey({
          sessionId: 'ABC123',
          chainIdKey: 'evm:1',
          accountAddress: accountAddressB,
          action: 'recover_add_owner',
        }),
      );
      expect(finalA?.status).toBe('confirmed');
      expect(finalB).toEqual(
        expect.objectContaining({
          status: 'confirmed',
          transactionHash: `0x${'bb'.repeat(32)}`,
        }),
      );
      expect(signerWrites).toHaveLength(2);
      expect(
        signerState.get(
          makeSignerKey({
            chainIdKey: 'evm:1',
            accountAddress: accountAddressB,
            signerId: newOwnerAddress,
          }),
        )?.status,
      ).toBe('active');
      expect(sessionRecord.status).toBe('completed');
      expect((sessionRecord as any).metadata?.evmRecoveryExecutionSummary).toEqual({
        total: 2,
        pending: 0,
        submitted: 0,
        confirmed: 2,
        failed: 0,
        skipped: 0,
      });
      expect(
        executionHistory.filter((record) => record.action === 'near_email_recovery'),
      ).toHaveLength(2);
    } finally {
      await srv.close();
    }
  });
});
