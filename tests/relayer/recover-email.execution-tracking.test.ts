import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  buildRecoveryEmailBody,
  buildRecoveryEmailPayload,
  buildRecoveryEmailSubject,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';
import {
  callCf,
  fetchJson,
  makeCfCtx,
  makeFakeAuthService,
  startExpressRouter,
} from './helpers';

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
  const raw = [`Subject: ${subject}`, 'From: sender@example.com', '', buildRecoveryEmailBody(payload)].join(
    '\r\n',
  );

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
    deviceNumber: 7,
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

test.describe('recover-email execution tracking', () => {
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
    const makeExecutionKey = (input: Record<string, unknown>) =>
      `${String(input.sessionId)}:${String(input.chainIdKey)}:${String(input.accountAddress)}:${String(input.action)}`;
    const makeSignerKey = (input: Record<string, unknown>) =>
      `${String(input.chainIdKey)}:${String(input.accountAddress)}:${String(input.signerId)}`;

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
          ...((input as any) as Record<string, unknown>),
          version: 'recovery_execution_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          createdAtMs:
            executionState.get(makeExecutionKey(input as any))?.createdAtMs || Date.now(),
          updatedAtMs: Date.now(),
        };
        executionState.set(makeExecutionKey(nextRecord), nextRecord);
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
});
