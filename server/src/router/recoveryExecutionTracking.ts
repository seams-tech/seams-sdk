import type { AuthService } from '../core/AuthService';
import { inferNearRecoveryChainIdKey } from '../core/recoveryExecutionRecords';
import {
  hashRecoveryEmailArtifact,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';

export const NEAR_EMAIL_RECOVERY_ACTION = 'near_email_recovery';
export const SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION = 'recover_add_owner';

export type RecoveryExecutionSummary = {
  total: number;
  pending: number;
  submitted: number;
  confirmed: number;
  failed: number;
  skipped: number;
};

export type TrackedNearRecoveryExecution = {
  sessionId: string;
  chainIdKey: string;
  accountAddress: string;
  expectedNewNearPublicKey: string;
  expectedNewEvmOwnerAddress: string;
  recoveryDeadlineEpochSeconds: number;
  recoveryEmailPayloadHash: string;
};

export async function resolveTrackedNearRecoveryExecution(
  service: Pick<AuthService, 'getRecoverySession'>,
  input: { accountId: string; recoveryPayload: RecoveryEmailPayload },
): Promise<TrackedNearRecoveryExecution | null> {
  if (input.recoveryPayload.nearAccountId !== input.accountId) return null;
  const recoveryEmailPayloadHash = await hashRecoveryEmailPayload(input.recoveryPayload);

  const result = await service.getRecoverySession({
    sessionId: input.recoveryPayload.recoverySessionId,
  });
  if (!result.ok || !result.record) return null;
  if (result.record.nearAccountId !== input.accountId) return null;
  if (result.record.newNearPublicKey !== input.recoveryPayload.newNearPublicKey) return null;
  if (result.record.newEvmOwnerAddress !== input.recoveryPayload.newEvmOwnerAddress) return null;
  if (result.record.recoveryDeadlineEpochSeconds !== input.recoveryPayload.deadlineEpochSeconds) {
    return null;
  }
  if (result.record.recoveryEmailPayloadHash !== recoveryEmailPayloadHash) return null;
  if (Math.floor(Date.now() / 1000) > result.record.recoveryDeadlineEpochSeconds) return null;

  const chainIdKey = inferNearRecoveryChainIdKey(result.record.nearAccountId);
  if (!chainIdKey) return null;

  return {
    sessionId: result.record.sessionId,
    chainIdKey,
    accountAddress: result.record.nearAccountId,
    expectedNewNearPublicKey: result.record.newNearPublicKey,
    expectedNewEvmOwnerAddress: result.record.newEvmOwnerAddress,
    recoveryDeadlineEpochSeconds: result.record.recoveryDeadlineEpochSeconds,
    recoveryEmailPayloadHash: result.record.recoveryEmailPayloadHash,
  };
}

export async function markTrackedRecoverySessionVerified(
  service: Pick<AuthService, 'updateRecoverySessionStatus'>,
  tracked: TrackedNearRecoveryExecution | null,
  input: {
    emailBlob: string;
  },
): Promise<void> {
  if (!tracked) return;
  const verifiedRecoveryArtifactHash = await hashRecoveryEmailArtifact(input.emailBlob);
  const updated = await service.updateRecoverySessionStatus({
    sessionId: tracked.sessionId,
    status: 'verified',
    metadataPatch: {
      verifiedRecoveryPayloadHash: tracked.recoveryEmailPayloadHash,
      verifiedRecoveryArtifactHash,
      verifiedAtMs: Date.now(),
      verifiedNearSuccessGate: 'pending',
    },
  });
  if (!updated.ok) {
    throw new Error(updated.message || 'Failed to mark recovery session verified');
  }
}

export async function recordTrackedNearRecoveryExecution(
  service: Pick<AuthService, 'recordRecoveryExecution'>,
  tracked: TrackedNearRecoveryExecution | null,
  input: {
    status: 'pending' | 'submitted' | 'failed';
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
  },
): Promise<void> {
  if (!tracked) return;
  await service.recordRecoveryExecution({
    sessionId: tracked.sessionId,
    chainIdKey: tracked.chainIdKey,
    accountAddress: tracked.accountAddress,
    action: NEAR_EMAIL_RECOVERY_ACTION,
    status: input.status,
    transactionHash: input.transactionHash,
    errorCode: input.errorCode,
    errorMessage: input.errorMessage,
    metadata: {
      expectedNewNearPublicKey: tracked.expectedNewNearPublicKey,
      expectedNewEvmOwnerAddress: tracked.expectedNewEvmOwnerAddress,
      recoveryDeadlineEpochSeconds: tracked.recoveryDeadlineEpochSeconds,
      recoveryEmailPayloadHash: tracked.recoveryEmailPayloadHash,
    },
  });
}

export async function transitionTrackedRecoverySession(
  service: Pick<AuthService, 'updateRecoverySessionStatus'>,
  tracked: TrackedNearRecoveryExecution | null,
  input: {
    status: 'near_recovered' | 'evm_recovering' | 'failed';
    metadataPatch?: Record<string, unknown>;
  },
): Promise<void> {
  if (!tracked) return;
  const updated = await service.updateRecoverySessionStatus({
    sessionId: tracked.sessionId,
    status: input.status,
    metadataPatch: input.metadataPatch,
  });
  if (!updated.ok) {
    throw new Error(updated.message || 'Failed to update recovery session');
  }
}

export async function queueTrackedSmartAccountRecoveryExecutions(
  service: Pick<
    AuthService,
    | 'getRecoverySession'
    | 'listSmartAccountRecoverySubjects'
    | 'recordRecoveryExecution'
    | 'updateRecoverySessionStatus'
  >,
  tracked: TrackedNearRecoveryExecution | null,
  input: {
    nearTransactionHash?: string;
  },
): Promise<number> {
  if (!tracked) return 0;
  const sessionMetadata = {
    ...(input.nearTransactionHash ? { nearRecoveryTransactionHash: input.nearTransactionHash } : {}),
  };

  const recoverySession = await service.getRecoverySession({ sessionId: tracked.sessionId });
  if (!recoverySession.ok || !recoverySession.record) return 0;
  const verifiedRecoveryPayloadHash = String(
    recoverySession.record.metadata?.verifiedRecoveryPayloadHash || '',
  ).trim();
  if (
    recoverySession.record.status !== 'verified' ||
    verifiedRecoveryPayloadHash !== recoverySession.record.recoveryEmailPayloadHash
  ) {
    throw new Error(
      `Recovery session ${tracked.sessionId} has not passed the verified-email gate for EVM continuation`,
    );
  }
  if (!recoverySession.record.newEvmOwnerAddress) {
    await transitionTrackedRecoverySession(service, tracked, {
      status: 'near_recovered',
      metadataPatch: {
        ...sessionMetadata,
        queuedEvmRecoveryCount: 0,
        verifiedNearSuccessGate: 'passed',
        nearRecoveryPassedAtMs: Date.now(),
      },
    });
    return 0;
  }

  const linkedAccounts = await service.listSmartAccountRecoverySubjects({
    nearAccountId: recoverySession.record.nearAccountId,
  });
  if (!linkedAccounts.ok || !linkedAccounts.records.length) {
    await transitionTrackedRecoverySession(service, tracked, {
      status: 'near_recovered',
      metadataPatch: {
        ...sessionMetadata,
        queuedEvmRecoveryCount: 0,
        verifiedNearSuccessGate: 'passed',
        nearRecoveryPassedAtMs: Date.now(),
      },
    });
    return 0;
  }

  const evmTargets = linkedAccounts.records.filter(
    (record) =>
      record.chainIdKey.startsWith('evm:') || record.chainIdKey.startsWith('tempo:'),
  );
  if (!evmTargets.length) {
    await transitionTrackedRecoverySession(service, tracked, {
      status: 'near_recovered',
      metadataPatch: {
        ...sessionMetadata,
        queuedEvmRecoveryCount: 0,
        verifiedNearSuccessGate: 'passed',
        nearRecoveryPassedAtMs: Date.now(),
      },
    });
    return 0;
  }

  await Promise.all(
    evmTargets.map(async (record) => {
      await service.recordRecoveryExecution({
        sessionId: tracked.sessionId,
        chainIdKey: record.chainIdKey,
        accountAddress: record.accountAddress,
        action: SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION,
        status: 'pending',
        metadata: {
          newEvmOwnerAddress: recoverySession.record?.newEvmOwnerAddress,
          expectedNewNearPublicKey: recoverySession.record?.newNearPublicKey,
          recoveryEmailPayloadHash: recoverySession.record?.recoveryEmailPayloadHash,
          recoveryDeadlineEpochSeconds: recoverySession.record?.recoveryDeadlineEpochSeconds,
          recoveryScope: recoverySession.record?.scope,
          ...sessionMetadata,
          verifiedNearSuccessGate: 'passed',
          ...(record.metadata?.sponsorshipScope
            ? { sponsorshipScope: record.metadata.sponsorshipScope }
            : {}),
          ...(record.metadata?.deployed === true
            ? { recoveryTargetMode: 'deployed' as const }
            : record.metadata?.deployed === false
              ? { recoveryTargetMode: 'undeployed' as const }
              : {}),
          ...(record.metadata ? { linkedAccount: record.metadata } : {}),
        },
      });
    }),
  );

  await transitionTrackedRecoverySession(service, tracked, {
    status: 'evm_recovering',
    metadataPatch: {
      ...sessionMetadata,
      queuedEvmRecoveryCount: evmTargets.length,
      evmContinuationQueuedAtMs: Date.now(),
      verifiedNearSuccessGate: 'passed',
      nearRecoveryPassedAtMs: Date.now(),
    },
  });

  return evmTargets.length;
}

export function summarizeSmartAccountRecoveryExecutions(
  records: Array<{ action?: string; status?: string }>,
): RecoveryExecutionSummary {
  const summary: RecoveryExecutionSummary = {
    total: 0,
    pending: 0,
    submitted: 0,
    confirmed: 0,
    failed: 0,
    skipped: 0,
  };
  for (const record of records) {
    if (record.action !== SMART_ACCOUNT_RECOVERY_ADD_OWNER_ACTION) continue;
    summary.total += 1;
    if (record.status === 'pending') summary.pending += 1;
    else if (record.status === 'submitted') summary.submitted += 1;
    else if (record.status === 'confirmed') summary.confirmed += 1;
    else if (record.status === 'failed') summary.failed += 1;
    else if (record.status === 'skipped') summary.skipped += 1;
  }
  return summary;
}

export async function reconcileRecoverySessionExecutionState(
  service: Pick<AuthService, 'getRecoverySession' | 'listRecoveryExecutions' | 'updateRecoverySessionStatus'>,
  input: { sessionId: string },
): Promise<
  | { ok: true; status: 'near_recovered' | 'evm_recovering' | 'completed' | 'failed'; summary: RecoveryExecutionSummary }
  | { ok: false; code: 'invalid_args' | 'internal'; message: string }
> {
  const sessionId = String(input.sessionId || '').trim();
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing sessionId' };
  }

  const recoverySession = await service.getRecoverySession({ sessionId });
  if (!recoverySession.ok || !recoverySession.record) {
    return {
      ok: false,
      code: recoverySession.ok ? 'invalid_args' : recoverySession.code,
      message: recoverySession.ok
        ? `Unknown recovery session: ${sessionId}`
        : recoverySession.message || 'Failed to load recovery session',
    };
  }

  const executions = await service.listRecoveryExecutions({ sessionId });
  if (!executions.ok) {
    return { ok: false, code: executions.code, message: executions.message };
  }

  const summary = summarizeSmartAccountRecoveryExecutions(executions.records);
  const metadataPatch = {
    evmRecoveryExecutionSummary: summary,
    evmRecoveryExecutionSummaryUpdatedAtMs: Date.now(),
  };

  if (summary.total === 0) {
    const updated = await service.updateRecoverySessionStatus({
      sessionId,
      status: 'near_recovered',
      metadataPatch,
    });
    if (!updated.ok) return { ok: false, code: updated.code, message: updated.message };
    return { ok: true, status: 'near_recovered', summary };
  }

  if (summary.failed > 0) {
    const updated = await service.updateRecoverySessionStatus({
      sessionId,
      status: 'failed',
      metadataPatch,
    });
    if (!updated.ok) return { ok: false, code: updated.code, message: updated.message };
    return { ok: true, status: 'failed', summary };
  }

  if (summary.pending > 0 || summary.submitted > 0) {
    const updated = await service.updateRecoverySessionStatus({
      sessionId,
      status: 'evm_recovering',
      metadataPatch,
    });
    if (!updated.ok) return { ok: false, code: updated.code, message: updated.message };
    return { ok: true, status: 'evm_recovering', summary };
  }

  const updated = await service.updateRecoverySessionStatus({
    sessionId,
    status: 'completed',
    metadataPatch,
  });
  if (!updated.ok) return { ok: false, code: updated.code, message: updated.message };
  return { ok: true, status: 'completed', summary };
}
