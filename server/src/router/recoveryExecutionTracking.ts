import type { AuthService } from '../core/AuthService';
import { inferNearRecoveryChainIdKey } from '../core/recoveryExecutionRecords';
import {
  hashRecoveryEmailArtifact,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';

export const NEAR_EMAIL_RECOVERY_ACTION = 'near_email_recovery';

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
    status: 'near_recovered' | 'failed';
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
