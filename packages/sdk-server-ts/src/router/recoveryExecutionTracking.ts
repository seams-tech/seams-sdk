import type { RouterApiAuthService } from './authServicePort';
import { inferNearRecoveryChainIdKey } from '../core/recoveryExecutionRecords';
import type { NormalizedLogger } from '../core/logger';
import type { EmailRecoveryRequest, EmailRecoveryResult } from '../email-recovery/types';
import {
  hashRecoveryEmailArtifact,
  hashRecoveryEmailPayload,
  type RecoveryEmailPayload,
} from '@shared/utils/recoveryEmail';

const NEAR_EMAIL_RECOVERY_ACTION = 'near_email_recovery';
export const NEAR_EMAIL_RECOVERY_SUBMIT_FAILED_CODE = 'near_email_recovery_submit_failed';

export type TrackedNearRecoveryExecution = {
  sessionId: string;
  chainIdKey: string;
  accountAddress: string;
  expectedNewNearPublicKey: string;
  expectedNewEvmOwnerAddress: string;
  recoveryDeadlineEpochSeconds: number;
  recoveryEmailPayloadHash: string;
};

export type TrackedRecoverEmailExecution = {
  accountId: string;
  emailBlob: string;
  recoveryPayload: RecoveryEmailPayload;
  trackedRecovery: TrackedNearRecoveryExecution;
};

type RecoverySessionReadService = Pick<RouterApiAuthService, 'getRecoverySession'>;
type RecoverySessionStatusService = Pick<RouterApiAuthService, 'updateRecoverySessionStatus'>;
type RecoveryExecutionRecordService = Pick<RouterApiAuthService, 'recordRecoveryExecution'>;
type RecoverEmailTrackingService = RecoverySessionReadService &
  RecoverySessionStatusService &
  RecoveryExecutionRecordService;
type RecoverEmailExecutionService = {
  requestEmailRecovery(request: EmailRecoveryRequest): Promise<EmailRecoveryResult>;
};

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'unknown error');
}

function recoverEmailFailureMessage(result: EmailRecoveryResult): string {
  return result.error || result.message || 'Email recovery failed';
}

function recoverEmailFailureRecord(result: EmailRecoveryResult): {
  status: 'failed';
  errorCode: string;
  errorMessage: string;
} {
  return {
    status: 'failed',
    errorCode: NEAR_EMAIL_RECOVERY_SUBMIT_FAILED_CODE,
    errorMessage: recoverEmailFailureMessage(result),
  };
}

export async function resolveTrackedNearRecoveryExecution(
  service: Pick<RouterApiAuthService, 'getRecoverySession'>,
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

async function resolveTrackedNearRecoveryExecutionSafely(input: {
  service: RecoverySessionReadService;
  accountId: string;
  recoveryPayload: RecoveryEmailPayload;
}): Promise<TrackedNearRecoveryExecution | null> {
  try {
    return await resolveTrackedNearRecoveryExecution(input.service, {
      accountId: input.accountId,
      recoveryPayload: input.recoveryPayload,
    });
  } catch {
    return null;
  }
}

export async function prepareTrackedRecoverEmailExecution(input: {
  service: RecoverySessionReadService & RecoverySessionStatusService;
  accountId: string;
  emailBlob: string;
  recoveryPayload: RecoveryEmailPayload;
}): Promise<TrackedRecoverEmailExecution | null> {
  const trackedRecovery = await resolveTrackedNearRecoveryExecutionSafely({
    service: input.service,
    accountId: input.accountId,
    recoveryPayload: input.recoveryPayload,
  });
  if (!trackedRecovery) return null;
  await markTrackedRecoverySessionVerified(input.service, trackedRecovery, {
    emailBlob: input.emailBlob,
  });
  return {
    accountId: input.accountId,
    emailBlob: input.emailBlob,
    recoveryPayload: input.recoveryPayload,
    trackedRecovery,
  };
}

async function markTrackedRecoverySessionVerified(
  service: Pick<RouterApiAuthService, 'updateRecoverySessionStatus'>,
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

export async function recordTrackedRecoverEmailPending(input: {
  service: RecoveryExecutionRecordService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
}): Promise<void> {
  await recordTrackedRecoveryExecutionSafely({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    record: { status: 'pending' },
  });
}

async function recordTrackedNearRecoveryExecution(
  service: Pick<RouterApiAuthService, 'recordRecoveryExecution'>,
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

async function recordTrackedRecoveryExecutionSafely(input: {
  service: RecoveryExecutionRecordService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
  record: {
    status: 'pending' | 'submitted' | 'failed';
    transactionHash?: string;
    errorCode?: string;
    errorMessage?: string;
  };
}): Promise<void> {
  try {
    await recordTrackedNearRecoveryExecution(
      input.service,
      input.execution.trackedRecovery,
      input.record,
    );
  } catch (error: unknown) {
    input.logger.warn('[recover-email] failed to persist recovery execution', {
      accountId: input.execution.accountId,
      sessionId: input.execution.trackedRecovery.sessionId,
      error: errorMessage(error),
    });
  }
}

async function transitionTrackedRecoverySession(
  service: Pick<RouterApiAuthService, 'updateRecoverySessionStatus'>,
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

async function markTrackedNearRecoverySubmitted(input: {
  service: RecoverySessionStatusService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
  transactionHash?: string;
}): Promise<void> {
  try {
    await transitionTrackedRecoverySession(input.service, input.execution.trackedRecovery, {
      status: 'near_recovered',
      metadataPatch: {
        ...(input.transactionHash ? { nearRecoveryTransactionHash: input.transactionHash } : {}),
        nearRecoverySubmittedAtMs: Date.now(),
      },
    });
  } catch (error: unknown) {
    input.logger.warn('[recover-email] failed to mark NEAR recovery submitted', {
      accountId: input.execution.accountId,
      sessionId: input.execution.trackedRecovery.sessionId,
      error: errorMessage(error),
    });
  }
}

async function markTrackedRecoveryFailed(input: {
  service: RecoverySessionStatusService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
  errorCode: string;
  errorMessage: string;
}): Promise<void> {
  try {
    await transitionTrackedRecoverySession(input.service, input.execution.trackedRecovery, {
      status: 'failed',
      metadataPatch: {
        recoveryFailureCode: input.errorCode,
        recoveryFailureMessage: input.errorMessage,
      },
    });
  } catch (error: unknown) {
    input.logger.warn('[recover-email] failed to update recovery session status', {
      accountId: input.execution.accountId,
      sessionId: input.execution.trackedRecovery.sessionId,
      error: errorMessage(error),
    });
  }
}

async function recordTrackedRecoverEmailResult(input: {
  service: RecoveryExecutionRecordService & RecoverySessionStatusService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
  result: EmailRecoveryResult;
}): Promise<void> {
  if (input.result.success) {
    await recordTrackedRecoveryExecutionSafely({
      service: input.service,
      logger: input.logger,
      execution: input.execution,
      record: {
        status: 'submitted',
        transactionHash: input.result.transactionHash,
      },
    });
    await markTrackedNearRecoverySubmitted({
      service: input.service,
      logger: input.logger,
      execution: input.execution,
      transactionHash: input.result.transactionHash,
    });
    return;
  }

  const failure = recoverEmailFailureRecord(input.result);
  await recordTrackedRecoveryExecutionSafely({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    record: failure,
  });
  await markTrackedRecoveryFailed({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    errorCode: failure.errorCode,
    errorMessage: failure.errorMessage,
  });
}

async function recordTrackedRecoverEmailException(input: {
  service: RecoveryExecutionRecordService & RecoverySessionStatusService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
  error: unknown;
}): Promise<void> {
  const message = errorMessage(input.error);
  await recordTrackedRecoveryExecutionSafely({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    record: {
      status: 'failed',
      errorCode: NEAR_EMAIL_RECOVERY_SUBMIT_FAILED_CODE,
      errorMessage: message,
    },
  });
  await markTrackedRecoveryFailed({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    errorCode: NEAR_EMAIL_RECOVERY_SUBMIT_FAILED_CODE,
    errorMessage: message,
  });
}

export async function runTrackedRecoverEmailExecution(input: {
  service: RecoverEmailTrackingService;
  executionService: RecoverEmailExecutionService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
}): Promise<EmailRecoveryResult> {
  const result = await input.executionService.requestEmailRecovery({
    accountId: input.execution.accountId,
    emailBlob: input.execution.emailBlob,
    recoveryPayload: input.execution.recoveryPayload,
  });
  await recordTrackedRecoverEmailResult({
    service: input.service,
    logger: input.logger,
    execution: input.execution,
    result,
  });
  return result;
}

export async function runTrackedRecoverEmailExecutionAsync(input: {
  service: RecoverEmailTrackingService;
  executionService: RecoverEmailExecutionService;
  logger: NormalizedLogger;
  execution: TrackedRecoverEmailExecution;
}): Promise<void> {
  try {
    const result = await runTrackedRecoverEmailExecution(input);
    input.logger.info('[recover-email] async complete', {
      success: result.success === true,
      accountId: input.execution.accountId,
      error: result.success ? undefined : result.error,
    });
  } catch (error: unknown) {
    await recordTrackedRecoverEmailException({
      service: input.service,
      logger: input.logger,
      execution: input.execution,
      error,
    });
    input.logger.error('[recover-email] async error', {
      accountId: input.execution.accountId,
      error: errorMessage(error),
    });
  }
}
