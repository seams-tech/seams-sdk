import type { AuthService } from '../core/AuthService';
import {
  confirmSubmittedSmartAccountRecoveryExecutions,
  executePendingSmartAccountRecoveryExecutions,
  retryFailedSmartAccountRecoveryExecutions,
} from '../core/recoveryAuthority';
import type { NormalizedRouterLogger } from './logger';
import type {
  RecoveryAuthorityExecutionResult,
  RecoveryAuthorityRetryResult,
} from '../core/recoveryAuthority';
import type { RecoveryAuthoritySponsorshipRuntime } from './recoveryAuthoritySponsorship';
import {
  monitorRecoveryAuthorityExecutions,
  type RecoveryAuthorityMonitoringConfig,
  type RecoveryAuthorityMonitoringSummary,
} from './recoveryAuthorityMonitoring';

export interface RecoveryAuthorityDispatchTickResult {
  retry: RecoveryAuthorityRetryResult;
  pending: RecoveryAuthorityExecutionResult;
  submitted: RecoveryAuthorityExecutionResult;
  monitoring: RecoveryAuthorityMonitoringSummary;
}

export async function dispatchRecoveryAuthorityTick(
  service: Pick<
    AuthService,
    | 'listRecoveryExecutionsByStatus'
    | 'listAccountSignersByAccount'
    | 'putAccountSigner'
    | 'getSmartAccountRecoverySubjectByAccount'
    | 'putSmartAccountRecoverySubject'
    | 'recordRecoveryExecution'
    | 'getRecoverySession'
    | 'listRecoveryExecutions'
    | 'updateRecoverySessionStatus'
  >,
  input: {
    logger: NormalizedRouterLogger;
    sponsorship?: RecoveryAuthoritySponsorshipRuntime | null;
    limit?: number;
    monitoring?: RecoveryAuthorityMonitoringConfig | null;
  },
): Promise<RecoveryAuthorityDispatchTickResult> {
  const retry = await retryFailedSmartAccountRecoveryExecutions(service, {
    ...(typeof input.limit === 'number' ? { limit: input.limit } : {}),
  });
  if (!retry.ok) {
    input.logger.warn('[recovery-authority] retry pass failed', {
      code: retry.code,
      message: retry.message,
    });
    throw new Error(retry.message || 'Recovery authority retry pass failed');
  }
  if (retry.result.processed > 0) {
    input.logger.info('[recovery-authority] retry pass completed', retry.result);
  }

  const pending = await executePendingSmartAccountRecoveryExecutions(service, {
    ...(typeof input.limit === 'number' ? { limit: input.limit } : {}),
    sponsorship: input.sponsorship || null,
  });
  if (!pending.ok) {
    input.logger.warn('[recovery-authority] pending execution pass failed', {
      code: pending.code,
      message: pending.message,
    });
    throw new Error(pending.message || 'Recovery authority pending execution pass failed');
  }
  if (pending.result.processed > 0) {
    input.logger.info('[recovery-authority] pending execution pass completed', pending.result);
  }

  const submitted = await confirmSubmittedSmartAccountRecoveryExecutions(service, {
    ...(typeof input.limit === 'number' ? { limit: input.limit } : {}),
    sponsorship: input.sponsorship || null,
  });
  if (!submitted.ok) {
    input.logger.warn('[recovery-authority] submitted execution pass failed', {
      code: submitted.code,
      message: submitted.message,
    });
    throw new Error(submitted.message || 'Recovery authority submitted execution pass failed');
  }
  if (submitted.result.processed > 0) {
    input.logger.info('[recovery-authority] submitted execution pass completed', submitted.result);
  }

  const monitoring = await monitorRecoveryAuthorityExecutions(service, {
    logger: input.logger,
    config: input.monitoring || null,
    observabilityIngestion: input.sponsorship?.observabilityIngestion || null,
    actorUserId: input.sponsorship?.webhookActorUserId,
    actorRoles: input.sponsorship?.webhookRoles,
  });
  if (!monitoring.ok) {
    input.logger.warn('[recovery-authority] monitoring pass failed', {
      code: monitoring.code,
      message: monitoring.message,
    });
    throw new Error(monitoring.message || 'Recovery authority monitoring pass failed');
  }

  return {
    retry: retry.result,
    pending: pending.result,
    submitted: submitted.result,
    monitoring: monitoring.summary,
  };
}
