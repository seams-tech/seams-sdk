import type { AuthService } from '../core/AuthService';
import type { NormalizedRouterLogger } from './logger';
import { dispatchRecoveryAuthorityTick } from './recoveryAuthorityDispatch';
import type { RecoveryAuthoritySponsorshipRuntime } from './recoveryAuthoritySponsorship';
import type { RecoveryAuthorityMonitoringConfig } from './recoveryAuthorityMonitoring';

type IntervalHandleLike = {
  unref?: () => void;
};

export interface RecoveryAuthorityIntervalRunner {
  start: () => void;
  stop: () => void;
  isRunning: () => boolean;
  triggerNow: () => Promise<void>;
}

export function createRecoveryAuthorityIntervalRunner(
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
    intervalMs: number;
    limit?: number;
    sponsorship?: RecoveryAuthoritySponsorshipRuntime | null;
    monitoring?: RecoveryAuthorityMonitoringConfig | null;
    runImmediately?: boolean;
    setIntervalImpl?: (callback: () => void, delayMs: number) => IntervalHandleLike | null;
    clearIntervalImpl?: (handle: IntervalHandleLike | null) => void;
  },
): RecoveryAuthorityIntervalRunner {
  const intervalMs = Math.max(1, Math.floor(Number(input.intervalMs) || 0));
  const setIntervalImpl =
    input.setIntervalImpl ||
    ((callback: () => void, delayMs: number) =>
      setInterval(callback, delayMs) as unknown as IntervalHandleLike);
  const clearIntervalImpl =
    input.clearIntervalImpl ||
    ((handle: IntervalHandleLike | null) => {
      if (!handle) return;
      clearInterval(handle as unknown as ReturnType<typeof setInterval>);
    });

  let timer: IntervalHandleLike | null = null;
  let inFlight: Promise<void> | null = null;

  const runTick = async (reason: 'startup' | 'interval' | 'manual'): Promise<void> => {
    if (inFlight) {
      input.logger.info('[recovery-authority][interval] skipped: tick already in flight', {
        reason,
      });
      return;
    }
    inFlight = (async () => {
      try {
        const result = await dispatchRecoveryAuthorityTick(service, {
          logger: input.logger,
          sponsorship: input.sponsorship || null,
          ...(typeof input.limit === 'number' ? { limit: input.limit } : {}),
          monitoring:
            input.monitoring === undefined
              ? { enabled: true }
              : input.monitoring,
        });
        input.logger.info('[recovery-authority][interval] tick completed', {
          reason,
          retriedProcessed: result.retry.processed,
          retriedCount: result.retry.retried,
          retrySkipped: result.retry.skipped,
          retryFailed: result.retry.failed,
          pendingProcessed: result.pending.processed,
          submittedProcessed: result.submitted.processed,
          stalePending: result.monitoring.stalePending,
          staleSubmitted: result.monitoring.staleSubmitted,
          failedExecutions: result.monitoring.failed,
        });
      } catch (error: unknown) {
        input.logger.error('[recovery-authority][interval] tick failed', {
          reason,
          message: error instanceof Error ? error.message : String(error),
        });
      } finally {
        inFlight = null;
      }
    })();
    await inFlight;
  };

  return {
    start() {
      if (timer) return;
      timer = setIntervalImpl(() => {
        void runTick('interval');
      }, intervalMs);
      if (timer && typeof timer.unref === 'function') {
        timer.unref();
      }
      if (input.runImmediately !== false) {
        void runTick('startup');
      }
    },
    stop() {
      if (!timer) return;
      clearIntervalImpl(timer);
      timer = null;
    },
    isRunning() {
      return timer !== null;
    },
    async triggerNow() {
      await runTick('manual');
    },
  };
}
