import type { Router as ExpressRouter } from 'express';
import { parseRecoverEmailRequest } from '../../../email-recovery/emailParsers';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  markTrackedRecoverySessionVerified,
  recordTrackedNearRecoveryExecution,
  queueTrackedSmartAccountRecoveryExecutions,
  resolveTrackedNearRecoveryExecution,
  transitionTrackedRecoverySession,
} from '../../recoveryExecutionTracking';
import { dispatchRecoveryAuthorityTick } from '../../recoveryAuthorityDispatch';
import { buildRecoveryAuthoritySponsorshipRuntime } from '../../recoveryAuthoritySponsorship';

export function registerRecoverEmailRoute(router: ExpressRouter, ctx: ExpressRelayContext): void {
  // Email recovery hook (DKIM/TEE flow):
  // Accept a ForwardableEmailPayload from the email worker and call the
  // per-user email-recoverer contract deployed on `accountId`.
  router.post('/recover-email', async (req: any, res: any) => {
    try {
      const prefer = String(req?.headers?.prefer || '').toLowerCase();
      const respondAsync =
        prefer.includes('respond-async') ||
        String((req?.query as any)?.async || '').trim() === '1' ||
        String((req?.query as any)?.respond_async || '').trim() === '1';

      const parsed = parseRecoverEmailRequest(req.body as unknown);
      if (!parsed.ok) {
        res.status(parsed.status).json({ code: parsed.code, message: parsed.message });
        return;
      }
      const { accountId, emailBlob, recoveryPayload } = parsed;
      const trackedRecovery = await resolveTrackedNearRecoveryExecution(ctx.service, {
        accountId,
        recoveryPayload,
      }).catch(() => null);
      if (!trackedRecovery) {
        res.status(400).json({
          code: 'invalid_recovery_session',
          message: 'Recovery email does not match a prepared canonical recovery session',
        });
        return;
      }
      await markTrackedRecoverySessionVerified(ctx.service, trackedRecovery, {
        emailBlob,
      });

      const persistExecution = async (input: {
        status: 'pending' | 'submitted' | 'failed';
        transactionHash?: string;
        errorCode?: string;
        errorMessage?: string;
      }): Promise<void> => {
        try {
          await recordTrackedNearRecoveryExecution(ctx.service, trackedRecovery, input);
        } catch (err: unknown) {
          ctx.logger.warn('[recover-email] failed to persist recovery execution', {
            accountId,
            sessionId: trackedRecovery?.sessionId,
            error: err instanceof Error ? err.message : String(err || 'unknown error'),
          });
        }
      };

      const queueEvmContinuation = async (transactionHash?: string): Promise<void> => {
        try {
          await queueTrackedSmartAccountRecoveryExecutions(ctx.service, trackedRecovery, {
            nearTransactionHash: transactionHash,
          });
          await dispatchRecoveryAuthorityTick(ctx.service, {
            logger: ctx.logger,
            sponsorship: buildRecoveryAuthoritySponsorshipRuntime({
              logger: ctx.logger,
              opts: ctx.opts,
            }),
          });
        } catch (err: unknown) {
          ctx.logger.warn('[recover-email] failed to queue linked EVM recovery executions', {
            accountId,
            sessionId: trackedRecovery?.sessionId,
            error: err instanceof Error ? err.message : String(err || 'unknown error'),
          });
        }
      };

      const markRecoveryFailed = async (errorCode: string, errorMessage: string): Promise<void> => {
        try {
          await transitionTrackedRecoverySession(ctx.service, trackedRecovery, {
            status: 'failed',
            metadataPatch: {
              recoveryFailureCode: errorCode,
              recoveryFailureMessage: errorMessage,
            },
          });
        } catch (err: unknown) {
          ctx.logger.warn('[recover-email] failed to update recovery session status', {
            accountId,
            sessionId: trackedRecovery?.sessionId,
            error: err instanceof Error ? err.message : String(err || 'unknown error'),
          });
        }
      };

      if (!ctx.service.emailRecovery) {
        res.status(503).json({
          code: 'email_recovery_unavailable',
          message: 'EmailRecoveryService is not configured on this server',
        });
        return;
      }

      if (respondAsync) {
        await persistExecution({ status: 'pending' });
        void ctx.service.emailRecovery
          .requestEmailRecovery({ accountId, emailBlob, recoveryPayload })
          .then(async (result) => {
            await persistExecution(
              result?.success
                ? {
                    status: 'submitted',
                    transactionHash: result.transactionHash,
                  }
                : {
                    status: 'failed',
                    errorCode: 'near_email_recovery_submit_failed',
                    errorMessage: result?.error || result?.message || 'Email recovery failed',
                  },
            );
            if (result?.success) {
              await queueEvmContinuation(result.transactionHash);
            } else {
              await markRecoveryFailed(
                'near_email_recovery_submit_failed',
                result?.error || result?.message || 'Email recovery failed',
              );
            }
            ctx.logger.info('[recover-email] async complete', {
              success: result?.success === true,
              accountId,
              error: result?.success ? undefined : result?.error,
            });
          })
          .catch(async (err: any) => {
            await persistExecution({
              status: 'failed',
              errorCode: 'near_email_recovery_submit_failed',
              errorMessage: err?.message || String(err),
            });
            await markRecoveryFailed(
              'near_email_recovery_submit_failed',
              err?.message || String(err),
            );
            ctx.logger.error('[recover-email] async error', {
              accountId,
              error: err?.message || String(err),
            });
          });

        res.status(202).json({ success: true, queued: true, accountId });
        return;
      }

      await persistExecution({ status: 'pending' });
      const result = await ctx.service.emailRecovery.requestEmailRecovery({
        accountId,
        emailBlob,
        recoveryPayload,
      });
      await persistExecution(
        result.success
          ? {
              status: 'submitted',
              transactionHash: result.transactionHash,
            }
          : {
              status: 'failed',
              errorCode: 'near_email_recovery_submit_failed',
              errorMessage: result.error || result.message || 'Email recovery failed',
            },
      );
      if (result.success) {
        await queueEvmContinuation(result.transactionHash);
      } else {
        await markRecoveryFailed(
          'near_email_recovery_submit_failed',
          result.error || result.message || 'Email recovery failed',
        );
      }
      res.status(result.success ? 202 : 400).json(result);
    } catch (e: any) {
      res.status(500).json({ code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
