import { parseRecoverEmailRequest } from '../../../email-recovery/emailParsers';
import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  markTrackedRecoverySessionVerified,
  recordTrackedNearRecoveryExecution,
  queueTrackedSmartAccountRecoveryExecutions,
  resolveTrackedNearRecoveryExecution,
  transitionTrackedRecoverySession,
} from '../../recoveryExecutionTracking';
import { dispatchRecoveryAuthorityTick } from '../../recoveryAuthorityDispatch';
import { buildRecoveryAuthoritySponsorshipRuntime } from '../../recoveryAuthoritySponsorship';

export async function handleRecoverEmail(ctx: CloudflareRelayContext): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/recover-email') return null;

  const prefer = String(ctx.request.headers.get('prefer') || '').toLowerCase();
  const respondAsync =
    prefer.includes('respond-async') ||
    String(ctx.url.searchParams.get('async') || '').trim() === '1' ||
    String(ctx.url.searchParams.get('respond_async') || '').trim() === '1';

  const rawBody = await readJson(ctx.request);
  const parsed = parseRecoverEmailRequest(rawBody);
  if (!parsed.ok) {
    return json({ code: parsed.code, message: parsed.message }, { status: parsed.status });
  }
  const { accountId, emailBlob, recoveryPayload } = parsed;
  const trackedRecovery = await resolveTrackedNearRecoveryExecution(ctx.service, {
    accountId,
    recoveryPayload,
  }).catch(() => null);
  if (!trackedRecovery) {
    return json(
      {
        code: 'invalid_recovery_session',
        message: 'Recovery email does not match a prepared canonical recovery session',
      },
      { status: 400 },
    );
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
    return json(
      {
        code: 'email_recovery_unavailable',
        message: 'EmailRecoveryService is not configured on this server',
      },
      { status: 503 },
    );
  }

  if (respondAsync && ctx.cfCtx && typeof ctx.cfCtx.waitUntil === 'function') {
    await persistExecution({ status: 'pending' });
    ctx.cfCtx.waitUntil(
      ctx.service.emailRecovery
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
        }),
    );
    return json({ success: true, queued: true, accountId }, { status: 202 });
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
  return json(result, { status: result.success ? 202 : 400 });
}
