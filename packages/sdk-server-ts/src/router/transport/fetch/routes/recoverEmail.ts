import { parseRecoverEmailRequest } from '../../../../email-recovery/emailParsers';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import {
  prepareTrackedRecoverEmailExecution,
  recordTrackedRecoverEmailPending,
  runTrackedRecoverEmailExecution,
  runTrackedRecoverEmailExecutionAsync,
} from '../../../recoveryExecutionTracking';

function isFetchRecoverEmailAsync(ctx: FetchRouterApiContext): boolean {
  const prefer = String(ctx.request.headers.get('prefer') || '').toLowerCase();
  return (
    prefer.includes('respond-async') ||
    String(ctx.url.searchParams.get('async') || '').trim() === '1' ||
    String(ctx.url.searchParams.get('respond_async') || '').trim() === '1'
  );
}

export async function handleRecoverEmail(
  ctx: FetchRouterApiContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST' || ctx.pathname !== '/recover-email') return null;

  const emailRecovery = ctx.opts.emailRecovery;
  if (emailRecovery?.kind !== 'prepare_and_execute') {
    return json(
      {
        code: 'email_recovery_unavailable',
        message: 'EmailRecoveryService is not configured on this server',
      },
      { status: 503 },
    );
  }

  const respondAsync = isFetchRecoverEmailAsync(ctx);

  const rawBody = await readJson(ctx.request);
  const parsed = parseRecoverEmailRequest(rawBody);
  if (!parsed.ok) {
    return json({ code: parsed.code, message: parsed.message }, { status: parsed.status });
  }
  const { accountId, emailBlob, recoveryPayload } = parsed;
  const execution = await prepareTrackedRecoverEmailExecution({
    service: ctx.service.recovery,
    accountId,
    emailBlob,
    recoveryPayload,
  });
  if (!execution) {
    return json(
      {
        code: 'invalid_recovery_session',
        message: 'Recovery email does not match a prepared canonical recovery session',
      },
      { status: 400 },
    );
  }

  if (respondAsync && ctx.runtime.kind === 'background') {
    await recordTrackedRecoverEmailPending({
      service: ctx.service.recovery,
      logger: ctx.logger,
      execution,
    });
    ctx.runtime.waitUntil(
      runTrackedRecoverEmailExecutionAsync({
        service: ctx.service.recovery,
        executionService: emailRecovery.executionService,
        logger: ctx.logger,
        execution,
      }),
    );
    return json({ success: true, queued: true, accountId }, { status: 202 });
  }

  await recordTrackedRecoverEmailPending({
    service: ctx.service.recovery,
    logger: ctx.logger,
    execution,
  });
  const result = await runTrackedRecoverEmailExecution({
    service: ctx.service.recovery,
    executionService: emailRecovery.executionService,
    logger: ctx.logger,
    execution,
  });
  return json(result, { status: result.success ? 202 : 400 });
}
