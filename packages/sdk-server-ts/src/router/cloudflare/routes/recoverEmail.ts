import { parseRecoverEmailRequest } from '../../../email-recovery/emailParsers';
import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  prepareTrackedRecoverEmailExecution,
  recordTrackedRecoverEmailPending,
  runTrackedRecoverEmailExecution,
  runTrackedRecoverEmailExecutionAsync,
} from '../../recoveryExecutionTracking';

function isCloudflareRecoverEmailAsync(ctx: CloudflareRouterApiContext): boolean {
  const prefer = String(ctx.request.headers.get('prefer') || '').toLowerCase();
  return (
    prefer.includes('respond-async') ||
    String(ctx.url.searchParams.get('async') || '').trim() === '1' ||
    String(ctx.url.searchParams.get('respond_async') || '').trim() === '1'
  );
}

export async function handleRecoverEmail(ctx: CloudflareRouterApiContext): Promise<Response | null> {
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

  const respondAsync = isCloudflareRecoverEmailAsync(ctx);

  const rawBody = await readJson(ctx.request);
  const parsed = parseRecoverEmailRequest(rawBody);
  if (!parsed.ok) {
    return json({ code: parsed.code, message: parsed.message }, { status: parsed.status });
  }
  const { accountId, emailBlob, recoveryPayload } = parsed;
  const execution = await prepareTrackedRecoverEmailExecution({
    service: ctx.service,
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

  if (respondAsync && ctx.cfCtx && typeof ctx.cfCtx.waitUntil === 'function') {
    await recordTrackedRecoverEmailPending({
      service: ctx.service,
      logger: ctx.logger,
      execution,
    });
    ctx.cfCtx.waitUntil(
      runTrackedRecoverEmailExecutionAsync({
        service: ctx.service,
        executionService: emailRecovery.executionService,
        logger: ctx.logger,
        execution,
      }),
    );
    return json({ success: true, queued: true, accountId }, { status: 202 });
  }

  await recordTrackedRecoverEmailPending({
    service: ctx.service,
    logger: ctx.logger,
    execution,
  });
  const result = await runTrackedRecoverEmailExecution({
    service: ctx.service,
    executionService: emailRecovery.executionService,
    logger: ctx.logger,
    execution,
  });
  return json(result, { status: result.success ? 202 : 400 });
}
