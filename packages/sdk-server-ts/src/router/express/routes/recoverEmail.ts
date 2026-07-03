import type { Request, Response, Router as ExpressRouter } from 'express';
import { parseRecoverEmailRequest } from '../../../email-recovery/emailParsers';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import {
  prepareTrackedRecoverEmailExecution,
  recordTrackedRecoverEmailPending,
  runTrackedRecoverEmailExecution,
  runTrackedRecoverEmailExecutionAsync,
} from '../../recoveryExecutionTracking';

function isExpressRecoverEmailAsync(req: Request): boolean {
  const prefer = String(req.headers?.prefer || '').toLowerCase();
  return (
    prefer.includes('respond-async') ||
    String(req.query?.async || '').trim() === '1' ||
    String(req.query?.respond_async || '').trim() === '1'
  );
}

async function handleExpressRecoverEmailRoute(
  ctx: ExpressRouterApiContext,
  req: Request,
  res: Response,
): Promise<void> {
  try {
    const emailRecovery = ctx.opts.emailRecovery;
    if (emailRecovery?.kind !== 'prepare_and_execute') {
      res.status(503).json({
        code: 'email_recovery_unavailable',
        message: 'EmailRecoveryService is not configured on this server',
      });
      return;
    }

    const parsed = parseRecoverEmailRequest(req.body as unknown);
    if (!parsed.ok) {
      res.status(parsed.status).json({ code: parsed.code, message: parsed.message });
      return;
    }
    const { accountId, emailBlob, recoveryPayload } = parsed;
    const execution = await prepareTrackedRecoverEmailExecution({
      service: ctx.service.recovery,
      accountId,
      emailBlob,
      recoveryPayload,
    });
    if (!execution) {
      res.status(400).json({
        code: 'invalid_recovery_session',
        message: 'Recovery email does not match a prepared canonical recovery session',
      });
      return;
    }

    if (isExpressRecoverEmailAsync(req)) {
      await recordTrackedRecoverEmailPending({
        service: ctx.service.recovery,
        logger: ctx.logger,
        execution,
      });
      void runTrackedRecoverEmailExecutionAsync({
        service: ctx.service.recovery,
        executionService: emailRecovery.executionService,
        logger: ctx.logger,
        execution,
      });
      res.status(202).json({ success: true, queued: true, accountId });
      return;
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
    res.status(result.success ? 202 : 400).json(result);
  } catch (e: unknown) {
    res.status(500).json({
      code: 'internal',
      message: e instanceof Error ? e.message : 'Internal error',
    });
  }
}

export function registerRecoverEmailRoute(
  router: ExpressRouter,
  ctx: ExpressRouterApiContext,
): void {
  router.post('/recover-email', handleExpressRecoverEmailRoute.bind(null, ctx));
}
