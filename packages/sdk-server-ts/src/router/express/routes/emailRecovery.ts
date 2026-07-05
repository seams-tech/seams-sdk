import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import type { RouterApiEmailRecoveryOptions } from '../../routerApi';
import { signEmailRecoveryThresholdSessionJwt } from '../../emailRecoveryThresholdSession';
import {
  parseFinalizeEmailRecoveryEd25519Request,
  parsePrepareEmailRecoveryRequest,
  parseRespondEmailRecoveryEd25519Request,
  parseRespondEmailRecoveryEcdsaRequest,
} from '../../emailRecoveryRequestValidation';

type ConfiguredEmailRecovery = RouterApiEmailRecoveryOptions;

async function handleExpressEmailRecoveryPrepare(input: {
  req: Request;
  res: Response;
  ctx: ExpressRouterApiContext;
  emailRecovery: ConfiguredEmailRecovery;
}): Promise<void> {
  try {
    const origin = String(input.req.headers?.origin || '').trim() || undefined;
    const parsed = parsePrepareEmailRecoveryRequest({ body: input.req.body, origin });
    if (!parsed.ok) {
      input.res.status(parsed.status).json(parsed.body);
      return;
    }
    const result = await input.emailRecovery.authService.prepareEmailRecovery(parsed.request);
    if (!result.ok) {
      input.res.status(result.code === 'internal' ? 500 : 400).json(result);
      return;
    }

    const signed = await signEmailRecoveryThresholdSessionJwt({
      result,
      session: input.ctx.opts.session,
    });
    if (!signed.ok) {
      input.res.status(signed.status).json(signed.body);
      return;
    }

    input.res.status(200).json(result);
  } catch (e: unknown) {
    input.res.status(500).json({
      ok: false,
      code: 'internal',
      message: e instanceof Error ? e.message : 'Internal error',
    });
  }
}

async function handleExpressEmailRecoveryEd25519Respond(input: {
  req: Request;
  res: Response;
  emailRecovery: ConfiguredEmailRecovery;
}): Promise<void> {
  try {
    const parsed = parseRespondEmailRecoveryEd25519Request(input.req.body);
    if (!parsed.ok) {
      input.res.status(parsed.status).json(parsed.body);
      return;
    }
    const result = await input.emailRecovery.authService.respondEmailRecoveryEd25519(
      parsed.request,
    );
    input.res.status(result.ok ? 200 : result.code === 'internal' ? 500 : 400).json(result);
  } catch (e: unknown) {
    input.res.status(500).json({
      ok: false,
      code: 'internal',
      message: e instanceof Error ? e.message : 'Internal error',
    });
  }
}

async function handleExpressEmailRecoveryEd25519Finalize(input: {
  req: Request;
  res: Response;
  ctx: ExpressRouterApiContext;
  emailRecovery: ConfiguredEmailRecovery;
}): Promise<void> {
  try {
    const parsed = parseFinalizeEmailRecoveryEd25519Request(input.req.body);
    if (!parsed.ok) {
      input.res.status(parsed.status).json(parsed.body);
      return;
    }
    const result = await input.emailRecovery.authService.finalizeEmailRecoveryEd25519(
      parsed.request,
    );
    if (!result.ok) {
      input.res.status(result.code === 'internal' ? 500 : 400).json(result);
      return;
    }

    const signed = await signEmailRecoveryThresholdSessionJwt({
      result,
      session: input.ctx.opts.session,
    });
    if (!signed.ok) {
      input.res.status(signed.status).json(signed.body);
      return;
    }

    input.res.status(200).json(result);
  } catch (e: unknown) {
    input.res.status(500).json({
      ok: false,
      code: 'internal',
      message: e instanceof Error ? e.message : 'Internal error',
    });
  }
}

async function handleExpressEmailRecoveryEcdsaRespond(input: {
  req: Request;
  res: Response;
  ctx: ExpressRouterApiContext;
  emailRecovery: ConfiguredEmailRecovery;
}): Promise<void> {
  try {
    const parsed = parseRespondEmailRecoveryEcdsaRequest(input.req.body);
    if (!parsed.ok) {
      input.res.status(parsed.status).json(parsed.body);
      return;
    }
    const result = await input.emailRecovery.authService.respondEmailRecoveryEcdsa(
      parsed.request,
    );
    if (!result.ok) {
      input.res.status(result.code === 'internal' ? 500 : 400).json(result);
      return;
    }

    const signed = await signEmailRecoveryThresholdSessionJwt({
      result,
      session: input.ctx.opts.session,
    });
    if (!signed.ok) {
      input.res.status(signed.status).json(signed.body);
      return;
    }

    input.res.status(200).json(result);
  } catch (e: unknown) {
    input.res.status(500).json({
      ok: false,
      code: 'internal',
      message: e instanceof Error ? e.message : 'Internal error',
    });
  }
}

export function registerEmailRecoveryRoutes(router: ExpressRouter, ctx: ExpressRouterApiContext): void {
  const emailRecovery = ctx.opts.emailRecovery;
  if (!emailRecovery) return;

  router.post('/email-recovery/prepare', async (req: Request, res: Response) => {
    await handleExpressEmailRecoveryPrepare({ req, res, ctx, emailRecovery });
  });

  router.post('/email-recovery/ed25519/respond', async (req: Request, res: Response) => {
    await handleExpressEmailRecoveryEd25519Respond({ req, res, emailRecovery });
  });

  router.post('/email-recovery/ed25519/finalize', async (req: Request, res: Response) => {
    await handleExpressEmailRecoveryEd25519Finalize({ req, res, ctx, emailRecovery });
  });

  router.post('/email-recovery/ecdsa/respond', async (req: Request, res: Response) => {
    await handleExpressEmailRecoveryEcdsaRespond({ req, res, ctx, emailRecovery });
  });
}
