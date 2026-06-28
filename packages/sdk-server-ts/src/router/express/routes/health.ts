import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';

export function registerHealthRoutes(router: ExpressRouter, ctx: ExpressRouterApiContext): void {
  if (ctx.opts.healthz) {
    router.get('/healthz', async (_req: Request, res: Response) => {
      const thresholdConfigured = Boolean(ctx.opts.threshold);

      res.status(200).json({
        ok: true,
        relayerAccount: ctx.service.getConfiguredRelayerAccount?.() ?? null,
        thresholdEd25519: { configured: thresholdConfigured },
      });
    });
  }

  if (ctx.opts.readyz) {
    router.get('/readyz', async (_req: Request, res: Response) => {
      const thresholdConfigured = Boolean(ctx.opts.threshold);
      try {
        await ctx.service.getRelayerAccount();
        res.status(200).json({
          ok: true,
          thresholdEd25519: { configured: thresholdConfigured },
        });
      } catch (error: unknown) {
        res.status(503).json({
          ok: false,
          code: 'relayer_unavailable',
          message: error instanceof Error ? error.message : String(error),
          thresholdEd25519: { configured: thresholdConfigured },
        });
      }
    });
  }
}
