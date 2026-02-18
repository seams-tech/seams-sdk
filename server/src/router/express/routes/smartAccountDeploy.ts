import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import { executeSmartAccountDeploy, parseSmartAccountDeployRequest } from '../../smartAccountDeploy';

export function registerSmartAccountDeployRoute(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/smart-account/deploy', async (req: Request, res: Response) => {
    const parsed = parseSmartAccountDeployRequest(req.body);
    if (!parsed.ok) {
      return res.status(400).json({
        ok: false,
        code: 'invalid_body',
        message: parsed.message,
      });
    }

    try {
      const result = await executeSmartAccountDeploy(ctx.opts, parsed.request);
      return res.status(result.ok ? 200 : 400).json(result);
    } catch (error: unknown) {
      const message =
        error && typeof error === 'object' && 'message' in error
          ? String((error as { message?: unknown }).message || 'internal error')
          : 'internal error';
      return res.status(500).json({
        ok: false,
        code: 'internal',
        message,
      });
    }
  });
}
