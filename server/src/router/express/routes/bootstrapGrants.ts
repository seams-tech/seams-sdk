import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  RelayBootstrapGrantError,
  parseRelayBootstrapGrantIssueBody,
} from '../../bootstrapGrantBroker';
import { extractBearerCredential } from '../../relayApiKeyAuth';

function readOriginHeader(req: Request): string {
  const headers = (req.headers || {}) as Record<string, unknown>;
  const direct = String(headers.origin || '').trim();
  if (direct) return direct;
  return String(headers.Origin || '').trim();
}

export function registerBootstrapGrantRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  router.post('/v1/registration/bootstrap-grants', async (req: Request, res: Response) => {
    const broker = ctx.opts.bootstrapGrantBroker;
    if (!broker) {
      res.status(503).json({
        ok: false,
        code: 'bootstrap_grants_not_configured',
        message: 'Managed bootstrap grants are not configured on this server',
      });
      return;
    }

    const publishableKey = extractBearerCredential((req.headers || {}) as Record<string, unknown>);
    if (!publishableKey) {
      res.status(401).json({
        ok: false,
        code: 'publishable_key_missing',
        message: 'Missing publishable key',
      });
      return;
    }

    try {
      const parsedBody = parseRelayBootstrapGrantIssueBody((req as any).body);
      const result = await broker.issueGrant({
        publishableKey,
        origin: readOriginHeader(req),
        ...parsedBody,
      });
      if (!result.ok) {
        ctx.logger.warn('[relay][bootstrap-grants] denied', {
          code: result.code,
          status: result.status,
          environmentId: parsedBody.environmentId,
        });
        res.status(result.status).json({
          ok: false,
          code: result.code,
          message: result.message,
          ...(result.payment ? { payment: result.payment } : {}),
        });
        return;
      }

      ctx.logger.info('[relay][bootstrap-grants] issued', {
        environmentId: parsedBody.environmentId,
        mode: result.grant.mode,
      });
      res.status(200).json({ ok: true, grant: result.grant });
    } catch (error: unknown) {
      if (error instanceof RelayBootstrapGrantError) {
        res.status(error.status).json({
          ok: false,
          code: error.code,
          message: error.message,
        });
        return;
      }
      const message = error instanceof Error ? error.message : String(error);
      res.status(500).json({ ok: false, code: 'internal', message });
    }
  });
}
