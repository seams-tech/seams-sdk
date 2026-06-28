import type { Router as ExpressRouter } from 'express';
import type { ExpressRouterApiContext } from '../createRouterApiRouter';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parseSyncAccountOptionsRequest,
  parseSyncAccountVerifyRequest,
} from '../../syncAccountRequestValidation';

export function registerSyncAccountRoutes(router: ExpressRouter, ctx: ExpressRouterApiContext): void {
  router.post('/sync-account/options', async (req: any, res: any) => {
    try {
      const parsed = parseSyncAccountOptionsRequest(req?.body);
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.createWebAuthnSyncAccountOptions(parsed.request);
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/sync-account/verify', async (req: any, res: any) => {
    try {
      const parsed = parseSyncAccountVerifyRequest({
        body: req?.body,
        origin: req.headers?.origin || req.headers?.Origin,
      });
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }

      const result = await ctx.service.verifyWebAuthnSyncAccount(parsed.request);
      if (!result.ok || !result.verified) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }

      const thresholdSession = result.thresholdEd25519?.session;
      if (thresholdSession) {
        if (thresholdSession.sessionKind !== 'jwt') {
          res.status(400).json({
            ok: false,
            code: 'invalid_body',
            message: 'threshold_ed25519.session_kind must be jwt',
          });
          return;
        }
        const sessionInfo = parseRouterAbEd25519BootstrapSessionJwtSessionInfo(thresholdSession);
        if (!sessionInfo) {
          res.status(500).json({
            ok: false,
            code: 'internal',
            message: 'invalid thresholdEd25519 session payload for jwt signing',
          });
          return;
        }
        const signed = await signRouterAbEd25519WalletSessionJwt({
          session: ctx.opts.session,
          userId: sessionInfo.walletId,
          rpId: result.rpId,
          relayerKeyId: result.thresholdEd25519?.relayerKeyId,
          sessionInfo,
          fallbackParticipantIds: result.thresholdEd25519?.participantIds,
          requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
          invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
        });
        if (!signed.ok) {
          res.status(signed.status).json({ ok: false, code: signed.code, message: signed.message });
          return;
        }
        result.thresholdEd25519!.session!.jwt = signed.jwt;
      }

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
