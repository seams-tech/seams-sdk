import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parseClaimLinkDeviceSessionRequest,
  parsePrepareLinkDeviceRequest,
  parseRegisterLinkDeviceSessionRequest,
  parseRespondLinkDeviceEcdsaRequest,
} from '../../linkDeviceRequestValidation';

export function registerLinkDeviceRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.get('/link-device/session/:sessionId', async (req: any, res: any) => {
    try {
      const sessionId = String(req?.params?.sessionId || '').trim();
      const result = await ctx.service.getLinkDeviceSession({ sessionId });
      if (!result.ok) {
        const status = result.code === 'not_found' ? 404 : result.code === 'internal' ? 500 : 400;
        res.status(status).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/link-device/session', async (req: any, res: any) => {
    try {
      const parsed = parseRegisterLinkDeviceSessionRequest(req?.body);
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.registerLinkDeviceSession(parsed.request);
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

  router.post('/link-device/session/claim', async (req: any, res: any) => {
    try {
      const parsed = parseClaimLinkDeviceSessionRequest(req?.body);
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.claimLinkDeviceSession(parsed.request);
      if (!result.ok) {
        const status = result.code === 'not_found' ? 404 : result.code === 'internal' ? 500 : 400;
        res.status(status).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/link-device/prepare', async (req: any, res: any) => {
    try {
      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const parsed = parsePrepareLinkDeviceRequest({ body: req?.body, origin });
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.prepareLinkDevice(parsed.request);
      if (!result.ok) {
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
          rpId: parsed.request.rp_id,
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

  router.post('/link-device/ecdsa/respond', async (req: any, res: any) => {
    try {
      const parsed = parseRespondLinkDeviceEcdsaRequest(req?.body);
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.respondLinkDeviceEcdsa(parsed.request);
      if (!result.ok) {
        const status = result.code === 'not_found' ? 404 : result.code === 'internal' ? 500 : 400;
        res.status(status).json(result);
        return;
      }
      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
