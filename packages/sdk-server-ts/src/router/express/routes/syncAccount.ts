import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';

export function registerSyncAccountRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/sync-account/options', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const result = await ctx.service.createWebAuthnSyncAccountOptions(req.body);
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
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const body = req.body;
      const challengeId = String(body.challengeId ?? body.challenge_id ?? '').trim();
      if (!challengeId) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'challengeId is required' });
        return;
      }
      if (!body.webauthn_authentication || typeof body.webauthn_authentication !== 'object') {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'webauthn_authentication is required',
        });
        return;
      }

      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const result = await ctx.service.verifyWebAuthnSyncAccount({
        challengeId,
        webauthn_authentication: body.webauthn_authentication,
        ...(body.threshold_ed25519 ? { threshold_ed25519: body.threshold_ed25519 } : {}),
        expected_origin: origin,
      });
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
          userId: result.accountId,
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
