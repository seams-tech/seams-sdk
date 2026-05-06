import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import { signThresholdSessionAuthToken } from '../../commonRouterUtils';

export function registerEmailRecoveryRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  router.post('/email-recovery/prepare', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const result = await ctx.service.prepareEmailRecovery({
        ...(req.body || {}),
        ...(origin ? { expected_origin: origin } : {}),
      });
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }

      const thresholdSession = result.thresholdEd25519?.session;
      if (thresholdSession) {
        const signed = await signThresholdSessionAuthToken({
          session: ctx.opts.session,
          kind: 'threshold_ed25519_session_v1',
          userId: result.accountId,
          rpId: (req.body || {}).rp_id,
          relayerKeyId: result.thresholdEd25519?.relayerKeyId,
          sessionInfo: thresholdSession,
          fallbackParticipantIds: result.thresholdEd25519?.participantIds,
          requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
          invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
        });
        if (!signed.ok) {
          res
            .status(signed.status)
            .json({ ok: false, code: signed.code, message: signed.message });
          return;
        }
        result.thresholdEd25519!.session!.jwt = signed.jwt;
      }

      const thresholdEcdsaSession = result.thresholdEcdsa?.session;
      if (thresholdEcdsaSession) {
        const signed = await signThresholdSessionAuthToken({
          session: ctx.opts.session,
          kind: 'threshold_ecdsa_session_v1',
          userId: result.accountId,
          rpId: (req.body || {}).rp_id,
          relayerKeyId: result.thresholdEcdsa?.relayerKeyId,
          sessionInfo: thresholdEcdsaSession,
          fallbackParticipantIds: result.thresholdEcdsa?.participantIds,
          requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
          invalidPayloadErrorMessage: 'invalid thresholdEcdsa session payload for jwt signing',
        });
        if (!signed.ok) {
          res
            .status(signed.status)
            .json({ ok: false, code: signed.code, message: signed.message });
          return;
        }
        result.thresholdEcdsa!.session!.jwt = signed.jwt;
      }

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
