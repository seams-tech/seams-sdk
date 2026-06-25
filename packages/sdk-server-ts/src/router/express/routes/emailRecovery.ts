import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import {
  parseRouterAbEd25519BootstrapSessionJwtSessionInfo,
  signRouterAbEd25519WalletSessionJwt,
} from '../../commonRouterUtils';
import {
  parsePrepareEmailRecoveryRequest,
  parseRespondEmailRecoveryEcdsaRequest,
} from '../../emailRecoveryRequestValidation';

export function registerEmailRecoveryRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  async function signEmailRecoveryThresholdSession(
    result: any,
    rpId: unknown,
    res: any,
  ): Promise<boolean> {
    const thresholdSession = result.thresholdEd25519?.session;
    if (!thresholdSession) return true;
    if (thresholdSession.sessionKind !== 'jwt') {
      res.status(400).json({
        ok: false,
        code: 'invalid_body',
        message: 'threshold_ed25519.session_kind must be jwt',
      });
      return false;
    }
    const sessionInfo = parseRouterAbEd25519BootstrapSessionJwtSessionInfo(thresholdSession);
    if (!sessionInfo) {
      res.status(500).json({
        ok: false,
        code: 'internal',
        message: 'invalid thresholdEd25519 session payload for jwt signing',
      });
      return false;
    }
    const signed = await signRouterAbEd25519WalletSessionJwt({
      session: ctx.opts.session,
      userId: sessionInfo.walletId,
      rpId,
      relayerKeyId: result.thresholdEd25519?.relayerKeyId,
      sessionInfo,
      fallbackParticipantIds: result.thresholdEd25519?.participantIds,
      requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
      invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
    });
    if (!signed.ok) {
      res.status(signed.status).json({ ok: false, code: signed.code, message: signed.message });
      return false;
    }
    result.thresholdEd25519.session.jwt = signed.jwt;
    return true;
  }

  router.post('/email-recovery/prepare', async (req: any, res: any) => {
    try {
      const origin = String(req.headers?.origin || req.headers?.Origin || '').trim() || undefined;
      const parsed = parsePrepareEmailRecoveryRequest({ body: req?.body, origin });
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.prepareEmailRecovery(parsed.request);
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }

      if (!(await signEmailRecoveryThresholdSession(result, parsed.request.rp_id, res))) return;

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/email-recovery/ecdsa/respond', async (req: any, res: any) => {
    try {
      const parsed = parseRespondEmailRecoveryEcdsaRequest(req?.body);
      if (!parsed.ok) {
        res.status(parsed.status).json(parsed.body);
        return;
      }
      const result = await ctx.service.respondEmailRecoveryEcdsa(parsed.request);
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }
      if (!(await signEmailRecoveryThresholdSession(result, result.walletBinding?.rpId, res))) {
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
