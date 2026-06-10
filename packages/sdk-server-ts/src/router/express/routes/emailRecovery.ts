import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import { signThresholdSessionAuthToken } from '../../commonRouterUtils';

export function registerEmailRecoveryRoutes(router: ExpressRouter, ctx: ExpressRelayContext): void {
  async function signEmailRecoveryThresholdSession(result: any, rpId: unknown, res: any): Promise<boolean> {
    const thresholdSession = result.thresholdEd25519?.session;
    if (!thresholdSession) return true;
    const signed = await signThresholdSessionAuthToken({
      session: ctx.opts.session,
      kind: 'threshold_ed25519_session_v1',
      userId: result.accountId,
      rpId,
      relayerKeyId: result.thresholdEd25519?.relayerKeyId,
      sessionInfo: thresholdSession,
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

      if (!(await signEmailRecoveryThresholdSession(result, (req.body || {}).rp_id, res))) return;

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/email-recovery/ecdsa/respond', async (req: any, res: any) => {
    try {
      if (!req?.body) {
        res
          .status(400)
          .json({ ok: false, code: 'invalid_body', message: 'Request body is required' });
        return;
      }
      const result = await ctx.service.respondEmailRecoveryEcdsa({ ...(req.body || {}) });
      if (!result.ok) {
        res.status(result.code === 'internal' ? 500 : 400).json(result);
        return;
      }
      if (!(await signEmailRecoveryThresholdSession(result, result.ecdsa?.bootstrap?.rpId, res))) {
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
