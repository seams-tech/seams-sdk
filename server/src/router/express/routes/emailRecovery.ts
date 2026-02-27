import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';

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
        if (!ctx.opts.session) {
          res.status(500).json({
            ok: false,
            code: 'sessions_disabled',
            message: 'Session signing is not configured on this server',
          });
          return;
        }
        const sessionKind = String(thresholdSession.sessionKind || '')
          .trim()
          .toLowerCase();
        if (sessionKind !== 'jwt') {
          res.status(400).json({
            ok: false,
            code: 'invalid_body',
            message: 'threshold_ed25519.session_kind must be jwt',
          });
          return;
        }
        const accountId = String(result.accountId || '').trim();
        const rpId = String((req.body || {}).rp_id || '').trim();
        const relayerKeyId = String(result.thresholdEd25519?.relayerKeyId || '').trim();
        const sessionId = String(thresholdSession.sessionId || '').trim();
        const thresholdExpiresAtMs = Number(thresholdSession.expiresAtMs);
        const participantIds = Array.isArray(thresholdSession.participantIds)
          ? thresholdSession.participantIds
          : Array.isArray(result.thresholdEd25519?.participantIds)
            ? result.thresholdEd25519!.participantIds
            : [];
        if (
          !accountId ||
          !rpId ||
          !relayerKeyId ||
          !sessionId ||
          !Number.isFinite(thresholdExpiresAtMs) ||
          thresholdExpiresAtMs <= 0 ||
          participantIds.length < 2
        ) {
          res.status(500).json({
            ok: false,
            code: 'internal',
            message: 'invalid thresholdEd25519 session payload for jwt signing',
          });
          return;
        }
        const nowSec = Math.floor(Date.now() / 1000);
        const expSec = Math.floor(thresholdExpiresAtMs / 1000);
        const jwt = await ctx.opts.session.signJwt(accountId, {
          kind: 'threshold_ed25519_session_v1',
          sessionId,
          relayerKeyId,
          rpId,
          participantIds,
          thresholdExpiresAtMs,
          iat: nowSec,
          exp: expSec,
        });
        result.thresholdEd25519!.session!.jwt = jwt;
      }

      res.status(200).json(result);
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
