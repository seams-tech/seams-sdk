import type { Request, Response, Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import type {
  CreateAccountAndRegisterRequest,
  CreateAccountAndRegisterResult,
} from '../../../core/types';
import { signThresholdSessionJwt } from '../../commonRouterUtils';

export function registerCreateAccountAndRegisterUser(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  router.post('/registration/bootstrap', async (req: Request, res: Response) => {
    try {
      const body = (req.body || {}) as any as CreateAccountAndRegisterRequest &
        Record<string, unknown>;
      const new_account_id = String(body.new_account_id || '').trim();
      const new_public_key =
        typeof body.new_public_key === 'string' ? body.new_public_key.trim() : '';
      const device_number = (body as any).device_number;
      const threshold_ed25519 = (body as any).threshold_ed25519;
      const threshold_ecdsa = (body as any).threshold_ecdsa;
      const rp_id = typeof body.rp_id === 'string' ? body.rp_id.trim() : '';
      const webauthn_registration = (body as any).webauthn_registration;
      const authenticator_options = (body as any).authenticator_options;

      if (!new_account_id)
        return res.status(400).json({ success: false, error: 'Missing or invalid new_account_id' });
      if (!rp_id)
        return res.status(400).json({ success: false, error: 'Missing or invalid rp_id' });
      if (!webauthn_registration || typeof webauthn_registration !== 'object') {
        return res
          .status(400)
          .json({ success: false, error: 'Missing or invalid webauthn_registration' });
      }

      const result = await ctx.service.createAccountAndRegisterUser({
        new_account_id,
        ...(new_public_key ? { new_public_key } : {}),
        device_number,
        ...(threshold_ed25519 ? { threshold_ed25519 } : {}),
        ...(threshold_ecdsa ? { threshold_ecdsa } : {}),
        rp_id,
        webauthn_registration,
        expected_origin: (req.headers?.origin || req.headers?.Origin) as string | undefined,
        authenticator_options,
      });

      const response: CreateAccountAndRegisterResult = result;
      if (!response.success) {
        res.status(400).json(response);
        return;
      }

      const session = ctx.opts.session;
      if (!session) {
        res.status(200).json(response);
        return;
      }

      const rpId = String(body.rp_id || '').trim();
      if (!rpId) {
        res
          .status(500)
          .json({ success: false, error: 'missing rp_id for threshold session token signing' });
        return;
      }

      if (response.thresholdEd25519?.session) {
        const signed = await signThresholdSessionJwt({
          session,
          kind: 'threshold_ed25519_session_v1',
          userId: new_account_id,
          rpId,
          relayerKeyId: response.thresholdEd25519.relayerKeyId,
          sessionInfo: response.thresholdEd25519.session,
          fallbackParticipantIds: response.thresholdEd25519.participantIds,
          requireJwtErrorMessage: 'threshold_ed25519.session_kind must be jwt',
          invalidPayloadErrorMessage: 'invalid thresholdEd25519 session payload for jwt signing',
        });
        if (!signed.ok) {
          res.status(signed.status).json({ success: false, error: signed.message });
          return;
        }
        response.thresholdEd25519.session.jwt = signed.jwt;
      }

      if (response.thresholdEcdsa?.session) {
        const signed = await signThresholdSessionJwt({
          session,
          kind: 'threshold_ecdsa_session_v1',
          userId: new_account_id,
          rpId,
          relayerKeyId: response.thresholdEcdsa.relayerKeyId,
          sessionInfo: response.thresholdEcdsa.session,
          fallbackParticipantIds: response.thresholdEcdsa.participantIds,
          requireJwtErrorMessage: 'threshold_ecdsa.session_kind must be jwt',
          invalidPayloadErrorMessage: 'invalid thresholdEcdsa session payload for jwt signing',
        });
        if (!signed.ok) {
          res.status(signed.status).json({ success: false, error: signed.message });
          return;
        }
        response.thresholdEcdsa.session.jwt = signed.jwt;
      }

      res.status(200).json(response);
    } catch (error: unknown) {
      const message =
        error && typeof error === 'object' && 'message' in error
          ? String((error as { message?: unknown }).message || 'internal error')
          : 'internal error';
      res.status(500).json({ success: false, error: message });
    }
  });
}
