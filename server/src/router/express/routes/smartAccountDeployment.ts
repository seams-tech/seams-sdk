import type { Router as ExpressRouter } from 'express';
import type { ExpressRelayContext } from '../createRelayRouter';
import { validateThresholdEcdsaSessionInputs } from '../../commonRouterUtils';
import { readCanonicalSmartAccountDeploymentManifest } from '../../smartAccountDeploymentManifest';
import {
  parseSmartAccountDeploymentManifestRequest,
  parseSmartAccountDeploymentObservationRequest,
} from '../../smartAccountDeploymentRequest';
import { syncSmartAccountRecoverySubjectDeployment } from '../../smartAccountRecoverySubjectDeploymentSync';

export function registerSmartAccountDeploymentRoutes(
  router: ExpressRouter,
  ctx: ExpressRelayContext,
): void {
  router.post('/smart-account/deployment/manifest', async (req: any, res: any) => {
    try {
      const validated = await validateThresholdEcdsaSessionInputs({
        body: req?.body,
        headers: req?.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) {
        res
          .status(validated.code === 'sessions_disabled' ? 500 : 401)
          .json({ ok: false, code: validated.code, message: validated.message });
        return;
      }

      const body = validated.body as Record<string, unknown>;
      const parsed = parseSmartAccountDeploymentManifestRequest(body);
      if (!parsed.chain || typeof parsed.chainId !== 'number' || !parsed.accountAddress) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'chain, chain_id, and account_address are required',
        });
        return;
      }

      const manifest = await readCanonicalSmartAccountDeploymentManifest({
        authService: ctx.service,
        expectedUserId: validated.claims.sub,
        chainIdKey: `${parsed.chain}:${parsed.chainId}`,
        accountAddress: parsed.accountAddress,
      });
      if (!manifest.ok) {
        const status =
          manifest.code === 'not_found'
            ? 404
            : manifest.code === 'forbidden'
              ? 403
              : manifest.code === 'internal'
                ? 500
                : 400;
        res.status(status).json({ ok: false, code: manifest.code, message: manifest.message });
        return;
      }

      res.status(200).json({
        ok: true,
        chainIdKey: manifest.chainIdKey,
        accountAddress: manifest.accountAddress,
        manifest: manifest.manifest,
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });

  router.post('/smart-account/deployment/observe', async (req: any, res: any) => {
    try {
      const validated = await validateThresholdEcdsaSessionInputs({
        body: req?.body,
        headers: req?.headers || {},
        session: ctx.opts.session,
      });
      if (!validated.ok) {
        res
          .status(validated.code === 'sessions_disabled' ? 500 : 401)
          .json({ ok: false, code: validated.code, message: validated.message });
        return;
      }

      const body = validated.body as Record<string, unknown>;
      const {
        chain,
        chainId,
        accountAddress,
        accountModel,
        deploymentTxHash,
        counterfactualAddress,
      } = parseSmartAccountDeploymentObservationRequest(body);
      if (!chain || typeof chainId !== 'number' || !accountAddress || !deploymentTxHash) {
        res.status(400).json({
          ok: false,
          code: 'invalid_body',
          message: 'chain, chain_id, account_address, and deployment_tx_hash are required',
        });
        return;
      }

      const synced = await syncSmartAccountRecoverySubjectDeployment({
        authService: ctx.service,
        expectedUserId: validated.claims.sub,
        update: {
          chain,
          chainId,
          accountAddress,
          deployed: true,
          ...(validated.claims.runtimeSnapshotScope
            ? { sponsorshipScope: validated.claims.runtimeSnapshotScope }
            : {}),
          ...(accountModel ? { accountModel } : {}),
          ...(deploymentTxHash ? { deploymentTxHash } : {}),
          ...(counterfactualAddress ? { counterfactualAddress } : {}),
        },
      });
      if (!synced.ok) {
        const status =
          synced.code === 'not_found'
            ? 404
            : synced.code === 'forbidden'
              ? 403
              : synced.code === 'internal'
                ? 500
                : 400;
        res.status(status).json({ ok: false, code: synced.code, message: synced.message });
        return;
      }

      res.status(200).json({
        ok: true,
        chainIdKey: synced.chainIdKey,
        accountAddress: synced.accountAddress,
        deployed: true,
      });
    } catch (e: any) {
      res
        .status(500)
        .json({ ok: false, code: 'internal', message: e?.message || 'Internal error' });
    }
  });
}
