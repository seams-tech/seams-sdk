import type { CloudflareRelayContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import { validateThresholdEcdsaSessionInputs } from '../../commonRouterUtils';
import { readCanonicalSmartAccountDeploymentManifest } from '../../smartAccountDeploymentManifest';
import {
  parseSmartAccountDeploymentManifestRequest,
  parseSmartAccountDeploymentObservationRequest,
} from '../../smartAccountDeploymentRequest';
import { syncSmartAccountRecoverySubjectDeployment } from '../../smartAccountRecoverySubjectDeploymentSync';

export async function handleSmartAccountDeployment(
  ctx: CloudflareRelayContext,
): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;
  if (
    ctx.pathname !== '/smart-account/deployment/observe' &&
    ctx.pathname !== '/smart-account/deployment/manifest'
  ) {
    return null;
  }

  const body = await readJson(ctx.request);
  const validated = await validateThresholdEcdsaSessionInputs({
    body,
    headers: Object.fromEntries(ctx.request.headers.entries()),
    session: ctx.opts.session,
  });
  if (!validated.ok) {
    return json(
      { ok: false, code: validated.code, message: validated.message },
      { status: validated.code === 'sessions_disabled' ? 500 : 401 },
    );
  }

  const parsedBody = validated.body as Record<string, unknown>;
  if (ctx.pathname === '/smart-account/deployment/manifest') {
    const parsed = parseSmartAccountDeploymentManifestRequest(parsedBody);
    if (!parsed.chain || typeof parsed.chainId !== 'number' || !parsed.accountAddress) {
      return json(
        {
          ok: false,
          code: 'invalid_body',
          message: 'chain, chain_id, and account_address are required',
        },
        { status: 400 },
      );
    }
    const manifest = await readCanonicalSmartAccountDeploymentManifest({
      authService: ctx.service,
      expectedUserId: validated.claims.sub,
      chainIdKey: `${parsed.chain}:${parsed.chainId}`,
      accountAddress: parsed.accountAddress,
    });
    if (!manifest.ok) {
      return json(
        { ok: false, code: manifest.code, message: manifest.message },
        {
          status:
            manifest.code === 'not_found'
              ? 404
              : manifest.code === 'forbidden'
                ? 403
                : manifest.code === 'internal'
                  ? 500
                  : 400,
        },
      );
    }
    return json(
      {
        ok: true,
        chainIdKey: manifest.chainIdKey,
        accountAddress: manifest.accountAddress,
        manifest: manifest.manifest,
      },
      { status: 200 },
    );
  }

  const {
    chain,
    chainId,
    accountAddress,
    accountModel,
    deploymentTxHash,
    counterfactualAddress,
  } = parseSmartAccountDeploymentObservationRequest(parsedBody);
  if (!chain || typeof chainId !== 'number' || !accountAddress || !deploymentTxHash) {
    return json(
      {
        ok: false,
        code: 'invalid_body',
        message: 'chain, chain_id, account_address, and deployment_tx_hash are required',
      },
      { status: 400 },
    );
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
    return json(
      { ok: false, code: synced.code, message: synced.message },
      {
        status:
          synced.code === 'not_found'
            ? 404
            : synced.code === 'forbidden'
              ? 403
              : synced.code === 'internal'
                ? 500
                : 400,
      },
    );
  }

  return json(
    {
      ok: true,
      chainIdKey: synced.chainIdKey,
      accountAddress: synced.accountAddress,
      deployed: true,
    },
    { status: 200 },
  );
}
