import type { CloudflareRouterApiContext } from '../createCloudflareRouter';
import { json, readJson } from '../http';
import {
  parseSyncAccountOptionsRequest,
  parseSyncAccountVerifyRequest,
} from '../../syncAccountRequestValidation';
import { buildPasskeyWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';

export async function handleSyncAccount(ctx: CloudflareRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/sync-account/options') {
    const body = await readJson(ctx.request);
    const parsed = parseSyncAccountOptionsRequest(body);
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.webAuthn.createWebAuthnSyncAccountOptions(parsed.request);
    return json(result, { status: result.ok ? 200 : result.code === 'internal' ? 500 : 400 });
  }

  if (ctx.pathname === '/sync-account/verify') {
    const body = await readJson(ctx.request);
    const parsed = parseSyncAccountVerifyRequest({
      body,
      origin: ctx.request.headers.get('origin'),
    });
    if (!parsed.ok) return json(parsed.body, { status: parsed.status });
    const result = await ctx.service.webAuthn.verifyWebAuthnSyncAccount(parsed.request);
    let responseBody: unknown = result;
    const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
    if (result.ok && result.verified && result.thresholdEd25519) {
      if (!yaoRuntime) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'Ed25519 Yao product registration is not configured',
          },
          { status: 500 },
        );
      }
      const thresholdEd25519 = result.thresholdEd25519;
      const firstParticipantId = thresholdEd25519?.participantIds?.[0];
      const secondParticipantId = thresholdEd25519?.participantIds?.[1];
      const signingWorkerId = String(thresholdEd25519?.relayerKeyId || '').trim();
      const walletId = String(result.walletId || '').trim();
      const nearAccountId = String(result.nearAccountId || '').trim();
      const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId || '').trim();
      const signerSlot = Number(result.signerSlot);
      const walletBinding = result.walletBinding;
      const credentialIdB64u = String(result.credentialIdB64u || '').trim();
      if (
        !thresholdEd25519 ||
        thresholdEd25519.participantIds?.length !== 2 ||
        firstParticipantId === undefined ||
        secondParticipantId === undefined ||
        !signingWorkerId ||
        !walletId ||
        !nearAccountId ||
        !nearEd25519SigningKeyId ||
        !Number.isSafeInteger(signerSlot) ||
        signerSlot < 1 ||
        !walletBinding ||
        !credentialIdB64u ||
        String(walletBinding.walletId) !== walletId ||
        String(walletBinding.nearAccountId) !== nearAccountId ||
        String(walletBinding.nearEd25519SigningKeyId) !== nearEd25519SigningKeyId ||
        walletBinding.signerSlot !== signerSlot
      ) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'verified passkey wallet is missing its Ed25519 Yao identity',
          },
          { status: 500 },
        );
      }
      const capability = yaoRuntime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        signerSlot,
        signingWorkerId,
        participantIds: [firstParticipantId, secondParticipantId],
      });
      if (!capability.ok) {
        return json(
          { ok: false, code: capability.code, message: capability.message },
          { status: capability.code === 'unknown_capability' ? 404 : 409 },
        );
      }
      const walletSession = await yaoRuntime.mintWalletSession({
        kind: 'registration_wallet_session_v1',
        walletId: walletIdFromString(capability.capability.applicationBinding.wallet_id),
        nearAccountId: capability.capability.nearAccountId,
        nearEd25519SigningKeyId:
          capability.capability.applicationBinding.near_ed25519_signing_key_id,
        authority: buildPasskeyWalletAuthAuthority({
          walletId: walletBinding.walletId,
          rpId: walletBinding.rpId,
          credentialIdB64u,
        }),
        thresholdSessionId: capability.capability.lifecycle.walletSessionId,
        participantIds: capability.capability.participantIds,
        runtimePolicyScope: capability.capability.runtimePolicyScope,
      });
      if (!walletSession.ok) {
        return json(
          { ok: false, code: walletSession.code, message: walletSession.message },
          { status: 500 },
        );
      }
      const normalSigningRuntime = ctx.service.thresholdRuntime.getRouterAbNormalSigningRuntime();
      if (!normalSigningRuntime) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'Ed25519 Yao normal-signing runtime is not configured',
          },
          { status: 500 },
        );
      }
      const provisioned =
        await normalSigningRuntime.provisionRouterAbEd25519YaoNormalSigningSession({
          kind: 'router_ab_ed25519_yao_normal_signing_session_v1',
          walletId,
          nearAccountId,
          nearEd25519SigningKeyId,
          authorityScope: walletSession.session.authorityScope,
          thresholdSessionId: walletSession.session.thresholdSessionId,
          signingGrantId: walletSession.session.signingGrantId,
          signingWorkerId,
          expiresAtMs: walletSession.session.expiresAtMs,
          participantIds: [firstParticipantId, secondParticipantId],
          remainingUses: walletSession.session.remainingUses,
        });
      if (!provisioned.ok) {
        return json(
          { ok: false, code: provisioned.code, message: provisioned.message },
          { status: 500 },
        );
      }
      responseBody = {
        ...result,
        thresholdEd25519: {
          ...thresholdEd25519,
          session: walletSession.session,
        },
        ed25519YaoRecovery: {
          kind: 'router_ab_ed25519_yao_sync_recovery_v1',
          capability: capability.capability,
        },
      };
    }
    return json(responseBody, {
      status: result.ok && result.verified ? 200 : result.code === 'internal' ? 500 : 400,
    });
  }

  return null;
}
