import type { FetchRouterApiContext } from '../createFetchRouter';
import { json, readJson } from '../../../framework/http';
import {
  parseSyncAccountOptionsRequest,
  parseSyncAccountVerifyRequest,
} from '../../../domains/syncAccount/syncAccountRequestValidation';
import {
  buildPasskeyWalletAuthAuthority,
  walletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  parsePrincipalId,
  parseReusableWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1 } from '@shared/utils/routerAbEd25519Yao';
import { validateRouterAbEd25519WalletSessionTokenInputs } from '../../../auth/commonRouterUtils';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import { isPlainObject } from '@shared/utils/validation';

function syncAccountResponseStatus(result: { ok: boolean; verified?: boolean; code?: string }) {
  if (result.ok && result.verified) return 200;
  switch (result.code) {
    case 'internal':
      return 500;
    // The credential is valid and the request is well formed; the wallet's
    // Ed25519 signer just does not exist yet. Retryable, not a client error.
    case 'ed25519_not_provisioned':
      return 409;
    default:
      return 400;
  }
}

export async function handleSyncAccount(ctx: FetchRouterApiContext): Promise<Response | null> {
  if (ctx.method !== 'POST') return null;

  if (ctx.pathname === '/sync-account/rejoin') {
    const body = await readJson(ctx.request);
    const authorized = await validateRouterAbEd25519WalletSessionTokenInputs({
      body,
      headers: Object.fromEntries(ctx.request.headers.entries()),
      session: ctx.opts.session,
    });
    if (!authorized.ok) {
      return json(
        { ok: false, code: authorized.code, message: authorized.message },
        { status: authorized.code === 'wallet_session_expired' ? 401 : 403 },
      );
    }
    const executeRequest = parseRouterAbEd25519YaoRegistrationActivationExecuteRequestV1(
      isPlainObject(body) ? body.executeRequest : null,
    );
    if (!executeRequest.ok) {
      return json(
        { ok: false, code: 'invalid_body', message: executeRequest.message },
        { status: 400 },
      );
    }
    const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
    if (!yaoRuntime) {
      return json(
        { ok: false, code: 'internal', message: 'Ed25519 Yao product is not configured' },
        { status: 500 },
      );
    }
    const lifecycle = executeRequest.value.binding.lifecycle;
    const claims = authorized.claims;
    if (
      lifecycle.account_id !== claims.walletId ||
      lifecycle.session_id !== claims.thresholdSessionId ||
      lifecycle.selected_server_id !== claims.relayerKeyId
    ) {
      return json(
        { ok: false, code: 'wallet_session_mismatch', message: 'Cold unlock identity changed' },
        { status: 403 },
      );
    }
    const replayed = await yaoRuntime.replayActivatedRegistration(executeRequest.value);
    return replayed.ok
      ? json({ ok: true, value: replayed.value }, { status: 200 })
      : json(
          { ok: false, code: replayed.code, message: replayed.message },
          { status: replayed.status },
        );
  }

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
      const capability = await yaoRuntime.resolveActiveCapability({
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId,
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
      if (capability.capability.nearAccountId !== nearAccountId) {
        return json(
          {
            ok: false,
            code: 'capability_conflict',
            message: 'Active Ed25519 Yao capability does not match the verified NEAR account',
          },
          { status: 409 },
        );
      }
      const authority = buildPasskeyWalletAuthAuthority({
        walletId: walletBinding.walletId,
        rpId: walletBinding.rpId,
        credentialIdB64u,
      });
      const authorityRef = await walletAuthAuthorityRef({ authority });
      const principalId = parsePrincipalId(walletId);
      const mintId = parseReusableWalletSessionMintId(parsed.request.challengeId);
      if (!principalId.ok || !mintId.ok) {
        return json(
          {
            ok: false,
            code: 'internal',
            message: 'Verified passkey Wallet Session identity is invalid',
          },
          { status: 500 },
        );
      }
      const issuedAtMs = Date.now();
      const expiresAtMs = issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
      const reusableWalletSession =
        await ctx.service.authorizationSessions.issueReusableWalletSession({
          tenantId: ctx.service.authorizationSessions.tenantId,
          principalId: principalId.value,
          walletId: walletIdFromString(walletId),
          authority: authorityRef,
          mintId: mintId.value,
          remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
          issuedAtMs,
          expiresAtMs,
        });
      const walletSession = await yaoRuntime.mintWalletSession({
        kind: 'verified_wallet_unlock_v1',
        walletId: walletIdFromString(walletId),
        nearAccountId,
        nearEd25519SigningKeyId,
        authority,
        thresholdSessionId: capability.capability.lifecycle.thresholdSessionId,
        authorizationId: reusableWalletSession.session.authorizationId,
        walletSessionId: reusableWalletSession.quota.walletSessionId,
        quotaId: reusableWalletSession.quota.quotaId,
        participantIds: [firstParticipantId, secondParticipantId],
        runtimePolicyScope: capability.capability.runtimePolicyScope,
        expiresAtMs,
        remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
      });
      if (!walletSession.ok) {
        return json(
          { ok: false, code: walletSession.code, message: walletSession.message },
          { status: 500 },
        );
      }
      const rpId = parseWebAuthnRpId(walletBinding.rpId);
      const credentialId = parseWebAuthnCredentialIdB64u(credentialIdB64u);
      if (!rpId.ok || !credentialId.ok) {
        return json(
          { ok: false, code: 'internal', message: 'Verified passkey custody identity is invalid' },
          { status: 500 },
        );
      }
      const custodyEnvelope = await ctx.service.passkeyCustody.readVerifiedEnvelope({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'passkey',
          rpId: rpId.value,
          credentialIdB64u: credentialId.value,
        },
      });
      if (custodyEnvelope.kind !== 'active') {
        return json(
          {
            ok: false,
            code: `custody_envelope_${custodyEnvelope.kind}`,
            message: 'Verified passkey has no unique active wallet custody envelope',
          },
          { status: custodyEnvelope.kind === 'conflict' ? 409 : 404 },
        );
      }
      const ecdsaSigners = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
        walletId,
      });
      responseBody = {
        ...result,
        thresholdEd25519: {
          ...thresholdEd25519,
          session: walletSession.session,
        },
        ed25519YaoRecovery: {
          kind: 'router_ab_ed25519_yao_sync_recovery_v1',
          authorityRef,
          capability: capability.capability,
        },
        walletCustody: {
          kind: 'wallet_custody_sync_bootstrap_v1',
          envelope: custodyEnvelope.envelope,
          storeVersion: custodyEnvelope.storeVersion,
        },
        ecdsaCustody: {
          kind: 'wallet_custody_ecdsa_sync_continuity_v1',
          signers: ecdsaSigners.map((signer) => ({
            chainTarget: signer.chainTarget,
            walletKey: signer.walletKey,
            activationReceipt: signer.activationReceipt,
            runtimePolicyScope: signer.runtimePolicyScope,
          })),
        },
      };
    }
    return json(responseBody, { status: syncAccountResponseStatus(result) });
  }

  return null;
}
