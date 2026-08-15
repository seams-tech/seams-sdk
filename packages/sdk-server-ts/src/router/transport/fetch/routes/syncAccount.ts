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
  parseAuthFactorId,
} from '@shared/authorization/capabilityKinds';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import { parseSessionOrigin, parseVerifiedOwnerProofId } from '../../../../authorization/domain';
import { buildVerifiedWalletSessionPasskeyFactorResult } from '../../../../authorization/factorEvidence';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { mintRouterAbEd25519YaoWalletSessionV1 } from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { isPlainObject } from '@shared/utils/validation';
import { authorWalletUnlockEcdsaRequest } from './sessions';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';

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
      const origin = parseSessionOrigin(parsed.request.expected_origin);
      const factorId = parseAuthFactorId(`passkey:${credentialIdB64u}`);
      const credentialId = parseWebAuthnCredentialIdB64u(credentialIdB64u);
      if (!factorId.ok || !credentialId.ok) {
        return json(
          { ok: false, code: 'internal', message: 'Verified passkey factor identity is invalid' },
          { status: 500 },
        );
      }
      const proof = await ctx.service.authorizedOperations.buildVerifiedOwnerProof({
        purpose: 'wallet_session',
        proofId: parseVerifiedOwnerProofId(`sync-account:${parsed.request.challengeId}`),
        factor: buildVerifiedWalletSessionPasskeyFactorResult({
          tenantId: ctx.service.authorizationSessions.tenantId,
          principalId: principalId.value,
          walletId: walletIdFromString(walletId),
          authorityRef,
          requestOrigin: origin,
          audience: origin,
          factorId: factorId.value,
          credentialIdB64u: credentialId.value,
          assertionDigest: parseDigestB64u(
            base64UrlEncode(await sha256BytesUtf8(alphabetizeStringify(parsed.request))),
          ),
          verifiedAtMs: issuedAtMs,
          expiresAtMs,
        }),
      });
      if (proof.purpose !== 'wallet_session') {
        return json(
          { ok: false, code: 'internal', message: 'Owner proof purpose is invalid' },
          { status: 500 },
        );
      }
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
      const walletSession = await mintRouterAbEd25519YaoWalletSessionV1({
        opaqueWalletSessions: ctx.service.authorizationSessions,
        tenantId: ctx.service.authorizationSessions.tenantId,
        signingWorkerId: yaoRuntime.signingWorkerId,
        sessionInput: {
          kind: 'verified_wallet_unlock_v1',
          proof,
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
        },
      });
      if (!walletSession.ok) {
        return json(
          { ok: false, code: walletSession.code, message: walletSession.message },
          { status: 500 },
        );
      }
      const rpId = parseWebAuthnRpId(walletBinding.rpId);
      if (!rpId.ok) {
        return json(
          { ok: false, code: 'internal', message: 'Verified passkey custody identity is invalid' },
          { status: 500 },
        );
      }
      const custodyEnvelope = await ctx.service.passkeyCustody.readVerifiedFactorCustody({
        walletId: walletIdFromString(walletId),
        factor: {
          kind: 'passkey',
          rpId: rpId.value,
          credentialIdB64u: credentialId.value,
        },
      });
      if (custodyEnvelope.kind !== 'active') {
        const manifestUnavailable = custodyEnvelope.kind === 'manifest_unavailable';
        return json(
          {
            ok: false,
            code: manifestUnavailable
              ? 'custody_manifest_unavailable'
              : `custody_envelope_${custodyEnvelope.kind}`,
            message: manifestUnavailable
              ? 'Wallet custody key manifest is unavailable'
              : 'Verified passkey has no unique active wallet custody envelope',
          },
          {
            status: manifestUnavailable ? 503 : custodyEnvelope.kind === 'conflict' ? 409 : 404,
          },
        );
      }
      const ecdsaSigners = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
        walletId,
      });
      let ecdsaSessionActivation = null;
      let ecdsaActivationReceipt = null;
      const firstEcdsaSigner = ecdsaSigners[0];
      if (firstEcdsaSigner) {
        const policy = parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1({
          kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
          key_handle: firstEcdsaSigner.walletKey.keyHandle,
          session_policy: {
            threshold_session_id: `sync-account-ecdsa:${parsed.request.challengeId}`,
            wallet_session_mint_id: mintId.value,
            ttl_ms: DEFAULT_WALLET_SESSION_TTL_MS,
            remaining_uses: DEFAULT_WALLET_SESSION_REMAINING_USES,
            runtime_policy_scope: firstEcdsaSigner.runtimePolicyScope,
          },
        });
        const authored = await authorWalletUnlockEcdsaRequest(ctx, walletId, policy);
        if (!authored.ok) {
          return json(
            { ok: false, code: authored.code, message: authored.message },
            { status: authored.status },
          );
        }
        const activatedResponse = await handleStrictEcdsaSessionActivation({
          ctx,
          body: authored.value.request,
          source: 'verified_ed25519_wallet_session',
          walletSessionToken: walletSession.session.walletSessionToken,
          proof,
        });
        const activatedBody: unknown = await activatedResponse.json();
        if (!activatedResponse.ok) {
          const failure = isPlainObject(activatedBody) ? activatedBody : {};
          return json(
            {
              ok: false,
              code: String(failure.code || 'ecdsa_session_activation_failed'),
              message: String(failure.message || 'ECDSA Wallet Session activation failed'),
            },
            { status: activatedResponse.status },
          );
        }
        ecdsaSessionActivation =
          parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(activatedBody);
        ecdsaActivationReceipt = authored.value.activationReceipt;
      }
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
        ...(ecdsaSessionActivation
          ? {
              ecdsaSession: ecdsaSessionActivation,
              ecdsaActivationReceipt,
            }
          : {}),
      };
    }
    return json(responseBody, { status: syncAccountResponseStatus(result) });
  }

  return null;
}
