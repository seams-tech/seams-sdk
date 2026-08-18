import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parsePrincipalId,
  type ReusableWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '@shared/utils/domainIds';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { isPlainObject } from '@shared/utils/validation';
import type { VerifiedOwnerProof } from '../../../../authorization/domain';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { authorWalletUnlockEcdsaRequest } from './sessions';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import { mintRouterAbEd25519YaoWalletSessionV1 } from '../../../domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import type { WebAuthnSyncAccountVerificationResult } from '../../../../core/authService/webauthn';

export type VerifiedSyncAccountResultV1 = Extract<
  WebAuthnSyncAccountVerificationResult,
  { readonly ok: true; readonly verified: true }
>;

export type SyncAccountBootstrapInputV1 = {
  readonly ctx: FetchRouterApiContext;
  readonly result: VerifiedSyncAccountResultV1;
  readonly authority: WalletAuthAuthority;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly mintId: ReusableWalletSessionMintId;
  readonly issuedAtMs: number;
  readonly ecdsaThresholdSessionId: string;
  readonly custody:
    | { readonly kind: 'read_verified_factor' }
    | {
        readonly kind: 'provided';
        readonly envelope: PasskeyCustodyEnvelopeRecord;
        readonly storeVersion: string;
      };
};

export type SyncAccountBootstrapResultV1 =
  | { readonly kind: 'ok'; readonly body: Record<string, unknown> }
  | { readonly kind: 'error'; readonly code: string; readonly message: string; readonly status: number };

export async function issueSyncAccountBootstrapV1(
  input: SyncAccountBootstrapInputV1,
): Promise<SyncAccountBootstrapResultV1> {
  const { ctx, result } = input;
  const yaoRuntime = ctx.opts.routerAbEd25519YaoProduct;
  const thresholdEd25519 = result.thresholdEd25519;
  const custodyKeyManifestDigestB64u = result.custodyKeyManifestDigestB64u;
  const walletBinding = result.walletBinding;
  const walletId = String(result.walletId).trim();
  const nearAccountId = String(result.nearAccountId).trim();
  const nearEd25519SigningKeyId = String(result.nearEd25519SigningKeyId).trim();
  const signingWorkerId = String(thresholdEd25519?.relayerKeyId || '').trim();
  const signerSlot = Number(result.signerSlot);
  const credentialIdB64u = String(result.credentialIdB64u).trim();
  const firstParticipantId = thresholdEd25519?.participantIds?.[0];
  const secondParticipantId = thresholdEd25519?.participantIds?.[1];
  if (!custodyKeyManifestDigestB64u) {
    return bootstrapError('internal', 'Sync verification did not resolve the wallet key manifest', 500);
  }
  if (!yaoRuntime) {
    return bootstrapError(
      'internal',
      'Ed25519 Yao product registration is not configured',
      500,
    );
  }
  if (
    thresholdEd25519?.participantIds?.length !== 2 ||
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
    walletBinding.signerSlot !== signerSlot ||
    input.authority.walletId !== walletId ||
    input.authorityRef.walletId !== walletId
  ) {
    return bootstrapError(
      'internal',
      'verified passkey wallet is missing its Ed25519 Yao identity',
      500,
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
    return bootstrapError(
      capability.code,
      capability.message,
      capability.code === 'unknown_capability' ? 404 : 409,
    );
  }
  if (capability.capability.nearAccountId !== nearAccountId) {
    return bootstrapError(
      'capability_conflict',
      'Active Ed25519 Yao capability does not match the verified NEAR account',
      409,
    );
  }

  const principalId = parsePrincipalId(walletId);
  if (!principalId.ok) {
    return bootstrapError('internal', 'Verified passkey Wallet Session identity is invalid', 500);
  }
  const reusableWalletSession =
    await ctx.service.authorizationSessions.issueReusableWalletSession({
      tenantId: ctx.service.authorizationSessions.tenantId,
      principalId: principalId.value,
      walletId: walletIdFromString(walletId),
      authority: input.authorityRef,
      mintId: input.mintId,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
    });
  const walletSession = await mintRouterAbEd25519YaoWalletSessionV1({
    opaqueWalletSessions: ctx.service.authorizationSessions,
    tenantId: ctx.service.authorizationSessions.tenantId,
    signingWorkerId: yaoRuntime.signingWorkerId,
    sessionInput: {
      kind: 'verified_wallet_unlock_v1',
      proof: input.proof,
      walletId: walletIdFromString(walletId),
      nearAccountId,
      nearEd25519SigningKeyId,
      authority: input.authority,
      thresholdSessionId: capability.capability.lifecycle.thresholdSessionId,
      authorizationId: reusableWalletSession.session.authorizationId,
      walletSessionId: reusableWalletSession.quota.walletSessionId,
      quotaId: reusableWalletSession.quota.quotaId,
      participantIds: [firstParticipantId, secondParticipantId],
      runtimePolicyScope: capability.capability.runtimePolicyScope,
      keyManifestDigestB64u: custodyKeyManifestDigestB64u,
      expiresAtMs: input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    },
  });
  if (!walletSession.ok) {
    return bootstrapError(walletSession.code, walletSession.message, 500);
  }

  const custodyEnvelope = await resolveCustodyEnvelope(input, walletId, walletBinding);
  if (custodyEnvelope.kind !== 'active') {
    const manifestUnavailable = custodyEnvelope.kind === 'manifest_unavailable';
    return bootstrapError(
      manifestUnavailable ? 'custody_manifest_unavailable' : `custody_envelope_${custodyEnvelope.kind}`,
      manifestUnavailable
        ? 'Wallet custody key manifest is unavailable'
        : 'Verified passkey has no unique active wallet custody envelope',
      manifestUnavailable ? 503 : custodyEnvelope.kind === 'conflict' ? 409 : 404,
    );
  }

  const ecdsaSigners = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId,
  });
  let ecdsaSessionActivation: unknown = null;
  let ecdsaActivationReceipt: unknown = null;
  const firstEcdsaSigner = ecdsaSigners[0];
  if (firstEcdsaSigner) {
    const policy = parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1({
      kind: 'router_ab_ecdsa_post_registration_session_activation_policy_v1',
      key_handle: firstEcdsaSigner.walletKey.keyHandle,
      session_policy: {
        threshold_session_id: input.ecdsaThresholdSessionId,
        wallet_session_mint_id: input.mintId,
        ttl_ms: DEFAULT_WALLET_SESSION_TTL_MS,
        remaining_uses: DEFAULT_WALLET_SESSION_REMAINING_USES,
        runtime_policy_scope: firstEcdsaSigner.runtimePolicyScope,
      },
    });
    const authored = await authorWalletUnlockEcdsaRequest(ctx, walletId, policy);
    if (!authored.ok) return bootstrapError(authored.code, authored.message, authored.status);
    const activatedResponse = await handleStrictEcdsaSessionActivation({
      ctx,
      body: authored.value.request,
      source: 'verified_ed25519_wallet_session',
      walletSessionToken: walletSession.session.walletSessionToken,
      proof: input.proof,
    });
    const activatedBody: unknown = await activatedResponse.json();
    if (!activatedResponse.ok) {
      const failure = isPlainObject(activatedBody) ? activatedBody : {};
      return bootstrapError(
        String(failure.code || 'ecdsa_session_activation_failed'),
        String(failure.message || 'ECDSA Wallet Session activation failed'),
        activatedResponse.status,
      );
    }
    ecdsaSessionActivation = parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(
      activatedBody,
    );
    ecdsaActivationReceipt = authored.value.activationReceipt;
  }

  return {
    kind: 'ok',
    body: {
      ...result,
      thresholdEd25519: {
        ...thresholdEd25519,
        session: walletSession.session,
      },
      ed25519YaoRecovery: {
        kind: 'router_ab_ed25519_yao_sync_recovery_v1',
        authorityRef: input.authorityRef,
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
        ? { ecdsaSession: ecdsaSessionActivation, ecdsaActivationReceipt }
        : {}),
    },
  };
}

async function resolveCustodyEnvelope(
  input: SyncAccountBootstrapInputV1,
  walletId: string,
  walletBinding: VerifiedSyncAccountResultV1['walletBinding'],
) {
  if (input.custody.kind === 'provided') {
    const factor = input.custody.envelope.factor;
    if (
      input.custody.envelope.walletId !== walletId ||
      factor.kind !== 'passkey' ||
      factor.rpId !== walletBinding.rpId ||
      factor.credentialIdB64u !== walletBinding.credentialIdB64u
    ) {
      return { kind: 'conflict' as const };
    }
    return {
      kind: 'active' as const,
      envelope: input.custody.envelope,
      storeVersion: input.custody.storeVersion,
    };
  }
  const rpId = parseWebAuthnRpId(walletBinding.rpId);
  const credentialId = parseWebAuthnCredentialIdB64u(walletBinding.credentialIdB64u);
  if (!rpId.ok || !credentialId.ok) return { kind: 'conflict' as const };
  return await input.ctx.service.passkeyCustody.readVerifiedFactorCustody({
    walletId: walletIdFromString(walletId),
    factor: {
      kind: 'passkey',
      rpId: rpId.value,
      credentialIdB64u: credentialId.value,
    },
  });
}

function bootstrapError(
  code: string,
  message: string,
  status: number,
): SyncAccountBootstrapResultV1 {
  return { kind: 'error', code, message, status };
}
