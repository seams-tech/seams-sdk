import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parsePrincipalId,
  type ReusableWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import { parseWebAuthnCredentialIdB64u, parseWebAuthnRpId } from '@shared/utils/domainIds';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '@shared/utils/signingSessionSeal';
import { deriveSigningRootId, type RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { isPlainObject } from '@shared/utils/validation';
import type { DirectV2IssueResult, VerifiedOwnerProof } from '../../../../authorization/domain';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../../../core/ThresholdService/validation';
import { authorWalletUnlockEcdsaRequest } from './sessions';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import type { WebAuthnSyncAccountVerificationResult } from '../../../../core/authService/webauthn';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../../../core/registrationContracts';

export type VerifiedSyncAccountResultV1 = Extract<
  WebAuthnSyncAccountVerificationResult,
  { readonly ok: true; readonly verified: true }
>;

export type SyncAccountBootstrapInputV1 = {
  readonly ctx: FetchRouterApiContext;
  readonly result: VerifiedSyncAccountResultV1;
  readonly authority: WalletAuthAuthority;
  readonly activeAuthority: ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
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
  | {
      readonly kind: 'already_committed';
      readonly committed: Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }>;
    }
  | {
      readonly kind: 'error';
      readonly code: string;
      readonly message: string;
      readonly status: number;
    };

function buildDirectSyncWalletSession(input: {
  readonly issued: Extract<DirectV2IssueResult, { readonly kind: 'issued' }>;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly authority: WalletAuthAuthority;
  readonly thresholdSessionId: string;
  readonly signingWorkerId: string;
  readonly participantIds: readonly [number, number];
  readonly runtimePolicyScope: RuntimePolicyScope;
}): WalletRegistrationEd25519YaoBootstrapSession {
  const routerAbNormalSigning = {
    kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
    signingWorkerId: input.signingWorkerId,
  } as const;
  return {
    sessionKind: 'opaque',
    walletSessionToken: input.issued.operationCredential.token,
    walletId: input.issued.session.walletId,
    nearAccountId: input.nearAccountId,
    nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
    authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(input.authority),
    thresholdSessionId: input.thresholdSessionId,
    authorizationId: input.issued.session.authorizationId,
    walletSessionId: input.issued.session.walletSessionId,
    quotaId: input.issued.session.quotaId,
    expiresAtMs: input.issued.session.expiresAtMs,
    participantIds: input.participantIds,
    remainingUses: input.issued.quota.remainingUses,
    signingRootId: deriveSigningRootId(input.runtimePolicyScope),
    signingRootVersion: input.runtimePolicyScope.signingRootVersion,
    runtimePolicyScope: input.runtimePolicyScope,
    routerAbNormalSigning,
  };
}

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
    return bootstrapError(
      'internal',
      'Sync verification did not resolve the wallet key manifest',
      500,
    );
  }
  if (!yaoRuntime) {
    return bootstrapError('internal', 'Ed25519 Yao product registration is not configured', 500);
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

  const custodyEnvelope = await resolveCustodyEnvelope(input, walletId, walletBinding);
  if (custodyEnvelope.kind !== 'active') {
    const manifestUnavailable = custodyEnvelope.kind === 'manifest_unavailable';
    return bootstrapError(
      manifestUnavailable
        ? 'custody_manifest_unavailable'
        : `custody_envelope_${custodyEnvelope.kind}`,
      manifestUnavailable
        ? 'Wallet custody key manifest is unavailable'
        : 'Verified passkey has no unique active wallet custody envelope',
      manifestUnavailable ? 503 : custodyEnvelope.kind === 'conflict' ? 409 : 404,
    );
  }

  const principalId = parsePrincipalId(walletId);
  if (!principalId.ok) {
    return bootstrapError('internal', 'Verified passkey Wallet Session identity is invalid', 500);
  }
  const issueDirect = ctx.service.authorizationSessions.issueDirectWalletSessionAuthorizationV2;
  if (!issueDirect) {
    return bootstrapError('internal', 'Direct Wallet Session issuance is not configured', 500);
  }
  const directIssue = await issueDirect({
    tenantId: ctx.service.authorizationSessions.tenantId,
    principalId: principalId.value,
    walletId: walletIdFromString(walletId),
    authority: input.activeAuthority,
    walletAuthMethodId: input.walletAuthMethodId,
    mintId: input.mintId,
    remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
  });
  if (directIssue.kind === 'already_committed') {
    return { kind: 'already_committed', committed: directIssue };
  }
  const walletSession = buildDirectSyncWalletSession({
    issued: directIssue,
    nearAccountId,
    nearEd25519SigningKeyId,
    authority: input.authority,
    thresholdSessionId: capability.capability.lifecycle.thresholdSessionId,
    signingWorkerId: yaoRuntime.signingWorkerId,
    participantIds: [firstParticipantId, secondParticipantId],
    runtimePolicyScope: capability.capability.runtimePolicyScope,
  });

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
      walletSessionToken: walletSession.walletSessionToken,
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
    ecdsaSessionActivation =
      parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1(activatedBody);
    ecdsaActivationReceipt = authored.value.activationReceipt;
  }

  return {
    kind: 'ok',
    body: {
      ...result,
      thresholdEd25519: {
        ...thresholdEd25519,
        session: walletSession,
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
