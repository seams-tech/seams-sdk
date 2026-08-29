import type { PasskeyCustodyEnvelopeRecord } from '@shared/passkey-custody';
import {
  parsePrincipalId,
  type ReusableWalletSessionMintId,
} from '@shared/authorization/capabilityKinds';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  mpcMaterialActivationRefsEqual,
  type WalletAuthMethodId,
  type WalletAuthorityId,
} from '@shared/utils/domainIds';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import { walletIdFromString, type WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type {
  WalletSessionClientCapabilityV1,
  MpcWalletSigningQuotaId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  ActiveWalletSessionV1,
  WalletSessionOperationCredentialV1,
} from '@shared/device-linking/contracts';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import {
  parseRouterAbEcdsaPostRegistrationSessionActivationPolicyV1,
  parseRouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaPostRegistrationSessionActivationResponseV1,
  type RouterAbEcdsaRegistrationActivationReceiptV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import { isPlainObject } from '@shared/utils/validation';
import { routerAbMpcMaterialActivationRefFromWire } from '@shared/utils/routerAbNormalSigningIdentity';
import {
  WALLET_SYNC_EXACT_RESPONSE_FAMILY_V1,
  type DirectV2IssueResult,
  type VerifiedOwnerProof,
} from '../../../../authorization/domain';
import type { FetchRouterApiContext } from '../createFetchRouter';
import { authorWalletUnlockEcdsaRequest } from './sessions';
import { handleStrictEcdsaSessionActivation } from './thresholdEcdsa';
import type { WebAuthnSyncAccountVerificationResult } from '../../../../core/authService/webauthn';
import type { WalletEcdsaSignerRecord } from '../../../../core/WalletStore';
import { projectActiveWalletSession } from '../../../../authorization/domain';
import type { RouterAbEd25519YaoActiveCapabilityDescriptorV1 } from '../../../domains/ed25519Yao/recovery/routerAbEd25519YaoRecovery';

export type VerifiedSyncAccountResultV1 = Extract<
  WebAuthnSyncAccountVerificationResult,
  { readonly ok: true; readonly verified: true }
>;

type SyncAccountExactThresholdEd25519SessionV1 = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly thresholdSessionId: string;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly routerAbNormalSigning: {
    readonly kind: 'router_ab_ed25519_normal_signing_v1';
    readonly signingWorkerId: string;
  };
};

type SyncAccountExactBootstrapBodyBaseV1 = {
  readonly ok: true;
  readonly verified: true;
  readonly accountId: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly walletAuthorityId: WalletAuthorityId;
  readonly foundingAuthority: ActiveWalletAuthorityV1;
  readonly foundingAuthMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'passkey'; readonly status: 'active' }
  >;
  readonly custodyKeyManifestDigestB64u: VerifiedSyncAccountResultV1['custodyKeyManifestDigestB64u'];
  readonly walletBinding: VerifiedSyncAccountResultV1['walletBinding'];
  readonly rpId: string;
  readonly signerSlot: number;
  readonly publicKey: string;
  readonly relayerKeyId: string;
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly thresholdEd25519: {
    readonly relayerKeyId: string;
    readonly keyVersion: string;
    readonly participantIds: readonly [number, number];
    readonly session: SyncAccountExactThresholdEd25519SessionV1;
  };
  readonly walletSession: ActiveWalletSessionV1;
  readonly operationCredential: WalletSessionOperationCredentialV1;
  readonly ed25519YaoRecovery: {
    readonly kind: 'router_ab_ed25519_yao_sync_recovery_v1';
    readonly authorityRef: WalletAuthAuthorityRef;
    readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1;
  };
  readonly walletCustody: {
    readonly kind: 'wallet_custody_sync_bootstrap_v1';
    readonly envelope: PasskeyCustodyEnvelopeRecord;
    readonly storeVersion: string;
  };
  readonly ecdsaCustody: {
    readonly kind: 'wallet_custody_ecdsa_sync_continuity_v1';
    readonly signers: readonly Pick<
      WalletEcdsaSignerRecord,
      'chainTarget' | 'walletKey' | 'activationReceipt' | 'runtimePolicyScope'
    >[];
  };
};

export type SyncAccountExactBootstrapBodyV1 = SyncAccountExactBootstrapBodyBaseV1 &
  (
    | {
        readonly ecdsaSession?: never;
        readonly ecdsaActivationReceipt?: never;
      }
    | {
        readonly ecdsaSession: RouterAbEcdsaPostRegistrationSessionActivationResponseV1;
        readonly ecdsaActivationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1;
      }
  );

export type SyncAccountBootstrapInputV1 = {
  readonly ctx: FetchRouterApiContext;
  readonly result: VerifiedSyncAccountResultV1;
  readonly authority: WalletAuthAuthority;
  readonly activeAuthority: ActiveWalletAuthorityV1;
  readonly foundingAuthMethod: Extract<
    WalletAuthMethodRecordV2,
    { readonly kind: 'passkey'; readonly status: 'active' }
  >;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityRef: WalletAuthAuthorityRef;
  readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
  readonly mintId: ReusableWalletSessionMintId;
  readonly walletSessionClientCapability: WalletSessionClientCapabilityV1;
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
  | { readonly kind: 'ok'; readonly body: SyncAccountExactBootstrapBodyV1 }
  | {
      readonly kind: 'already_committed';
      readonly committed: Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }>;
    }
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
    !String(thresholdEd25519?.keyVersion || '').trim() ||
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
  const authorityEd25519Activation = input.activeAuthority.signerActivations.ed25519;
  if (
    !authorityEd25519Activation ||
    !mpcMaterialActivationRefsEqual(
      authorityEd25519Activation.materialActivation,
      routerAbMpcMaterialActivationRefFromWire(capability.capability.materialActivation),
    )
  ) {
    return bootstrapError(
      'capability_conflict',
      'Active Ed25519 Yao capability does not match the wallet authority material activation',
      409,
    );
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

  const principalId = parsePrincipalId(walletId);
  if (!principalId.ok) {
    return bootstrapError('internal', 'Verified passkey Wallet Session identity is invalid', 500);
  }
  const directIssue = await ctx.service.authorizationSessions.issueDirectWalletSessionAuthorizationV2({
    tenantId: ctx.service.authorizationSessions.tenantId,
    principalId: principalId.value,
    walletId: walletIdFromString(walletId),
    authority: input.activeAuthority,
    walletAuthMethodId: input.walletAuthMethodId,
    mintId: input.mintId,
    remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    issuedAtMs: input.issuedAtMs,
    expiresAtMs: input.issuedAtMs + DEFAULT_WALLET_SESSION_TTL_MS,
    walletSessionClientCapability: input.walletSessionClientCapability,
    responseFamily: WALLET_SYNC_EXACT_RESPONSE_FAMILY_V1,
  });
  if (directIssue.kind === 'already_committed') {
    return { kind: 'already_committed', committed: directIssue };
  }
  if (directIssue.kind === 'protocol_mismatch') {
    return bootstrapError(directIssue.code, directIssue.message, 409);
  }

  const ecdsaSigners = await ctx.service.walletRegistration.listWalletEcdsaCustodyContinuity({
    walletId,
  });
  let ecdsaSessionActivation: RouterAbEcdsaPostRegistrationSessionActivationResponseV1 | null =
    null;
  let ecdsaActivationReceipt: RouterAbEcdsaRegistrationActivationReceiptV1 | null = null;
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
      walletSessionToken: directIssue.operationCredential.token,
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

  const bodyBase: SyncAccountExactBootstrapBodyBaseV1 = {
    ok: true,
    verified: true,
    accountId: String(result.accountId).trim(),
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    walletAuthMethodId: input.walletAuthMethodId,
    walletAuthorityId: input.activeAuthority.authorityId,
    foundingAuthority: input.activeAuthority,
    foundingAuthMethod: input.foundingAuthMethod,
    custodyKeyManifestDigestB64u,
    walletBinding,
    rpId: String(result.rpId).trim(),
    signerSlot,
    publicKey: String(result.publicKey).trim(),
    relayerKeyId: signingWorkerId,
    credentialIdB64u,
    credentialPublicKeyB64u: String(result.credentialPublicKeyB64u).trim(),
    thresholdEd25519: {
      relayerKeyId: signingWorkerId,
      keyVersion: String(thresholdEd25519.keyVersion).trim(),
      participantIds: [firstParticipantId, secondParticipantId],
      session: {
        walletId,
        nearAccountId,
        nearEd25519SigningKeyId,
        thresholdSessionId: capability.capability.lifecycle.thresholdSessionId,
        walletSessionId: directIssue.session.walletSessionId,
        quotaId: directIssue.session.quotaId,
        expiresAtMs: directIssue.session.expiresAtMs,
        remainingUses: directIssue.quota.remainingUses,
        runtimePolicyScope: capability.capability.runtimePolicyScope,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: yaoRuntime.signingWorkerId,
        },
      },
    },
    walletSession: projectActiveWalletSession({
      session: directIssue.session,
      quota: directIssue.quota,
    }),
    operationCredential: directIssue.operationCredential,
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
  };
  if (ecdsaSessionActivation && ecdsaActivationReceipt) {
    const body: SyncAccountExactBootstrapBodyV1 = {
      ...bodyBase,
      ecdsaSession: ecdsaSessionActivation,
      ecdsaActivationReceipt,
    };
    return { kind: 'ok', body };
  }
  const body: SyncAccountExactBootstrapBodyV1 = bodyBase;
  return { kind: 'ok', body };
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
