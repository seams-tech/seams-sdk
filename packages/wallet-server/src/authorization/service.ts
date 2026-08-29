import type { WalletAuthMethodId, WalletId } from '@shared/utils/domainIds';
import type { ActiveWalletAuthorityV1 } from '@shared/authorization/walletAuthority';
import type {
  ActiveWalletSessionQuota,
  AuthorizedOperation,
  AuthorizedOperationInput,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDeliveryV2,
  HostedWalletSeamsSessionExchangeNonce,
  IssuedHostedWalletSeamsSessionExchangeV2,
  PersistedHostedWalletSeamsSessionExchangeV2Result,
  RedeemHostedWalletSeamsSessionExchangeV2Input,
  RedeemHostedWalletSeamsSessionExchangeV2Result,
  ExactWalletSessionStatusV2,
  ResolvedHostedWalletSessionOperationCredentialV2,
  SessionOrigin,
  VerifiedAuthorizationEvidenceSet,
  IssuedWalletSessionAuthorizationV2,
  DirectV2CommitResult,
  DirectV2IssueResult,
  PersistedActiveWalletSessionAuthorizationV2,
  WalletSessionAuthorizationV2MintLookup,
  WalletSessionAuthorizationV2MintRead,
  WalletSessionIssuanceResponseFamilyV1,
  WalletSessionAuthorization,
  WalletSessionAuthorizationV2,
  VerifiedOwnerProof,
} from './domain';
import {
  buildActiveWalletSessionQuota,
  buildAuthorizedOperation,
  buildWalletSessionAuthorization,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  buildPersistedActiveWalletSessionAuthorizationV2,
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseHostedWalletSessionCredentialId,
  parseHostedWalletSessionOperationCredentialV1,
  parsePrimaryWalletSessionOperationCredentialToken,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from './domain';
import {
  parseHostedWalletSessionExchangeCodeId,
  parseWalletSessionAuthorizationId,
  parseEcdsaAuthorizationSessionId,
  type MpcWalletSigningQuotaId,
  type AuthorizedOperationId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { WalletSessionClientCapabilityV1 } from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  buildVerifiedWalletOperationFactorEvidenceSet,
  buildVerifiedOwnerProof,
  type VerifiedWalletOperationFactorEvidenceSetInput,
  type VerifiedOwnerProofInput,
} from './factorEvidence';
import type {
  CapabilityPolicyPort,
  AuthorizationEvidenceRequirementEvaluation,
  ParseAuthorizationEvidenceRequirementResult,
} from './capabilityPolicy';
import type { AuthorizationEvidenceRequirement } from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
import type { WalletSessionOperationCredentialV1 } from '@shared/device-linking/contracts';
import { parseWalletSessionOperationCredentialV1 } from '@shared/device-linking/parsers';
import type { RouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import type { RouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import { parseRouterAbEd25519NormalSigningState } from '@shared/utils/signingSessionSeal';
import { parseRouterAbEcdsaDerivationNormalSigningStateV1 } from '@shared/utils/routerAbEcdsaDerivation';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseWalletAuthAuthority,
  parseWalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type { ProviderSubject, WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import {
  parseProviderSubject,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import { normalizeRuntimePolicyScope } from '@shared/threshold/signingRootScope';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../core/ThresholdService/validation';
import type { CapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

export interface AuthorizationSessionPort {
  putIssuedHostedWalletSeamsSessionExchange(
    exchange: IssuedHostedWalletSeamsSessionExchangeV2,
  ): Promise<void>;
  redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeV2Input,
  ): Promise<PersistedHostedWalletSeamsSessionExchangeV2Result>;
  readHostedWalletSessionOperationCredentialV2(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly requestOrigin: SessionOrigin;
    readonly nowMs: number;
  }): Promise<ResolvedHostedWalletSessionOperationCredentialV2 | null>;
}

export interface AuthorizationEvidencePort {
  putVerifiedEvidenceSet(evidenceSet: VerifiedAuthorizationEvidenceSet): Promise<void>;
  consumeVerifiedOwnerProof(
    proof: VerifiedOwnerProof,
    consumedAtMs: number,
    consumptionScopeId: string,
  ): Promise<boolean>;
}

export interface AuthorizationGrantPort {
  revokeReusableWalletSessionsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void>;
  putWalletSessionAuthorization(input: {
    readonly session: WalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  readWalletSessionAuthorizationByMint(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletId: WalletId;
    readonly authority: WalletAuthAuthorityRef;
    readonly mintId: ReusableWalletSessionMintId;
    readonly nowMs: number;
  }): Promise<IssuedReusableWalletSession | null>;
  putWalletSessionAuthorizationV2(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  replaceWalletSessionAuthorizationV2AuthorityProjection(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ): Promise<WalletSessionAuthorizationV2MintRead | null>;
  commitDirectWalletSessionAuthorizationV2(input: {
    readonly persisted: PersistedActiveWalletSessionAuthorizationV2;
  }): Promise<DirectV2CommitResult>;
  readWalletSessionAuthorizationV2ByAuthorizationId(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  readWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletSessionId: WalletSessionId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  putWalletSessionAuthorizationV2OperationCredential(input: {
    readonly session: WalletSessionAuthorizationV2;
    readonly tokenHash: DigestB64u;
  }): Promise<void>;
  readWalletSessionAuthorizationV2ByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
  readExactWalletSessionStatusByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly nowMs: number;
  }): Promise<ExactWalletSessionStatusV2>;
  putOpaqueWalletSessionToken(input: {
    readonly tokenHash: DigestB64u;
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: OpaqueOwnerWalletSessionBinding;
    readonly tenantId: TenantId;
    readonly walletSessionId: WalletSessionId;
  }): Promise<void>;
  readOpaqueWalletSessionToken(input: {
    readonly tenantId: TenantId;
    readonly tokenHash: DigestB64u;
    readonly curve: OpaqueWalletSessionCurve;
    readonly nowMs: number;
  }): Promise<ResolvedOpaqueWalletSessionToken | null>;
}

export interface AuthorizedOperationPort {
  readAuthorizedOperationById(input: {
    readonly tenantId: TenantId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<AuthorizedOperation | null>;
  readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null>;
  admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: AuthorizedOperationMaterialScope;
  }): Promise<AuthorizedOperationAdmissionResult>;
  completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly response: AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation>;
}

export type AuthorizedOperationAdmissionResult =
  | { readonly kind: 'claimed'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'replayed'; readonly operation: AuthorizedOperation }
  | { readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }
  | {
      readonly kind:
        | 'authorization_grant_rejected'
        | 'verified_step_up_rejected'
        | 'wallet_session_quota_exhausted'
        | 'material_mismatch';
    };

export type EcdsaMaterialActivationScope = Readonly<{
  readonly walletId: WalletId;
  readonly keyHandle: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}>;

export type AuthorizedOperationMaterialScope = EcdsaMaterialActivationScope & {
  readonly kind?: 'ecdsa_material_activation';
};

export type AuthorizationServicePorts = {
  readonly policy: CapabilityPolicyPort;
  readonly sessions: AuthorizationSessionPort;
  readonly evidence: AuthorizationEvidencePort;
  readonly grants: AuthorizationGrantPort;
  readonly authorizedOperations: AuthorizedOperationPort;
  readonly audit: object;
};

export type IssueReusableWalletSessionInput = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly mintId: ReusableWalletSessionMintId;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type IssueWalletSessionAuthorizationV2Input = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: import('@shared/authorization/walletAuthority').ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly mintId: ReusableWalletSessionMintId;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type IssueDirectWalletSessionAuthorizationV2Input =
  IssueWalletSessionAuthorizationV2Input & {
    readonly walletSessionClientCapability: WalletSessionClientCapabilityV1;
    readonly responseFamily: WalletSessionIssuanceResponseFamilyV1;
  };

export type IssuedReusableWalletSession = {
  readonly session: WalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
};

type ReusableWalletSessionV2ProjectionInput = {
  readonly reusableWalletSession: IssuedReusableWalletSession;
  readonly authority: ActiveWalletAuthorityV1;
  readonly walletAuthMethodId: WalletAuthMethodId;
};

function projectReusableWalletSessionV2(
  input: ReusableWalletSessionV2ProjectionInput,
): IssuedWalletSessionAuthorizationV2 {
  const reusable = input.reusableWalletSession;
  if (
    reusable.session.walletId !== input.authority.walletId ||
    reusable.session.authority.walletId !== input.authority.walletId ||
    reusable.session.authority.walletAuthMethodId !== input.walletAuthMethodId
  ) {
    throw new Error('Reusable Wallet Session does not match the active V2 authority');
  }
  const session = buildWalletSessionAuthorizationV2({
    tenantId: reusable.session.tenantId,
    principalId: reusable.session.principalId,
    walletId: reusable.session.walletId,
    authorityId: input.authority.authorityId,
    walletAuthMethodId: input.walletAuthMethodId,
    authorityDigestB64u: input.authority.authorityDigestB64u,
    authorityRevocationEpoch: input.authority.revocationEpoch,
    mintId: reusable.session.mintId,
    authorizationId: reusable.session.authorizationId,
    walletSessionId: reusable.session.walletSessionId,
    quotaId: reusable.session.quotaId,
    capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
    createdAtMs: reusable.session.createdAtMs,
    expiresAtMs: reusable.session.expiresAtMs,
  });
  const quota = buildActiveWalletSessionQuota({
    tenantId: reusable.quota.tenantId,
    principalId: reusable.quota.principalId,
    walletSessionId: reusable.quota.walletSessionId,
    quotaId: reusable.quota.quotaId,
    remainingUses: reusable.quota.remainingUses,
    expiresAtMs: reusable.quota.expiresAtMs,
  });
  return { session, quota };
}

export type OpaqueWalletSessionCurve = 'ecdsa' | 'ed25519';

/** Trusted, curve-local data retained for an opaque owner Wallet Session. */
export type OpaqueOwnerWalletSessionBinding =
  | {
      readonly kind: 'opaque_owner_wallet_session_binding_v1';
      readonly curve: 'ed25519';
      readonly walletId: WalletId;
      readonly thresholdSessionId: string;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly relayerKeyId: string;
      readonly participantIds: readonly number[];
      readonly thresholdExpiresAtMs: number;
      readonly subjectId: string;
      readonly keyManifestDigestB64u: DigestB64u;
      readonly nearAccountId: string;
      readonly nearEd25519SigningKeyId: string;
      readonly authority: WalletAuthAuthority;
      readonly authorityScope: ThresholdEd25519AuthorityScope;
      readonly runtimePolicyScope: RuntimePolicyScope;
      readonly routerAbNormalSigning: RouterAbEd25519NormalSigningState;
    }
  | {
      readonly kind: 'opaque_owner_wallet_session_binding_v1';
      readonly curve: 'ecdsa';
      readonly walletId: WalletId;
      readonly thresholdSessionId: string;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly authorizationSessionId: string;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly relayerKeyId: string;
      readonly participantIds: readonly number[];
      readonly thresholdExpiresAtMs: number;
      readonly subjectId: string;
      readonly keyManifestDigestB64u: DigestB64u;
      readonly keyHandle: string;
      readonly walletAuthAuthorityRef: WalletAuthAuthorityRef;
      readonly authSource:
        | { readonly kind: 'passkey'; readonly credentialIdB64u: WebAuthnCredentialIdB64u }
        | {
            readonly kind: 'oidc_provider';
            readonly providerId: 'google_oidc' | 'oidc';
            readonly providerSubject: ProviderSubject;
          };
      readonly runtimePolicyScope?: RuntimePolicyScope;
      readonly routerAbEcdsaDerivationNormalSigning: RouterAbEcdsaDerivationNormalSigningStateV1;
    };

function opaqueBindingObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function opaqueBindingString(value: unknown): string | null {
  const text = typeof value === 'string' ? value.trim() : '';
  return text || null;
}

function parseOpaqueBindingBase(value: Record<string, unknown>): {
  walletId: WalletId;
  thresholdSessionId: string;
  authorizationId: WalletSessionAuthorizationId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  relayerKeyId: string;
  participantIds: readonly number[];
  thresholdExpiresAtMs: number;
  subjectId: string;
  keyManifestDigestB64u: DigestB64u;
} | null {
  const walletId = parseWalletId(value.walletId);
  const authorizationId = parseWalletSessionAuthorizationId(value.authorizationId);
  const walletSessionId = parseWalletSessionId(value.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaId(value.quotaId);
  const thresholdSessionId = opaqueBindingString(value.thresholdSessionId);
  const relayerKeyId = opaqueBindingString(value.relayerKeyId);
  const subjectId = opaqueBindingString(value.subjectId);
  const thresholdExpiresAtMs = value.thresholdExpiresAtMs;
  const participantIds = value.participantIds;
  const normalizedParticipantIds = normalizeThresholdEd25519ParticipantIds(participantIds);
  // The key manifest this session's key set was registered against. Owner
  // custody seals no manifest into the seed — each key set records its own at
  // registration — so the session claim is where a verified manifest becomes
  // addressable per curve.
  let keyManifestDigestB64u: DigestB64u;
  try {
    keyManifestDigestB64u = parseDigestB64u(value.keyManifestDigestB64u);
  } catch {
    return null;
  }
  if (
    !walletId.ok ||
    !authorizationId.ok ||
    !walletSessionId.ok ||
    !quotaId.ok ||
    !thresholdSessionId ||
    !relayerKeyId ||
    !subjectId ||
    typeof thresholdExpiresAtMs !== 'number' ||
    !Number.isSafeInteger(thresholdExpiresAtMs) ||
    thresholdExpiresAtMs <= 0 ||
    !Array.isArray(participantIds) ||
    !normalizedParticipantIds ||
    normalizedParticipantIds.length < 2 ||
    normalizedParticipantIds.length !== participantIds.length ||
    normalizedParticipantIds.some((id, index) => id !== participantIds[index])
  ) {
    return null;
  }
  return {
    walletId: walletId.value,
    thresholdSessionId,
    authorizationId: authorizationId.value,
    walletSessionId: walletSessionId.value,
    quotaId: quotaId.value,
    relayerKeyId,
    participantIds: normalizedParticipantIds,
    thresholdExpiresAtMs,
    subjectId,
    keyManifestDigestB64u,
  };
}

type OpaqueEcdsaAuthSource =
  | { readonly kind: 'passkey'; readonly credentialIdB64u: WebAuthnCredentialIdB64u }
  | {
      readonly kind: 'oidc_provider';
      readonly providerId: 'google_oidc' | 'oidc';
      readonly providerSubject: ProviderSubject;
    };

function parseOpaqueEcdsaAuthSource(value: unknown): OpaqueEcdsaAuthSource | null {
  const record = opaqueBindingObject(value);
  if (!record) return null;
  if (record.kind === 'passkey') {
    const credentialId = parseWebAuthnCredentialIdB64u(record.credentialIdB64u);
    return credentialId.ok ? { kind: 'passkey', credentialIdB64u: credentialId.value } : null;
  }
  if (
    record.kind !== 'oidc_provider' ||
    (record.providerId !== 'google_oidc' && record.providerId !== 'oidc')
  ) {
    return null;
  }
  const providerSubject = parseProviderSubject(record.providerSubject);
  return providerSubject.ok
    ? {
        kind: 'oidc_provider',
        providerId: record.providerId,
        providerSubject: providerSubject.value,
      }
    : null;
}

/** Converts persisted JSON into the only owner admission shape core code accepts. */
export function parseOpaqueOwnerWalletSessionBinding(
  value: unknown,
): OpaqueOwnerWalletSessionBinding | null {
  if (typeof value === 'string') {
    try {
      value = JSON.parse(value);
    } catch {
      return null;
    }
  }
  const record = opaqueBindingObject(value);
  if (!record || record.kind !== 'opaque_owner_wallet_session_binding_v1') {
    return null;
  }
  const base = parseOpaqueBindingBase(record);
  if (!base || (record.curve !== 'ed25519' && record.curve !== 'ecdsa')) return null;
  try {
    if (record.curve === 'ed25519') {
      const authority = parseWalletAuthAuthority(record.authority);
      const nearAccountId = opaqueBindingString(record.nearAccountId);
      const nearEd25519SigningKeyId = opaqueBindingString(record.nearEd25519SigningKeyId);
      const runtimePolicyScope = opaqueBindingObject(record.runtimePolicyScope);
      const routerAbNormalSigning = parseRouterAbEd25519NormalSigningState(
        record.routerAbNormalSigning,
      );
      if (
        !authority ||
        !nearAccountId ||
        !nearEd25519SigningKeyId ||
        !runtimePolicyScope ||
        !routerAbNormalSigning
      ) {
        return null;
      }
      return {
        kind: 'opaque_owner_wallet_session_binding_v1',
        curve: 'ed25519',
        ...base,
        nearAccountId,
        nearEd25519SigningKeyId,
        authority,
        authorityScope: thresholdEd25519AuthorityScopeFromWalletAuthAuthority(authority),
        runtimePolicyScope: normalizeRuntimePolicyScope(runtimePolicyScope),
        routerAbNormalSigning,
      };
    }
    const authorizationSessionIdRaw = opaqueBindingString(record.authorizationSessionId);
    const authorizationSessionId = authorizationSessionIdRaw
      ? parseEcdsaAuthorizationSessionId(authorizationSessionIdRaw)
      : null;
    const keyHandle = opaqueBindingString(record.keyHandle);
    const walletAuthAuthorityRef = parseWalletAuthAuthorityRef(record.walletAuthAuthorityRef);
    const authSource = parseOpaqueEcdsaAuthSource(record.authSource);
    const normalSigning = parseRouterAbEcdsaDerivationNormalSigningStateV1(
      record.routerAbEcdsaDerivationNormalSigning,
    );
    if (
      !authorizationSessionId?.ok ||
      !keyHandle ||
      !walletAuthAuthorityRef ||
      !authSource ||
      !normalSigning
    ) {
      return null;
    }
    const runtimePolicyScope =
      record.runtimePolicyScope === undefined
        ? undefined
        : normalizeRuntimePolicyScope(opaqueBindingObject(record.runtimePolicyScope) || {});
    return {
      kind: 'opaque_owner_wallet_session_binding_v1',
      curve: 'ecdsa',
      ...base,
      authorizationSessionId: authorizationSessionId.value,
      keyHandle,
      walletAuthAuthorityRef,
      authSource,
      ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
      routerAbEcdsaDerivationNormalSigning: normalSigning,
    };
  } catch {
    return null;
  }
}

export type IssuedOpaqueWalletSessionToken = {
  readonly kind: 'opaque_wallet_session_token';
  readonly token: string;
  readonly curve: OpaqueWalletSessionCurve;
  readonly expiresAtMs: number;
};

export type PreparedWalletSessionAuthorizationV2 = {
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
};

export type ResolvedOpaqueWalletSessionToken = {
  readonly kind: 'resolved_opaque_wallet_session_token';
  readonly curve: OpaqueWalletSessionCurve;
  readonly binding: OpaqueOwnerWalletSessionBinding;
  readonly authorization: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletId: WalletId;
    readonly authorityDigest: DigestB64u;
    /**
     * Which wallet auth method issued this session, when the row records one.
     *
     * Null for sessions minted before provenance was persisted: they are
     * unattributed and cannot be fenced by binding, so they run out on their
     * own clock instead. Everything minted since carries its issuer.
     */
    readonly walletAuthMethodId: WalletAuthMethodId | null;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly expiresAtMs: number;
  };
};

export class AuthorizationService {
  constructor(private readonly ports: AuthorizationServicePorts) {}

  async revokeReusableWalletSessionsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void> {
    await this.ports.grants.revokeReusableWalletSessionsForAuthMethod(input);
  }

  async mintHostedWalletSeamsSessionExchange(input: {
    readonly authorization: IssuedWalletSessionAuthorizationV2;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDeliveryV2> {
    const expiresAtMs = Math.min(
      input.expiresAtMs,
      input.authorization.session.expiresAtMs,
      input.authorization.quota.expiresAtMs,
    );
    if (
      !Number.isSafeInteger(input.issuedAtMs) ||
      input.issuedAtMs <= 0 ||
      !Number.isSafeInteger(expiresAtMs) ||
      expiresAtMs <= input.issuedAtMs
    ) {
      throw new Error('hosted-wallet Seams session exchange expiry must follow issuance');
    }
    const exchangeCode = parseHostedWalletSeamsSessionExchangeCode(
      secureRandomBase64Url(32, 'hosted-wallet Seams session exchange codes'),
    );
    const nonce = parseHostedWalletSeamsSessionExchangeNonce(
      secureRandomBase64Url(32, 'hosted-wallet Seams session exchange nonces'),
    );
    const exchangeCodeId = parseRequired(
      `hwx_${secureRandomBase64Url(18, 'hosted-wallet Seams session exchange identifiers')}`,
      parseHostedWalletSessionExchangeCodeId,
    );
    await this.ports.sessions.putIssuedHostedWalletSeamsSessionExchange({
      kind: 'issued_hosted_wallet_session_exchange_v2',
      tenantId: input.authorization.session.tenantId,
      exchangeCodeId,
      authorizationId: input.authorization.session.authorizationId,
      walletSessionId: input.authorization.session.walletSessionId,
      quotaId: input.authorization.session.quotaId,
      principalId: input.authorization.session.principalId,
      walletId: input.authorization.session.walletId,
      authorityId: input.authorization.session.authorityId,
      walletAuthMethodId: input.authorization.session.walletAuthMethodId,
      codeHash: await digestOpaqueValue(exchangeCode),
      nonceDigest: await digestOpaqueValue(nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs,
    });
    return {
      kind: 'hosted_wallet_session_exchange_delivery_v2',
      exchangeCode,
      nonce,
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      expiresAtMs,
    };
  }

  async redeemHostedWalletSeamsSessionExchange(input: {
    readonly exchangeCode: HostedWalletSeamsSessionExchangeCode;
    readonly nonce: HostedWalletSeamsSessionExchangeNonce;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeV2Result> {
    const hostedCredentialToken = `wsh_${secureRandomBase64Url(
      32,
      'hosted-wallet exchanged child credentials',
    )}`;
    const hostedCredentialId = parseHostedWalletSessionCredentialId(
      `hcr_${secureRandomBase64Url(18, 'hosted-wallet child credential identifiers')}`,
    );
    const persisted = await this.ports.sessions.redeemHostedWalletSeamsSessionExchange({
      codeHash: await digestOpaqueValue(input.exchangeCode),
      nonceDigest: await digestOpaqueValue(input.nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      tokenHash: await digestOpaqueValue(hostedCredentialToken),
      hostedCredentialId,
      redeemedAtMs: input.redeemedAtMs,
    });
    if (persisted.kind !== 'redeemed') return persisted;
    const operationCredential = parseHostedWalletSessionOperationCredentialV1({
      kind: 'opaque_hosted_wallet_session_operation_credential_v1',
      token: hostedCredentialToken,
      walletSessionId: persisted.walletSessionId,
    });
    return {
      kind: 'redeemed',
      walletSessionId: persisted.walletSessionId,
      operationCredential,
      expiresAtMs: persisted.expiresAtMs,
    };
  }

  async recordVerifiedWalletOperationFactorEvidenceSet(
    input: VerifiedWalletOperationFactorEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet> {
    const evidenceSet = await buildVerifiedWalletOperationFactorEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async buildVerifiedOwnerProof(input: VerifiedOwnerProofInput): Promise<VerifiedOwnerProof> {
    return await buildVerifiedOwnerProof(input);
  }

  async readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null> {
    return await this.ports.authorizedOperations.readAuthorizedOperation(input);
  }

  async readAuthorizedOperationById(input: {
    readonly tenantId: TenantId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<AuthorizedOperation | null> {
    return await this.ports.authorizedOperations.readAuthorizedOperationById(input);
  }

  async admitAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: AuthorizedOperationMaterialScope;
  }): Promise<AuthorizedOperationAdmissionResult> {
    return await this.ports.authorizedOperations.admitAuthorizedOperation(input);
  }

  async completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: CompletedCapabilityOperationResult;
    readonly response: AuthorizedOperationReplayResponse;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation> {
    return await this.ports.authorizedOperations.completeAuthorizedOperation(input);
  }

  async issueReusableWalletSession(
    input: IssueReusableWalletSessionInput,
  ): Promise<IssuedReusableWalletSession> {
    const authorizationId = parseRequired(
      await deriveReusableWalletSessionId(input, 'authorization'),
      parseWalletSessionAuthorizationId,
    );
    const walletSessionId = parseRequired(
      await deriveReusableWalletSessionId(input, 'wallet_session'),
      parseWalletSessionId,
    );
    const quotaId = parseRequired(
      await deriveReusableWalletSessionId(input, 'quota'),
      parseMpcWalletSigningQuotaId,
    );
    const session = buildWalletSessionAuthorization({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authority: input.authority,
      mintId: input.mintId,
      authorizationId,
      walletSessionId,
      quotaId,
      createdAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: session.expiresAtMs,
    });
    await this.ports.grants.putWalletSessionAuthorization({ session, quota });
    const persisted = await this.ports.grants.readWalletSessionAuthorizationByMint({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authority: input.authority,
      mintId: input.mintId,
      nowMs: input.issuedAtMs,
    });
    if (!persisted) throw new Error('Issued Wallet Session authorization was not persisted');
    return persisted;
  }

  async issueWalletSessionAuthorizationV2(
    input: IssueWalletSessionAuthorizationV2Input,
  ): Promise<IssuedWalletSessionAuthorizationV2> {
    const prepared = await this.prepareWalletSessionAuthorizationV2(input);
    await this.ports.grants.putWalletSessionAuthorizationV2(prepared);
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: prepared.session,
      nowMs: input.issuedAtMs,
    });
    if (!persisted) throw new Error('Issued V2 Wallet Session authorization was not persisted');
    if (persisted.quota.remainingUses !== prepared.quota.remainingUses) {
      throw new Error('V2 Wallet Session issuance replay does not match');
    }
    return persisted;
  }

  /**
   * Issues one exact Wallet Session and its primary credential in the same
   * persistence transition. The replay branch is credential-free because a
   * committed digest cannot reproduce plaintext.
   */
  async issueDirectWalletSessionAuthorizationV2(
    input: IssueDirectWalletSessionAuthorizationV2Input,
  ): Promise<DirectV2IssueResult> {
    if (input.authority.walletId !== input.walletId) {
      throw new Error('Wallet Session authorization authority does not identify the wallet');
    }
    const lookup: WalletSessionAuthorizationV2MintLookup = {
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authorityId: input.authority.authorityId,
      walletAuthMethodId: input.walletAuthMethodId,
      mintId: input.mintId,
    };
    const alreadyCommitted = await this.ports.grants.readWalletSessionAuthorizationV2ByMint(lookup);
    if (alreadyCommitted) return directV2ReplayResult(alreadyCommitted, input);

    const prepared = await this.prepareWalletSessionAuthorizationV2(input);
    const token = `wst_${secureRandomBase64Url(32, 'direct V2 Wallet Session operation credentials')}`;
    const operationCredential = parseWalletSessionOperationCredentialV1({
      kind: 'opaque_wallet_session_operation_credential_v1',
      token,
      walletSessionId: prepared.session.walletSessionId,
    });
    const persisted = buildPersistedActiveWalletSessionAuthorizationV2({
      session: prepared.session,
      quota: prepared.quota,
      primaryOperationCredentialDigestB64u: await digestOpaqueValue(token),
      walletSessionClientCapability: input.walletSessionClientCapability,
      responseFamily: input.responseFamily,
    });
    const commit = await this.ports.grants.commitDirectWalletSessionAuthorizationV2({ persisted });
    if (commit.kind === 'already_committed') {
      return directV2ReplayResult(commit.committed, input);
    }
    const committed = await this.ports.grants.readWalletSessionAuthorizationV2ByMint(lookup);
    if (!committed) {
      throw new Error('Direct V2 Wallet Session authorization was not persisted');
    }
    if (
      committed.primaryOperationCredentialDigestB64u !==
      persisted.primaryOperationCredentialDigestB64u
    ) {
      throw new Error('Direct V2 Wallet Session credential digest does not match its commit');
    }
    if (!directV2CommitMetadataMatches(committed, input)) {
      return directV2ProtocolMismatch();
    }
    return {
      kind: 'issued',
      session: prepared.session,
      quota: prepared.quota,
      operationCredential,
    };
  }

  /**
   * Issues the separately transported ordinary-operation bearer. The digest is
   * persisted against the exact V2 authorization row; the plaintext remains
   * in the activation/unlock response only.
   */
  async issueWalletSessionAuthorizationV2OperationCredential(input: {
    readonly session: WalletSessionAuthorizationV2;
  }): Promise<WalletSessionOperationCredentialV1> {
    const token = `wst_${secureRandomBase64Url(32, 'V2 Wallet Session operation credentials')}`;
    await this.ports.grants.putWalletSessionAuthorizationV2OperationCredential({
      session: input.session,
      tokenHash: await digestOpaqueValue(token),
    });
    return {
      kind: 'opaque_wallet_session_operation_credential_v1',
      token,
      walletSessionId: input.session.walletSessionId,
    };
  }

  /**
   * Persists the V2 authority projection for a registration session after its
   * founding authority is committed. The bearer session keeps its identity so
   * owner request authentication and the V2 source read observe one session.
   */
  async issueWalletSessionAuthorizationV2FromReusableSession(input: {
    readonly reusableWalletSession: IssuedReusableWalletSession;
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<IssuedWalletSessionAuthorizationV2> {
    const projected = projectReusableWalletSessionV2(input);
    await this.ports.grants.putWalletSessionAuthorizationV2(projected);
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: projected.session,
      nowMs: input.reusableWalletSession.session.createdAtMs,
    });
    if (!persisted) {
      throw new Error('Promoted V2 Wallet Session authorization was not persisted');
    }
    return persisted;
  }

  async refreshWalletSessionAuthorizationV2FromReusableSession(input: {
    readonly reusableWalletSession: IssuedReusableWalletSession;
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<IssuedWalletSessionAuthorizationV2> {
    const projected = projectReusableWalletSessionV2(input);
    await this.ports.grants.replaceWalletSessionAuthorizationV2AuthorityProjection(projected);
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: projected.session,
      nowMs: input.reusableWalletSession.session.createdAtMs,
    });
    if (!persisted) {
      throw new Error('Refreshed V2 Wallet Session authority projection was not persisted');
    }
    return persisted;
  }

  async refreshWalletSessionAuthorizationV2AuthorityProjection(input: {
    readonly existing: IssuedWalletSessionAuthorizationV2;
    readonly authority: ActiveWalletAuthorityV1;
    readonly walletAuthMethodId: WalletAuthMethodId;
  }): Promise<IssuedWalletSessionAuthorizationV2> {
    const current = input.existing.session;
    if (
      current.walletId !== input.authority.walletId ||
      current.authorityId !== input.authority.authorityId ||
      current.walletAuthMethodId !== input.walletAuthMethodId
    ) {
      throw new Error('Direct V2 Wallet Session authority projection identity does not match');
    }
    const session = buildWalletSessionAuthorizationV2({
      tenantId: current.tenantId,
      principalId: current.principalId,
      walletId: current.walletId,
      authorityId: current.authorityId,
      walletAuthMethodId: current.walletAuthMethodId,
      authorityDigestB64u: input.authority.authorityDigestB64u,
      authorityRevocationEpoch: input.authority.revocationEpoch,
      mintId: current.mintId,
      authorizationId: current.authorizationId,
      walletSessionId: current.walletSessionId,
      quotaId: current.quotaId,
      capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
      createdAtMs: current.createdAtMs,
      expiresAtMs: current.expiresAtMs,
    });
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: current,
      nowMs: Date.now(),
    });
    if (!persisted) {
      throw new Error('Direct V2 Wallet Session authority projection is unavailable');
    }
    await this.ports.grants.replaceWalletSessionAuthorizationV2AuthorityProjection({
      session,
      quota: persisted.quota,
    });
    const refreshed = await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId({
      expected: session,
      nowMs: Date.now(),
    });
    if (!refreshed) {
      throw new Error('Direct V2 Wallet Session authority projection was not refreshed');
    }
    return refreshed;
  }

  async prepareWalletSessionAuthorizationV2(
    input: IssueWalletSessionAuthorizationV2Input,
  ): Promise<PreparedWalletSessionAuthorizationV2> {
    if (input.authority.walletId !== input.walletId) {
      throw new Error('Wallet Session authorization authority does not identify the wallet');
    }
    const authorizationId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'authorization'),
      parseWalletSessionAuthorizationId,
    );
    const walletSessionId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'wallet_session'),
      parseWalletSessionId,
    );
    const quotaId = parseRequired(
      await deriveWalletSessionAuthorizationV2Id(input, 'quota'),
      parseMpcWalletSigningQuotaId,
    );
    const session = buildWalletSessionAuthorizationV2({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authorityId: input.authority.authorityId,
      walletAuthMethodId: input.walletAuthMethodId,
      authorityDigestB64u: input.authority.authorityDigestB64u,
      authorityRevocationEpoch: input.authority.revocationEpoch,
      mintId: input.mintId,
      authorizationId,
      walletSessionId,
      quotaId,
      capabilitySubjects: buildWalletSessionCapabilitySubjectsV1(input.authority),
      createdAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletSessionId,
      quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: session.expiresAtMs,
    });
    return { session, quota };
  }

  async readWalletSessionAuthorizationV2ByMint(
    input: WalletSessionAuthorizationV2MintLookup,
  ): Promise<WalletSessionAuthorizationV2MintRead | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByMint(input);
  }

  async readWalletSessionAuthorizationV2ByAuthorizationId(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByAuthorizationId(input);
  }

  async readWalletSessionAuthorizationV2ByIdentity(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletSessionId: WalletSessionId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByIdentity(input);
  }

  async readWalletSessionAuthorizationV2ByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
    return await this.ports.grants.readWalletSessionAuthorizationV2ByOperationCredential({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(input.token),
      nowMs: input.nowMs,
    });
  }

  /**
   * Resolves the exact `/wallet/session/status` lifecycle. A credential from
   * another family never reaches persistence: only the primary `wst_` token
   * names a V2 authorization, so anything else is absent by construction.
   */
  async readExactWalletSessionStatusByOperationCredential(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly nowMs: number;
  }): Promise<ExactWalletSessionStatusV2> {
    let token: ReturnType<typeof parsePrimaryWalletSessionOperationCredentialToken>;
    try {
      token = parsePrimaryWalletSessionOperationCredentialToken(input.token);
    } catch {
      return { kind: 'missing' };
    }
    return await this.ports.grants.readExactWalletSessionStatusByOperationCredential({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(token),
      nowMs: input.nowMs,
    });
  }

  async readHostedWalletSessionOperationCredentialV2(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly requestOrigin: SessionOrigin;
    readonly nowMs: number;
  }): Promise<ResolvedHostedWalletSessionOperationCredentialV2 | null> {
    if (!/^wsh_[A-Za-z0-9_-]{43}$/.test(input.token)) return null;
    return await this.ports.sessions.readHostedWalletSessionOperationCredentialV2({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(input.token),
      requestOrigin: input.requestOrigin,
      nowMs: input.nowMs,
    });
  }

  async issueOpaqueWalletSessionToken(input: {
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly tenantId: TenantId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly expiresAtMs: number;
    readonly consumedAtMs: number;
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: OpaqueOwnerWalletSessionBinding;
  }): Promise<IssuedOpaqueWalletSessionToken> {
    if (input.proof.tenantId !== input.tenantId) {
      throw new Error('owner proof does not match the opaque Wallet Session tenant');
    }
    if (
      input.binding.curve !== input.curve ||
      input.binding.authorizationId !== input.authorizationId ||
      input.binding.walletSessionId !== input.walletSessionId ||
      input.binding.quotaId !== input.quotaId ||
      input.binding.thresholdExpiresAtMs !== input.expiresAtMs
    ) {
      throw new Error('opaque Wallet Session binding does not match its authorization');
    }
    const consumedAtMs = requirePositiveTimestamp(
      input.consumedAtMs,
      'owner proof consumption time',
    );
    if (
      input.proof.verifiedAtMs > consumedAtMs ||
      input.proof.expiresAtMs <= consumedAtMs ||
      input.expiresAtMs <= consumedAtMs
    ) {
      throw new Error('owner proof or Wallet Session expiry is invalid');
    }
    const bindingJson = JSON.stringify(input.binding);
    if (!bindingJson || bindingJson === '{}') {
      throw new Error('opaque Wallet Session binding is required');
    }
    const consumed = await this.ports.evidence.consumeVerifiedOwnerProof(
      input.proof,
      consumedAtMs,
      String(input.walletSessionId),
    );
    if (!consumed) throw new Error('owner proof has already been consumed');
    const token = `wst_${secureRandomBase64Url(32, 'opaque Wallet Session tokens')}`;
    await this.ports.grants.putOpaqueWalletSessionToken({
      tokenHash: await digestOpaqueValue(token),
      curve: input.curve,
      binding: input.binding,
      tenantId: input.tenantId,
      walletSessionId: input.walletSessionId,
    });
    return {
      kind: 'opaque_wallet_session_token',
      token,
      curve: input.curve,
      expiresAtMs: input.expiresAtMs,
    };
  }

  async resolveOpaqueWalletSessionToken(input: {
    readonly tenantId: TenantId;
    readonly token: string;
    readonly curve: OpaqueWalletSessionCurve;
    readonly nowMs: number;
  }): Promise<ResolvedOpaqueWalletSessionToken | null> {
    return await this.ports.grants.readOpaqueWalletSessionToken({
      tenantId: input.tenantId,
      tokenHash: await digestOpaqueValue(input.token),
      curve: input.curve,
      nowMs: input.nowMs,
    });
  }

  async readWalletSessionAuthorizationByMint(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletId: WalletId;
    readonly authority: WalletAuthAuthorityRef;
    readonly mintId: ReusableWalletSessionMintId;
    readonly nowMs: number;
  }): Promise<IssuedReusableWalletSession | null> {
    return await this.ports.grants.readWalletSessionAuthorizationByMint(input);
  }

  parseEvidenceRequirement(value: unknown): ParseAuthorizationEvidenceRequirementResult {
    return this.ports.policy.parseEvidenceRequirement(value);
  }

  evaluateEvidenceRequirement(
    requirement: AuthorizationEvidenceRequirement,
    evidenceSet: VerifiedAuthorizationEvidenceSet,
  ): AuthorizationEvidenceRequirementEvaluation {
    return this.ports.policy.evaluateEvidenceRequirement(requirement, evidenceSet);
  }
}

async function deriveReusableWalletSessionId(
  input: IssueReusableWalletSessionInput,
  kind: 'authorization' | 'wallet_session' | 'quota',
): Promise<string> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(
      [
        'seams:reusable-wallet-session-issuance:v1',
        kind,
        input.tenantId,
        input.principalId,
        input.walletId,
        input.authority.authorityDigest,
        input.mintId,
      ].join('\0'),
    ),
  );
  const prefix = kind === 'authorization' ? 'wlt' : kind === 'wallet_session' ? 'wls' : 'wsq';
  return `${prefix}_${digest}`;
}

async function deriveWalletSessionAuthorizationV2Id(
  input: IssueWalletSessionAuthorizationV2Input,
  kind: 'authorization' | 'wallet_session' | 'quota',
): Promise<string> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(
      [
        'seams:wallet-session-authorization-v2-issuance:v1',
        kind,
        input.tenantId,
        input.principalId,
        input.walletId,
        input.authority.authorityId,
        input.walletAuthMethodId,
        input.authority.authorityDigestB64u,
        String(input.authority.revocationEpoch),
        input.mintId,
      ].join('\0'),
    ),
  );
  const prefix = kind === 'authorization' ? 'wlt' : kind === 'wallet_session' ? 'wls' : 'wsq';
  return `${prefix}_${digest}`;
}

export async function digestOpaqueValue(value: string) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(value)));
}

function directV2AlreadyCommitted(
  session: WalletSessionAuthorizationV2,
): Extract<DirectV2IssueResult, { readonly kind: 'already_committed' }> {
  return {
    kind: 'already_committed',
    walletId: session.walletId,
    authorityId: session.authorityId,
    walletAuthMethodId: session.walletAuthMethodId,
    mintId: session.mintId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    next: 'unlock_exact_method',
  };
}

function directV2CommitMetadataMatches(
  committed: WalletSessionAuthorizationV2MintRead,
  expected: Pick<
    IssueDirectWalletSessionAuthorizationV2Input,
    'walletSessionClientCapability' | 'responseFamily'
  >,
): boolean {
  return (
    committed.walletSessionClientCapability === expected.walletSessionClientCapability &&
    committed.responseFamily === expected.responseFamily
  );
}

function directV2ProtocolMismatch(): Extract<
  DirectV2IssueResult,
  { readonly kind: 'protocol_mismatch' }
> {
  return {
    kind: 'protocol_mismatch',
    code: 'protocol_mismatch',
    message: 'Wallet Session unlock protocol does not match the committed issuance',
  };
}

function directV2ReplayResult(
  committed: WalletSessionAuthorizationV2MintRead,
  expected: Pick<
    IssueDirectWalletSessionAuthorizationV2Input,
    'walletSessionClientCapability' | 'responseFamily'
  >,
): DirectV2IssueResult {
  if (!directV2CommitMetadataMatches(committed, expected)) {
    return directV2ProtocolMismatch();
  }
  return directV2AlreadyCommitted(committed.session);
}

function parseRequired<T>(
  value: unknown,
  parser: (raw: unknown) => { readonly ok: true; readonly value: T } | { readonly ok: false },
): T {
  const parsed = parser(value);
  if (!parsed.ok) throw new Error('generated authorization identifier was invalid');
  return parsed.value;
}

function requirePositiveTimestamp(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be positive`);
  return value;
}
