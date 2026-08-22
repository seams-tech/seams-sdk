import type { WalletAuthMethodId } from '@shared/utils/domainIds';
import type {
  ActiveWalletSessionQuota,
  AuthorizedOperation,
  AuthorizedOperationInput,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDelivery,
  HostedWalletSeamsSessionExchangeNonce,
  IssuedHostedWalletSeamsSessionExchange,
  PersistedHostedWalletSeamsSessionExchangeResult,
  RedeemHostedWalletSeamsSessionExchangeInput,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  LinkedDeviceWalletSessionAuthorization,
  LinkedDeviceWalletSessionStatus,
  SessionOrigin,
  VerifiedAuthorizationEvidenceSet,
  IssuedWalletSessionAuthorizationV2,
  WalletSessionAuthorization,
  WalletSessionAuthorizationV2,
  VerifiedOwnerProof,
} from './domain';
import {
  buildActiveWalletSessionQuota,
  buildAuthorizedOperation,
  buildLinkedDevicePrincipalId,
  buildLinkedDeviceWalletSessionAuthorization,
  buildWalletSessionAuthorization,
  buildWalletSessionAuthorizationV2,
  buildWalletSessionCapabilitySubjectsV1,
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from './domain';
import {
  buildLinkedDeviceWalletSessionAuthorizationRef,
  parseHostedWalletSessionExchangeCodeId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseWalletSessionAuthorizationId,
  parseEcdsaAuthorizationSessionId,
  type MpcWalletSigningQuotaId,
  type AuthorizedOperationId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
  type EcdsaAuthorizationSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import { delegatedWalletPermissionNamesV1 } from '@shared/authorization/delegatedAuthority';
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
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  WalletId,
  WalletKeyId,
} from '@shared/utils/domainIds';
import type { LaneShareEpoch, SigningLaneId } from '@shared/signing-lanes';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { ThresholdEd25519AuthorityScope } from '../core/types';
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
import {
  isLinkedDeviceWalletSessionRenewalCapabilityV1,
  type LinkedDeviceWalletSessionRenewalCapabilityV1,
} from '../router/domains/signingOperations/walletExecutionAdmission';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';

export interface AuthorizationSessionPort {
  readReusableWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<ReusableWalletSessionStatus>;
  putIssuedHostedWalletSeamsSessionExchange(
    exchange: IssuedHostedWalletSeamsSessionExchange,
  ): Promise<void>;
  redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeInput,
  ): Promise<PersistedHostedWalletSeamsSessionExchangeResult>;
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
  readWalletSessionAuthorizationV2ByMint(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null>;
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
  putLinkedDeviceWalletSessionAuthorization(input: {
    readonly authorization: LinkedDeviceWalletSessionAuthorization;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  readLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<IssuedLinkedDeviceWalletSession | null>;
  readClaimedLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionAuthorization | null>;
  getLinkedDeviceWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionStatus>;
  renewLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly deviceId: LinkedDeviceId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly revocationEpoch: number;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
    readonly remainingUses: number;
  }): Promise<void>;
  revokeLinkedDeviceWalletSession(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<void>;
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

export type LinkedDeviceMaterialActivationScopeV1 = Readonly<{
  readonly kind: 'linked_device_lane';
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly revocationEpoch: number;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}>;

export type AuthorizedOperationMaterialScope =
  | (EcdsaMaterialActivationScope & { readonly kind?: 'ecdsa_material_activation' })
  | LinkedDeviceMaterialActivationScopeV1;

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

export type IssuedReusableWalletSession = {
  readonly session: WalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
};

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

export type IssuedLinkedDeviceWalletSession = {
  readonly authorization: LinkedDeviceWalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
};

export type IssueLinkedDeviceWalletSessionInput = {
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly permission: LinkedDeviceWalletSessionAuthorization['permission'];
  readonly revocationEpoch: number;
  readonly remainingUses: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceWalletSessionIdentityV1 = {
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type RenewLinkedDeviceWalletSessionInputV1 = {
  readonly renewedAtMs: number;
  readonly renewal: LinkedDeviceWalletSessionRenewalCapabilityV1;
};

export class AuthorizationService {
  constructor(private readonly ports: AuthorizationServicePorts) {}

  async readReusableWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<ReusableWalletSessionStatus> {
    return await this.ports.sessions.readReusableWalletSessionStatus(input);
  }

  async revokeReusableWalletSessionsForAuthMethod(input: {
    readonly tenantId: TenantId;
    readonly walletId: WalletId;
    readonly walletAuthMethodId: WalletAuthMethodId;
    readonly nowMs: number;
  }): Promise<void> {
    await this.ports.grants.revokeReusableWalletSessionsForAuthMethod(input);
  }

  async mintHostedWalletSeamsSessionExchange(input: {
    readonly tenantId: TenantId;
    readonly walletSessionId: WalletSessionId;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: Readonly<Record<string, unknown>>;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDelivery> {
    if (!Number.isSafeInteger(input.issuedAtMs) || input.expiresAtMs <= input.issuedAtMs) {
      throw new Error('hosted-wallet Seams session exchange expiry must follow issuance');
    }
    const bindingJson = JSON.stringify(input.binding);
    if (!bindingJson || bindingJson === '{}') {
      throw new Error('hosted-wallet exchange binding is required');
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
      kind: 'issued_hosted_wallet_session_exchange',
      tenantId: input.tenantId,
      exchangeCodeId,
      walletSessionId: input.walletSessionId,
      codeHash: await digestOpaqueValue(exchangeCode),
      nonceDigest: await digestOpaqueValue(nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      curve: input.curve,
      bindingJson,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    return {
      kind: 'hosted_wallet_session_exchange_delivery',
      exchangeCode,
      nonce,
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      expiresAtMs: input.expiresAtMs,
    };
  }

  async redeemHostedWalletSeamsSessionExchange(input: {
    readonly exchangeCode: HostedWalletSeamsSessionExchangeCode;
    readonly nonce: HostedWalletSeamsSessionExchangeNonce;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly curve: OpaqueWalletSessionCurve;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeResult> {
    const walletSessionToken = `wst_${secureRandomBase64Url(
      32,
      'hosted-wallet exchanged Wallet Session tokens',
    )}`;
    const persisted = await this.ports.sessions.redeemHostedWalletSeamsSessionExchange({
      codeHash: await digestOpaqueValue(input.exchangeCode),
      nonceDigest: await digestOpaqueValue(input.nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      tokenHash: await digestOpaqueValue(walletSessionToken),
      curve: input.curve,
      redeemedAtMs: input.redeemedAtMs,
    });
    if (persisted.kind !== 'redeemed') return persisted;
    return {
      kind: 'redeemed',
      walletSessionId: persisted.walletSessionId,
      walletSessionToken,
      curve: persisted.curve,
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
    await this.ports.grants.putWalletSessionAuthorizationV2({ session, quota });
    const persisted = await this.ports.grants.readWalletSessionAuthorizationV2ByMint({
      expected: session,
      nowMs: input.issuedAtMs,
    });
    if (!persisted) throw new Error('Issued V2 Wallet Session authorization was not persisted');
    return persisted;
  }

  async readWalletSessionAuthorizationV2ByMint(input: {
    readonly expected: WalletSessionAuthorizationV2;
    readonly nowMs: number;
  }): Promise<IssuedWalletSessionAuthorizationV2 | null> {
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

  async issueLinkedDeviceWalletSession(
    input: IssueLinkedDeviceWalletSessionInput,
  ): Promise<IssuedLinkedDeviceWalletSession> {
    const { authorizationId, walletSessionId, quotaId } =
      await deriveLinkedDeviceWalletSessionIdentityV1(input);
    const authorization = buildLinkedDeviceWalletSessionAuthorization({
      tenantId: input.tenantId,
      authorizationGrantRef: buildLinkedDeviceWalletSessionAuthorizationRef(authorizationId),
      walletId: input.walletId,
      enrollmentId: input.enrollmentId,
      deviceId: input.deviceId,
      walletSessionId,
      quotaId,
      keyManifestDigestB64u: input.keyManifestDigestB64u,
      permission: input.permission,
      revocationEpoch: input.revocationEpoch,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs: input.expiresAtMs,
    });
    const quota = buildActiveWalletSessionQuota({
      tenantId: authorization.tenantId,
      principalId: authorization.principalId,
      walletSessionId: authorization.walletSessionId,
      quotaId: authorization.quotaId,
      remainingUses: input.remainingUses,
      expiresAtMs: authorization.expiresAtMs,
    });
    await this.ports.grants.putLinkedDeviceWalletSessionAuthorization({
      authorization,
      quota,
    });
    const persisted = await this.ports.grants.readLinkedDeviceWalletSessionAuthorization({
      tenantId: authorization.tenantId,
      deviceId: authorization.deviceId,
      authorizationId: authorization.authorizationGrantRef.authorizationId,
      walletSessionId: authorization.walletSessionId,
      quotaId: authorization.quotaId,
      nowMs: input.issuedAtMs,
    });
    if (!persisted) {
      throw new Error('linked-device Wallet Session authorization was not persisted');
    }
    return persisted;
  }

  async getLinkedDeviceWalletSessionStatus(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<LinkedDeviceWalletSessionStatus> {
    const principalId = buildLinkedDevicePrincipalId(input.deviceId);
    return await this.ports.grants.getLinkedDeviceWalletSessionStatus({
      ...input,
      principalId,
    });
  }

  async readLinkedDeviceWalletSessionAuthorization(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<IssuedLinkedDeviceWalletSession | null> {
    return await this.ports.grants.readLinkedDeviceWalletSessionAuthorization(input);
  }

  async renewLinkedDeviceWalletSession(
    input: RenewLinkedDeviceWalletSessionInputV1,
  ): Promise<IssuedLinkedDeviceWalletSession> {
    if (!isLinkedDeviceWalletSessionRenewalCapabilityV1(input.renewal)) {
      throw new Error('linked-device Wallet Session renewal capability is invalid');
    }
    const renewal = input.renewal;
    if (renewal.revocationEpoch < 0 || !Number.isSafeInteger(renewal.revocationEpoch)) {
      throw new Error('linked-device Wallet Session renewal epoch is invalid');
    }
    if (
      !Number.isSafeInteger(input.renewedAtMs) ||
      input.renewedAtMs <= 0 ||
      !Number.isSafeInteger(renewal.verifiedAtMs) ||
      renewal.verifiedAtMs > input.renewedAtMs
    ) {
      throw new Error('linked-device Wallet Session renewal time is invalid');
    }
    const expiresAtMs = input.renewedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= input.renewedAtMs) {
      throw new Error('linked-device Wallet Session renewal expiry is invalid');
    }
    const principalId = buildLinkedDevicePrincipalId(renewal.deviceId);
    await this.ports.grants.renewLinkedDeviceWalletSessionAuthorization({
      tenantId: renewal.tenantId,
      principalId,
      deviceId: renewal.deviceId,
      enrollmentId: renewal.enrollmentId,
      authorizationId: renewal.authorizationId,
      walletSessionId: renewal.walletSessionId,
      quotaId: renewal.quotaId,
      revocationEpoch: renewal.revocationEpoch,
      issuedAtMs: input.renewedAtMs,
      expiresAtMs,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    });
    const persisted = await this.readLinkedDeviceWalletSessionAuthorization({
      tenantId: renewal.tenantId,
      deviceId: renewal.deviceId,
      authorizationId: renewal.authorizationId,
      walletSessionId: renewal.walletSessionId,
      quotaId: renewal.quotaId,
      nowMs: input.renewedAtMs,
    });
    if (!persisted) {
      throw new Error('linked-device Wallet Session renewal was not persisted');
    }
    return persisted;
  }

  async revokeLinkedDeviceWalletSession(input: {
    readonly tenantId: TenantId;
    readonly deviceId: LinkedDeviceId;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly nowMs: number;
  }): Promise<void> {
    const principalId = buildLinkedDevicePrincipalId(input.deviceId);
    await this.ports.grants.revokeLinkedDeviceWalletSession({
      ...input,
      principalId,
    });
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

export async function deriveLinkedDeviceWalletSessionIdentityV1(
  input: IssueLinkedDeviceWalletSessionInput,
): Promise<LinkedDeviceWalletSessionIdentityV1> {
  return {
    authorizationId: parseRequired(
      await deriveLinkedDeviceWalletSessionId(input, 'authorization'),
      parseLinkedDeviceWalletSessionAuthorizationId,
    ),
    walletSessionId: parseRequired(
      await deriveLinkedDeviceWalletSessionId(input, 'wallet_session'),
      parseWalletSessionId,
    ),
    quotaId: parseRequired(
      await deriveLinkedDeviceWalletSessionId(input, 'quota'),
      parseMpcWalletSigningQuotaId,
    ),
  };
}

async function deriveLinkedDeviceWalletSessionId(
  input: IssueLinkedDeviceWalletSessionInput,
  kind: 'authorization' | 'wallet_session' | 'quota',
): Promise<string> {
  const digest = base64UrlEncode(
    await sha256BytesUtf8(
      [
        'seams:linked-device-wallet-session-issuance:v1',
        kind,
        input.tenantId,
        input.walletId,
        input.enrollmentId,
        input.deviceId,
        input.keyManifestDigestB64u,
        String(input.revocationEpoch),
        delegatedWalletPermissionNamesV1(input.permission).join(','),
        String(input.remainingUses),
        String(input.issuedAtMs),
        String(input.expiresAtMs),
      ].join('\0'),
    ),
  );
  const prefix = kind === 'authorization' ? 'lda' : kind === 'wallet_session' ? 'ldw' : 'ldq';
  return `${prefix}_${digest}`;
}

async function digestOpaqueValue(value: string) {
  return parseDigestB64u(base64UrlEncode(await sha256BytesUtf8(value)));
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
