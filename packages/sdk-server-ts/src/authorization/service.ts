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
  WalletSessionAuthorization,
  VerifiedOwnerProof,
} from './domain';
import {
  buildActiveWalletSessionQuota,
  buildAuthorizedOperation,
  buildLinkedDevicePrincipalId,
  buildLinkedDeviceWalletSessionAuthorization,
  buildWalletSessionAuthorization,
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
  type MpcWalletSigningQuotaId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
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
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  WalletId,
  WalletKeyId,
} from '@shared/utils/domainIds';
import type { LaneShareEpoch, SigningLaneId } from '@shared/signing-lanes';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';
import type { CapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import {
  isLinkedDeviceWalletSessionRenewalCapabilityV1,
  type LinkedDeviceWalletSessionRenewalCapabilityV1,
} from '../router/domains/signingOperations/walletExecutionAdmission';
import {
  computeLinkedDeviceWalletSessionRenewalIntentDigestV1,
  linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1,
} from '@shared/device-linking/digests';
import {
  DEFAULT_WALLET_SESSION_REMAINING_USES,
  DEFAULT_WALLET_SESSION_TTL_MS,
} from '@shared/threshold/sessionPolicy';

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
  putOpaqueWalletSessionToken(input: {
    readonly tokenHash: DigestB64u;
    readonly curve: OpaqueWalletSessionCurve;
    readonly bindingJson: string;
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

export type IssuedReusableWalletSession = {
  readonly session: WalletSessionAuthorization;
  readonly quota: ActiveWalletSessionQuota;
};

export type OpaqueWalletSessionCurve = 'ecdsa' | 'ed25519';

export type IssuedOpaqueWalletSessionToken = {
  readonly kind: 'opaque_wallet_session_token';
  readonly token: string;
  readonly curve: OpaqueWalletSessionCurve;
  readonly expiresAtMs: number;
};

export type ResolvedOpaqueWalletSessionToken = {
  readonly kind: 'resolved_opaque_wallet_session_token';
  readonly curve: OpaqueWalletSessionCurve;
  readonly binding: unknown;
  readonly authorization: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletId: WalletId;
    readonly authorityDigest: DigestB64u;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly expiresAtMs: number;
  };
  readonly quota: ActiveWalletSessionQuota;
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
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly revocationEpoch: number;
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

  async mintHostedWalletSeamsSessionExchange(input: {
    readonly tenantId: TenantId;
    readonly walletSessionId: WalletSessionId;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDelivery> {
    if (!Number.isSafeInteger(input.issuedAtMs) || input.expiresAtMs <= input.issuedAtMs) {
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
      kind: 'issued_hosted_wallet_session_exchange',
      tenantId: input.tenantId,
      exchangeCodeId,
      walletSessionId: input.walletSessionId,
      codeHash: await digestOpaqueValue(exchangeCode),
      nonceDigest: await digestOpaqueValue(nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
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
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: Readonly<Record<string, unknown>>;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeResult> {
    const bindingJson = JSON.stringify(input.binding);
    if (!bindingJson || bindingJson === '{}') {
      throw new Error('hosted-wallet exchange binding is required');
    }
    const walletSessionToken = `wst_${secureRandomBase64Url(
      32,
      'hosted-wallet exchanged Wallet Session tokens',
    )}`;
    const persisted = await this.ports.sessions.redeemHostedWalletSeamsSessionExchange({
      codeHash: await digestOpaqueValue(input.exchangeCode),
      nonceDigest: await digestOpaqueValue(input.nonce),
      appOrigin: input.appOrigin,
      tokenHash: await digestOpaqueValue(walletSessionToken),
      curve: input.curve,
      bindingJson,
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
    switch (input.purpose) {
      case 'wallet_session':
        return await buildVerifiedOwnerProof(input);
      case 'operation':
        return await buildVerifiedOwnerProof(input);
    }
  }

  async readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null> {
    return await this.ports.authorizedOperations.readAuthorizedOperation(input);
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

  async issueOpaqueWalletSessionToken(input: {
    readonly proof: Extract<VerifiedOwnerProof, { readonly purpose: 'wallet_session' }>;
    readonly tenantId: TenantId;
    readonly authorizationId: WalletSessionAuthorizationId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly expiresAtMs: number;
    readonly consumedAtMs: number;
    readonly curve: OpaqueWalletSessionCurve;
    readonly binding: Readonly<Record<string, unknown>>;
  }): Promise<IssuedOpaqueWalletSessionToken> {
    if (input.proof.tenantId !== input.tenantId) {
      throw new Error('owner proof does not match the opaque Wallet Session tenant');
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
      bindingJson,
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
    if (
      renewal.tenantId !== input.tenantId ||
      renewal.deviceId !== input.deviceId ||
      renewal.enrollmentId !== input.enrollmentId ||
      renewal.authorizationId !== input.authorizationId ||
      renewal.walletSessionId !== input.walletSessionId ||
      renewal.quotaId !== input.quotaId ||
      renewal.revocationEpoch < 0 ||
      !Number.isSafeInteger(renewal.revocationEpoch)
    ) {
      throw new Error('linked-device Wallet Session renewal capability binding differs');
    }
    const expectedIntentDigest = await computeLinkedDeviceWalletSessionRenewalIntentDigestV1({
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      deviceId: input.deviceId,
      enrollmentId: input.enrollmentId,
    });
    if (
      renewal.authorizedOperationId !== linkedDeviceWalletSessionRenewalAuthorizedOperationIdV1() ||
      renewal.intentDigestB64u !== expectedIntentDigest
    ) {
      throw new Error('linked-device Wallet Session renewal intent differs');
    }
    if (
      !Number.isSafeInteger(input.renewedAtMs) ||
      input.renewedAtMs <= 0 ||
      !Number.isSafeInteger(renewal.verifiedAtMs) ||
      renewal.verifiedAtMs > input.renewedAtMs
    ) {
      throw new Error('linked-device Wallet Session renewal time is invalid');
    }
    const status = await this.getLinkedDeviceWalletSessionStatus({
      tenantId: input.tenantId,
      deviceId: input.deviceId,
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      nowMs: input.renewedAtMs,
    });
    switch (status.kind) {
      case 'active':
      case 'exhausted':
      case 'expired':
        if (
          status.deviceId !== input.deviceId ||
          status.enrollmentId !== input.enrollmentId ||
          status.authorizationId !== input.authorizationId ||
          status.walletSessionId !== input.walletSessionId ||
          status.quotaId !== input.quotaId ||
          status.revocationEpoch !== renewal.revocationEpoch
        ) {
          throw new Error('linked-device Wallet Session renewal status binding differs');
        }
        break;
      case 'missing':
      case 'invalid':
        throw new Error('linked-device Wallet Session authorization is unavailable');
      case 'revoked':
        throw new Error('linked-device Wallet Session authorization is revoked');
      default:
        return assertNeverLinkedDeviceWalletSessionStatus(status);
    }
    const expiresAtMs = input.renewedAtMs + DEFAULT_WALLET_SESSION_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= input.renewedAtMs) {
      throw new Error('linked-device Wallet Session renewal expiry is invalid');
    }
    const principalId = buildLinkedDevicePrincipalId(input.deviceId);
    await this.ports.grants.renewLinkedDeviceWalletSessionAuthorization({
      tenantId: input.tenantId,
      principalId,
      deviceId: input.deviceId,
      enrollmentId: input.enrollmentId,
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      revocationEpoch: renewal.revocationEpoch,
      issuedAtMs: input.renewedAtMs,
      expiresAtMs,
      remainingUses: DEFAULT_WALLET_SESSION_REMAINING_USES,
    });
    const persisted = await this.readLinkedDeviceWalletSessionAuthorization({
      tenantId: input.tenantId,
      deviceId: input.deviceId,
      authorizationId: input.authorizationId,
      walletSessionId: input.walletSessionId,
      quotaId: input.quotaId,
      nowMs: input.renewedAtMs,
    });
    if (!persisted) {
      throw new Error('linked-device Wallet Session renewal was not persisted');
    }
    if (
      persisted.authorization.tenantId !== input.tenantId ||
      persisted.authorization.enrollmentId !== input.enrollmentId ||
      persisted.authorization.issuedAtMs !== input.renewedAtMs ||
      persisted.authorization.expiresAtMs !== expiresAtMs ||
      persisted.quota.remainingUses !== DEFAULT_WALLET_SESSION_REMAINING_USES ||
      persisted.quota.expiresAtMs !== expiresAtMs
    ) {
      throw new Error('linked-device Wallet Session renewal readback differs');
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

function assertNeverLinkedDeviceWalletSessionStatus(value: never): never {
  throw new Error(`unknown linked-device Wallet Session status: ${String(value)}`);
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
        input.permission.kind,
        input.permission.administrationScope,
        input.permission.localUserPresence,
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
