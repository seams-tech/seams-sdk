import type {
  ActiveAuthorizationSession,
  ActiveWalletSessionQuota,
  AuthorizedOperation,
  AuthorizedOperationInput,
  AuthorizedOperationReplayResponse,
  CompletedCapabilityOperationResult,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDelivery,
  HostedWalletSeamsSessionExchangeNonce,
  IssuedHostedWalletSeamsSessionExchange,
  RedeemHostedWalletSeamsSessionExchangeInput,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  LinkedDeviceWalletSessionAuthorization,
  LinkedDeviceWalletSessionStatus,
  SessionOrigin,
  VerifiedAuthorizationEvidenceSet,
  WalletSessionAuthorization,
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
  parseSeamsSessionId,
  parseWalletSessionAuthorizationId,
  type MpcWalletSigningQuotaId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type SeamsSessionId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  buildVerifiedFactorEvidenceSet,
  buildVerifiedSessionEvidenceSet,
  type VerifiedFactorEvidenceSetInput,
  type VerifiedSessionEvidenceSetInput,
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

export interface AuthorizationSessionPort {
  putActiveSession(session: ActiveAuthorizationSession): Promise<void>;
  readActiveSession(input: {
    readonly tenantId: TenantId;
    readonly sessionId: SeamsSessionId;
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null>;
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
  ): Promise<RedeemHostedWalletSeamsSessionExchangeResult>;
}

export interface AuthorizationEvidencePort {
  putVerifiedEvidenceSet(evidenceSet: VerifiedAuthorizationEvidenceSet): Promise<void>;
}

export interface AuthorizationGrantPort {
  putActiveWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void>;
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

export class AuthorizationService {
  constructor(private readonly ports: AuthorizationServicePorts) {}

  async recordActiveSession(session: ActiveAuthorizationSession): Promise<void> {
    await this.ports.sessions.putActiveSession(session);
  }

  async readActiveSession(input: {
    readonly tenantId: TenantId;
    readonly sessionId: SeamsSessionId;
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null> {
    return await this.ports.sessions.readActiveSession(input);
  }

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
    readonly principalId: PrincipalId;
    readonly sourceSessionId: SeamsSessionId;
    readonly appOrigin: SessionOrigin;
    readonly walletOrigin: SessionOrigin;
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  }): Promise<HostedWalletSeamsSessionExchangeDelivery> {
    const source = await this.ports.sessions.readActiveSession({
      tenantId: input.tenantId,
      sessionId: input.sourceSessionId,
      nowMs: input.issuedAtMs,
    });
    if (
      !source ||
      source.principalId !== input.principalId ||
      source.audience.kind !== 'first_party_web' ||
      source.audience.origin !== input.appOrigin
    ) {
      throw new Error('source authorization session is unavailable');
    }
    const expiresAtMs = Math.min(input.expiresAtMs, source.lifecycle.expiresAtMs);
    if (!Number.isSafeInteger(input.issuedAtMs) || expiresAtMs <= input.issuedAtMs) {
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
      sourceSessionId: input.sourceSessionId,
      codeHash: await digestOpaqueValue(exchangeCode),
      nonceDigest: await digestOpaqueValue(nonce),
      appOrigin: input.appOrigin,
      walletOrigin: input.walletOrigin,
      issuedAtMs: input.issuedAtMs,
      expiresAtMs,
    });
    return {
      kind: 'hosted_wallet_session_exchange_delivery',
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
    readonly walletOrigin: SessionOrigin;
    readonly redeemedAtMs: number;
  }): Promise<RedeemHostedWalletSeamsSessionExchangeResult> {
    const targetSessionId = parseRequired(
      `ses_${secureRandomBase64Url(24, 'hosted-wallet Seams sessions')}`,
      parseSeamsSessionId,
    );
    return await this.ports.sessions.redeemHostedWalletSeamsSessionExchange({
      codeHash: await digestOpaqueValue(input.exchangeCode),
      nonceDigest: await digestOpaqueValue(input.nonce),
      walletOrigin: input.walletOrigin,
      targetSessionId,
      redeemedAtMs: input.redeemedAtMs,
    });
  }

  async recordVerifiedFactorEvidenceSet(
    input: VerifiedFactorEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet> {
    const evidenceSet = await buildVerifiedFactorEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async recordVerifiedSessionEvidenceSet(
    input: VerifiedSessionEvidenceSetInput,
  ): Promise<VerifiedAuthorizationEvidenceSet> {
    const evidenceSet = await buildVerifiedSessionEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async recordWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void> {
    await this.ports.grants.putActiveWalletSessionQuota(quota);
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
