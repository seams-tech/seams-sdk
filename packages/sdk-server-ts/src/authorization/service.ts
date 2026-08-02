import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  ActiveReusableWalletSession,
  ActiveWalletSessionQuota,
  AuthorizationAuditEvent,
  CapabilityGrantUse,
  CapabilityOperationClaim,
  CapabilityOperationCompletionClaimRef,
  CapabilityOperationResultRef,
  ClaimCapabilityOperationResult,
  CompleteCapabilityOperationResult,
  CompletedCapabilityOperationResult,
  HostedWalletSeamsSessionExchangeCode,
  HostedWalletSeamsSessionExchangeDelivery,
  HostedWalletSeamsSessionExchangeNonce,
  IssuedHostedWalletSeamsSessionExchange,
  RedeemHostedWalletSeamsSessionExchangeInput,
  RedeemHostedWalletSeamsSessionExchangeResult,
  ReusableWalletSessionStatus,
  SessionOrigin,
  VerifiedGrantEvidenceSet,
} from './domain';
import type {
  AuthorizationGrant,
  AuthorizedOperation,
  AuthorizedOperationInput,
} from './operationAuthorization';
import { buildWalletSessionAuthorization } from './operationAuthorization';
import {
  buildActiveReusableWalletSession,
  buildActiveWalletSessionQuota,
  buildCapabilityOperationClaim,
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
} from './domain';
import {
  CAPABILITY_KINDS,
  parseAuthorizationGrantRef,
  parseHostedWalletSessionExchangeCodeId,
  parseWalletSessionAuthorizationId,
  type AuthorizationAuditEventId,
  type CapabilityGrantId,
  type CapabilityGrantUseId,
  type CapabilityId,
  type CapabilityOperationId,
  type CapabilityOperationRef,
  type MpcWalletSigningQuotaId,
  parseSeamsSessionId,
  type PrincipalId,
  type ReusableWalletSessionMintId,
  type SeamsSessionId,
  type TenantId,
  type WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  buildCapabilityGrantRequest,
  buildVerifiedFactorEvidenceSet,
  buildVerifiedSessionEvidenceSet,
  type CapabilityGrantRequestInput,
  type VerifiedFactorEvidenceSetInput,
  type VerifiedSessionEvidenceSetInput,
} from './factorEvidence';
import type {
  CapabilityPolicyPort,
  GrantEvidenceRequirementEvaluation,
  ParseGrantEvidenceRequirementResult,
} from './capabilityPolicy';
import type { GrantEvidenceRequirement } from '@shared/authorization/capabilityKinds';
import {
  buildCapabilityOperationEnvelope,
  computeCapabilityOperationFingerprintDigest,
  type CapabilityOperationEnvelope,
} from '@shared/authorization/operationFingerprint';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { RouterAbMpcMaterialActivationRefWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RuntimePolicyScope } from '@shared/threshold/signingRootScope';

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
  putVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void>;
}

type CapabilityGrantClaimSourceBase = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly authorizationSessionId: SeamsSessionId;
  readonly grantId: CapabilityGrantId;
  readonly evidenceSetDigest: ActiveCapabilityGrant['evidenceSetDigest'];
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: ActiveCapabilityGrant['laneDigest'];
  readonly intentDigest: ActiveCapabilityGrant['intentDigest'];
  readonly displayDigest: ActiveCapabilityGrant['displayDigest'];
};

export type CapabilityGrantClaimSource =
  | (CapabilityGrantClaimSourceBase & {
      readonly authority: Extract<
        ActiveCapabilityGrant,
        { readonly authority: { readonly kind: 'reusable_wallet_session' } }
      >['authority'];
    })
  | (CapabilityGrantClaimSourceBase & {
      readonly authority: { readonly kind: 'operation_step_up' };
    });

export interface AuthorizationGrantPort {
  putAuthorizationGrant(grant: AuthorizationGrant): Promise<void>;
  readAuthorizationGrant(input: {
    readonly tenantId: TenantId;
    readonly authorizationGrantRef: import('@shared/authorization/capabilityKinds').AuthorizationGrantRef;
  }): Promise<AuthorizationGrant | null>;
  putActiveGrant(grant: ActiveCapabilityGrant): Promise<void>;
  putActiveWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void>;
  putActiveReusableWalletSession(input: {
    readonly session: ActiveReusableWalletSession;
    readonly quota: ActiveWalletSessionQuota;
  }): Promise<void>;
  readGrantClaimSource(input: {
    readonly tenantId: TenantId;
    readonly grantId: CapabilityGrantId;
  }): Promise<CapabilityGrantClaimSource | null>;
}

export interface AuthorizationClaimPort {
  readAuthorizedOperation(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: import('@shared/authorization/operationFingerprint').CapabilityOperationFingerprintDigest;
  }): Promise<AuthorizedOperation | null>;
  claimAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: EcdsaMaterialActivationScope;
  }): Promise<
    | { readonly kind: 'claimed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'replayed'; readonly operation: AuthorizedOperation }
    | { readonly kind: 'operation_in_progress'; readonly operation: AuthorizedOperation }
    | {
        readonly kind:
          | 'authorization_grant_rejected'
          | 'verified_step_up_rejected'
          | 'wallet_session_quota_exhausted'
          | 'material_mismatch';
      }
  >;
  completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: import('./operationAuthorization').AuthorizedOperationResult;
    readonly resultRef: import('./operationAuthorization').AuthorizedOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<AuthorizedOperation>;
  readOperationUse(input: {
    readonly tenantId: TenantId;
    readonly operationFingerprintDigest: CapabilityOperationClaim['operationFingerprintDigest'];
  }): Promise<CapabilityGrantUse | null>;
  claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult>;
  claimEcdsaOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicClaimResult>;
  putEcdsaEvidenceAndGrant(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicAuthorizationResult>;
  claimEcdsaReusableWalletSessionOperation(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaReusableWalletSessionClaimOutcome>;
  completeOperation(input: {
    readonly claim: CapabilityOperationClaim | CapabilityOperationCompletionClaimRef;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult>;
}

export type EcdsaMaterialActivationScope = Readonly<{
  readonly walletId: WalletId;
  readonly keyHandle: string;
  readonly runtimePolicyScope: RuntimePolicyScope;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
}>;

export type EcdsaAtomicAuthorizationResult =
  | { readonly kind: 'committed' }
  | { readonly kind: 'material_mismatch' };

export type EcdsaAtomicClaimResult =
  | ClaimCapabilityOperationResult
  | { readonly kind: 'material_mismatch' };

export type EcdsaReusableWalletSessionClaimOutcome = {
  readonly claim: CapabilityOperationClaim | null;
  readonly result: EcdsaAtomicClaimResult;
};

function ecdsaMaterialMatchesCapability(input: {
  readonly material: EcdsaMaterialActivationScope;
  readonly capabilityId: CapabilityId;
  readonly operation: CapabilityOperationRef;
}): boolean {
  return (
    input.operation.capabilityKind === CAPABILITY_KINDS.evmEcdsaMpcSigning &&
    String(input.material.walletId) === input.material.materialActivation.material_owner &&
    input.material.materialActivation.capability === input.capabilityId
  );
}

export interface AuthorizationAuditPort {
  readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null>;
}

export type AuthorizationServicePorts = {
  readonly policy: CapabilityPolicyPort;
  readonly sessions: AuthorizationSessionPort;
  readonly evidence: AuthorizationEvidencePort;
  readonly grants: AuthorizationGrantPort;
  readonly claims: AuthorizationClaimPort;
  readonly audit: AuthorizationAuditPort;
};

export type OperationStepUpClaimInput = {
  readonly tenantId: TenantId;
  readonly grantId: CapabilityGrantId;
  readonly useId: CapabilityGrantUseId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly authorizationSessionId: SeamsSessionId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: ActiveCapabilityGrant['laneDigest'];
  readonly intentDigest: ActiveCapabilityGrant['intentDigest'];
  readonly displayDigest: ActiveCapabilityGrant['displayDigest'];
  readonly claimedAtMs: number;
};

export type ReusableWalletSessionClaimInput = {
  readonly tenantId: TenantId;
  readonly grantId: CapabilityGrantId;
  readonly useId: CapabilityGrantUseId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: ActiveCapabilityGrant['laneDigest'];
  readonly intentDigest: ActiveCapabilityGrant['intentDigest'];
  readonly displayDigest: ActiveCapabilityGrant['displayDigest'];
  readonly claimedAtMs: number;
};

export type ReusableWalletSessionClaimOutcome = {
  readonly claim: CapabilityOperationClaim | null;
  readonly result: ClaimCapabilityOperationResult;
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
  readonly session: ActiveReusableWalletSession;
  readonly quota: ActiveWalletSessionQuota;
  readonly authorization: AuthorizationGrant;
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
    if (
      !Number.isSafeInteger(input.issuedAtMs) ||
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
  ): Promise<VerifiedGrantEvidenceSet> {
    const evidenceSet = await buildVerifiedFactorEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async recordVerifiedSessionEvidenceSet(
    input: VerifiedSessionEvidenceSetInput,
  ): Promise<VerifiedGrantEvidenceSet> {
    const evidenceSet = await buildVerifiedSessionEvidenceSet(input);
    await this.ports.evidence.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async issueGrant(input: CapabilityGrantRequestInput): Promise<void> {
    const request = buildCapabilityGrantRequest(input);
    await this.ports.grants.putActiveGrant(request.grant);
  }

  async recordWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void> {
    await this.ports.grants.putActiveWalletSessionQuota(quota);
  }

  async claimAuthorizedOperation(input: {
    readonly operation: AuthorizedOperationInput;
    readonly material?: EcdsaMaterialActivationScope;
  }): ReturnType<AuthorizationClaimPort['claimAuthorizedOperation']> {
    return await this.ports.claims.claimAuthorizedOperation(input);
  }

  async completeAuthorizedOperation(input: {
    readonly operation: AuthorizedOperation;
    readonly result: import('./operationAuthorization').AuthorizedOperationResult;
    readonly resultRef: import('./operationAuthorization').AuthorizedOperationResultRef;
    readonly completedAtMs: number;
  }): ReturnType<AuthorizationClaimPort['completeAuthorizedOperation']> {
    return await this.ports.claims.completeAuthorizedOperation(input);
  }

  async issueReusableWalletSession(
    input: IssueReusableWalletSessionInput,
  ): Promise<IssuedReusableWalletSession> {
    const walletSessionId = parseRequired(
      await deriveReusableWalletSessionId(input, 'wallet-session'),
      parseWalletSessionId,
    );
    const quotaId = parseRequired(
      await deriveReusableWalletSessionId(input, 'wallet-quota'),
      parseMpcWalletSigningQuotaId,
    );
    const session = buildActiveReusableWalletSession({
      tenantId: input.tenantId,
      principalId: input.principalId,
      walletId: input.walletId,
      authority: input.authority,
      mintId: input.mintId,
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
    await this.ports.grants.putActiveReusableWalletSession({ session, quota });
    const authorization = buildWalletSessionAuthorization({
      authorizationGrantRef: parseRequired(
        await deriveReusableWalletSessionId(input, 'authorization-grant'),
        parseAuthorizationGrantRef,
      ),
      authorizationId: parseRequired(
        await deriveReusableWalletSessionId(input, 'authorization-id'),
        parseWalletSessionAuthorizationId,
      ),
      tenantId: session.tenantId,
      principalId: session.principalId,
      walletId: session.walletId,
      walletSessionId: session.walletSessionId,
      quotaId: session.quotaId,
      revocationEpoch: 1,
      createdAtMs: session.createdAtMs,
      expiresAtMs: session.expiresAtMs,
    });
    await this.ports.grants.putAuthorizationGrant(authorization);
    return { session, quota, authorization };
  }

  async claimOperationStepUpFromGrant(
    input: OperationStepUpClaimInput,
  ): Promise<ClaimCapabilityOperationResult> {
    const operation = operationEnvelopeFromClaimInput(input);
    const existing = await this.lookupOperationClaim(operation);
    if (existing) return existing;
    const session = await this.ports.sessions.readActiveSession({
      tenantId: input.tenantId,
      sessionId: input.authorizationSessionId,
      nowMs: input.claimedAtMs,
    });
    if (!session || session.principalId !== input.principalId) {
      return { kind: 'grant_mismatch' };
    }
    const grant = await this.ports.grants.readGrantClaimSource({
      tenantId: input.tenantId,
      grantId: input.grantId,
    });
    if (!grant || !operationStepUpGrantMatches(grant, input)) {
      return { kind: 'grant_mismatch' };
    }
    const claim = await buildCapabilityOperationClaim({
      tenantId: input.tenantId,
      useId: input.useId,
      auditEventId: input.auditEventId,
      grantId: input.grantId,
      operation,
      evidenceSetDigest: grant.evidenceSetDigest,
      claimedAtMs: input.claimedAtMs,
      authorization: { kind: 'operation_step_up' },
    });
    return await this.ports.claims.claimOperation(claim);
  }

  async claimReusableWalletSessionFromGrant(
    input: ReusableWalletSessionClaimInput,
  ): Promise<ClaimCapabilityOperationResult> {
    return (await this.claimReusableWalletSessionOperation(input)).result;
  }

  async claimReusableWalletSessionOperation(
    input: ReusableWalletSessionClaimInput,
  ): Promise<ReusableWalletSessionClaimOutcome> {
    const operation = operationEnvelopeFromClaimInput(input);
    const existing = await this.lookupOperationClaim(operation);
    if (existing) return { claim: null, result: existing };
    const claim = await buildCapabilityOperationClaim({
      tenantId: input.tenantId,
      useId: input.useId,
      auditEventId: input.auditEventId,
      grantId: input.grantId,
      operation,
      evidenceSetDigest: await digestOpaqueValue(
        [
          'reusable-wallet-session-operation',
          input.tenantId,
          input.principalId,
          input.walletSessionId,
          input.quotaId,
        ].join(':'),
      ),
      claimedAtMs: input.claimedAtMs,
      authorization: {
        kind: 'reusable_wallet_session',
        walletSessionId: input.walletSessionId,
        quotaId: input.quotaId,
      },
    });
    return {
      claim,
      result: await this.ports.claims.claimOperation(claim),
    };
  }

  async claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult> {
    return await this.ports.claims.claimOperation(claim);
  }

  async claimEcdsaOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicClaimResult> {
    if (
      input.material.runtimePolicyScope.orgId !== input.claim.tenantId ||
      !ecdsaMaterialMatchesCapability({
        material: input.material,
        capabilityId: input.claim.operation.capabilityId,
        operation: input.claim.operation.operation,
      })
    ) {
      return { kind: 'material_mismatch' };
    }
    return await this.ports.claims.claimEcdsaOperation(input);
  }

  async claimEcdsaOperationStepUpFromGrant(input: {
    readonly claim: OperationStepUpClaimInput;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicClaimResult> {
    if (
      input.material.runtimePolicyScope.orgId !== input.claim.tenantId ||
      !ecdsaMaterialMatchesCapability({
        material: input.material,
        capabilityId: input.claim.capabilityId,
        operation: input.claim.operation,
      })
    ) {
      return { kind: 'material_mismatch' };
    }
    const operation = operationEnvelopeFromClaimInput(input.claim);
    const session = await this.ports.sessions.readActiveSession({
      tenantId: input.claim.tenantId,
      sessionId: input.claim.authorizationSessionId,
      nowMs: input.claim.claimedAtMs,
    });
    if (!session || session.principalId !== input.claim.principalId) {
      return { kind: 'grant_mismatch' };
    }
    const grant = await this.ports.grants.readGrantClaimSource({
      tenantId: input.claim.tenantId,
      grantId: input.claim.grantId,
    });
    if (!grant || !operationStepUpGrantMatches(grant, input.claim)) {
      return { kind: 'grant_mismatch' };
    }
    const claim = await buildCapabilityOperationClaim({
      tenantId: input.claim.tenantId,
      useId: input.claim.useId,
      auditEventId: input.claim.auditEventId,
      grantId: input.claim.grantId,
      operation,
      evidenceSetDigest: grant.evidenceSetDigest,
      claimedAtMs: input.claim.claimedAtMs,
      authorization: { kind: 'operation_step_up' },
    });
    return await this.ports.claims.claimEcdsaOperation({
      claim,
      material: input.material,
    });
  }

  async putEcdsaEvidenceAndGrant(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaAtomicAuthorizationResult> {
    if (
      input.material.runtimePolicyScope.orgId !== input.evidenceSet.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.grant.tenantId ||
      input.evidenceSet.tenantId !== input.grant.tenantId ||
      !ecdsaMaterialMatchesCapability({
        material: input.material,
        capabilityId: input.grant.capabilityId,
        operation: input.grant.operation,
      })
    ) {
      return { kind: 'material_mismatch' };
    }
    return await this.ports.claims.putEcdsaEvidenceAndGrant(input);
  }

  async claimEcdsaReusableWalletSessionOperation(input: {
    readonly evidenceSet: VerifiedGrantEvidenceSet;
    readonly grant: ActiveCapabilityGrant;
    readonly claim: CapabilityOperationClaim;
    readonly material: EcdsaMaterialActivationScope;
  }): Promise<EcdsaReusableWalletSessionClaimOutcome> {
    if (
      input.material.runtimePolicyScope.orgId !== input.evidenceSet.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.grant.tenantId ||
      input.material.runtimePolicyScope.orgId !== input.claim.tenantId ||
      input.evidenceSet.tenantId !== input.grant.tenantId ||
      input.evidenceSet.tenantId !== input.claim.tenantId ||
      !ecdsaMaterialMatchesCapability({
        material: input.material,
        capabilityId: input.grant.capabilityId,
        operation: input.grant.operation,
      }) ||
      !ecdsaMaterialMatchesCapability({
        material: input.material,
        capabilityId: input.claim.operation.capabilityId,
        operation: input.claim.operation.operation,
      })
    ) {
      return { claim: null, result: { kind: 'material_mismatch' } };
    }
    return await this.ports.claims.claimEcdsaReusableWalletSessionOperation(input);
  }

  async lookupOperationClaim(
    operation: CapabilityOperationEnvelope,
  ): Promise<ClaimCapabilityOperationResult | null> {
    const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(operation);
    const use = await this.ports.claims.readOperationUse({
      tenantId: operation.tenantId,
      operationFingerprintDigest,
    });
    if (!use) return null;
    return existingOperationClaimResult(use, operation);
  }

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim | CapabilityOperationCompletionClaimRef;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult> {
    return await this.ports.claims.completeOperation(input);
  }

  async readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null> {
    return await this.ports.audit.readAuditEvent(input);
  }

  parseEvidenceRequirement(value: unknown): ParseGrantEvidenceRequirementResult {
    return this.ports.policy.parseEvidenceRequirement(value);
  }

  evaluateEvidenceRequirement(
    requirement: GrantEvidenceRequirement,
    evidenceSet: VerifiedGrantEvidenceSet,
  ): GrantEvidenceRequirementEvaluation {
    return this.ports.policy.evaluateEvidenceRequirement(requirement, evidenceSet);
  }
}

function operationEnvelopeFromClaimInput(
  input: OperationStepUpClaimInput | ReusableWalletSessionClaimInput,
): CapabilityOperationEnvelope {
  return buildCapabilityOperationEnvelope({
    tenantId: input.tenantId,
    principalId: input.principalId,
    capabilityId: input.capabilityId,
    operationId: input.operationId,
    operation: input.operation,
    digests: {
      laneDigest: input.laneDigest,
      intentDigest: input.intentDigest,
      displayDigest: input.displayDigest,
    },
  });
}

function existingOperationClaimResult(
  use: CapabilityGrantUse,
  operation: CapabilityOperationEnvelope,
): ClaimCapabilityOperationResult {
  if (
    use.tenantId !== operation.tenantId ||
    use.principalId !== operation.principalId ||
    use.capabilityId !== operation.capabilityId ||
    use.operationId !== operation.operationId ||
    use.operation.capabilityKind !== operation.operation.capabilityKind ||
    use.operation.operationKind !== operation.operation.operationKind
  ) {
    return { kind: 'grant_mismatch' };
  }
  switch (use.kind) {
    case 'claimed':
      return { kind: 'operation_in_progress', use };
    case 'completed':
      return { kind: 'replayed', use };
  }
}

function operationStepUpGrantMatches(
  grant: CapabilityGrantClaimSource,
  input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly authorizationSessionId: SeamsSessionId;
    readonly capabilityId: CapabilityId;
    readonly operationId: CapabilityOperationId;
    readonly operation: CapabilityOperationRef;
    readonly laneDigest: ActiveCapabilityGrant['laneDigest'];
    readonly intentDigest: ActiveCapabilityGrant['intentDigest'];
    readonly displayDigest: ActiveCapabilityGrant['displayDigest'];
  },
): boolean {
  return (
    grant.authority.kind === 'operation_step_up' &&
    grant.tenantId === input.tenantId &&
    grant.principalId === input.principalId &&
    grant.authorizationSessionId === input.authorizationSessionId &&
    grant.capabilityId === input.capabilityId &&
    grant.operationId === input.operationId &&
    grant.operation.capabilityKind === input.operation.capabilityKind &&
    grant.operation.operationKind === input.operation.operationKind &&
    grant.laneDigest === input.laneDigest &&
    grant.intentDigest === input.intentDigest &&
    grant.displayDigest === input.displayDigest
  );
}

async function deriveReusableWalletSessionId(
  input: IssueReusableWalletSessionInput,
  kind: 'wallet-session' | 'wallet-quota' | 'authorization-grant' | 'authorization-id',
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
  return `${kind === 'wallet-session' ? 'wlt' : 'wsq'}_${digest}`;
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
