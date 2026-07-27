import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
  ActiveReusableWalletSession,
  ActiveWalletSessionQuota,
  AuthorizationAuditEvent,
  CapabilityOperationClaim,
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
  parseHostedWalletSessionExchangeCodeId,
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
import { buildCapabilityOperationEnvelope } from '@shared/authorization/operationFingerprint';
import type { WalletId } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

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
  claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult>;
  completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult>;
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
    return { session, quota };
  }

  async claimOperationStepUpFromGrant(
    input: OperationStepUpClaimInput,
  ): Promise<ClaimCapabilityOperationResult> {
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
    const operation = buildCapabilityOperationEnvelope({
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
    const grant = await this.ports.grants.readGrantClaimSource({
      tenantId: input.tenantId,
      grantId: input.grantId,
    });
    if (!grant || !reusableWalletSessionGrantMatches(grant, input)) {
      return { claim: null, result: { kind: 'grant_mismatch' } };
    }
    const operation = buildCapabilityOperationEnvelope({
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
    const claim = await buildCapabilityOperationClaim({
      tenantId: input.tenantId,
      useId: input.useId,
      auditEventId: input.auditEventId,
      grantId: input.grantId,
      operation,
      evidenceSetDigest: grant.evidenceSetDigest,
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

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
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

function reusableWalletSessionGrantMatches(
  grant: CapabilityGrantClaimSource,
  input: {
    readonly tenantId: TenantId;
    readonly principalId: PrincipalId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly capabilityId: CapabilityId;
    readonly operationId: CapabilityOperationId;
    readonly operation: CapabilityOperationRef;
    readonly laneDigest: ActiveCapabilityGrant['laneDigest'];
    readonly intentDigest: ActiveCapabilityGrant['intentDigest'];
    readonly displayDigest: ActiveCapabilityGrant['displayDigest'];
  },
): boolean {
  return (
    grant.authority.kind === 'reusable_wallet_session' &&
    grant.tenantId === input.tenantId &&
    grant.principalId === input.principalId &&
    grant.authority.walletSessionId === input.walletSessionId &&
    grant.authority.quotaId === input.quotaId &&
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
  kind: 'wallet-session' | 'wallet-quota',
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
