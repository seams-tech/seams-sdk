import type {
  ActiveAuthorizationSession,
  ActiveCapabilityGrant,
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
  SessionOrigin,
  VerifiedGrantEvidenceSet,
} from './domain';
import {
  parseHostedWalletSeamsSessionExchangeCode,
  parseHostedWalletSeamsSessionExchangeNonce,
} from './domain';
import {
  parseHostedWalletSessionExchangeCodeId,
  parseSeamsSessionId,
  type PrincipalId,
  type SeamsSessionId,
  type TenantId,
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

export interface AuthorizationStore {
  putActiveSession(session: ActiveAuthorizationSession): Promise<void>;
  readActiveSession(input: {
    readonly tenantId: TenantId;
    readonly sessionId: SeamsSessionId;
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null>;
  putIssuedHostedWalletSeamsSessionExchange(
    exchange: IssuedHostedWalletSeamsSessionExchange,
  ): Promise<void>;
  redeemHostedWalletSeamsSessionExchange(
    input: RedeemHostedWalletSeamsSessionExchangeInput,
  ): Promise<RedeemHostedWalletSeamsSessionExchangeResult>;
  putVerifiedEvidenceSet(evidenceSet: VerifiedGrantEvidenceSet): Promise<void>;
  putActiveGrant(grant: ActiveCapabilityGrant): Promise<void>;
  putActiveWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void>;
  claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult>;
  completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult>;
  readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null>;
}

export class AuthorizationService {
  constructor(private readonly store: AuthorizationStore) {}

  async recordActiveSession(session: ActiveAuthorizationSession): Promise<void> {
    await this.store.putActiveSession(session);
  }

  async readActiveSession(input: {
    readonly tenantId: TenantId;
    readonly sessionId: SeamsSessionId;
    readonly nowMs: number;
  }): Promise<ActiveAuthorizationSession | null> {
    return await this.store.readActiveSession(input);
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
    const source = await this.store.readActiveSession({
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
    await this.store.putIssuedHostedWalletSeamsSessionExchange({
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
    return await this.store.redeemHostedWalletSeamsSessionExchange({
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
    await this.store.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async recordVerifiedSessionEvidenceSet(
    input: VerifiedSessionEvidenceSetInput,
  ): Promise<VerifiedGrantEvidenceSet> {
    const evidenceSet = await buildVerifiedSessionEvidenceSet(input);
    await this.store.putVerifiedEvidenceSet(evidenceSet);
    return evidenceSet;
  }

  async issueGrant(input: CapabilityGrantRequestInput): Promise<void> {
    const request = buildCapabilityGrantRequest(input);
    await this.store.putActiveGrant(request.grant);
  }

  async recordWalletSessionQuota(quota: ActiveWalletSessionQuota): Promise<void> {
    await this.store.putActiveWalletSessionQuota(quota);
  }

  async claimOperation(claim: CapabilityOperationClaim): Promise<ClaimCapabilityOperationResult> {
    return await this.store.claimOperation(claim);
  }

  async completeOperation(input: {
    readonly claim: CapabilityOperationClaim;
    readonly result: CompletedCapabilityOperationResult;
    readonly resultRef: CapabilityOperationResultRef;
    readonly completedAtMs: number;
  }): Promise<CompleteCapabilityOperationResult> {
    return await this.store.completeOperation(input);
  }

  async readAuditEvent(input: {
    readonly tenantId: CapabilityOperationClaim['tenantId'];
    readonly eventId: CapabilityOperationClaim['auditEventId'];
  }): Promise<AuthorizationAuditEvent | null> {
    return await this.store.readAuditEvent(input);
  }
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
