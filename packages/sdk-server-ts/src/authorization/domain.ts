import type {
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  WalletSessionAuthorizationId,
  DeviceId,
  AuthorizationEvidenceId,
  AuthorizationEvidenceKind,
  HostedWalletSessionExchangeCodeId,
  MpcWalletSigningQuotaId,
  PrincipalId,
  ReusableWalletSessionMintId,
  SeamsSessionId,
  TenantId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
export {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
export type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import { computeCapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import type { DomainId, WalletId } from '@shared/utils/domainIds';
import {
  parseAppSessionVersion,
  parseProviderSubject,
  parseWebAuthnCredentialIdB64u,
  type AppSessionVersion,
  type ProviderSubject,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export type HostedWalletSeamsSessionExchangeCode = DomainId<'HostedWalletSeamsSessionExchangeCode'>;
export type HostedWalletSeamsSessionExchangeNonce =
  DomainId<'HostedWalletSeamsSessionExchangeNonce'>;
export type SessionOrigin = DomainId<'SessionOrigin'>;
export type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';

export type ActiveAuthorizationSession = {
  readonly kind: 'active_authorization_session';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly sessionId: SeamsSessionId;
  readonly authSource:
    | {
        readonly kind: 'oidc_provider';
        readonly providerId: 'google_oidc' | 'oidc';
        readonly providerSubject: ProviderSubject;
      }
    | {
        readonly kind: 'passkey';
        readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      };
  readonly deviceId: DeviceId;
  readonly audience:
    | {
        readonly kind: 'first_party_web';
        readonly origin: SessionOrigin;
      }
    | {
        readonly kind: 'hosted_wallet_iframe';
        readonly appOrigin: SessionOrigin;
        readonly walletOrigin: SessionOrigin;
      };
  readonly appSessionVersion: AppSessionVersion;
  readonly assurance: 'session' | 'step_up';
  readonly createdAtMs: number;
  readonly lifecycle: {
    readonly kind: 'active';
    readonly expiresAtMs: number;
  };
};

export type IssuedHostedWalletSeamsSessionExchange = {
  readonly kind: 'issued_hosted_wallet_session_exchange';
  readonly tenantId: TenantId;
  readonly exchangeCodeId: HostedWalletSessionExchangeCodeId;
  readonly sourceSessionId: SeamsSessionId;
  readonly codeHash: DigestB64u;
  readonly nonceDigest: DigestB64u;
  readonly appOrigin: SessionOrigin;
  readonly walletOrigin: SessionOrigin;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type HostedWalletSeamsSessionExchangeDelivery = {
  readonly kind: 'hosted_wallet_session_exchange_delivery';
  readonly exchangeCode: HostedWalletSeamsSessionExchangeCode;
  readonly nonce: HostedWalletSeamsSessionExchangeNonce;
  readonly appOrigin: SessionOrigin;
  readonly walletOrigin: SessionOrigin;
  readonly expiresAtMs: number;
};

export type RedeemHostedWalletSeamsSessionExchangeResult =
  | {
      readonly kind: 'redeemed';
      readonly session: ActiveAuthorizationSession;
    }
  | {
      readonly kind:
        | 'invalid_code'
        | 'expired'
        | 'already_consumed'
        | 'nonce_mismatch'
        | 'wallet_origin_mismatch'
        | 'source_session_unavailable';
    };

export type RedeemHostedWalletSeamsSessionExchangeInput = {
  readonly codeHash: DigestB64u;
  readonly nonceDigest: DigestB64u;
  readonly walletOrigin: SessionOrigin;
  readonly targetSessionId: SeamsSessionId;
  readonly redeemedAtMs: number;
};

export type VerifiedAuthorizationEvidence = {
  readonly evidenceId: AuthorizationEvidenceId;
  readonly evidenceKind: AuthorizationEvidenceKind;
  readonly evidenceDigest: DigestB64u;
};

export type { VerifiedAuthorizationEvidenceSet } from './factorEvidence';

export type ActiveWalletSessionQuota = {
  readonly kind: 'active_wallet_session_quota';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly remainingUses: number;
  readonly expiresAtMs: number;
};

export type WalletSessionAuthorization = {
  readonly kind: 'wallet_session_authorization';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly mintId: ReusableWalletSessionMintId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type AuthorizationGrant = WalletSessionAuthorization;

export type OperationAuthorizationSource =
  | {
      readonly kind: 'authorization_grant';
      readonly authorizationGrantRef: AuthorizationGrantRef;
      readonly evidenceSetDigest?: never;
    }
  | {
      readonly kind: 'verified_step_up';
      readonly authorizationGrantRef?: never;
      readonly evidenceSetDigest: DigestB64u;
    };

type AuthorizedOperationLifecycle =
  | {
      readonly lifecycle: 'claimed';
      readonly result?: never;
      readonly resultRef?: never;
      readonly completedAtMs?: never;
    }
  | {
      readonly lifecycle: 'completed';
      readonly result: CompletedCapabilityOperationResult;
      readonly resultRef: CapabilityOperationResultRef;
      readonly completedAtMs: number;
    };

export type AuthorizedOperation = AuthorizedOperationLifecycle & {
  readonly kind: 'authorized_operation';
  readonly tenantId: TenantId;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly claimedAtMs: number;
  readonly operation: CapabilityOperationEnvelope;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly authorization: OperationAuthorizationSource;
  readonly quota:
    | {
        readonly kind: 'consume_reusable_wallet_session';
        readonly quotaId: MpcWalletSigningQuotaId;
      }
    | { readonly kind: 'quota_neutral'; readonly quotaId?: never };
};

export type AuthorizedOperationInput = {
  readonly tenantId: TenantId;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly operation: CapabilityOperationEnvelope;
  readonly authorization: OperationAuthorizationSource;
  readonly quota:
    | {
        readonly kind: 'consume_reusable_wallet_session';
        readonly quotaId: MpcWalletSigningQuotaId;
      }
    | { readonly kind: 'quota_neutral'; readonly quotaId?: never };
  readonly claimedAtMs: number;
};

export async function buildAuthorizedOperation(
  input: AuthorizedOperationInput,
): Promise<AuthorizedOperation> {
  if (input.tenantId !== input.operation.tenantId) {
    throw new Error('authorized operation tenant must match its operation envelope');
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    input.operation,
  );
  return {
    ...input,
    kind: 'authorized_operation',
    operationFingerprintDigest,
    lifecycle: 'claimed',
  };
}

type ReusableWalletSessionStatusIdentity = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
};

export type ReusableWalletSessionStatus =
  | (ReusableWalletSessionStatusIdentity & {
      readonly kind: 'active';
      readonly remainingUses: number;
      readonly expiresAtMs: number;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly kind: 'exhausted';
      readonly remainingUses: 0;
      readonly expiresAtMs: number;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly kind: 'expired';
      readonly expiresAtMs: number;
      readonly remainingUses?: never;
    })
  | (ReusableWalletSessionStatusIdentity & {
      readonly kind: 'superseded' | 'missing' | 'invalid';
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
    });

export type CompletedCapabilityOperationResult =
  | 'succeeded'
  | 'failed_before_side_effect'
  | 'failed_after_side_effect';

export type CapabilityOperationResultRef = {
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly resultDigest: DigestB64u;
  readonly resultStorageRef: DomainId<'CapabilityOperationResultStorageRef'>;
};

export function parseHostedWalletSeamsSessionExchangeCode(
  value: unknown,
): HostedWalletSeamsSessionExchangeCode {
  return parseAuthorizationDomainId(value, 'hostedWalletSessionExchangeCode');
}

export function parseHostedWalletSeamsSessionExchangeNonce(
  value: unknown,
): HostedWalletSeamsSessionExchangeNonce {
  return parseAuthorizationDomainId(value, 'hostedWalletSessionExchangeNonce');
}

export function parseSessionOrigin(value: unknown): SessionOrigin {
  if (typeof value !== 'string' || value.trim() !== value) {
    throw new Error('session origin must be a canonical HTTP origin');
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('session origin must be a canonical HTTP origin');
  }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.origin !== value ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  ) {
    throw new Error('session origin must be a canonical HTTP origin');
  }
  return value as SessionOrigin;
}

export function buildActiveAuthorizationSession(
  fields: Omit<ActiveAuthorizationSession, 'kind'>,
): ActiveAuthorizationSession {
  requireOrderedTimes(fields.createdAtMs, fields.lifecycle.expiresAtMs, 'authorization session');
  requireAuthorizationSource(fields.authSource);
  requireSessionAudience(fields.audience);
  requireOpaqueVersion(fields.appSessionVersion);
  return {
    kind: 'active_authorization_session',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    sessionId: fields.sessionId,
    authSource: fields.authSource,
    deviceId: fields.deviceId,
    audience: fields.audience,
    appSessionVersion: fields.appSessionVersion,
    assurance: fields.assurance,
    createdAtMs: fields.createdAtMs,
    lifecycle: fields.lifecycle,
  };
}

export function buildActiveWalletSessionQuota(
  fields: Omit<ActiveWalletSessionQuota, 'kind'>,
): ActiveWalletSessionQuota {
  requirePositiveCount(fields.remainingUses, 'Wallet Session quota remaining uses');
  requirePositiveTime(fields.expiresAtMs, 'Wallet Session quota expiry');
  return {
    kind: 'active_wallet_session_quota',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletSessionId: fields.walletSessionId,
    quotaId: fields.quotaId,
    remainingUses: fields.remainingUses,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function buildWalletSessionAuthorization(
  fields: Omit<WalletSessionAuthorization, 'kind'>,
): WalletSessionAuthorization {
  requireOrderedTimes(fields.createdAtMs, fields.expiresAtMs, 'reusable Wallet Session');
  if (fields.authority.walletId !== fields.walletId) {
    throw new Error('reusable Wallet Session authority must identify the exact wallet');
  }
  const authorizationId = String(fields.authorizationId);
  const walletSessionId = String(fields.walletSessionId);
  const quotaId = String(fields.quotaId);
  if (
    authorizationId === walletSessionId ||
    authorizationId === quotaId ||
    walletSessionId === quotaId
  ) {
    throw new Error('authorization, Wallet Session, and quota identities must be pairwise distinct');
  }
  return {
    kind: 'wallet_session_authorization',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletId: fields.walletId,
    authority: fields.authority,
    mintId: fields.mintId,
    authorizationId: fields.authorizationId,
    walletSessionId: fields.walletSessionId,
    quotaId: fields.quotaId,
    createdAtMs: fields.createdAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

function parseAuthorizationDomainId<TName extends string>(
  value: unknown,
  fieldName: string,
): DomainId<TName> {
  if (
    typeof value !== 'string' ||
    value.trim() !== value ||
    value.length === 0 ||
    value.length > 512 ||
    // eslint-disable-next-line no-control-regex
    /[\s\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${fieldName} must be a compact opaque identifier`);
  }
  return value as DomainId<TName>;
}

function requirePositiveCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function requirePositiveTime(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive timestamp`);
  }
}

function requireOrderedTimes(createdAtMs: number, expiresAtMs: number, label: string): void {
  requirePositiveTime(createdAtMs, `${label} creation`);
  requirePositiveTime(expiresAtMs, `${label} expiry`);
  if (expiresAtMs <= createdAtMs) {
    throw new Error(`${label} expiry must follow creation`);
  }
}

function requireAuthorizationSource(source: ActiveAuthorizationSession['authSource']): void {
  switch (source.kind) {
    case 'oidc_provider':
      requireDomainIdParse(
        parseProviderSubject(source.providerSubject),
        'authSource.providerSubject',
      );
      return;
    case 'passkey':
      requireDomainIdParse(
        parseWebAuthnCredentialIdB64u(source.credentialIdB64u),
        'authSource.credentialIdB64u',
      );
      return;
  }
}

function requireSessionAudience(audience: ActiveAuthorizationSession['audience']): void {
  switch (audience.kind) {
    case 'first_party_web':
      parseSessionOrigin(audience.origin);
      return;
    case 'hosted_wallet_iframe':
      parseSessionOrigin(audience.appOrigin);
      parseSessionOrigin(audience.walletOrigin);
      return;
  }
}

function requireOpaqueVersion(value: AppSessionVersion): void {
  requireDomainIdParse(parseAppSessionVersion(value), 'appSessionVersion');
}

function requireDomainIdParse(
  result: { readonly ok: true } | { readonly ok: false; readonly error: { message: string } },
  label: string,
): void {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
}
