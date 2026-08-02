import type {
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  CapabilityBindingId,
  CapabilityGrantId,
  CapabilityGrantUseId,
  CapabilityId,
  CapabilityOperationId,
  CapabilityOperationRef,
  DeviceId,
  GrantEvidenceId,
  GrantEvidenceKind,
  GrantEvidenceSetId,
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

export type VerifiedGrantEvidence = {
  readonly evidenceId: GrantEvidenceId;
  readonly evidenceKind: GrantEvidenceKind;
  readonly evidenceDigest: DigestB64u;
};

export type { VerifiedGrantEvidenceSet } from './factorEvidence';

type ActiveCapabilityGrantBase = {
  readonly kind: 'active_capability_grant';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly grantId: CapabilityGrantId;
  readonly bindingId: CapabilityBindingId;
  readonly evidenceSetId: GrantEvidenceSetId;
  readonly evidenceSetDigest: DigestB64u;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
  readonly remainingUses: number;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type ActiveCapabilityGrant =
  | (ActiveCapabilityGrantBase & {
      readonly authority: {
        readonly kind: 'reusable_wallet_session';
        readonly walletSessionId: WalletSessionId;
        readonly quotaId: MpcWalletSigningQuotaId;
      };
      readonly remainingUses: 1;
    })
  | (ActiveCapabilityGrantBase & {
      readonly authority: {
        readonly kind: 'operation_step_up';
        readonly walletSessionId?: never;
        readonly quotaId?: never;
      };
      readonly remainingUses: 1;
    });

export type ActiveCapabilityGrantInput = Omit<ActiveCapabilityGrantBase, 'kind'> &
  (
    | {
        readonly authority: {
          readonly kind: 'reusable_wallet_session';
          readonly walletSessionId: WalletSessionId;
          readonly quotaId: MpcWalletSigningQuotaId;
        };
        readonly remainingUses: 1;
      }
    | {
        readonly authority: {
          readonly kind: 'operation_step_up';
          readonly walletSessionId?: never;
          readonly quotaId?: never;
        };
        readonly remainingUses: 1;
      }
  );

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

type CapabilityOperationClaimBase = {
  readonly tenantId: TenantId;
  readonly useId: CapabilityGrantUseId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly grantId: CapabilityGrantId;
  readonly operation: CapabilityOperationEnvelope;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly evidenceSetDigest: DigestB64u;
  readonly claimedAtMs: number;
};

const capabilityOperationClaimBrand: unique symbol = Symbol('CapabilityOperationClaim');

export type CapabilityOperationClaim =
  | (CapabilityOperationClaimBase & {
      readonly [capabilityOperationClaimBrand]: true;
      readonly authorization: {
        readonly kind: 'reusable_wallet_session';
        readonly walletSessionId: WalletSessionId;
        readonly quotaId: MpcWalletSigningQuotaId;
      };
      readonly quota: { readonly kind: 'consume_reusable_wallet_session' };
    })
  | (CapabilityOperationClaimBase & {
      readonly [capabilityOperationClaimBrand]: true;
      readonly authorization: {
        readonly kind: 'reusable_wallet_session';
        readonly walletSessionId: WalletSessionId;
        readonly quotaId: MpcWalletSigningQuotaId;
      };
      readonly quota: { readonly kind: 'quota_neutral' };
    })
  | (CapabilityOperationClaimBase & {
      readonly [capabilityOperationClaimBrand]: true;
      readonly authorization: {
        readonly kind: 'operation_step_up';
        readonly walletSessionId?: never;
        readonly quotaId?: never;
      };
      readonly quota: { readonly kind: 'quota_neutral' };
    });

export type CapabilityOperationClaimInput = CapabilityOperationClaimBase &
  (
    | {
        readonly authorization: {
          readonly kind: 'reusable_wallet_session';
          readonly walletSessionId: WalletSessionId;
          readonly quotaId: MpcWalletSigningQuotaId;
        };
      }
    | {
        readonly authorization: {
          readonly kind: 'operation_step_up';
          readonly walletSessionId?: never;
          readonly quotaId?: never;
        };
      }
  );

type CapabilityOperationCompletionClaimRefFields = Pick<
  CapabilityOperationClaimBase,
  'tenantId' | 'useId' | 'grantId' | 'operationFingerprintDigest'
>;

const capabilityOperationCompletionClaimRefBrand: unique symbol = Symbol(
  'CapabilityOperationCompletionClaimRef',
);

export type CapabilityOperationCompletionClaimRef =
  CapabilityOperationCompletionClaimRefFields & {
    readonly [capabilityOperationCompletionClaimRefBrand]: true;
  };

export function buildCapabilityOperationCompletionClaimRef(
  input: CapabilityOperationCompletionClaimRefFields,
): CapabilityOperationCompletionClaimRef {
  return {
    [capabilityOperationCompletionClaimRefBrand]: true,
    tenantId: input.tenantId,
    useId: input.useId,
    grantId: input.grantId,
    operationFingerprintDigest: input.operationFingerprintDigest,
  };
}

export type CompletedCapabilityOperationResult =
  | 'succeeded'
  | 'failed_before_side_effect'
  | 'failed_after_side_effect';

export type CapabilityOperationResultRef = {
  readonly resultDigest: DigestB64u;
  readonly resultStorageRef: DomainId<'CapabilityOperationResultStorageRef'>;
};

export type ClaimedCapabilityGrantUse = {
  readonly kind: 'claimed';
  readonly tenantId: TenantId;
  readonly useId: CapabilityGrantUseId;
  readonly grantId: CapabilityGrantId;
  readonly principalId: PrincipalId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly evidenceSetDigest: DigestB64u;
  readonly claimedAtMs: number;
};

export type CompletedCapabilityGrantUse = Omit<ClaimedCapabilityGrantUse, 'kind'> & {
  readonly kind: 'completed';
  readonly result: CompletedCapabilityOperationResult;
  readonly resultRef: CapabilityOperationResultRef;
  readonly completedAtMs: number;
};

export type CapabilityGrantUse = ClaimedCapabilityGrantUse | CompletedCapabilityGrantUse;

export type ClaimCapabilityOperationResult =
  | { readonly kind: 'claimed'; readonly use: ClaimedCapabilityGrantUse }
  | { readonly kind: 'operation_in_progress'; readonly use: ClaimedCapabilityGrantUse }
  | { readonly kind: 'replayed'; readonly use: CompletedCapabilityGrantUse }
  | {
      readonly kind:
        | 'grant_exhausted'
        | 'grant_expired'
        | 'grant_mismatch'
        | 'wallet_session_quota_exhausted'
        | 'wallet_session_expired'
        | 'wallet_session_mismatch';
    };

export type CompleteCapabilityOperationResult =
  | { readonly kind: 'completed'; readonly use: CompletedCapabilityGrantUse }
  | { readonly kind: 'already_completed'; readonly use: CompletedCapabilityGrantUse }
  | { readonly kind: 'claim_missing' }
  | { readonly kind: 'claim_mismatch' };

type AuthorizationAuditEventBase = {
  readonly kind: 'authorization_audit_event';
  readonly tenantId: TenantId;
  readonly eventId: AuthorizationAuditEventId;
  readonly principalId: PrincipalId;
  readonly grantId: CapabilityGrantId;
  readonly useId: CapabilityGrantUseId;
  readonly capabilityId: CapabilityId;
  readonly operationId: CapabilityOperationId;
  readonly operation: CapabilityOperationRef;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly evidenceSetDigest: DigestB64u;
  readonly result: 'claimed' | CompletedCapabilityOperationResult;
  readonly createdAtMs: number;
};

export type AuthorizationAuditEvent = AuthorizationAuditEventBase &
  (
    | {
        readonly authorization: {
          readonly kind: 'operation_step_up';
          readonly sessionId: SeamsSessionId;
          readonly deviceId: DeviceId;
        };
      }
    | {
        readonly authorization: {
          readonly kind: 'reusable_wallet_session';
          readonly walletSessionId: WalletSessionId;
        };
      }
  );

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

export function buildActiveCapabilityGrant(
  fields: ActiveCapabilityGrantInput,
): ActiveCapabilityGrant {
  requireOrderedTimes(fields.createdAtMs, fields.expiresAtMs, 'capability grant');
  requirePositiveCount(fields.remainingUses, 'capability grant remaining uses');
  if (fields.remainingUses !== 1) {
    throw new Error('capability grants require exactly one use');
  }
  switch (fields.authority.kind) {
    case 'reusable_wallet_session':
      return {
        kind: 'active_capability_grant',
        tenantId: fields.tenantId,
        principalId: fields.principalId,
        grantId: fields.grantId,
        bindingId: fields.bindingId,
        evidenceSetId: fields.evidenceSetId,
        evidenceSetDigest: fields.evidenceSetDigest,
        capabilityId: fields.capabilityId,
        operationId: fields.operationId,
        operation: fields.operation,
        laneDigest: fields.laneDigest,
        intentDigest: fields.intentDigest,
        displayDigest: fields.displayDigest,
        authority: fields.authority,
        remainingUses: fields.remainingUses,
        createdAtMs: fields.createdAtMs,
        expiresAtMs: fields.expiresAtMs,
      };
    case 'operation_step_up':
      return {
        kind: 'active_capability_grant',
        tenantId: fields.tenantId,
        principalId: fields.principalId,
        grantId: fields.grantId,
        bindingId: fields.bindingId,
        evidenceSetId: fields.evidenceSetId,
        evidenceSetDigest: fields.evidenceSetDigest,
        capabilityId: fields.capabilityId,
        operationId: fields.operationId,
        operation: fields.operation,
        laneDigest: fields.laneDigest,
        intentDigest: fields.intentDigest,
        displayDigest: fields.displayDigest,
        authority: fields.authority,
        remainingUses: 1,
        createdAtMs: fields.createdAtMs,
        expiresAtMs: fields.expiresAtMs,
      };
  }
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
  return {
    kind: 'wallet_session_authorization',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletId: fields.walletId,
    authority: fields.authority,
    mintId: fields.mintId,
    walletSessionId: fields.walletSessionId,
    quotaId: fields.quotaId,
    createdAtMs: fields.createdAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function operationConsumesWalletSessionQuota(operation: CapabilityOperationRef): boolean {
  switch (operation.capabilityKind) {
    case 'vault_access':
      return false;
    case 'near_ed25519_mpc_signing':
      return operation.operationKind !== 'near.export_key';
    case 'evm_ecdsa_mpc_signing':
      return operation.operationKind !== 'evm.export_key';
  }
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

export async function buildCapabilityOperationClaim(
  input: Omit<CapabilityOperationClaimInput, 'operationFingerprintDigest'>,
): Promise<CapabilityOperationClaim> {
  if (input.tenantId !== input.operation.tenantId) {
    throw new Error('capability operation claim tenant must match its operation envelope');
  }
  const operationFingerprintDigest = await computeCapabilityOperationFingerprintDigest(
    input.operation,
  );
  const consumesQuota = operationConsumesWalletSessionQuota(input.operation.operation);
  switch (input.authorization.kind) {
    case 'reusable_wallet_session':
      if (consumesQuota) {
        return {
          [capabilityOperationClaimBrand]: true,
          tenantId: input.tenantId,
          useId: input.useId,
          auditEventId: input.auditEventId,
          grantId: input.grantId,
          operation: input.operation,
          operationFingerprintDigest,
          evidenceSetDigest: input.evidenceSetDigest,
          claimedAtMs: input.claimedAtMs,
          authorization: input.authorization,
          quota: { kind: 'consume_reusable_wallet_session' },
        };
      }
      return {
        [capabilityOperationClaimBrand]: true,
        tenantId: input.tenantId,
        useId: input.useId,
        auditEventId: input.auditEventId,
        grantId: input.grantId,
        operation: input.operation,
        operationFingerprintDigest,
        evidenceSetDigest: input.evidenceSetDigest,
        claimedAtMs: input.claimedAtMs,
        authorization: input.authorization,
        quota: { kind: 'quota_neutral' },
      };
    case 'operation_step_up':
      return {
        [capabilityOperationClaimBrand]: true,
        tenantId: input.tenantId,
        useId: input.useId,
        auditEventId: input.auditEventId,
        grantId: input.grantId,
        operation: input.operation,
        operationFingerprintDigest,
        evidenceSetDigest: input.evidenceSetDigest,
        claimedAtMs: input.claimedAtMs,
        authorization: input.authorization,
        quota: { kind: 'quota_neutral' },
      };
  }
}
