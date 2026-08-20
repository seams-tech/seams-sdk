import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseAuthorizationGrantRef,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseTenantId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationRef,
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  WalletSessionAuthorizationId,
  LinkedDeviceWalletSessionAuthorizationId,
  AuthorizationEvidenceId,
  AuthorizationEvidenceKind,
  HostedWalletSessionExchangeCodeId,
  MpcWalletSigningQuotaId,
  PrincipalId,
  ReusableWalletSessionMintId,
  TenantId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
export {
  parseMpcWalletSigningQuotaId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
export type {
  LinkedDeviceWalletSessionAuthorizationId,
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';
import { computeCapabilityOperationFingerprintDigest } from '@shared/authorization/operationFingerprint';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseWalletId,
  type DomainId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type WalletId,
} from '@shared/utils/domainIds';
import type { ProviderSubject, WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type {
  AuthFactorIdentity,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import {
  parseDelegatedWalletAuthorityV1,
  type DelegatedWalletAuthorityV1,
} from '@shared/authorization/delegatedAuthority';

/** A server-only identity for one consumed owner authentication result. */
export type VerifiedOwnerProofId = DomainId<'VerifiedOwnerProofId'>;

export type HostedWalletSeamsSessionExchangeCode = DomainId<'HostedWalletSeamsSessionExchangeCode'>;
export type HostedWalletSeamsSessionExchangeNonce =
  DomainId<'HostedWalletSeamsSessionExchangeNonce'>;
export type SessionOrigin = DomainId<'SessionOrigin'>;
export type {
  CapabilityOperationEnvelope,
  CapabilityOperationFingerprintDigest,
} from '@shared/authorization/operationFingerprint';

export type OwnerOperationBinding = {
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly operation: CapabilityOperationRef;
  readonly laneDigest: DigestB64u;
  readonly intentDigest: DigestB64u;
  readonly displayDigest: DigestB64u;
};

export type VerifiedOwnerProofMethod = AuthFactorIdentity['kind'];

export type VerifiedOwnerProofCommon = {
  readonly kind: 'verified_owner_proof_v1';
  readonly proofId: VerifiedOwnerProofId;
  readonly method: VerifiedOwnerProofMethod;
  readonly authSource:
    | { readonly kind: 'passkey'; readonly credentialIdB64u: WebAuthnCredentialIdB64u }
    | {
        readonly kind: 'oidc_provider';
        readonly providerId: 'google_oidc' | 'oidc';
        readonly providerSubject: ProviderSubject;
      };
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authority: WalletAuthAuthorityRef;
  readonly origin: SessionOrigin;
  readonly audience: SessionOrigin;
  readonly replayIdentity: string;
  readonly verifiedAtMs: number;
  readonly expiresAtMs: number;
};

export type VerifiedOwnerProofFields = VerifiedOwnerProofCommon &
  (
    | {
        readonly purpose: 'wallet_session';
        readonly operation?: never;
      }
    | {
        readonly purpose: 'operation';
        readonly operation: OwnerOperationBinding;
      }
  );

export type { VerifiedOwnerProof } from './factorEvidence';

export type IssuedHostedWalletSeamsSessionExchange = {
  readonly kind: 'issued_hosted_wallet_session_exchange';
  readonly tenantId: TenantId;
  readonly exchangeCodeId: HostedWalletSessionExchangeCodeId;
  readonly walletSessionId: WalletSessionId;
  readonly codeHash: DigestB64u;
  readonly nonceDigest: DigestB64u;
  readonly appOrigin: SessionOrigin;
  readonly walletOrigin: SessionOrigin;
  readonly curve: 'ecdsa' | 'ed25519';
  readonly bindingJson: string;
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

export type HostedWalletSeamsSessionExchangeRejection = {
  readonly kind:
    | 'invalid_code'
    | 'expired'
    | 'already_consumed'
    | 'nonce_mismatch'
    | 'app_origin_mismatch'
    | 'wallet_session_unavailable';
};

export type PersistedHostedWalletSeamsSessionExchangeResult =
  | {
      readonly kind: 'redeemed';
      readonly tenantId: TenantId;
      readonly walletSessionId: WalletSessionId;
      readonly curve: 'ecdsa' | 'ed25519';
      readonly expiresAtMs: number;
    }
  | HostedWalletSeamsSessionExchangeRejection;

export type RedeemHostedWalletSeamsSessionExchangeResult =
  | {
      readonly kind: 'redeemed';
      readonly walletSessionId: WalletSessionId;
      readonly walletSessionToken: string;
      readonly curve: 'ecdsa' | 'ed25519';
      readonly expiresAtMs: number;
    }
  | HostedWalletSeamsSessionExchangeRejection;

export type RedeemHostedWalletSeamsSessionExchangeInput = {
  readonly codeHash: DigestB64u;
  readonly nonceDigest: DigestB64u;
  readonly appOrigin: SessionOrigin;
  readonly walletOrigin: SessionOrigin;
  readonly tokenHash: DigestB64u;
  readonly curve: 'ecdsa' | 'ed25519';
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

export type LinkedDeviceWalletSessionPermissionV1 = DelegatedWalletAuthorityV1;

export type LinkedDeviceWalletSessionAuthorizationV1 = {
  readonly kind: 'linked_device_wallet_session_authorization_v1';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly authorizationGrantRef: Extract<
    AuthorizationGrantRef,
    { readonly kind: 'linked_device_wallet_session_authorization_v1' }
  >;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly permission: LinkedDeviceWalletSessionPermissionV1;
  readonly revocationEpoch: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type LinkedDeviceWalletSessionAuthorization = LinkedDeviceWalletSessionAuthorizationV1;
export type AuthorizationGrant =
  | WalletSessionAuthorization
  | LinkedDeviceWalletSessionAuthorizationV1;

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

export type OwnerOperationStepUpReason =
  | 'wallet_session_missing'
  | 'wallet_session_expired'
  | 'wallet_session_exhausted'
  | 'wallet_session_ended'
  | 'wallet_session_superseded';

export type OwnerOperationAuthorizationDenial = {
  readonly code:
    | 'invalid_identity'
    | 'invalid_authority'
    | 'invalid_operation'
    | 'inactive_material'
    | 'replayed_step_up'
    | 'authorization_unavailable';
  readonly message: string;
};

export type OwnerOperationAuthorizationSource =
  | {
      readonly kind: 'authorization_grant';
      readonly authorizationGrantRef: Extract<
        AuthorizationGrantRef,
        { readonly kind: 'wallet_session_authorization' }
      >;
      readonly evidenceSetDigest?: never;
    }
  | Extract<OperationAuthorizationSource, { readonly kind: 'verified_step_up' }>;

export type OwnerOperationAuthorizationDecision<TStepUpPreparation> =
  | {
      readonly kind: 'authorized';
      readonly operation: AuthorizedOperation & { readonly lifecycle: 'claimed' };
      readonly source: OwnerOperationAuthorizationSource;
      readonly stepUp?: never;
      readonly denial?: never;
    }
  | {
      readonly kind: 'step_up_required';
      readonly reason: OwnerOperationStepUpReason;
      readonly stepUp: TStepUpPreparation;
      readonly operation?: never;
      readonly source?: never;
      readonly denial?: never;
    }
  | {
      readonly kind: 'denied';
      readonly denial: OwnerOperationAuthorizationDenial;
      readonly operation?: never;
      readonly source?: never;
      readonly stepUp?: never;
    };

type AuthorizedOperationLifecycle =
  | {
      readonly lifecycle: 'claimed';
      readonly result?: never;
      readonly response?: never;
      readonly resultDigest?: never;
      readonly completedAtMs?: never;
    }
  | {
      readonly lifecycle: 'completed';
      readonly result: CompletedCapabilityOperationResult;
      readonly response: AuthorizedOperationReplayResponse;
      readonly resultDigest: DigestB64u;
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

type AuthorizedOperationInputFields = {
  readonly tenantId: TenantId;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly auditEventId: AuthorizationAuditEventId;
  readonly claimedAtMs: number;
};

type NearOperationRef = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: typeof CAPABILITY_KINDS.nearEd25519MpcSigning }
>;
type EvmOperationRef = Extract<
  CapabilityOperationRef,
  { readonly capabilityKind: typeof CAPABILITY_KINDS.evmEcdsaMpcSigning }
>;
type ReusableSigningOperationRef =
  | (NearOperationRef & {
      readonly operationKind: Exclude<
        NearOperationRef['operationKind'],
        (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['exportKey']
      >;
    })
  | (EvmOperationRef & {
      readonly operationKind: Exclude<
        EvmOperationRef['operationKind'],
        (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['exportKey']
      >;
    });

type QuotaNeutralOperationRef =
  | Extract<
      CapabilityOperationRef,
      { readonly capabilityKind: typeof CAPABILITY_KINDS.vaultAccess }
    >
  | (NearOperationRef & {
      readonly operationKind: (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['exportKey'];
    })
  | (EvmOperationRef & {
      readonly operationKind: (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['exportKey'];
    });

type AuthorizationGrantSource = Extract<
  OperationAuthorizationSource,
  { readonly kind: 'authorization_grant' }
>;
type VerifiedStepUpSource = Extract<
  OperationAuthorizationSource,
  { readonly kind: 'verified_step_up' }
>;
type ConsumingQuota = {
  readonly kind: 'consume_reusable_wallet_session';
  readonly quotaId: MpcWalletSigningQuotaId;
};
type QuotaNeutral = { readonly kind: 'quota_neutral'; readonly quotaId?: never };

export type AuthorizedOperationInput =
  | (AuthorizedOperationInputFields & {
      readonly operation: CapabilityOperationEnvelope<ReusableSigningOperationRef>;
      readonly authorization: AuthorizationGrantSource;
      readonly quota: ConsumingQuota;
    })
  | (AuthorizedOperationInputFields & {
      readonly operation: CapabilityOperationEnvelope<QuotaNeutralOperationRef>;
      readonly authorization: AuthorizationGrantSource;
      readonly quota: QuotaNeutral;
    })
  | (AuthorizedOperationInputFields & {
      readonly operation: CapabilityOperationEnvelope;
      readonly authorization: VerifiedStepUpSource;
      readonly quota: QuotaNeutral;
    });

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

export type LinkedDeviceWalletSessionStatusIdentity = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly deviceId: LinkedDeviceId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly revocationEpoch: number;
};

export type LinkedDeviceWalletSessionStatus =
  | (LinkedDeviceWalletSessionStatusIdentity & {
      readonly kind: 'active';
      readonly remainingUses: number;
      readonly expiresAtMs: number;
    })
  | (LinkedDeviceWalletSessionStatusIdentity & {
      readonly kind: 'exhausted';
      readonly remainingUses: 0;
      readonly expiresAtMs: number;
    })
  | (LinkedDeviceWalletSessionStatusIdentity & {
      readonly kind: 'expired';
      readonly expiresAtMs: number;
      readonly remainingUses?: never;
    })
  | (LinkedDeviceWalletSessionStatusIdentity & {
      readonly kind: 'revoked';
      readonly revokedAtMs: number;
      readonly remainingUses?: never;
      readonly expiresAtMs: number;
    })
  | {
      readonly kind: 'missing' | 'invalid';
      readonly tenantId: TenantId;
      readonly principalId: PrincipalId;
      readonly deviceId: LinkedDeviceId;
      readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly remainingUses?: never;
      readonly expiresAtMs?: never;
    };

export type CompletedCapabilityOperationResult =
  | 'succeeded'
  | 'failed_before_side_effect'
  | 'failed_after_side_effect';

export type AuthorizedOperationReplayResponse = {
  readonly status: number;
  readonly contentType: string;
  readonly bodyText: string;
};

export const AUTHORIZED_OPERATION_REPLAY_BODY_MAX_BYTES = 64 * 1024;

const AUTHORIZED_OPERATION_RESULT_DIGEST_DOMAIN_V1 =
  'seams:authorization:authorized-operation-result:v1';

export function parseAuthorizedOperationReplayResponse(
  value: unknown,
): AuthorizedOperationReplayResponse {
  if (!isRecord(value)) {
    throw new Error('authorized operation replay response must be an object');
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== 3 || keys.join('|') !== 'bodyText|contentType|status') {
    throw new Error(
      'authorized operation replay response must contain only status, contentType, and bodyText',
    );
  }
  const status = value.status;
  if (typeof status !== 'number' || !Number.isSafeInteger(status) || status < 200 || status > 599) {
    throw new Error('authorized operation replay response status must be an HTTP status');
  }
  const contentType = value.contentType;
  if (
    typeof contentType !== 'string' ||
    contentType.length === 0 ||
    contentType.trim() !== contentType ||
    contentType.length > 255 ||
    // eslint-disable-next-line no-control-regex
    /[\u0000-\u001f\u007f]/.test(contentType)
  ) {
    throw new Error('authorized operation replay response contentType is invalid');
  }
  const bodyText = value.bodyText;
  if (typeof bodyText !== 'string') {
    throw new Error('authorized operation replay response bodyText must be text');
  }
  if (new TextEncoder().encode(bodyText).byteLength > AUTHORIZED_OPERATION_REPLAY_BODY_MAX_BYTES) {
    throw new Error('authorized operation replay response bodyText is too large');
  }
  if (responseStatusHasNoBody(status) && bodyText.length !== 0) {
    throw new Error('authorized operation replay response status cannot carry a body');
  }
  return { status, contentType, bodyText };
}

export function authorizedOperationReplayBodyInit(
  response: AuthorizedOperationReplayResponse,
): string | null {
  const parsed = parseAuthorizedOperationReplayResponse(response);
  return responseStatusHasNoBody(parsed.status) ? null : parsed.bodyText;
}

function responseStatusHasNoBody(status: number): boolean {
  return status === 204 || status === 205 || status === 304;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function computeAuthorizedOperationResultDigest(
  response: AuthorizedOperationReplayResponse,
): Promise<DigestB64u> {
  const parsed = parseAuthorizedOperationReplayResponse(response);
  return parseDigestB64u(
    base64UrlEncode(
      await sha256BytesUtf8(
        `${AUTHORIZED_OPERATION_RESULT_DIGEST_DOMAIN_V1}|${alphabetizeStringify(parsed)}`,
      ),
    ),
  );
}

export function parseHostedWalletSeamsSessionExchangeCode(
  value: unknown,
): HostedWalletSeamsSessionExchangeCode {
  return parseAuthorizationDomainId(value, 'hostedWalletSessionExchangeCode');
}

export function parseVerifiedOwnerProofId(value: unknown): VerifiedOwnerProofId {
  return parseAuthorizationDomainId(value, 'verifiedOwnerProofId');
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
    throw new Error(
      'authorization, Wallet Session, and quota identities must be pairwise distinct',
    );
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

export function buildLinkedDevicePrincipalId(deviceId: LinkedDeviceId): PrincipalId {
  const parsed = parsePrincipalId(`linked-device:${String(deviceId)}`);
  if (!parsed.ok) throw new Error('linked device principal identity is invalid');
  return parsed.value;
}

export function buildLinkedDeviceWalletSessionAuthorization(
  fields: Omit<LinkedDeviceWalletSessionAuthorizationV1, 'kind' | 'principalId'>,
): LinkedDeviceWalletSessionAuthorizationV1 {
  const principalId = buildLinkedDevicePrincipalId(fields.deviceId);
  requireOrderedTimes(fields.issuedAtMs, fields.expiresAtMs, 'linked-device Wallet Session');
  requireNonnegativeInteger(fields.revocationEpoch, 'linked-device revocation epoch');
  parseDigestB64u(fields.keyManifestDigestB64u);
  requireLinkedDeviceWalletSessionPermission(fields.permission);
  if (fields.authorizationGrantRef.kind !== 'linked_device_wallet_session_authorization_v1') {
    throw new Error('linked-device authorization must carry its linked grant reference');
  }
  if (
    String(fields.authorizationGrantRef.authorizationId) === String(fields.walletSessionId) ||
    String(fields.authorizationGrantRef.authorizationId) === String(fields.quotaId) ||
    String(fields.walletSessionId) === String(fields.quotaId)
  ) {
    throw new Error(
      'linked-device authorization, Wallet Session, and quota identities must be pairwise distinct',
    );
  }
  return {
    kind: 'linked_device_wallet_session_authorization_v1',
    tenantId: fields.tenantId,
    principalId,
    authorizationGrantRef: fields.authorizationGrantRef,
    walletId: fields.walletId,
    enrollmentId: fields.enrollmentId,
    deviceId: fields.deviceId,
    walletSessionId: fields.walletSessionId,
    quotaId: fields.quotaId,
    keyManifestDigestB64u: fields.keyManifestDigestB64u,
    permission: fields.permission,
    revocationEpoch: fields.revocationEpoch,
    issuedAtMs: fields.issuedAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function parseLinkedDeviceWalletSessionAuthorization(
  value: unknown,
): LinkedDeviceWalletSessionAuthorizationV1 {
  if (!isRecord(value)) throw new Error('linked-device authorization must be an object');
  const expectedKeys = [
    'authorizationGrantRef',
    'deviceId',
    'enrollmentId',
    'expiresAtMs',
    'issuedAtMs',
    'keyManifestDigestB64u',
    'kind',
    'permission',
    'principalId',
    'quotaId',
    'revocationEpoch',
    'tenantId',
    'walletId',
    'walletSessionId',
  ];
  const keys = Object.keys(value).sort();
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index])
  ) {
    throw new Error('linked-device authorization contains unexpected fields');
  }
  if (value.kind !== 'linked_device_wallet_session_authorization_v1') {
    throw new Error('linked-device authorization kind is invalid');
  }
  const grantRef = parseAuthorizationGrantRef(value.authorizationGrantRef);
  if (!grantRef.ok || grantRef.value.kind !== 'linked_device_wallet_session_authorization_v1') {
    throw new Error('linked-device authorization grant reference is invalid');
  }
  const tenantId = parseTenantIdRequired(value.tenantId);
  const principalId = parsePrincipalIdRequired(value.principalId);
  const deviceId = parseLinkedDeviceIdRequired(value.deviceId);
  const enrollmentId = parseLinkedDeviceEnrollmentIdRequired(value.enrollmentId);
  const walletId = parseWalletIdRequired(value.walletId);
  const walletSessionId = parseWalletSessionIdRequired(value.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaIdRequired(value.quotaId);
  const authorization = buildLinkedDeviceWalletSessionAuthorization({
    tenantId,
    authorizationGrantRef: grantRef.value,
    walletId,
    enrollmentId,
    deviceId,
    walletSessionId,
    quotaId,
    keyManifestDigestB64u: parseDigestB64u(value.keyManifestDigestB64u),
    permission: parseLinkedDeviceWalletSessionPermission(value.permission),
    revocationEpoch: requireNonnegativeInteger(
      value.revocationEpoch,
      'linked-device revocation epoch',
    ),
    issuedAtMs: requirePositiveTimestamp(value.issuedAtMs, 'linked-device issuedAtMs'),
    expiresAtMs: requirePositiveTimestamp(value.expiresAtMs, 'linked-device expiresAtMs'),
  });
  if (authorization.principalId !== principalId) {
    throw new Error('linked-device authorization principalId does not match deviceId');
  }
  return authorization;
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

function parseTenantIdRequired(value: unknown): TenantId {
  const parsed = parseTenantId(value);
  if (!parsed.ok) throw new Error(`linked-device authorization tenantId: ${parsed.error.message}`);
  return parsed.value;
}

function parsePrincipalIdRequired(value: unknown): PrincipalId {
  const parsed = parsePrincipalId(value);
  if (!parsed.ok) {
    throw new Error(`linked-device authorization principalId: ${parsed.error.message}`);
  }
  return parsed.value;
}

function parseLinkedDeviceIdRequired(value: unknown): LinkedDeviceId {
  const parsed = parseLinkedDeviceId(value);
  if (!parsed.ok) throw new Error(`linked-device authorization deviceId: ${parsed.error.message}`);
  return parsed.value;
}

function parseLinkedDeviceEnrollmentIdRequired(value: unknown): LinkedDeviceEnrollmentId {
  const parsed = parseLinkedDeviceEnrollmentId(value);
  if (!parsed.ok) {
    throw new Error(`linked-device authorization enrollmentId: ${parsed.error.message}`);
  }
  return parsed.value;
}

function parseWalletIdRequired(value: unknown): WalletId {
  const parsed = parseWalletId(value);
  if (!parsed.ok) throw new Error(`linked-device authorization walletId: ${parsed.error.message}`);
  return parsed.value;
}

function parseWalletSessionIdRequired(value: unknown): WalletSessionId {
  const parsed = parseWalletSessionId(value);
  if (!parsed.ok) {
    throw new Error(`linked-device authorization walletSessionId: ${parsed.error.message}`);
  }
  return parsed.value;
}

function parseMpcWalletSigningQuotaIdRequired(value: unknown): MpcWalletSigningQuotaId {
  const parsed = parseMpcWalletSigningQuotaId(value);
  if (!parsed.ok) {
    throw new Error(`linked-device authorization quotaId: ${parsed.error.message}`);
  }
  return parsed.value;
}

function parseLinkedDeviceWalletSessionPermission(
  value: unknown,
): LinkedDeviceWalletSessionPermissionV1 {
  const parsed = parseDelegatedWalletAuthorityV1(value);
  if (!parsed.ok) {
    throw new Error(`linked-device authorization permission: ${parsed.error.message}`);
  }
  return parsed.value;
}

function requireLinkedDeviceWalletSessionPermission(
  value: LinkedDeviceWalletSessionPermissionV1,
): void {
  parseLinkedDeviceWalletSessionPermission(value);
}

function requirePositiveCount(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

function requireNonnegativeInteger(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${label} must be a nonnegative safe integer`);
  }
  return value;
}

function requirePositiveTimestamp(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
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


function requireDomainIdParse(
  result: { readonly ok: true } | { readonly ok: false; readonly error: { message: string } },
  label: string,
): void {
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
}
