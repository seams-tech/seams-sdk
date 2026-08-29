import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
  parseMpcWalletSigningQuotaId,
  parsePrincipalId,
  parseReusableWalletSessionMintId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  CapabilityOperationRef,
  AuthorizationAuditEventId,
  AuthorizationGrantRef,
  AuthorizedOperationId,
  WalletSessionAuthorizationId,
  AuthorizationEvidenceId,
  AuthorizationEvidenceKind,
  HostedWalletSessionExchangeCodeId,
  MpcWalletSigningQuotaId,
  PrincipalId,
  ReusableWalletSessionMintId,
  TenantId,
  WalletSessionId,
  WalletSessionClientCapabilityV1,
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
import {
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  type DomainId,
  type MpcMaterialActivationRef,
  type WalletAuthMethodId,
  type WalletAuthorityId,
  type WalletId,
} from '@shared/utils/domainIds';
import type { ProviderSubject, WebAuthnCredentialIdB64u } from '@shared/utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { base64UrlEncode } from '@shared/utils/encoders';
import type { AuthFactorIdentity, WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import { mpcMaterialActivationRefsEqual } from '@shared/utils/domainIds';
import type {
  ActiveWalletAuthorityV1,
  WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import {
  parseActiveWalletSessionV1,
  type ActiveWalletSessionV1,
  type WalletSessionOperationCredentialV1,
} from '@shared/device-linking';

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

export type WalletSessionCapabilitySubjectV1 =
  | {
      readonly kind: 'sign';
      readonly keyFamily: 'ed25519';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'sign';
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'export_keys';
      readonly keyFamily: 'ed25519';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'export_keys';
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly kind: 'link_devices';
      readonly authorityId: WalletAuthorityId;
    }
  | {
      readonly kind: 'revoke_devices';
      readonly authorityId: WalletAuthorityId;
    };

export type WalletSessionCapabilitySubjectsV1 = readonly [
  WalletSessionCapabilitySubjectV1,
  ...WalletSessionCapabilitySubjectV1[],
];

export type WalletSessionAuthorizationV2 = {
  readonly kind: 'wallet_session_authorization_v2';
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly authorityDigestB64u: DigestB64u;
  readonly authorityRevocationEpoch: number;
  readonly mintId: ReusableWalletSessionMintId;
  readonly authorizationId: WalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly capabilitySubjects: WalletSessionCapabilitySubjectsV1;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type IssuedWalletSessionAuthorizationV2 = {
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
};

export function projectActiveWalletSession(
  issued: IssuedWalletSessionAuthorizationV2,
): ActiveWalletSessionV1 {
  const capabilitySubjects = issued.session.capabilitySubjects.map((subject) => {
    switch (subject.kind) {
      case 'sign':
      case 'export_keys':
        return {
          kind: subject.kind,
          keyFamily: subject.keyFamily,
          materialActivation: subject.materialActivation,
        };
      case 'link_devices':
      case 'revoke_devices':
        return { kind: subject.kind };
      default:
        throw new Error('Issued linked-device Wallet Session subject is invalid');
    }
  });
  const first = capabilitySubjects[0];
  if (!first) throw new Error('Issued linked-device Wallet Session has no subjects');
  return parseActiveWalletSessionV1({
    kind: 'active_wallet_session_v1',
    walletId: issued.session.walletId,
    authorityId: issued.session.authorityId,
    authMethodId: issued.session.walletAuthMethodId,
    authorizationId: issued.session.authorizationId,
    authorityDigestB64u: issued.session.authorityDigestB64u,
    authorityRevocationEpoch: issued.session.authorityRevocationEpoch,
    capabilitySubjects: [first, ...capabilitySubjects.slice(1)],
    issuedAtMs: issued.session.createdAtMs,
    expiresAtMs: issued.session.expiresAtMs,
  });
}

/** Exact response families are persisted so replay cannot cross route contracts. */
export const WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1 = 'wallet_unlock_exact_response_v1' as const;
export const WALLET_SYNC_EXACT_RESPONSE_FAMILY_V1 = 'wallet_sync_exact_response_v1' as const;
export const WALLET_REGISTRATION_EXACT_RESPONSE_FAMILY_V1 =
  'wallet_registration_exact_response_v1' as const;

export type WalletSessionIssuanceResponseFamilyV1 =
  | typeof WALLET_UNLOCK_EXACT_RESPONSE_FAMILY_V1
  | typeof WALLET_SYNC_EXACT_RESPONSE_FAMILY_V1
  | typeof WALLET_REGISTRATION_EXACT_RESPONSE_FAMILY_V1;

/**
 * The server-side aggregate that is safe to expose to persistence code after
 * an exact Wallet Session commit. The credential digest never crosses the
 * browser or wire response boundary.
 */
export type PersistedActiveWalletSessionAuthorizationV2 = {
  readonly kind: 'persisted_active_wallet_session_authorization_v2';
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
  readonly primaryOperationCredentialDigestB64u: DigestB64u;
  readonly walletSessionClientCapability: WalletSessionClientCapabilityV1;
  readonly responseFamily: WalletSessionIssuanceResponseFamilyV1;
  readonly retiredAtMs?: never;
};

export type WalletSessionAuthorizationV2MintLookup = {
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly walletId: WalletId;
  readonly authorityId: WalletAuthorityId;
  readonly walletAuthMethodId: WalletAuthMethodId;
  readonly mintId: ReusableWalletSessionMintId;
};

/**
 * A credential-free readback of one committed issuance attempt. It remains
 * readable after retirement so a retry can identify the original commit.
 */
export type WalletSessionAuthorizationV2MintRead = {
  readonly kind: 'committed';
  readonly session: WalletSessionAuthorizationV2;
  readonly primaryOperationCredentialDigestB64u: DigestB64u;
  readonly walletSessionClientCapability: WalletSessionClientCapabilityV1 | null;
  readonly responseFamily: string | null;
  readonly retiredAtMs: number | null;
};

export type DirectV2CommitResult =
  | { readonly kind: 'inserted' }
  | {
      readonly kind: 'already_committed';
      readonly committed: WalletSessionAuthorizationV2MintRead;
    };

export type DirectV2IssueResult =
  | {
      readonly kind: 'issued';
      readonly session: WalletSessionAuthorizationV2;
      readonly quota: ActiveWalletSessionQuota;
      readonly operationCredential: WalletSessionOperationCredentialV1;
    }
  | {
      readonly kind: 'already_committed';
      readonly walletId: WalletId;
      readonly authorityId: WalletAuthorityId;
      readonly walletAuthMethodId: WalletAuthMethodId;
      readonly mintId: ReusableWalletSessionMintId;
      readonly authorizationId: WalletSessionAuthorizationId;
      readonly walletSessionId: WalletSessionId;
      readonly quotaId: MpcWalletSigningQuotaId;
      readonly next: 'unlock_exact_method';
    }
  | {
      readonly kind: 'protocol_mismatch';
      readonly code: 'protocol_mismatch';
      readonly message: string;
    };

export function buildPersistedActiveWalletSessionAuthorizationV2(fields: {
  readonly session: WalletSessionAuthorizationV2;
  readonly quota: ActiveWalletSessionQuota;
  readonly primaryOperationCredentialDigestB64u: DigestB64u;
  readonly walletSessionClientCapability: WalletSessionClientCapabilityV1;
  readonly responseFamily: WalletSessionIssuanceResponseFamilyV1;
}): PersistedActiveWalletSessionAuthorizationV2 {
  if (
    fields.session.tenantId !== fields.quota.tenantId ||
    fields.session.principalId !== fields.quota.principalId ||
    fields.session.walletSessionId !== fields.quota.walletSessionId ||
    fields.session.quotaId !== fields.quota.quotaId ||
    fields.session.expiresAtMs !== fields.quota.expiresAtMs
  ) {
    throw new Error('V2 persisted active authorization and quota must have one exact identity');
  }
  parseDigestB64u(fields.primaryOperationCredentialDigestB64u);
  return {
    kind: 'persisted_active_wallet_session_authorization_v2',
    session: fields.session,
    quota: fields.quota,
    primaryOperationCredentialDigestB64u: fields.primaryOperationCredentialDigestB64u,
    walletSessionClientCapability: fields.walletSessionClientCapability,
    responseFamily: fields.responseFamily,
  };
}

type WalletSessionSignerSubjectKind = 'sign' | 'export_keys';

function appendWalletSessionSignerSubjects(
  subjects: WalletSessionCapabilitySubjectV1[],
  kind: WalletSessionSignerSubjectKind,
  signerActivations: WalletSignerActivationSetV1,
): void {
  if (
    signerActivations.keyFamilies.length === 1 &&
    signerActivations.keyFamilies[0] === 'ed25519'
  ) {
    if (!signerActivations.ed25519) {
      throw new Error('Ed25519 signer activation is missing');
    }
    subjects.push({
      kind,
      keyFamily: 'ed25519',
      materialActivation: signerActivations.ed25519.materialActivation,
    });
    return;
  }
  if (
    signerActivations.keyFamilies.length === 1 &&
    signerActivations.keyFamilies[0] === 'ecdsa_secp256k1'
  ) {
    if (!signerActivations.ecdsa) {
      throw new Error('ECDSA signer activation is missing');
    }
    subjects.push({
      kind,
      keyFamily: 'ecdsa_secp256k1',
      materialActivation: signerActivations.ecdsa.materialActivation,
    });
    return;
  }
  if (!signerActivations.ed25519 || !signerActivations.ecdsa) {
    throw new Error('both-family signer activations are incomplete');
  }
  subjects.push(
    {
      kind,
      keyFamily: 'ed25519',
      materialActivation: signerActivations.ed25519.materialActivation,
    },
    {
      kind,
      keyFamily: 'ecdsa_secp256k1',
      materialActivation: signerActivations.ecdsa.materialActivation,
    },
  );
}

export function buildWalletSessionCapabilitySubjectsV1(
  authority: ActiveWalletAuthorityV1,
): WalletSessionCapabilitySubjectsV1 {
  const subjects: WalletSessionCapabilitySubjectV1[] = [];
  if (authority.permissions.includes('sign')) {
    appendWalletSessionSignerSubjects(subjects, 'sign', authority.signerActivations);
  }
  if (authority.permissions.includes('export_keys')) {
    appendWalletSessionSignerSubjects(subjects, 'export_keys', authority.signerActivations);
  }
  if (authority.permissions.includes('link_devices')) {
    subjects.push({ kind: 'link_devices', authorityId: authority.authorityId });
  }
  if (authority.permissions.includes('revoke_devices')) {
    subjects.push({ kind: 'revoke_devices', authorityId: authority.authorityId });
  }
  const [firstSubject, ...remainingSubjects] = subjects;
  if (!firstSubject) {
    throw new Error('active wallet authority must produce capability subjects');
  }
  return [firstSubject, ...remainingSubjects];
}

export function buildWalletSessionAuthorizationV2(
  fields: Omit<WalletSessionAuthorizationV2, 'kind'>,
): WalletSessionAuthorizationV2 {
  requireNonnegativeInteger(
    fields.authorityRevocationEpoch,
    'Wallet Session authority revocation epoch',
  );
  parseDigestB64u(fields.authorityDigestB64u);
  if (fields.capabilitySubjects.length === 0) {
    throw new Error('Wallet Session capability subjects are required');
  }
  requireOrderedTimes(fields.createdAtMs, fields.expiresAtMs, 'Wallet Session authorization');
  const identityValues = [
    String(fields.authorizationId),
    String(fields.walletSessionId),
    String(fields.quotaId),
  ];
  if (new Set(identityValues).size !== identityValues.length) {
    throw new Error('Wallet Session authorization identities must be pairwise distinct');
  }
  return {
    kind: 'wallet_session_authorization_v2',
    tenantId: fields.tenantId,
    principalId: fields.principalId,
    walletId: fields.walletId,
    authorityId: fields.authorityId,
    walletAuthMethodId: fields.walletAuthMethodId,
    authorityDigestB64u: fields.authorityDigestB64u,
    authorityRevocationEpoch: fields.authorityRevocationEpoch,
    mintId: fields.mintId,
    authorizationId: fields.authorizationId,
    walletSessionId: fields.walletSessionId,
    quotaId: fields.quotaId,
    capabilitySubjects: fields.capabilitySubjects,
    createdAtMs: fields.createdAtMs,
    expiresAtMs: fields.expiresAtMs,
  };
}

export function walletSessionCapabilitySubjectsV1Equal(
  left: WalletSessionCapabilitySubjectsV1,
  right: WalletSessionCapabilitySubjectsV1,
): boolean {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index += 1) {
    const leftSubject = left[index];
    const rightSubject = right[index];
    if (!leftSubject || !rightSubject || leftSubject.kind !== rightSubject.kind) return false;
    switch (leftSubject.kind) {
      case 'sign':
      case 'export_keys':
        break;
      case 'link_devices':
      case 'revoke_devices':
        if (
          rightSubject.kind !== leftSubject.kind ||
          leftSubject.authorityId !== rightSubject.authorityId
        ) {
          return false;
        }
        break;
    }
    if (leftSubject.kind === 'sign' || leftSubject.kind === 'export_keys') {
      if (
        rightSubject.kind !== leftSubject.kind ||
        leftSubject.keyFamily !== rightSubject.keyFamily ||
        !mpcMaterialActivationRefsEqual(
          leftSubject.materialActivation,
          rightSubject.materialActivation,
        )
      ) {
        return false;
      }
    }
  }
  return true;
}

export function walletSessionAuthorizationV2RecordsEqual(
  left: WalletSessionAuthorizationV2,
  right: WalletSessionAuthorizationV2,
): boolean {
  return (
    left.kind === right.kind &&
    left.tenantId === right.tenantId &&
    left.principalId === right.principalId &&
    left.walletId === right.walletId &&
    left.authorityId === right.authorityId &&
    left.walletAuthMethodId === right.walletAuthMethodId &&
    left.authorityDigestB64u === right.authorityDigestB64u &&
    left.authorityRevocationEpoch === right.authorityRevocationEpoch &&
    left.mintId === right.mintId &&
    left.authorizationId === right.authorizationId &&
    left.walletSessionId === right.walletSessionId &&
    left.quotaId === right.quotaId &&
    walletSessionCapabilitySubjectsV1Equal(left.capabilitySubjects, right.capabilitySubjects) &&
    left.createdAtMs === right.createdAtMs &&
    left.expiresAtMs === right.expiresAtMs
  );
}

function hasExactFields(
  value: Record<string, unknown>,
  expectedFields: readonly string[],
): boolean {
  const fields = Object.keys(value).sort();
  const sortedExpectedFields = [...expectedFields].sort();
  return (
    fields.length === sortedExpectedFields.length &&
    fields.every((field, index) => field === sortedExpectedFields[index])
  );
}

function parseMpcMaterialActivationRefRequired(value: unknown): MpcMaterialActivationRef {
  const parsed = parseMpcMaterialActivationRef(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseWalletAuthorityIdRequired(value: unknown): WalletAuthorityId {
  const parsed = parseWalletAuthorityId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseWalletAuthMethodIdRequired(value: unknown): WalletAuthMethodId {
  const parsed = parseWalletAuthMethodId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function parseWalletSessionCapabilitySubject(value: unknown): WalletSessionCapabilitySubjectV1 {
  if (!isRecord(value) || typeof value.kind !== 'string') {
    throw new Error('Wallet Session capability subject must be an object');
  }
  switch (value.kind) {
    case 'sign':
    case 'export_keys': {
      if (!hasExactFields(value, ['kind', 'keyFamily', 'materialActivation'])) {
        throw new Error('Wallet Session signer capability subject contains unexpected fields');
      }
      if (value.keyFamily !== 'ed25519' && value.keyFamily !== 'ecdsa_secp256k1') {
        throw new Error('Wallet Session signer capability subject key family is invalid');
      }
      return {
        kind: value.kind,
        keyFamily: value.keyFamily,
        materialActivation: parseMpcMaterialActivationRefRequired(value.materialActivation),
      };
    }
    case 'link_devices':
    case 'revoke_devices':
      if (!hasExactFields(value, ['kind', 'authorityId'])) {
        throw new Error(
          'Wallet Session administration capability subject contains unexpected fields',
        );
      }
      return {
        kind: value.kind,
        authorityId: parseWalletAuthorityIdRequired(value.authorityId),
      };
    default:
      throw new Error('Wallet Session capability subject kind is unsupported');
  }
}

function parseWalletSessionCapabilitySubjects(value: unknown): WalletSessionCapabilitySubjectsV1 {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('Wallet Session capability subjects must be non-empty');
  }
  const subjects: WalletSessionCapabilitySubjectV1[] = [];
  for (const subject of value) {
    subjects.push(parseWalletSessionCapabilitySubject(subject));
  }
  const [firstSubject, ...remainingSubjects] = subjects;
  if (!firstSubject) throw new Error('Wallet Session capability subjects must be non-empty');
  return [firstSubject, ...remainingSubjects];
}

export function parseWalletSessionAuthorizationV2(value: unknown): WalletSessionAuthorizationV2 {
  if (
    !isRecord(value) ||
    !hasExactFields(value, [
      'kind',
      'tenantId',
      'principalId',
      'walletId',
      'authorityId',
      'walletAuthMethodId',
      'authorityDigestB64u',
      'authorityRevocationEpoch',
      'mintId',
      'authorizationId',
      'walletSessionId',
      'quotaId',
      'capabilitySubjects',
      'createdAtMs',
      'expiresAtMs',
    ])
  ) {
    throw new Error('Wallet Session authorization V2 contains unexpected fields');
  }
  if (value.kind !== 'wallet_session_authorization_v2') {
    throw new Error('Wallet Session authorization V2 kind is invalid');
  }
  const tenantId = parseTenantIdRequired(value.tenantId);
  const principalId = parsePrincipalIdRequired(value.principalId);
  const walletId = parseWalletIdRequired(value.walletId);
  const authorityId = parseWalletAuthorityIdRequired(value.authorityId);
  const walletAuthMethodId = parseWalletAuthMethodIdRequired(value.walletAuthMethodId);
  const authorityDigestB64u = parseDigestB64u(value.authorityDigestB64u);
  const mintIdResult = parseReusableWalletSessionMintId(value.mintId);
  if (!mintIdResult.ok) throw new Error(mintIdResult.error.message);
  const authorizationIdResult = parseWalletSessionAuthorizationId(value.authorizationId);
  if (!authorizationIdResult.ok) throw new Error(authorizationIdResult.error.message);
  const walletSessionId = parseWalletSessionIdRequired(value.walletSessionId);
  const quotaId = parseMpcWalletSigningQuotaIdRequired(value.quotaId);
  return buildWalletSessionAuthorizationV2({
    tenantId,
    principalId,
    walletId,
    authorityId,
    walletAuthMethodId,
    authorityDigestB64u,
    authorityRevocationEpoch: requireNonnegativeInteger(
      value.authorityRevocationEpoch,
      'Wallet Session authority revocation epoch',
    ),
    mintId: mintIdResult.value,
    authorizationId: authorizationIdResult.value,
    walletSessionId,
    quotaId,
    capabilitySubjects: parseWalletSessionCapabilitySubjects(value.capabilitySubjects),
    createdAtMs: requirePositiveTimestamp(value.createdAtMs, 'Wallet Session createdAtMs'),
    expiresAtMs: requirePositiveTimestamp(value.expiresAtMs, 'Wallet Session expiresAtMs'),
  });
}

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
