import type {
  RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims,
  RouterAbEcdsaDerivationWalletSessionClaims,
  RouterAbEd25519LinkedDeviceWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
  LinkedDeviceWalletSessionPermissionClaimsV1,
} from '../../core/ThresholdService/validation';
import type { OpaqueOwnerWalletSessionBinding } from '../../authorization/service';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type {
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  WalletKeyId,
} from '@shared/utils/domainIds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { LinkedDeviceWalletSessionAuthorizationId } from '@shared/authorization/capabilityKinds';

type BaseVerifiedWalletSessionAuth = {
  kind: 'wallet_session';
  curve: 'ecdsa' | 'ed25519';
  authorizationKind: 'owner_wallet_session';
  thresholdSessionId: string;
  walletId: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  userId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

type OwnerVerifiedWalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  authorizationKind: 'owner_wallet_session';
  authorizationId: WalletSessionAuthorizationId;
  linkedDevice?: never;
};

type LinkedVerifiedWalletSessionBase = {
  kind: 'wallet_session';
  curve: 'ecdsa' | 'ed25519';
  authorizationKind: 'linked_device_wallet_session';
  walletId: string;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  userId: string;
  authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  tenantId: TenantId;
  deviceId: LinkedDeviceId;
  enrollmentId: LinkedDeviceEnrollmentId;
  walletKeyId: WalletKeyId;
  keyManifestDigestB64u: DigestB64u;
  revocationEpoch: number;
  permission: LinkedDeviceWalletSessionPermissionClaimsV1;
  issuedAtMs: number;
  expiresAtMs: number;
  iat: number;
  exp: number;
  nbf?: number;
  linkedDevice?: {
    readonly deviceId: LinkedDeviceId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
  };
};

export type VerifiedOwnerEcdsaWalletSessionAuth = OwnerVerifiedWalletSessionAuth & {
  curve: 'ecdsa';
  walletAuthAuthorityRef: WalletAuthAuthorityRef;
  authSource: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'];
  keyHandle: string;
  rpId?: never;
  ed25519RelayerKeyId?: never;
};

export type VerifiedLinkedDeviceEcdsaWalletSessionAuth = LinkedVerifiedWalletSessionBase & {
  curve: 'ecdsa';
  keyHandle?: never;
  walletAuthAuthorityRef?: never;
  authSource?: never;
  rpId?: never;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEcdsaWalletSessionAuth =
  | VerifiedOwnerEcdsaWalletSessionAuth
  | VerifiedLinkedDeviceEcdsaWalletSessionAuth;

export type VerifiedOwnerEd25519WalletSessionAuth = OwnerVerifiedWalletSessionAuth & {
  curve: 'ed25519';
  authority: WalletAuthAuthority;
  authorityScope: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>['authorityScope'];
  ed25519RelayerKeyId: string;
  rpId?: never;
  keyHandle?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedLinkedDeviceEd25519WalletSessionAuth = LinkedVerifiedWalletSessionBase & {
  curve: 'ed25519';
  ed25519RelayerKeyId?: never;
  authority?: never;
  authorityScope?: never;
  rpId?: never;
  keyHandle?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedEd25519WalletSessionAuth =
  | VerifiedOwnerEd25519WalletSessionAuth
  | VerifiedLinkedDeviceEd25519WalletSessionAuth;

export type VerifiedWalletSessionAuth =
  | VerifiedEcdsaWalletSessionAuth
  | VerifiedEd25519WalletSessionAuth;

function buildVerifiedLinkedDeviceBase(
  claims:
    | RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims
    | RouterAbEd25519LinkedDeviceWalletSessionClaims,
): LinkedVerifiedWalletSessionBase {
  return {
    kind: 'wallet_session',
    curve: claims.kind === 'router_ab_ecdsa_derivation_wallet_session_v1' ? 'ecdsa' : 'ed25519',
    authorizationKind: 'linked_device_wallet_session',
    walletId: claims.walletId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    userId: claims.walletId,
    authorizationId: claims.authorizationId,
    tenantId: claims.tenantId,
    deviceId: claims.deviceId,
    enrollmentId: claims.enrollmentId,
    walletKeyId: claims.walletKeyId,
    keyManifestDigestB64u: claims.keyManifestDigestB64u,
    revocationEpoch: claims.revocationEpoch,
    permission: claims.permission,
    issuedAtMs: claims.issuedAtMs,
    expiresAtMs: claims.expiresAtMs,
    iat: claims.iat,
    exp: claims.exp,
    ...(claims.nbf === undefined ? {} : { nbf: claims.nbf }),
    linkedDevice: {
      deviceId: claims.deviceId,
      enrollmentId: claims.enrollmentId,
    },
  };
}

export function buildVerifiedEcdsaWalletSessionAuth(
  claims: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>,
): VerifiedOwnerEcdsaWalletSessionAuth;
export function buildVerifiedEcdsaWalletSessionAuth(
  claims: RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims,
): VerifiedLinkedDeviceEcdsaWalletSessionAuth;
export function buildVerifiedEcdsaWalletSessionAuth(
  claims:
    | Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>
    | RouterAbEcdsaDerivationLinkedDeviceWalletSessionClaims,
): VerifiedEcdsaWalletSessionAuth {
  if (claims.authorizationKind === 'linked_device_wallet_session') {
    return {
      ...buildVerifiedLinkedDeviceBase(claims),
      curve: 'ecdsa',
    };
  }
  return {
    kind: 'wallet_session',
    curve: 'ecdsa',
    authorizationKind: 'owner_wallet_session',
    thresholdSessionId: claims.thresholdSessionId,
    walletId: claims.walletId,
    authorizationId: claims.authorizationId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    userId: claims.walletId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    keyHandle: claims.keyHandle,
    walletAuthAuthorityRef: claims.walletAuthAuthorityRef,
    authSource: claims.authSource,
  };
}

export function buildVerifiedEd25519WalletSessionAuth(
  claims: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>,
): VerifiedOwnerEd25519WalletSessionAuth;
export function buildVerifiedEd25519WalletSessionAuth(
  claims: RouterAbEd25519LinkedDeviceWalletSessionClaims,
): VerifiedLinkedDeviceEd25519WalletSessionAuth;
export function buildVerifiedEd25519WalletSessionAuth(
  claims:
    | Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>
    | RouterAbEd25519LinkedDeviceWalletSessionClaims,
): VerifiedEd25519WalletSessionAuth {
  if (claims.authorizationKind === 'linked_device_wallet_session') {
    return {
      ...buildVerifiedLinkedDeviceBase(claims),
      curve: 'ed25519',
    };
  }
  return {
    kind: 'wallet_session',
    curve: 'ed25519',
    authorizationKind: 'owner_wallet_session',
    thresholdSessionId: claims.thresholdSessionId,
    walletId: claims.walletId,
    authorizationId: claims.authorizationId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    userId: claims.walletId,
    authority: claims.authority,
    authorityScope: claims.authorityScope,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    ed25519RelayerKeyId: claims.relayerKeyId,
  };
}
