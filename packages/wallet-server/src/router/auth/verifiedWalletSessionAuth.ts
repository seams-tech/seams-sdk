import type { OpaqueOwnerWalletSessionBinding } from '../../authorization/service';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';

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
  /**
   * The manifest the wallet's key set for this curve was registered against.
   */
  keyManifestDigestB64u: DigestB64u;
};

export type VerifiedOwnerEcdsaWalletSessionAuth = OwnerVerifiedWalletSessionAuth & {
  curve: 'ecdsa';
  walletAuthAuthorityRef: WalletAuthAuthorityRef;
  authSource: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>['authSource'];
  keyHandle: string;
  rpId?: never;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEcdsaWalletSessionAuth = VerifiedOwnerEcdsaWalletSessionAuth;

export type VerifiedOwnerEd25519WalletSessionAuth = OwnerVerifiedWalletSessionAuth & {
  curve: 'ed25519';
  authority: WalletAuthAuthority;
  authorityScope: Extract<
    OpaqueOwnerWalletSessionBinding,
    { readonly curve: 'ed25519' }
  >['authorityScope'];
  ed25519RelayerKeyId: string;
  rpId?: never;
  keyHandle?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedEd25519WalletSessionAuth = VerifiedOwnerEd25519WalletSessionAuth;

export type VerifiedWalletSessionAuth =
  | VerifiedEcdsaWalletSessionAuth
  | VerifiedEd25519WalletSessionAuth;

export function buildVerifiedEcdsaWalletSessionAuth(
  session: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ecdsa' }>,
): VerifiedEcdsaWalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ecdsa',
    authorizationKind: 'owner_wallet_session',
    thresholdSessionId: session.thresholdSessionId,
    walletId: session.walletId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    userId: session.walletId,
    relayerKeyId: session.relayerKeyId,
    participantIds: session.participantIds,
    expiresAtMs: Math.floor(Number(session.thresholdExpiresAtMs) || 0),
    keyManifestDigestB64u: session.keyManifestDigestB64u,
    keyHandle: session.keyHandle,
    walletAuthAuthorityRef: session.walletAuthAuthorityRef,
    authSource: session.authSource,
  };
}

export function buildVerifiedEd25519WalletSessionAuth(
  session: Extract<OpaqueOwnerWalletSessionBinding, { readonly curve: 'ed25519' }>,
): VerifiedEd25519WalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ed25519',
    authorizationKind: 'owner_wallet_session',
    thresholdSessionId: session.thresholdSessionId,
    walletId: session.walletId,
    authorizationId: session.authorizationId,
    walletSessionId: session.walletSessionId,
    quotaId: session.quotaId,
    userId: session.walletId,
    authority: session.authority,
    authorityScope: session.authorityScope,
    relayerKeyId: session.relayerKeyId,
    participantIds: session.participantIds,
    expiresAtMs: Math.floor(Number(session.thresholdExpiresAtMs) || 0),
    keyManifestDigestB64u: session.keyManifestDigestB64u,
    ed25519RelayerKeyId: session.relayerKeyId,
  };
}
