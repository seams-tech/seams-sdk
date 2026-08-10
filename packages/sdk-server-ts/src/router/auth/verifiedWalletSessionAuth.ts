import type {
  RouterAbEcdsaDerivationWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../../core/ThresholdService/validation';
import type {
  WalletAuthAuthority,
  WalletAuthAuthorityRef,
} from '@shared/utils/walletAuthAuthority';
import type {
  MpcWalletSigningQuotaId,
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';

type BaseVerifiedWalletSessionAuth = {
  kind: 'wallet_session';
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  authorizationId: WalletSessionAuthorizationId;
  walletSessionId: WalletSessionId;
  quotaId: MpcWalletSigningQuotaId;
  userId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

export type VerifiedEcdsaWalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ecdsa';
  walletAuthAuthorityRef: WalletAuthAuthorityRef;
  authSource: RouterAbEcdsaDerivationWalletSessionClaims['authSource'];
  keyHandle: string;
  rpId?: never;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEd25519WalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ed25519';
  authority: WalletAuthAuthority;
  authorityScope?: never;
  ed25519RelayerKeyId: string;
  rpId?: never;
  keyHandle?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedWalletSessionAuth =
  | VerifiedEcdsaWalletSessionAuth
  | VerifiedEd25519WalletSessionAuth;

export function buildVerifiedEcdsaWalletSessionAuth(
  claims: RouterAbEcdsaDerivationWalletSessionClaims,
): VerifiedEcdsaWalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ecdsa',
    thresholdSessionId: claims.thresholdSessionId,
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
  claims: RouterAbEd25519WalletSessionClaims,
): VerifiedEd25519WalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ed25519',
    thresholdSessionId: claims.thresholdSessionId,
    authorizationId: claims.authorizationId,
    walletSessionId: claims.walletSessionId,
    quotaId: claims.quotaId,
    userId: claims.walletId,
    authority: claims.authority,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    ed25519RelayerKeyId: claims.relayerKeyId,
  };
}
