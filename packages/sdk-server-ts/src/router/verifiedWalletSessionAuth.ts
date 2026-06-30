import type {
  RouterAbEcdsaHssWalletSessionClaims,
  RouterAbEd25519WalletSessionClaims,
} from '../core/ThresholdService/validation';

type BaseVerifiedWalletSessionAuth = {
  kind: 'wallet_session';
  curve: 'ecdsa' | 'ed25519';
  thresholdSessionId: string;
  signingGrantId: string;
  userId: string;
  relayerKeyId: string;
  participantIds: readonly number[];
  expiresAtMs: number;
};

export type VerifiedEcdsaWalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ecdsa';
  evmFamilySigningKeySlotId: string;
  keyHandle: string;
  rpId?: never;
  ed25519RelayerKeyId?: never;
};

export type VerifiedEd25519WalletSessionAuth = BaseVerifiedWalletSessionAuth & {
  curve: 'ed25519';
  rpId: string;
  ed25519RelayerKeyId: string;
  keyHandle?: never;
  evmFamilySigningKeySlotId?: never;
  ecdsaThresholdKeyId?: never;
};

export type VerifiedWalletSessionAuth =
  | VerifiedEcdsaWalletSessionAuth
  | VerifiedEd25519WalletSessionAuth;

export function buildVerifiedEcdsaWalletSessionAuth(
  claims: RouterAbEcdsaHssWalletSessionClaims,
): VerifiedEcdsaWalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ecdsa',
    thresholdSessionId: claims.thresholdSessionId,
    signingGrantId: claims.signingGrantId,
    userId: claims.walletId,
    evmFamilySigningKeySlotId: claims.evmFamilySigningKeySlotId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    keyHandle: claims.keyHandle,
  };
}

export function buildVerifiedEd25519WalletSessionAuth(
  claims: RouterAbEd25519WalletSessionClaims,
): VerifiedEd25519WalletSessionAuth {
  return {
    kind: 'wallet_session',
    curve: 'ed25519',
    thresholdSessionId: claims.thresholdSessionId,
    signingGrantId: claims.signingGrantId,
    userId: claims.walletId,
    rpId: claims.rpId,
    relayerKeyId: claims.relayerKeyId,
    participantIds: claims.participantIds,
    expiresAtMs: Math.floor(Number(claims.thresholdExpiresAtMs) || 0),
    ed25519RelayerKeyId: claims.relayerKeyId,
  };
}
