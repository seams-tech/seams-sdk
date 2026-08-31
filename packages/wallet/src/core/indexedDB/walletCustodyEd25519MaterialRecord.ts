import { base58Encode } from '@shared/utils/base58';
import { base64UrlDecode } from '@shared/utils/base64';
import { buildEnvelopeAAD, KEY_PAYLOAD_ENC_VERSION } from './keyMaterialEnvelope';
import type { KeyMaterialRecord } from './keyMaterial.types';

export const WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND =
  'wallet_custody_ed25519_active_client_v1' as const;

export const WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM =
  'chacha20poly1305-hkdf-sha256-wallet-custody-seed-v1' as const;

const WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION = 1;

export type WalletCustodyEd25519MaterialBindingV1 = {
  readonly kind: typeof WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND;
  readonly applicationBindingDigestB64u: string;
  readonly registeredPublicKeyB64u: string;
  readonly participantIds: readonly [number, number];
  readonly stateEpoch: string;
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly signerSlot: number;
  readonly signingWorkerId: string;
  readonly signingWorkerVerifyingShareB64u: string;
};

export type WalletCustodySealedEd25519MaterialV1 = {
  readonly ciphertextB64u: string;
  readonly nonceB64u: string;
};

export type WalletCustodyEd25519MaterialTargetV1 = {
  readonly profileId: string;
  readonly chainIdKey: string;
  readonly accountAddress: string;
};

/** Rejects a row binding that cannot be found or reopened after persistence. */
export function assertWalletCustodyEd25519MaterialBindingV1(
  binding: WalletCustodyEd25519MaterialBindingV1,
): void {
  for (const [label, value] of [
    ['walletId', binding.walletId],
    ['nearAccountId', binding.nearAccountId],
    ['nearEd25519SigningKeyId', binding.nearEd25519SigningKeyId],
    ['signingWorkerId', binding.signingWorkerId],
    ['applicationBindingDigestB64u', binding.applicationBindingDigestB64u],
    ['signingWorkerVerifyingShareB64u', binding.signingWorkerVerifyingShareB64u],
    ['stateEpoch', binding.stateEpoch],
  ] as const) {
    if (!String(value || '').trim()) {
      throw new Error(`Wallet custody Ed25519 material binding requires ${label}`);
    }
  }
  if (binding.participantIds.length !== 2) {
    throw new Error('Wallet custody Ed25519 material binding requires exactly two participants');
  }
}

/** Builds the IndexedDB row from material already sealed by the custody ceremony. */
export function buildWalletCustodyEd25519MaterialRecordV1(input: {
  readonly target: WalletCustodyEd25519MaterialTargetV1;
  readonly binding: WalletCustodyEd25519MaterialBindingV1;
  readonly sealed: WalletCustodySealedEd25519MaterialV1;
}): KeyMaterialRecord {
  const { binding, sealed, target } = input;
  assertWalletCustodyEd25519MaterialBindingV1(binding);
  const registeredPublicKey = base64UrlDecode(binding.registeredPublicKeyB64u);
  if (registeredPublicKey.length !== 32) {
    throw new Error('Wallet custody Ed25519 material requires a 32-byte registered public key');
  }
  if (!sealed.ciphertextB64u || !sealed.nonceB64u) {
    throw new Error('Wallet custody Ed25519 material requires its sealed ciphertext and nonce');
  }

  return {
    profileId: target.profileId,
    signerSlot: binding.signerSlot,
    chainIdKey: target.chainIdKey,
    accountAddress: target.accountAddress,
    keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    algorithm: 'ed25519',
    publicKey: `ed25519:${base58Encode(registeredPublicKey)}`,
    signerId: binding.nearEd25519SigningKeyId,
    payload: { binding },
    payloadEnvelope: {
      encVersion: KEY_PAYLOAD_ENC_VERSION,
      alg: WALLET_CUSTODY_ED25519_MATERIAL_ALGORITHM,
      nonce: sealed.nonceB64u,
      ciphertext: sealed.ciphertextB64u,
      aad: buildEnvelopeAAD({
        profileId: target.profileId,
        signerSlot: binding.signerSlot,
        chainIdKey: target.chainIdKey,
        accountAddress: target.accountAddress,
        keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
        schemaVersion: WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION,
        signerId: binding.nearEd25519SigningKeyId,
      }),
    },
    timestamp: Date.now(),
    schemaVersion: WALLET_CUSTODY_ED25519_MATERIAL_SCHEMA_VERSION,
  };
}
