import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EcdsaThresholdKeyId } from '../keyMaterialBrands';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import type { SignerSlot } from '@shared/utils/signerSlot';
import type { CapabilityInstanceRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';

export type NearEd25519WalletUnlockSubject = {
  readonly kind: 'near_ed25519_wallet';
  readonly walletId: WalletId;
  readonly nearAccountId: AccountId;
  readonly nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  readonly signerSlot: SignerSlot;
  readonly ecdsaThresholdKeyId?: never;
};

export type EvmFamilyEcdsaWalletUnlockSubject = {
  readonly kind: 'evm_family_ecdsa_wallet';
  readonly walletId: WalletId;
  readonly capability: CapabilityInstanceRef;
  readonly authority: WalletAuthAuthorityRef;
  readonly ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  readonly nearAccountId?: never;
  readonly nearEd25519SigningKeyId?: never;
  readonly signerSlot?: never;
};

export type WalletUnlockSubject =
  | NearEd25519WalletUnlockSubject
  | EvmFamilyEcdsaWalletUnlockSubject;

export type WalletUnlockSubjectSet = {
  readonly kind: 'wallet_unlock_subject_set';
  readonly walletId: WalletId;
  readonly subjects: readonly [WalletUnlockSubject, ...WalletUnlockSubject[]];
};

export type EvmFamilyEcdsaWalletUnlockSubjectSet = {
  readonly kind: 'wallet_unlock_subject_set';
  readonly walletId: WalletId;
  readonly subjects: readonly [
    EvmFamilyEcdsaWalletUnlockSubject,
    ...EvmFamilyEcdsaWalletUnlockSubject[],
  ];
};
