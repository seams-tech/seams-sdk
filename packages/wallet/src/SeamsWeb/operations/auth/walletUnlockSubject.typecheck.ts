import { parseWalletAuthMethodId } from '@shared/utils/domainIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseEcdsaThresholdKeyId } from '@/core/signingEngine/session/keyMaterialBrands';
import { toAccountId } from '@/core/types/accountIds';
import {
  parseCapabilityInstanceRef,
  parseWalletAuthorityBindingDigest,
} from '@shared/utils/domainIds';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';
import {
  resolveWalletUnlockSubjectSet,
  type WalletUnlockSubject,
  type WalletUnlockSubjectSet,
} from './walletUnlockSubject';

const walletId = toWalletId('wallet-unlock-typecheck');
const ecdsaThresholdKeyId = parseEcdsaThresholdKeyId('ecdsa-threshold-key-typecheck');
const capability = parseCapabilityInstanceRef('ecdsa-capability-typecheck');
const authorityDigest = parseWalletAuthorityBindingDigest('ecdsa-authority-typecheck');
if (!capability.ok || !authorityDigest.ok) {
  throw new Error('type fixture requires valid ECDSA capability identity');
}
const signerSlot = parseSignerSlot(1);
if (!signerSlot) throw new Error('type fixture requires a valid signer slot');

const walletAuthMethodId = parseWalletAuthMethodId('passkey:wallet.example.test:typecheck');
if (!walletAuthMethodId.ok) {
  throw new Error('type fixture requires a valid wallet auth-method identity');
}
const ecdsaSubject: WalletUnlockSubject = {
  kind: 'evm_family_ecdsa_wallet',
  walletId,
  capability: capability.value,
  authority: {
    kind: 'wallet_auth_authority_ref',
    walletAuthMethodId: walletAuthMethodId.value,
    walletId,
    authorityDigest: authorityDigest.value,
  },
  ecdsaThresholdKeyId,
};

const subjectSet: WalletUnlockSubjectSet = {
  kind: 'wallet_unlock_subject_set',
  walletId,
  subjects: [ecdsaSubject],
};

void subjectSet;

const emptySubjectSet: WalletUnlockSubjectSet = {
  kind: 'wallet_unlock_subject_set',
  walletId,
  // @ts-expect-error a resolved subject set must contain at least one exact capability subject
  subjects: [],
};

void emptySubjectSet;

resolveWalletUnlockSubjectSet({
  walletId,
  requestedCapabilityFamilies: { kind: 'evm_family_ecdsa_only' },
});

// @ts-expect-error subject resolution requires an explicit requested capability-family scope
resolveWalletUnlockSubjectSet({ walletId });

const legacySlotSubject: WalletUnlockSubject = {
  kind: 'evm_family_ecdsa_wallet',
  walletId,
  // @ts-expect-error ECDSA subjects use exact threshold key identity, never a signing-key slot
  evmFamilySigningKeySlotId: 'wallet-key:legacy-slot',
};

void legacySlotSubject;

const broadMixedEcdsaSubject = {
  kind: 'evm_family_ecdsa_wallet' as const,
  walletId,
  ecdsaThresholdKeyId,
  nearAccountId: toAccountId('alice.testnet'),
};

// @ts-expect-error broad values cannot combine ECDSA and NEAR capability identity
const rejectedMixedEcdsaSubject: WalletUnlockSubject = broadMixedEcdsaSubject;
void rejectedMixedEcdsaSubject;

const broadMixedNearSubject = {
  kind: 'near_ed25519_wallet' as const,
  walletId,
  nearAccountId: toAccountId('alice.testnet'),
  nearEd25519SigningKeyId: parseNearEd25519SigningKeyId('near-key-typecheck'),
  signerSlot,
  ecdsaThresholdKeyId,
};

// @ts-expect-error broad values cannot combine NEAR and ECDSA capability identity
const rejectedMixedNearSubject: WalletUnlockSubject = broadMixedNearSubject;
void rejectedMixedNearSubject;
