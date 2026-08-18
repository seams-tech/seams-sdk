import type {
  EmailOtpWalletPostUnlockActivation,
  EmailOtpWalletPostUnlockActivationDeps,
} from './walletActivation';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

declare const deps: EmailOtpWalletPostUnlockActivationDeps;
declare const signer: NearEd25519SignerBinding;
declare const walletId: WalletId;

const nearActivation: EmailOtpWalletPostUnlockActivation = {
  kind: 'near_ed25519_wallet',
  signer,
};

const ecdsaActivation: EmailOtpWalletPostUnlockActivation = {
  kind: 'evm_family_ecdsa_wallet',
  walletId,
};

void deps;
void nearActivation;
void ecdsaActivation;

// @ts-expect-error An Ed25519 activation requires an exact signer binding.
const missingSigner: EmailOtpWalletPostUnlockActivation = { kind: 'near_ed25519_wallet' };

// @ts-expect-error EVM-family ECDSA activation cannot carry an Ed25519 signer.
const mixedBranches: EmailOtpWalletPostUnlockActivation = {
  kind: 'evm_family_ecdsa_wallet',
  walletId,
  signer,
};

void missingSigner;
void mixedBranches;
