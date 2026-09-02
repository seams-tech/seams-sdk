import type {
  EmailOtpWalletPostUnlockActivation,
  EmailOtpWalletPostUnlockActivationDeps,
} from './walletActivation';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { WalletAuthMethodId } from '@shared/utils/domainIds';

declare const deps: EmailOtpWalletPostUnlockActivationDeps;
declare const signer: NearEd25519SignerBinding;
declare const walletId: WalletId;
declare const walletAuthMethodId: WalletAuthMethodId;

const nearActivation: EmailOtpWalletPostUnlockActivation = {
  kind: 'near_ed25519_wallet',
  signer,
  walletAuthMethodId,
};

const ecdsaActivation: EmailOtpWalletPostUnlockActivation = {
  kind: 'evm_family_ecdsa_wallet',
  walletId,
  walletAuthMethodId,
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
  walletAuthMethodId,
  signer,
};

void missingSigner;
void mixedBranches;
