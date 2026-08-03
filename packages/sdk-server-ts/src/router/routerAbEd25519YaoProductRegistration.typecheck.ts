import type { RouterAbEd25519YaoWalletSessionMintInputV1 } from './routerAbEd25519YaoProductRegistration';

type VerifiedWalletUnlockSessionMintInput = Extract<
  RouterAbEd25519YaoWalletSessionMintInputV1,
  { readonly kind: 'verified_wallet_unlock_v1' }
>;

declare const verifiedWalletUnlockIdentity: Omit<
  VerifiedWalletUnlockSessionMintInput,
  'kind' | 'expiresAtMs' | 'remainingUses'
>;

const validVerifiedWalletUnlockSessionMintInput: VerifiedWalletUnlockSessionMintInput = {
  ...verifiedWalletUnlockIdentity,
  kind: 'verified_wallet_unlock_v1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

const invalidRegistrationWalletSessionMintInput: RouterAbEd25519YaoWalletSessionMintInputV1 = {
  ...verifiedWalletUnlockIdentity,
  // @ts-expect-error Registration cannot mint a reusable Wallet Session.
  kind: 'registration_wallet_session_v1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

void validVerifiedWalletUnlockSessionMintInput;
void invalidRegistrationWalletSessionMintInput;
