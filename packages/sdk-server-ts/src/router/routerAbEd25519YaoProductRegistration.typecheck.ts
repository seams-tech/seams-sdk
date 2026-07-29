import type { RouterAbEd25519YaoWalletSessionMintInputV1 } from './routerAbEd25519YaoProductRegistration';

type RecoveryWalletSessionMintInput = Extract<
  RouterAbEd25519YaoWalletSessionMintInputV1,
  { readonly kind: 'shared_email_otp_recovery_wallet_session_v1' }
>;

declare const recoveryIdentity: Omit<
  RecoveryWalletSessionMintInput,
  'kind' | 'expiresAtMs' | 'remainingUses'
>;

const validRecoveryWalletSessionMintInput: RecoveryWalletSessionMintInput = {
  ...recoveryIdentity,
  kind: 'shared_email_otp_recovery_wallet_session_v1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

const invalidRegistrationWalletSessionMintInput: RouterAbEd25519YaoWalletSessionMintInputV1 = {
  ...recoveryIdentity,
  // @ts-expect-error Registration cannot mint a reusable Wallet Session.
  kind: 'registration_wallet_session_v1',
  expiresAtMs: 1_900_000_000_000,
  remainingUses: 3,
};

void validRecoveryWalletSessionMintInput;
void invalidRegistrationWalletSessionMintInput;
