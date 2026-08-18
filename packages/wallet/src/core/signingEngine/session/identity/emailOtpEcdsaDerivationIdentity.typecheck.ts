import {
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
  type EmailOtpAuthSubjectId,
  type WalletSessionUserId,
} from './emailOtpEcdsaDerivationIdentity';

const walletSessionUserId = toWalletSessionUserId('wallet.testnet');
const authSubjectId = toEmailOtpAuthSubjectId('google:subject-1');

// @ts-expect-error provider-scoped Email OTP subjects cannot become wallet-scoped DERIVATION ids
const invalidWalletSessionUserId: WalletSessionUserId = authSubjectId;

// @ts-expect-error wallet-scoped DERIVATION ids cannot become provider auth subjects
const invalidAuthSubjectId: EmailOtpAuthSubjectId = walletSessionUserId;

void invalidWalletSessionUserId;
void invalidAuthSubjectId;

export {};
