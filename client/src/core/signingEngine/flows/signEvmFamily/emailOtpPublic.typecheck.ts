import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EnrollEmailOtpInternalArgs } from './emailOtpPublic';

declare const walletId: WalletId;

const validEnrollEmailOtpInternalArgs: EnrollEmailOtpInternalArgs = {
  walletId,
  otpCode: '123456',
};
void validEnrollEmailOtpInternalArgs;

const invalidEnrollEmailOtpInternalArgs: EnrollEmailOtpInternalArgs = {
  // @ts-expect-error internal Email OTP enrollment requires WalletId.
  walletId: 'alice.testnet',
  otpCode: '123456',
};
void invalidEnrollEmailOtpInternalArgs;

export {};
