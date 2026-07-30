import {
  toEcdsaDerivationThresholdKeyId,
  toEmailOtpAuthSubjectId,
  toWalletSessionUserId,
  type EmailOtpExistingKeyBootstrap,
  type EmailOtpRegistrationBootstrap,
  type EmailOtpAuthSubjectId,
  type WalletSessionUserId,
} from './emailOtpEcdsaDerivationIdentity';

const walletSessionUserId = toWalletSessionUserId('wallet.testnet');
const authSubjectId = toEmailOtpAuthSubjectId('google:subject-1');
const ecdsaThresholdKeyId = toEcdsaDerivationThresholdKeyId('ecdsa-key-1');

// @ts-expect-error provider-scoped Email OTP subjects cannot become wallet-scoped DERIVATION ids
const invalidWalletSessionUserId: WalletSessionUserId = authSubjectId;

// @ts-expect-error wallet-scoped DERIVATION ids cannot become provider auth subjects
const invalidAuthSubjectId: EmailOtpAuthSubjectId = walletSessionUserId;

void invalidWalletSessionUserId;
void invalidAuthSubjectId;

void ({
  operation: 'email_otp_bootstrap',
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  keyHandle: 'ederivation-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error registration bootstrap must not carry a preexisting ECDSA key id
  ecdsaThresholdKeyId,
} satisfies EmailOtpRegistrationBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error existing-key bootstrap must carry keyHandle
} satisfies EmailOtpExistingKeyBootstrap);

void ({
  operation: 'email_otp_bootstrap',
  // @ts-expect-error existing-key bootstrap rejects scattered threshold-key identity
  ecdsaThresholdKeyId,
  keyHandle: 'ederivation-key-handle-1',
} satisfies EmailOtpExistingKeyBootstrap);

export {};
