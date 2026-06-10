import type {
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from './publicApi/types';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

declare const target: ThresholdEcdsaChainTarget;
declare const flowResult: GoogleEmailOtpWalletAuthResult<GoogleEmailOtpWalletAuthFlow>;
declare const loginFlow: GoogleEmailOtpWalletAuthLoginFlow;
declare const registrationFlow: GoogleEmailOtpWalletAuthRegistrationFlow;
declare const submitSuccess: GoogleEmailOtpWalletAuthSubmitSuccess;

if (flowResult.ok) {
  void flowResult.value.walletId;
} else {
  void flowResult.error.code;
}

// @ts-expect-error callers must branch on ok before reading the flow value
void flowResult.value;

// @ts-expect-error login flows cannot reroll wallet ids
loginFlow.rerollWalletId();

// @ts-expect-error registration flows do not expose OTP submit
registrationFlow.submit({ otpCode: '123456' });

// @ts-expect-error registration flows do not satisfy login-flow delivery contract
const invalidRegistrationDelivery: { delivery: 'sent' } = registrationFlow;
void invalidRegistrationDelivery;

void registrationFlow.completeRegistration();
void registrationFlow.rerollWalletId();

declare const registrationRerollResult: Awaited<
  ReturnType<GoogleEmailOtpWalletAuthRegistrationFlow['rerollWalletId']>
>;

if (registrationRerollResult.ok) {
  void registrationRerollResult.value.completeRegistration();
  // @ts-expect-error registration wallet-id reroll cannot return a login OTP flow
  registrationRerollResult.value.submit({ otpCode: '123456' });
}

const explicitTargets = {
  kind: 'explicit',
  targets: [target],
} satisfies GoogleEmailOtpWalletAuthEcdsaTargets;
void explicitTargets;

const emptyExplicitTargets = {
  kind: 'explicit',
  // @ts-expect-error explicit ECDSA target policy must contain at least one target
  targets: [],
} satisfies GoogleEmailOtpWalletAuthEcdsaTargets;
void emptyExplicitTargets;

void submitSuccess.walletId;
void submitSuccess.mode;
void submitSuccess.session;

// @ts-expect-error app code cannot access app session JWT from submit success
void submitSuccess.appSessionJwt;

// @ts-expect-error app code cannot access recovery codes from submit success
void submitSuccess.recoveryKeys;

// @ts-expect-error app code cannot access ECDSA bootstrap material from submit success
void submitSuccess.bootstrap;
