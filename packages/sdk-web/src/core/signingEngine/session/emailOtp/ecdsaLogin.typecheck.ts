import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { AppOrWalletSessionAuth } from '@shared/utils/sessionTokens';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type {
  EmailOtpEcdsaLoginReconnectInput,
  EmailOtpEcdsaTransactionStepUpInput,
} from './ecdsaLogin';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const authLane: EmailOtpAuthLane;
declare const routeAuth: AppOrWalletSessionAuth;
declare const record: ThresholdEcdsaSessionRecord;

const loginReconnect: EmailOtpEcdsaLoginReconnectInput = {
  mode: 'login_reconnect',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  appSessionJwt: 'app-session-jwt',
};
void loginReconnect;

const loginReconnectWithRegistrationAttempt: EmailOtpEcdsaLoginReconnectInput = {
  mode: 'login_reconnect',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  appSessionJwt: 'app-session-jwt',
  // @ts-expect-error login reconnect does not accept registration attempts.
  registrationAttemptId: 'registration-attempt',
};
void loginReconnectWithRegistrationAttempt;

const transactionStepUpWithAuthLane: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  authLane,
};
void transactionStepUpWithAuthLane;

const transactionStepUpWithRecordAuthLane: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  record,
  authLane,
};
void transactionStepUpWithRecordAuthLane;

const transactionStepUpWithRouteAuth: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  record,
  routeAuth,
};
void transactionStepUpWithRouteAuth;

// @ts-expect-error transaction step-up requires an auth lane or route auth.
const transactionStepUpMissingAuth: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  record,
};
void transactionStepUpMissingAuth;

const transactionStepUpWithRegistrationAttempt: EmailOtpEcdsaTransactionStepUpInput = {
  mode: 'transaction_step_up',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  authLane,
  // @ts-expect-error transaction step-up does not accept registration attempts.
  registrationAttemptId: 'registration-attempt',
};
void transactionStepUpWithRegistrationAttempt;

export {};
