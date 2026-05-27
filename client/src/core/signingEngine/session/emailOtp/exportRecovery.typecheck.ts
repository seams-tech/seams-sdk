import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { VerifiedEcdsaPublicFacts } from '../identity/evmFamilyEcdsaIdentity';
import type {
  EmailOtpEcdsaAuthorizedExportStepUpInput,
  EmailOtpEcdsaFreshLoginExportStepUpInput,
} from './exportRecovery';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const routePlan: EmailOtpRoutePlan;
declare const record: ThresholdEcdsaSessionRecord;
declare const roleLocalState: NonNullable<
  ThresholdEcdsaSessionRecord['ecdsaHssRoleLocalClientState']
>;
declare const publicFacts: VerifiedEcdsaPublicFacts;
declare const runtimePolicyScope: ThresholdRuntimePolicyScope;

const authorizedExport: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record,
  rpId: 'localhost',
  shamirPrimeB64u: 'prime',
  keyHandle: 'ehss-key-handle-1',
  roleLocalState,
};
void authorizedExport;

// @ts-expect-error authorized ECDSA export requires role-local client state.
const authorizedExportWithoutRoleLocalState: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record,
  rpId: 'localhost',
  shamirPrimeB64u: 'prime',
  keyHandle: 'ehss-key-handle-1',
};
void authorizedExportWithoutRoleLocalState;

const freshExport: EmailOtpEcdsaFreshLoginExportStepUpInput = {
  mode: 'export_step_up',
  source: 'fresh_login',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  publicFacts,
  runtimePolicyScope,
  authSubjectMode: 'explicit_auth_subject',
  authSubjectId: 'email-subject-1',
};
void freshExport;

const freshExportWithWalletSessionSubject: EmailOtpEcdsaFreshLoginExportStepUpInput = {
  mode: 'export_step_up',
  source: 'fresh_login',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  publicFacts,
  runtimePolicyScope,
  authSubjectMode: 'wallet_session_subject',
};
void freshExportWithWalletSessionSubject;

// @ts-expect-error fresh Email OTP ECDSA export requires runtimePolicyScope.
const freshExportWithoutRuntimeScope: EmailOtpEcdsaFreshLoginExportStepUpInput = {
  mode: 'export_step_up',
  source: 'fresh_login',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  publicFacts,
  authSubjectMode: 'wallet_session_subject',
};
void freshExportWithoutRuntimeScope;

// @ts-expect-error wallet-session subject branch rejects explicit authSubjectId.
const freshExportWithMixedSubject: EmailOtpEcdsaFreshLoginExportStepUpInput = {
  mode: 'export_step_up',
  source: 'fresh_login',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  publicFacts,
  runtimePolicyScope,
  authSubjectMode: 'wallet_session_subject',
  authSubjectId: 'email-subject-1',
};
void freshExportWithMixedSubject;

export {};
