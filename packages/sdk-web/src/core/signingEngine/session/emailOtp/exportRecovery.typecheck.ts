import type {
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdRuntimePolicyScope } from '@/core/signingEngine/threshold/sessionPolicy';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { VerifiedEcdsaPublicFacts } from '../identity/evmFamilyEcdsaIdentity';
import type { EcdsaRoleLocalExportMaterial } from '../persistence/ecdsaRoleLocalRecords';
import type {
  EmailOtpEcdsaAuthorizedExportStepUpInput,
  EmailOtpEcdsaFreshLoginExportStepUpInput,
} from './exportRecovery';

declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const routePlan: EmailOtpRoutePlan;
declare const record: ThresholdEcdsaSessionRecord;
declare const roleLocalMaterial: EcdsaRoleLocalExportMaterial;
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
  shamirPrimeB64u: 'prime',
  keyHandle: 'ehss-key-handle-1',
  roleLocalMaterial,
};
void authorizedExport;

const authorizedExportWithRpId: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record,
  // @ts-expect-error authorized ECDSA export is wallet-key/session scoped, not RP-scoped.
  rpId: 'localhost',
  shamirPrimeB64u: 'prime',
  keyHandle: 'ehss-key-handle-1',
  roleLocalMaterial,
};
void authorizedExportWithRpId;

// @ts-expect-error authorized ECDSA export requires role-local material.
const authorizedExportWithoutRoleLocalMaterial: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record,
  shamirPrimeB64u: 'prime',
  keyHandle: 'ehss-key-handle-1',
};
void authorizedExportWithoutRoleLocalMaterial;

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
  emailHashHex: 'email-hash',
  runtimePolicyScope,
  providerIdentityMode: 'explicit_provider_user',
  providerUserId: 'email-subject-1',
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
  emailHashHex: 'email-hash',
  runtimePolicyScope,
  providerIdentityMode: 'wallet_session_subject',
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
  emailHashHex: 'email-hash',
  providerIdentityMode: 'wallet_session_subject',
};
void freshExportWithoutRuntimeScope;

// @ts-expect-error wallet-session subject branch rejects explicit provider identity.
const freshExportWithMixedProviderIdentity: EmailOtpEcdsaFreshLoginExportStepUpInput = {
  mode: 'export_step_up',
  source: 'fresh_login',
  walletSession,
  chainTarget,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  publicFacts,
  emailHashHex: 'email-hash',
  runtimePolicyScope,
  providerIdentityMode: 'wallet_session_subject',
  providerUserId: 'email-subject-1',
};
void freshExportWithMixedProviderIdentity;

export {};
