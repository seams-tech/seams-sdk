import type { WalletSessionRef } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpRoutePlan } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { EcdsaRoleLocalExportMaterial } from '../persistence/ecdsaRoleLocalRecords';
import type { EmailOtpEcdsaExportSessionRecord } from '../../flows/recovery/ecdsaExportMaterial';
import type {
  EmailOtpEcdsaAuthorizedExportStepUpInput,
} from './exportRecovery';

declare const walletSession: WalletSessionRef;
declare const routePlan: EmailOtpRoutePlan;
declare const record: ThresholdEcdsaSessionRecord;
declare const exportRecord: EmailOtpEcdsaExportSessionRecord;
declare const roleLocalMaterial: EcdsaRoleLocalExportMaterial;

const authorizedExport: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record: exportRecord,
  shamirPrimeB64u: 'prime',
  keyHandle: 'ederivation-key-handle-1',
  roleLocalMaterial,
};
void authorizedExport;

const authorizedExportWithLooseRecord: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  // @ts-expect-error authorized ECDSA export requires a runtime-policy-scoped record.
  record,
  shamirPrimeB64u: 'prime',
  keyHandle: 'ederivation-key-handle-1',
  roleLocalMaterial,
};
void authorizedExportWithLooseRecord;

const authorizedExportWithRpId: EmailOtpEcdsaAuthorizedExportStepUpInput = {
  mode: 'export_step_up',
  source: 'authorized_signing_session',
  walletSession,
  challengeId: 'challenge-1',
  otpCode: '123456',
  relayUrl: 'https://relay.example',
  routePlan,
  record: exportRecord,
  // @ts-expect-error authorized ECDSA export is wallet-key/session scoped, not RP-scoped.
  rpId: 'localhost',
  shamirPrimeB64u: 'prime',
  keyHandle: 'ederivation-key-handle-1',
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
  record: exportRecord,
  shamirPrimeB64u: 'prime',
  keyHandle: 'ederivation-key-handle-1',
};
void authorizedExportWithoutRoleLocalMaterial;

export {};
