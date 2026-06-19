import type {
  EmailOtpEd25519SealedRecoveryRecord,
  SealedRecoveryWalletSessionAuth,
} from './recoveryRecord';

declare const currentRecord: EmailOtpEd25519SealedRecoveryRecord;
declare const walletSessionAuth: SealedRecoveryWalletSessionAuth;

const validRecoveryRecordWithWalletSessionAuth = {
  ...currentRecord,
  walletSessionAuth,
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void validRecoveryRecordWithWalletSessionAuth;

const invalidRecoveryRecordWithOldTokenField = {
  ...currentRecord,
  // @ts-expect-error normalized sealed recovery records expose walletSessionAuth.
  thresholdSessionAuthToken: 'wallet-session-jwt',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithOldTokenField;

const invalidRecoveryRecordWithOldSessionKindField = {
  ...currentRecord,
  // @ts-expect-error normalized sealed recovery records expose walletSessionAuth.
  sessionKind: 'jwt',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithOldSessionKindField;

const invalidRecoveryRecordWithRawClientBase = {
  ...currentRecord,
  // @ts-expect-error normalized Email OTP Ed25519 sealed recovery records do not carry raw HSS material.
  xClientBaseB64u: 'raw-client-base',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithRawClientBase;

const invalidRecoveryRecordWithRawClientVerifier = {
  ...currentRecord,
  // @ts-expect-error normalized Email OTP Ed25519 sealed recovery records do not carry raw HSS material.
  clientVerifyingShareB64u: 'raw-client-verifier',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithRawClientVerifier;
