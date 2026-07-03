import type {
  EmailOtpEd25519SealedRecoveryRecord,
  SealedRecoveryWalletSessionAuth,
} from './recoveryRecord';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

declare const currentRecord: EmailOtpEd25519SealedRecoveryRecord;
declare const walletSessionAuth: SealedRecoveryWalletSessionAuth;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const passkeyAuthority: PasskeyWalletAuthAuthority;

const validRecoveryRecordWithWalletSessionAuth = {
  ...currentRecord,
  walletSessionAuth,
  authority: emailOtpAuthority,
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void validRecoveryRecordWithWalletSessionAuth;

const invalidRecoveryRecordWithWrongAuthority = {
  ...currentRecord,
  // @ts-expect-error Email OTP sealed recovery records require Email OTP wallet auth authority.
  authority: passkeyAuthority,
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithWrongAuthority;

const invalidRecoveryRecordWithLooseAuthority = {
  ...currentRecord,
  // @ts-expect-error normalized sealed recovery records expose one bound authority field.
  walletSessionAuthority: emailOtpAuthority,
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidRecoveryRecordWithLooseAuthority;

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

const validRecoveryRecordWithClientVerifier = {
  ...currentRecord,
  clientVerifyingShareB64u: 'client-verifier',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void validRecoveryRecordWithClientVerifier;
