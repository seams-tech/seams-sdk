import type {
  EmailOtpEcdsaSealedRecoveryRecord,
  EmailOtpEd25519SealedRecoveryRecord,
  PasskeyEd25519SealedRecoveryRecord,
  SealedRecoveryWalletSessionAuth,
} from './recoveryRecord';
import {
  sealedRecoverySessionKind,
  sealedRecoveryWalletSessionJwt,
} from './recoveryRecord';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

declare const currentRecord: EmailOtpEd25519SealedRecoveryRecord;
declare const currentEcdsaRecord: EmailOtpEcdsaSealedRecoveryRecord;
declare const currentPasskeyRecord: PasskeyEd25519SealedRecoveryRecord;
declare const walletSessionAuth: SealedRecoveryWalletSessionAuth;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const passkeyAuthority: PasskeyWalletAuthAuthority;

const validRecoveryRecordWithWalletSessionAuth = {
  ...currentRecord,
  walletSessionAuth,
  authority: emailOtpAuthority,
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void validRecoveryRecordWithWalletSessionAuth;

const normalizedRecoverySessionKind: 'jwt' =
  sealedRecoverySessionKind(walletSessionAuth);
void normalizedRecoverySessionKind;

const normalizedRecoveryWalletSessionJwt: string =
  sealedRecoveryWalletSessionJwt(walletSessionAuth);
void normalizedRecoveryWalletSessionJwt;

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

const invalidEmailOtpRecordWithProviderSubjectSibling = {
  ...currentRecord,
  // @ts-expect-error normalized sealed records derive provider subject from authority.factor.
  providerSubjectId: 'google:alice',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidEmailOtpRecordWithProviderSubjectSibling;

const invalidEmailOtpEcdsaRecordWithEmailHashSibling = {
  ...currentEcdsaRecord,
  // @ts-expect-error normalized sealed records derive email hash from authority.verifier.
  emailHashHex: 'email-hash',
} satisfies EmailOtpEcdsaSealedRecoveryRecord;
void invalidEmailOtpEcdsaRecordWithEmailHashSibling;

const invalidEmailOtpRecordWithRpSibling = {
  ...currentRecord,
  // @ts-expect-error normalized Email OTP sealed records do not carry passkey verifier RP IDs.
  rpId: 'wallet.example.test',
} satisfies EmailOtpEd25519SealedRecoveryRecord;
void invalidEmailOtpRecordWithRpSibling;

const invalidPasskeyRecordWithCredentialSibling = {
  ...currentPasskeyRecord,
  // @ts-expect-error normalized sealed records derive credential id from authority.factor.
  credentialIdB64u: 'credential-id',
} satisfies PasskeyEd25519SealedRecoveryRecord;
void invalidPasskeyRecordWithCredentialSibling;

const invalidPasskeyRecordWithRpSibling = {
  ...currentPasskeyRecord,
  // @ts-expect-error normalized sealed records derive passkey rpId from authority.verifier.
  rpId: 'wallet.example.test',
} satisfies PasskeyEd25519SealedRecoveryRecord;
void invalidPasskeyRecordWithRpSibling;
