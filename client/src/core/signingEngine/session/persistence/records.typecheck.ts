import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseRawThresholdEcdsaSessionRecord } from './records';
import type {
  getEmailOtpThresholdEcdsaKeyRefForSigning,
  getEmailOtpThresholdEcdsaSessionRecordForSigning,
  getPasskeyThresholdEcdsaKeyRefForSigning,
  getPasskeyThresholdEcdsaSessionRecordForSigning,
  RawThresholdEcdsaSessionRecord,
  ThresholdEcdsaSessionRecord,
} from './records';

declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const rawEcdsaRecord: RawThresholdEcdsaSessionRecord;

type EmailOtpEcdsaSigningLookupArgs = Parameters<
  typeof getEmailOtpThresholdEcdsaSessionRecordForSigning
>[1];
type EmailOtpEcdsaKeyRefLookupArgs = Parameters<
  typeof getEmailOtpThresholdEcdsaKeyRefForSigning
>[1];
type PasskeyEcdsaSigningLookupArgs = Parameters<
  typeof getPasskeyThresholdEcdsaSessionRecordForSigning
>[1];
type PasskeyEcdsaKeyRefLookupArgs = Parameters<
  typeof getPasskeyThresholdEcdsaKeyRefForSigning
>[1];

const emailOtpLookupArgs: EmailOtpEcdsaSigningLookupArgs = {
  walletId,
  chainTarget,
};
void emailOtpLookupArgs;

const emailOtpKeyRefLookupArgs: EmailOtpEcdsaKeyRefLookupArgs = {
  walletId,
  chainTarget,
};
void emailOtpKeyRefLookupArgs;

const passkeyLookupArgs: PasskeyEcdsaSigningLookupArgs = {
  walletId,
  chainTarget,
  source: 'login',
};
void passkeyLookupArgs;

const passkeyKeyRefLookupArgs: PasskeyEcdsaKeyRefLookupArgs = {
  walletId,
  chainTarget,
  source: 'login',
};
void passkeyKeyRefLookupArgs;

const invalidEmailOtpLookupArgs: EmailOtpEcdsaSigningLookupArgs = {
  // @ts-expect-error ECDSA signing record lookup requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
};
void invalidEmailOtpLookupArgs;

const invalidPasskeyLookupArgs: PasskeyEcdsaSigningLookupArgs = {
  // @ts-expect-error ECDSA signing record lookup requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
  source: 'login',
};
void invalidPasskeyLookupArgs;

// @ts-expect-error raw ECDSA records must be parsed before core consumers receive them.
const rawRecordAsNormalizedRecord: ThresholdEcdsaSessionRecord = rawEcdsaRecord;
void rawRecordAsNormalizedRecord;

const parsedRecord: ThresholdEcdsaSessionRecord =
  parseRawThresholdEcdsaSessionRecord(rawEcdsaRecord);
void parsedRecord;
