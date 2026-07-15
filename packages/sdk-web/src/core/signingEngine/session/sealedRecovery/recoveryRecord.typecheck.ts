import type {
  EmailOtpEcdsaSealedRecoveryRecord,
  PasskeyEcdsaSealedRecoveryRecord,
  SealedRecoveryRecord,
  SealedRecoveryWalletSessionAuth,
} from './recoveryRecord';
import { sealedRecoverySessionKind, sealedRecoveryWalletSessionJwt } from './recoveryRecord';
import type {
  EmailOtpWalletAuthAuthority,
  PasskeyWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';

declare const emailOtpRecord: EmailOtpEcdsaSealedRecoveryRecord;
declare const passkeyRecord: PasskeyEcdsaSealedRecoveryRecord;
declare const walletSessionAuth: SealedRecoveryWalletSessionAuth;
declare const emailOtpAuthority: EmailOtpWalletAuthAuthority;
declare const passkeyAuthority: PasskeyWalletAuthAuthority;

const normalizedRecoverySessionKind: 'jwt' = sealedRecoverySessionKind(walletSessionAuth);
void normalizedRecoverySessionKind;

const normalizedRecoveryWalletSessionJwt: string =
  sealedRecoveryWalletSessionJwt(walletSessionAuth);
void normalizedRecoveryWalletSessionJwt;

const validEmailOtpRecord = {
  ...emailOtpRecord,
  walletSessionAuth,
  authority: emailOtpAuthority,
} satisfies EmailOtpEcdsaSealedRecoveryRecord;
void validEmailOtpRecord;

const invalidEmailOtpAuthority = {
  ...emailOtpRecord,
  // @ts-expect-error Email OTP records require Email OTP wallet authority.
  authority: passkeyAuthority,
} satisfies EmailOtpEcdsaSealedRecoveryRecord;
void invalidEmailOtpAuthority;

const invalidEmailOtpIdentitySibling = {
  ...emailOtpRecord,
  // @ts-expect-error Email identity is derived from the bound authority.
  emailHashHex: 'email-hash',
} satisfies EmailOtpEcdsaSealedRecoveryRecord;
void invalidEmailOtpIdentitySibling;

const invalidPasskeyIdentitySibling = {
  ...passkeyRecord,
  // @ts-expect-error Passkey identity is derived from the bound authority.
  credentialIdB64u: 'credential-id',
} satisfies PasskeyEcdsaSealedRecoveryRecord;
void invalidPasskeyIdentitySibling;

const invalidEd25519Record = {
  ...passkeyRecord,
  // @ts-expect-error Sealed recovery is ECDSA-only.
  curve: 'ed25519',
} satisfies SealedRecoveryRecord;
void invalidEd25519Record;

export {};
