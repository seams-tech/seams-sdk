export {
  EMAIL_OTP_RECOVERY_KEY_ALPHABET as WALLET_RECOVERY_CODE_ALPHABET,
  EMAIL_OTP_RECOVERY_KEY_BYTE_LENGTH as WALLET_RECOVERY_CODE_BYTE_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_CHAR_LENGTH as WALLET_RECOVERY_CODE_CHAR_LENGTH,
  EMAIL_OTP_RECOVERY_KEY_COUNT as WALLET_RECOVERY_CODE_COUNT,
  EMAIL_OTP_RECOVERY_KEY_GROUP_COUNT as WALLET_RECOVERY_CODE_GROUP_COUNT,
  EMAIL_OTP_RECOVERY_KEY_GROUP_LENGTH as WALLET_RECOVERY_CODE_GROUP_LENGTH,
  buildEmailOtpRecoveryCodeSet as buildWalletRecoveryCodeSet,
  formatEmailOtpRecoveryKey as formatWalletRecoveryCode,
  normalizeEmailOtpRecoveryKey as normalizeWalletRecoveryCode,
} from '../utils/emailOtpRecoveryKey';

export type {
  EmailOtpRecoveryCode as WalletRecoveryCode,
  EmailOtpRecoveryCodeSet as WalletRecoveryCodeSet,
} from '../utils/emailOtpRecoveryKey';

/* The code *format* is shared with Email OTP — same alphabet, length, and
   grouping, because it is the same thing a user writes down. The code's
   *identity* is not: an Email OTP id is bound to an enrollment, which a
   passkey wallet does not have. See `recoveryKeyId.ts`. */
export {
  deriveWalletRecoveryKeyId,
  deriveWalletRecoveryKeyIdFromBytes,
  isDerivedWalletRecoveryKeyId,
  parseDerivedWalletRecoveryKeyId,
  WALLET_RECOVERY_KEY_ID_PREFIX_V1,
} from './recoveryKeyId';

export type { DerivedWalletRecoveryKeyId } from './recoveryKeyId';

/* Issuance, which establishing custody performs in the same act as sealing —
   see `recoveryCodeIssuance.ts`. */
export { issueWalletRecoveryCodes, zeroizeIssuedWalletRecoveryCodes } from './recoveryCodeIssuance';

export type { IssuedWalletRecoveryCodes } from './recoveryCodeIssuance';

/* The attempt that binds a code's lifecycle to its activation outcome. */
export { runWalletRecoveryWithCode } from './recoveryCodeAttempt';

/* All-or-nothing promotion across the wallet's key sets. */
export type {
  WalletRecoveryActivationResult,
  WalletRecoveryAttemptOutcome,
} from './recoveryCodeAttempt';

export {
  buildWalletRecoveryBackupAcknowledgementV1,
  parseWalletRecoveryBackupAcknowledgementV1,
  walletRecoveryBackupIsOutstanding,
} from './backupAcknowledgement';

export type { WalletRecoveryBackupAcknowledgementV1 } from './backupAcknowledgement';
