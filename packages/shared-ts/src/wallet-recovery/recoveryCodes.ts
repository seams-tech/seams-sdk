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
  DerivedEmailOtpRecoveryKeyId as DerivedWalletRecoveryKeyId,
  EmailOtpRecoveryCode as WalletRecoveryCode,
  EmailOtpRecoveryCodeSet as WalletRecoveryCodeSet,
} from '../utils/emailOtpRecoveryKey';
