export const EMAIL_OTP_CHANNEL = 'email_otp' as const;

export const WALLET_UNLOCK_BACKENDS = ['passkey', EMAIL_OTP_CHANNEL] as const;

export type WalletUnlockBackend = (typeof WALLET_UNLOCK_BACKENDS)[number];

export type WalletEmailOtpChannel = typeof EMAIL_OTP_CHANNEL;

export const WALLET_EMAIL_OTP_LOGIN_OPERATIONS = [
  'wallet_unlock',
  'transaction_sign',
  'export_key',
] as const;

export type WalletEmailOtpLoginOperation = (typeof WALLET_EMAIL_OTP_LOGIN_OPERATIONS)[number];

export const WALLET_EMAIL_OTP_REGISTRATION_OPERATION = 'registration' as const;

export type WalletEmailOtpOperation =
  | WalletEmailOtpLoginOperation
  | typeof WALLET_EMAIL_OTP_REGISTRATION_OPERATION;

export const WALLET_EMAIL_OTP_ACTIONS = {
  login: 'wallet_email_otp_login',
  registration: 'wallet_email_otp_registration',
  unseal: 'wallet_email_otp_unseal',
} as const;

export type WalletEmailOtpAction =
  (typeof WALLET_EMAIL_OTP_ACTIONS)[keyof typeof WALLET_EMAIL_OTP_ACTIONS];

export const WALLET_EMAIL_OTP_EXPORT_OPERATION = 'export_key' as const;
export const WALLET_EMAIL_OTP_UNLOCK_OPERATION = 'wallet_unlock' as const;
export const WALLET_EMAIL_OTP_TRANSACTION_SIGN_OPERATION = 'transaction_sign' as const;

export function isWalletUnlockBackend(value: string): value is WalletUnlockBackend {
  return (WALLET_UNLOCK_BACKENDS as readonly string[]).includes(value);
}

export function isWalletEmailOtpLoginOperation(
  value: string,
): value is WalletEmailOtpLoginOperation {
  return (WALLET_EMAIL_OTP_LOGIN_OPERATIONS as readonly string[]).includes(value);
}
