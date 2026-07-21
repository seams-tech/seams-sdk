export const EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_CODE =
  'email_otp_device_recovery_required' as const;

export const EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_MESSAGE =
  'This Email OTP wallet is not available on this device. Recover the wallet to continue.';

export class EmailOtpDeviceRecoveryRequiredError extends Error {
  readonly code = EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_CODE;

  constructor() {
    super(EMAIL_OTP_DEVICE_RECOVERY_REQUIRED_MESSAGE);
    this.name = 'EmailOtpDeviceRecoveryRequiredError';
  }
}
