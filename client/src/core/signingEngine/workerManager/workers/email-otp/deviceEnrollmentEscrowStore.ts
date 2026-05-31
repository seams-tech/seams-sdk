import {
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_NAME,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_VERSION,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME,
  emailOtpDeviceEnrollmentEscrowRepository,
  normalizeEmailOtpDeviceEnrollmentEscrowRecord,
  type EmailOtpDeviceEnrollmentEscrowRecord,
  type WriteEmailOtpDeviceEnrollmentEscrowRecordInput,
} from '../../../../indexedDB/seamsWalletDB/emailOtpDeviceEnrollmentEscrows';

export {
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_ALG,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_NAME,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_DB_VERSION,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_RECORD_VERSION,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_SECRET_KIND,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORAGE_SCOPE,
  EMAIL_OTP_DEVICE_ENROLLMENT_ESCROW_STORE_NAME,
  normalizeEmailOtpDeviceEnrollmentEscrowRecord,
  type EmailOtpDeviceEnrollmentEscrowRecord,
};

export async function readEmailOtpDeviceEnrollmentEscrowRecord(args: {
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
}): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
  return await emailOtpDeviceEnrollmentEscrowRepository.read(args);
}

export async function readSingleEmailOtpDeviceEnrollmentEscrowRecordForWallet(args: {
  walletId: string;
}): Promise<EmailOtpDeviceEnrollmentEscrowRecord | null> {
  return await emailOtpDeviceEnrollmentEscrowRepository.readSingleForWallet(args);
}

export async function writeEmailOtpDeviceEnrollmentEscrowRecord(
  args: WriteEmailOtpDeviceEnrollmentEscrowRecordInput,
): Promise<void> {
  await emailOtpDeviceEnrollmentEscrowRepository.write(args);
}

export async function deleteEmailOtpDeviceEnrollmentEscrowRecord(args: {
  walletId: string;
  authSubjectId: string;
  enrollmentId: string;
}): Promise<void> {
  await emailOtpDeviceEnrollmentEscrowRepository.delete(args);
}

export async function clearAllEmailOtpDeviceEnrollmentEscrowRecords(): Promise<void> {
  await emailOtpDeviceEnrollmentEscrowRepository.clearAll();
}
