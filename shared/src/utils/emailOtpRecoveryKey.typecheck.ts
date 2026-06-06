import {
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
  type EmailOtpRecoveryWrapBinding,
} from './emailOtpRecoveryKey';

const binding: EmailOtpRecoveryWrapBinding = buildEmailOtpRecoveryWrapBinding({
  walletId: 'wallet.testnet',
  userId: 'user.testnet',
  authSubjectId: 'google-subject',
  authMethod: 'google_sso_email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-v1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  recoveryKeyId: 'recovery-key-1',
});

void encodeEmailOtpRecoveryWrappedEnrollmentAad(binding);

const flatRawRecoveryWrappedEscrowRecord = {
  walletId: 'wallet.testnet',
  userId: 'user.testnet',
  authSubjectId: 'google-subject',
  authMethod: 'google_sso_email_otp',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-v1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  recoveryKeyId: 'recovery-key-1',
};

// @ts-expect-error crypto helpers require a parsed recovery-wrap binding, not a raw flat record
void encodeEmailOtpRecoveryWrappedEnrollmentAad(flatRawRecoveryWrappedEscrowRecord);

void buildEmailOtpRecoveryWrapBinding({
  walletId: 'wallet.testnet',
  userId: 'user.testnet',
  authSubjectId: 'google-subject',
  // @ts-expect-error auth method is a branch discriminant, not arbitrary string metadata
  authMethod: 'passkey',
  enrollmentId: 'enrollment-1',
  enrollmentVersion: '1',
  enrollmentSealKeyVersion: 'seal-v1',
  signingRootId: 'signing-root-1',
  signingRootVersion: 'default',
  recoveryKeyId: 'recovery-key-1',
});
