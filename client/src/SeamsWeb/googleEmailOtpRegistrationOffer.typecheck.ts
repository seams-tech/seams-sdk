import type {
  EmailOtpRecoveryCodeBackupAck,
  GoogleEmailOtpRegistrationCandidate,
  GoogleEmailOtpRegistrationCandidateId,
  GoogleEmailOtpRegistrationFinalizeInput,
  GoogleEmailOtpRegistrationOffer,
  GoogleEmailOtpRegistrationOfferId,
  RegistrationFinalizeIdempotencyKey,
} from './publicApi/types';
import type { WalletId } from '@shared/utils/registrationIntent';

declare const offerId: GoogleEmailOtpRegistrationOfferId;
declare const candidateId: GoogleEmailOtpRegistrationCandidateId;
declare const idempotencyKey: RegistrationFinalizeIdempotencyKey;
declare const walletId: WalletId;
declare const backedUpEnrollment: GoogleEmailOtpRegistrationFinalizeInput['emailOtpEnrollment'];

const candidate = {
  candidateId,
  walletId,
} satisfies GoogleEmailOtpRegistrationCandidate;

const backupAck = {
  kind: 'email_otp_recovery_code_backup_ack_v1',
  offerId,
  candidateId,
  recoveryCodesIssuedAtMs: 1_765_000_000_000,
  backupActionKind: 'download',
  acknowledgedAtMs: 1_765_000_001_000,
  idempotencyKey,
} satisfies EmailOtpRecoveryCodeBackupAck;

const offer = {
  kind: 'google_email_otp_registration_offer_v1',
  offerId,
  expiresAtMs: 1_765_000_600_000,
  emailHint: 'a***@example.com',
  candidates: [candidate],
  selectedCandidateId: candidateId,
} satisfies GoogleEmailOtpRegistrationOffer;

void offer;

const finalize = {
  kind: 'google_email_otp_registration_finalize_v1',
  offerId,
  candidateId,
  idempotencyKey,
  emailOtpEnrollment: backedUpEnrollment,
  backupAck,
} satisfies GoogleEmailOtpRegistrationFinalizeInput;

void finalize;

({
  ...offer,
  // @ts-expect-error registration offers cannot carry OTP challenge ids
  challengeId: 'challenge-1',
}) satisfies GoogleEmailOtpRegistrationOffer;

({
  ...offer,
  // @ts-expect-error registration offers cannot carry OTP codes
  otpCode: '123456',
}) satisfies GoogleEmailOtpRegistrationOffer;

({
  ...offer,
  // @ts-expect-error registration offers cannot carry WebAuthn data
  webauthn: { publicKey: {} },
}) satisfies GoogleEmailOtpRegistrationOffer;

({
  ...offer,
  // @ts-expect-error registration offers cannot carry passkey data
  passkey: { credentialId: 'credential' },
}) satisfies GoogleEmailOtpRegistrationOffer;

({
  ...finalize,
  // @ts-expect-error finalize selects a candidate id instead of trusting wallet ids
  walletId,
}) satisfies GoogleEmailOtpRegistrationFinalizeInput;

({
  ...finalize,
  backupAck: {
    ...backupAck,
    // @ts-expect-error backup ACKs must not include recovery codes
    recoveryCodes: ['secret-code'],
  },
}) satisfies GoogleEmailOtpRegistrationFinalizeInput;

({
  ...finalize,
  // @ts-expect-error finalize cannot carry passkey registration output
  passkey: { credentialId: 'credential' },
}) satisfies GoogleEmailOtpRegistrationFinalizeInput;

({
  ...backedUpEnrollment,
  // @ts-expect-error Google SSO registration enrollment uses registrationAuthorityId
  challengeId: 'otp-challenge-1',
}) satisfies GoogleEmailOtpRegistrationFinalizeInput['emailOtpEnrollment'];

({
  ...backedUpEnrollment,
  // @ts-expect-error Google SSO registration enrollment cannot carry OTP codes
  otpCode: '123456',
}) satisfies GoogleEmailOtpRegistrationFinalizeInput['emailOtpEnrollment'];
