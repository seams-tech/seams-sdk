import type {
  GoogleEmailOtpRegistrationEnrollmentResult,
  GoogleEmailOtpRegistrationCandidate,
  GoogleEmailOtpRegistrationCandidateId,
  GoogleEmailOtpRegistrationFinalizeInput,
  GoogleEmailOtpRegistrationOffer,
  GoogleEmailOtpRegistrationOfferId,
  RegistrationFinalizeIdempotencyKey,
} from '@/SeamsWeb/publicApi/types';
import { EMAIL_OTP_CHANNEL } from '@shared/utils/emailOtpDomain';
import { walletIdFromString } from '@shared/utils/registrationIntent';
import { isPlainObject } from '@shared/utils/validation';

const OTP_ONLY_FORBIDDEN_FIELDS = [
  'delivery',
  'challengeId',
  'otpCode',
  'resend',
  'webauthn',
  'webauthnRegistration',
  'webauthn_registration',
  'authenticatorOptions',
  'publicKey',
  'passkey',
  'passkeyPrfFirstB64u',
] as const;

const SECRET_MATERIAL_FIELDS = [
  'recoveryKeys',
  'recoveryCodes',
  'appSessionJwt',
  'bootstrap',
  'bootstrapMaterial',
  'clientSecret32',
] as const;

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isPlainObject(value)) throw new Error(`${label} must be an object`);
  return value;
}

function requireString(value: unknown, label: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) throw new Error(`${label} is required`);
  return normalized;
}

function requireTimestampMs(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer timestamp`);
  }
  return value;
}

function rejectFields(
  record: Record<string, unknown>,
  fields: readonly string[],
  label: string,
): void {
  const forbiddenField = fields.find((field) =>
    Object.prototype.hasOwnProperty.call(record, field),
  );
  if (forbiddenField) throw new Error(`${label} must not include ${forbiddenField}`);
}

function parseOfferId(value: unknown): GoogleEmailOtpRegistrationOfferId {
  return requireString(value, 'offerId') as GoogleEmailOtpRegistrationOfferId;
}

function parseCandidateId(value: unknown, label = 'candidateId'): GoogleEmailOtpRegistrationCandidateId {
  return requireString(value, label) as GoogleEmailOtpRegistrationCandidateId;
}

function parseFinalizeIdempotencyKey(value: unknown): RegistrationFinalizeIdempotencyKey {
  return requireString(value, 'idempotencyKey') as RegistrationFinalizeIdempotencyKey;
}

function parseCandidate(value: unknown): GoogleEmailOtpRegistrationCandidate {
  const record = requireRecord(value, 'registration candidate');
  rejectFields(record, OTP_ONLY_FORBIDDEN_FIELDS, 'registration candidate');
  rejectFields(record, SECRET_MATERIAL_FIELDS, 'registration candidate');
  return {
    candidateId: parseCandidateId(record.candidateId),
    walletId: walletIdFromString(requireString(record.walletId, 'candidate.walletId')),
  };
}

function parseEmailOtpChannel(value: unknown): typeof EMAIL_OTP_CHANNEL {
  if (value !== EMAIL_OTP_CHANNEL) {
    throw new Error(`emailOtpEnrollment.otpChannel must be ${EMAIL_OTP_CHANNEL}`);
  }
  return EMAIL_OTP_CHANNEL;
}

function parseRegistrationEnrollment(value: unknown): GoogleEmailOtpRegistrationEnrollmentResult {
  const record = requireRecord(value, 'emailOtpEnrollment');
  rejectFields(record, OTP_ONLY_FORBIDDEN_FIELDS, 'emailOtpEnrollment');
  rejectFields(record, SECRET_MATERIAL_FIELDS, 'emailOtpEnrollment');
  return {
    registrationAuthorityId: requireString(
      record.registrationAuthorityId,
      'emailOtpEnrollment.registrationAuthorityId',
    ),
    otpChannel: parseEmailOtpChannel(record.otpChannel),
    enrollmentId: requireString(record.enrollmentId, 'emailOtpEnrollment.enrollmentId'),
    enrollmentSealKeyVersion: requireString(
      record.enrollmentSealKeyVersion,
      'emailOtpEnrollment.enrollmentSealKeyVersion',
    ),
    serverSealedFactorCiphertextB64u: requireString(
      record.serverSealedFactorCiphertextB64u,
      'emailOtpEnrollment.serverSealedFactorCiphertextB64u',
    ),
    clientUnlockPublicKeyB64u: requireString(
      record.clientUnlockPublicKeyB64u,
      'emailOtpEnrollment.clientUnlockPublicKeyB64u',
    ),
    unlockKeyVersion: requireString(record.unlockKeyVersion, 'emailOtpEnrollment.unlockKeyVersion'),
  };
}

export function parseGoogleEmailOtpRegistrationOffer(
  value: unknown,
): GoogleEmailOtpRegistrationOffer {
  const record = requireRecord(value, 'Google Email OTP registration offer');
  rejectFields(record, OTP_ONLY_FORBIDDEN_FIELDS, 'Google Email OTP registration offer');
  rejectFields(record, SECRET_MATERIAL_FIELDS, 'Google Email OTP registration offer');
  if (record.kind !== 'google_email_otp_registration_offer_v1') {
    throw new Error('registration offer kind must be google_email_otp_registration_offer_v1');
  }
  if (!Array.isArray(record.candidates) || record.candidates.length < 1) {
    throw new Error('registration offer must include at least one candidate');
  }
  const candidates = record.candidates.map(parseCandidate);
  const selectedCandidateId = parseCandidateId(record.selectedCandidateId, 'selectedCandidateId');
  if (!candidates.some((candidate) => candidate.candidateId === selectedCandidateId)) {
    throw new Error('selectedCandidateId must refer to an offered candidate');
  }
  const [firstCandidate, ...remainingCandidates] = candidates;
  return {
    kind: 'google_email_otp_registration_offer_v1',
    offerId: parseOfferId(record.offerId),
    expiresAtMs: requireTimestampMs(record.expiresAtMs, 'expiresAtMs'),
    emailHint: requireString(record.emailHint, 'emailHint'),
    candidates: [firstCandidate, ...remainingCandidates],
    selectedCandidateId,
  };
}

export function parseGoogleEmailOtpRegistrationFinalizeInput(
  value: unknown,
): GoogleEmailOtpRegistrationFinalizeInput {
  const record = requireRecord(value, 'Google Email OTP registration finalize input');
  rejectFields(record, OTP_ONLY_FORBIDDEN_FIELDS, 'Google Email OTP registration finalize input');
  rejectFields(record, ['walletId', ...SECRET_MATERIAL_FIELDS], 'Google Email OTP registration finalize input');
  if (record.kind !== 'google_email_otp_registration_finalize_v1') {
    throw new Error('registration finalize kind must be google_email_otp_registration_finalize_v1');
  }
  return {
    kind: 'google_email_otp_registration_finalize_v1',
    offerId: parseOfferId(record.offerId),
    candidateId: parseCandidateId(record.candidateId),
    idempotencyKey: parseFinalizeIdempotencyKey(record.idempotencyKey),
    emailOtpEnrollment: parseRegistrationEnrollment(record.emailOtpEnrollment),
  };
}
