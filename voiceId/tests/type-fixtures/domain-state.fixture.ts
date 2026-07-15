import type {
  VoiceIdAttestedEvidence,
  VoiceIdEnrollmentRecord,
  VoiceIdExperimentalBrowserEvidence,
  VoiceIdVerificationRecord,
} from '../../shared/src/index.ts';
import {
  nowIsoDateTime,
  parseEncryptedBytes,
  parseEnrollmentId,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdChallengeNonce,
} from '../../shared/src/index.ts';

const userId = parseUserId('owner');
const enrollmentId = parseEnrollmentId('enrollment_1');
const verificationId = parseVerificationId('verification_1');
const promptSetId = parsePromptSetId('prompt_set_1');
const modelVersion = parseModelVersion('model_1');
const templateVersion = parseTemplateVersion('template_1');
const thresholdVersion = parseThresholdVersion('threshold_1');
const encryptedTemplate = parseEncryptedBytes('ciphertext');
const now = nowIsoDateTime(new Date('2026-07-13T00:00:00.000Z'));
const challengeNonce = parseVoiceIdChallengeNonce('challenge_nonce_123456');
const promptSequence = [
  parsePromptPhrase('Copper river carries morning light'),
  parsePromptPhrase('Seven quiet lanterns cross the harbor'),
  parsePromptPhrase('Bright cedar branches move in winter'),
  parsePromptPhrase('A silver compass points toward home'),
] as const;

const pendingEnrollment: VoiceIdEnrollmentRecord = {
  state: 'pending_continuous_recording',
  userId,
  enrollmentId,
  promptSetId,
  promptSequence,
  modelVersion,
  createdAt: now,
  expiresAt: now,
  minimumCaptureMs: 12_000,
  targetCaptureMs: 18_000,
  maximumCaptureMs: 30_000,
};

pendingEnrollment;

const analyzingEnrollment: VoiceIdEnrollmentRecord = {
  state: 'analyzing_continuous_recording',
  userId,
  enrollmentId,
  promptSetId,
  promptSequence,
  modelVersion,
  createdAt: now,
  expiresAt: now,
  minimumCaptureMs: 12_000,
  targetCaptureMs: 18_000,
  maximumCaptureMs: 30_000,
  analysisStartedAt: now,
  analysisExpiresAt: now,
};

analyzingEnrollment;

// @ts-expect-error analyzing enrollment cannot contain template material.
const invalidAnalyzingEnrollment: VoiceIdEnrollmentRecord = {
  state: 'analyzing_continuous_recording',
  userId,
  enrollmentId,
  promptSetId,
  promptSequence,
  modelVersion,
  createdAt: now,
  expiresAt: now,
  minimumCaptureMs: 12_000,
  targetCaptureMs: 18_000,
  maximumCaptureMs: 30_000,
  analysisStartedAt: now,
  analysisExpiresAt: now,
  encryptedTemplate,
};

invalidAnalyzingEnrollment;

// @ts-expect-error an analysis claim cannot be spread directly into enrolled state.
const invalidEnrolledSpread: VoiceIdEnrollmentRecord = {
  ...analyzingEnrollment,
  state: 'enrolled',
  templateVersion,
  thresholdVersion,
  encryptedTemplate,
  enrolledAt: now,
};

invalidEnrolledSpread;

// @ts-expect-error pending enrollment cannot contain a template.
const invalidPendingEnrollment: VoiceIdEnrollmentRecord = {
  state: 'pending_continuous_recording',
  userId,
  enrollmentId,
  promptSetId,
  promptSequence,
  modelVersion,
  createdAt: now,
  expiresAt: now,
  minimumCaptureMs: 12_000,
  targetCaptureMs: 18_000,
  maximumCaptureMs: 30_000,
  encryptedTemplate,
};

invalidPendingEnrollment;

const enrolled: VoiceIdEnrollmentRecord = {
  state: 'enrolled',
  userId,
  enrollmentId,
  promptSetId,
  modelVersion,
  templateVersion,
  thresholdVersion,
  encryptedTemplate,
  createdAt: now,
  enrolledAt: now,
};

enrolled;

const issued: VoiceIdVerificationRecord = {
  state: 'issued',
  userId,
  enrollmentId,
  verificationId,
  expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
  challengeNonce,
  createdAt: now,
  expiresAt: now,
};

issued;

const analyzingVerification: VoiceIdVerificationRecord = {
  state: 'analyzing',
  userId,
  enrollmentId,
  verificationId,
  expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
  challengeNonce,
  createdAt: now,
  expiresAt: now,
  analysisStartedAt: now,
  analysisExpiresAt: now,
};

analyzingVerification;

const invalidAnalyzingVerification: VoiceIdVerificationRecord = {
  state: 'analyzing',
  userId,
  enrollmentId,
  verificationId,
  expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
  challengeNonce,
  createdAt: now,
  expiresAt: now,
  analysisStartedAt: now,
  analysisExpiresAt: now,
  // @ts-expect-error analyzing verification cannot contain a result.
  result: { kind: 'rejected' },
};

invalidAnalyzingVerification;

// @ts-expect-error an analysis claim cannot be spread into an issued-expiry terminal record.
const invalidExpiredSpread: VoiceIdVerificationRecord = {
  ...analyzingVerification,
  state: 'expired',
  completedAt: now,
};

invalidExpiredSpread;

const invalidIssued: VoiceIdVerificationRecord = {
  state: 'issued',
  userId,
  enrollmentId,
  verificationId,
  expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
  challengeNonce,
  createdAt: now,
  expiresAt: now,
  // @ts-expect-error issued verification cannot contain a result.
  result: { kind: 'rejected' },
};

invalidIssued;

declare const experimentalEvidence: VoiceIdExperimentalBrowserEvidence;
declare const attestedEvidence: VoiceIdAttestedEvidence;

// @ts-expect-error attested evidence requires the private boundary-builder brand.
const invalidDirectAttestedEvidence: VoiceIdAttestedEvidence = {
  kind: 'attested_evidence',
  verificationId: attestedEvidence.verificationId,
  enrollmentId: attestedEvidence.enrollmentId,
  speaker: attestedEvidence.speaker,
  phrase: attestedEvidence.phrase,
  quality: attestedEvidence.quality,
  captureFreshness: attestedEvidence.captureFreshness,
  pad: attestedEvidence.pad,
  deviceProof: attestedEvidence.deviceProof,
  captureProfile: attestedEvidence.captureProfile,
  calibration: attestedEvidence.calibration,
  modelVersion: attestedEvidence.modelVersion,
  thresholdVersion: attestedEvidence.thresholdVersion,
  completedAt: attestedEvidence.completedAt,
};

invalidDirectAttestedEvidence;

type TestWalletSigningAuthorization = {
  kind: 'test_wallet_signing_authorization';
  admittedDigest: string;
};

declare function testSigningBoundary(authorization: TestWalletSigningAuthorization): void;

// @ts-expect-error E0 evidence is structurally signing-ineligible.
testSigningBoundary(experimentalEvidence);

// @ts-expect-error E2 evidence is structurally signing-ineligible.
testSigningBoundary(attestedEvidence);

const invalidExperimentalEvidence: VoiceIdExperimentalBrowserEvidence = {
  ...experimentalEvidence,
  // @ts-expect-error evidence cannot carry signing authorization.
  signingAuthorization: { kind: 'test_wallet_signing_authorization', admittedDigest: 'digest' },
};

invalidExperimentalEvidence;
