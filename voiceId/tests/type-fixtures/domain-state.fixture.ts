import type {
  VoiceIdEnrollmentSample,
  VoiceIdEnrollmentRecord,
  VoiceIdEnrollmentState,
  VoiceIdVerificationRecord,
  VoiceIdVerificationResult,
} from '../../shared/src/index.ts';
import { VoiceIdService } from '../../server/src/VoiceIdService.ts';
import {
  parseEncryptedBytes,
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
} from '../../shared/src/index.ts';

const userId = parseUserId('owner');
const enrollmentId = parseEnrollmentId('enroll_1');
const verificationId = parseVerificationId('verify_1');
const modelVersion = parseModelVersion('model_1');
const templateVersion = parseTemplateVersion('template_1');
const thresholdVersion = parseThresholdVersion('threshold_1');
const promptSetId = parsePromptSetId('prompt_1');
const isoDateTime = parseIsoDateTime('2026-06-08T00:00:00.000Z');
const encryptedTemplate = parseEncryptedBytes('ciphertext');

const validNotEnrolled: VoiceIdEnrollmentState = {
  kind: 'not_enrolled',
  userId,
};

validNotEnrolled;

// @ts-expect-error enrollmentId is invalid on not_enrolled.
const invalidNotEnrolled: VoiceIdEnrollmentState = {
  kind: 'not_enrolled',
  userId,
  enrollmentId,
};

invalidNotEnrolled;

// @ts-expect-error templateVersion is invalid on enrollment_pending.
const invalidPendingState: VoiceIdEnrollmentState = {
  kind: 'enrollment_pending',
  userId,
  enrollmentId,
  promptSetId,
  requiredSampleCount: 3,
  acceptedSampleCount: 0,
  expiresAt: isoDateTime,
  templateVersion,
};

invalidPendingState;

// @ts-expect-error disabledAt is invalid on enrolled.
const invalidEnrolledState: VoiceIdEnrollmentState = {
  kind: 'enrolled',
  userId,
  enrollmentId,
  modelVersion,
  templateVersion,
  enrolledAt: isoDateTime,
  disabledAt: isoDateTime,
};

invalidEnrolledState;

// @ts-expect-error encryptedTemplate is invalid on pending enrollment records.
const invalidPendingRecord: VoiceIdEnrollmentRecord = {
  state: 'pending',
  userId,
  enrollmentId,
  promptSetId,
  modelVersion,
  createdAt: isoDateTime,
  expiresAt: isoDateTime,
  requiredSampleCount: 3,
  acceptedSampleCount: 0,
  attemptCount: 0,
  encryptedTemplate,
};

invalidPendingRecord;

const validEnrolledRecord: VoiceIdEnrollmentRecord = {
  state: 'enrolled',
  userId,
  enrollmentId,
  promptSetId,
  modelVersion,
  templateVersion,
  thresholdVersion,
  encryptedTemplate,
  createdAt: isoDateTime,
  enrolledAt: isoDateTime,
};

validEnrolledRecord;

const invalidIssuedRecord: VoiceIdVerificationRecord = {
  state: 'issued',
  userId,
  enrollmentId,
  expectedPhrase: parsePromptPhrase('Walking on clouds'),
  verificationId,
  createdAt: isoDateTime,
  expiresAt: isoDateTime,
  attemptCount: 0,
  result: {
    // @ts-expect-error issued verification records cannot contain result data.
    kind: 'rejected',
    verificationId,
    reason: 'phrase_mismatch',
  },
};

invalidIssuedRecord;

const invalidAcceptedResult: VoiceIdVerificationResult = {
  kind: 'accepted',
  enrollmentId,
  verificationId,
  templateVersion,
  modelVersion,
  thresholdVersion,
  checks: {
    phrase: {
      kind: 'rejected',
      // @ts-expect-error accepted verification requires accepted branch checks.
      reason: 'phrase_mismatch',
      expectedNormalized: 'a',
      spokenNormalized: 'b',
      confidence: 0.9,
    },
    speaker: {
      kind: 'accepted',
      score: 0.9,
      threshold: 0.8,
      modelVersion,
      thresholdVersion,
    },
    quality: {
      kind: 'accepted',
      durationMs: 1200,
      signalScore: 0.9,
    },
  },
};

invalidAcceptedResult;

declare const service: VoiceIdService;
declare const rawRequestBody: Record<string, unknown>;
declare const browserBlob: Blob;
declare const browserFile: File;
declare const browserFormData: FormData;

// @ts-expect-error raw request bodies cannot cross into core service functions.
service.addEnrollmentSample(rawRequestBody);

// @ts-expect-error browser Blob cannot cross into core service functions.
service.addEnrollmentSample(browserBlob);

// @ts-expect-error browser File cannot cross into core service functions.
service.addEnrollmentSample(browserFile);

// @ts-expect-error browser FormData cannot cross into core service functions.
service.addEnrollmentSample(browserFormData);

declare const typedEnrollmentSample: VoiceIdEnrollmentSample;
service.addEnrollmentSample(typedEnrollmentSample);
