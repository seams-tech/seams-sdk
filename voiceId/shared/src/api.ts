import type { VoiceIdAudioQualityResult } from './audio.ts';
import {
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseVerificationId,
  type IsoDateTime,
  type VoiceIdEnrollmentId,
  type VoiceIdModelVersion,
  type VoiceIdPromptSetId,
  type VoiceIdTemplateVersion,
  type VoiceIdThresholdVersion,
  type VoiceIdVerificationId,
} from './ids.ts';
import { assertExactObjectKeys, parseJsonObject } from './parsers.ts';
import {
  parseVoiceIdAudioQualityResult,
  parseVoiceIdEnrollmentFailureReason,
  parseVoiceIdPhraseMatchResult,
  parseVoiceIdVerificationResult,
} from './resultParsers.ts';
import type { VoiceIdEnrollmentPromptSequence, VoiceIdPromptPhrase } from './prompts.ts';
import { parseEnrollmentPromptSequence, parsePromptPhrase } from './prompts.ts';
import type { VoiceIdEnrollmentRecord } from './records.ts';
import type { VoiceIdPhraseMatchResult, VoiceIdVerificationResult } from './results.ts';

export type VoiceIdOperationErrorKind =
  | 'malformed_request'
  | 'missing_enrollment'
  | 'missing_verification'
  | 'invalid_state'
  | 'identity_mismatch'
  | 'expired';

export type VoiceIdOperationError = {
  [TKind in VoiceIdOperationErrorKind]: { kind: TKind; message: string };
}[VoiceIdOperationErrorKind];

export type VoiceIdApiProtocolErrorKind = 'origin_forbidden' | 'not_found';

export type VoiceIdApiProtocolError = {
  [TKind in VoiceIdApiProtocolErrorKind]: { kind: TKind; message: string };
}[VoiceIdApiProtocolErrorKind];

export type VoiceIdApiError = VoiceIdOperationError | VoiceIdApiProtocolError;

export type VoiceIdApiResponse<TValue> =
  | { kind: 'ok'; value: TValue }
  | { kind: 'error'; error: VoiceIdApiError };

export type VoiceIdEnrollmentStartApiValue = {
  enrollmentId: VoiceIdEnrollmentId;
  promptSetId: VoiceIdPromptSetId;
  promptSequence: VoiceIdEnrollmentPromptSequence;
  modelVersion: VoiceIdModelVersion;
  expiresAt: IsoDateTime;
  minimumCaptureMs: number;
  targetCaptureMs: number;
  maximumCaptureMs: number;
};

export type VoiceIdEnrollmentSubmitApiValue =
  | {
      kind: 'enrolled';
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      enrolledAt: IsoDateTime;
      quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
      phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
    }
  | {
      kind: 'rejected';
      enrollmentId: VoiceIdEnrollmentId;
      failedAt: IsoDateTime;
      reason: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'];
    };

export type VoiceIdEnrollmentDisableApiValue = {
  kind: 'disabled';
  enrollmentId: VoiceIdEnrollmentId;
  disabledAt: IsoDateTime;
};

export type VoiceIdVerificationStartApiValue = {
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  prompt: VoiceIdPromptPhrase;
  expiresAt: IsoDateTime;
};

export type VoiceIdVerificationSubmitApiValue = VoiceIdVerificationResult;

export function parseVoiceIdEnrollmentStartApiResponse(
  value: unknown,
): VoiceIdApiResponse<VoiceIdEnrollmentStartApiValue> {
  return parseApiResponse(value, parseEnrollmentStartValue);
}

export function parseVoiceIdEnrollmentSubmitApiResponse(
  value: unknown,
): VoiceIdApiResponse<VoiceIdEnrollmentSubmitApiValue> {
  return parseApiResponse(value, parseEnrollmentSubmitValue);
}

export function parseVoiceIdEnrollmentDisableApiResponse(
  value: unknown,
): VoiceIdApiResponse<VoiceIdEnrollmentDisableApiValue> {
  return parseApiResponse(value, parseEnrollmentDisableValue);
}

export function parseVoiceIdVerificationStartApiResponse(
  value: unknown,
): VoiceIdApiResponse<VoiceIdVerificationStartApiValue> {
  return parseApiResponse(value, parseVerificationStartValue);
}

export function parseVoiceIdVerificationSubmitApiResponse(
  value: unknown,
): VoiceIdApiResponse<VoiceIdVerificationSubmitApiValue> {
  return parseApiResponse(value, parseVoiceIdVerificationResult);
}

function parseApiResponse<TValue>(
  value: unknown,
  parseValue: (value: unknown) => TValue,
): VoiceIdApiResponse<TValue> {
  const response = parseJsonObject(value, 'VoiceID API response');
  switch (response.kind) {
    case 'ok':
      assertExactObjectKeys(response, ['kind', 'value'], 'VoiceID API success response');
      return { kind: 'ok', value: parseValue(response.value) };
    case 'error':
      assertExactObjectKeys(response, ['kind', 'error'], 'VoiceID API error response');
      return { kind: 'error', error: parseApiError(response.error) };
    default:
      throw new Error('VoiceID API response kind is invalid');
  }
}

function parseApiError(value: unknown): VoiceIdApiError {
  const error = parseJsonObject(value, 'VoiceID API error');
  assertExactObjectKeys(error, ['kind', 'message'], 'VoiceID API error');
  const message = parseString(error.message, 'VoiceID API error message');
  switch (error.kind) {
    case 'malformed_request':
    case 'missing_enrollment':
    case 'missing_verification':
    case 'invalid_state':
    case 'identity_mismatch':
    case 'expired':
    case 'origin_forbidden':
    case 'not_found':
      return { kind: error.kind, message };
    default:
      throw new Error('VoiceID API error kind is invalid');
  }
}

function parseEnrollmentStartValue(value: unknown): VoiceIdEnrollmentStartApiValue {
  const result = parseJsonObject(value, 'enrollment start value');
  assertExactObjectKeys(
    result,
    [
      'enrollmentId',
      'promptSetId',
      'promptSequence',
      'modelVersion',
      'expiresAt',
      'minimumCaptureMs',
      'targetCaptureMs',
      'maximumCaptureMs',
    ],
    'enrollment start value',
  );
  return {
    enrollmentId: parseEnrollmentId(result.enrollmentId),
    promptSetId: parsePromptSetId(result.promptSetId),
    promptSequence: parseEnrollmentPromptSequence(result.promptSequence),
    modelVersion: parseModelVersion(result.modelVersion),
    expiresAt: parseIsoDateTime(result.expiresAt),
    minimumCaptureMs: parsePositiveNumber(result.minimumCaptureMs, 'minimumCaptureMs'),
    targetCaptureMs: parsePositiveNumber(result.targetCaptureMs, 'targetCaptureMs'),
    maximumCaptureMs: parsePositiveNumber(result.maximumCaptureMs, 'maximumCaptureMs'),
  };
}

function parseEnrollmentSubmitValue(value: unknown): VoiceIdEnrollmentSubmitApiValue {
  const result = parseJsonObject(value, 'enrollment submit value');
  switch (result.kind) {
    case 'enrolled': {
      assertExactObjectKeys(
        result,
        [
          'kind',
          'enrollmentId',
          'modelVersion',
          'templateVersion',
          'thresholdVersion',
          'enrolledAt',
          'quality',
          'phrase',
        ],
        'enrolled API value',
      );
      const quality = parseVoiceIdAudioQualityResult(result.quality);
      const phrase = parseVoiceIdPhraseMatchResult(result.phrase);
      if (quality.kind !== 'accepted' || phrase.kind !== 'accepted') {
        throw new Error('enrolled API value requires accepted quality and phrase');
      }
      return {
        kind: 'enrolled',
        enrollmentId: parseEnrollmentId(result.enrollmentId),
        modelVersion: parseModelVersion(result.modelVersion),
        templateVersion: parseTemplateVersion(result.templateVersion),
        thresholdVersion: parseThresholdVersion(result.thresholdVersion),
        enrolledAt: parseIsoDateTime(result.enrolledAt),
        quality,
        phrase,
      };
    }
    case 'rejected':
      assertExactObjectKeys(
        result,
        ['kind', 'enrollmentId', 'failedAt', 'reason'],
        'rejected enrollment API value',
      );
      return {
        kind: 'rejected',
        enrollmentId: parseEnrollmentId(result.enrollmentId),
        failedAt: parseIsoDateTime(result.failedAt),
        reason: parseVoiceIdEnrollmentFailureReason(result.reason),
      };
    default:
      throw new Error('enrollment submit value kind is invalid');
  }
}

function parseEnrollmentDisableValue(value: unknown): VoiceIdEnrollmentDisableApiValue {
  const result = parseJsonObject(value, 'enrollment disable value');
  assertExactObjectKeys(result, ['kind', 'enrollmentId', 'disabledAt'], 'enrollment disable value');
  if (result.kind !== 'disabled') throw new Error('enrollment disable value kind is invalid');
  return {
    kind: 'disabled',
    enrollmentId: parseEnrollmentId(result.enrollmentId),
    disabledAt: parseIsoDateTime(result.disabledAt),
  };
}

function parseVerificationStartValue(value: unknown): VoiceIdVerificationStartApiValue {
  const result = parseJsonObject(value, 'verification start value');
  assertExactObjectKeys(
    result,
    ['enrollmentId', 'verificationId', 'prompt', 'expiresAt'],
    'verification start value',
  );
  return {
    enrollmentId: parseEnrollmentId(result.enrollmentId),
    verificationId: parseVerificationId(result.verificationId),
    prompt: parsePromptPhrase(result.prompt),
    expiresAt: parseIsoDateTime(result.expiresAt),
  };
}

function parseString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value;
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return value;
}
