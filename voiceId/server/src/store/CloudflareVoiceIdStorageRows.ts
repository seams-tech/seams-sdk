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
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  type EncryptedBytes,
  type IsoDateTime,
  type VoiceIdModelVersion,
  type VoiceIdThresholdVersion,
} from '../../../shared/src/index.ts';
import type { VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../../shared/src/records.ts';
import type {
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
  VoiceIdVerificationChecks,
  VoiceIdVerificationResult,
} from '../../../shared/src/results.ts';

const storageSchemaVersion = 1;

const forbiddenRawCaptureColumns = new Set([
  'audio',
  'audioBytes',
  'rawAudio',
  'rawAudioBytes',
  'bytes',
  'blob',
  'rawCapture',
  'rawCaptureBytes',
  'rawSample',
  'rawSampleBytes',
]);

export type VoiceIdCloudflareEnrollmentRow = {
  schemaVersion: 1;
  recordKind: 'voice_id_enrollment';
  userId: string;
  enrollmentId: string;
  state: 'pending' | 'enrolled' | 'disabled';
  promptSetId: string;
  modelVersion: string;
  createdAt: string;
  expiresAt: string | null;
  requiredSampleCount: number | null;
  acceptedSampleCount: number | null;
  attemptCount: number | null;
  templateVersion: string | null;
  thresholdVersion: string | null;
  encryptedTemplate: string | null;
  enrolledAt: string | null;
  disabledAt: string | null;
};

export type VoiceIdCloudflareVerificationRow = {
  schemaVersion: 1;
  recordKind: 'voice_id_verification';
  userId: string;
  enrollmentId: string;
  verificationId: string;
  state: 'issued' | 'accepted' | 'rejected' | 'uncertain' | 'expired';
  expectedPhrase: string;
  intentDigest: string;
  intentExpiresAt: string;
  intentNonce: string;
  createdAt: string;
  expiresAt: string;
  attemptCount: number | null;
  completedAt: string | null;
  resultJson: string | null;
  ownerPresenceEvidenceKind: 'available' | 'consumed' | null;
  ownerPresenceConsumedAt: string | null;
};

export function serializeEnrollmentRecordForCloudflare(
  record: VoiceIdEnrollmentRecord,
): VoiceIdCloudflareEnrollmentRow {
  switch (record.state) {
    case 'pending':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_enrollment',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        state: record.state,
        promptSetId: record.promptSetId,
        modelVersion: record.modelVersion,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        requiredSampleCount: record.requiredSampleCount,
        acceptedSampleCount: record.acceptedSampleCount,
        attemptCount: record.attemptCount,
        templateVersion: null,
        thresholdVersion: null,
        encryptedTemplate: null,
        enrolledAt: null,
        disabledAt: null,
      };
    case 'enrolled':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_enrollment',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        state: record.state,
        promptSetId: record.promptSetId,
        modelVersion: record.modelVersion,
        createdAt: record.createdAt,
        expiresAt: null,
        requiredSampleCount: null,
        acceptedSampleCount: null,
        attemptCount: null,
        templateVersion: record.templateVersion,
        thresholdVersion: record.thresholdVersion,
        encryptedTemplate: record.encryptedTemplate,
        enrolledAt: record.enrolledAt,
        disabledAt: null,
      };
    case 'disabled':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_enrollment',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        state: record.state,
        promptSetId: record.promptSetId,
        modelVersion: record.modelVersion,
        createdAt: record.createdAt,
        expiresAt: null,
        requiredSampleCount: null,
        acceptedSampleCount: null,
        attemptCount: null,
        templateVersion: record.templateVersion,
        thresholdVersion: record.thresholdVersion,
        encryptedTemplate: record.encryptedTemplate,
        enrolledAt: record.enrolledAt,
        disabledAt: record.disabledAt,
      };
  }
}

export function parseCloudflareEnrollmentRow(value: unknown): VoiceIdEnrollmentRecord {
  const row = parseObject(value, 'enrollment row');
  rejectRawCaptureColumns(row, 'enrollment row');
  assertLiteral(row.schemaVersion, storageSchemaVersion, 'schemaVersion');
  assertLiteral(row.recordKind, 'voice_id_enrollment', 'recordKind');

  const state = parseEnrollmentState(row.state);
  const userId = parseUserId(row.userId);
  const enrollmentId = parseEnrollmentId(row.enrollmentId);
  const promptSetId = parsePromptSetId(row.promptSetId);
  const modelVersion = parseModelVersion(row.modelVersion);
  const createdAt = parseIsoDateTime(row.createdAt);

  switch (state) {
    case 'pending':
      assertNull(row.templateVersion, 'pending.templateVersion');
      assertNull(row.thresholdVersion, 'pending.thresholdVersion');
      assertNull(row.encryptedTemplate, 'pending.encryptedTemplate');
      assertNull(row.enrolledAt, 'pending.enrolledAt');
      assertNull(row.disabledAt, 'pending.disabledAt');
      return {
        state,
        userId,
        enrollmentId,
        promptSetId,
        modelVersion,
        createdAt,
        expiresAt: parseIsoDateTime(row.expiresAt),
        requiredSampleCount: parseNonNegativeInteger(row.requiredSampleCount, 'requiredSampleCount'),
        acceptedSampleCount: parseNonNegativeInteger(row.acceptedSampleCount, 'acceptedSampleCount'),
        attemptCount: parseNonNegativeInteger(row.attemptCount, 'attemptCount'),
      };
    case 'enrolled':
      assertNull(row.expiresAt, 'enrolled.expiresAt');
      assertNull(row.requiredSampleCount, 'enrolled.requiredSampleCount');
      assertNull(row.acceptedSampleCount, 'enrolled.acceptedSampleCount');
      assertNull(row.attemptCount, 'enrolled.attemptCount');
      assertNull(row.disabledAt, 'enrolled.disabledAt');
      return {
        state,
        userId,
        enrollmentId,
        promptSetId,
        modelVersion,
        createdAt,
        templateVersion: parseTemplateVersion(row.templateVersion),
        thresholdVersion: parseThresholdVersion(row.thresholdVersion),
        encryptedTemplate: parseEncryptedBytes(row.encryptedTemplate),
        enrolledAt: parseIsoDateTime(row.enrolledAt),
      };
    case 'disabled':
      assertNull(row.expiresAt, 'disabled.expiresAt');
      assertNull(row.requiredSampleCount, 'disabled.requiredSampleCount');
      assertNull(row.acceptedSampleCount, 'disabled.acceptedSampleCount');
      assertNull(row.attemptCount, 'disabled.attemptCount');
      return {
        state,
        userId,
        enrollmentId,
        promptSetId,
        modelVersion,
        createdAt,
        templateVersion: parseTemplateVersion(row.templateVersion),
        thresholdVersion: parseThresholdVersion(row.thresholdVersion),
        encryptedTemplate: parseEncryptedBytes(row.encryptedTemplate),
        enrolledAt: parseIsoDateTime(row.enrolledAt),
        disabledAt: parseIsoDateTime(row.disabledAt),
      };
  }
}

export function serializeVerificationRecordForCloudflare(
  record: VoiceIdVerificationRecord,
): VoiceIdCloudflareVerificationRow {
  switch (record.state) {
    case 'issued':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_verification',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        state: record.state,
        expectedPhrase: record.expectedPhrase,
        intentDigest: record.intentDigest,
        intentExpiresAt: record.intentExpiresAt,
        intentNonce: record.intentNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        attemptCount: record.attemptCount,
        completedAt: null,
        resultJson: null,
        ownerPresenceEvidenceKind: null,
        ownerPresenceConsumedAt: null,
      };
    case 'accepted':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_verification',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        state: record.state,
        expectedPhrase: record.expectedPhrase,
        intentDigest: record.intentDigest,
        intentExpiresAt: record.intentExpiresAt,
        intentNonce: record.intentNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        attemptCount: null,
        completedAt: record.completedAt,
        resultJson: JSON.stringify(record.result),
        ownerPresenceEvidenceKind: record.ownerPresenceEvidence.kind,
        ownerPresenceConsumedAt: record.ownerPresenceEvidence.kind === 'consumed'
          ? record.ownerPresenceEvidence.consumedAt
          : null,
      };
    case 'rejected':
    case 'uncertain':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_verification',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        state: record.state,
        expectedPhrase: record.expectedPhrase,
        intentDigest: record.intentDigest,
        intentExpiresAt: record.intentExpiresAt,
        intentNonce: record.intentNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        attemptCount: null,
        completedAt: record.completedAt,
        resultJson: JSON.stringify(record.result),
        ownerPresenceEvidenceKind: null,
        ownerPresenceConsumedAt: null,
      };
    case 'expired':
      return {
        schemaVersion: storageSchemaVersion,
        recordKind: 'voice_id_verification',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        state: record.state,
        expectedPhrase: record.expectedPhrase,
        intentDigest: record.intentDigest,
        intentExpiresAt: record.intentExpiresAt,
        intentNonce: record.intentNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        attemptCount: null,
        completedAt: record.completedAt,
        resultJson: null,
        ownerPresenceEvidenceKind: null,
        ownerPresenceConsumedAt: null,
      };
  }
}

export function parseCloudflareVerificationRow(value: unknown): VoiceIdVerificationRecord {
  const row = parseObject(value, 'verification row');
  rejectRawCaptureColumns(row, 'verification row');
  assertLiteral(row.schemaVersion, storageSchemaVersion, 'schemaVersion');
  assertLiteral(row.recordKind, 'voice_id_verification', 'recordKind');

  const state = parseVerificationState(row.state);
  const base = {
    userId: parseUserId(row.userId),
    enrollmentId: parseEnrollmentId(row.enrollmentId),
    verificationId: parseVerificationId(row.verificationId),
    expectedPhrase: parsePromptPhrase(row.expectedPhrase),
    intentDigest: parseVoiceIdIntentDigest(row.intentDigest),
    intentExpiresAt: parseIsoDateTime(row.intentExpiresAt),
    intentNonce: parseVoiceIdIntentNonce(row.intentNonce),
    createdAt: parseIsoDateTime(row.createdAt),
    expiresAt: parseIsoDateTime(row.expiresAt),
  };

  switch (state) {
    case 'issued':
      assertNull(row.completedAt, 'issued.completedAt');
      assertNull(row.resultJson, 'issued.resultJson');
      assertNull(row.ownerPresenceEvidenceKind, 'issued.ownerPresenceEvidenceKind');
      assertNull(row.ownerPresenceConsumedAt, 'issued.ownerPresenceConsumedAt');
      return {
        ...base,
        state,
        attemptCount: parseNonNegativeInteger(row.attemptCount, 'attemptCount'),
      };
    case 'accepted': {
      assertNull(row.attemptCount, 'accepted.attemptCount');
      const result = parseVerificationResult(row.resultJson);
      if (result.kind !== 'accepted') {
        throw new Error('accepted verification row requires accepted result');
      }
      return {
        ...base,
        state,
        completedAt: parseIsoDateTime(row.completedAt),
        result,
        ownerPresenceEvidence: parseOwnerPresenceEvidenceState(row),
      };
    }
    case 'rejected': {
      assertNull(row.attemptCount, 'rejected.attemptCount');
      assertNull(row.ownerPresenceEvidenceKind, 'rejected.ownerPresenceEvidenceKind');
      assertNull(row.ownerPresenceConsumedAt, 'rejected.ownerPresenceConsumedAt');
      const result = parseVerificationResult(row.resultJson);
      if (result.kind !== 'rejected') {
        throw new Error('rejected verification row requires rejected result');
      }
      return {
        ...base,
        state,
        completedAt: parseIsoDateTime(row.completedAt),
        result,
      };
    }
    case 'uncertain': {
      assertNull(row.attemptCount, 'uncertain.attemptCount');
      assertNull(row.ownerPresenceEvidenceKind, 'uncertain.ownerPresenceEvidenceKind');
      assertNull(row.ownerPresenceConsumedAt, 'uncertain.ownerPresenceConsumedAt');
      const result = parseVerificationResult(row.resultJson);
      if (result.kind !== 'uncertain') {
        throw new Error('uncertain verification row requires uncertain result');
      }
      return {
        ...base,
        state,
        completedAt: parseIsoDateTime(row.completedAt),
        result,
      };
    }
    case 'expired':
      assertNull(row.attemptCount, 'expired.attemptCount');
      assertNull(row.resultJson, 'expired.resultJson');
      assertNull(row.ownerPresenceEvidenceKind, 'expired.ownerPresenceEvidenceKind');
      assertNull(row.ownerPresenceConsumedAt, 'expired.ownerPresenceConsumedAt');
      return {
        ...base,
        state,
        completedAt: parseIsoDateTime(row.completedAt),
      };
  }
}

function parseOwnerPresenceEvidenceState(
  row: Record<string, unknown>,
): Extract<VoiceIdVerificationRecord, { state: 'accepted' }>['ownerPresenceEvidence'] {
  switch (row.ownerPresenceEvidenceKind) {
    case 'available':
      assertNull(row.ownerPresenceConsumedAt, 'available.ownerPresenceConsumedAt');
      return { kind: 'available' };
    case 'consumed':
      return {
        kind: 'consumed',
        consumedAt: parseIsoDateTime(row.ownerPresenceConsumedAt),
      };
    default:
      throw new Error('accepted verification row requires owner-presence evidence state');
  }
}

function parseVerificationResult(value: unknown): VoiceIdVerificationResult {
  const result = parseJsonStringObject(value, 'verification result');
  const kind = parseString(result.kind, 'verification result kind');
  switch (kind) {
    case 'accepted':
      return {
        kind,
        enrollmentId: parseEnrollmentId(result.enrollmentId),
        verificationId: parseVerificationId(result.verificationId),
        templateVersion: parseTemplateVersion(result.templateVersion),
        modelVersion: parseModelVersion(result.modelVersion),
        thresholdVersion: parseThresholdVersion(result.thresholdVersion),
        checks: parseAcceptedChecks(result.checks),
      };
    case 'rejected':
      return {
        kind,
        verificationId: parseVerificationId(result.verificationId),
        reason: parseRejectedReason(result.reason),
        checks: parseChecks(result.checks),
      };
    case 'uncertain':
      return {
        kind,
        verificationId: parseVerificationId(result.verificationId),
        reason: parseUncertainReason(result.reason),
        checks: parseChecks(result.checks),
      };
    default:
      throw new Error('verification result kind is invalid');
  }
}

function parseAcceptedChecks(value: unknown): Extract<VoiceIdVerificationResult, { kind: 'accepted' }>['checks'] {
  const checks = parseChecks(value);
  if (checks.phrase.kind !== 'accepted' || checks.speaker.kind !== 'accepted' || checks.quality.kind !== 'accepted') {
    throw new Error('accepted verification result requires accepted checks');
  }

  return {
    phrase: checks.phrase,
    speaker: checks.speaker,
    quality: checks.quality,
  };
}

function parseChecks(value: unknown): VoiceIdVerificationChecks {
  const input = parseObject(value, 'verification checks');
  return {
    phrase: parsePhraseResult(input.phrase),
    speaker: parseSpeakerResult(input.speaker),
    quality: parseQualityResult(input.quality),
  };
}

function parsePhraseResult(value: unknown): VoiceIdPhraseMatchResult {
  const input = parseObject(value, 'phrase result');
  const base = {
    expectedNormalized: parseString(input.expectedNormalized, 'expectedNormalized'),
    spokenNormalized: parseString(input.spokenNormalized, 'spokenNormalized'),
    confidence: parseScore(input.confidence, 'phrase confidence'),
  };
  if (input.kind === 'accepted') {
    return { kind: 'accepted', ...base };
  }
  if (input.kind === 'rejected') {
    return { kind: 'rejected', reason: parsePhraseRejectedReason(input.reason), ...base };
  }
  if (input.kind === 'uncertain') {
    return { kind: 'uncertain', reason: parsePhraseUncertainReason(input.reason), ...base };
  }

  throw new Error('phrase result kind is invalid');
}

function parseSpeakerResult(value: unknown): VoiceIdSpeakerMatchResult {
  const input = parseObject(value, 'speaker result');
  const base = {
    score: parseScore(input.score, 'speaker score'),
    threshold: parseScore(input.threshold, 'speaker threshold'),
    modelVersion: parseModelVersion(input.modelVersion),
    thresholdVersion: parseThresholdVersion(input.thresholdVersion),
  };
  if (input.kind === 'accepted') {
    return { kind: 'accepted', ...base };
  }
  if (input.kind === 'rejected') {
    assertLiteral(input.reason, 'speaker_mismatch', 'speaker reason');
    return { kind: 'rejected', reason: 'speaker_mismatch', ...base };
  }
  if (input.kind === 'uncertain') {
    return { kind: 'uncertain', reason: parseSpeakerUncertainReason(input.reason), ...base };
  }

  throw new Error('speaker result kind is invalid');
}

function parseQualityResult(value: unknown): VoiceIdAudioQualityResult {
  const input = parseObject(value, 'quality result');
  const durationMs = parseNonNegativeNumber(input.durationMs, 'quality durationMs');
  if (input.kind === 'accepted') {
    return {
      kind: 'accepted',
      durationMs,
      signalScore: parseScore(input.signalScore, 'quality signalScore'),
    };
  }
  if (input.kind === 'rejected') {
    return {
      kind: 'rejected',
      reason: parseQualityRejectedReason(input.reason),
      durationMs,
    };
  }
  if (input.kind === 'uncertain') {
    return {
      kind: 'uncertain',
      reason: parseQualityUncertainReason(input.reason),
      durationMs,
    };
  }

  throw new Error('quality result kind is invalid');
}

function parseEnrollmentState(value: unknown): VoiceIdCloudflareEnrollmentRow['state'] {
  if (value === 'pending' || value === 'enrolled' || value === 'disabled') {
    return value;
  }

  throw new Error('enrollment row state is invalid');
}

function parseVerificationState(value: unknown): VoiceIdCloudflareVerificationRow['state'] {
  if (
    value === 'issued'
    || value === 'accepted'
    || value === 'rejected'
    || value === 'uncertain'
    || value === 'expired'
  ) {
    return value;
  }

  throw new Error('verification row state is invalid');
}

function parseRejectedReason(value: unknown): Extract<VoiceIdVerificationResult, { kind: 'rejected' }>['reason'] {
  if (
    value === 'phrase_mismatch'
    || value === 'speaker_mismatch'
    || value === 'low_audio_quality'
    || value === 'too_many_attempts'
    || value === 'expired'
  ) {
    return value;
  }

  throw new Error('rejected verification reason is invalid');
}

function parseUncertainReason(value: unknown): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>['reason'] {
  if (
    value === 'noisy_audio'
    || value === 'too_short'
    || value === 'model_low_confidence'
    || value === 'verifier_unavailable'
  ) {
    return value;
  }

  throw new Error('uncertain verification reason is invalid');
}

function parsePhraseRejectedReason(value: unknown): Extract<VoiceIdPhraseMatchResult, { kind: 'rejected' }>['reason'] {
  if (value === 'phrase_mismatch' || value === 'ambiguous_transcript') {
    return value;
  }

  throw new Error('phrase rejected reason is invalid');
}

function parsePhraseUncertainReason(value: unknown): Extract<VoiceIdPhraseMatchResult, { kind: 'uncertain' }>['reason'] {
  if (value === 'transcript_low_confidence' || value === 'transcript_unavailable') {
    return value;
  }

  throw new Error('phrase uncertain reason is invalid');
}

function parseSpeakerUncertainReason(value: unknown): Extract<VoiceIdSpeakerMatchResult, { kind: 'uncertain' }>['reason'] {
  if (value === 'model_low_confidence' || value === 'verifier_unavailable' || value === 'low_audio_quality') {
    return value;
  }

  throw new Error('speaker uncertain reason is invalid');
}

function parseQualityRejectedReason(value: unknown): Extract<VoiceIdAudioQualityResult, { kind: 'rejected' }>['reason'] {
  if (value === 'too_short' || value === 'empty_audio') {
    return value;
  }

  throw new Error('quality rejected reason is invalid');
}

function parseQualityUncertainReason(value: unknown): Extract<VoiceIdAudioQualityResult, { kind: 'uncertain' }>['reason'] {
  if (
    value === 'noisy_audio'
    || value === 'too_short'
    || value === 'model_low_confidence'
    || value === 'undecodable_audio'
    || value === 'clipped_audio'
    || value === 'low_speech'
    || value === 'low_snr'
  ) {
    return value;
  }

  throw new Error('quality uncertain reason is invalid');
}

function parseJsonStringObject(value: unknown, fieldName: string): Record<string, unknown> {
  const json = parseString(value, `${fieldName} JSON`);
  try {
    return parseObject(JSON.parse(json), fieldName);
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Error(`${fieldName} must be valid JSON`);
    }
    throw error;
  }
}

function parseObject(value: unknown, fieldName: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }

  return value as Record<string, unknown>;
}

function parseString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }

  return value;
}

function parseNonNegativeInteger(value: unknown, fieldName: string): number {
  const parsed = parseNonNegativeNumber(value, fieldName);
  if (!Number.isInteger(parsed)) {
    throw new Error(`${fieldName} must be an integer`);
  }

  return parsed;
}

function parseNonNegativeNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new Error(`${fieldName} must be a non-negative number`);
  }

  return value;
}

function parseScore(value: unknown, fieldName: string): number {
  const parsed = parseNonNegativeNumber(value, fieldName);
  if (parsed > 1) {
    throw new Error(`${fieldName} must be <= 1`);
  }

  return parsed;
}

function assertLiteral<TValue extends string | number>(
  value: unknown,
  expected: TValue,
  fieldName: string,
): asserts value is TValue {
  if (value !== expected) {
    throw new Error(`${fieldName} must be ${String(expected)}`);
  }
}

function assertNull(value: unknown, fieldName: string): asserts value is null {
  if (value !== null) {
    throw new Error(`${fieldName} must be null`);
  }
}

function rejectRawCaptureColumns(row: Record<string, unknown>, fieldName: string): void {
  for (const key of Object.keys(row)) {
    if (forbiddenRawCaptureColumns.has(key)) {
      throw new Error(`${fieldName} must not contain raw capture column ${key}`);
    }
  }
}
