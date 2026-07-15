import {
  assertExactObjectKeys,
  parseEncryptedBytes,
  parseEnrollmentId,
  parseEnrollmentPromptSequence,
  parseIsoDateTime,
  parseJsonObject,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdEnrollmentFailureReason,
  parseVoiceIdEvidenceObservedResult,
  parseVoiceIdRejectedResult,
  parseVoiceIdUncertainResult,
  parseVoiceIdChallengeNonce,
} from '../../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../../shared/src/records.ts';

const storageSchemaVersion = 4;

export type VoiceIdCloudflareEnrollmentRow = {
  schemaVersion: number;
  recordKind: 'enrollment';
  userId: string;
  enrollmentId: string;
  lifecycleState: VoiceIdEnrollmentRecord['state'];
  createdAt: string;
  recordJson: string;
};

export type VoiceIdCloudflareVerificationRow = {
  schemaVersion: number;
  recordKind: 'verification';
  userId: string;
  enrollmentId: string;
  verificationId: string;
  lifecycleState: VoiceIdVerificationRecord['state'];
  createdAt: string;
  recordJson: string;
};

export function serializeEnrollmentRecordForCloudflare(
  record: VoiceIdEnrollmentRecord,
): VoiceIdCloudflareEnrollmentRow {
  return {
    schemaVersion: storageSchemaVersion,
    recordKind: 'enrollment',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    lifecycleState: record.state,
    createdAt: record.createdAt,
    recordJson: JSON.stringify(record),
  };
}

export function serializeVerificationRecordForCloudflare(
  record: VoiceIdVerificationRecord,
): VoiceIdCloudflareVerificationRow {
  return {
    schemaVersion: storageSchemaVersion,
    recordKind: 'verification',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    lifecycleState: record.state,
    createdAt: record.createdAt,
    recordJson: JSON.stringify(record),
  };
}

export function parseCloudflareEnrollmentRow(
  row: VoiceIdCloudflareEnrollmentRow,
): VoiceIdEnrollmentRecord {
  assertRowHeader(row.schemaVersion, row.recordKind, 'enrollment');
  const record = parseEnrollmentRecord(parseStoredJson(row.recordJson, 'enrollment record'));
  if (
    record.userId !== row.userId
    || record.enrollmentId !== row.enrollmentId
    || record.state !== row.lifecycleState
    || record.createdAt !== row.createdAt
  ) {
    throw new Error('enrollment row indexes do not match record payload');
  }
  return record;
}

export function parseCloudflareVerificationRow(
  row: VoiceIdCloudflareVerificationRow,
): VoiceIdVerificationRecord {
  assertRowHeader(row.schemaVersion, row.recordKind, 'verification');
  const record = parseVerificationRecord(parseStoredJson(row.recordJson, 'verification record'));
  if (
    record.userId !== row.userId
    || record.enrollmentId !== row.enrollmentId
    || record.verificationId !== row.verificationId
    || record.state !== row.lifecycleState
    || record.createdAt !== row.createdAt
  ) {
    throw new Error('verification row indexes do not match record payload');
  }
  return record;
}

function parseEnrollmentRecord(value: unknown): VoiceIdEnrollmentRecord {
  const record = parseJsonObject(value, 'enrollment record');
  const common = {
    userId: parseUserId(record.userId),
    enrollmentId: parseEnrollmentId(record.enrollmentId),
    promptSetId: parsePromptSetId(record.promptSetId),
    modelVersion: parseModelVersion(record.modelVersion),
    createdAt: parseIsoDateTime(record.createdAt),
  };
  switch (record.state) {
    case 'pending_continuous_recording':
      assertExactObjectKeys(
        record,
        [
          'state', 'userId', 'enrollmentId', 'promptSetId', 'promptSequence',
          'modelVersion', 'createdAt', 'expiresAt', 'minimumCaptureMs',
          'targetCaptureMs', 'maximumCaptureMs',
        ],
        'pending enrollment record',
      );
      return {
        state: 'pending_continuous_recording',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        promptSetId: common.promptSetId,
        modelVersion: common.modelVersion,
        createdAt: common.createdAt,
        expiresAt: parseIsoDateTime(record.expiresAt),
        promptSequence: parseEnrollmentPromptSequence(record.promptSequence),
        minimumCaptureMs: parsePositiveNumber(record.minimumCaptureMs, 'minimumCaptureMs'),
        targetCaptureMs: parsePositiveNumber(record.targetCaptureMs, 'targetCaptureMs'),
        maximumCaptureMs: parsePositiveNumber(record.maximumCaptureMs, 'maximumCaptureMs'),
      };
    case 'analyzing_continuous_recording':
      assertExactObjectKeys(
        record,
        [
          'state', 'userId', 'enrollmentId', 'promptSetId', 'promptSequence',
          'modelVersion', 'createdAt', 'expiresAt', 'minimumCaptureMs',
          'targetCaptureMs', 'maximumCaptureMs', 'analysisStartedAt', 'analysisExpiresAt',
        ],
        'analyzing enrollment record',
      );
      return {
        state: 'analyzing_continuous_recording',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        promptSetId: common.promptSetId,
        modelVersion: common.modelVersion,
        createdAt: common.createdAt,
        expiresAt: parseIsoDateTime(record.expiresAt),
        promptSequence: parseEnrollmentPromptSequence(record.promptSequence),
        minimumCaptureMs: parsePositiveNumber(record.minimumCaptureMs, 'minimumCaptureMs'),
        targetCaptureMs: parsePositiveNumber(record.targetCaptureMs, 'targetCaptureMs'),
        maximumCaptureMs: parsePositiveNumber(record.maximumCaptureMs, 'maximumCaptureMs'),
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
      };
    case 'failed':
      assertExactObjectKeys(
        record,
        ['state', 'userId', 'enrollmentId', 'promptSetId', 'modelVersion', 'createdAt', 'failedAt', 'failureReason'],
        'failed enrollment record',
      );
      return {
        state: 'failed',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        promptSetId: common.promptSetId,
        modelVersion: common.modelVersion,
        createdAt: common.createdAt,
        failedAt: parseIsoDateTime(record.failedAt),
        failureReason: parseVoiceIdEnrollmentFailureReason(record.failureReason),
      };
    case 'enrolled':
      assertExactObjectKeys(
        record,
        [
          'state', 'userId', 'enrollmentId', 'promptSetId', 'modelVersion',
          'templateVersion', 'thresholdVersion', 'encryptedTemplate', 'createdAt', 'enrolledAt',
        ],
        'enrolled record',
      );
      return {
        state: 'enrolled',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        promptSetId: common.promptSetId,
        modelVersion: common.modelVersion,
        createdAt: common.createdAt,
        templateVersion: parseTemplateVersion(record.templateVersion),
        thresholdVersion: parseThresholdVersion(record.thresholdVersion),
        encryptedTemplate: parseEncryptedBytes(record.encryptedTemplate),
        enrolledAt: parseIsoDateTime(record.enrolledAt),
      };
    case 'disabled':
      assertExactObjectKeys(
        record,
        [
          'state', 'userId', 'enrollmentId', 'promptSetId', 'modelVersion',
          'templateVersion', 'thresholdVersion', 'encryptedTemplate', 'createdAt',
          'enrolledAt', 'disabledAt',
        ],
        'disabled enrollment record',
      );
      return {
        state: 'disabled',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        promptSetId: common.promptSetId,
        modelVersion: common.modelVersion,
        createdAt: common.createdAt,
        templateVersion: parseTemplateVersion(record.templateVersion),
        thresholdVersion: parseThresholdVersion(record.thresholdVersion),
        encryptedTemplate: parseEncryptedBytes(record.encryptedTemplate),
        enrolledAt: parseIsoDateTime(record.enrolledAt),
        disabledAt: parseIsoDateTime(record.disabledAt),
      };
    default:
      throw new Error('enrollment record state is invalid');
  }
}

function parseVerificationRecord(value: unknown): VoiceIdVerificationRecord {
  const record = parseJsonObject(value, 'verification record');
  const common = {
    userId: parseUserId(record.userId),
    enrollmentId: parseEnrollmentId(record.enrollmentId),
    verificationId: parseVerificationId(record.verificationId),
    expectedPhrase: parsePromptPhrase(record.expectedPhrase),
    challengeNonce: parseVoiceIdChallengeNonce(record.challengeNonce),
    createdAt: parseIsoDateTime(record.createdAt),
    expiresAt: parseIsoDateTime(record.expiresAt),
  };
  switch (record.state) {
    case 'issued':
      assertExactObjectKeys(record, verificationRecordKeys([]), 'issued verification record');
      return {
        state: 'issued',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
      };
    case 'analyzing':
      assertExactObjectKeys(
        record,
        verificationRecordKeys(['analysisStartedAt', 'analysisExpiresAt']),
        'analyzing verification record',
      );
      return {
        state: 'analyzing',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
      };
    case 'evidence_observed':
      assertExactObjectKeys(
        record,
        verificationRecordKeys(['analysisStartedAt', 'analysisExpiresAt', 'completedAt', 'result']),
        'observed verification record',
      );
      return {
        state: 'evidence_observed',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
        completedAt: parseIsoDateTime(record.completedAt),
        result: parseVoiceIdEvidenceObservedResult(record.result),
      };
    case 'rejected':
      assertExactObjectKeys(
        record,
        verificationRecordKeys(['analysisStartedAt', 'analysisExpiresAt', 'completedAt', 'result']),
        'rejected verification record',
      );
      return {
        state: 'rejected',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
        completedAt: parseIsoDateTime(record.completedAt),
        result: parseVoiceIdRejectedResult(record.result),
      };
    case 'uncertain':
      assertExactObjectKeys(
        record,
        verificationRecordKeys(['analysisStartedAt', 'analysisExpiresAt', 'completedAt', 'result']),
        'uncertain verification record',
      );
      return {
        state: 'uncertain',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
        completedAt: parseIsoDateTime(record.completedAt),
        result: parseVoiceIdUncertainResult(record.result),
      };
    case 'expired':
      assertExactObjectKeys(
        record,
        [
          'state', 'userId', 'enrollmentId', 'verificationId', 'expectedPhrase',
          'challengeNonce', 'createdAt', 'expiresAt', 'completedAt',
        ],
        'expired verification record',
      );
      return {
        state: 'expired',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        completedAt: parseIsoDateTime(record.completedAt),
      };
    case 'analysis_failed':
      assertExactObjectKeys(
        record,
        verificationRecordKeys([
          'analysisStartedAt',
          'analysisExpiresAt',
          'completedAt',
          'failureReason',
        ]),
        'failed verification analysis record',
      );
      if (record.failureReason !== 'analysis_timeout') {
        throw new Error('verification analysis failure reason is invalid');
      }
      return {
        state: 'analysis_failed',
        userId: common.userId,
        enrollmentId: common.enrollmentId,
        verificationId: common.verificationId,
        expectedPhrase: common.expectedPhrase,
        challengeNonce: common.challengeNonce,
        createdAt: common.createdAt,
        expiresAt: common.expiresAt,
        analysisStartedAt: parseIsoDateTime(record.analysisStartedAt),
        analysisExpiresAt: parseIsoDateTime(record.analysisExpiresAt),
        completedAt: parseIsoDateTime(record.completedAt),
        failureReason: 'analysis_timeout',
      };
    default:
      throw new Error('verification record state is invalid');
  }
}

function parseStoredJson(value: unknown, fieldName: string): unknown {
  if (typeof value !== 'string') throw new Error(`${fieldName} must be JSON text`);
  return JSON.parse(value) as unknown;
}

function assertRowHeader(actualVersion: unknown, actualKind: unknown, expectedKind: string): void {
  if (actualVersion !== storageSchemaVersion || actualKind !== expectedKind) {
    throw new Error(`${expectedKind} row header is invalid`);
  }
}

function verificationRecordKeys(branchKeys: readonly string[]): readonly string[] {
  const keys = [
    'state', 'userId', 'enrollmentId', 'verificationId', 'expectedPhrase',
    'challengeNonce', 'createdAt', 'expiresAt',
  ];
  return [...keys, ...branchKeys];
}

function parsePositiveNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return value;
}
