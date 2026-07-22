import {
  assertNever,
  buildAudioInput,
  combineEnrollmentPromptSequence,
  normalizePromptPhrase,
  nowIsoDateTime,
  parseEnrollmentId,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  type IsoDateTime,
  type UserId,
  type VoiceIdAudioInput,
  type VoiceIdAudioQualityResult,
  type VoiceIdChallengeNonce,
  type VoiceIdEnrollmentId,
  type VoiceIdEnrollmentPromptSequence,
  type VoiceIdModelVersion,
  type VoiceIdOperationError,
  type VoiceIdPromptPhrase,
  type VoiceIdPromptSetId,
  type VoiceIdThresholdVersion,
  type VoiceIdVerificationId,
} from '../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../shared/src/records.ts';
import type {
  VoiceIdEnrollmentRecording,
  VoiceIdVerificationRecording,
} from '../../shared/src/samples.ts';
import type {
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
  VoiceIdVerificationChecks,
  VoiceIdVerificationResult,
} from '../../shared/src/results.ts';
import type {
  VoiceIdEnrollmentTemplateBuildResult,
  VoiceIdSpeakerVerification,
  VoiceIdVerifier,
} from './verifier/VoiceIdVerifier.ts';
import type { VoiceIdEnrollmentStore, VoiceIdVerificationStore } from './store/VoiceIdStores.ts';
import type { VoiceIdTranscriptProvider } from './transcript/VoiceIdTranscriptProvider.ts';

export const voiceIdFakeSpeakerScoreThreshold = 0.82;
export const voiceIdEcapaLocalDevSpeakerScoreThreshold = 0.6352;

const defaultEnrollmentPrompts: VoiceIdEnrollmentPromptSequence = [
  parsePromptPhrase('Copper river carries morning light'),
  parsePromptPhrase('Seven quiet lanterns cross the harbor'),
  parsePromptPhrase('Bright cedar branches move in winter'),
  parsePromptPhrase('A silver compass points toward home'),
];

const defaultVerificationPromptBases: readonly VoiceIdPromptPhrase[] = [
  parsePromptPhrase('River lantern'),
  parsePromptPhrase('Silver meadow'),
  parsePromptPhrase('Cedar compass'),
  parsePromptPhrase('Harbor sunrise'),
];

export function parseVoiceIdSpeakerScoreThreshold(value: unknown, fieldName: string): number {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a probability string`);
  }
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new Error(`${fieldName} must be a probability string`);
  }
  return parsed;
}

export type VoiceIdServiceConfig = {
  enrollmentPromptTtlMs: number;
  verificationPromptTtlMs: number;
  enrollmentAnalysisTtlMs: number;
  verificationAnalysisTtlMs: number;
  minimumEnrollmentCaptureMs: number;
  targetEnrollmentCaptureMs: number;
  maximumEnrollmentCaptureMs: number;
  speakerScoreThreshold: number;
  promptSetId: VoiceIdPromptSetId;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  enrollmentPrompts: VoiceIdEnrollmentPromptSequence;
  verificationPromptBases: readonly VoiceIdPromptPhrase[];
};

export type VoiceIdLifecycleAuditEvent = {
  kind:
    | 'enrollment_started'
    | 'enrollment_completed'
    | 'enrollment_failed'
    | 'verification_issued'
    | 'verification_completed';
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId | null;
  resultKind: VoiceIdAuditResultKind;
  scoreBands: VoiceIdAuditScoreBands;
  at: IsoDateTime;
};

export type VoiceIdAuditEvent = VoiceIdLifecycleAuditEvent;

export type VoiceIdAuditResultKind =
  | 'issued'
  | 'evidence_observed'
  | 'rejected'
  | 'uncertain'
  | 'enrolled'
  | 'failed';

export type VoiceIdAuditScoreBand = 'none' | 'very_low' | 'low' | 'medium' | 'high';

export type VoiceIdAuditScoreBands =
  | { kind: 'none' }
  | {
      kind: 'enrollment_recording';
      qualitySignal: VoiceIdAuditScoreBand;
      phraseConfidence: VoiceIdAuditScoreBand;
    }
  | {
      kind: 'verification';
      phraseConfidence: VoiceIdAuditScoreBand;
      speakerScore: VoiceIdAuditScoreBand;
      speakerThreshold: VoiceIdAuditScoreBand;
      qualitySignal: VoiceIdAuditScoreBand;
    };

export type VoiceIdServiceError = VoiceIdOperationError;

export type VoiceIdServiceResult<TValue> =
  | { kind: 'ok'; value: TValue }
  | { kind: 'error'; error: VoiceIdServiceError };

export type StartEnrollmentResult = {
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>;
  promptSequence: VoiceIdEnrollmentPromptSequence;
};

export type SubmitEnrollmentRecordingResult =
  | {
      kind: 'enrolled';
      record: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>;
      quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
      phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
    }
  | {
      kind: 'rejected';
      record: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>;
      reason: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'];
    };

export type StartVerificationResult = {
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>;
  prompt: VoiceIdPromptPhrase;
};

export type VoiceIdServiceDependencies = {
  enrollmentStore: VoiceIdEnrollmentStore;
  verificationStore: VoiceIdVerificationStore;
  verifier: VoiceIdVerifier;
  transcriptProvider: VoiceIdTranscriptProvider;
  config: VoiceIdServiceConfig;
  now: () => Date;
  createChallengeNonce: () => VoiceIdChallengeNonce;
  emitAuditEvent: (event: VoiceIdAuditEvent) => void;
};

export class VoiceIdService {
  constructor(private readonly dependencies: VoiceIdServiceDependencies) {}

  async startEnrollment(input: {
    userId: UserId;
  }): Promise<VoiceIdServiceResult<StartEnrollmentResult>> {
    const now = this.now();
    const enrollmentId = parseEnrollmentId(`enroll_${this.dependencies.createChallengeNonce()}`);
    const record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }> = {
      state: 'pending_continuous_recording',
      userId: input.userId,
      enrollmentId,
      promptSetId: this.dependencies.config.promptSetId,
      promptSequence: this.dependencies.config.enrollmentPrompts,
      modelVersion: this.dependencies.config.modelVersion,
      createdAt: now,
      expiresAt: this.futureIso(this.dependencies.config.enrollmentPromptTtlMs),
      minimumCaptureMs: this.dependencies.config.minimumEnrollmentCaptureMs,
      targetCaptureMs: this.dependencies.config.targetEnrollmentCaptureMs,
      maximumCaptureMs: this.dependencies.config.maximumEnrollmentCaptureMs,
    };

    const created = await this.dependencies.enrollmentStore.create(record);
    if (!created) {
      return lifecycleConflict('enrollment id is already in use');
    }
    this.emitAudit('enrollment_started', record, null, 'issued', noAuditScores());
    return { kind: 'ok', value: { record, promptSequence: record.promptSequence } };
  }

  async submitEnrollmentRecording(
    recording: VoiceIdEnrollmentRecording,
  ): Promise<VoiceIdServiceResult<SubmitEnrollmentRecordingResult>> {
    const record = await this.dependencies.enrollmentStore.getByEnrollmentId(
      recording.enrollmentId,
    );
    if (record === null) {
      return {
        kind: 'error',
        error: { kind: 'missing_enrollment', message: 'enrollment does not exist' },
      };
    }
    if (record.userId !== recording.userId) {
      return {
        kind: 'error',
        error: { kind: 'identity_mismatch', message: 'enrollment user does not match' },
      };
    }
    if (record.state === 'analyzing_continuous_recording') {
      if (this.isExpired(record.analysisExpiresAt)) {
        return await this.rejectEnrollmentAnalysis(record, 'analysis_timeout');
      }
      return {
        kind: 'error',
        error: { kind: 'invalid_state', message: 'enrollment recording is being analyzed' },
      };
    }
    if (record.state !== 'pending_continuous_recording') {
      return {
        kind: 'error',
        error: { kind: 'invalid_state', message: 'enrollment recording is already completed' },
      };
    }
    if (this.isExpired(record.expiresAt)) {
      return await this.rejectPendingEnrollment(record, 'expired');
    }
    if (recording.audio.metadata.durationMs < record.minimumCaptureMs) {
      return await this.rejectPendingEnrollment(record, 'capture_too_short');
    }
    if (recording.audio.metadata.durationMs > record.maximumCaptureMs) {
      return await this.rejectPendingEnrollment(record, 'capture_too_long');
    }

    const analysis = buildEnrollmentAnalysisClaim(
      record,
      this.now(),
      this.futureIso(this.dependencies.config.enrollmentAnalysisTtlMs),
    );
    const claimed = await this.dependencies.enrollmentStore.claimPending(analysis);
    if (!claimed) {
      return lifecycleConflict('enrollment recording was claimed concurrently');
    }

    const expectedPhrase = combineEnrollmentPromptSequence(analysis.promptSequence);
    const phrase = await this.matchPhrase(recording.audio, expectedPhrase);
    if (this.isExpired(analysis.analysisExpiresAt)) {
      return await this.rejectEnrollmentAnalysis(analysis, 'analysis_timeout');
    }
    if (phrase.kind === 'rejected') {
      return await this.rejectEnrollmentAnalysis(analysis, 'phrase_rejected');
    }
    if (phrase.kind === 'uncertain') {
      const reason =
        phrase.reason === 'transcript_unavailable'
          ? 'verifier_unavailable'
          : 'transcript_uncertain';
      return await this.rejectEnrollmentAnalysis(analysis, reason);
    }

    const template = await this.buildEnrollmentTemplate(
      recording.audio,
      analysis.promptSequence.length,
    );
    if (this.isExpired(analysis.analysisExpiresAt)) {
      return await this.rejectEnrollmentAnalysis(analysis, 'analysis_timeout');
    }
    if (template === null) {
      return await this.rejectEnrollmentAnalysis(analysis, 'verifier_unavailable');
    }
    if (template.kind === 'rejected') {
      return await this.rejectEnrollmentAnalysis(analysis, template.reason);
    }

    const enrolled: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }> = {
      state: 'enrolled',
      userId: analysis.userId,
      enrollmentId: analysis.enrollmentId,
      promptSetId: analysis.promptSetId,
      modelVersion: template.modelVersion,
      templateVersion: template.templateVersion,
      thresholdVersion: template.thresholdVersion,
      encryptedTemplate: template.encryptedTemplate,
      createdAt: analysis.createdAt,
      enrolledAt: this.now(),
    };
    const completed = await this.dependencies.enrollmentStore.completeAnalysis(enrolled);
    if (!completed) {
      return lifecycleConflict('enrollment recording was consumed concurrently');
    }
    this.emitAudit(
      'enrollment_completed',
      enrolled,
      null,
      'enrolled',
      enrollmentAuditScoreBands(template.quality, phrase),
    );
    return {
      kind: 'ok',
      value: { kind: 'enrolled', record: enrolled, quality: template.quality, phrase },
    };
  }

  async disableEnrollment(input: {
    userId: UserId;
    enrollmentId: VoiceIdEnrollmentId;
  }): Promise<VoiceIdServiceResult<Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>>> {
    const record = await this.dependencies.enrollmentStore.getByEnrollmentId(input.enrollmentId);
    if (record === null) {
      return {
        kind: 'error',
        error: { kind: 'missing_enrollment', message: 'enrollment does not exist' },
      };
    }
    if (record.userId !== input.userId) {
      return {
        kind: 'error',
        error: { kind: 'identity_mismatch', message: 'enrollment user does not match' },
      };
    }
    if (record.state !== 'enrolled') {
      return {
        kind: 'error',
        error: { kind: 'invalid_state', message: 'only enrolled records can be disabled' },
      };
    }

    const disabled: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }> = {
      state: 'disabled',
      userId: record.userId,
      enrollmentId: record.enrollmentId,
      promptSetId: record.promptSetId,
      modelVersion: record.modelVersion,
      templateVersion: record.templateVersion,
      thresholdVersion: record.thresholdVersion,
      encryptedTemplate: record.encryptedTemplate,
      createdAt: record.createdAt,
      enrolledAt: record.enrolledAt,
      disabledAt: this.now(),
    };
    const transitioned = await this.dependencies.enrollmentStore.disable(disabled);
    if (!transitioned) {
      return lifecycleConflict('enrollment changed before disablement completed');
    }
    return { kind: 'ok', value: disabled };
  }

  async startVerification(input: {
    userId: UserId;
    enrollmentId: VoiceIdEnrollmentId;
  }): Promise<VoiceIdServiceResult<StartVerificationResult>> {
    const enrollment = await this.dependencies.enrollmentStore.getByEnrollmentId(
      input.enrollmentId,
    );
    if (enrollment === null || enrollment.state !== 'enrolled') {
      return {
        kind: 'error',
        error: { kind: 'missing_enrollment', message: 'active enrollment does not exist' },
      };
    }
    if (enrollment.userId !== input.userId) {
      return {
        kind: 'error',
        error: { kind: 'identity_mismatch', message: 'enrollment user does not match' },
      };
    }

    const now = this.now();
    const challengeNonce = this.dependencies.createChallengeNonce();
    const verificationId = parseVerificationId(`verify_${challengeNonce}`);
    const expectedPhrase = buildVerificationPrompt(
      challengeNonce,
      this.dependencies.config.verificationPromptBases,
    );
    const record: Extract<VoiceIdVerificationRecord, { state: 'issued' }> = {
      state: 'issued',
      userId: input.userId,
      enrollmentId: input.enrollmentId,
      verificationId,
      expectedPhrase,
      challengeNonce,
      createdAt: now,
      expiresAt: this.futureIso(this.dependencies.config.verificationPromptTtlMs),
    };
    const created = await this.dependencies.verificationStore.create(record);
    if (!created) {
      return lifecycleConflict('verification id is already in use');
    }
    this.emitAudit('verification_issued', enrollment, verificationId, 'issued', noAuditScores());
    return { kind: 'ok', value: { record, prompt: expectedPhrase } };
  }

  async submitVerificationRecording(
    recording: VoiceIdVerificationRecording,
  ): Promise<VoiceIdServiceResult<VoiceIdVerificationResult>> {
    const verification = await this.dependencies.verificationStore.getByVerificationId(
      recording.verificationId,
    );
    if (verification === null) {
      return {
        kind: 'error',
        error: { kind: 'missing_verification', message: 'verification does not exist' },
      };
    }
    if (
      verification.userId !== recording.userId ||
      verification.enrollmentId !== recording.enrollmentId
    ) {
      return {
        kind: 'error',
        error: { kind: 'identity_mismatch', message: 'verification identity does not match' },
      };
    }
    if (verification.state === 'analyzing') {
      if (this.isExpired(verification.analysisExpiresAt)) {
        return await this.expireVerificationAnalysis(verification);
      }
      return {
        kind: 'error',
        error: { kind: 'invalid_state', message: 'verification capture is being analyzed' },
      };
    }
    if (verification.state !== 'issued') {
      return {
        kind: 'error',
        error: { kind: 'invalid_state', message: 'verification capture is already completed' },
      };
    }
    if (this.isExpired(verification.expiresAt)) {
      const expired = buildExpiredVerificationRecord(verification, this.now());
      const consumed = await this.dependencies.verificationStore.expireIssued(expired);
      if (!consumed) {
        return lifecycleConflict('verification challenge was consumed concurrently');
      }
      return {
        kind: 'error',
        error: { kind: 'expired', message: 'verification challenge expired' },
      };
    }

    const enrollment = await this.dependencies.enrollmentStore.getByEnrollmentId(
      recording.enrollmentId,
    );
    if (enrollment === null || enrollment.state !== 'enrolled') {
      return {
        kind: 'error',
        error: { kind: 'missing_enrollment', message: 'active enrollment does not exist' },
      };
    }

    const analysis = buildVerificationAnalysisClaim(
      verification,
      this.now(),
      this.futureIso(this.dependencies.config.verificationAnalysisTtlMs),
    );
    const claimed = await this.dependencies.verificationStore.claimIssued(analysis);
    if (!claimed) {
      return lifecycleConflict('verification challenge was claimed concurrently');
    }

    const [phrase, speakerVerification] = await Promise.all([
      this.matchPhrase(recording.audio, analysis.expectedPhrase),
      this.verifySpeaker(recording.audio, enrollment),
    ]);
    if (this.isExpired(analysis.analysisExpiresAt)) {
      return await this.expireVerificationAnalysis(analysis);
    }
    const checks: VoiceIdVerificationChecks = {
      phrase,
      quality: speakerVerification.quality,
      speaker: speakerVerification.speaker,
    };
    const completedAt = this.now();
    const result = buildVerificationResult({
      verification: analysis,
      enrollment,
      checks,
      completedAt,
    });
    const completedRecord = buildCompletedVerificationRecord(analysis, completedAt, result);
    const consumed = await this.dependencies.verificationStore.completeAnalysis(completedRecord);
    if (!consumed) {
      return lifecycleConflict('verification challenge was consumed concurrently');
    }
    this.emitAudit(
      'verification_completed',
      enrollment,
      recording.verificationId,
      result.kind,
      verificationAuditScoreBands(checks),
    );
    return { kind: 'ok', value: result };
  }

  private async rejectPendingEnrollment(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
    reason: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'],
  ): Promise<VoiceIdServiceResult<SubmitEnrollmentRecordingResult>> {
    const failed = buildFailedEnrollmentRecord(record, reason, this.now());
    const completed = await this.dependencies.enrollmentStore.failPending(failed);
    if (!completed) {
      return lifecycleConflict('enrollment recording was consumed concurrently');
    }
    this.emitAudit('enrollment_failed', failed, null, 'failed', noAuditScores());
    return { kind: 'ok', value: { kind: 'rejected', record: failed, reason } };
  }

  private async rejectEnrollmentAnalysis(
    record: Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }>,
    reason: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'],
  ): Promise<VoiceIdServiceResult<SubmitEnrollmentRecordingResult>> {
    const failed = buildFailedEnrollmentRecord(record, reason, this.now());
    const completed = await this.dependencies.enrollmentStore.completeAnalysis(failed);
    if (!completed) {
      return lifecycleConflict('enrollment analysis was completed concurrently');
    }
    this.emitAudit('enrollment_failed', failed, null, 'failed', noAuditScores());
    return { kind: 'ok', value: { kind: 'rejected', record: failed, reason } };
  }

  private async expireVerificationAnalysis(
    record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>,
  ): Promise<VoiceIdServiceResult<VoiceIdVerificationResult>> {
    const failed = buildFailedVerificationAnalysisRecord(record, this.now());
    const completed = await this.dependencies.verificationStore.completeAnalysis(failed);
    if (!completed) {
      return lifecycleConflict('verification analysis recovery raced another request');
    }
    return {
      kind: 'error',
      error: { kind: 'expired', message: 'verification analysis lease expired' },
    };
  }

  private async buildEnrollmentTemplate(
    audio: VoiceIdAudioInput,
    expectedPromptCount: number,
  ): Promise<VoiceIdEnrollmentTemplateBuildResult | null> {
    try {
      return await this.dependencies.verifier.buildEnrollmentTemplate({
        audio,
        expectedPromptCount,
      });
    } catch {
      return null;
    }
  }

  private async matchPhrase(
    audio: VoiceIdAudioInput,
    expectedPhrase: VoiceIdPromptPhrase,
  ): Promise<VoiceIdPhraseMatchResult> {
    try {
      return await this.dependencies.transcriptProvider.matchPhrase({ audio, expectedPhrase });
    } catch {
      return {
        kind: 'uncertain',
        reason: 'transcript_unavailable',
        expectedNormalized: normalizePromptPhrase(expectedPhrase),
        spokenNormalized: '',
        confidence: 0,
      };
    }
  }

  private async verifySpeaker(
    audio: VoiceIdAudioInput,
    enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>,
  ): Promise<VoiceIdSpeakerVerification> {
    try {
      return await this.dependencies.verifier.verifySpeaker({
        audio,
        threshold: this.dependencies.config.speakerScoreThreshold,
        template: {
          encryptedTemplate: enrollment.encryptedTemplate,
          templateVersion: enrollment.templateVersion,
          modelVersion: enrollment.modelVersion,
          thresholdVersion: enrollment.thresholdVersion,
        },
      });
    } catch {
      return unavailableSpeakerVerification(audio, this.dependencies.config);
    }
  }

  private emitAudit(
    kind: VoiceIdLifecycleAuditEvent['kind'],
    record: VoiceIdEnrollmentRecord,
    verificationId: VoiceIdVerificationId | null,
    resultKind: VoiceIdAuditResultKind,
    scoreBands: VoiceIdAuditScoreBands,
  ): void {
    this.dependencies.emitAuditEvent({
      kind,
      userId: record.userId,
      enrollmentId: record.enrollmentId,
      verificationId,
      resultKind,
      scoreBands,
      at: this.now(),
    });
  }

  private now(): IsoDateTime {
    return nowIsoDateTime(this.dependencies.now());
  }

  private futureIso(ttlMs: number): IsoDateTime {
    return nowIsoDateTime(new Date(this.dependencies.now().getTime() + ttlMs));
  }

  private isExpired(expiresAt: IsoDateTime): boolean {
    return Date.parse(expiresAt) <= this.dependencies.now().getTime();
  }
}

export function defaultVoiceIdServiceConfig(
  input: {
    speakerScoreThreshold?: number;
  } = {},
): VoiceIdServiceConfig {
  return {
    enrollmentPromptTtlMs: 10 * 60 * 1000,
    verificationPromptTtlMs: 2 * 60 * 1000,
    enrollmentAnalysisTtlMs: 60 * 1000,
    verificationAnalysisTtlMs: 30 * 1000,
    minimumEnrollmentCaptureMs: 12_000,
    targetEnrollmentCaptureMs: 18_000,
    maximumEnrollmentCaptureMs: 30_000,
    speakerScoreThreshold: input.speakerScoreThreshold ?? voiceIdFakeSpeakerScoreThreshold,
    promptSetId: parsePromptSetId('voiceid-continuous-prompts-v1'),
    modelVersion: parseModelVersion('voiceid-e0-research-model-v1'),
    thresholdVersion: parseThresholdVersion('voiceid-e0-research-threshold-v1'),
    enrollmentPrompts: defaultEnrollmentPrompts,
    verificationPromptBases: defaultVerificationPromptBases,
  };
}

export function makeDemoAudioInput(input: {
  durationMs: number;
  bytes?: Uint8Array;
}): VoiceIdAudioInput {
  const bytes = input.bytes ?? new Uint8Array([1, 2, 3, 4]);
  return buildAudioInput(bytes, {
    mimeType: 'audio/webm',
    durationMs: input.durationMs,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength: bytes.byteLength,
    capturedAt: nowIsoDateTime(),
    recorder: 'test',
  });
}

function buildEnrollmentAnalysisClaim(
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
  analysisStartedAt: IsoDateTime,
  analysisExpiresAt: IsoDateTime,
): Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }> {
  return {
    state: 'analyzing_continuous_recording',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    promptSetId: record.promptSetId,
    promptSequence: record.promptSequence,
    modelVersion: record.modelVersion,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    minimumCaptureMs: record.minimumCaptureMs,
    targetCaptureMs: record.targetCaptureMs,
    maximumCaptureMs: record.maximumCaptureMs,
    analysisStartedAt,
    analysisExpiresAt,
  };
}

function buildFailedEnrollmentRecord(
  record: Extract<VoiceIdEnrollmentRecord, {
    state: 'pending_continuous_recording' | 'analyzing_continuous_recording';
  }>,
  failureReason: Extract<VoiceIdEnrollmentRecord, { state: 'failed' }>['failureReason'],
  failedAt: IsoDateTime,
): Extract<VoiceIdEnrollmentRecord, { state: 'failed' }> {
  return {
    state: 'failed',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    promptSetId: record.promptSetId,
    modelVersion: record.modelVersion,
    createdAt: record.createdAt,
    failedAt,
    failureReason,
  };
}

function buildVerificationAnalysisClaim(
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
  analysisStartedAt: IsoDateTime,
  analysisExpiresAt: IsoDateTime,
): Extract<VoiceIdVerificationRecord, { state: 'analyzing' }> {
  return {
    state: 'analyzing',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analysisStartedAt,
    analysisExpiresAt,
  };
}

function buildFailedVerificationAnalysisRecord(
  record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>,
  completedAt: IsoDateTime,
): Extract<VoiceIdVerificationRecord, { state: 'analysis_failed' }> {
  return {
    state: 'analysis_failed',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analysisStartedAt: record.analysisStartedAt,
    analysisExpiresAt: record.analysisExpiresAt,
    completedAt,
    failureReason: 'analysis_timeout',
  };
}

function buildVerificationPrompt(
  nonce: VoiceIdChallengeNonce,
  promptBases: readonly VoiceIdPromptPhrase[],
): VoiceIdPromptPhrase {
  if (promptBases.length === 0) {
    throw new Error('verification prompt bases must not be empty');
  }
  const selector = nonce.charCodeAt(nonce.length - 1) % promptBases.length;
  const base = promptBases[selector];
  const randomFragment = nonce.slice(-6).split('').join(' ');
  return parsePromptPhrase(`${base}. ${randomFragment}`);
}

function unavailableSpeakerVerification(
  audio: VoiceIdAudioInput,
  config: VoiceIdServiceConfig,
): VoiceIdSpeakerVerification {
  return {
    quality: {
      kind: 'uncertain',
      reason: 'verifier_unavailable',
      durationMs: audio.metadata.durationMs,
    },
    speaker: {
      kind: 'uncertain',
      reason: 'verifier_unavailable',
      score: 0,
      threshold: config.speakerScoreThreshold,
      modelVersion: config.modelVersion,
      thresholdVersion: config.thresholdVersion,
    },
  };
}

function buildVerificationResult(input: {
  verification: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>;
  enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>;
  checks: VoiceIdVerificationChecks;
  completedAt: IsoDateTime;
}): VoiceIdVerificationResult {
  if (input.checks.quality.kind === 'rejected') {
    return rejectedVerification(
      input.verification.verificationId,
      'low_audio_quality',
      input.checks,
    );
  }
  if (input.checks.quality.kind === 'uncertain') {
    return uncertainVerification(
      input.verification.verificationId,
      uncertainReasonFromQuality(input.checks.quality),
      input.checks,
    );
  }
  if (input.checks.phrase.kind === 'rejected') {
    return rejectedVerification(input.verification.verificationId, 'phrase_mismatch', input.checks);
  }
  if (input.checks.speaker.kind === 'rejected') {
    return rejectedVerification(
      input.verification.verificationId,
      'speaker_mismatch',
      input.checks,
    );
  }
  if (input.checks.phrase.kind === 'uncertain' || input.checks.speaker.kind === 'uncertain') {
    return uncertainVerification(
      input.verification.verificationId,
      uncertainReasonFromChecks(input.checks),
      input.checks,
    );
  }

  return {
    kind: 'evidence_observed',
    evidence: {
      kind: 'experimental_browser_evidence',
      verificationId: input.verification.verificationId,
      enrollmentId: input.enrollment.enrollmentId,
      observedChecks: {
        phrase: input.checks.phrase,
        speaker: input.checks.speaker,
        quality: input.checks.quality,
        captureFreshness: {
          kind: 'browser_timing_observation',
          challengeIssuedAt: input.verification.createdAt,
          captureReceivedAt: input.completedAt,
          serverVerifiedFreshness: false,
        },
        pad: { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' },
        captureProfile: {
          kind: 'ordinary_browser_capture',
          source: 'media_recorder',
          microphoneIntegrity: 'unverified',
        },
      },
      modelVersion: input.enrollment.modelVersion,
      thresholdVersion: input.enrollment.thresholdVersion,
      completedAt: input.completedAt,
    },
  };
}

function uncertainReasonFromChecks(
  checks: VoiceIdVerificationChecks,
): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>['reason'] {
  if (checks.phrase.kind === 'uncertain') {
    const reason = checks.phrase.reason;
    switch (reason) {
      case 'transcript_unavailable':
        return 'verifier_unavailable';
      case 'transcript_low_confidence':
        return 'model_low_confidence';
      default:
        return assertNever(reason);
    }
  }
  if (checks.speaker.kind === 'uncertain') {
    const reason = checks.speaker.reason;
    switch (reason) {
      case 'verifier_unavailable':
        return 'verifier_unavailable';
      case 'low_audio_quality':
        return 'noisy_audio';
      case 'model_low_confidence':
        return 'model_low_confidence';
      default:
        return assertNever(reason);
    }
  }
  throw new Error('uncertain verification requires an uncertain check');
}

function uncertainReasonFromQuality(
  quality: Extract<VoiceIdAudioQualityResult, { kind: 'uncertain' }>,
): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>['reason'] {
  switch (quality.reason) {
    case 'too_short':
      return 'too_short';
    case 'verifier_unavailable':
      return 'verifier_unavailable';
    case 'noisy_audio':
    case 'model_low_confidence':
    case 'undecodable_audio':
    case 'clipped_audio':
    case 'low_speech':
    case 'low_snr':
    case 'metadata_mismatch':
      return 'noisy_audio';
    default:
      return assertNever(quality.reason);
  }
}

function rejectedVerification(
  verificationId: VoiceIdVerificationId,
  reason: Extract<VoiceIdVerificationResult, { kind: 'rejected' }>['reason'],
  checks: VoiceIdVerificationChecks,
): Extract<VoiceIdVerificationResult, { kind: 'rejected' }> {
  return { kind: 'rejected', verificationId, reason, checks };
}

function uncertainVerification(
  verificationId: VoiceIdVerificationId,
  reason: Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>['reason'],
  checks: VoiceIdVerificationChecks,
): Extract<VoiceIdVerificationResult, { kind: 'uncertain' }> {
  return { kind: 'uncertain', verificationId, reason, checks };
}

function buildCompletedVerificationRecord(
  record: Extract<VoiceIdVerificationRecord, { state: 'analyzing' }>,
  completedAt: IsoDateTime,
  result: VoiceIdVerificationResult,
): Extract<VoiceIdVerificationRecord, { state: 'evidence_observed' | 'rejected' | 'uncertain' }> {
  switch (result.kind) {
    case 'evidence_observed':
      return {
        state: 'evidence_observed',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        expectedPhrase: record.expectedPhrase,
        challengeNonce: record.challengeNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        analysisStartedAt: record.analysisStartedAt,
        analysisExpiresAt: record.analysisExpiresAt,
        completedAt,
        result,
      };
    case 'rejected':
      return {
        state: 'rejected',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        expectedPhrase: record.expectedPhrase,
        challengeNonce: record.challengeNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        analysisStartedAt: record.analysisStartedAt,
        analysisExpiresAt: record.analysisExpiresAt,
        completedAt,
        result,
      };
    case 'uncertain':
      return {
        state: 'uncertain',
        userId: record.userId,
        enrollmentId: record.enrollmentId,
        verificationId: record.verificationId,
        expectedPhrase: record.expectedPhrase,
        challengeNonce: record.challengeNonce,
        createdAt: record.createdAt,
        expiresAt: record.expiresAt,
        analysisStartedAt: record.analysisStartedAt,
        analysisExpiresAt: record.analysisExpiresAt,
        completedAt,
        result,
      };
    default:
      return assertNever(result);
  }
}

function buildExpiredVerificationRecord(
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
  completedAt: IsoDateTime,
): Extract<VoiceIdVerificationRecord, { state: 'expired' }> {
  return {
    state: 'expired',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    completedAt,
  };
}

function enrollmentAuditScoreBands(
  quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>,
  phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>,
): VoiceIdAuditScoreBands {
  return {
    kind: 'enrollment_recording',
    qualitySignal: auditScoreBand(quality.signalScore),
    phraseConfidence: auditScoreBand(phrase.confidence),
  };
}

function verificationAuditScoreBands(checks: VoiceIdVerificationChecks): VoiceIdAuditScoreBands {
  return {
    kind: 'verification',
    phraseConfidence: auditScoreBand(checks.phrase.confidence),
    speakerScore: auditScoreBand(checks.speaker.score),
    speakerThreshold: auditScoreBand(checks.speaker.threshold),
    qualitySignal:
      checks.quality.kind === 'accepted' ? auditScoreBand(checks.quality.signalScore) : 'none',
  };
}

function auditScoreBand(score: number): VoiceIdAuditScoreBand {
  if (!Number.isFinite(score)) return 'none';
  if (score < 0.25) return 'very_low';
  if (score < 0.5) return 'low';
  if (score < 0.75) return 'medium';
  return 'high';
}

function noAuditScores(): Extract<VoiceIdAuditScoreBands, { kind: 'none' }> {
  return { kind: 'none' };
}

function lifecycleConflict<TValue>(message: string): VoiceIdServiceResult<TValue> {
  return { kind: 'error', error: { kind: 'invalid_state', message } };
}
