import {
  authorizeVoiceIdOwnerPresence,
  buildVoiceIdOwnerPresenceResult,
  buildAudioInput,
  evaluateVoiceIdAudioLiveness,
  normalizePromptPhrase,
  nowIsoDateTime,
  parseEnrollmentId,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  type VoiceIdAuthPolicyRejectReason,
  type VoiceIdAudioLivenessSignals,
  type VoiceIdAudioLivenessPolicy,
  type VoiceIdAuthPolicyDecision,
  type VoiceIdAuthPolicyUseCase,
  type VoiceIdIntentDigest,
  type VoiceIdIntentNonce,
  type VoiceIdLivenessResult,
  type VoiceIdLocalDeviceContext,
  type VoiceIdOwnerPresenceResult,
  type IsoDateTime,
  type UserId,
  type VoiceIdEnrollmentId,
  type VoiceIdModelVersion,
  type VoiceIdPolicyVersion,
  type VoiceIdPromptSetId,
  type VoiceIdThresholdVersion,
  type VoiceIdVerificationId,
} from '../../shared/src/index.ts';
import type {
  VoiceIdEnrollmentRecord,
  VoiceIdVerificationRecord,
} from '../../shared/src/records.ts';
import type { VoiceIdPromptPhrase } from '../../shared/src/prompts.ts';
import type {
  VoiceIdEnrollmentSample,
  VoiceIdVerificationSample,
} from '../../shared/src/samples.ts';
import type {
  VoiceIdVerificationChecks,
  VoiceIdVerificationResult,
} from '../../shared/src/results.ts';
import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../shared/src/audio.ts';
import type {
  VoiceIdEnrollmentEmbedding,
  VoiceIdSpeakerVerification,
  VoiceIdTemplateBuildResult,
  VoiceIdVerifier,
} from './verifier/VoiceIdVerifier.ts';
import type { VoiceIdEnrollmentStore, VoiceIdVerificationStore } from './store/VoiceIdStores.ts';
import type { VoiceIdTranscriptProvider } from './transcript/VoiceIdTranscriptProvider.ts';

export const voiceIdFakeSpeakerScoreThreshold = 0.82;
export const voiceIdEcapaLocalDevSpeakerScoreThreshold = 0.6352;

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
  maxEnrollmentSampleAttempts: number;
  maxVerificationAttempts: number;
  requiredAcceptedEnrollmentSamples: number;
  speakerScoreThreshold: number;
  promptSetId: VoiceIdPromptSetId;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
};

export type VoiceIdLifecycleAuditEvent = {
  kind:
    | 'enrollment_started'
    | 'enrollment_sample_recorded'
    | 'enrollment_finalized'
    | 'verification_issued'
    | 'verification_completed';
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId | null;
  resultKind: VoiceIdAuditResultKind;
  scoreBands: VoiceIdAuditScoreBands;
  at: IsoDateTime;
  policyVersion?: never;
  decisionKind?: never;
  decisionReason?: never;
};

export type VoiceIdOwnerPresenceAuditEvent = {
  kind: 'owner_presence_authorized';
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  resultKind: Extract<VoiceIdAuditResultKind, 'accepted' | 'rejected'>;
  scoreBands: Extract<VoiceIdAuditScoreBands, { kind: 'none' }>;
  at: IsoDateTime;
  policyVersion: VoiceIdPolicyVersion;
  decisionKind: VoiceIdAuthPolicyDecision['kind'];
  decisionReason: VoiceIdAuthPolicyRejectReason | null;
};

export type VoiceIdAuditEvent = VoiceIdLifecycleAuditEvent | VoiceIdOwnerPresenceAuditEvent;

export type VoiceIdAuditResultKind =
  | 'issued'
  | 'accepted'
  | 'rejected'
  | 'uncertain'
  | 'enrolled';

export type VoiceIdAuditScoreBand =
  | 'none'
  | 'very_low'
  | 'low'
  | 'medium'
  | 'high';

export type VoiceIdAuditScoreBands =
  | { kind: 'none' }
  | {
      kind: 'enrollment_sample';
      qualitySignal: VoiceIdAuditScoreBand;
    }
  | {
      kind: 'verification';
      phraseConfidence: VoiceIdAuditScoreBand;
      speakerScore: VoiceIdAuditScoreBand;
      speakerThreshold: VoiceIdAuditScoreBand;
      qualitySignal: VoiceIdAuditScoreBand;
    };

export type VoiceIdServiceError =
  | { kind: 'malformed_request'; message: string }
  | { kind: 'missing_enrollment'; message: string }
  | { kind: 'missing_verification'; message: string }
  | { kind: 'invalid_state'; message: string }
  | { kind: 'expired'; message: string }
  | { kind: 'too_many_attempts'; message: string }
  | { kind: 'verifier_unavailable'; message: string };

export type VoiceIdServiceResult<TValue> =
  | { kind: 'ok'; value: TValue }
  | { kind: 'error'; error: VoiceIdServiceError };

export type StartEnrollmentResult = {
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending' }>;
  prompt: VoiceIdPromptPhrase;
};

export type AddEnrollmentSampleResult = {
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending' }>;
  quality: VoiceIdAudioQualityResult;
  acceptedSampleCount: number;
};

export type StartVerificationResult = {
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>;
  prompt: VoiceIdPromptPhrase;
};

export type AuthorizeOwnerPresenceInput = {
  verificationId: VoiceIdVerificationId;
  intentDigest: VoiceIdIntentDigest;
  useCase: VoiceIdAuthPolicyUseCase;
  policyVersion: VoiceIdPolicyVersion;
  audio: VoiceIdAudioLivenessSignals;
  context: VoiceIdLocalDeviceContext;
  policy: VoiceIdAudioLivenessPolicy;
};

export type AuthorizeOwnerPresenceResult = {
  liveness: VoiceIdLivenessResult;
  ownerPresence: VoiceIdOwnerPresenceResult;
  decision: VoiceIdAuthPolicyDecision;
};

export type VoiceIdServiceDependencies = {
  enrollmentStore: VoiceIdEnrollmentStore;
  verificationStore: VoiceIdVerificationStore;
  verifier: VoiceIdVerifier;
  transcriptProvider: VoiceIdTranscriptProvider;
  config: VoiceIdServiceConfig;
  now: () => Date;
  emitAuditEvent: (event: VoiceIdAuditEvent) => void;
};

export class VoiceIdService {
  private readonly enrollmentEmbeddings = new Map<VoiceIdEnrollmentId, VoiceIdEnrollmentEmbedding[]>();

  constructor(private readonly dependencies: VoiceIdServiceDependencies) {}

  async startEnrollment(input: {
    userId: UserId;
    phrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdServiceResult<StartEnrollmentResult>> {
    const now = this.now();
    const enrollmentId = parseEnrollmentId(`enroll_${now}_${input.userId}`);
    const record: Extract<VoiceIdEnrollmentRecord, { state: 'pending' }> = {
      state: 'pending',
      userId: input.userId,
      enrollmentId,
      promptSetId: this.dependencies.config.promptSetId,
      modelVersion: this.dependencies.config.modelVersion,
      createdAt: now,
      expiresAt: this.futureIso(this.dependencies.config.enrollmentPromptTtlMs),
      requiredSampleCount: this.dependencies.config.requiredAcceptedEnrollmentSamples,
      acceptedSampleCount: 0,
      attemptCount: 0,
    };

    await this.dependencies.enrollmentStore.save(record);
    this.dependencies.emitAuditEvent(this.audit('enrollment_started', record, null, 'issued', noAuditScores()));

    return { kind: 'ok', value: { record, prompt: input.phrase } };
  }

  async addEnrollmentSample(
    sample: VoiceIdEnrollmentSample,
  ): Promise<VoiceIdServiceResult<AddEnrollmentSampleResult>> {
    const record = await this.dependencies.enrollmentStore.getByEnrollmentId(sample.enrollmentId);
    if (record === null) {
      return { kind: 'error', error: { kind: 'missing_enrollment', message: 'enrollment does not exist' } };
    }
    if (record.state !== 'pending') {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'enrollment is not pending' } };
    }
    if (this.isExpired(record.expiresAt)) {
      return { kind: 'error', error: { kind: 'expired', message: 'enrollment prompt expired' } };
    }
    if (record.attemptCount >= this.dependencies.config.maxEnrollmentSampleAttempts) {
      return { kind: 'error', error: { kind: 'too_many_attempts', message: 'too many enrollment attempts' } };
    }

    let embedding: VoiceIdEnrollmentEmbedding;
    try {
      embedding = await this.dependencies.verifier.extractEnrollmentEmbedding({ audio: sample.audio });
    } catch (error) {
      return this.verifierUnavailable('enrollment embedding extraction', error);
    }
    const acceptedIncrement = embedding.quality.kind === 'accepted' ? 1 : 0;
    const updated: Extract<VoiceIdEnrollmentRecord, { state: 'pending' }> = {
      ...record,
      acceptedSampleCount: record.acceptedSampleCount + acceptedIncrement,
      attemptCount: record.attemptCount + 1,
    };

    if (embedding.quality.kind === 'accepted') {
      this.enrollmentEmbeddings.set(sample.enrollmentId, [
        ...(this.enrollmentEmbeddings.get(sample.enrollmentId) ?? []),
        embedding,
      ]);
    }

    await this.dependencies.enrollmentStore.save(updated);
    this.dependencies.emitAuditEvent(
      this.audit(
        'enrollment_sample_recorded',
        updated,
        null,
        embedding.quality.kind,
        enrollmentSampleAuditScoreBands(embedding.quality),
      ),
    );

    return {
      kind: 'ok',
      value: {
        record: updated,
        quality: embedding.quality,
        acceptedSampleCount: updated.acceptedSampleCount,
      },
    };
  }

  async finalizeEnrollment(input: {
    userId: UserId;
    enrollmentId: VoiceIdEnrollmentId;
  }): Promise<VoiceIdServiceResult<Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>>> {
    const record = await this.dependencies.enrollmentStore.getByEnrollmentId(input.enrollmentId);
    if (record === null) {
      return { kind: 'error', error: { kind: 'missing_enrollment', message: 'enrollment does not exist' } };
    }
    if (record.state !== 'pending') {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'enrollment is not pending' } };
    }
    if (record.acceptedSampleCount < record.requiredSampleCount) {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'insufficient accepted samples' } };
    }

    let template: VoiceIdTemplateBuildResult;
    try {
      template = await this.dependencies.verifier.buildTemplate({
        embeddings: this.enrollmentEmbeddings.get(input.enrollmentId) ?? [],
      });
    } catch (error) {
      return this.verifierUnavailable('template build', error);
    }
    if (template.kind === 'rejected') {
      return { kind: 'error', error: { kind: 'invalid_state', message: template.reason } };
    }

    const enrolled: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }> = {
      state: 'enrolled',
      userId: input.userId,
      enrollmentId: record.enrollmentId,
      promptSetId: record.promptSetId,
      modelVersion: template.modelVersion,
      templateVersion: template.templateVersion,
      thresholdVersion: template.thresholdVersion,
      encryptedTemplate: template.encryptedTemplate,
      createdAt: record.createdAt,
      enrolledAt: this.now(),
    };

    await this.dependencies.enrollmentStore.save(enrolled);
    this.enrollmentEmbeddings.delete(input.enrollmentId);
    this.dependencies.emitAuditEvent(this.audit('enrollment_finalized', enrolled, null, 'enrolled', noAuditScores()));

    return { kind: 'ok', value: enrolled };
  }

  async disableEnrollment(input: {
    userId: UserId;
    enrollmentId: VoiceIdEnrollmentId;
  }): Promise<VoiceIdServiceResult<Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }>>> {
    const record = await this.dependencies.enrollmentStore.getByEnrollmentId(input.enrollmentId);
    if (record === null) {
      return { kind: 'error', error: { kind: 'missing_enrollment', message: 'enrollment does not exist' } };
    }
    if (record.state !== 'enrolled') {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'only enrolled records can be disabled' } };
    }

    const disabled: Extract<VoiceIdEnrollmentRecord, { state: 'disabled' }> = {
      ...record,
      state: 'disabled',
      disabledAt: this.now(),
    };
    await this.dependencies.enrollmentStore.save(disabled);

    return { kind: 'ok', value: disabled };
  }

  async startVerification(input: {
    userId: UserId;
    enrollmentId: VoiceIdEnrollmentId;
    phrase: VoiceIdPromptPhrase;
    intentDigest: VoiceIdIntentDigest;
    intentExpiresAt: IsoDateTime;
    intentNonce: VoiceIdIntentNonce;
  }): Promise<VoiceIdServiceResult<StartVerificationResult>> {
    const enrollment = await this.dependencies.enrollmentStore.getByEnrollmentId(input.enrollmentId);
    if (enrollment === null || enrollment.state !== 'enrolled') {
      return { kind: 'error', error: { kind: 'missing_enrollment', message: 'active enrollment does not exist' } };
    }
    if (this.isExpired(input.intentExpiresAt)) {
      return { kind: 'error', error: { kind: 'expired', message: 'intent expired' } };
    }

    const now = this.now();
    const verificationId = parseVerificationId(`verify_${now}_${input.userId}`);
    const record: Extract<VoiceIdVerificationRecord, { state: 'issued' }> = {
      state: 'issued',
      userId: input.userId,
      enrollmentId: input.enrollmentId,
      expectedPhrase: input.phrase,
      intentDigest: input.intentDigest,
      intentExpiresAt: input.intentExpiresAt,
      intentNonce: input.intentNonce,
      verificationId,
      createdAt: now,
      expiresAt: earlierIso(this.futureIso(this.dependencies.config.verificationPromptTtlMs), input.intentExpiresAt),
      attemptCount: 0,
    };
    await this.dependencies.verificationStore.save(record);
    this.dependencies.emitAuditEvent(this.audit('verification_issued', enrollment, verificationId, 'issued', noAuditScores()));

    return { kind: 'ok', value: { record, prompt: input.phrase } };
  }

  async verifySample(
    sample: VoiceIdVerificationSample,
  ): Promise<VoiceIdServiceResult<VoiceIdVerificationResult>> {
    const verification = await this.dependencies.verificationStore.getByVerificationId(sample.verificationId);
    if (verification === null) {
      return { kind: 'error', error: { kind: 'missing_verification', message: 'verification does not exist' } };
    }
    if (verification.state !== 'issued') {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'verification is already completed' } };
    }
    if (this.isExpired(verification.expiresAt)) {
      const expired: Extract<VoiceIdVerificationRecord, { state: 'expired' }> = {
        ...verification,
        state: 'expired',
        completedAt: this.now(),
      };
      await this.dependencies.verificationStore.save(expired);
      return { kind: 'error', error: { kind: 'expired', message: 'verification prompt expired' } };
    }
    if (verification.attemptCount >= this.dependencies.config.maxVerificationAttempts) {
      return { kind: 'error', error: { kind: 'too_many_attempts', message: 'too many verification attempts' } };
    }

    const enrollment = await this.dependencies.enrollmentStore.getByEnrollmentId(sample.enrollmentId);
    if (enrollment === null || enrollment.state !== 'enrolled') {
      return { kind: 'error', error: { kind: 'missing_enrollment', message: 'active enrollment does not exist' } };
    }

    const phrase = await this.matchPhrase({
      audio: sample.audio,
      expectedPhrase: verification.expectedPhrase,
      spokenPhrase: sample.spokenPhrase,
    });
    let speakerVerification: VoiceIdSpeakerVerification;
    try {
      speakerVerification = await this.dependencies.verifier.verifySpeaker({
        audio: sample.audio,
        threshold: this.dependencies.config.speakerScoreThreshold,
        template: {
          encryptedTemplate: enrollment.encryptedTemplate,
          templateVersion: enrollment.templateVersion,
          modelVersion: enrollment.modelVersion,
          thresholdVersion: enrollment.thresholdVersion,
        },
      });
    } catch (error) {
      return this.verifierUnavailable('speaker verification', error);
    }
    const checks = {
      phrase,
      quality: speakerVerification.quality,
      speaker: speakerVerification.speaker,
    };
    const result = buildVerificationResult({
      verificationId: sample.verificationId,
      enrollment,
      checks,
    });
    const completedAt = this.now();
    const completedRecord = buildCompletedVerificationRecord({
      record: verification,
      completedAt,
      result,
    });

    await this.dependencies.verificationStore.save(completedRecord);
    this.dependencies.emitAuditEvent(
      this.audit(
        'verification_completed',
        enrollment,
        sample.verificationId,
        result.kind,
        verificationAuditScoreBands(checks),
      ),
    );

    return { kind: 'ok', value: result };
  }

  async authorizeOwnerPresence(
    input: AuthorizeOwnerPresenceInput,
  ): Promise<VoiceIdServiceResult<AuthorizeOwnerPresenceResult>> {
    const record = await this.dependencies.verificationStore.getByVerificationId(input.verificationId);
    if (record === null) {
      return { kind: 'error', error: { kind: 'missing_verification', message: 'verification does not exist' } };
    }
    if (record.state === 'issued') {
      return { kind: 'error', error: { kind: 'invalid_state', message: 'verification is not completed' } };
    }

    const liveness = evaluateVoiceIdAudioLiveness({
      audio: input.audio,
      context: input.context,
      policy: input.policy,
    });
    const ownerPresence = buildVoiceIdOwnerPresenceResult({
      record,
      liveness,
    });
    const decision = authorizeVoiceIdOwnerPresence({
      ownerPresence,
      intentDigest: input.intentDigest,
      useCase: input.useCase,
      now: this.dependencies.now(),
    });
    this.dependencies.emitAuditEvent(this.ownerPresenceAudit(record, input.policyVersion, decision));
    if (decision.kind === 'accepted' && record.state === 'accepted') {
      await this.dependencies.verificationStore.save({
        ...record,
        ownerPresenceEvidence: {
          kind: 'consumed' as const,
          consumedAt: this.now(),
        },
      });
    }

    return { kind: 'ok', value: { liveness, ownerPresence, decision } };
  }

  private ownerPresenceAudit(
    record: Exclude<VoiceIdVerificationRecord, { state: 'issued' }>,
    policyVersion: VoiceIdPolicyVersion,
    decision: VoiceIdAuthPolicyDecision,
  ): VoiceIdOwnerPresenceAuditEvent {
    return {
      kind: 'owner_presence_authorized',
      userId: record.userId,
      enrollmentId: record.enrollmentId,
      verificationId: record.verificationId,
      resultKind: decision.kind === 'accepted' ? 'accepted' : 'rejected',
      scoreBands: { kind: 'none' },
      at: this.now(),
      policyVersion,
      decisionKind: decision.kind,
      decisionReason: decision.kind === 'rejected' ? decision.reason : null,
    };
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

  private audit(
    kind: VoiceIdLifecycleAuditEvent['kind'],
    record: VoiceIdEnrollmentRecord,
    verificationId: VoiceIdVerificationId | null,
    resultKind: VoiceIdAuditResultKind,
    scoreBands: VoiceIdAuditScoreBands,
  ): VoiceIdLifecycleAuditEvent {
    return {
      kind,
      userId: record.userId,
      enrollmentId: record.enrollmentId,
      verificationId,
      resultKind,
      scoreBands,
      at: this.now(),
    };
  }

  private async matchPhrase(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
    spokenPhrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdVerificationChecks['phrase']> {
    try {
      return await this.dependencies.transcriptProvider.matchPhrase(input);
    } catch {
      return {
        kind: 'uncertain',
        reason: 'transcript_unavailable',
        expectedNormalized: normalizePromptPhrase(input.expectedPhrase),
        spokenNormalized: normalizePromptPhrase(input.spokenPhrase),
        confidence: 0,
      };
    }
  }

  private verifierUnavailable(operation: string, error: unknown): VoiceIdServiceResult<never> {
    return {
      kind: 'error',
      error: {
        kind: 'verifier_unavailable',
        message: `VoiceID verifier unavailable during ${operation}: ${errorMessage(error)}`,
      },
    };
  }
}

function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function noAuditScores(): VoiceIdAuditScoreBands {
  return { kind: 'none' };
}

function enrollmentSampleAuditScoreBands(quality: VoiceIdAudioQualityResult): VoiceIdAuditScoreBands {
  return {
    kind: 'enrollment_sample',
    qualitySignal: quality.kind === 'accepted' ? auditScoreBand(quality.signalScore) : 'none',
  };
}

function verificationAuditScoreBands(checks: VoiceIdVerificationChecks): VoiceIdAuditScoreBands {
  return {
    kind: 'verification',
    phraseConfidence: auditScoreBand(checks.phrase.confidence),
    speakerScore: auditScoreBand(checks.speaker.score),
    speakerThreshold: auditScoreBand(checks.speaker.threshold),
    qualitySignal: checks.quality.kind === 'accepted' ? auditScoreBand(checks.quality.signalScore) : 'none',
  };
}

function auditScoreBand(score: number): VoiceIdAuditScoreBand {
  if (score < 0.25) {
    return 'very_low';
  }
  if (score < 0.5) {
    return 'low';
  }
  if (score < 0.75) {
    return 'medium';
  }
  return 'high';
}

export function defaultVoiceIdServiceConfig(input: {
  speakerScoreThreshold?: number;
} = {}): VoiceIdServiceConfig {
  return {
    enrollmentPromptTtlMs: 10 * 60 * 1000,
    verificationPromptTtlMs: 2 * 60 * 1000,
    maxEnrollmentSampleAttempts: 6,
    maxVerificationAttempts: 2,
    requiredAcceptedEnrollmentSamples: 3,
    speakerScoreThreshold: input.speakerScoreThreshold ?? voiceIdFakeSpeakerScoreThreshold,
    promptSetId: parsePromptSetId('voiceid-mvp-prompts-v1'),
    modelVersion: parseModelVersion('fake-voiceid-model-v1'),
    thresholdVersion: parseThresholdVersion('fake-threshold-v1'),
  };
}

export function makeDemoAudioInput(input: {
  durationMs: number;
  bytes?: Uint8Array;
  speakerLabel?: string;
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
    fixtureBehavior: {
      kind: 'speaker_label',
      speakerLabel: input.speakerLabel ?? 'owner',
    },
  });
}

export function buildEnrollmentSample(input: {
  userId: string;
  enrollmentId: string;
  expectedPhrase: string;
  spokenPhrase: string;
  attemptNumber: number;
  audio: VoiceIdAudioInput;
}): VoiceIdEnrollmentSample {
  return {
    userId: parseUserId(input.userId),
    enrollmentId: parseEnrollmentId(input.enrollmentId),
    expectedPhrase: parsePromptPhrase(input.expectedPhrase),
    spokenPhrase: parsePromptPhrase(input.spokenPhrase),
    attemptNumber: input.attemptNumber,
    audio: input.audio,
  };
}

function buildVerificationResult(input: {
  verificationId: VoiceIdVerificationId;
  enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>;
  checks: VoiceIdVerificationChecks;
}): VoiceIdVerificationResult {
  if (input.checks.quality.kind === 'rejected') {
    return {
      kind: 'rejected',
      verificationId: input.verificationId,
      reason: 'low_audio_quality',
      checks: input.checks,
    };
  }
  if (input.checks.quality.kind === 'uncertain') {
    return {
      kind: 'uncertain',
      verificationId: input.verificationId,
      reason: input.checks.quality.reason === 'too_short' ? 'too_short' : 'noisy_audio',
      checks: input.checks,
    };
  }
  if (input.checks.phrase.kind === 'rejected') {
    return {
      kind: 'rejected',
      verificationId: input.verificationId,
      reason: 'phrase_mismatch',
      checks: input.checks,
    };
  }
  if (input.checks.speaker.kind === 'rejected') {
    return {
      kind: 'rejected',
      verificationId: input.verificationId,
      reason: 'speaker_mismatch',
      checks: input.checks,
    };
  }
  if (input.checks.phrase.kind === 'uncertain' || input.checks.speaker.kind === 'uncertain') {
    return {
      kind: 'uncertain',
      verificationId: input.verificationId,
      reason: 'model_low_confidence',
      checks: input.checks,
    };
  }

  return {
    kind: 'accepted',
    enrollmentId: input.enrollment.enrollmentId,
    verificationId: input.verificationId,
    templateVersion: input.enrollment.templateVersion,
    checks: {
      phrase: input.checks.phrase,
      speaker: input.checks.speaker,
      quality: input.checks.quality,
    },
    modelVersion: input.enrollment.modelVersion,
    thresholdVersion: input.enrollment.thresholdVersion,
  };
}

function buildCompletedVerificationRecord(input: {
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>;
  completedAt: IsoDateTime;
  result: VoiceIdVerificationResult;
}): Exclude<VoiceIdVerificationRecord, { state: 'issued' | 'expired' }> {
  if (input.result.kind === 'accepted') {
    return {
      ...input.record,
      state: 'accepted',
      completedAt: input.completedAt,
      result: input.result,
      ownerPresenceEvidence: { kind: 'available' },
    };
  }
  if (input.result.kind === 'rejected') {
    return {
      ...input.record,
      state: 'rejected',
      completedAt: input.completedAt,
      result: input.result,
    };
  }
  return {
    ...input.record,
    state: 'uncertain',
    completedAt: input.completedAt,
    result: input.result,
  };
}

function earlierIso(left: IsoDateTime, right: IsoDateTime): IsoDateTime {
  return Date.parse(left) <= Date.parse(right) ? left : right;
}
