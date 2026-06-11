import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import {
  createId,
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';
import type {
  VoiceIdEnrollmentEmbedding,
  VoiceIdSpeakerVerification,
  VoiceIdTemplateBuildResult,
  VoiceIdVerifier,
} from './VoiceIdVerifier.ts';

export const PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION = 'voice_id_verifier_v1';

export type PythonVoiceIdVerifierTransport = {
  extractEnrollmentEmbedding(request: PythonExtractEnrollmentEmbeddingRequest): Promise<unknown>;
  buildTemplate(request: PythonBuildTemplateRequest): Promise<unknown>;
  verifySpeaker(request: PythonVerifySpeakerRequest): Promise<unknown>;
};

export type PythonVoiceIdVerifierConfig = {
  readonly transport: PythonVoiceIdVerifierTransport;
  readonly createRequestId?: () => string;
};

export type PythonExtractEnrollmentEmbeddingRequest = {
  readonly schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  readonly requestId: string;
  readonly audio: PythonAudioRequest;
};

export type PythonBuildTemplateRequest = {
  readonly schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  readonly requestId: string;
  readonly embeddings: readonly PythonTemplateEmbeddingRequest[];
};

export type PythonVerifySpeakerRequest = {
  readonly schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  readonly requestId: string;
  readonly audio: PythonAudioRequest;
  readonly template: PythonTemplateReferenceRequest;
  readonly threshold: number;
};

export type PythonAudioRequest = {
  readonly audioBase64: string;
  readonly metadata: {
    readonly mimeType: string;
    readonly durationMs: number;
    readonly sampleRate:
      | { readonly kind: 'known'; readonly hertz: number }
      | { readonly kind: 'unknown' };
    readonly channelCount:
      | { readonly kind: 'known'; readonly count: number }
      | { readonly kind: 'unknown' };
    readonly byteLength: number;
    readonly capturedAt: string;
    readonly recorder: string;
  };
};

export type PythonTemplateEmbeddingRequest = {
  readonly vector: readonly number[];
  readonly speakerLabel: string;
  readonly quality: VoiceIdAudioQualityResult;
};

export type PythonTemplateReferenceRequest = {
  readonly encryptedTemplate: string;
  readonly templateVersion: string;
  readonly modelVersion: string;
  readonly thresholdVersion: string;
};

type PythonResponseObject = Record<string, unknown>;

export class PythonVoiceIdVerifier implements VoiceIdVerifier {
  private readonly createRequestId: () => string;

  constructor(private readonly config: PythonVoiceIdVerifierConfig) {
    this.createRequestId = config.createRequestId ?? createPythonVerifierRequestId;
  }

  async extractEnrollmentEmbedding(input: {
    audio: VoiceIdAudioInput;
  }): Promise<VoiceIdEnrollmentEmbedding> {
    return parsePythonEnrollmentEmbeddingResponse(
      await this.config.transport.extractEnrollmentEmbedding({
        schemaVersion: PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
        requestId: this.createRequestId(),
        audio: buildPythonAudioRequest(input.audio),
      }),
    );
  }

  async buildTemplate(input: {
    embeddings: readonly VoiceIdEnrollmentEmbedding[];
  }): Promise<VoiceIdTemplateBuildResult> {
    return parsePythonTemplateBuildResponse(
      await this.config.transport.buildTemplate({
        schemaVersion: PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
        requestId: this.createRequestId(),
        embeddings: input.embeddings.map((embedding) => ({
          vector: embedding.vector,
          speakerLabel: embedding.speakerLabel,
          quality: embedding.quality,
        })),
      }),
    );
  }

  async verifySpeaker(input: {
    audio: VoiceIdAudioInput;
    template: Parameters<VoiceIdVerifier['verifySpeaker']>[0]['template'];
    threshold: number;
  }): Promise<VoiceIdSpeakerVerification> {
    return parsePythonSpeakerVerificationResponse(
      await this.config.transport.verifySpeaker({
        schemaVersion: PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
        requestId: this.createRequestId(),
        audio: buildPythonAudioRequest(input.audio),
        template: {
          encryptedTemplate: input.template.encryptedTemplate,
          templateVersion: input.template.templateVersion,
          modelVersion: input.template.modelVersion,
          thresholdVersion: input.template.thresholdVersion,
        },
        threshold: input.threshold,
      }),
    );
  }
}

export function parsePythonEnrollmentEmbeddingResponse(
  value: unknown,
): VoiceIdEnrollmentEmbedding {
  const response = requireObject(value, 'enrollment embedding response');
  requireKind(response, 'embedding');
  requireNonEmptyString(response, 'requestId');
  parseModelVersion(requireNonEmptyString(response, 'modelVersion'));
  parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion'));
  return {
    vector: requireNumberArray(response.embedding, 'embedding'),
    speakerLabel: requireNonEmptyString(response, 'speakerLabel'),
    quality: parsePythonAudioQuality(response.quality),
  };
}

export function parsePythonTemplateBuildResponse(
  value: unknown,
): VoiceIdTemplateBuildResult {
  const response = requireObject(value, 'template build response');
  const kind = requireOneOf(response.kind, ['built', 'rejected'], 'kind');
  switch (kind) {
    case 'built':
      requireNonEmptyString(response, 'requestId');
      return {
        kind: 'built',
        encryptedTemplate: parseEncryptedBytes(requireNonEmptyString(response, 'encryptedTemplate')),
        templateVersion: parseTemplateVersion(requireNonEmptyString(response, 'templateVersion')),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
        speakerLabel: requireNonEmptyString(response, 'speakerLabel'),
      };
    case 'rejected':
      requireNonEmptyString(response, 'requestId');
      return {
        kind: 'rejected',
        reason: requireOneOf(
          response.reason,
          ['insufficient_quality', 'inconsistent_speaker'],
          'reason',
        ),
      };
  }
}

export function parsePythonSpeakerVerificationResponse(
  value: unknown,
): VoiceIdSpeakerVerification {
  const response = requireObject(value, 'speaker verification response');
  requireKind(response, 'speaker_verification');
  requireNonEmptyString(response, 'requestId');
  return {
    quality: parsePythonAudioQuality(response.quality),
    speaker: parsePythonSpeaker(response.speaker),
  };
}

function buildPythonAudioRequest(audio: VoiceIdAudioInput): PythonAudioRequest {
  return {
    audioBase64: Buffer.from(audio.bytes.buffer, audio.bytes.byteOffset, audio.bytes.byteLength).toString('base64'),
    metadata: {
      mimeType: audio.metadata.mimeType,
      durationMs: audio.metadata.durationMs,
      sampleRate: audio.metadata.sampleRate,
      channelCount: audio.metadata.channelCount,
      byteLength: audio.metadata.byteLength,
      capturedAt: audio.metadata.capturedAt,
      recorder: audio.metadata.recorder,
    },
  };
}

function parsePythonAudioQuality(value: unknown): VoiceIdAudioQualityResult {
  const response = requireObject(value, 'audio quality');
  const kind = requireOneOf(response.kind, ['accepted', 'rejected', 'uncertain'], 'quality.kind');
  switch (kind) {
    case 'accepted':
      return {
        kind: 'accepted',
        durationMs: requirePositiveNumber(response.durationMs, 'quality.durationMs'),
        signalScore: requireProbability(response.signalScore, 'quality.signalScore'),
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: requireOneOf(response.reason, ['too_short', 'empty_audio'], 'quality.reason'),
        durationMs: requirePositiveNumber(response.durationMs, 'quality.durationMs'),
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: requireOneOf(
          response.reason,
          ['noisy_audio', 'too_short', 'model_low_confidence'],
          'quality.reason',
        ),
        durationMs: requirePositiveNumber(response.durationMs, 'quality.durationMs'),
      };
  }
}

function parsePythonSpeaker(value: unknown): VoiceIdSpeakerMatchResult {
  const response = requireObject(value, 'speaker result');
  const kind = requireOneOf(response.kind, ['accepted', 'rejected', 'uncertain'], 'speaker.kind');
  switch (kind) {
    case 'accepted':
      return {
        kind: 'accepted',
        score: requireProbability(response.score, 'speaker.score'),
        threshold: requireProbability(response.threshold, 'speaker.threshold'),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: requireOneOf(response.reason, ['speaker_mismatch'], 'speaker.reason'),
        score: requireProbability(response.score, 'speaker.score'),
        threshold: requireProbability(response.threshold, 'speaker.threshold'),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: requireOneOf(
          response.reason,
          ['model_low_confidence', 'verifier_unavailable'],
          'speaker.reason',
        ),
        score: requireProbability(response.score, 'speaker.score'),
        threshold: requireProbability(response.threshold, 'speaker.threshold'),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
      };
  }
}

function requireObject(value: unknown, fieldName: string): PythonResponseObject {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value as PythonResponseObject;
}

function requireKind(value: PythonResponseObject, expected: string): void {
  const actual = requireNonEmptyString(value, 'kind');
  if (actual !== expected) {
    throw new Error(`kind must be ${expected}`);
  }
}

function requireNonEmptyString(value: PythonResponseObject, fieldName: string): string {
  const fieldValue = value[fieldName];
  if (typeof fieldValue !== 'string' || fieldValue.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return fieldValue.trim();
}

function requireOneOf<TValue extends string>(
  value: unknown,
  allowed: readonly TValue[],
  fieldName: string,
): TValue {
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} is invalid`);
  }
  const matched = allowed.find((item) => item === value);
  if (matched === undefined) {
    throw new Error(`${fieldName} is invalid`);
  }
  return matched;
}

function requireNumberArray(value: unknown, fieldName: string): readonly number[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${fieldName} must be a non-empty number array`);
  }
  return value.map((item, index) => requireFiniteNumber(item, `${fieldName}[${index}]`));
}

function requirePositiveNumber(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (parsed <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return parsed;
}

function requireProbability(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (parsed < 0 || parsed > 1) {
    throw new Error(`${fieldName} must be between 0 and 1`);
  }
  return parsed;
}

function requireFiniteNumber(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new Error(`${fieldName} must be a finite number`);
  }
  return value;
}

function createPythonVerifierRequestId(): string {
  return createId<string>('python_voiceid_request');
}
