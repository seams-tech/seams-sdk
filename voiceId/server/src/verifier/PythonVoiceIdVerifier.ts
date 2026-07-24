import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import {
  createRandomId,
  parseEncryptedBytes,
  parseModelVersion,
  parseTemplateVersion,
  parseThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';
import type {
  VoiceIdEnrollmentAnalysis,
  VoiceIdEnrollmentSpeechWindow,
  VoiceIdEnrollmentTemplateBuildResult,
  VoiceIdEnrollmentTemplateFailureReason,
  VoiceIdSpeakerVerification,
  VoiceIdVerifier,
} from './VoiceIdVerifier.ts';

export const PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION = 'voice_id_verifier_v2';

export type PythonVoiceIdVerifierTransport = {
  buildEnrollmentTemplate(request: PythonBuildEnrollmentTemplateRequest): Promise<unknown>;
  verifySpeaker(request: PythonVerifySpeakerRequest): Promise<unknown>;
  analyzeVerification(request: PythonAnalyzeVerificationRequest): Promise<unknown>;
};

export type PythonVoiceIdVerifierConfig = {
  readonly transport: PythonVoiceIdVerifierTransport;
  readonly createRequestId?: () => string;
};

export type PythonBuildEnrollmentTemplateRequest = {
  readonly schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  readonly requestId: string;
  readonly audio: PythonAudioRequest;
  readonly expectedPromptCount: number;
};

export type PythonVerifySpeakerRequest = {
  readonly schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  readonly requestId: string;
  readonly audio: PythonAudioRequest;
  readonly template: PythonTemplateReferenceRequest;
  readonly threshold: number;
};

export type PythonAnalyzeSpeechRequest = {
  schemaVersion: 'voice_id_verifier_v2';
  requestId: string;
  audio: {
    audioBase64: string;
    metadata: {
      mimeType: string;
      durationMs: number;
      sampleRate: { kind: 'known'; hertz: number } | { kind: 'unknown' };
      channelCount: { kind: 'known'; count: number } | { kind: 'unknown' };
      byteLength: number;
      capturedAt: string;
      recorder: string;
    };
  };
  expectedPhrase: string;
  intentName: string;
};

export type PythonAnalyzeVerificationRequest = {
  schemaVersion: typeof PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION;
  requestId: string;
  audio: PythonAudioRequest;
  template: PythonTemplateReferenceRequest;
  threshold: number;
  expectedPhrase: string;
  intentName: string;
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

  async buildEnrollmentTemplate(input: {
    audio: VoiceIdAudioInput;
    expectedPromptCount: number;
  }): Promise<VoiceIdEnrollmentTemplateBuildResult> {
    return parsePythonEnrollmentTemplateResponse(
      await this.config.transport.buildEnrollmentTemplate({
        schemaVersion: PYTHON_VOICE_ID_VERIFIER_SCHEMA_VERSION,
        requestId: this.createRequestId(),
        audio: buildPythonAudioRequest(input.audio),
        expectedPromptCount: input.expectedPromptCount,
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

export function parsePythonEnrollmentTemplateResponse(
  value: unknown,
): VoiceIdEnrollmentTemplateBuildResult {
  const response = requireObject(value, 'enrollment template response');
  const kind = requireOneOf(response.kind, ['built', 'rejected'], 'kind');
  switch (kind) {
    case 'built': {
      requireExactKeys(
        response,
        [
          'kind',
          'requestId',
          'encryptedTemplate',
          'templateVersion',
          'modelVersion',
          'thresholdVersion',
          'quality',
          'analysis',
        ],
        'built enrollment template response',
      );
      requireNonEmptyString(response, 'requestId');
      const quality = parsePythonAudioQuality(response.quality);
      if (quality.kind !== 'accepted') {
        throw new Error('built enrollment template response requires accepted quality');
      }
      return {
        kind: 'built',
        encryptedTemplate: parseEncryptedBytes(requireNonEmptyString(response, 'encryptedTemplate')),
        templateVersion: parseTemplateVersion(requireNonEmptyString(response, 'templateVersion')),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
        quality,
        analysis: parsePythonEnrollmentAnalysis(response.analysis),
      };
    }
    case 'rejected':
      requireExactKeys(
        response,
        ['kind', 'requestId', 'reason'],
        'rejected enrollment template response',
      );
      requireNonEmptyString(response, 'requestId');
      return {
        kind: 'rejected',
        reason: parsePythonEnrollmentTemplateFailureReason(response.reason),
      };
  }
}

function parsePythonEnrollmentTemplateFailureReason(
  value: unknown,
): VoiceIdEnrollmentTemplateFailureReason {
  return requireOneOf(
    value,
    [
      'decoder_failure',
      'metadata_mismatch',
      'interrupted_capture',
      'insufficient_speech',
      'insufficient_windows',
      'duplicate_windows',
      'multi_speaker',
      'clipped_audio',
      'low_snr',
      'incoherent_windows',
      'template_build_failed',
    ],
    'enrollment template failure reason',
  );
}

function parsePythonEnrollmentAnalysis(value: unknown): VoiceIdEnrollmentAnalysis {
  const analysis = requireObject(value, 'enrollment analysis');
  requireExactKeys(
    analysis,
    [
      'analysisVersion',
      'sourceCodec',
      'sourceSampleRateHz',
      'sourceChannelCount',
      'decodedDurationMs',
      'usableSpeechMs',
      'windows',
    ],
    'enrollment analysis',
  );
  return {
    analysisVersion: requireNonEmptyString(analysis, 'analysisVersion'),
    sourceCodec: requireNonEmptyString(analysis, 'sourceCodec'),
    sourceSampleRateHz: requirePositiveInteger(analysis.sourceSampleRateHz, 'sourceSampleRateHz'),
    sourceChannelCount: requirePositiveInteger(analysis.sourceChannelCount, 'sourceChannelCount'),
    decodedDurationMs: requirePositiveNumber(analysis.decodedDurationMs, 'decodedDurationMs'),
    usableSpeechMs: requirePositiveNumber(analysis.usableSpeechMs, 'usableSpeechMs'),
    windows: parsePythonEnrollmentWindows(analysis.windows),
  };
}

function parsePythonEnrollmentWindows(value: unknown): readonly VoiceIdEnrollmentSpeechWindow[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error('enrollment analysis windows must be a non-empty array');
  }
  return value.map(parsePythonEnrollmentWindow);
}

function parsePythonEnrollmentWindow(
  value: unknown,
  arrayIndex: number,
): VoiceIdEnrollmentSpeechWindow {
  const window = requireObject(value, `enrollment analysis windows[${arrayIndex}]`);
  requireExactKeys(
    window,
    ['index', 'startMs', 'endMs', 'speechMs', 'signalScore', 'templateWeight'],
    `enrollment analysis windows[${arrayIndex}]`,
  );
  const index = requireNonNegativeInteger(window.index, `windows[${arrayIndex}].index`);
  if (index !== arrayIndex) {
    throw new Error(`windows[${arrayIndex}].index must equal its array position`);
  }
  const startMs = requireNonNegativeNumber(window.startMs, `windows[${arrayIndex}].startMs`);
  const endMs = requirePositiveNumber(window.endMs, `windows[${arrayIndex}].endMs`);
  if (endMs <= startMs) {
    throw new Error(`windows[${arrayIndex}].endMs must be greater than startMs`);
  }
  return {
    index,
    startMs,
    endMs,
    speechMs: requirePositiveNumber(window.speechMs, `windows[${arrayIndex}].speechMs`),
    signalScore: requireProbability(window.signalScore, `windows[${arrayIndex}].signalScore`),
    templateWeight: requireProbability(window.templateWeight, `windows[${arrayIndex}].templateWeight`),
  };
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
    audioBase64: encodeBase64Bytes(audio.bytes),
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

export function encodeBase64Bytes(bytes: Uint8Array): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let output = '';
  let index = 0;
  for (; index + 2 < bytes.length; index += 3) {
    const value = (bytes[index] << 16) | (bytes[index + 1] << 8) | bytes[index + 2];
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += alphabet[(value >> 6) & 63];
    output += alphabet[value & 63];
  }

  const remaining = bytes.length - index;
  if (remaining === 1) {
    const value = bytes[index] << 16;
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += '==';
  } else if (remaining === 2) {
    const value = (bytes[index] << 16) | (bytes[index + 1] << 8);
    output += alphabet[(value >> 18) & 63];
    output += alphabet[(value >> 12) & 63];
    output += alphabet[(value >> 6) & 63];
    output += '=';
  }

  return output;
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
          [
            'noisy_audio',
            'too_short',
            'model_low_confidence',
            'undecodable_audio',
            'clipped_audio',
            'low_speech',
            'low_snr',
            'metadata_mismatch',
          ],
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
        score: requireCosineScore(response.score, 'speaker.score'),
        threshold: requireProbability(response.threshold, 'speaker.threshold'),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: requireOneOf(response.reason, ['speaker_mismatch'], 'speaker.reason'),
        score: requireCosineScore(response.score, 'speaker.score'),
        threshold: requireProbability(response.threshold, 'speaker.threshold'),
        modelVersion: parseModelVersion(requireNonEmptyString(response, 'modelVersion')),
        thresholdVersion: parseThresholdVersion(requireNonEmptyString(response, 'thresholdVersion')),
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: requireOneOf(
          response.reason,
          ['model_low_confidence', 'verifier_unavailable', 'low_audio_quality'],
          'speaker.reason',
        ),
        score: requireCosineScore(response.score, 'speaker.score'),
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

function requireExactKeys(
  value: PythonResponseObject,
  expectedKeys: readonly string[],
  fieldName: string,
): void {
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpectedKeys.length
    || actualKeys.some((key, index) => key !== sortedExpectedKeys[index])
  ) {
    throw new Error(`${fieldName} contains unexpected or missing fields`);
  }
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

function requirePositiveNumber(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (parsed <= 0) {
    throw new Error(`${fieldName} must be positive`);
  }
  return parsed;
}

function requireNonNegativeNumber(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (parsed < 0) {
    throw new Error(`${fieldName} must be non-negative`);
  }
  return parsed;
}

function requirePositiveInteger(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${fieldName} must be a positive integer`);
  }
  return parsed;
}

function requireNonNegativeInteger(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (!Number.isInteger(parsed) || parsed < 0) {
    throw new Error(`${fieldName} must be a non-negative integer`);
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

function requireCosineScore(value: unknown, fieldName: string): number {
  const parsed = requireFiniteNumber(value, fieldName);
  if (parsed < -1 || parsed > 1) {
    throw new Error(`${fieldName} must be between -1 and 1`);
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
  return createRandomId('python_voiceid_request');
}
