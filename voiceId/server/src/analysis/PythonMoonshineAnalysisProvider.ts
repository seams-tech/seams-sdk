import type { VoiceIdAudioInput } from '../../../shared/src/audio.ts';
import type { VoiceIdExperimentalPad } from '../../../shared/src/evidence.ts';
import { normalizePromptPhrase, type VoiceIdPromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdIntentMatchResult } from '../../../shared/src/results.ts';
import type { VoiceIdEnrollmentRecord } from '../../../shared/src/records.ts';
import {
  parsePythonSpeakerVerificationResponse,
  type PythonAnalyzeVerificationRequest,
  type PythonVoiceIdVerifierTransport,
} from '../verifier/PythonVoiceIdVerifier.ts';
import { createRandomId } from '../../../shared/src/ids.ts';
import {
  parseMoonshineSpeechAnalysis,
  type VoiceIdMoonshineSpeechAnalysis,
} from '../transcript/PythonMoonshineTranscriptProvider.ts';
import type { VoiceIdAnalysisProvider, VoiceIdVerificationAnalysis } from './VoiceIdAnalysisProvider.ts';

export class PythonMoonshineAnalysisProvider implements VoiceIdAnalysisProvider {
  constructor(
    private readonly transport: PythonVoiceIdVerifierTransport,
    private readonly intentName: string,
  ) {}

  async analyzeVerification(
    input: Parameters<VoiceIdAnalysisProvider['analyzeVerification']>[0],
  ): Promise<VoiceIdVerificationAnalysis> {
    try {
      const response = await this.transport.analyzeVerification(
        buildAnalyzeVerificationRequest(
          input.audio,
          input.expectedPhrase,
          input.enrollment,
          input.threshold,
          this.intentName,
        ),
      );
      return parseVerificationAnalysisResponse(
        response,
        input.expectedPhrase,
        resolveIntentName(this.intentName, input.expectedPhrase),
      );
    } catch {
      return unavailableVerificationAnalysis(
        input.audio.metadata.durationMs,
        input.expectedPhrase,
        input.enrollment,
        input.threshold,
      );
    }
  }
}

export function buildAnalyzeVerificationRequest(
  audio: VoiceIdAudioInput,
  expectedPhrase: VoiceIdPromptPhrase,
  enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>,
  threshold: number,
  intentName: string,
): PythonAnalyzeVerificationRequest {
  return {
    schemaVersion: 'voice_id_verifier_v2',
    requestId: createRandomId('voice_analysis'),
    audio: {
      audioBase64: encodeBase64(audio.bytes),
      metadata: {
        mimeType: audio.metadata.mimeType,
        durationMs: audio.metadata.durationMs,
        sampleRate: audio.metadata.sampleRate,
        channelCount: audio.metadata.channelCount,
        byteLength: audio.metadata.byteLength,
        capturedAt: audio.metadata.capturedAt,
        recorder: audio.metadata.recorder,
      },
    },
    template: {
      encryptedTemplate: enrollment.encryptedTemplate,
      templateVersion: enrollment.templateVersion,
      modelVersion: enrollment.modelVersion,
      thresholdVersion: enrollment.thresholdVersion,
    },
    threshold,
    expectedPhrase,
    intentName: resolveIntentName(intentName, expectedPhrase),
  };
}

function parseVerificationAnalysisResponse(
  value: unknown,
  expectedPhrase: VoiceIdPromptPhrase,
  expectedIntent: string,
): VoiceIdVerificationAnalysis {
  const data = requireRecord(value, 'verification analysis response');
  requireExactKeys(data, ['kind', 'requestId', 'quality', 'speaker', 'speech', 'pad']);
  if (data.kind !== 'verification_analysis') {
    throw new Error('verification analysis response kind is invalid');
  }
  requireString(data.requestId, 'requestId');
  const qualityAndSpeaker = parsePythonSpeakerVerificationResponse({
    kind: 'speaker_verification',
    requestId: data.requestId,
    quality: data.quality,
    speaker: data.speaker,
  });
  const speech = parseMoonshineSpeechAnalysis(data.speech, expectedPhrase);
  const pad = parsePad(data.pad);
  return {
    phrase: speech.phrase,
    intent: parseIntent(speech, expectedIntent),
    speaker: qualityAndSpeaker.speaker,
    quality: qualityAndSpeaker.quality,
    pad,
  };
}

function parseIntent(
  speech: VoiceIdMoonshineSpeechAnalysis,
  expectedIntent: string,
): VoiceIdIntentMatchResult {
  switch (speech.intent.kind) {
    case 'accepted':
      return {
        kind: 'accepted',
        expectedIntent,
        matchedIntent: speech.intent.intent,
        confidence: speech.intent.confidence,
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: speech.intent.intent === null ? 'intent_out_of_set' : 'intent_mismatch',
        expectedIntent,
        matchedIntent: speech.intent.intent,
        confidence: speech.intent.confidence,
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: 'intent_low_confidence',
        expectedIntent,
        matchedIntent: speech.intent.intent,
        confidence: speech.intent.confidence,
      };
    default:
      return assertNever(speech.intent);
  }
}

function parsePad(value: unknown): VoiceIdExperimentalPad {
  const data = requireRecord(value, 'pad');
  requireExactKeys(data, ['kind', 'reason']);
  if (data.kind !== 'pad_unavailable' || data.reason !== 'ordinary_browser_capture') {
    throw new Error('verification analysis PAD result is invalid');
  }
  return { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' };
}

function resolveIntentName(configuredIntentName: string, expectedPhrase: VoiceIdPromptPhrase): string {
  return configuredIntentName === 'expected_phrase'
    ? normalizePromptPhrase(expectedPhrase)
    : configuredIntentName;
}

function unavailableVerificationAnalysis(
  durationMs: number,
  expectedPhrase: VoiceIdPromptPhrase,
  enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>,
  threshold: number,
): VoiceIdVerificationAnalysis {
  return {
    phrase: {
      kind: 'uncertain',
      reason: 'transcript_unavailable',
      expectedNormalized: normalizePromptPhrase(expectedPhrase),
      spokenNormalized: '',
      confidence: 0,
    },
    intent: {
      kind: 'uncertain',
      reason: 'intent_unavailable',
      expectedIntent: normalizePromptPhrase(expectedPhrase),
      matchedIntent: null,
      confidence: 0,
    },
    speaker: {
      kind: 'uncertain',
      reason: 'verifier_unavailable',
      score: 0,
      threshold,
      modelVersion: enrollment.modelVersion,
      thresholdVersion: enrollment.thresholdVersion,
    },
    quality: {
      kind: 'uncertain',
      reason: 'verifier_unavailable',
      durationMs,
    },
    pad: { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' },
  };
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary);
}

function requireRecord(value: unknown, fieldName: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireExactKeys(data: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(data).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error('verification analysis response contains unexpected or missing fields');
  }
}

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function assertNever(value: never): never {
  throw new Error(`unhandled Moonshine intent: ${String(value)}`);
}
