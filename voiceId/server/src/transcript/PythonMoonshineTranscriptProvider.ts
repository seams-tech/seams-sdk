import type { VoiceIdAudioInput } from '../../../shared/src/audio.ts';
import { createRandomId } from '../../../shared/src/ids.ts';
import { normalizePromptPhrase, type VoiceIdPromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdPhraseMatchResult } from '../../../shared/src/results.ts';
import type { PythonAnalyzeSpeechRequest } from '../verifier/PythonVoiceIdVerifier.ts';
import { PythonHttpVoiceIdVerifierTransport } from '../verifier/PythonHttpVoiceIdVerifierTransport.ts';
import type { VoiceIdTranscriptProvider } from './VoiceIdTranscriptProvider.ts';

export type VoiceIdMoonshineIntentDecision =
  | {
      kind: 'accepted';
      intent: string;
      canonicalPhrase: string;
      confidence: number;
      reason: null;
    }
  | {
      kind: 'rejected' | 'uncertain';
      intent: string | null;
      canonicalPhrase: string | null;
      confidence: number;
      reason: string;
    };

export type VoiceIdMoonshineSpeechAnalysis = {
  transcript: string;
  phrase: VoiceIdPhraseMatchResult;
  intent: VoiceIdMoonshineIntentDecision;
  sampleRateHz: 16000;
};

export class PythonMoonshineTranscriptProvider implements VoiceIdTranscriptProvider {
  constructor(
    private readonly transport: PythonHttpVoiceIdVerifierTransport,
    private readonly intentName: string,
  ) {}

  async matchPhrase(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdPhraseMatchResult> {
    const analysis = await this.analyze(input);
    return phraseDecisionForLifecycle(analysis);
  }

  async analyze(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdMoonshineSpeechAnalysis> {
    const response = await this.transport.analyzeSpeech(
      buildAnalyzeSpeechRequest(
        input.audio,
        input.expectedPhrase,
        resolveIntentName(this.intentName, input.expectedPhrase),
      ),
    );
    return parseMoonshineSpeechAnalysis(response, input.expectedPhrase);
  }
}

function buildAnalyzeSpeechRequest(
  audio: VoiceIdAudioInput,
  expectedPhrase: VoiceIdPromptPhrase,
  intentName: string,
): PythonAnalyzeSpeechRequest {
  return {
    schemaVersion: 'voice_id_verifier_v2',
    requestId: createRandomId('voice_moonshine'),
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
    expectedPhrase,
    intentName,
  };
}

function resolveIntentName(
  configuredIntentName: string,
  expectedPhrase: VoiceIdPromptPhrase,
): string {
  return configuredIntentName === 'expected_phrase' ? expectedPhrase : configuredIntentName;
}

export function parseMoonshineSpeechAnalysis(
  value: unknown,
  expectedPhrase: VoiceIdPromptPhrase,
): VoiceIdMoonshineSpeechAnalysis {
  const data = requireRecord(value, 'Moonshine speech analysis response');
  requireExactKeys(data, ['kind', 'requestId', 'transcript', 'phrase', 'intent', 'sampleRateHz']);
  if (data.kind !== 'speech_analysis') {
    throw new Error('Moonshine speech analysis response kind is invalid');
  }
  const transcript = requireString(data.transcript, 'transcript');
  const phrase = parsePhraseDecision(data.phrase, expectedPhrase);
  const intent = parseIntentDecision(data.intent);
  if (data.sampleRateHz !== 16000) {
    throw new Error('Moonshine speech analysis must report 16 kHz PCM');
  }
  return { transcript, phrase, intent, sampleRateHz: 16000 };
}

function parsePhraseDecision(value: unknown, expectedPhrase: VoiceIdPromptPhrase): VoiceIdPhraseMatchResult {
  const data = requireRecord(value, 'phrase');
  const kind = requireString(data.kind, 'phrase.kind');
  const expectedNormalized = requireString(data.expectedNormalized, 'phrase.expectedNormalized');
  const spokenNormalized = requireStringOrEmpty(data.spokenNormalized, 'phrase.spokenNormalized');
  const confidence = requireProbability(data.confidence, 'phrase.confidence');
  if (expectedNormalized !== normalizePromptPhrase(expectedPhrase)) {
    throw new Error('Moonshine phrase expected normalization does not match the request');
  }
  if (kind === 'accepted') {
    return { kind, expectedNormalized, spokenNormalized, confidence };
  }
  if (kind === 'rejected') {
    return { kind, reason: 'phrase_mismatch', expectedNormalized, spokenNormalized, confidence };
  }
  if (kind === 'uncertain') {
    return { kind, reason: 'transcript_unavailable', expectedNormalized, spokenNormalized, confidence };
  }
  throw new Error('Moonshine phrase decision kind is invalid');
}

function parseIntentDecision(value: unknown): VoiceIdMoonshineIntentDecision {
  const data = requireRecord(value, 'intent');
  const kind = requireString(data.kind, 'intent.kind');
  const intent = nullableString(data.intent, 'intent.intent');
  const canonicalPhrase = nullableString(data.canonicalPhrase, 'intent.canonicalPhrase');
  const confidence = requireProbability(data.confidence, 'intent.confidence');
  const reason = nullableString(data.reason, 'intent.reason');
  if (kind === 'accepted' && intent !== null && canonicalPhrase !== null && reason === null) {
    return { kind, intent, canonicalPhrase, confidence, reason };
  }
  if ((kind === 'rejected' || kind === 'uncertain') && reason !== null) {
    return { kind, intent, canonicalPhrase, confidence, reason };
  }
  throw new Error('Moonshine intent decision shape is invalid');
}

function phraseDecisionForLifecycle(
  analysis: VoiceIdMoonshineSpeechAnalysis,
): VoiceIdPhraseMatchResult {
  if (analysis.intent.kind === 'accepted') {
    return analysis.phrase;
  }
  if (analysis.intent.kind === 'uncertain') {
    return {
      kind: 'uncertain',
      reason: 'transcript_low_confidence',
      expectedNormalized: analysis.phrase.expectedNormalized,
      spokenNormalized: analysis.phrase.spokenNormalized,
      confidence: Math.min(analysis.phrase.confidence, analysis.intent.confidence),
    };
  }
  return {
    kind: 'rejected',
    reason: 'phrase_mismatch',
    expectedNormalized: analysis.phrase.expectedNormalized,
    spokenNormalized: analysis.phrase.spokenNormalized,
    confidence: Math.min(analysis.phrase.confidence, analysis.intent.confidence),
  };
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunkSize = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

function requireRecord(value: unknown, fieldName: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new Error(`${fieldName} must be an object`);
  }
  return value;
}

function requireExactKeys(data: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(data).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error('Moonshine response contains unexpected or missing fields');
  }
}

function requireString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty string`);
  }
  return value.trim();
}

function requireStringOrEmpty(value: unknown, fieldName: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${fieldName} must be a string`);
  }
  return value.trim();
}

function nullableString(value: unknown, fieldName: string): string | null {
  if (value === null) {
    return null;
  }
  return requireString(value, fieldName);
}

function requireProbability(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1) {
    throw new Error(`${fieldName} must be a number between 0 and 1`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
