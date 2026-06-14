import type { VoiceIdAudioInput } from '../../../shared/src/audio.ts';
import type { VoiceIdPromptPhrase } from '../../../shared/src/prompts.ts';
import { normalizePromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdPhraseMatchResult } from '../../../shared/src/results.ts';
import type { VoiceIdTranscriptProvider } from './VoiceIdTranscriptProvider.ts';

export type VoiceIdCloudflareWorkersAiAsrModel = '@cf/openai/whisper';

export type VoiceIdCloudflareWorkersAiBinding = {
  run(model: VoiceIdCloudflareWorkersAiAsrModel, input: { audio: number[] }): Promise<unknown>;
};

export type VoiceIdCloudflareWorkersAiTranscriptProviderConfig = {
  ai: VoiceIdCloudflareWorkersAiBinding;
  model: VoiceIdCloudflareWorkersAiAsrModel;
};

export class CloudflareWorkersAiTranscriptProvider implements VoiceIdTranscriptProvider {
  private readonly ai: VoiceIdCloudflareWorkersAiBinding;
  private readonly model: VoiceIdCloudflareWorkersAiAsrModel;

  constructor(config: VoiceIdCloudflareWorkersAiTranscriptProviderConfig) {
    this.ai = config.ai;
    this.model = config.model;
  }

  async matchPhrase(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
    spokenPhrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdPhraseMatchResult> {
    const expectedNormalized = normalizePromptPhrase(input.expectedPhrase);
    const transcript = parseCloudflareWorkersAiWhisperResponse(
      await this.ai.run(this.model, { audio: [...input.audio.bytes] }),
    );
    const spokenNormalized = normalizeAsrTranscript(transcript);

    if (spokenNormalized.length === 0) {
      return {
        kind: 'uncertain',
        reason: 'transcript_unavailable',
        expectedNormalized,
        spokenNormalized,
        confidence: 0,
      };
    }

    if (spokenNormalized === expectedNormalized) {
      return {
        kind: 'accepted',
        expectedNormalized,
        spokenNormalized,
        confidence: 0.92,
      };
    }

    return {
      kind: 'rejected',
      reason: 'phrase_mismatch',
      expectedNormalized,
      spokenNormalized,
      confidence: 0.9,
    };
  }
}

function normalizeAsrTranscript(transcript: string): string {
  return normalizePromptPhrase(transcript.replace(/[.?!]+$/g, ''));
}

export function parseCloudflareWorkersAiWhisperResponse(value: unknown): string {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Cloudflare Workers AI ASR response must be an object');
  }
  const response = value as Record<string, unknown>;
  if (typeof response.text === 'string') {
    return response.text.trim();
  }

  const transcriptionInfo = response.transcription_info;
  if (
    transcriptionInfo
    && typeof transcriptionInfo === 'object'
    && !Array.isArray(transcriptionInfo)
    && typeof (transcriptionInfo as Record<string, unknown>).text === 'string'
  ) {
    return String((transcriptionInfo as Record<string, unknown>).text).trim();
  }

  throw new Error('Cloudflare Workers AI ASR response text is missing');
}

export function parseCloudflareWorkersAiAsrModel(
  value: unknown,
): VoiceIdCloudflareWorkersAiAsrModel {
  const model = value === undefined || value === '' ? '@cf/openai/whisper' : value;
  if (model === '@cf/openai/whisper') {
    return model;
  }
  throw new Error("VOICEID_CLOUDFLARE_ASR_MODEL must be '@cf/openai/whisper'");
}

export function requireCloudflareWorkersAiBinding(
  value: unknown,
): VoiceIdCloudflareWorkersAiBinding {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('AI binding must be a Cloudflare Workers AI binding');
  }
  const binding = value as { readonly run?: unknown };
  if (typeof binding.run !== 'function') {
    throw new Error('AI binding must expose run(model, input)');
  }
  return value as VoiceIdCloudflareWorkersAiBinding;
}
