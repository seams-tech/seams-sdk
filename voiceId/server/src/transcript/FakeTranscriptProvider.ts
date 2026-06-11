import { normalizePromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdPhraseMatchResult } from '../../../shared/src/results.ts';
import type { VoiceIdTranscriptProvider } from './VoiceIdTranscriptProvider.ts';

export class FakeTranscriptProvider implements VoiceIdTranscriptProvider {
  async matchPhrase(input: Parameters<VoiceIdTranscriptProvider['matchPhrase']>[0]): Promise<VoiceIdPhraseMatchResult> {
    if (input.audio.metadata.fixtureBehavior.kind === 'noisy') {
      return buildUncertainPhrase(input.expectedPhrase, input.spokenPhrase);
    }

    const expectedNormalized = normalizePromptPhrase(input.expectedPhrase);
    const spokenNormalized = normalizePromptPhrase(input.spokenPhrase);

    if (expectedNormalized === spokenNormalized) {
      return {
        kind: 'accepted',
        expectedNormalized,
        spokenNormalized,
        confidence: 0.98,
      };
    }

    return {
      kind: 'rejected',
      reason: 'phrase_mismatch',
      expectedNormalized,
      spokenNormalized,
      confidence: 0.97,
    };
  }
}

function buildUncertainPhrase(expectedPhrase: string, spokenPhrase: string): VoiceIdPhraseMatchResult {
  return {
    kind: 'uncertain',
    reason: 'transcript_low_confidence',
    expectedNormalized: normalizePromptPhrase(expectedPhrase),
    spokenNormalized: normalizePromptPhrase(spokenPhrase),
    confidence: 0.42,
  };
}
