import { normalizePromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdPhraseMatchResult } from '../../../shared/src/results.ts';
import type { VoiceIdTranscriptProvider } from './VoiceIdTranscriptProvider.ts';

const noisyAudioMarker = 0xf1;
const wrongPhraseAudioMarker = 0xf4;

export class FakeTranscriptProvider implements VoiceIdTranscriptProvider {
  async matchPhrase(
    input: Parameters<VoiceIdTranscriptProvider['matchPhrase']>[0],
  ): Promise<VoiceIdPhraseMatchResult> {
    const expectedNormalized = normalizePromptPhrase(input.expectedPhrase);
    if (input.audio.bytes[0] === noisyAudioMarker) {
      return {
        kind: 'uncertain',
        reason: 'transcript_low_confidence',
        expectedNormalized,
        spokenNormalized: '',
        confidence: 0.42,
      };
    }
    if (input.audio.bytes[0] === wrongPhraseAudioMarker) {
      return {
        kind: 'rejected',
        reason: 'phrase_mismatch',
        expectedNormalized,
        spokenNormalized: 'wrong phrase',
        confidence: 0.97,
      };
    }

    return {
      kind: 'accepted',
      expectedNormalized,
      spokenNormalized: expectedNormalized,
      confidence: 0.98,
    };
  }
}
