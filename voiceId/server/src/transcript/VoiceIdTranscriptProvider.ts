import type { VoiceIdAudioInput } from '../../../shared/src/audio.ts';
import type { VoiceIdPromptPhrase } from '../../../shared/src/prompts.ts';
import type { VoiceIdPhraseMatchResult } from '../../../shared/src/results.ts';

export type VoiceIdTranscriptProvider = {
  matchPhrase(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
  }): Promise<VoiceIdPhraseMatchResult>;
};
