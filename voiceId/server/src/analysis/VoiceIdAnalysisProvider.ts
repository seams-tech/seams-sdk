import type { VoiceIdAudioInput } from '../../../shared/src/audio.ts';
import type { VoiceIdExperimentalPad } from '../../../shared/src/evidence.ts';
import { normalizePromptPhrase, type VoiceIdPromptPhrase } from '../../../shared/src/prompts.ts';
import type {
  VoiceIdIntentMatchResult,
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
} from '../../../shared/src/results.ts';
import type { VoiceIdEnrollmentRecord } from '../../../shared/src/records.ts';
import type { VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import type { VoiceIdSpeakerVerification, VoiceIdVerifier } from '../verifier/VoiceIdVerifier.ts';
import type { VoiceIdTranscriptProvider } from '../transcript/VoiceIdTranscriptProvider.ts';

export type VoiceIdVerificationAnalysis = {
  phrase: VoiceIdPhraseMatchResult;
  intent: VoiceIdIntentMatchResult;
  speaker: VoiceIdSpeakerMatchResult;
  quality: VoiceIdAudioQualityResult;
  pad: VoiceIdExperimentalPad;
};

export type VoiceIdAnalysisProvider = {
  analyzeVerification(input: {
    audio: VoiceIdAudioInput;
    expectedPhrase: VoiceIdPromptPhrase;
    enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>;
    threshold: number;
  }): Promise<VoiceIdVerificationAnalysis>;
};

export class SplitVoiceIdAnalysisProvider implements VoiceIdAnalysisProvider {
  constructor(
    private readonly transcriptProvider: VoiceIdTranscriptProvider,
    private readonly verifier: VoiceIdVerifier,
  ) {}

  async analyzeVerification(
    input: Parameters<VoiceIdAnalysisProvider['analyzeVerification']>[0],
  ): Promise<VoiceIdVerificationAnalysis> {
    const [phrase, speakerVerification] = await Promise.all([
      matchPhraseSafely(this.transcriptProvider, input.audio, input.expectedPhrase),
      verifySpeakerSafely(this.verifier, input.audio, input.enrollment, input.threshold),
    ]);
    return {
      phrase,
      intent: intentFromPhrase(phrase),
      speaker: speakerVerification.speaker,
      quality: speakerVerification.quality,
      pad: { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' },
    };
  }
}

export function intentFromPhrase(phrase: VoiceIdPhraseMatchResult): VoiceIdIntentMatchResult {
  switch (phrase.kind) {
    case 'accepted':
      return {
        kind: 'accepted',
        expectedIntent: 'expected_phrase',
        matchedIntent: 'expected_phrase',
        confidence: phrase.confidence,
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: 'intent_mismatch',
        expectedIntent: 'expected_phrase',
        matchedIntent: null,
        confidence: phrase.confidence,
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        reason: 'intent_low_confidence',
        expectedIntent: 'expected_phrase',
        matchedIntent: null,
        confidence: phrase.confidence,
      };
    default:
      return assertNever(phrase);
  }
}

async function matchPhraseSafely(
  transcriptProvider: VoiceIdTranscriptProvider,
  audio: VoiceIdAudioInput,
  expectedPhrase: VoiceIdPromptPhrase,
): Promise<VoiceIdPhraseMatchResult> {
  try {
    return await transcriptProvider.matchPhrase({ audio, expectedPhrase });
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

async function verifySpeakerSafely(
  verifier: VoiceIdVerifier,
  audio: VoiceIdAudioInput,
  enrollment: Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }>,
  threshold: number,
): Promise<VoiceIdSpeakerVerification> {
  try {
    return await verifier.verifySpeaker({
      audio,
      threshold,
      template: {
        encryptedTemplate: enrollment.encryptedTemplate,
        templateVersion: enrollment.templateVersion,
        modelVersion: enrollment.modelVersion,
        thresholdVersion: enrollment.thresholdVersion,
      },
    });
  } catch {
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
        threshold,
        modelVersion: enrollment.modelVersion,
        thresholdVersion: enrollment.thresholdVersion,
      },
    };
  }
}

function assertNever(value: never): never {
  throw new Error(`unhandled VoiceID phrase result: ${String(value)}`);
}
