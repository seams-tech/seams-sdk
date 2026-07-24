import type { VoiceIdAudioQualityResult } from './audio.ts';
import type { VoiceIdExperimentalPad } from './evidence.ts';
import type {
  VoiceIdModelVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import type { VoiceIdExperimentalBrowserEvidence } from './evidence.ts';

export type VoiceIdPhraseMatchResult =
  | {
      kind: 'accepted';
      expectedNormalized: string;
      spokenNormalized: string;
      confidence: number;
    }
  | {
      kind: 'rejected';
      reason: 'phrase_mismatch' | 'ambiguous_transcript';
      expectedNormalized: string;
      spokenNormalized: string;
      confidence: number;
    }
  | {
      kind: 'uncertain';
      reason: 'transcript_low_confidence' | 'transcript_unavailable';
      expectedNormalized: string;
      spokenNormalized: string;
      confidence: number;
    };

export type VoiceIdSpeakerMatchResult =
  | {
      kind: 'accepted';
      score: number;
      threshold: number;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
    }
  | {
      kind: 'rejected';
      reason: 'speaker_mismatch';
      score: number;
      threshold: number;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
    }
  | {
      kind: 'uncertain';
      reason: 'model_low_confidence' | 'verifier_unavailable' | 'low_audio_quality';
      score: number;
      threshold: number;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
    };

export type VoiceIdIntentMatchResult =
  | {
      kind: 'accepted';
      expectedIntent: string;
      matchedIntent: string;
      confidence: number;
    }
  | {
      kind: 'rejected';
      reason: 'intent_mismatch' | 'intent_out_of_set';
      expectedIntent: string;
      matchedIntent: string | null;
      confidence: number;
    }
  | {
      kind: 'uncertain';
      reason: 'intent_low_confidence' | 'intent_unavailable';
      expectedIntent: string;
      matchedIntent: string | null;
      confidence: number;
    };

export type VoiceIdVerificationChecks = {
  phrase: VoiceIdPhraseMatchResult;
  intent: VoiceIdIntentMatchResult;
  speaker: VoiceIdSpeakerMatchResult;
  quality: VoiceIdAudioQualityResult;
  pad: VoiceIdExperimentalPad;
};

export type VoiceIdVerificationResult =
  | {
      kind: 'evidence_observed';
      evidence: VoiceIdExperimentalBrowserEvidence;
    }
  | {
      kind: 'rejected';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'phrase_mismatch'
        | 'intent_mismatch'
        | 'speaker_mismatch'
        | 'low_audio_quality';
      checks: VoiceIdVerificationChecks;
    }
  | {
      kind: 'uncertain';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'noisy_audio'
        | 'too_short'
        | 'model_low_confidence'
        | 'intent_low_confidence'
        | 'verifier_unavailable';
      checks: VoiceIdVerificationChecks;
    };
