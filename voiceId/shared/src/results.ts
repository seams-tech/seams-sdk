import type { VoiceIdAudioQualityResult } from './audio.ts';
import type {
  VoiceIdEnrollmentId,
  VoiceIdModelVersion,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';

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
      reason: 'model_low_confidence' | 'verifier_unavailable';
      score: number;
      threshold: number;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
    };

export type VoiceIdVerificationChecks = {
  phrase: VoiceIdPhraseMatchResult;
  speaker: VoiceIdSpeakerMatchResult;
  quality: VoiceIdAudioQualityResult;
};

export type VoiceIdVerificationResult =
  | {
      kind: 'accepted';
      enrollmentId: VoiceIdEnrollmentId;
      verificationId: VoiceIdVerificationId;
      templateVersion: VoiceIdTemplateVersion;
      checks: {
        phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
        speaker: Extract<VoiceIdSpeakerMatchResult, { kind: 'accepted' }>;
        quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
      };
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
    }
  | {
      kind: 'rejected';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'phrase_mismatch'
        | 'speaker_mismatch'
        | 'low_audio_quality'
        | 'too_many_attempts'
        | 'expired';
      checks: VoiceIdVerificationChecks;
    }
  | {
      kind: 'uncertain';
      verificationId: VoiceIdVerificationId;
      reason:
        | 'noisy_audio'
        | 'too_short'
        | 'model_low_confidence'
        | 'verifier_unavailable';
      checks: VoiceIdVerificationChecks;
    };
