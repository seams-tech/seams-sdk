import type {
  EncryptedBytes,
  VoiceIdModelVersion,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';

export type VoiceIdEnrollmentSpeechWindow = {
  index: number;
  startMs: number;
  endMs: number;
  speechMs: number;
  signalScore: number;
  templateWeight: number;
};

export type VoiceIdEnrollmentAnalysis = {
  analysisVersion: string;
  sourceCodec: string;
  sourceSampleRateHz: number;
  sourceChannelCount: number;
  decodedDurationMs: number;
  usableSpeechMs: number;
  windows: readonly VoiceIdEnrollmentSpeechWindow[];
};

export type VoiceIdEnrollmentTemplateFailureReason =
  | 'decoder_failure'
  | 'metadata_mismatch'
  | 'interrupted_capture'
  | 'insufficient_speech'
  | 'insufficient_windows'
  | 'duplicate_windows'
  | 'multi_speaker'
  | 'clipped_audio'
  | 'low_snr'
  | 'incoherent_windows'
  | 'template_build_failed';

export type VoiceIdEnrollmentTemplateBuildResult =
  | {
      kind: 'built';
      encryptedTemplate: EncryptedBytes;
      templateVersion: VoiceIdTemplateVersion;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
      analysis: VoiceIdEnrollmentAnalysis;
    }
  | {
      kind: 'rejected';
      reason: VoiceIdEnrollmentTemplateFailureReason;
    };

export type VoiceIdSpeakerVerification = {
  quality: VoiceIdAudioQualityResult;
  speaker: VoiceIdSpeakerMatchResult;
};

export type VoiceIdTemplateReference = {
  encryptedTemplate: EncryptedBytes;
  templateVersion: VoiceIdTemplateVersion;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
};

export type VoiceIdVerifier = {
  buildEnrollmentTemplate(input: {
    audio: VoiceIdAudioInput;
    expectedPromptCount: number;
  }): Promise<VoiceIdEnrollmentTemplateBuildResult>;
  verifySpeaker(input: {
    audio: VoiceIdAudioInput;
    template: VoiceIdTemplateReference;
    threshold: number;
  }): Promise<VoiceIdSpeakerVerification>;
};
