import type {
  EncryptedBytes,
  VoiceIdModelVersion,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
} from '../../../shared/src/ids.ts';
import type { VoiceIdAudioInput, VoiceIdAudioQualityResult } from '../../../shared/src/audio.ts';
import type { VoiceIdSpeakerMatchResult } from '../../../shared/src/results.ts';

export type VoiceIdEnrollmentEmbedding = {
  vector: readonly number[];
  speakerLabel: string;
  quality: VoiceIdAudioQualityResult;
};

export type VoiceIdTemplateBuildResult =
  | {
      kind: 'built';
      encryptedTemplate: EncryptedBytes;
      templateVersion: VoiceIdTemplateVersion;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      speakerLabel: string;
    }
  | {
      kind: 'rejected';
      reason: 'insufficient_quality' | 'inconsistent_speaker';
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
  extractEnrollmentEmbedding(input: {
    audio: VoiceIdAudioInput;
  }): Promise<VoiceIdEnrollmentEmbedding>;
  buildTemplate(input: {
    embeddings: readonly VoiceIdEnrollmentEmbedding[];
  }): Promise<VoiceIdTemplateBuildResult>;
  verifySpeaker(input: {
    audio: VoiceIdAudioInput;
    template: VoiceIdTemplateReference;
    threshold: number;
  }): Promise<VoiceIdSpeakerVerification>;
};
