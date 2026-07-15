import type {
  EncryptedBytes,
  IsoDateTime,
  UserId,
  VoiceIdChallengeNonce,
  VoiceIdEnrollmentId,
  VoiceIdModelVersion,
  VoiceIdPromptSetId,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import type {
  VoiceIdEnrollmentPromptSequence,
  VoiceIdPromptPhrase,
} from './prompts.ts';
import type { VoiceIdVerificationResult } from './results.ts';

export type VoiceIdEnrollmentRecord = {
  userId: UserId;
} & (
  | {
      state: 'pending_continuous_recording';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      promptSequence: VoiceIdEnrollmentPromptSequence;
      modelVersion: VoiceIdModelVersion;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      minimumCaptureMs: number;
      targetCaptureMs: number;
      maximumCaptureMs: number;
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      encryptedTemplate?: never;
      templateVersion?: never;
      thresholdVersion?: never;
      enrolledAt?: never;
      disabledAt?: never;
      failedAt?: never;
      failureReason?: never;
    }
  | {
      state: 'analyzing_continuous_recording';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      promptSequence: VoiceIdEnrollmentPromptSequence;
      modelVersion: VoiceIdModelVersion;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      minimumCaptureMs: number;
      targetCaptureMs: number;
      maximumCaptureMs: number;
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      encryptedTemplate?: never;
      templateVersion?: never;
      thresholdVersion?: never;
      enrolledAt?: never;
      disabledAt?: never;
      failedAt?: never;
      failureReason?: never;
    }
  | {
      state: 'failed';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      modelVersion: VoiceIdModelVersion;
      createdAt: IsoDateTime;
      failedAt: IsoDateTime;
      failureReason:
        | 'expired'
        | 'capture_too_short'
        | 'capture_too_long'
        | 'phrase_rejected'
        | 'transcript_uncertain'
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
        | 'template_build_failed'
        | 'analysis_timeout'
        | 'verifier_unavailable';
      promptSequence?: never;
      expiresAt?: never;
      minimumCaptureMs?: never;
      targetCaptureMs?: never;
      maximumCaptureMs?: never;
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      encryptedTemplate?: never;
      templateVersion?: never;
      thresholdVersion?: never;
      enrolledAt?: never;
      disabledAt?: never;
    }
  | {
      state: 'enrolled';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      encryptedTemplate: EncryptedBytes;
      createdAt: IsoDateTime;
      enrolledAt: IsoDateTime;
      promptSequence?: never;
      expiresAt?: never;
      minimumCaptureMs?: never;
      targetCaptureMs?: never;
      maximumCaptureMs?: never;
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      failedAt?: never;
      failureReason?: never;
      disabledAt?: never;
    }
  | {
      state: 'disabled';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      encryptedTemplate: EncryptedBytes;
      createdAt: IsoDateTime;
      enrolledAt: IsoDateTime;
      disabledAt: IsoDateTime;
      promptSequence?: never;
      expiresAt?: never;
      minimumCaptureMs?: never;
      targetCaptureMs?: never;
      maximumCaptureMs?: never;
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      failedAt?: never;
      failureReason?: never;
    }
);

export type VoiceIdVerificationRecord = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  expectedPhrase: VoiceIdPromptPhrase;
  challengeNonce: VoiceIdChallengeNonce;
  createdAt: IsoDateTime;
  expiresAt: IsoDateTime;
} & (
  | {
      state: 'issued';
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      completedAt?: never;
      result?: never;
    }
  | {
      state: 'analyzing';
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      completedAt?: never;
      result?: never;
    }
  | {
      state: 'evidence_observed';
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      failureReason?: never;
      result: Extract<VoiceIdVerificationResult, { kind: 'evidence_observed' }>;
    }
  | {
      state: 'rejected';
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      failureReason?: never;
      result: Extract<VoiceIdVerificationResult, { kind: 'rejected' }>;
    }
  | {
      state: 'uncertain';
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      failureReason?: never;
      result: Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>;
    }
  | {
      state: 'expired';
      analysisStartedAt?: never;
      analysisExpiresAt?: never;
      completedAt: IsoDateTime;
      failureReason?: never;
      result?: never;
    }
  | {
      state: 'analysis_failed';
      analysisStartedAt: IsoDateTime;
      analysisExpiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      failureReason: 'analysis_timeout';
      result?: never;
    }
);
