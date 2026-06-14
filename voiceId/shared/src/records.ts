import type {
  EncryptedBytes,
  IsoDateTime,
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdIntentDigest,
  VoiceIdModelVersion,
  VoiceIdPromptSetId,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import type { VoiceIdIntentNonce } from './intents.ts';
import type { VoiceIdPromptPhrase } from './prompts.ts';
import type { VoiceIdVerificationResult } from './results.ts';

export type VoiceIdEnrollmentTemplate = {
  encryptedTemplate: EncryptedBytes;
  modelVersion: VoiceIdModelVersion;
  templateVersion: VoiceIdTemplateVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  promptSetId: VoiceIdPromptSetId;
};

export type VoiceIdEnrollmentRecord = {
  userId: UserId;
} & (
  | {
      state: 'pending';
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      modelVersion: VoiceIdModelVersion;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      requiredSampleCount: number;
      acceptedSampleCount: number;
      attemptCount: number;
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
    }
);

export type VoiceIdVerificationRecord = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  expectedPhrase: VoiceIdPromptPhrase;
  intentDigest: VoiceIdIntentDigest;
  intentExpiresAt: IsoDateTime;
  intentNonce: VoiceIdIntentNonce;
} & (
  | {
      state: 'issued';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      attemptCount: number;
      completedAt?: never;
      result?: never;
      ownerPresenceEvidence?: never;
    }
  | {
      state: 'accepted';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result: Extract<VoiceIdVerificationResult, { kind: 'accepted' }>;
      ownerPresenceEvidence: VoiceIdOwnerPresenceEvidenceState;
    }
  | {
      state: 'rejected';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result: Extract<VoiceIdVerificationResult, { kind: 'rejected' }>;
      ownerPresenceEvidence?: never;
    }
  | {
      state: 'uncertain';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result: Extract<VoiceIdVerificationResult, { kind: 'uncertain' }>;
      ownerPresenceEvidence?: never;
    }
  | {
      state: 'expired';
      verificationId: VoiceIdVerificationId;
      createdAt: IsoDateTime;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
      result?: never;
      ownerPresenceEvidence?: never;
    }
);

export type VoiceIdOwnerPresenceEvidenceState =
  | {
      kind: 'available';
      consumedAt?: never;
    }
  | {
      kind: 'consumed';
      consumedAt: IsoDateTime;
    };
