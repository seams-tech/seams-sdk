import type {
  VoiceIdEnrollmentId,
  VoiceIdModelVersion,
  VoiceIdPromptSetId,
  VoiceIdTemplateVersion,
  UserId,
  IsoDateTime,
} from './ids.ts';

export type VoiceIdEnrollmentState =
  | {
      kind: 'not_enrolled';
      userId: UserId;
      enrollmentId?: never;
      templateVersion?: never;
      disabledAt?: never;
    }
  | {
      kind: 'enrollment_pending';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      promptSetId: VoiceIdPromptSetId;
      requiredSampleCount: number;
      acceptedSampleCount: number;
      expiresAt: IsoDateTime;
      templateVersion?: never;
      disabledAt?: never;
    }
  | {
      kind: 'enrolled';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      enrolledAt: IsoDateTime;
      disabledAt?: never;
    }
  | {
      kind: 'disabled';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      modelVersion: VoiceIdModelVersion;
      templateVersion: VoiceIdTemplateVersion;
      disabledAt: IsoDateTime;
    };
