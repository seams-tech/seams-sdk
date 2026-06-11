import type { VoiceIdAudioInput } from './audio.ts';
import type {
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdVerificationId,
} from './ids.ts';
import type { VoiceIdPromptPhrase } from './prompts.ts';

export type VoiceIdEnrollmentSample = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  expectedPhrase: VoiceIdPromptPhrase;
  spokenPhrase: VoiceIdPromptPhrase;
  attemptNumber: number;
  audio: VoiceIdAudioInput;
};

export type VoiceIdVerificationSample = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  expectedPhrase: VoiceIdPromptPhrase;
  spokenPhrase: VoiceIdPromptPhrase;
  attemptNumber: number;
  audio: VoiceIdAudioInput;
};
