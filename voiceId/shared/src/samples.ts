import type { VoiceIdAudioInput } from './audio.ts';
import type {
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdVerificationId,
} from './ids.ts';

export type VoiceIdEnrollmentRecording = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  audio: VoiceIdAudioInput;
};

export type VoiceIdVerificationRecording = {
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  audio: VoiceIdAudioInput;
};
