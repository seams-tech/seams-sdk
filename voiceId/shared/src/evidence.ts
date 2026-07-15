import type { VoiceIdAudioQualityResult } from './audio.ts';
import type {
  IsoDateTime,
  VoiceIdEnrollmentId,
  VoiceIdModelVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import type {
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
} from './results.ts';

declare const attestedEvidenceBrand: unique symbol;

export type VoiceIdExperimentalCaptureFreshness = {
  kind: 'browser_timing_observation';
  challengeIssuedAt: IsoDateTime;
  captureReceivedAt: IsoDateTime;
  serverVerifiedFreshness: false;
};

export type VoiceIdExperimentalPad = {
  kind: 'pad_unavailable';
  reason: 'ordinary_browser_capture';
};

export type VoiceIdExperimentalCaptureProfile = {
  kind: 'ordinary_browser_capture';
  source: 'media_recorder';
  microphoneIntegrity: 'unverified';
};

export type VoiceIdObservedChecks = {
  phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
  speaker: Extract<VoiceIdSpeakerMatchResult, { kind: 'accepted' }>;
  quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
  captureFreshness: VoiceIdExperimentalCaptureFreshness;
  pad: VoiceIdExperimentalPad;
  captureProfile: VoiceIdExperimentalCaptureProfile;
};

export type VoiceIdExperimentalBrowserEvidence = {
  kind: 'experimental_browser_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  observedChecks: VoiceIdObservedChecks;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  completedAt: IsoDateTime;
  signingAuthorization?: never;
};

export type VoiceIdStepUpOnlyEvidence = {
  kind: 'step_up_only_evidence';
  verificationId: VoiceIdVerificationId;
  reason:
    | 'browser_capture_boundary'
    | 'pad_unavailable'
    | 'device_proof_unavailable';
  source: VoiceIdExperimentalBrowserEvidence;
  signingAuthorization?: never;
};

export type VoiceIdAcceptedCaptureFreshness = {
  kind: 'server_verified_capture_freshness';
  challengeIssuedAt: IsoDateTime;
  captureReceivedAt: IsoDateTime;
  verifiedAt: IsoDateTime;
};

export type VoiceIdAcceptedPad = {
  kind: 'accepted_pad';
  calibrationId: string;
  score: number;
};

export type VoiceIdVerifiedDeviceProof = {
  kind: 'verified_device_proof';
  deviceId: string;
  attestationId: string;
  evidenceCommitment: string;
};

export type VoiceIdApprovedCaptureProfile = {
  kind: 'approved_capture_profile';
  captureProfileId: string;
  microphonePath: 'protected_sensor_path';
};

export type VoiceIdApprovedCalibration = {
  kind: 'approved_calibration';
  calibrationId: string;
  attackClasses: readonly string[];
};

export type VoiceIdAttestedEvidence = {
  readonly [attestedEvidenceBrand]: true;
  kind: 'attested_evidence';
  verificationId: VoiceIdVerificationId;
  enrollmentId: VoiceIdEnrollmentId;
  speaker: Extract<VoiceIdSpeakerMatchResult, { kind: 'accepted' }>;
  phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
  quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
  captureFreshness: VoiceIdAcceptedCaptureFreshness;
  pad: VoiceIdAcceptedPad;
  deviceProof: VoiceIdVerifiedDeviceProof;
  captureProfile: VoiceIdApprovedCaptureProfile;
  calibration: VoiceIdApprovedCalibration;
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  completedAt: IsoDateTime;
  signingAuthorization?: never;
};

export type VoiceIdEvidence =
  | VoiceIdExperimentalBrowserEvidence
  | VoiceIdStepUpOnlyEvidence
  | VoiceIdAttestedEvidence;
