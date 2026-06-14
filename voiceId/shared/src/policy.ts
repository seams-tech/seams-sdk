import { assertNever } from './assertNever.ts';
import type { VoiceIdAudioQualityResult } from './audio.ts';
import type {
  IsoDateTime,
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdIntentDigest,
  VoiceIdModelVersion,
  VoiceIdTemplateVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import type { VoiceIdVerificationRecord } from './records.ts';
import type {
  VoiceIdPhraseMatchResult,
  VoiceIdSpeakerMatchResult,
  VoiceIdVerificationChecks,
} from './results.ts';

export type VoiceIdLivenessResult =
  | {
      kind: 'accepted';
      method: 'audio';
      checkedAt: IsoDateTime;
    }
  | {
      kind: 'not_required';
      reason: 'browser_mvp_policy';
    }
  | {
      kind: 'rejected';
      reason: 'replay_detected';
    }
  | {
      kind: 'uncertain';
      reason: 'liveness_unavailable';
    };

export type VoiceIdAcceptedLivenessResult =
  | Extract<VoiceIdLivenessResult, { kind: 'accepted' }>
  | Extract<VoiceIdLivenessResult, { kind: 'not_required' }>;

export type VoiceIdCompletedVerificationRecord = Extract<
  VoiceIdVerificationRecord,
  { state: 'accepted' | 'rejected' | 'uncertain' | 'expired' }
>;

export type VoiceIdOwnerPresenceRejectedReason =
  | 'phrase_mismatch'
  | 'speaker_mismatch'
  | 'low_audio_quality'
  | 'liveness_mismatch'
  | 'intent_mismatch'
  | 'evidence_replayed'
  | 'expired'
  | 'too_many_attempts';

export type VoiceIdOwnerPresenceUncertainReason =
  | 'noisy_audio'
  | 'too_short'
  | 'low_audio_quality'
  | 'no_speech_detected'
  | 'low_snr'
  | 'clipped_audio'
  | 'model_low_confidence'
  | 'transcript_unavailable'
  | 'liveness_unavailable'
  | 'verifier_unavailable';

export type VoiceIdOwnerPresenceResult =
  | {
      kind: 'accepted';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      verificationId: VoiceIdVerificationId;
      intentDigest: VoiceIdIntentDigest;
      templateVersion: VoiceIdTemplateVersion;
      modelVersion: VoiceIdModelVersion;
      thresholdVersion: VoiceIdThresholdVersion;
      phrase: Extract<VoiceIdPhraseMatchResult, { kind: 'accepted' }>;
      speaker: Extract<VoiceIdSpeakerMatchResult, { kind: 'accepted' }>;
      quality: Extract<VoiceIdAudioQualityResult, { kind: 'accepted' }>;
      liveness: VoiceIdAcceptedLivenessResult;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
    }
  | {
      kind: 'rejected';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      verificationId: VoiceIdVerificationId;
      intentDigest: VoiceIdIntentDigest;
      reason: VoiceIdOwnerPresenceRejectedReason;
      checks: VoiceIdVerificationChecks | null;
      liveness: VoiceIdLivenessResult;
      modelVersion: VoiceIdModelVersion | null;
      thresholdVersion: VoiceIdThresholdVersion | null;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
    }
  | {
      kind: 'uncertain';
      userId: UserId;
      enrollmentId: VoiceIdEnrollmentId;
      verificationId: VoiceIdVerificationId;
      intentDigest: VoiceIdIntentDigest;
      reason: VoiceIdOwnerPresenceUncertainReason;
      checks: VoiceIdVerificationChecks | null;
      liveness: VoiceIdLivenessResult;
      modelVersion: VoiceIdModelVersion | null;
      thresholdVersion: VoiceIdThresholdVersion | null;
      expiresAt: IsoDateTime;
      completedAt: IsoDateTime;
    };

export type VoiceIdOwnerPresenceIntentDecision =
  | {
      kind: 'accepted';
      ownerPresence: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>;
    }
  | {
      kind: 'rejected';
      reason: 'owner_presence_not_accepted' | 'intent_mismatch';
      ownerPresence: VoiceIdOwnerPresenceResult;
    };

export function buildVoiceIdOwnerPresenceResult(input: {
  record: VoiceIdCompletedVerificationRecord;
  liveness: VoiceIdLivenessResult;
}): VoiceIdOwnerPresenceResult {
  switch (input.record.state) {
    case 'accepted':
      return buildAcceptedOwnerPresence({
        record: input.record,
        liveness: input.liveness,
      });
    case 'rejected':
      return {
        kind: 'rejected',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        reason: input.record.result.reason,
        checks: input.record.result.checks,
        liveness: input.liveness,
        modelVersion: input.record.result.checks.speaker.modelVersion,
        thresholdVersion: input.record.result.checks.speaker.thresholdVersion,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        reason: mapUncertainReason(input.record.result.reason),
        checks: input.record.result.checks,
        liveness: input.liveness,
        modelVersion: input.record.result.checks.speaker.modelVersion,
        thresholdVersion: input.record.result.checks.speaker.thresholdVersion,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
    case 'expired':
      return {
        kind: 'rejected',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        reason: 'expired',
        checks: null,
        liveness: input.liveness,
        modelVersion: null,
        thresholdVersion: null,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
  }
}

export function evaluateVoiceIdOwnerPresenceForIntent(input: {
  ownerPresence: VoiceIdOwnerPresenceResult;
  intentDigest: VoiceIdIntentDigest;
}): VoiceIdOwnerPresenceIntentDecision {
  if (input.ownerPresence.intentDigest !== input.intentDigest) {
    return {
      kind: 'rejected',
      reason: 'intent_mismatch',
      ownerPresence: input.ownerPresence,
    };
  }
  if (input.ownerPresence.kind !== 'accepted') {
    return {
      kind: 'rejected',
      reason: 'owner_presence_not_accepted',
      ownerPresence: input.ownerPresence,
    };
  }

  return {
    kind: 'accepted',
    ownerPresence: input.ownerPresence,
  };
}

function buildAcceptedOwnerPresence(input: {
  record: Extract<VoiceIdVerificationRecord, { state: 'accepted' }>;
  liveness: VoiceIdLivenessResult;
}): VoiceIdOwnerPresenceResult {
  if (input.record.ownerPresenceEvidence.kind === 'consumed') {
    return {
      kind: 'rejected',
      userId: input.record.userId,
      enrollmentId: input.record.enrollmentId,
      verificationId: input.record.verificationId,
      intentDigest: input.record.intentDigest,
      reason: 'evidence_replayed',
      checks: input.record.result.checks,
      liveness: input.liveness,
      modelVersion: input.record.result.modelVersion,
      thresholdVersion: input.record.result.thresholdVersion,
      expiresAt: ownerPresenceExpiresAt(input.record),
      completedAt: input.record.completedAt,
    };
  }

  switch (input.liveness.kind) {
    case 'accepted':
    case 'not_required':
      return {
        kind: 'accepted',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        templateVersion: input.record.result.templateVersion,
        modelVersion: input.record.result.modelVersion,
        thresholdVersion: input.record.result.thresholdVersion,
        phrase: input.record.result.checks.phrase,
        speaker: input.record.result.checks.speaker,
        quality: input.record.result.checks.quality,
        liveness: input.liveness,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
    case 'rejected':
      return {
        kind: 'rejected',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        reason: 'liveness_mismatch',
        checks: input.record.result.checks,
        liveness: input.liveness,
        modelVersion: input.record.result.modelVersion,
        thresholdVersion: input.record.result.thresholdVersion,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
    case 'uncertain':
      return {
        kind: 'uncertain',
        userId: input.record.userId,
        enrollmentId: input.record.enrollmentId,
        verificationId: input.record.verificationId,
        intentDigest: input.record.intentDigest,
        reason: 'liveness_unavailable',
        checks: input.record.result.checks,
        liveness: input.liveness,
        modelVersion: input.record.result.modelVersion,
        thresholdVersion: input.record.result.thresholdVersion,
        expiresAt: ownerPresenceExpiresAt(input.record),
        completedAt: input.record.completedAt,
      };
  }

  return assertNever(input.liveness);
}

function ownerPresenceExpiresAt(record: VoiceIdCompletedVerificationRecord): IsoDateTime {
  return Date.parse(record.intentExpiresAt) < Date.parse(record.expiresAt)
    ? record.intentExpiresAt
    : record.expiresAt;
}

function mapUncertainReason(
  reason: Extract<VoiceIdVerificationRecord, { state: 'uncertain' }>['result']['reason'],
): VoiceIdOwnerPresenceUncertainReason {
  switch (reason) {
    case 'noisy_audio':
    case 'too_short':
    case 'model_low_confidence':
    case 'verifier_unavailable':
      return reason;
  }
}
