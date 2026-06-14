import { assertNever } from './assertNever.ts';
import type {
  IsoDateTime,
  UserId,
  VoiceIdEnrollmentId,
  VoiceIdIntentDigest,
  VoiceIdModelVersion,
  VoiceIdPolicyVersion,
  VoiceIdThresholdVersion,
  VoiceIdVerificationId,
} from './ids.ts';
import {
  evaluateVoiceIdOwnerPresenceForIntent,
  type VoiceIdOwnerPresenceIntentDecision,
  type VoiceIdOwnerPresenceRejectedReason,
  type VoiceIdOwnerPresenceResult,
  type VoiceIdOwnerPresenceUncertainReason,
} from './policy.ts';
import type { VoiceIdLocalDeviceContext } from './livenessPolicy.ts';

export type VoiceIdAuthPolicyUseCase =
  | 'wallet_mpc_signing'
  | 'wallet_session'
  | 'robot_command';

export type VoiceIdAuthPolicyAcceptedEvidence = {
  kind: 'voice_id_owner_presence_evidence';
  useCase: VoiceIdAuthPolicyUseCase;
  intentDigest: VoiceIdIntentDigest;
  userId: UserId;
  enrollmentId: VoiceIdEnrollmentId;
  verificationId: VoiceIdVerificationId;
  expiresAt: IsoDateTime;
  completedAt: IsoDateTime;
  liveness:
    | {
        kind: 'audio_liveness';
        checkedAt: IsoDateTime;
      }
    | {
        kind: 'liveness_not_required';
        reason: 'browser_mvp_policy';
      };
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
};

export type VoiceIdAuthPolicyRejectReason =
  | 'intent_mismatch'
  | 'owner_presence_rejected'
  | 'owner_presence_uncertain'
  | 'owner_presence_expired';

export type VoiceIdAuthPolicyDecision =
  | {
      kind: 'accepted';
      evidence: VoiceIdAuthPolicyAcceptedEvidence;
      ownerPresence: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>;
    }
  | {
      kind: 'rejected';
      reason: VoiceIdAuthPolicyRejectReason;
      detail:
        | VoiceIdOwnerPresenceRejectedReason
        | VoiceIdOwnerPresenceUncertainReason
        | 'intent_mismatch'
        | 'expired';
      retryable: boolean;
      ownerPresence: VoiceIdOwnerPresenceResult;
    };

export type VoiceIdWalletPolicyActionTier =
  | { kind: 'low_risk_robot_command' }
  | { kind: 'low_value_known_recipient_payment' }
  | { kind: 'new_recipient_payment' }
  | { kind: 'high_value_or_anomalous_payment' };

export type VoiceIdWalletPolicyStepUp =
  | {
      kind: 'not_required';
    }
  | {
      kind: 'required';
      reason: 'new_recipient' | 'high_value_or_anomalous';
    };

export type VoiceIdWalletPolicyDeviceBoundary = {
  kind: 'local_device_sidecar';
  deviceId: string;
  sidecarId: string;
  localPolicyVersion: string;
  evaluatedAt: IsoDateTime;
};

export type VoiceIdWalletPolicyInput = {
  kind: 'voice_id_wallet_policy_input';
  policyVersion: VoiceIdPolicyVersion;
  useCase: VoiceIdAuthPolicyUseCase;
  intentDigest: VoiceIdIntentDigest;
  device: VoiceIdWalletPolicyDeviceBoundary;
  ownerPresence: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>;
  transcript: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>['phrase'];
  speaker: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>['speaker'];
  liveness: VoiceIdAuthPolicyAcceptedEvidence['liveness'];
  modelVersion: VoiceIdModelVersion;
  thresholdVersion: VoiceIdThresholdVersion;
  actionTier: VoiceIdWalletPolicyActionTier;
};

export type VoiceIdWalletPolicyDecision =
  | {
      kind: 'accepted';
      input: VoiceIdWalletPolicyInput;
      stepUp: Extract<VoiceIdWalletPolicyStepUp, { kind: 'not_required' }>;
    }
  | {
      kind: 'step_up_required';
      input: VoiceIdWalletPolicyInput;
      stepUp: Extract<VoiceIdWalletPolicyStepUp, { kind: 'required' }>;
    };

export function authorizeVoiceIdOwnerPresence(input: {
  ownerPresence: VoiceIdOwnerPresenceResult;
  intentDigest: VoiceIdIntentDigest;
  useCase: VoiceIdAuthPolicyUseCase;
  now: Date;
}): VoiceIdAuthPolicyDecision {
  const intentDecision = evaluateVoiceIdOwnerPresenceForIntent({
    ownerPresence: input.ownerPresence,
    intentDigest: input.intentDigest,
  });
  if (intentDecision.kind === 'rejected') {
    return authPolicyRejectionFromIntentDecision(intentDecision);
  }

  const acceptedOwnerPresence = intentDecision.ownerPresence;

  if (isExpiredAt(acceptedOwnerPresence.expiresAt, input.now)) {
    return {
      kind: 'rejected',
      reason: 'owner_presence_expired',
      detail: 'expired',
      retryable: true,
      ownerPresence: acceptedOwnerPresence,
    };
  }

  return {
    kind: 'accepted',
    evidence: {
      kind: 'voice_id_owner_presence_evidence',
      useCase: input.useCase,
      intentDigest: input.intentDigest,
      userId: acceptedOwnerPresence.userId,
      enrollmentId: acceptedOwnerPresence.enrollmentId,
      verificationId: acceptedOwnerPresence.verificationId,
      expiresAt: acceptedOwnerPresence.expiresAt,
      completedAt: acceptedOwnerPresence.completedAt,
      liveness: acceptedLivenessEvidence(acceptedOwnerPresence.liveness),
      modelVersion: acceptedOwnerPresence.modelVersion,
      thresholdVersion: acceptedOwnerPresence.thresholdVersion,
    },
    ownerPresence: acceptedOwnerPresence,
  };
}

export function buildVoiceIdWalletPolicyInput(input: {
  authDecision: Extract<VoiceIdAuthPolicyDecision, { kind: 'accepted' }>;
  policyVersion: VoiceIdPolicyVersion;
  actionTier: VoiceIdWalletPolicyActionTier;
  deviceContext: VoiceIdLocalDeviceContext;
}): VoiceIdWalletPolicyInput {
  const ownerPresence = input.authDecision.ownerPresence;
  return {
    kind: 'voice_id_wallet_policy_input',
    policyVersion: input.policyVersion,
    useCase: input.authDecision.evidence.useCase,
    intentDigest: input.authDecision.evidence.intentDigest,
    device: {
      kind: 'local_device_sidecar',
      deviceId: input.deviceContext.deviceId,
      sidecarId: input.deviceContext.sidecarId,
      localPolicyVersion: input.deviceContext.localPolicyVersion,
      evaluatedAt: input.deviceContext.evaluatedAt,
    },
    ownerPresence,
    transcript: ownerPresence.phrase,
    speaker: ownerPresence.speaker,
    liveness: input.authDecision.evidence.liveness,
    modelVersion: input.authDecision.evidence.modelVersion,
    thresholdVersion: input.authDecision.evidence.thresholdVersion,
    actionTier: input.actionTier,
  };
}

export function evaluateVoiceIdWalletPolicy(
  input: VoiceIdWalletPolicyInput,
): VoiceIdWalletPolicyDecision {
  switch (input.actionTier.kind) {
    case 'low_risk_robot_command':
    case 'low_value_known_recipient_payment':
      return {
        kind: 'accepted',
        input,
        stepUp: { kind: 'not_required' },
      };
    case 'new_recipient_payment':
      return {
        kind: 'step_up_required',
        input,
        stepUp: { kind: 'required', reason: 'new_recipient' },
      };
    case 'high_value_or_anomalous_payment':
      return {
        kind: 'step_up_required',
        input,
        stepUp: { kind: 'required', reason: 'high_value_or_anomalous' },
      };
    default:
      return assertNever(input.actionTier);
  }
}

function authPolicyRejectionFromIntentDecision(
  decision: Extract<VoiceIdOwnerPresenceIntentDecision, { kind: 'rejected' }>,
): Extract<VoiceIdAuthPolicyDecision, { kind: 'rejected' }> {
  if (decision.reason === 'intent_mismatch') {
    return {
      kind: 'rejected',
      reason: 'intent_mismatch',
      detail: 'intent_mismatch',
      retryable: false,
      ownerPresence: decision.ownerPresence,
    };
  }

  switch (decision.ownerPresence.kind) {
    case 'accepted':
      return {
        kind: 'rejected',
        reason: 'intent_mismatch',
        detail: 'intent_mismatch',
        retryable: false,
        ownerPresence: decision.ownerPresence,
      };
    case 'rejected':
      return {
        kind: 'rejected',
        reason: 'owner_presence_rejected',
        detail: decision.ownerPresence.reason,
        retryable: retryableRejectedReason(decision.ownerPresence.reason),
        ownerPresence: decision.ownerPresence,
      };
    case 'uncertain':
      return {
        kind: 'rejected',
        reason: 'owner_presence_uncertain',
        detail: decision.ownerPresence.reason,
        retryable: true,
        ownerPresence: decision.ownerPresence,
      };
    default:
      return assertNever(decision.ownerPresence);
  }
}

function acceptedLivenessEvidence(
  liveness: Extract<VoiceIdOwnerPresenceResult, { kind: 'accepted' }>['liveness'],
): VoiceIdAuthPolicyAcceptedEvidence['liveness'] {
  switch (liveness.kind) {
    case 'accepted':
      return {
        kind: 'audio_liveness',
        checkedAt: liveness.checkedAt,
      };
    case 'not_required':
      return {
        kind: 'liveness_not_required',
        reason: liveness.reason,
      };
    default:
      return assertNever(liveness);
  }
}

function retryableRejectedReason(reason: VoiceIdOwnerPresenceRejectedReason): boolean {
  switch (reason) {
    case 'phrase_mismatch':
    case 'speaker_mismatch':
    case 'low_audio_quality':
    case 'liveness_mismatch':
    case 'expired':
    case 'too_many_attempts':
      return true;
    case 'intent_mismatch':
    case 'evidence_replayed':
      return false;
    default:
      return assertNever(reason);
  }
}

function isExpiredAt(expiresAt: IsoDateTime, now: Date): boolean {
  return Date.parse(expiresAt) <= now.getTime();
}
