import assert from 'node:assert/strict';
import test from 'node:test';
import {
  authorizeVoiceIdOwnerPresence,
  buildVoiceIdOwnerPresenceResult,
  buildVoiceIdWalletPolicyInput,
  consumeVoiceIdOwnerPresenceForWalletPolicy,
  evaluateVoiceIdWalletPolicy,
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptPhrase,
  parseVoiceIdPolicyVersion,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  type VoiceIdAuthPolicyDecision,
  type VoiceIdAuthPolicyUseCase,
  type VoiceIdCompletedVerificationRecord,
  type VoiceIdLivenessResult,
  type VoiceIdVerificationChecks,
} from '../../shared/src/index.ts';

const intentDigest = parseVoiceIdIntentDigest('A'.repeat(43));
const otherIntentDigest = parseVoiceIdIntentDigest('B'.repeat(43));
const intentExpiresAt = parseIsoDateTime('2026-06-13T00:05:00.000Z');
const intentNonce = parseVoiceIdIntentNonce('nonce_123456');
const policyVersion = parseVoiceIdPolicyVersion('voiceid-wallet-policy-v1');
const policyNow = new Date('2026-06-13T00:02:00.000Z');
const acceptedLiveness: VoiceIdLivenessResult = {
  kind: 'accepted',
  method: 'audio',
  checkedAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
};
const deviceContext = {
  kind: 'local_device_context_v1' as const,
  deviceId: 'reachy-mini-devkit',
  sidecarId: 'voiceid-sidecar-1',
  captureStartedAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
  evaluatedAt: parseIsoDateTime('2026-06-13T00:00:02.200Z'),
  localPolicyVersion: 'voiceid-liveness-policy-v1',
};

test('VoiceID auth policy emits accepted owner-presence evidence for wallet signing', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_mpc_signing',
    now: policyNow,
  });

  assert.equal(decision.kind, 'accepted');
  assert.equal(decision.evidence.kind, 'voice_id_owner_presence_evidence');
  assert.equal(decision.evidence.useCase, 'wallet_mpc_signing');
  assert.equal(decision.evidence.intentDigest, intentDigest);
  assert.equal(decision.evidence.userId, 'owner');
  assert.equal(decision.evidence.enrollmentId, 'enroll_1');
  assert.equal(decision.evidence.verificationId, 'verify_1');
  assert.equal(decision.evidence.liveness.kind, 'audio_liveness');
  assert.equal(decision.evidence.modelVersion, 'model-v1');
  assert.equal(decision.evidence.thresholdVersion, 'threshold-v1');
});

test('VoiceID wallet policy input carries owner presence and model metadata', () => {
  const authDecision = acceptedAuthDecision('wallet_mpc_signing');

  const input = buildVoiceIdWalletPolicyInput({
    authDecision,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });
  const policyDecision = evaluateVoiceIdWalletPolicy(input);

  assert.equal(input.kind, 'voice_id_wallet_policy_input');
  assert.equal(input.policyVersion, policyVersion);
  assert.equal(input.intentDigest, intentDigest);
  assert.deepEqual(input.device, {
    kind: 'local_device_sidecar',
    deviceId: 'reachy-mini-devkit',
    sidecarId: 'voiceid-sidecar-1',
    localPolicyVersion: 'voiceid-liveness-policy-v1',
    evaluatedAt: parseIsoDateTime('2026-06-13T00:00:02.200Z'),
  });
  assert.equal(input.ownerPresence.kind, 'accepted');
  assert.equal(input.transcript.kind, 'accepted');
  assert.equal(input.speaker.kind, 'accepted');
  assert.equal(input.liveness.kind, 'audio_liveness');
  assert.equal(input.modelVersion, 'model-v1');
  assert.equal(input.thresholdVersion, 'threshold-v1');
  assert.deepEqual(policyDecision, {
    kind: 'accepted',
    input,
    stepUp: { kind: 'not_required' },
  });
});

test('VoiceID wallet policy requires step-up for risky payment tiers', () => {
  const authDecision = acceptedAuthDecision('wallet_mpc_signing');
  const newRecipientInput = buildVoiceIdWalletPolicyInput({
    authDecision,
    policyVersion,
    actionTier: { kind: 'new_recipient_payment' },
    deviceContext,
  });
  const highRiskInput = buildVoiceIdWalletPolicyInput({
    authDecision,
    policyVersion,
    actionTier: { kind: 'high_value_or_anomalous_payment' },
    deviceContext,
  });

  assert.deepEqual(evaluateVoiceIdWalletPolicy(newRecipientInput), {
    kind: 'step_up_required',
    input: newRecipientInput,
    stepUp: { kind: 'required', reason: 'new_recipient' },
  });
  assert.deepEqual(evaluateVoiceIdWalletPolicy(highRiskInput), {
    kind: 'step_up_required',
    input: highRiskInput,
    stepUp: { kind: 'required', reason: 'high_value_or_anomalous' },
  });
});

test('VoiceID wallet policy consumes accepted owner-presence authorization', () => {
  const authDecision = acceptedAuthDecision('wallet_mpc_signing');

  const consumed = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });

  assert.equal(consumed.kind, 'accepted');
  assert.equal(consumed.authDecision, authDecision);
  assert.equal(consumed.input.intentDigest, intentDigest);
  assert.equal(consumed.input.policyVersion, policyVersion);
  assert.equal(consumed.input.modelVersion, 'model-v1');
  assert.equal(consumed.input.thresholdVersion, 'threshold-v1');
  assert.equal(consumed.input.liveness.kind, 'audio_liveness');
  assert.equal(consumed.input.device.deviceId, 'reachy-mini-devkit');
  assert.equal(consumed.input.device.sidecarId, 'voiceid-sidecar-1');
  assert.equal(consumed.decision.kind, 'accepted');
  assert.equal('rejection' in consumed, false);
});

test('VoiceID wallet policy consumption returns step-up decisions before signing', () => {
  const authDecision = acceptedAuthDecision('wallet_mpc_signing');

  const newRecipient = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision,
    policyVersion,
    actionTier: { kind: 'new_recipient_payment' },
    deviceContext,
  });
  const highRisk = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision,
    policyVersion,
    actionTier: { kind: 'high_value_or_anomalous_payment' },
    deviceContext,
  });

  assert.equal(newRecipient.kind, 'step_up_required');
  assert.equal(newRecipient.input.intentDigest, intentDigest);
  assert.deepEqual(newRecipient.decision.stepUp, { kind: 'required', reason: 'new_recipient' });
  assert.equal('rejection' in newRecipient, false);
  assert.equal(highRisk.kind, 'step_up_required');
  assert.equal(highRisk.input.intentDigest, intentDigest);
  assert.deepEqual(highRisk.decision.stepUp, { kind: 'required', reason: 'high_value_or_anomalous' });
  assert.equal('rejection' in highRisk, false);
});

test('VoiceID wallet policy consumption preserves rejected owner-presence authorization', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: rejectedRecord(),
    liveness: acceptedLiveness,
  });
  const authDecision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_mpc_signing',
    now: policyNow,
  });

  const consumed = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });

  assert.equal(consumed.kind, 'rejected');
  assert.equal(consumed.authDecision, authDecision);
  assert.deepEqual(consumed.rejection, {
    kind: 'owner_presence_authorization_rejected',
    reason: 'owner_presence_rejected',
    detail: 'speaker_mismatch',
    retryable: true,
    ownerPresence,
  });
  assert.equal('input' in consumed, false);
  assert.equal('decision' in consumed, false);
});

test('VoiceID wallet policy consumption preserves uncertain owner-presence authorization', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: uncertainRecord(),
    liveness: acceptedLiveness,
  });
  const authDecision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_mpc_signing',
    now: policyNow,
  });

  const consumed = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });

  assert.equal(consumed.kind, 'rejected');
  assert.equal(consumed.rejection.reason, 'owner_presence_uncertain');
  assert.equal(consumed.rejection.detail, 'model_low_confidence');
  assert.equal(consumed.rejection.retryable, true);
  assert.equal(consumed.rejection.ownerPresence, ownerPresence);
});

test('VoiceID wallet policy consumption preserves expired and mismatched authorizations', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });
  const expired = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_mpc_signing',
    now: new Date('2026-06-13T00:06:00.000Z'),
  });
  const mismatched = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest: otherIntentDigest,
    useCase: 'wallet_mpc_signing',
    now: policyNow,
  });

  const expiredConsumed = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision: expired,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });
  const mismatchedConsumed = consumeVoiceIdOwnerPresenceForWalletPolicy({
    authDecision: mismatched,
    policyVersion,
    actionTier: { kind: 'low_value_known_recipient_payment' },
    deviceContext,
  });

  assert.equal(expiredConsumed.kind, 'rejected');
  assert.equal(expiredConsumed.rejection.reason, 'owner_presence_expired');
  assert.equal(expiredConsumed.rejection.detail, 'expired');
  assert.equal(mismatchedConsumed.kind, 'rejected');
  assert.equal(mismatchedConsumed.rejection.reason, 'intent_mismatch');
  assert.equal(mismatchedConsumed.rejection.detail, 'intent_mismatch');
  assert.equal(mismatchedConsumed.rejection.retryable, false);
});

test('VoiceID auth policy preserves explicit browser-MVP liveness exemption', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: { kind: 'not_required', reason: 'browser_mvp_policy' },
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_session',
    now: policyNow,
  });

  assert.equal(decision.kind, 'accepted');
  assert.deepEqual(decision.evidence.liveness, {
    kind: 'liveness_not_required',
    reason: 'browser_mvp_policy',
  });
});

test('VoiceID auth policy rejects mismatched intent binding without retry', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest: otherIntentDigest,
    useCase: 'robot_command',
    now: policyNow,
  });

  assert.deepEqual(decision, {
    kind: 'rejected',
    reason: 'intent_mismatch',
    detail: 'intent_mismatch',
    retryable: false,
    ownerPresence,
  });
});

test('VoiceID auth policy maps rejected owner presence into retryable policy rejection', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: rejectedRecord(),
    liveness: acceptedLiveness,
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_mpc_signing',
    now: policyNow,
  });

  assert.equal(decision.kind, 'rejected');
  assert.equal(decision.reason, 'owner_presence_rejected');
  assert.equal(decision.detail, 'speaker_mismatch');
  assert.equal(decision.retryable, true);
  assert.equal(decision.ownerPresence, ownerPresence);
});

test('VoiceID auth policy maps uncertain owner presence into retryable policy rejection', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: uncertainRecord(),
    liveness: acceptedLiveness,
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'wallet_session',
    now: policyNow,
  });

  assert.equal(decision.kind, 'rejected');
  assert.equal(decision.reason, 'owner_presence_uncertain');
  assert.equal(decision.detail, 'model_low_confidence');
  assert.equal(decision.retryable, true);
  assert.equal(decision.ownerPresence, ownerPresence);
});

test('VoiceID auth policy rejects expired owner-presence evidence', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });

  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase: 'robot_command',
    now: new Date('2026-06-13T00:06:00.000Z'),
  });

  assert.equal(decision.kind, 'rejected');
  assert.equal(decision.reason, 'owner_presence_expired');
  assert.equal(decision.detail, 'expired');
  assert.equal(decision.retryable, true);
  assert.equal(decision.ownerPresence, ownerPresence);
});

function acceptedAuthDecision(
  useCase: VoiceIdAuthPolicyUseCase,
): Extract<VoiceIdAuthPolicyDecision, { kind: 'accepted' }> {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });
  const decision = authorizeVoiceIdOwnerPresence({
    ownerPresence,
    intentDigest,
    useCase,
    now: policyNow,
  });
  if (decision.kind !== 'accepted') {
    throw new Error(`expected accepted auth decision, got ${decision.kind}`);
  }
  return decision;
}

function acceptedRecord(): Extract<VoiceIdCompletedVerificationRecord, { state: 'accepted' }> {
  return {
    state: 'accepted',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest,
    intentExpiresAt,
    intentNonce,
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
    result: {
      kind: 'accepted',
      enrollmentId: parseEnrollmentId('enroll_1'),
      verificationId: parseVerificationId('verify_1'),
      templateVersion: parseTemplateVersion('template-v1'),
      checks: acceptedChecks(),
      modelVersion: parseModelVersion('model-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
    },
    ownerPresenceEvidence: { kind: 'available' },
  };
}

function rejectedRecord(): Extract<VoiceIdCompletedVerificationRecord, { state: 'rejected' }> {
  return {
    state: 'rejected',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest,
    intentExpiresAt,
    intentNonce,
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
    result: {
      kind: 'rejected',
      verificationId: parseVerificationId('verify_1'),
      reason: 'speaker_mismatch',
      checks: rejectedChecks(),
    },
  };
}

function uncertainRecord(): Extract<VoiceIdCompletedVerificationRecord, { state: 'uncertain' }> {
  return {
    state: 'uncertain',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest,
    intentExpiresAt,
    intentNonce,
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
    result: {
      kind: 'uncertain',
      verificationId: parseVerificationId('verify_1'),
      reason: 'model_low_confidence',
      checks: uncertainChecks(),
    },
  };
}

function acceptedChecks(): Extract<VoiceIdCompletedVerificationRecord, { state: 'accepted' }>['result']['checks'] {
  return {
    phrase: {
      kind: 'accepted',
      expectedNormalized: 'walking on clouds',
      spokenNormalized: 'walking on clouds',
      confidence: 0.98,
    },
    speaker: {
      kind: 'accepted',
      score: 0.94,
      threshold: 0.82,
      modelVersion: parseModelVersion('model-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
    },
    quality: {
      kind: 'accepted',
      durationMs: 1800,
      signalScore: 0.94,
    },
  };
}

function rejectedChecks(): VoiceIdVerificationChecks {
  return {
    ...acceptedChecks(),
    speaker: {
      kind: 'rejected',
      reason: 'speaker_mismatch',
      score: 0.31,
      threshold: 0.82,
      modelVersion: parseModelVersion('model-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
    },
  };
}

function uncertainChecks(): VoiceIdVerificationChecks {
  return {
    ...acceptedChecks(),
    speaker: {
      kind: 'uncertain',
      reason: 'model_low_confidence',
      score: 0.78,
      threshold: 0.82,
      modelVersion: parseModelVersion('model-v1'),
      thresholdVersion: parseThresholdVersion('threshold-v1'),
    },
  };
}
