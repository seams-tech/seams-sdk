import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildVoiceIdOwnerPresenceResult,
  evaluateVoiceIdOwnerPresenceForIntent,
  type VoiceIdCompletedVerificationRecord,
  type VoiceIdLivenessResult,
} from '../../server/src/index.ts';
import {
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptPhrase,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  type VoiceIdVerificationChecks,
} from '../../shared/src/index.ts';

const intentDigest = parseVoiceIdIntentDigest('A'.repeat(43));
const otherIntentDigest = parseVoiceIdIntentDigest('B'.repeat(43));
const intentExpiresAt = parseIsoDateTime('2026-06-13T00:05:00.000Z');
const intentNonce = parseVoiceIdIntentNonce('nonce_123456');
const acceptedLiveness: VoiceIdLivenessResult = {
  kind: 'accepted',
  method: 'audio',
  checkedAt: parseIsoDateTime('2026-06-13T00:01:00.000Z'),
};

test('VoiceID intent digest requires unpadded base64url 32-byte digest shape', () => {
  assert.equal(parseVoiceIdIntentDigest('A'.repeat(43)), 'A'.repeat(43));
  assert.throws(
    () => parseVoiceIdIntentDigest('not-a-digest'),
    /intentDigest must be an unpadded base64url-encoded 32-byte digest/,
  );
});

test('owner-presence policy result accepts completed VoiceID with matching intent', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: acceptedLiveness,
  });

  assert.equal(ownerPresence.kind, 'accepted');
  assert.equal(ownerPresence.intentDigest, intentDigest);
  assert.equal(ownerPresence.liveness.kind, 'accepted');

  assert.deepEqual(
    evaluateVoiceIdOwnerPresenceForIntent({ ownerPresence, intentDigest }),
    {
      kind: 'accepted',
      ownerPresence,
    },
  );
});

test('owner-presence policy result downgrades accepted VoiceID when liveness rejects', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: {
      kind: 'rejected',
      reason: 'replay_detected',
    },
  });

  assert.equal(ownerPresence.kind, 'rejected');
  assert.equal(ownerPresence.reason, 'liveness_mismatch');
  const decision = evaluateVoiceIdOwnerPresenceForIntent({ ownerPresence, intentDigest });
  assert.equal(decision.kind, 'rejected');
  assert.equal(decision.reason, 'owner_presence_not_accepted');
});

test('owner-presence policy result rejects mismatched intent digest', () => {
  const ownerPresence = buildVoiceIdOwnerPresenceResult({
    record: acceptedRecord(),
    liveness: { kind: 'not_required', reason: 'browser_mvp_policy' },
  });

  assert.deepEqual(
    evaluateVoiceIdOwnerPresenceForIntent({ ownerPresence, intentDigest: otherIntentDigest }),
    {
      kind: 'rejected',
      reason: 'intent_mismatch',
      ownerPresence,
    },
  );
});

test('owner-presence policy result preserves rejected, uncertain, and expired branches', () => {
  const rejected = buildVoiceIdOwnerPresenceResult({
    record: rejectedRecord(),
    liveness: acceptedLiveness,
  });
  assert.equal(rejected.kind, 'rejected');
  assert.equal(rejected.reason, 'speaker_mismatch');
  assert.equal(rejected.modelVersion, 'model-v1');

  const uncertain = buildVoiceIdOwnerPresenceResult({
    record: uncertainRecord(),
    liveness: acceptedLiveness,
  });
  assert.equal(uncertain.kind, 'uncertain');
  assert.equal(uncertain.reason, 'model_low_confidence');
  assert.equal(uncertain.thresholdVersion, 'threshold-v1');

  const expired = buildVoiceIdOwnerPresenceResult({
    record: expiredRecord(),
    liveness: acceptedLiveness,
  });
  assert.equal(expired.kind, 'rejected');
  assert.equal(expired.reason, 'expired');
  assert.equal(expired.checks, null);
  assert.equal(expired.modelVersion, null);
});

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

function expiredRecord(): Extract<VoiceIdCompletedVerificationRecord, { state: 'expired' }> {
  return {
    state: 'expired',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest,
    intentExpiresAt,
    intentNonce,
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:06:00.000Z'),
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
