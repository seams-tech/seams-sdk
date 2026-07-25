import assert from 'node:assert/strict';
import test from 'node:test';
import {
  nowIsoDateTime,
  parseEnrollmentId,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdChallengeNonce,
  type VoiceIdEnrollmentRecord,
  type VoiceIdVerificationRecord,
} from '../../shared/src/index.ts';
import {
  parseCloudflareEnrollmentRow,
  parseCloudflareVerificationRow,
  serializeEnrollmentRecordForCloudflare,
  serializeVerificationRecordForCloudflare,
} from '../../server/src/index.ts';

const now = nowIsoDateTime(new Date('2026-07-13T00:00:00.000Z'));
const pending = pendingEnrollment();

test('Cloudflare rows round-trip continuous enrollment records', () => {
  const row = serializeEnrollmentRecordForCloudflare(pending);
  assert.equal(row.schemaVersion, 4);
  assert.equal(row.recordKind, 'enrollment');
  assert.deepEqual(parseCloudflareEnrollmentRow(row), pending);
});

test('Cloudflare rows round-trip E0 verification evidence', () => {
  const record = observedVerification();
  const row = serializeVerificationRecordForCloudflare(record);
  assert.equal(row.schemaVersion, 4);
  assert.equal(row.recordKind, 'verification');
  assert.deepEqual(parseCloudflareVerificationRow(row), record);
});

test('Cloudflare rows reject index and payload mismatches', () => {
  const row = serializeEnrollmentRecordForCloudflare(pending);
  assert.throws(
    () => parseCloudflareEnrollmentRow({ ...row, userId: 'different-user' }),
    /indexes do not match/,
  );
});

function pendingEnrollment(): VoiceIdEnrollmentRecord {
  return {
    state: 'pending_continuous_recording',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enrollment_1'),
    promptSetId: parsePromptSetId('prompt_set_1'),
    promptSequence: [
      parsePromptPhrase('Copper river carries morning light'),
      parsePromptPhrase('Seven quiet lanterns cross the harbor'),
      parsePromptPhrase('Bright cedar branches move in winter'),
      parsePromptPhrase('A silver compass points toward home'),
    ],
    modelVersion: parseModelVersion('model_1'),
    createdAt: now,
    expiresAt: now,
    minimumCaptureMs: 12_000,
    targetCaptureMs: 18_000,
    maximumCaptureMs: 30_000,
  };
}

function observedVerification(): VoiceIdVerificationRecord {
  const verificationId = parseVerificationId('verification_1');
  const enrollmentId = parseEnrollmentId('enrollment_1');
  const modelVersion = parseModelVersion('model_1');
  const thresholdVersion = parseThresholdVersion('threshold_1');
  const phrase = {
    kind: 'accepted' as const,
    expectedNormalized: 'river lantern a b c d e f',
    spokenNormalized: 'river lantern a b c d e f',
    confidence: 0.98,
  };
  const speaker = {
    kind: 'accepted' as const,
    score: 0.94,
    threshold: 0.82,
    modelVersion,
    thresholdVersion,
  };
  const quality = { kind: 'accepted' as const, durationMs: 4_000, signalScore: 0.94 };
  return {
    state: 'evidence_observed',
    userId: parseUserId('owner'),
    enrollmentId,
    verificationId,
    expectedPhrase: parsePromptPhrase('River lantern a b c d e f'),
    challengeNonce: parseVoiceIdChallengeNonce('challenge_nonce_abcdef'),
    createdAt: now,
    expiresAt: now,
    analysisStartedAt: now,
    analysisExpiresAt: now,
    completedAt: now,
    result: {
      kind: 'evidence_observed',
      evidence: {
        kind: 'experimental_browser_evidence',
        verificationId,
        enrollmentId,
        observedChecks: {
          phrase,
          intent: {
            kind: 'accepted',
            expectedIntent: 'expected_phrase',
            matchedIntent: 'expected_phrase',
            confidence: 0.94,
          },
          speaker,
          quality,
          captureFreshness: {
            kind: 'browser_timing_observation',
            challengeIssuedAt: now,
            captureReceivedAt: now,
            serverVerifiedFreshness: false,
          },
          pad: { kind: 'pad_unavailable', reason: 'ordinary_browser_capture' },
          captureProfile: {
            kind: 'ordinary_browser_capture',
            source: 'media_recorder',
            microphoneIntegrity: 'unverified',
          },
        },
        modelVersion,
        thresholdVersion,
        completedAt: now,
      },
    },
  };
}
