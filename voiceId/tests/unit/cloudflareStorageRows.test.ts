import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseCloudflareEnrollmentRow,
  parseCloudflareVerificationRow,
  serializeEnrollmentRecordForCloudflare,
  serializeVerificationRecordForCloudflare,
} from '../../server/src/store/CloudflareVoiceIdStorageRows.ts';
import {
  parseEncryptedBytes,
  parseEnrollmentId,
  parseIsoDateTime,
  parseModelVersion,
  parsePromptPhrase,
  parsePromptSetId,
  parseTemplateVersion,
  parseThresholdVersion,
  parseUserId,
  parseVerificationId,
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  type VoiceIdEnrollmentRecord,
  type VoiceIdVerificationRecord,
  type VoiceIdVerificationResult,
} from '../../shared/src/index.ts';

test('Cloudflare enrollment rows keep pending templates impossible', () => {
  const pending = makePendingEnrollment();
  const row = serializeEnrollmentRecordForCloudflare(pending);

  assert.equal(row.state, 'pending');
  assert.equal(row.encryptedTemplate, null);
  assert.equal(row.templateVersion, null);
  assert.equal(row.thresholdVersion, null);
  assert.deepEqual(parseCloudflareEnrollmentRow(row), pending);

  assert.throws(
    () => parseCloudflareEnrollmentRow({ ...row, encryptedTemplate: 'ciphertext' }),
    /pending\.encryptedTemplate must be null/,
  );
});

test('Cloudflare enrollment rows require encrypted templates for enrolled records', () => {
  const enrolled = makeEnrolledEnrollment();
  const row = serializeEnrollmentRecordForCloudflare(enrolled);

  assert.equal(row.state, 'enrolled');
  assert.equal(row.encryptedTemplate, 'ciphertext');
  assert.equal(row.templateVersion, 'template-v1');
  assert.equal(row.thresholdVersion, 'threshold-v1');
  assert.deepEqual(parseCloudflareEnrollmentRow(row), enrolled);

  assert.throws(
    () => parseCloudflareEnrollmentRow({ ...row, encryptedTemplate: null }),
    /encryptedTemplate must be a non-empty string/,
  );
});

test('Cloudflare verification rows do not store raw capture payloads', () => {
  const issued = makeIssuedVerification();
  const row = serializeVerificationRecordForCloudflare(issued);

  assert.equal(row.state, 'issued');
  assert.equal(row.resultJson, null);
  assert.equal(row.completedAt, null);
  assert.equal(row.ownerPresenceEvidenceKind, null);
  assert.equal(row.ownerPresenceConsumedAt, null);
  assert.equal(Object.hasOwn(row, 'audio'), false);
  assert.equal(Object.hasOwn(row, 'rawAudioBytes'), false);
  assert.equal(Object.hasOwn(row, 'rawCaptureBytes'), false);
  assert.deepEqual(parseCloudflareVerificationRow(row), issued);

  assert.throws(
    () => parseCloudflareVerificationRow({ ...row, rawCaptureBytes: 'base64-capture' }),
    /must not contain raw capture column rawCaptureBytes/,
  );
});

test('Cloudflare verification rows roundtrip completed results', () => {
  const completed = makeAcceptedVerification();
  const row = serializeVerificationRecordForCloudflare(completed);

  assert.equal(row.state, 'accepted');
  assert.equal(row.attemptCount, null);
  assert.equal(row.ownerPresenceEvidenceKind, 'available');
  assert.equal(row.ownerPresenceConsumedAt, null);
  assert.equal(typeof row.resultJson, 'string');
  assert.deepEqual(parseCloudflareVerificationRow(row), completed);

  assert.throws(
    () => parseCloudflareVerificationRow({
      ...row,
      resultJson: JSON.stringify({ ...completed.result, kind: 'rejected', reason: 'phrase_mismatch' }),
    }),
    /accepted verification row requires accepted result/,
  );
});

function makePendingEnrollment(): Extract<VoiceIdEnrollmentRecord, { state: 'pending' }> {
  return {
    state: 'pending',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    promptSetId: parsePromptSetId('prompt-v1'),
    modelVersion: parseModelVersion('model-v1'),
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:10:00.000Z'),
    requiredSampleCount: 3,
    acceptedSampleCount: 1,
    attemptCount: 2,
  };
}

function makeEnrolledEnrollment(): Extract<VoiceIdEnrollmentRecord, { state: 'enrolled' }> {
  return {
    state: 'enrolled',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    promptSetId: parsePromptSetId('prompt-v1'),
    modelVersion: parseModelVersion('model-v1'),
    templateVersion: parseTemplateVersion('template-v1'),
    thresholdVersion: parseThresholdVersion('threshold-v1'),
    encryptedTemplate: parseEncryptedBytes('ciphertext'),
    createdAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    enrolledAt: parseIsoDateTime('2026-06-13T00:05:00.000Z'),
  };
}

function makeIssuedVerification(): Extract<VoiceIdVerificationRecord, { state: 'issued' }> {
  return {
    state: 'issued',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest: parseVoiceIdIntentDigest('A'.repeat(43)),
    intentExpiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    intentNonce: parseVoiceIdIntentNonce('nonce_123456'),
    createdAt: parseIsoDateTime('2026-06-13T00:06:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    attemptCount: 0,
  };
}

function makeAcceptedVerification(): Extract<VoiceIdVerificationRecord, { state: 'accepted' }> {
  const result: VoiceIdVerificationResult = {
    kind: 'accepted',
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    templateVersion: parseTemplateVersion('template-v1'),
    modelVersion: parseModelVersion('model-v1'),
    thresholdVersion: parseThresholdVersion('threshold-v1'),
    checks: {
      phrase: {
        kind: 'accepted',
        expectedNormalized: 'walking on clouds',
        spokenNormalized: 'walking on clouds',
        confidence: 0.98,
      },
      speaker: {
        kind: 'accepted',
        score: 0.93,
        threshold: 0.82,
        modelVersion: parseModelVersion('model-v1'),
        thresholdVersion: parseThresholdVersion('threshold-v1'),
      },
      quality: {
        kind: 'accepted',
        durationMs: 1800,
        signalScore: 0.94,
      },
    },
  };

  return {
    state: 'accepted',
    userId: parseUserId('owner'),
    enrollmentId: parseEnrollmentId('enroll_1'),
    verificationId: parseVerificationId('verify_1'),
    expectedPhrase: parsePromptPhrase('Walking on clouds'),
    intentDigest: parseVoiceIdIntentDigest('A'.repeat(43)),
    intentExpiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    intentNonce: parseVoiceIdIntentNonce('nonce_123456'),
    createdAt: parseIsoDateTime('2026-06-13T00:06:00.000Z'),
    expiresAt: parseIsoDateTime('2026-06-13T00:07:00.000Z'),
    completedAt: parseIsoDateTime('2026-06-13T00:06:20.000Z'),
    result,
    ownerPresenceEvidence: { kind: 'available' },
  };
}
