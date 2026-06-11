import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildAudioInput,
  nowIsoDateTime,
  parsePromptPhrase,
  parseUserId,
} from '../../shared/src/index.ts';
import {
  VoiceIdService,
  defaultVoiceIdServiceConfig,
  type VoiceIdServiceConfig,
} from '../../server/src/VoiceIdService.ts';
import {
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
} from '../../server/src/store/VoiceIdStores.ts';
import { FakeVoiceIdVerifier } from '../../server/src/verifier/FakeVoiceIdVerifier.ts';
import { FakeTranscriptProvider } from '../../server/src/transcript/FakeTranscriptProvider.ts';
import type { VoiceIdTranscriptProvider } from '../../server/src/transcript/VoiceIdTranscriptProvider.ts';

test('enrolls and verifies matching speaker and phrase', async () => {
  const service = createTestService();
  const userId = parseUserId('owner');
  const phrase = parsePromptPhrase('Walking on clouds');
  const enrollment = await service.startEnrollment({ userId, phrase });
  assert.equal(enrollment.kind, 'ok');

  const enrollmentId = enrollment.value.record.enrollmentId;
  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    const sample = await service.addEnrollmentSample({
      userId,
      enrollmentId,
      expectedPhrase: phrase,
      spokenPhrase: phrase,
      attemptNumber,
      audio: makeAudio('owner'),
    });
    assert.equal(sample.kind, 'ok');
  }

  const finalized = await service.finalizeEnrollment({ userId, enrollmentId });
  assert.equal(finalized.kind, 'ok');
  assert.equal(finalized.value.state, 'enrolled');

  const verification = await service.startVerification({ userId, enrollmentId, phrase });
  assert.equal(verification.kind, 'ok');

  const result = await service.verifySample({
    userId,
    enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: phrase,
    spokenPhrase: phrase,
    attemptNumber: 1,
    audio: makeAudio('owner'),
  });
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'accepted');
});

test('rejects phrase mismatch during verification', async () => {
  const fixture = await createEnrolledFixture();
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
  });
  assert.equal(verification.kind, 'ok');

  const result = await fixture.service.verifySample({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: fixture.phrase,
    spokenPhrase: parsePromptPhrase('Send 5 USDC to Alice'),
    attemptNumber: 1,
    audio: makeAudio('owner'),
  });
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'rejected');
  assert.equal(result.value.kind === 'rejected' ? result.value.reason : '', 'phrase_mismatch');
});

test('does not count too-short enrollment samples as accepted', async () => {
  const service = createTestService();
  const userId = parseUserId('owner');
  const phrase = parsePromptPhrase('Walking on clouds');
  const enrollment = await service.startEnrollment({ userId, phrase });
  assert.equal(enrollment.kind, 'ok');

  const sample = await service.addEnrollmentSample({
    userId,
    enrollmentId: enrollment.value.record.enrollmentId,
    expectedPhrase: phrase,
    spokenPhrase: phrase,
    attemptNumber: 1,
    audio: makeAudio('owner', { durationMs: 500 }),
  });

  assert.equal(sample.kind, 'ok');
  assert.equal(sample.value.quality.kind, 'uncertain');
  assert.equal(sample.value.acceptedSampleCount, 0);
});

test('does not count noisy enrollment samples as accepted', async () => {
  const service = createTestService();
  const userId = parseUserId('owner');
  const phrase = parsePromptPhrase('Walking on clouds');
  const enrollment = await service.startEnrollment({ userId, phrase });
  assert.equal(enrollment.kind, 'ok');

  const sample = await service.addEnrollmentSample({
    userId,
    enrollmentId: enrollment.value.record.enrollmentId,
    expectedPhrase: phrase,
    spokenPhrase: phrase,
    attemptNumber: 1,
    audio: makeAudio('owner', { fixtureBehavior: 'noisy' }),
  });

  assert.equal(sample.kind, 'ok');
  assert.equal(sample.value.quality.kind, 'uncertain');
  assert.equal(sample.value.acceptedSampleCount, 0);
});

test('rejects finalization with insufficient accepted enrollment samples', async () => {
  const service = createTestService();
  const userId = parseUserId('owner');
  const phrase = parsePromptPhrase('Walking on clouds');
  const enrollment = await service.startEnrollment({ userId, phrase });
  assert.equal(enrollment.kind, 'ok');

  const finalized = await service.finalizeEnrollment({
    userId,
    enrollmentId: enrollment.value.record.enrollmentId,
  });

  assert.equal(finalized.kind, 'error');
  assert.equal(finalized.error.kind, 'invalid_state');
});

test('rejects expired verification prompts', async () => {
  const fixture = await createEnrolledFixture({
    config: {
      ...defaultVoiceIdServiceConfig(),
      verificationPromptTtlMs: -1,
    },
  });
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
  });
  assert.equal(verification.kind, 'ok');

  const result = await fixture.service.verifySample({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: fixture.phrase,
    spokenPhrase: fixture.phrase,
    attemptNumber: 1,
    audio: makeAudio('owner'),
  });

  assert.equal(result.kind, 'error');
  assert.equal(result.error.kind, 'expired');
});

test('rejects speaker mismatch during verification', async () => {
  const fixture = await createEnrolledFixture();
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
  });
  assert.equal(verification.kind, 'ok');

  const result = await fixture.service.verifySample({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: fixture.phrase,
    spokenPhrase: fixture.phrase,
    attemptNumber: 1,
    audio: makeAudio('alice'),
  });
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'rejected');
  assert.equal(result.value.kind === 'rejected' ? result.value.reason : '', 'speaker_mismatch');
});

test('returns uncertain for noisy runtime audio', async () => {
  const fixture = await createEnrolledFixture();
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
  });
  assert.equal(verification.kind, 'ok');

  const result = await fixture.service.verifySample({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: fixture.phrase,
    spokenPhrase: fixture.phrase,
    attemptNumber: 1,
    audio: makeAudio('owner', { fixtureBehavior: 'noisy' }),
  });
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'uncertain');
});

test('returns uncertain when transcript provider is unavailable', async () => {
  const fixture = await createEnrolledFixture({
    transcriptProvider: {
      async matchPhrase() {
        throw new Error('transcript provider unavailable');
      },
    },
  });
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
  });
  assert.equal(verification.kind, 'ok');

  const result = await fixture.service.verifySample({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    verificationId: verification.value.record.verificationId,
    expectedPhrase: fixture.phrase,
    spokenPhrase: fixture.phrase,
    attemptNumber: 1,
    audio: makeAudio('owner'),
  });

  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'uncertain');
  assert.equal(result.value.kind === 'uncertain' ? result.value.reason : '', 'model_low_confidence');
  assert.equal(result.value.checks.phrase.kind, 'uncertain');
});

function createTestService(input: {
  config?: VoiceIdServiceConfig;
  transcriptProvider?: VoiceIdTranscriptProvider;
} = {}): VoiceIdService {
  return new VoiceIdService({
    enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
    verificationStore: new InMemoryVoiceIdVerificationStore(),
    verifier: new FakeVoiceIdVerifier(),
    transcriptProvider: input.transcriptProvider ?? new FakeTranscriptProvider(),
    config: input.config ?? defaultVoiceIdServiceConfig(),
    now: () => new Date(),
    emitAuditEvent: () => {},
  });
}

async function createEnrolledFixture(input: {
  config?: VoiceIdServiceConfig;
  transcriptProvider?: VoiceIdTranscriptProvider;
} = {}) {
  const service = createTestService(input);
  const userId = parseUserId('owner');
  const phrase = parsePromptPhrase('Walking on clouds');
  const enrollment = await service.startEnrollment({ userId, phrase });
  assert.equal(enrollment.kind, 'ok');
  const enrollmentId = enrollment.value.record.enrollmentId;
  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    await service.addEnrollmentSample({
      userId,
      enrollmentId,
      expectedPhrase: phrase,
      spokenPhrase: phrase,
      attemptNumber,
      audio: makeAudio('owner'),
    });
  }
  const finalized = await service.finalizeEnrollment({ userId, enrollmentId });
  assert.equal(finalized.kind, 'ok');
  return { service, userId, phrase, enrollmentId };
}

function makeAudio(
  speakerLabel: string,
  input: {
    fixtureBehavior?: 'normal' | 'noisy';
    durationMs?: number;
  } = {},
) {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const fixtureBehavior = input.fixtureBehavior ?? 'normal';
  return buildAudioInput(bytes, {
    mimeType: 'audio/webm',
    durationMs: input.durationMs ?? 1500,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength: bytes.byteLength,
    capturedAt: nowIsoDateTime(),
    recorder: 'test',
    fixtureBehavior:
      fixtureBehavior === 'noisy'
        ? { kind: 'noisy', speakerLabel }
        : { kind: 'speaker_label', speakerLabel },
  });
}
