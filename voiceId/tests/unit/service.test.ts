import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildAudioInput,
  nowIsoDateTime,
  parseIsoDateTime,
  parsePromptPhrase,
  parseUserId,
  parseVoiceIdIntentDigest,
  parseVoiceIdIntentNonce,
  parseVoiceIdPolicyVersion,
} from '../../shared/src/index.ts';
import {
  VoiceIdService,
  defaultVoiceIdServiceConfig,
  type VoiceIdAuditEvent,
  type VoiceIdServiceConfig,
} from '../../server/src/VoiceIdService.ts';
import {
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
} from '../../server/src/store/VoiceIdStores.ts';
import { FakeVoiceIdVerifier } from '../../server/src/verifier/FakeVoiceIdVerifier.ts';
import type { VoiceIdVerifier } from '../../server/src/verifier/VoiceIdVerifier.ts';
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

  const verification = await service.startVerification({
    userId,
    enrollmentId,
    phrase,
    ...testIntentBinding(),
  });
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

test('emits enrollment audit score bands without raw capture data', async () => {
  const auditEvents: VoiceIdAuditEvent[] = [];
  const service = createTestService({ auditEvents });
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
    audio: makeAudio('owner'),
  });
  assert.equal(sample.kind, 'ok');

  const event = requireAuditEvent(auditEvents, 'enrollment_sample_recorded');
  assert.equal(event.resultKind, 'accepted');
  assert.deepEqual(event.scoreBands, {
    kind: 'enrollment_sample',
    qualitySignal: 'high',
  });
  assertNoRawCaptureAuditFields(event);
});

test('emits verification audit score bands without raw capture data', async () => {
  const auditEvents: VoiceIdAuditEvent[] = [];
  const fixture = await createEnrolledFixture({ auditEvents });
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
    ...testIntentBinding(),
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
  assert.equal(result.value.kind, 'accepted');

  const event = requireAuditEvent(auditEvents, 'verification_completed');
  assert.equal(event.resultKind, 'accepted');
  assert.deepEqual(event.scoreBands, {
    kind: 'verification',
    phraseConfidence: 'high',
    speakerScore: 'high',
    speakerThreshold: 'high',
    qualitySignal: 'high',
  });
  assertNoRawCaptureAuditFields(event);
});

test('rejects phrase mismatch during verification', async () => {
  const fixture = await createEnrolledFixture();
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
    ...testIntentBinding(),
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
    ...testIntentBinding(),
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
    ...testIntentBinding(),
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
    ...testIntentBinding(),
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
    ...testIntentBinding(),
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

test('returns verifier_unavailable when enrollment embedding extraction fails', async () => {
  const service = createTestService({
    verifier: new ControlledFailingVoiceIdVerifier('extractEnrollmentEmbedding'),
  });
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
    audio: makeAudio('owner'),
  });

  assert.equal(sample.kind, 'error');
  assert.equal(sample.error.kind, 'verifier_unavailable');
});

test('returns verifier_unavailable when template build fails', async () => {
  const verifier = new ControlledFailingVoiceIdVerifier();
  const service = createTestService({ verifier });
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

  verifier.failingOperation = 'buildTemplate';
  const finalized = await service.finalizeEnrollment({ userId, enrollmentId });

  assert.equal(finalized.kind, 'error');
  assert.equal(finalized.error.kind, 'verifier_unavailable');
});

test('returns verifier_unavailable when speaker verification fails', async () => {
  const verifier = new ControlledFailingVoiceIdVerifier();
  const fixture = await createEnrolledFixture({ verifier });
  verifier.failingOperation = 'verifySpeaker';
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
    ...testIntentBinding(),
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
  assert.equal(result.error.kind, 'verifier_unavailable');
});

test('authorizes owner presence once for the issued intent', async () => {
  const auditEvents: VoiceIdAuditEvent[] = [];
  const fixture = await createAcceptedVerificationFixture({ auditEvents });

  const first = await fixture.service.authorizeOwnerPresence({
    verificationId: fixture.verificationId,
    intentDigest: testIntentBinding().intentDigest,
    useCase: 'wallet_mpc_signing',
    policyVersion: parseVoiceIdPolicyVersion('voiceid-wallet-policy-v1'),
    audio: acceptedAudioLivenessSignals(),
    context: localDeviceContext(),
    policy: {
      kind: 'audio_liveness_policy_v1',
      minSpeechDurationMs: 500,
      maxSpeechDurationMs: 5000,
      maxPromptToSpeechStartMs: 2000,
      requireTrustedMicrophone: true,
    },
  });

  assert.equal(first.kind, 'ok');
  assert.equal(first.value.decision.kind, 'accepted');
  assert.equal(first.value.ownerPresence.intentDigest, testIntentBinding().intentDigest);

  const second = await fixture.service.authorizeOwnerPresence({
    verificationId: fixture.verificationId,
    intentDigest: testIntentBinding().intentDigest,
    useCase: 'wallet_mpc_signing',
    policyVersion: parseVoiceIdPolicyVersion('voiceid-wallet-policy-v1'),
    audio: acceptedAudioLivenessSignals(),
    context: localDeviceContext(),
    policy: {
      kind: 'audio_liveness_policy_v1',
      minSpeechDurationMs: 500,
      maxSpeechDurationMs: 5000,
      maxPromptToSpeechStartMs: 2000,
      requireTrustedMicrophone: true,
    },
  });

  assert.equal(second.kind, 'ok');
  assert.equal(second.value.ownerPresence.kind, 'rejected');
  assert.equal(second.value.ownerPresence.kind === 'rejected' ? second.value.ownerPresence.reason : '', 'evidence_replayed');
  assert.equal(second.value.decision.kind, 'rejected');
  assert.equal(second.value.decision.kind === 'rejected' ? second.value.decision.retryable : true, false);

  const authorizationEvents = auditEvents.filter((event) => event.kind === 'owner_presence_authorized');
  assert.equal(authorizationEvents.length, 2);
  assert.deepEqual(authorizationEvents.map((event) => event.resultKind), ['accepted', 'rejected']);
  assert.deepEqual(authorizationEvents.map((event) => event.policyVersion), [
    'voiceid-wallet-policy-v1',
    'voiceid-wallet-policy-v1',
  ]);
  assertNoRawCaptureAuditFields(authorizationEvents[0]);
});

function createTestService(input: {
  config?: VoiceIdServiceConfig;
  transcriptProvider?: VoiceIdTranscriptProvider;
  verifier?: VoiceIdVerifier;
  auditEvents?: VoiceIdAuditEvent[];
} = {}): VoiceIdService {
  return new VoiceIdService({
    enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
    verificationStore: new InMemoryVoiceIdVerificationStore(),
    verifier: input.verifier ?? new FakeVoiceIdVerifier(),
    transcriptProvider: input.transcriptProvider ?? new FakeTranscriptProvider(),
    config: input.config ?? defaultVoiceIdServiceConfig(),
    now: () => new Date(),
    emitAuditEvent: (event) => {
      input.auditEvents?.push(event);
    },
  });
}

async function createEnrolledFixture(input: {
  config?: VoiceIdServiceConfig;
  transcriptProvider?: VoiceIdTranscriptProvider;
  verifier?: VoiceIdVerifier;
  auditEvents?: VoiceIdAuditEvent[];
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

async function createAcceptedVerificationFixture(input: { auditEvents?: VoiceIdAuditEvent[] } = {}) {
  const fixture = await createEnrolledFixture(input);
  const verification = await fixture.service.startVerification({
    userId: fixture.userId,
    enrollmentId: fixture.enrollmentId,
    phrase: fixture.phrase,
    ...testIntentBinding(),
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
  assert.equal(result.value.kind, 'accepted');

  return {
    ...fixture,
    verificationId: verification.value.record.verificationId,
  };
}

function requireAuditEvent(
  auditEvents: readonly VoiceIdAuditEvent[],
  kind: VoiceIdAuditEvent['kind'],
): VoiceIdAuditEvent {
  const event = auditEvents.find((candidate) => candidate.kind === kind);
  if (event === undefined) {
    throw new Error(`missing audit event ${kind}`);
  }
  return event;
}

function assertNoRawCaptureAuditFields(event: VoiceIdAuditEvent): void {
  const rawEvent = event as unknown as Record<string, unknown>;
  assert.equal(Object.hasOwn(rawEvent, 'audio'), false);
  assert.equal(Object.hasOwn(rawEvent, 'audioBytes'), false);
  assert.equal(Object.hasOwn(rawEvent, 'rawAudio'), false);
  assert.equal(Object.hasOwn(rawEvent, 'rawAudioBytes'), false);
  assert.equal(Object.hasOwn(rawEvent, 'rawCapture'), false);
  assert.equal(Object.hasOwn(rawEvent, 'rawCaptureBytes'), false);
}

type ControlledFailingOperation =
  | 'extractEnrollmentEmbedding'
  | 'buildTemplate'
  | 'verifySpeaker'
  | null;

class ControlledFailingVoiceIdVerifier implements VoiceIdVerifier {
  failingOperation: ControlledFailingOperation;
  private readonly fallback = new FakeVoiceIdVerifier();

  constructor(failingOperation: ControlledFailingOperation = null) {
    this.failingOperation = failingOperation;
  }

  async extractEnrollmentEmbedding(input: Parameters<VoiceIdVerifier['extractEnrollmentEmbedding']>[0]) {
    if (this.failingOperation === 'extractEnrollmentEmbedding') {
      throw new Error('python verifier unavailable');
    }
    return await this.fallback.extractEnrollmentEmbedding(input);
  }

  async buildTemplate(input: Parameters<VoiceIdVerifier['buildTemplate']>[0]) {
    if (this.failingOperation === 'buildTemplate') {
      throw new Error('python verifier unavailable');
    }
    return await this.fallback.buildTemplate(input);
  }

  async verifySpeaker(input: Parameters<VoiceIdVerifier['verifySpeaker']>[0]) {
    if (this.failingOperation === 'verifySpeaker') {
      throw new Error('python verifier unavailable');
    }
    return await this.fallback.verifySpeaker(input);
  }
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

function testIntentBinding() {
  return {
    intentDigest: parseVoiceIdIntentDigest('A'.repeat(43)),
    intentExpiresAt: parseIsoDateTime('2099-01-01T00:00:00.000Z'),
    intentNonce: parseVoiceIdIntentNonce('nonce_123456'),
  };
}

function acceptedAudioLivenessSignals() {
  return {
    kind: 'audio_liveness_signals_v1' as const,
    promptOpenedAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    speechStartedAt: parseIsoDateTime('2026-06-13T00:00:00.600Z'),
    speechEndedAt: parseIsoDateTime('2026-06-13T00:00:01.900Z'),
    captureSource: {
      kind: 'trusted_microphone' as const,
      deviceId: 'reachy-mic-1',
    },
    replayRisk: { kind: 'low' as const },
  };
}

function localDeviceContext() {
  return {
    kind: 'local_device_context_v1' as const,
    deviceId: 'reachy-mini-devkit',
    sidecarId: 'voiceid-sidecar-1',
    captureStartedAt: parseIsoDateTime('2026-06-13T00:00:00.000Z'),
    evaluatedAt: parseIsoDateTime('2026-06-13T00:00:02.200Z'),
    localPolicyVersion: 'voiceid-liveness-policy-v1',
  };
}
