import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import test from 'node:test';
import {
  nowIsoDateTime,
  parseUserId,
  parseVoiceIdChallengeNonce,
  type VoiceIdEnrollmentRecord,
  type VoiceIdVerificationRecord,
} from '../../shared/src/index.ts';
import {
  defaultVoiceIdServiceConfig,
  FakeTranscriptProvider,
  FakeVoiceIdVerifier,
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
  makeDemoAudioInput,
  VoiceIdService,
  type VoiceIdAuditEvent,
  type VoiceIdServiceConfig,
  type VoiceIdSpeakerVerification,
  type VoiceIdTranscriptProvider,
  type VoiceIdVerifier,
} from '../../server/src/index.ts';

const userId = parseUserId('owner');
const fixedNonce = parseVoiceIdChallengeNonce('challenge_nonce_abcdef');

test('continuous enrollment uses four prompts and one atomic recording', async () => {
  const fixture = createFixture();
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');
  assert.equal(started.value.promptSequence.length, 4);
  assert.equal(started.value.record.minimumCaptureMs, 12_000);
  assert.equal(started.value.record.targetCaptureMs, 18_000);
  assert.equal(started.value.record.maximumCaptureMs, 30_000);

  const completed = await fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: started.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  assert.equal(completed.kind, 'ok');
  assert.equal(completed.value.kind, 'enrolled');
  assert.equal((await fixture.enrollmentStore.getByUserId(userId))?.state, 'enrolled');
  assert.deepEqual(fixture.auditEvents.map(readAuditKind), ['enrollment_started', 'enrollment_completed']);
});

test('short enrollment fails atomically and cannot accept another recording', async () => {
  const fixture = createFixture();
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');
  const enrollmentId = started.value.record.enrollmentId;

  const rejected = await fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  assert.equal(rejected.kind, 'ok');
  assert.equal(rejected.value.kind, 'rejected');
  assert.equal(rejected.value.kind === 'rejected' ? rejected.value.reason : '', 'capture_too_short');
  assert.equal((await fixture.enrollmentStore.getByEnrollmentId(enrollmentId))?.state, 'failed');

  const replay = await fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  assert.equal(replay.kind, 'error');
  assert.equal(replay.error.kind, 'invalid_state');
});

test('uncertain transcript and template transport failures become precise terminal states', async () => {
  const transcriptFixture = createFixture();
  const transcriptStart = await transcriptFixture.service.startEnrollment({ userId });
  assert.equal(transcriptStart.kind, 'ok');
  const transcriptResult = await transcriptFixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: transcriptStart.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000, bytes: new Uint8Array([0xf1, 1, 2, 3]) }),
  });
  assert.equal(transcriptResult.kind, 'ok');
  assert.equal(
    transcriptResult.value.kind === 'rejected' ? transcriptResult.value.reason : '',
    'transcript_uncertain',
  );

  const templateFixture = createFixture({ verifier: new ThrowingTemplateVerifier() });
  const templateStart = await templateFixture.service.startEnrollment({ userId });
  assert.equal(templateStart.kind, 'ok');
  const templateResult = await templateFixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: templateStart.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  assert.equal(templateResult.kind, 'ok');
  assert.equal(
    templateResult.value.kind === 'rejected' ? templateResult.value.reason : '',
    'verifier_unavailable',
  );
});

test('verification prompt and nonce are server-owned and produce only E0 evidence', async () => {
  const fixture = createFixture();
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  assert.equal(started.value.record.challengeNonce, fixedNonce);
  assert.match(started.value.prompt, /a b c d e f$/);

  const completed = await fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  assert.equal(completed.kind, 'ok');
  assert.equal(completed.value.kind, 'evidence_observed');
  if (completed.value.kind !== 'evidence_observed') return;
  assert.equal(completed.value.evidence.kind, 'experimental_browser_evidence');
  assert.equal(completed.value.evidence.observedChecks.pad.kind, 'pad_unavailable');
  assert.equal(
    completed.value.evidence.observedChecks.captureFreshness.serverVerifiedFreshness,
    false,
  );
  assert.equal('signingAuthorization' in completed.value.evidence, false);
});

test('verification challenge commits exactly one concurrent capture', async () => {
  const fixture = createFixture();
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  const recording = {
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  };
  const [first, second] = await Promise.all([
    fixture.service.submitVerificationRecording(recording),
    fixture.service.submitVerificationRecording(recording),
  ]);
  let acceptedCount = 0;
  let conflictCount = 0;
  for (const result of [first, second]) {
    if (result.kind === 'ok') acceptedCount += 1;
    if (result.kind === 'error' && result.error.kind === 'invalid_state') conflictCount += 1;
  }
  assert.equal(acceptedCount, 1);
  assert.equal(conflictCount, 1);
});

test('a lost enrollment response cannot repeat terminal model work', async () => {
  const fixture = createFixture();
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');
  const recording = {
    userId,
    enrollmentId: started.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  };

  const discardedResponse = await fixture.service.submitEnrollmentRecording(recording);
  assert.equal(discardedResponse.kind, 'ok');

  const retry = await fixture.service.submitEnrollmentRecording(recording);
  assert.equal(retry.kind, 'error');
  assert.equal(retry.error.kind, 'invalid_state');
  assert.equal(
    (await fixture.enrollmentStore.getByEnrollmentId(recording.enrollmentId))?.state,
    'enrolled',
  );
  assert.equal(fixture.auditEvents.filter(isEnrollmentCompletedAudit).length, 1);
});

test('a lost verification response cannot repeat terminal model work', async () => {
  const fixture = createFixture();
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  const recording = {
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  };

  const discardedResponse = await fixture.service.submitVerificationRecording(recording);
  assert.equal(discardedResponse.kind, 'ok');

  const retry = await fixture.service.submitVerificationRecording(recording);
  assert.equal(retry.kind, 'error');
  assert.equal(retry.error.kind, 'invalid_state');
  assert.equal(
    (await fixture.verificationStore.getByVerificationId(recording.verificationId))?.state,
    'evidence_observed',
  );
  assert.equal(fixture.auditEvents.filter(isVerificationCompletedAudit).length, 1);
});

test('enrollment analysis is claimed before transcript work begins', async () => {
  const transcriptProvider = new BlockingTranscriptProvider();
  const fixture = createFixture({ transcriptProvider });
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');

  const submission = fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: started.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  await transcriptProvider.waitUntilStarted();

  const claimed = await fixture.enrollmentStore.getByEnrollmentId(started.value.record.enrollmentId);
  assert.equal(claimed?.state, 'analyzing_continuous_recording');

  transcriptProvider.release();
  const result = await submission;
  assert.equal(result.kind, 'ok');
});

test('an in-flight enrollment analysis fails when its lease expires', async () => {
  const transcriptProvider = new BlockingTranscriptProvider();
  const clock = new MutableClock(fixedNow());
  const fixture = createFixture({
    transcriptProvider,
    now: clock.now.bind(clock),
    config: { ...defaultVoiceIdServiceConfig(), enrollmentAnalysisTtlMs: 1_000 },
  });
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');

  const submission = fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: started.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  await transcriptProvider.waitUntilStarted();
  clock.advanceMs(2_000);
  transcriptProvider.release();

  const result = await submission;
  assert.equal(result.kind, 'ok');
  assert.equal(result.kind === 'ok' && result.value.kind === 'rejected' ? result.value.reason : '', 'analysis_timeout');
});

test('an in-flight verification analysis fails when its lease expires', async () => {
  const transcriptProvider = new BlockingTranscriptProvider(4_000);
  const clock = new MutableClock(fixedNow());
  const fixture = createFixture({
    transcriptProvider,
    now: clock.now.bind(clock),
    config: { ...defaultVoiceIdServiceConfig(), verificationAnalysisTtlMs: 1_000 },
  });
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');

  const submission = fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  await transcriptProvider.waitUntilStarted();
  clock.advanceMs(2_000);
  transcriptProvider.release();

  const result = await submission;
  assert.equal(result.kind, 'error');
  assert.equal(result.error.kind, 'expired');
  assert.equal(
    (await fixture.verificationStore.getByVerificationId(started.value.record.verificationId))
      ?.state,
    'analysis_failed',
  );
});

test('verification phrase and speaker inference start concurrently', async () => {
  const probe = new VerificationInferenceProbe();
  const fixture = createFixture({
    transcriptProvider: new ProbedTranscriptProvider(probe),
    verifier: new ProbedVoiceIdVerifier(probe),
  });
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');

  const submission = fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  await probe.waitUntilBothStarted();
  probe.release();

  const result = await submission;
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'evidence_observed');
});

test('stale enrollment analysis becomes a precise terminal failure', async () => {
  const fixture = createFixture();
  const started = await fixture.service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');
  const staleClaim = staleEnrollmentAnalysis(started.value.record);
  assert.equal(await fixture.enrollmentStore.claimPending(staleClaim), true);

  const result = await fixture.service.submitEnrollmentRecording({
    userId,
    enrollmentId: staleClaim.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });

  assert.equal(result.kind, 'ok');
  assert.equal(result.kind === 'ok' && result.value.kind === 'rejected' ? result.value.reason : '', 'analysis_timeout');
  assert.equal((await fixture.enrollmentStore.getByEnrollmentId(staleClaim.enrollmentId))?.state, 'failed');
});

test('stale verification analysis is recovered without rerunning providers', async () => {
  const fixture = createFixture();
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  const staleClaim = staleVerificationAnalysis(started.value.record);
  assert.equal(await fixture.verificationStore.claimIssued(staleClaim), true);

  const result = await fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: staleClaim.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });

  assert.equal(result.kind, 'error');
  assert.equal(result.error.kind, 'expired');
  assert.equal(
    (await fixture.verificationStore.getByVerificationId(staleClaim.verificationId))?.state,
    'analysis_failed',
  );
});

test('phrase mismatch rejects evidence without creating an accepted branch', async () => {
  const fixture = createFixture();
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  const result = await fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000, bytes: new Uint8Array([0xf4, 1, 2, 3]) }),
  });
  assert.equal(result.kind, 'ok');
  assert.equal(result.value.kind, 'rejected');
  assert.equal(result.value.kind === 'rejected' ? result.value.reason : '', 'phrase_mismatch');
});

test('verification preserves transcript and speaker provider outages', async () => {
  const transcriptFixture = createFixture({
    transcriptProvider: new VerificationUnavailableTranscriptProvider(),
  });
  const transcriptEnrollmentId = await enroll(transcriptFixture.service);
  const transcriptStart = await transcriptFixture.service.startVerification({
    userId,
    enrollmentId: transcriptEnrollmentId,
  });
  assert.equal(transcriptStart.kind, 'ok');
  const transcriptResult = await transcriptFixture.service.submitVerificationRecording({
    userId,
    enrollmentId: transcriptEnrollmentId,
    verificationId: transcriptStart.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  assert.equal(transcriptResult.kind, 'ok');
  assert.equal(
    transcriptResult.value.kind === 'uncertain' ? transcriptResult.value.reason : '',
    'verifier_unavailable',
  );

  const speakerFixture = createFixture({ verifier: new UnavailableSpeakerVerifier() });
  const speakerEnrollmentId = await enroll(speakerFixture.service);
  const speakerStart = await speakerFixture.service.startVerification({
    userId,
    enrollmentId: speakerEnrollmentId,
  });
  assert.equal(speakerStart.kind, 'ok');
  const speakerResult = await speakerFixture.service.submitVerificationRecording({
    userId,
    enrollmentId: speakerEnrollmentId,
    verificationId: speakerStart.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  assert.equal(speakerResult.kind, 'ok');
  assert.equal(
    speakerResult.value.kind === 'uncertain' ? speakerResult.value.reason : '',
    'verifier_unavailable',
  );
});

test('expired verification is consumed as expired', async () => {
  const fixture = createFixture({
    config: { ...defaultVoiceIdServiceConfig(), verificationPromptTtlMs: -1 },
  });
  const enrollmentId = await enroll(fixture.service);
  const started = await fixture.service.startVerification({ userId, enrollmentId });
  assert.equal(started.kind, 'ok');
  const result = await fixture.service.submitVerificationRecording({
    userId,
    enrollmentId,
    verificationId: started.value.record.verificationId,
    audio: makeDemoAudioInput({ durationMs: 4_000 }),
  });
  assert.equal(result.kind, 'error');
  assert.equal(result.error.kind, 'expired');
  assert.equal((await fixture.verificationStore.getByVerificationId(started.value.record.verificationId))?.state, 'expired');
});

function createFixture(input: {
  config?: VoiceIdServiceConfig;
  transcriptProvider?: VoiceIdTranscriptProvider;
  verifier?: VoiceIdVerifier;
  now?: () => Date;
} = {}) {
  const enrollmentStore = new InMemoryVoiceIdEnrollmentStore();
  const verificationStore = new InMemoryVoiceIdVerificationStore();
  const auditEvents: VoiceIdAuditEvent[] = [];
  const service = new VoiceIdService({
    enrollmentStore,
    verificationStore,
    verifier: input.verifier ?? new FakeVoiceIdVerifier(),
    transcriptProvider: input.transcriptProvider ?? new FakeTranscriptProvider(),
    config: input.config ?? defaultVoiceIdServiceConfig(),
    now: input.now ?? fixedNow,
    createChallengeNonce: fixedChallengeNonce,
    emitAuditEvent: auditEvents.push.bind(auditEvents),
  });
  return { service, enrollmentStore, verificationStore, auditEvents };
}

async function enroll(service: VoiceIdService) {
  const started = await service.startEnrollment({ userId });
  assert.equal(started.kind, 'ok');
  const submitted = await service.submitEnrollmentRecording({
    userId,
    enrollmentId: started.value.record.enrollmentId,
    audio: makeDemoAudioInput({ durationMs: 18_000 }),
  });
  assert.equal(submitted.kind, 'ok');
  assert.equal(submitted.value.kind, 'enrolled');
  return started.value.record.enrollmentId;
}

function fixedNow(): Date {
  return new Date('2026-07-13T00:00:00.000Z');
}

function fixedChallengeNonce() {
  return fixedNonce;
}

function readAuditKind(event: VoiceIdAuditEvent): string {
  return event.kind;
}

function isEnrollmentCompletedAudit(event: VoiceIdAuditEvent): boolean {
  return event.kind === 'enrollment_completed';
}

function isVerificationCompletedAudit(event: VoiceIdAuditEvent): boolean {
  return event.kind === 'verification_completed';
}

class ThrowingTemplateVerifier extends FakeVoiceIdVerifier {
  override async buildEnrollmentTemplate(
    _input: Parameters<VoiceIdVerifier['buildEnrollmentTemplate']>[0],
  ): Promise<never> {
    throw new Error('template transport unavailable');
  }
}

class VerificationUnavailableTranscriptProvider extends FakeTranscriptProvider {
  override async matchPhrase(
    input: Parameters<VoiceIdTranscriptProvider['matchPhrase']>[0],
  ): ReturnType<VoiceIdTranscriptProvider['matchPhrase']> {
    if (input.audio.metadata.durationMs === 4_000) {
      throw new Error('transcript provider unavailable');
    }
    return await super.matchPhrase(input);
  }
}

class BlockingTranscriptProvider extends FakeTranscriptProvider {
  private readonly events = new EventEmitter();
  private hasStarted = false;

  constructor(private readonly blockedDurationMs = 18_000) {
    super();
  }

  override async matchPhrase(
    input: Parameters<VoiceIdTranscriptProvider['matchPhrase']>[0],
  ): ReturnType<VoiceIdTranscriptProvider['matchPhrase']> {
    if (input.audio.metadata.durationMs !== this.blockedDurationMs) {
      return await super.matchPhrase(input);
    }
    this.hasStarted = true;
    this.events.emit('started');
    await once(this.events, 'released');
    return await super.matchPhrase(input);
  }

  async waitUntilStarted(): Promise<void> {
    if (this.hasStarted) return;
    await once(this.events, 'started');
  }

  release(): void {
    this.events.emit('released');
  }
}

class VerificationInferenceProbe {
  private readonly events = new EventEmitter();
  private transcriptStarted = false;
  private speakerStarted = false;

  markTranscriptStarted(): void {
    this.transcriptStarted = true;
    this.emitBothStarted();
  }

  markSpeakerStarted(): void {
    this.speakerStarted = true;
    this.emitBothStarted();
  }

  async waitUntilBothStarted(): Promise<void> {
    if (this.transcriptStarted && this.speakerStarted) return;
    await once(this.events, 'both-started');
  }

  async waitUntilReleased(): Promise<void> {
    await once(this.events, 'released');
  }

  release(): void {
    this.events.emit('released');
  }

  private emitBothStarted(): void {
    if (this.transcriptStarted && this.speakerStarted) {
      this.events.emit('both-started');
    }
  }
}

class ProbedTranscriptProvider extends FakeTranscriptProvider {
  constructor(private readonly probe: VerificationInferenceProbe) {
    super();
  }

  override async matchPhrase(
    input: Parameters<VoiceIdTranscriptProvider['matchPhrase']>[0],
  ): ReturnType<VoiceIdTranscriptProvider['matchPhrase']> {
    if (input.audio.metadata.durationMs === 4_000) {
      this.probe.markTranscriptStarted();
      await this.probe.waitUntilReleased();
    }
    return await super.matchPhrase(input);
  }
}

class ProbedVoiceIdVerifier extends FakeVoiceIdVerifier {
  constructor(private readonly probe: VerificationInferenceProbe) {
    super();
  }

  override async verifySpeaker(
    input: Parameters<VoiceIdVerifier['verifySpeaker']>[0],
  ): Promise<VoiceIdSpeakerVerification> {
    this.probe.markSpeakerStarted();
    await this.probe.waitUntilReleased();
    return await super.verifySpeaker(input);
  }
}

class MutableClock {
  constructor(private value: Date) {}

  now(): Date {
    return new Date(this.value);
  }

  advanceMs(durationMs: number): void {
    this.value = new Date(this.value.getTime() + durationMs);
  }
}

function staleEnrollmentAnalysis(
  record: Extract<VoiceIdEnrollmentRecord, { state: 'pending_continuous_recording' }>,
): Extract<VoiceIdEnrollmentRecord, { state: 'analyzing_continuous_recording' }> {
  const staleAt = nowIsoDateTime(new Date('2026-07-12T00:00:00.000Z'));
  return {
    state: 'analyzing_continuous_recording',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    promptSetId: record.promptSetId,
    promptSequence: record.promptSequence,
    modelVersion: record.modelVersion,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    minimumCaptureMs: record.minimumCaptureMs,
    targetCaptureMs: record.targetCaptureMs,
    maximumCaptureMs: record.maximumCaptureMs,
    analysisStartedAt: staleAt,
    analysisExpiresAt: staleAt,
  };
}

function staleVerificationAnalysis(
  record: Extract<VoiceIdVerificationRecord, { state: 'issued' }>,
): Extract<VoiceIdVerificationRecord, { state: 'analyzing' }> {
  const staleAt = nowIsoDateTime(new Date('2026-07-12T00:00:00.000Z'));
  return {
    state: 'analyzing',
    userId: record.userId,
    enrollmentId: record.enrollmentId,
    verificationId: record.verificationId,
    expectedPhrase: record.expectedPhrase,
    challengeNonce: record.challengeNonce,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    analysisStartedAt: staleAt,
    analysisExpiresAt: staleAt,
  };
}

class UnavailableSpeakerVerifier extends FakeVoiceIdVerifier {
  override async verifySpeaker(
    input: Parameters<VoiceIdVerifier['verifySpeaker']>[0],
  ): Promise<VoiceIdSpeakerVerification> {
    const result = await super.verifySpeaker(input);
    return {
      quality: result.quality,
      speaker: {
        kind: 'uncertain',
        reason: 'verifier_unavailable',
        score: 0,
        threshold: input.threshold,
        modelVersion: input.template.modelVersion,
        thresholdVersion: input.template.thresholdVersion,
      },
    };
  }
}
