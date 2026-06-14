import assert from 'node:assert/strict';
import test from 'node:test';
import {
  FakeTranscriptProvider,
  FakeVoiceIdVerifier,
  InMemoryVoiceIdEnrollmentStore,
  InMemoryVoiceIdVerificationStore,
  VoiceIdService,
  createDefaultVoiceIdService,
  defaultVoiceIdServiceConfig,
} from '../../server/src/index.ts';
import { createVoiceIdFetchHandler } from '../../server/src/routes.ts';
import { nowIsoDateTime } from '../../shared/src/index.ts';

test('route handler completes enrollment start', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const response = await postJson(handler, '/voice-id/enrollment/start', {
    userId: 'owner',
    phrase: 'Walking on clouds',
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as { kind: string; value: { record: { state: string } } };
  assert.equal(body.kind, 'ok');
  assert.equal(body.value.record.state, 'pending');
});

test('route handler completes valid verification flow', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const enrollmentStart = await readOkResponse<{
    record: { enrollmentId: string };
  }>(
    await postJson(handler, '/voice-id/enrollment/start', {
      userId: 'owner',
      phrase: 'Walking on clouds',
    }),
  );

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    const sampleResponse = await postSample(handler, '/voice-id/enrollment/sample', {
      fields: {
        userId: 'owner',
        enrollmentId: enrollmentStart.record.enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      },
      speakerLabel: 'owner',
    });
    assert.equal(sampleResponse.status, 200);
  }

  const finalized = await readOkResponse<{ state: string }>(
    await postJson(handler, '/voice-id/enrollment/finalize', {
      userId: 'owner',
      enrollmentId: enrollmentStart.record.enrollmentId,
    }),
  );
  assert.equal(finalized.state, 'enrolled');

  const verificationStart = await readOkResponse<{
    record: { verificationId: string };
  }>(
    await postJson(handler, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollmentStart.record.enrollmentId,
      phrase: 'Walking on clouds',
      ...testIntentBindingBody(),
    }),
  );

  const verificationResponse = await postSample(handler, '/voice-id/verification/sample', {
    fields: {
      userId: 'owner',
      enrollmentId: enrollmentStart.record.enrollmentId,
      verificationId: verificationStart.record.verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    },
    speakerLabel: 'owner',
  });

  const verificationResult = await readOkResponse<{ kind: string }>(verificationResponse);
  assert.equal(verificationResult.kind, 'accepted');
});

test('route handler authorizes owner presence for accepted verification and liveness', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const completed = await completeAcceptedVerification(handler);

  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId),
  );

  const result = await readOkResponse<{
    liveness: { kind: string };
    ownerPresence: { kind: string; intentDigest: string; liveness: { kind: string } };
    decision: { kind: string; evidence: { useCase: string; intentDigest: string } };
  }>(response);
  assert.equal(result.liveness.kind, 'accepted');
  assert.equal(result.ownerPresence.kind, 'accepted');
  assert.equal(result.ownerPresence.intentDigest, 'A'.repeat(43));
  assert.equal(result.decision.kind, 'accepted');
  assert.equal(result.decision.evidence.useCase, 'wallet_mpc_signing');
});

test('route handler rejects owner-presence authorization for mismatched intent digest', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const completed = await completeAcceptedVerification(handler);

  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId, {
      intentDigest: 'B'.repeat(43),
    }),
  );

  const result = await readOkResponse<{
    ownerPresence: { kind: string; intentDigest: string };
    decision: { kind: string; reason: string; detail: string; retryable: boolean };
  }>(response);
  assert.equal(result.ownerPresence.kind, 'accepted');
  assert.equal(result.ownerPresence.intentDigest, 'A'.repeat(43));
  assert.equal(result.decision.kind, 'rejected');
  assert.equal(result.decision.reason, 'intent_mismatch');
  assert.equal(result.decision.detail, 'intent_mismatch');
  assert.equal(result.decision.retryable, false);
});

test('route handler rejects replayed owner-presence evidence', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const completed = await completeAcceptedVerification(handler);

  const first = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId),
  );
  assert.equal((await readOkResponse<{ decision: { kind: string } }>(first)).decision.kind, 'accepted');

  const replayed = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId),
  );

  const result = await readOkResponse<{
    ownerPresence: { kind: string; reason: string };
    decision: { kind: string; reason: string; detail: string; retryable: boolean };
  }>(replayed);
  assert.equal(result.ownerPresence.kind, 'rejected');
  assert.equal(result.ownerPresence.reason, 'evidence_replayed');
  assert.equal(result.decision.kind, 'rejected');
  assert.equal(result.decision.reason, 'owner_presence_rejected');
  assert.equal(result.decision.detail, 'evidence_replayed');
  assert.equal(result.decision.retryable, false);
});

test('route handler rejects expired owner-presence evidence', async () => {
  let now = new Date('2026-06-13T00:00:00.000Z');
  const handler = createVoiceIdFetchHandler(new VoiceIdService({
    enrollmentStore: new InMemoryVoiceIdEnrollmentStore(),
    verificationStore: new InMemoryVoiceIdVerificationStore(),
    verifier: new FakeVoiceIdVerifier(),
    transcriptProvider: new FakeTranscriptProvider(),
    config: defaultVoiceIdServiceConfig(),
    now: () => now,
    emitAuditEvent: () => {},
  }));
  const completed = await completeAcceptedVerification(handler, {
    intentDigest: 'A'.repeat(43),
    intentExpiresAt: '2026-06-13T00:01:00.000Z',
    intentNonce: 'nonce_123456',
  });

  now = new Date('2026-06-13T00:02:00.000Z');
  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId),
  );

  const result = await readOkResponse<{
    ownerPresence: { kind: string; expiresAt: string };
    decision: { kind: string; reason: string; detail: string; retryable: boolean };
  }>(response);
  assert.equal(result.ownerPresence.kind, 'accepted');
  assert.equal(result.ownerPresence.expiresAt, '2026-06-13T00:01:00.000Z');
  assert.equal(result.decision.kind, 'rejected');
  assert.equal(result.decision.reason, 'owner_presence_expired');
  assert.equal(result.decision.detail, 'expired');
  assert.equal(result.decision.retryable, true);
});

test('route handler returns uncertain when audio source is unattested', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const completed = await completeAcceptedVerification(handler);

  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId, {
      audio: {
        ...acceptedAudioLivenessSignals(),
        captureSource: { kind: 'unknown_microphone', reason: 'robot_source_unattested' },
      },
    }),
  );

  const result = await readOkResponse<{
    liveness: { kind: string; reason: string };
    ownerPresence: { kind: string; reason: string };
    decision: { kind: string; reason: string; detail: string; retryable: boolean };
  }>(response);
  assert.equal(result.liveness.kind, 'uncertain');
  assert.equal(result.liveness.reason, 'liveness_unavailable');
  assert.equal(result.ownerPresence.kind, 'uncertain');
  assert.equal(result.ownerPresence.reason, 'liveness_unavailable');
  assert.equal(result.decision.kind, 'rejected');
  assert.equal(result.decision.reason, 'owner_presence_uncertain');
  assert.equal(result.decision.detail, 'liveness_unavailable');
  assert.equal(result.decision.retryable, true);
});

test('route handler rejects accepted verification when audio replay risk is high', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const completed = await completeAcceptedVerification(handler);

  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(completed.verificationId, {
      audio: {
        ...acceptedAudioLivenessSignals(),
        replayRisk: { kind: 'high', reason: 'reused_capture_hash' },
      },
    }),
  );

  const result = await readOkResponse<{
    liveness: { kind: string; reason: string };
    ownerPresence: { kind: string; reason: string };
    decision: { kind: string; reason: string; detail: string; retryable: boolean };
  }>(response);
  assert.equal(result.liveness.kind, 'rejected');
  assert.equal(result.liveness.reason, 'replay_detected');
  assert.equal(result.ownerPresence.kind, 'rejected');
  assert.equal(result.ownerPresence.reason, 'liveness_mismatch');
  assert.equal(result.decision.kind, 'rejected');
  assert.equal(result.decision.reason, 'owner_presence_rejected');
  assert.equal(result.decision.detail, 'liveness_mismatch');
  assert.equal(result.decision.retryable, true);
});

test('route handler requires completed verification before owner-presence authorization', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const enrollmentStart = await completeEnrollment(handler);
  const verificationStart = await readOkResponse<{
    record: { verificationId: string };
  }>(
    await postJson(handler, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollmentStart.enrollmentId,
      phrase: 'Walking on clouds',
      ...testIntentBindingBody(),
    }),
  );

  const response = await postJson(
    handler,
    '/voice-id/owner-presence/authorize',
    buildOwnerPresenceAuthorizationBody(verificationStart.record.verificationId),
  );

  assert.equal(response.status, 409);
  const body = (await response.json()) as { kind: string; error: { kind: string; message: string } };
  assert.equal(body.kind, 'error');
  assert.equal(body.error.kind, 'invalid_state');
  assert.equal(body.error.message, 'verification is not completed');
});

test('route handler rejects malformed metadata', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const form = new FormData();
  form.set('audio', new Blob([new Uint8Array([1, 2, 3])], { type: 'audio/webm' }));
  form.set('metadata', JSON.stringify({ bad: true }));
  form.set(
    'fields',
    JSON.stringify({
      userId: 'owner',
      enrollmentId: 'enroll_test',
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    }),
  );

  const response = await handler(
    new Request('http://localhost/voice-id/enrollment/sample', {
      method: 'POST',
      body: form,
    }),
  );

  assert.equal(response.status, 400);
});

test('route handler rejects missing audio blob', async () => {
  const handler = createVoiceIdFetchHandler(createDefaultVoiceIdService());
  const form = new FormData();
  form.set('metadata', JSON.stringify(buildTestMetadata(3)));
  form.set(
    'fields',
    JSON.stringify({
      userId: 'owner',
      enrollmentId: 'enroll_test',
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    }),
  );

  const response = await handler(
    new Request('http://localhost/voice-id/enrollment/sample', {
      method: 'POST',
      body: form,
    }),
  );

  assert.equal(response.status, 400);
});

async function postJson(
  handler: ReturnType<typeof createVoiceIdFetchHandler>,
  path: string,
  body: Record<string, unknown>,
): Promise<Response> {
  return await handler(
    new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

async function postSample(
  handler: ReturnType<typeof createVoiceIdFetchHandler>,
  path: string,
  input: {
    fields: Record<string, unknown>;
    speakerLabel: string;
  },
): Promise<Response> {
  const bytes = new Uint8Array([1, 2, 3]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set('metadata', JSON.stringify(buildTestMetadata(bytes.byteLength, input.speakerLabel)));
  form.set('fields', JSON.stringify(input.fields));

  return await handler(
    new Request(`http://localhost${path}`, {
      method: 'POST',
      body: form,
    }),
  );
}

async function completeAcceptedVerification(
  handler: ReturnType<typeof createVoiceIdFetchHandler>,
  intentBinding: Record<string, unknown> = testIntentBindingBody(),
): Promise<{ enrollmentId: string; verificationId: string }> {
  const enrollment = await completeEnrollment(handler);
  const verificationStart = await readOkResponse<{
    record: { verificationId: string };
  }>(
    await postJson(handler, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollment.enrollmentId,
      phrase: 'Walking on clouds',
      ...intentBinding,
    }),
  );

  const verificationResponse = await postSample(handler, '/voice-id/verification/sample', {
    fields: {
      userId: 'owner',
      enrollmentId: enrollment.enrollmentId,
      verificationId: verificationStart.record.verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    },
    speakerLabel: 'owner',
  });

  const verificationResult = await readOkResponse<{ kind: string }>(verificationResponse);
  assert.equal(verificationResult.kind, 'accepted');

  return {
    enrollmentId: enrollment.enrollmentId,
    verificationId: verificationStart.record.verificationId,
  };
}

async function completeEnrollment(
  handler: ReturnType<typeof createVoiceIdFetchHandler>,
): Promise<{ enrollmentId: string }> {
  const enrollmentStart = await readOkResponse<{
    record: { enrollmentId: string };
  }>(
    await postJson(handler, '/voice-id/enrollment/start', {
      userId: 'owner',
      phrase: 'Walking on clouds',
    }),
  );

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    const sampleResponse = await postSample(handler, '/voice-id/enrollment/sample', {
      fields: {
        userId: 'owner',
        enrollmentId: enrollmentStart.record.enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      },
      speakerLabel: 'owner',
    });
    assert.equal(sampleResponse.status, 200);
  }

  const finalized = await readOkResponse<{ state: string }>(
    await postJson(handler, '/voice-id/enrollment/finalize', {
      userId: 'owner',
      enrollmentId: enrollmentStart.record.enrollmentId,
    }),
  );
  assert.equal(finalized.state, 'enrolled');

  return { enrollmentId: enrollmentStart.record.enrollmentId };
}

function buildOwnerPresenceAuthorizationBody(
  verificationId: string,
  overrides: {
    audio?: Record<string, unknown>;
    intentDigest?: string;
  } = {},
): Record<string, unknown> {
  return {
    verificationId,
    intentDigest: overrides.intentDigest ?? 'A'.repeat(43),
    useCase: 'wallet_mpc_signing',
    policyVersion: 'voiceid-wallet-policy-v1',
    audio: overrides.audio ?? acceptedAudioLivenessSignals(),
    context: {
      kind: 'local_device_context_v1',
      deviceId: 'reachy-mini-devkit',
      sidecarId: 'voiceid-sidecar-1',
      captureStartedAt: '2026-06-13T00:00:00.000Z',
      evaluatedAt: '2026-06-13T00:00:02.200Z',
      localPolicyVersion: 'voiceid-liveness-policy-v1',
    },
  };
}

function testIntentBindingBody(): Record<string, unknown> {
  return {
    intentDigest: 'A'.repeat(43),
    intentExpiresAt: '2099-01-01T00:00:00.000Z',
    intentNonce: 'nonce_123456',
  };
}

function acceptedAudioLivenessSignals(): Record<string, unknown> {
  return {
    kind: 'audio_liveness_signals_v1',
    promptOpenedAt: '2026-06-13T00:00:00.000Z',
    speechStartedAt: '2026-06-13T00:00:00.600Z',
    speechEndedAt: '2026-06-13T00:00:01.900Z',
    captureSource: {
      kind: 'trusted_microphone',
      deviceId: 'reachy-mic-1',
    },
    replayRisk: { kind: 'low' },
  };
}

async function readOkResponse<TValue>(response: Response): Promise<TValue> {
  assert.equal(response.status, 200);
  const body = (await response.json()) as { kind: string; value: TValue };
  assert.equal(body.kind, 'ok');
  return body.value;
}

export function buildTestMetadata(byteLength: number, speakerLabel = 'owner') {
  return {
    mimeType: 'audio/webm',
    durationMs: 1500,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength,
    capturedAt: nowIsoDateTime(),
    recorder: 'test',
    fixtureBehavior: { kind: 'speaker_label', speakerLabel },
  };
}
