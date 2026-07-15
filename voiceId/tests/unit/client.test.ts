import assert from 'node:assert/strict';
import test from 'node:test';
import { nowIsoDateTime, type VoiceIdAudioMetadata } from '../../shared/src/index.ts';
import { VoiceIdClient } from '../../client/src/index.ts';

test('client uses only the E0 evidence route surface', async () => {
  const calls: string[] = [];
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch: createFetchRecorder(calls),
  });
  await client.startEnrollment({ userId: 'owner' });
  await client.startVerification({ userId: 'owner', enrollmentId: 'enrollment_1' });
  await client.submitEnrollmentRecording({
    blob: new Blob([new Uint8Array([1, 2, 3, 4])], { type: 'audio/webm' }),
    metadata: audioMetadata(4),
    userId: 'owner',
    enrollmentId: 'enrollment_1',
  });
  await client.submitVerificationRecording({
    blob: new Blob([new Uint8Array([1, 2, 3, 4])], { type: 'audio/webm' }),
    metadata: audioMetadata(4),
    userId: 'owner',
    enrollmentId: 'enrollment_1',
    verificationId: 'verification_1',
  });
  assert.deepEqual(calls, [
    '/voice-id/evidence/enrollment/start',
    '/voice-id/evidence/verification/start',
    '/voice-id/evidence/enrollment/recording',
    '/voice-id/evidence/verification/recording',
  ]);
});

test('verification start sends no phrase, digest, policy, or liveness input', async () => {
  let requestBody: Record<string, unknown> | null = null;
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch: async (_input, init) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return jsonOkResponse('/voice-id/evidence/verification/start');
    },
  });
  await client.startVerification({ userId: 'owner', enrollmentId: 'enrollment_1' });
  assert.deepEqual(requestBody, { userId: 'owner', enrollmentId: 'enrollment_1' });
});

test('client rejects enrollment payloads that expose template material', async () => {
  const leakedValue = apiValueForPath('/voice-id/evidence/enrollment/recording');
  leakedValue.encryptedTemplate = 'forbidden-template';
  const client = new VoiceIdClient({
    baseUrl: 'http://localhost',
    fetch: async () =>
      new Response(JSON.stringify({ kind: 'ok', value: leakedValue }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
  });

  await assert.rejects(
    client.submitEnrollmentRecording({
      blob: new Blob([new Uint8Array([1, 2, 3, 4])], { type: 'audio/webm' }),
      metadata: audioMetadata(4),
      userId: 'owner',
      enrollmentId: 'enrollment_1',
    }),
    /unexpected fields: encryptedTemplate/,
  );
});

function createFetchRecorder(calls: string[]): typeof fetch {
  return async (input) => {
    const path = new URL(String(input)).pathname;
    calls.push(path);
    return jsonOkResponse(path);
  };
}

function jsonOkResponse(path: string): Response {
  return new Response(JSON.stringify({ kind: 'ok', value: apiValueForPath(path) }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function apiValueForPath(path: string): Record<string, unknown> {
  switch (path) {
    case '/voice-id/evidence/enrollment/start':
      return {
        enrollmentId: 'enrollment_1',
        promptSetId: 'prompt_set_1',
        promptSequence: ['One', 'Two', 'Three', 'Four'],
        modelVersion: 'model_1',
        expiresAt: '2026-07-13T00:02:00.000Z',
        minimumCaptureMs: 12_000,
        targetCaptureMs: 18_000,
        maximumCaptureMs: 30_000,
      };
    case '/voice-id/evidence/enrollment/recording':
      return {
        kind: 'enrolled',
        enrollmentId: 'enrollment_1',
        modelVersion: 'model_1',
        templateVersion: 'template_1',
        thresholdVersion: 'threshold_1',
        enrolledAt: '2026-07-13T00:00:00.000Z',
        quality: acceptedQuality(),
        phrase: acceptedPhrase(),
      };
    case '/voice-id/evidence/enrollment/disable':
      return {
        kind: 'disabled',
        enrollmentId: 'enrollment_1',
        disabledAt: '2026-07-13T00:00:00.000Z',
      };
    case '/voice-id/evidence/verification/start':
      return {
        enrollmentId: 'enrollment_1',
        verificationId: 'verification_1',
        prompt: 'River lantern a b c d e f',
        expiresAt: '2026-07-13T00:02:00.000Z',
      };
    case '/voice-id/evidence/verification/recording':
      return {
        kind: 'uncertain',
        verificationId: 'verification_1',
        reason: 'model_low_confidence',
        checks: {
          phrase: acceptedPhrase(),
          speaker: {
            kind: 'uncertain',
            reason: 'model_low_confidence',
            score: 0.8,
            threshold: 0.82,
            modelVersion: 'model_1',
            thresholdVersion: 'threshold_1',
          },
          quality: acceptedQuality(),
        },
      };
    default:
      throw new Error(`unexpected client test path: ${path}`);
  }
}

function acceptedQuality(): Record<string, unknown> {
  return { kind: 'accepted', durationMs: 4_000, signalScore: 0.9 };
}

function acceptedPhrase(): Record<string, unknown> {
  return {
    kind: 'accepted',
    expectedNormalized: 'river lantern a b c d e f',
    spokenNormalized: 'river lantern a b c d e f',
    confidence: 0.99,
  };
}

function audioMetadata(byteLength: number): VoiceIdAudioMetadata {
  return {
    mimeType: 'audio/webm',
    durationMs: 4_000,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength,
    capturedAt: nowIsoDateTime(),
    recorder: 'test',
  };
}
