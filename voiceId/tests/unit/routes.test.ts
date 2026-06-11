import assert from 'node:assert/strict';
import test from 'node:test';
import { createDefaultVoiceIdService } from '../../server/src/index.ts';
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
