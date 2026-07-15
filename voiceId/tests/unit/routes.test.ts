import assert from 'node:assert/strict';
import test from 'node:test';
import { nowIsoDateTime } from '../../shared/src/index.ts';
import { createDefaultVoiceIdService, createVoiceIdFetchHandler } from '../../server/src/index.ts';

test('health identifies the route surface as signing-ineligible E0 evidence', async () => {
  const handler = createHandler();
  const response = await handler(new Request('http://localhost/voice-id/health'));
  const body = (await response.json()) as Record<string, unknown>;
  assert.equal(response.status, 200);
  assert.equal(body.evidenceTier, 'experimental_browser_evidence');
  assert.equal(body.signingEligible, false);
  assert.deepEqual(body.routes, [
    'POST /voice-id/evidence/enrollment/start',
    'POST /voice-id/evidence/enrollment/recording',
    'POST /voice-id/evidence/enrollment/disable',
    'POST /voice-id/evidence/verification/start',
    'POST /voice-id/evidence/verification/recording',
  ]);
});

test('route flow uses one enrollment recording and returns E0 evidence', async () => {
  const handler = createHandler();
  const enrollment = await startEnrollment(handler);
  const enrolled = await postAudio(
    handler,
    '/voice-id/evidence/enrollment/recording',
    {
      userId: 'owner',
      enrollmentId: enrollment.enrollmentId,
    },
    18_000,
  );
  assert.equal(enrolled.kind, 'enrolled');
  assert.equal('encryptedTemplate' in enrolled, false);
  assert.equal('record' in enrolled, false);

  const verificationResponse = await postJson(handler, '/voice-id/evidence/verification/start', {
    userId: 'owner',
    enrollmentId: enrollment.enrollmentId,
  });
  const verification = await readOkValue(verificationResponse);
  assert.equal(typeof verification.prompt, 'string');

  const completedResponse = await postAudio(
    handler,
    '/voice-id/evidence/verification/recording',
    {
      userId: 'owner',
      enrollmentId: enrollment.enrollmentId,
      verificationId: requireString(verification.verificationId, 'verificationId'),
    },
    4_000,
  );
  assert.equal(completedResponse.kind, 'evidence_observed');
  const evidence = requireObject(completedResponse.evidence, 'evidence');
  assert.equal(evidence.kind, 'experimental_browser_evidence');
  assert.equal('signingAuthorization' in evidence, false);
});

test('route boundary rejects unexpected security-sensitive fields', async () => {
  const handler = createHandler();
  const response = await postJson(handler, '/voice-id/evidence/enrollment/start', {
    userId: 'owner',
    clientSelectedPrompt: 'untrusted prompt',
  });
  assert.equal(response.kind, 'error');
  const error = requireObject(response.error, 'error');
  assert.equal(error.kind, 'malformed_request');
});

test('CORS reflects only an explicitly allowed origin', async () => {
  const handler = createHandler(['https://wallet.example.test']);
  const allowed = await handler(
    new Request('http://localhost/voice-id/health', {
      headers: { Origin: 'https://wallet.example.test' },
    }),
  );
  assert.equal(allowed.status, 200);
  assert.equal(allowed.headers.get('Access-Control-Allow-Origin'), 'https://wallet.example.test');

  const forbidden = await handler(
    new Request('http://localhost/voice-id/health', {
      headers: { Origin: 'https://attacker.example.test' },
    }),
  );
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.headers.get('Access-Control-Allow-Origin'), null);
});

function createHandler(allowedOrigins: readonly string[] = []) {
  return createVoiceIdFetchHandler(
    createDefaultVoiceIdService({
      verifierMode: 'fake',
      transcriptProviderMode: 'fake',
    }),
    { allowedOrigins },
  );
}

async function startEnrollment(handler: ReturnType<typeof createHandler>) {
  const response = await postJson(handler, '/voice-id/evidence/enrollment/start', {
    userId: 'owner',
  });
  const value = requireObject(response.value, 'enrollment response');
  const prompts = value.promptSequence;
  assert.equal(Array.isArray(prompts) ? prompts.length : 0, 4);
  return { enrollmentId: requireString(value.enrollmentId, 'enrollmentId') };
}

async function postJson(
  handler: ReturnType<typeof createHandler>,
  path: string,
  body: Record<string, unknown>,
) {
  const response = await handler(
    new Request(`http://localhost${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
  return (await response.json()) as Record<string, unknown>;
}

async function postAudio(
  handler: ReturnType<typeof createHandler>,
  path: string,
  fields: Record<string, unknown>,
  durationMs: number,
) {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set(
    'metadata',
    JSON.stringify({
      mimeType: 'audio/webm',
      durationMs,
      sampleRate: { kind: 'unknown' },
      channelCount: { kind: 'unknown' },
      byteLength: bytes.byteLength,
      capturedAt: nowIsoDateTime(),
      recorder: 'test',
    }),
  );
  form.set('fields', JSON.stringify(fields));
  const response = await handler(
    new Request(`http://localhost${path}`, { method: 'POST', body: form }),
  );
  return await readOkValue((await response.json()) as Record<string, unknown>);
}

async function readOkValue(response: Record<string, unknown>) {
  assert.equal(response.kind, 'ok');
  return requireObject(response.value, 'response value');
}

function requireObject(value: unknown, fieldName: string): Record<string, unknown> {
  assert.equal(
    value !== null && typeof value === 'object' && !Array.isArray(value),
    true,
    fieldName,
  );
  return value as Record<string, unknown>;
}

function requireString(value: unknown, fieldName: string): string {
  assert.equal(typeof value, 'string', fieldName);
  return String(value);
}
