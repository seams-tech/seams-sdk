import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createDefaultVoiceIdService,
  createVoiceIdServerCapability,
  voiceIdCapabilityRoutes,
  type VoiceIdCapabilityRoute,
  type VoiceIdRegisteredRouteHandler,
} from '../../server/src/index.ts';
import { nowIsoDateTime } from '../../shared/src/index.ts';

test('VoiceID server capability exposes typed route metadata', () => {
  assert.deepEqual(
    voiceIdCapabilityRoutes.map((route) => route.id),
    [
      'voice_id_health',
      'voice_id_enrollment_start',
      'voice_id_enrollment_sample',
      'voice_id_enrollment_finalize',
      'voice_id_enrollment_disable',
      'voice_id_verification_start',
      'voice_id_verification_sample',
      'voice_id_owner_presence_authorize',
    ],
  );
  assert.equal(voiceIdCapabilityRoutes.every((route) => route.path.startsWith('/voice-id/')), true);
  assert.equal(
    voiceIdCapabilityRoutes.some((route) => route.body.kind === 'multipart_audio'),
    true,
  );
});

test('VoiceID capability registers routes through a host boundary', async () => {
  const host = new FakeIntegratedVoiceIdHost();
  const capability = createVoiceIdServerCapability({
    kind: 'service',
    service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
  });

  assert.equal(capability.kind, 'voice_id_server_capability_v1');
  capability.registerRoutes(host);

  assert.deepEqual(host.routeIds(), voiceIdCapabilityRoutes.map((route) => route.id));

  const health = await host.fetch(new Request('https://host.example/voice-id/health'));
  assert.equal(health.status, 200);
  const healthBody = (await health.json()) as { service: string };
  assert.equal(healthBody.service, 'voice-id-api');

  const enrollment = await readOkResponse<{ record: { enrollmentId: string } }>(
    await postJson(host, '/voice-id/enrollment/start', {
      userId: 'owner',
      phrase: 'Walking on clouds',
    }),
  );

  for (let attemptNumber = 1; attemptNumber <= 3; attemptNumber += 1) {
    await readOkResponse<{ quality: { kind: string } }>(
      await postSample(host, '/voice-id/enrollment/sample', {
        userId: 'owner',
        enrollmentId: enrollment.record.enrollmentId,
        expectedPhrase: 'Walking on clouds',
        spokenPhrase: 'Walking on clouds',
        attemptNumber,
      }),
    );
  }

  const finalized = await readOkResponse<{ state: string }>(
    await postJson(host, '/voice-id/enrollment/finalize', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
    }),
  );
  assert.equal(finalized.state, 'enrolled');

  const verification = await readOkResponse<{ record: { verificationId: string } }>(
    await postJson(host, '/voice-id/verification/start', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      phrase: 'Walking on clouds',
      ...testIntentBindingBody(),
    }),
  );

  const result = await readOkResponse<{ kind: string }>(
    await postSample(host, '/voice-id/verification/sample', {
      userId: 'owner',
      enrollmentId: enrollment.record.enrollmentId,
      verificationId: verification.record.verificationId,
      expectedPhrase: 'Walking on clouds',
      spokenPhrase: 'Walking on clouds',
      attemptNumber: 1,
    }),
  );
  assert.equal(result.kind, 'accepted');
});

class FakeIntegratedVoiceIdHost {
  private readonly routes: Array<{
    route: VoiceIdCapabilityRoute;
    handler: VoiceIdRegisteredRouteHandler;
  }> = [];

  register(route: VoiceIdCapabilityRoute, handler: VoiceIdRegisteredRouteHandler): void {
    this.routes.push({ route, handler });
  }

  routeIds(): readonly string[] {
    return this.routes.map(({ route }) => route.id);
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const route = this.routes.find(
      (candidate) => candidate.route.method === request.method && candidate.route.path === url.pathname,
    );
    if (route === undefined) {
      return new Response(JSON.stringify({ kind: 'error', error: { kind: 'not_found' } }), { status: 404 });
    }

    return await route.handler(request);
  }
}

function testIntentBindingBody(): Record<string, unknown> {
  return {
    intentDigest: 'A'.repeat(43),
    intentExpiresAt: '2099-01-01T00:00:00.000Z',
    intentNonce: 'nonce_123456',
  };
}

async function postJson(
  host: FakeIntegratedVoiceIdHost,
  path: string,
  body: Record<string, unknown>,
): Promise<Response> {
  return await host.fetch(
    new Request(`https://host.example${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
  );
}

async function postSample(
  host: FakeIntegratedVoiceIdHost,
  path: string,
  fields: Record<string, unknown>,
): Promise<Response> {
  const bytes = new Uint8Array([1, 2, 3, 4]);
  const form = new FormData();
  form.set('audio', new Blob([bytes], { type: 'audio/webm' }));
  form.set('metadata', JSON.stringify(buildTestMetadata(bytes.byteLength)));
  form.set('fields', JSON.stringify(fields));

  return await host.fetch(
    new Request(`https://host.example${path}`, {
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

function buildTestMetadata(byteLength: number) {
  return {
    mimeType: 'audio/webm',
    durationMs: 1800,
    sampleRate: { kind: 'unknown' },
    channelCount: { kind: 'unknown' },
    byteLength,
    capturedAt: nowIsoDateTime(new Date('2026-06-13T00:00:00.000Z')),
    recorder: 'capability-test',
    fixtureBehavior: { kind: 'speaker_label', speakerLabel: 'owner' },
  };
}
