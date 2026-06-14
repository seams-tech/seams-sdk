import assert from 'node:assert/strict';
import test from 'node:test';
import type { Router as ExpressRouter } from 'express';
import {
  createDefaultVoiceIdService,
  createVoiceIdRelayRouteExtension,
  createVoiceIdRelayRouterModule,
  createVoiceIdServerCapability,
  voiceIdCapabilityRoutes,
} from '../../server/src/index.ts';

test('VoiceID relay extension maps capability routes to SDK route definitions', () => {
  const extension = createVoiceIdRelayRouteExtension(
    createVoiceIdServerCapability({
      kind: 'service',
      service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
    }),
  );

  assert.equal(extension.kind, 'universal_route_extension');
  assert.equal(extension.id, 'voice_id');
  assert.deepEqual(
    extension.routes.map((route) => route.id),
    voiceIdCapabilityRoutes.map((route) => route.id),
  );
  assert.deepEqual(
    extension.routes.map((route) => `${route.method} ${route.path}`),
    voiceIdCapabilityRoutes.map((route) => `${route.method} ${route.path}`),
  );

  const health = extension.routes.find((route) => route.id === 'voice_id_health');
  assert.ok(health);
  assert.equal(health.auth.plane, 'public');
  assert.equal('proof' in health.auth ? health.auth.proof : undefined, undefined);

  const verificationSample = extension.routes.find(
    (route) => route.id === 'voice_id_verification_sample',
  );
  assert.ok(verificationSample);
  assert.equal(verificationSample.auth.plane, 'public');
  assert.equal(
    'proof' in verificationSample.auth ? verificationSample.auth.proof : undefined,
    'challenge_exchange',
  );
});

test('VoiceID relay module wraps the VoiceID route extension', () => {
  const module = createVoiceIdRelayRouterModule(
    createVoiceIdServerCapability({
      kind: 'service',
      service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
    }),
  );

  assert.equal(module.kind, 'relay_router_module');
  assert.equal(module.id, 'voice_id');
  assert.equal(module.routeExtensions.length, 1);
  assert.equal(module.routeExtensions[0].id, 'voice_id');
  assert.deepEqual(
    module.routeExtensions[0].routes.map((route) => route.id),
    voiceIdCapabilityRoutes.map((route) => route.id),
  );
});

test('VoiceID relay extension dispatches Cloudflare requests through capability fetch', async () => {
  const extension = createVoiceIdRelayRouteExtension(
    createVoiceIdServerCapability({
      kind: 'service',
      service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
    }),
  );
  const route = extension.routes.find((candidate) => candidate.id === 'voice_id_health');
  assert.ok(route);

  const response = await extension.handleCloudflareRoute({
    request: new Request('https://relay.example/voice-id/health'),
    route,
    pathname: '/voice-id/health',
    method: 'GET',
  });

  assert.equal(response.status, 200);
  const body = (await response.json()) as { kind: string; service: string };
  assert.equal(body.kind, 'ok');
  assert.equal(body.service, 'voice-id-api');
});

test('VoiceID relay extension registers Express routes from capability metadata', () => {
  const router = new RecordingExpressRouter();
  const extension = createVoiceIdRelayRouteExtension(
    createVoiceIdServerCapability({
      kind: 'service',
      service: createDefaultVoiceIdService({ verifierMode: 'fake' }),
    }),
  );

  extension.registerExpressRoutes({
    router: router.asExpressRouter(),
    routes: extension.routes,
  });

  assert.deepEqual(
    router.routeKeys(),
    voiceIdCapabilityRoutes.map((route) => `${route.method} ${route.path}`),
  );
});

class RecordingExpressRouter {
  private readonly routes: Array<{ method: 'GET' | 'POST'; path: string }> = [];

  get(path: string): RecordingExpressRouter {
    this.routes.push({ method: 'GET', path });
    return this;
  }

  post(path: string): RecordingExpressRouter {
    this.routes.push({ method: 'POST', path });
    return this;
  }

  asExpressRouter(): ExpressRouter {
    return this as unknown as ExpressRouter;
  }

  routeKeys(): readonly string[] {
    return this.routes.map((route) => `${route.method} ${route.path}`);
  }
}
