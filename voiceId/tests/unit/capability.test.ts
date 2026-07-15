import assert from 'node:assert/strict';
import test from 'node:test';
import {
  createDefaultVoiceIdService,
  createVoiceIdServerCapability,
  voiceIdCapabilityRoutes,
} from '../../server/src/index.ts';

test('capability exposes only E0 evidence routes', () => {
  assert.deepEqual(voiceIdCapabilityRoutes.map(readRouteId), [
    'voice_id_health',
    'voice_id_evidence_enrollment_start',
    'voice_id_evidence_enrollment_recording',
    'voice_id_evidence_enrollment_disable',
    'voice_id_evidence_verification_start',
    'voice_id_evidence_verification_recording',
  ]);
  for (const route of voiceIdCapabilityRoutes) {
    assert.equal(route.evidenceTier, 'E0');
    assert.equal(route.signingEligible, false);
    assert.equal(route.path.includes('/authorize'), false);
  }
});

test('capability registers its evidence handlers without a Router signing adapter', () => {
  const capability = createVoiceIdServerCapability({
    kind: 'service',
    service: createDefaultVoiceIdService({
      verifierMode: 'fake',
      transcriptProviderMode: 'fake',
    }),
    httpSecurity: { allowedOrigins: [] },
  });
  const registered: string[] = [];
  capability.registerRoutes({
    register(route) {
      registered.push(route.id);
    },
  });
  assert.equal(capability.kind, 'voice_id_e0_evidence_capability_v1');
  assert.deepEqual(registered, voiceIdCapabilityRoutes.map(readRouteId));
});

function readRouteId(route: (typeof voiceIdCapabilityRoutes)[number]): string {
  return route.id;
}
