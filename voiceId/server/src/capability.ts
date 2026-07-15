import type { VoiceIdService } from './VoiceIdService.ts';
import {
  createVoiceIdFetchHandler,
  type VoiceIdFetchHandler,
  type VoiceIdHttpSecurityConfig,
} from './routes.ts';

export type VoiceIdCapabilityVersion = 'voice_id_e0_evidence_capability_v1';

export type VoiceIdCapabilityRouteId =
  | 'voice_id_health'
  | 'voice_id_evidence_enrollment_start'
  | 'voice_id_evidence_enrollment_recording'
  | 'voice_id_evidence_enrollment_disable'
  | 'voice_id_evidence_verification_start'
  | 'voice_id_evidence_verification_recording';

export type VoiceIdCapabilityRoute = {
  id: VoiceIdCapabilityRouteId;
  method: 'GET' | 'POST';
  path: string;
  body: { kind: 'none' } | { kind: 'json' } | { kind: 'multipart_audio' };
  summary: string;
  evidenceTier: 'E0';
  signingEligible: false;
};

export type VoiceIdCapabilityRouteRegistry = {
  register(route: VoiceIdCapabilityRoute, handler: VoiceIdFetchHandler): void;
};

export type VoiceIdServerCapabilityInput =
  | { kind: 'service'; service: VoiceIdService; httpSecurity: VoiceIdHttpSecurityConfig }
  | { kind: 'fetch_handler'; fetchHandler: VoiceIdFetchHandler };

export type VoiceIdServerCapability = {
  kind: VoiceIdCapabilityVersion;
  routes: readonly VoiceIdCapabilityRoute[];
  fetch: VoiceIdFetchHandler;
  registerRoutes(registry: VoiceIdCapabilityRouteRegistry): void;
};

export const voiceIdCapabilityRoutes = Object.freeze([
  evidenceRoute('voice_id_health', 'GET', '/voice-id/health', { kind: 'none' }, 'VoiceID E0 health metadata'),
  evidenceRoute(
    'voice_id_evidence_enrollment_start',
    'POST',
    '/voice-id/evidence/enrollment/start',
    { kind: 'json' },
    'Start a continuous E0 enrollment recording',
  ),
  evidenceRoute(
    'voice_id_evidence_enrollment_recording',
    'POST',
    '/voice-id/evidence/enrollment/recording',
    { kind: 'multipart_audio' },
    'Submit one continuous E0 enrollment recording',
  ),
  evidenceRoute(
    'voice_id_evidence_enrollment_disable',
    'POST',
    '/voice-id/evidence/enrollment/disable',
    { kind: 'json' },
    'Disable an E0 VoiceID enrollment',
  ),
  evidenceRoute(
    'voice_id_evidence_verification_start',
    'POST',
    '/voice-id/evidence/verification/start',
    { kind: 'json' },
    'Issue a server-owned E0 verification challenge',
  ),
  evidenceRoute(
    'voice_id_evidence_verification_recording',
    'POST',
    '/voice-id/evidence/verification/recording',
    { kind: 'multipart_audio' },
    'Submit one E0 verification recording',
  ),
] satisfies readonly VoiceIdCapabilityRoute[]);

export function createVoiceIdServerCapability(input: VoiceIdServerCapabilityInput): VoiceIdServerCapability {
  const fetchHandler = input.kind === 'service'
    ? createVoiceIdFetchHandler(input.service, input.httpSecurity)
    : input.fetchHandler;
  return {
    kind: 'voice_id_e0_evidence_capability_v1',
    routes: voiceIdCapabilityRoutes,
    fetch: fetchHandler,
    registerRoutes: registerVoiceIdRoutes.bind(null, fetchHandler),
  };
}

function registerVoiceIdRoutes(
  fetchHandler: VoiceIdFetchHandler,
  registry: VoiceIdCapabilityRouteRegistry,
): void {
  for (const route of voiceIdCapabilityRoutes) {
    registry.register(route, fetchHandler);
  }
}

function evidenceRoute(
  id: VoiceIdCapabilityRouteId,
  method: VoiceIdCapabilityRoute['method'],
  path: string,
  body: VoiceIdCapabilityRoute['body'],
  summary: string,
): VoiceIdCapabilityRoute {
  return { id, method, path, body, summary, evidenceTier: 'E0', signingEligible: false };
}
