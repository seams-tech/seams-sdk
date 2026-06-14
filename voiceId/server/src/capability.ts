import type { VoiceIdService } from './VoiceIdService.ts';
import {
  createVoiceIdFetchHandler,
  type VoiceIdFetchHandler,
} from './routes.ts';

export type VoiceIdCapabilityVersion = 'voice_id_server_capability_v1';

export type VoiceIdCapabilityRouteId =
  | 'voice_id_health'
  | 'voice_id_enrollment_start'
  | 'voice_id_enrollment_sample'
  | 'voice_id_enrollment_finalize'
  | 'voice_id_enrollment_disable'
  | 'voice_id_verification_start'
  | 'voice_id_verification_sample'
  | 'voice_id_owner_presence_authorize';

export type VoiceIdCapabilityRouteMethod = 'GET' | 'POST';

export type VoiceIdCapabilityRouteBody =
  | { kind: 'none' }
  | { kind: 'json' }
  | { kind: 'multipart_audio' };

export type VoiceIdCapabilityRoute = {
  id: VoiceIdCapabilityRouteId;
  method: VoiceIdCapabilityRouteMethod;
  path: string;
  body: VoiceIdCapabilityRouteBody;
  summary: string;
};

export type VoiceIdRegisteredRouteHandler = (request: Request) => Promise<Response>;

export type VoiceIdCapabilityRouteRegistry = {
  register(route: VoiceIdCapabilityRoute, handler: VoiceIdRegisteredRouteHandler): void;
};

export type VoiceIdServerCapabilityInput =
  | {
      kind: 'service';
      service: VoiceIdService;
    }
  | {
      kind: 'fetch_handler';
      fetchHandler: VoiceIdFetchHandler;
    };

export type VoiceIdServerCapability = {
  kind: VoiceIdCapabilityVersion;
  routes: readonly VoiceIdCapabilityRoute[];
  fetch: VoiceIdFetchHandler;
  registerRoutes(registry: VoiceIdCapabilityRouteRegistry): void;
};

export const voiceIdCapabilityRoutes = Object.freeze([
  {
    id: 'voice_id_health',
    method: 'GET',
    path: '/voice-id/health',
    body: { kind: 'none' },
    summary: 'VoiceID health and route metadata',
  },
  {
    id: 'voice_id_enrollment_start',
    method: 'POST',
    path: '/voice-id/enrollment/start',
    body: { kind: 'json' },
    summary: 'Start VoiceID enrollment',
  },
  {
    id: 'voice_id_enrollment_sample',
    method: 'POST',
    path: '/voice-id/enrollment/sample',
    body: { kind: 'multipart_audio' },
    summary: 'Submit VoiceID enrollment sample',
  },
  {
    id: 'voice_id_enrollment_finalize',
    method: 'POST',
    path: '/voice-id/enrollment/finalize',
    body: { kind: 'json' },
    summary: 'Finalize VoiceID enrollment',
  },
  {
    id: 'voice_id_enrollment_disable',
    method: 'POST',
    path: '/voice-id/enrollment/disable',
    body: { kind: 'json' },
    summary: 'Disable VoiceID enrollment',
  },
  {
    id: 'voice_id_verification_start',
    method: 'POST',
    path: '/voice-id/verification/start',
    body: { kind: 'json' },
    summary: 'Start VoiceID verification',
  },
  {
    id: 'voice_id_verification_sample',
    method: 'POST',
    path: '/voice-id/verification/sample',
    body: { kind: 'multipart_audio' },
    summary: 'Submit VoiceID verification sample',
  },
  {
    id: 'voice_id_owner_presence_authorize',
    method: 'POST',
    path: '/voice-id/owner-presence/authorize',
    body: { kind: 'json' },
    summary: 'Authorize VoiceID owner-presence evidence for an intent digest',
  },
] satisfies readonly VoiceIdCapabilityRoute[]);

export function createVoiceIdServerCapability(input: VoiceIdServerCapabilityInput): VoiceIdServerCapability {
  const fetchHandler = input.kind === 'service'
    ? createVoiceIdFetchHandler(input.service)
    : input.fetchHandler;

  return {
    kind: 'voice_id_server_capability_v1',
    routes: voiceIdCapabilityRoutes,
    fetch: fetchHandler,
    registerRoutes(registry) {
      for (const route of voiceIdCapabilityRoutes) {
        registry.register(route, async (request) => await fetchHandler(request));
      }
    },
  };
}
