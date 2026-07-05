import type { RouterApiModule } from '../../../packages/sdk-server-ts/src/router/modules';
import type {
  RouterApiCloudflareRouteExtensionInput,
  RouterApiRouteExtension,
} from '../../../packages/sdk-server-ts/src/router/routeExtensions';
import type { RouteDefinition } from '../../../packages/sdk-server-ts/src/router/routeDefinitions';
import type {
  VoiceIdCapabilityRoute,
  VoiceIdServerCapability,
} from './capability.ts';

export type VoiceIdRouterApiRouteDefinition = RouteDefinition & {
  surface: 'relay';
  method: VoiceIdCapabilityRoute['method'];
};

export type VoiceIdRouterApiRouteExtension = Extract<
  RouterApiRouteExtension,
  { kind: 'cloudflare_route_extension' }
> & {
  id: 'voice_id';
};

export type VoiceIdRouterApiModule = RouterApiModule & { id: 'voice_id' };

export function createVoiceIdRouterApiModule(
  capability: VoiceIdServerCapability,
): VoiceIdRouterApiModule {
  return Object.freeze({
    kind: 'router_api_module',
    id: 'voice_id',
    routeExtensions: Object.freeze([createVoiceIdRouterApiRouteExtension(capability)]),
  });
}

export function createVoiceIdRouterApiRouteExtension(
  capability: VoiceIdServerCapability,
): VoiceIdRouterApiRouteExtension {
  const routes = Object.freeze(
    capability.routes.map((route) => voiceIdCapabilityRouteToRouterApiRouteDefinition(route)),
  );

  return {
    kind: 'cloudflare_route_extension',
    id: 'voice_id',
    routes,
    handleCloudflareRoute: async ({ request }: RouterApiCloudflareRouteExtensionInput) =>
      await capability.fetch(request),
  };
}

export function voiceIdCapabilityRouteToRouterApiRouteDefinition(
  route: VoiceIdCapabilityRoute,
): VoiceIdRouterApiRouteDefinition {
  const isHealthRoute = route.id === 'voice_id_health';
  const auth: VoiceIdRouterApiRouteDefinition['auth'] = isHealthRoute
    ? {
        plane: 'public',
        rationale: 'VoiceID health metadata is public diagnostics.',
      }
    : {
        plane: 'public',
        proof: 'challenge_exchange',
        rationale: 'VoiceID routes exchange owner-presence evidence through VoiceID-owned validation.',
      };

  return Object.freeze({
    id: route.id,
    surface: 'relay',
    method: route.method,
    path: route.path,
    auth,
    metering: voiceIdRouterApiRouteMetering(),
    summary: route.summary,
  });
}

function voiceIdRouterApiRouteMetering(): VoiceIdRouterApiRouteDefinition['metering'] {
  return { kind: 'none' };
}
