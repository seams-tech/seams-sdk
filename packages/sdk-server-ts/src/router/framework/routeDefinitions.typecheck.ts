import type { RouteAuthPolicy, RoutePrincipal } from './routeAuthPolicy';
import type { RouteDefinition } from './routeDefinitions';

const relayRoute: RouteDefinition = {
  id: 'relay_route_type_fixture',
  surface: 'relay',
  method: 'GET',
  path: '/relay-route-type-fixture',
  auth: {
    plane: 'public',
    rationale: 'Compile-time route boundary fixture.',
  },
  metering: { kind: 'none' },
  summary: 'Relay route type fixture',
};
void relayRoute;

const consoleSurfaceRoute: RouteDefinition = {
  id: 'console_surface_type_fixture',
  // @ts-expect-error Public SDK routes are relay-only.
  surface: 'console',
  method: 'GET',
  path: '/console-surface-type-fixture',
  auth: {
    plane: 'public',
    rationale: 'Compile-time route boundary fixture.',
  },
  metering: { kind: 'none' },
  summary: 'Rejected console surface type fixture',
};
void consoleSurfaceRoute;

const consoleAuthPolicy: RouteAuthPolicy = {
  // @ts-expect-error Console authorization belongs to the private console package.
  plane: 'console',
};
void consoleAuthPolicy;

// @ts-expect-error Console principals belong to the private console package.
const consolePrincipalKind: RoutePrincipal['kind'] = 'console';
void consolePrincipalKind;
