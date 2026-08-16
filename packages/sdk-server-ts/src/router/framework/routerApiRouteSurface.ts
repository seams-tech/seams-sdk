import type { RouterApiOptions } from './routerApi';
import {
  createRouterApiRouteDefinitions,
  type RouterApiRouteDefinitionOptions,
  type RouteDefinition,
} from './routeDefinitions';
import {
  assertUniqueRouterApiRouteDefinitions,
  getRouterApiRouteExtensionDefinitions,
  type RouterApiRouteExtensionTransport,
} from './routeExtensions';
import { resolveRouterApiModuleRouteExtensions } from './modules';

const ROUTER_API_ROUTE_SURFACE_SYMBOL = Symbol.for('seams.routerApiRouteSurface');
const SIGNED_DELEGATE_ROUTE_ID = 'signed_delegate';

export interface RouterApiRouteSurface {
  routeDefinitions: readonly RouteDefinition[];
  signedDelegatePath: string;
}

export function resolveRouterApiRouteDefinitionOptions(
  opts: RouterApiOptions,
): RouterApiRouteDefinitionOptions {
  return {
    enableHealthz: Boolean(opts.healthz),
    enableSigningSessionSeal: Boolean(opts.signingSessionSeal),
    enableReadyz: Boolean(opts.readyz),
    signingSessionSealBasePath: opts.signingSessionSeal?.basePath,
  };
}

function findSignedDelegatePath(routeDefinitions: readonly RouteDefinition[]): string {
  return (
    routeDefinitions.find((route) => route.id === SIGNED_DELEGATE_ROUTE_ID)?.path || ''
  );
}

export function resolveRouterApiRouteSurface(
  opts: RouterApiOptions,
  input: { transport?: RouterApiRouteExtensionTransport } = {},
): RouterApiRouteSurface {
  const transport = input.transport || 'fetch';
  const routeExtensions = resolveRouterApiModuleRouteExtensions(opts);
  const routeDefinitions = [
    ...createRouterApiRouteDefinitions(resolveRouterApiRouteDefinitionOptions(opts)),
    ...getRouterApiRouteExtensionDefinitions(routeExtensions, transport),
  ];
  assertUniqueRouterApiRouteDefinitions(routeDefinitions);
  return {
    routeDefinitions: Object.freeze(routeDefinitions),
    signedDelegatePath: findSignedDelegatePath(routeDefinitions),
  };
}

export function attachRouterApiRouteSurface<T extends object>(
  target: T,
  surface: RouterApiRouteSurface,
): T {
  Object.defineProperty(target, ROUTER_API_ROUTE_SURFACE_SYMBOL, {
    configurable: false,
    enumerable: false,
    value: Object.freeze({
      ...surface,
      routeDefinitions: Object.freeze([...surface.routeDefinitions]),
    }),
    writable: false,
  });
  return target;
}

export function getRouterApiRouteSurface(target: unknown): RouterApiRouteSurface | null {
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) return null;
  const value = (target as Record<PropertyKey, unknown>)[ROUTER_API_ROUTE_SURFACE_SYMBOL];
  if (!value || typeof value !== 'object') return null;
  const surface = value as Partial<RouterApiRouteSurface>;
  if (typeof surface.signedDelegatePath !== 'string' || !Array.isArray(surface.routeDefinitions)) {
    return null;
  }
  return {
    routeDefinitions: surface.routeDefinitions,
    signedDelegatePath: surface.signedDelegatePath,
  };
}
