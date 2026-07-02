import { ensureLeadingSlash } from '@shared/utils/validation';
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

export interface RouterApiRouteSurface {
  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
  signedDelegatePath: string;
}

export function isEmailRecoveryPrepareRoutesEnabled(opts: RouterApiOptions): boolean {
  return Boolean(opts.emailRecovery);
}

export function isRecoverEmailRouteEnabled(opts: RouterApiOptions): boolean {
  return opts.emailRecovery?.kind === 'prepare_and_execute';
}

export function resolveRouterApiRouteDefinitionOptions(
  opts: RouterApiOptions,
): RouterApiRouteDefinitionOptions {
  const mePath = String(opts.sessionRoutes?.state || '').trim() || '/session/state';
  let signedDelegatePath = '';
  if (opts.signedDelegate) {
    signedDelegatePath = ensureLeadingSlash(opts.signedDelegate.route) || '/signed-delegate';
  }
  return {
    enableHealthz: Boolean(opts.healthz),
    enableEmailRecoveryPrepare: isEmailRecoveryPrepareRoutesEnabled(opts),
    enableRecoverEmail: isRecoverEmailRouteEnabled(opts),
    enableSigningSessionSeal: Boolean(opts.signingSessionSeal),
    enableReadyz: Boolean(opts.readyz),
    enableSponsoredEvmCall: Boolean(opts.sponsoredEvmCall),
    signingSessionSealBasePath: opts.signingSessionSeal?.basePath,
    sessionStatePath: mePath,
    signedDelegatePath: signedDelegatePath || undefined,
    sponsoredEvmCallPath: opts.sponsoredEvmCall?.route,
  };
}

export function resolveRouterApiRouteSurface(
  opts: RouterApiOptions,
  input: { transport?: RouterApiRouteExtensionTransport } = {},
): RouterApiRouteSurface {
  const mePath = String(opts.sessionRoutes?.state || '').trim() || '/session/state';
  let signedDelegatePath = '';
  if (opts.signedDelegate) {
    signedDelegatePath = ensureLeadingSlash(opts.signedDelegate.route) || '/signed-delegate';
  }
  const transport = input.transport || 'cloudflare';
  const routeExtensions = resolveRouterApiModuleRouteExtensions(opts);
  const routeDefinitions = [
    ...createRouterApiRouteDefinitions(resolveRouterApiRouteDefinitionOptions(opts)),
    ...getRouterApiRouteExtensionDefinitions(routeExtensions, transport),
  ];
  assertUniqueRouterApiRouteDefinitions(routeDefinitions);
  return {
    mePath,
    routeDefinitions: Object.freeze(routeDefinitions),
    signedDelegatePath,
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
  if (
    typeof surface.mePath !== 'string' ||
    typeof surface.signedDelegatePath !== 'string' ||
    !Array.isArray(surface.routeDefinitions)
  ) {
    return null;
  }
  return {
    mePath: surface.mePath,
    routeDefinitions: surface.routeDefinitions,
    signedDelegatePath: surface.signedDelegatePath,
  };
}
