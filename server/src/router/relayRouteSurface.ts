import { ensureLeadingSlash } from '@shared/utils/validation';
import type { RelayRouterOptions } from './relay';
import {
  createRelayRouteDefinitions,
  type RelayRouteDefinitionOptions,
  type RouteDefinition,
} from './routeDefinitions';

const RELAY_ROUTE_SURFACE_SYMBOL = Symbol.for('seams.relayRouteSurface');

export interface RelayRouteSurface {
  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
  signedDelegatePath: string;
}

export function resolveRelayRouteDefinitionOptions(
  opts: RelayRouterOptions,
): RelayRouteDefinitionOptions {
  const mePath = String(opts.sessionRoutes?.state || '').trim() || '/session/state';
  let signedDelegatePath = '';
  if (opts.signedDelegate) {
    signedDelegatePath = ensureLeadingSlash(opts.signedDelegate.route) || '/signed-delegate';
  }
  return {
    enableHealthz: Boolean(opts.healthz),
    enableSigningSessionSeal: Boolean(opts.signingSessionSeal && opts.signingSessionSeal.enabled !== false),
    enableReadyz: Boolean(opts.readyz),
    enableSponsoredEvmCall: Boolean(opts.sponsoredEvmCall),
    signingSessionSealBasePath: opts.signingSessionSeal?.basePath,
    sessionStatePath: mePath,
    signedDelegatePath: signedDelegatePath || undefined,
    sponsoredEvmCallPath: opts.sponsoredEvmCall?.route,
  };
}

export function resolveRelayRouteSurface(opts: RelayRouterOptions): RelayRouteSurface {
  const mePath = String(opts.sessionRoutes?.state || '').trim() || '/session/state';
  let signedDelegatePath = '';
  if (opts.signedDelegate) {
    signedDelegatePath = ensureLeadingSlash(opts.signedDelegate.route) || '/signed-delegate';
  }
  const routeDefinitions = Object.freeze(
    createRelayRouteDefinitions(resolveRelayRouteDefinitionOptions(opts)),
  );
  return {
    mePath,
    routeDefinitions,
    signedDelegatePath,
  };
}

export function attachRelayRouteSurface<T extends object>(
  target: T,
  surface: RelayRouteSurface,
): T {
  Object.defineProperty(target, RELAY_ROUTE_SURFACE_SYMBOL, {
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

export function getRelayRouteSurface(target: unknown): RelayRouteSurface | null {
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) return null;
  const value = (target as Record<PropertyKey, unknown>)[RELAY_ROUTE_SURFACE_SYMBOL];
  if (!value || typeof value !== 'object') return null;
  const surface = value as Partial<RelayRouteSurface>;
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
