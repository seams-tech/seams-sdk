import { createConsoleRouteDefinitions, type RouteDefinition } from '@seams/sdk-server/internal/router/routeDefinitions';

const CONSOLE_ROUTE_SURFACE_SYMBOL = Symbol.for('seams.consoleRouteSurface');

export interface ConsoleRouteSurface {
  routeDefinitions: readonly RouteDefinition[];
}

export function resolveConsoleRouteSurface(): ConsoleRouteSurface {
  return {
    routeDefinitions: Object.freeze(createConsoleRouteDefinitions()),
  };
}

export function attachConsoleRouteSurface<T extends object>(
  target: T,
  surface: ConsoleRouteSurface,
): T {
  Object.defineProperty(target, CONSOLE_ROUTE_SURFACE_SYMBOL, {
    configurable: false,
    enumerable: false,
    value: Object.freeze({
      routeDefinitions: Object.freeze([...surface.routeDefinitions]),
    }),
    writable: false,
  });
  return target;
}

export function getConsoleRouteSurface(target: unknown): ConsoleRouteSurface | null {
  if (!target || (typeof target !== 'object' && typeof target !== 'function')) return null;
  const value = (target as Record<PropertyKey, unknown>)[CONSOLE_ROUTE_SURFACE_SYMBOL];
  if (!value || typeof value !== 'object') return null;
  const surface = value as Partial<ConsoleRouteSurface>;
  if (!Array.isArray(surface.routeDefinitions)) return null;
  return {
    routeDefinitions: surface.routeDefinitions,
  };
}
