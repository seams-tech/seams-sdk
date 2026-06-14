import type { Router as ExpressRouter } from 'express';
import { defineRoute, type RouteDefinition } from './routeDefinitions';

export type RelayRouteExtensionTransport = 'cloudflare' | 'express';

export interface RelayCloudflareRouteExtensionInput {
  request: Request;
  route: RouteDefinition;
  pathname: string;
  method: string;
  env?: unknown;
  cfCtx?: unknown;
}

export interface RelayExpressRouteExtensionInput {
  router: ExpressRouter;
  routes: readonly RouteDefinition[];
}

interface RelayRouteExtensionBase {
  id: string;
  routes: readonly RouteDefinition[];
}

export type RelayRouteExtension =
  | (RelayRouteExtensionBase & {
      kind: 'cloudflare_route_extension';
      handleCloudflareRoute(input: RelayCloudflareRouteExtensionInput): Promise<Response> | Response;
      registerExpressRoutes?: never;
    })
  | (RelayRouteExtensionBase & {
      kind: 'express_route_extension';
      registerExpressRoutes(input: RelayExpressRouteExtensionInput): void;
      handleCloudflareRoute?: never;
    })
  | (RelayRouteExtensionBase & {
      kind: 'universal_route_extension';
      handleCloudflareRoute(input: RelayCloudflareRouteExtensionInput): Promise<Response> | Response;
      registerExpressRoutes(input: RelayExpressRouteExtensionInput): void;
    });

export type RelayCloudflareRouteExtension = Extract<
  RelayRouteExtension,
  { kind: 'cloudflare_route_extension' | 'universal_route_extension' }
>;

export type RelayExpressRouteExtension = Extract<
  RelayRouteExtension,
  { kind: 'express_route_extension' | 'universal_route_extension' }
>;

function assertNever(_value: never): never {
  throw new Error('Unhandled relay route extension kind');
}

function normalizeExtensionId(extension: RelayRouteExtension): string {
  const id = String(extension.id || '').trim();
  if (!id) {
    throw new Error('relay route extension id is required');
  }
  return id;
}

function relayRouteExtensionSupportsTransport(
  extension: RelayRouteExtension,
  transport: RelayRouteExtensionTransport,
): boolean {
  switch (extension.kind) {
    case 'cloudflare_route_extension':
      return transport === 'cloudflare';
    case 'express_route_extension':
      return transport === 'express';
    case 'universal_route_extension':
      return true;
    default:
      return assertNever(extension);
  }
}

export function getRelayRouteExtensionRoutes(
  extension: RelayRouteExtension,
  transport: RelayRouteExtensionTransport,
): readonly RouteDefinition[] {
  const extensionId = normalizeExtensionId(extension);
  if (!relayRouteExtensionSupportsTransport(extension, transport)) return [];
  if (!Array.isArray(extension.routes) || extension.routes.length === 0) {
    throw new Error(`relay route extension ${extensionId} must declare at least one route`);
  }

  return Object.freeze(
    extension.routes.map((route) => {
      const normalized = defineRoute(route);
      if (normalized.surface !== 'relay') {
        throw new Error(`relay route extension ${extensionId} route ${normalized.id} must use relay surface`);
      }
      return normalized;
    }),
  );
}

export function getRelayRouteExtensionDefinitions(
  extensions: readonly RelayRouteExtension[] | undefined,
  transport: RelayRouteExtensionTransport,
): readonly RouteDefinition[] {
  if (!extensions || extensions.length === 0) return [];
  return Object.freeze(
    extensions.flatMap((extension) => [...getRelayRouteExtensionRoutes(extension, transport)]),
  );
}

export function assertUniqueRelayRouteDefinitions(definitions: readonly RouteDefinition[]): void {
  const seenIds = new Map<string, string>();
  const seenRoutes = new Map<string, string>();

  for (const definition of definitions) {
    const existingId = seenIds.get(definition.id);
    if (existingId) {
      throw new Error(`duplicate relay route definition id ${definition.id} from ${existingId}`);
    }
    seenIds.set(definition.id, definition.path);

    const paths = [definition.path, ...(definition.aliases || [])];
    for (const path of paths) {
      const key = `${definition.method} ${path}`;
      const existingRouteId = seenRoutes.get(key);
      if (existingRouteId) {
        throw new Error(
          `duplicate relay route definition path ${key} from ${existingRouteId} and ${definition.id}`,
        );
      }
      seenRoutes.set(key, definition.id);
    }
  }
}

export function getRelayRouteExtensionsForTransport(
  extensions: readonly RelayRouteExtension[] | undefined,
  transport: 'cloudflare',
): readonly RelayCloudflareRouteExtension[];
export function getRelayRouteExtensionsForTransport(
  extensions: readonly RelayRouteExtension[] | undefined,
  transport: 'express',
): readonly RelayExpressRouteExtension[];
export function getRelayRouteExtensionsForTransport(
  extensions: readonly RelayRouteExtension[] | undefined,
  transport: RelayRouteExtensionTransport,
): readonly RelayRouteExtension[] {
  if (!extensions || extensions.length === 0) return [];
  return Object.freeze(
    extensions.filter((extension) => relayRouteExtensionSupportsTransport(extension, transport)),
  );
}
