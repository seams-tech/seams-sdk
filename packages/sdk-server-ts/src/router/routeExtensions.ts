import { defineRoute, type RouteDefinition } from './routeDefinitions';

export type RouterApiRouteExtensionTransport = 'cloudflare';

export interface RouterApiCloudflareRouteExtensionInput {
  request: Request;
  route: RouteDefinition;
  pathname: string;
  method: string;
  env?: unknown;
  cfCtx?: unknown;
}

interface RouterApiRouteExtensionBase {
  id: string;
  routes: readonly RouteDefinition[];
}

export type RouterApiRouteExtension = RouterApiRouteExtensionBase & {
  kind: 'cloudflare_route_extension';
  handleCloudflareRoute(input: RouterApiCloudflareRouteExtensionInput): Promise<Response> | Response;
};

export type RouterApiCloudflareRouteExtension = RouterApiRouteExtension;

function normalizeExtensionId(extension: RouterApiRouteExtension): string {
  const id = String(extension.id || '').trim();
  if (!id) {
    throw new Error('Router API route extension id is required');
  }
  return id;
}

function relayRouteExtensionSupportsTransport(
  extension: RouterApiRouteExtension,
  transport: RouterApiRouteExtensionTransport,
): boolean {
  switch (extension.kind) {
    case 'cloudflare_route_extension':
      return transport === 'cloudflare';
  }
}

export function getRouterApiRouteExtensionRoutes(
  extension: RouterApiRouteExtension,
  transport: RouterApiRouteExtensionTransport,
): readonly RouteDefinition[] {
  const extensionId = normalizeExtensionId(extension);
  if (!relayRouteExtensionSupportsTransport(extension, transport)) return [];
  if (!Array.isArray(extension.routes) || extension.routes.length === 0) {
    throw new Error(`Router API route extension ${extensionId} must declare at least one route`);
  }

  return Object.freeze(
    extension.routes.map((route) => {
      const normalized = defineRoute(route);
      if (normalized.surface !== 'relay') {
        throw new Error(
          `Router API route extension ${extensionId} route ${normalized.id} must use Router API surface`,
        );
      }
      return normalized;
    }),
  );
}

export function getRouterApiRouteExtensionDefinitions(
  extensions: readonly RouterApiRouteExtension[] | undefined,
  transport: RouterApiRouteExtensionTransport,
): readonly RouteDefinition[] {
  if (!extensions || extensions.length === 0) return [];
  return Object.freeze(
    extensions.flatMap((extension) => [...getRouterApiRouteExtensionRoutes(extension, transport)]),
  );
}

export function assertUniqueRouterApiRouteDefinitions(definitions: readonly RouteDefinition[]): void {
  const seenIds = new Map<string, string>();
  const seenRoutes = new Map<string, string>();

  for (const definition of definitions) {
    const existingId = seenIds.get(definition.id);
    if (existingId) {
      throw new Error(`duplicate Router API route definition id ${definition.id} from ${existingId}`);
    }
    seenIds.set(definition.id, definition.path);

    const paths = [definition.path, ...(definition.aliases || [])];
    for (const path of paths) {
      const key = `${definition.method} ${path}`;
      const existingRouteId = seenRoutes.get(key);
      if (existingRouteId) {
        throw new Error(
          `duplicate Router API route definition path ${key} from ${existingRouteId} and ${definition.id}`,
        );
      }
      seenRoutes.set(key, definition.id);
    }
  }
}

export function getRouterApiRouteExtensionsForTransport(
  extensions: readonly RouterApiRouteExtension[] | undefined,
  transport: 'cloudflare',
): readonly RouterApiCloudflareRouteExtension[];
export function getRouterApiRouteExtensionsForTransport(
  extensions: readonly RouterApiRouteExtension[] | undefined,
  transport: RouterApiRouteExtensionTransport,
): readonly RouterApiRouteExtension[] {
  if (!extensions || extensions.length === 0) return [];
  return Object.freeze(
    extensions.filter((extension) => relayRouteExtensionSupportsTransport(extension, transport)),
  );
}
