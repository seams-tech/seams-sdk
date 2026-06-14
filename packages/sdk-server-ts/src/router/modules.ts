import type { RelayRouteExtension } from './routeExtensions';

export type RelayRouterModuleKind = 'relay_router_module';

export interface RelayRouterModule {
  kind: RelayRouterModuleKind;
  id: string;
  routeExtensions: readonly RelayRouteExtension[];
}

export interface RelayRouterModuleOptions {
  routeExtensions?: readonly RelayRouteExtension[];
  modules?: readonly RelayRouterModule[];
}

export function createRelayRouterModule(input: {
  id: string;
  routeExtensions: readonly RelayRouteExtension[];
}): RelayRouterModule {
  return Object.freeze({
    kind: 'relay_router_module',
    id: normalizeRelayRouterModuleId(input.id),
    routeExtensions: Object.freeze(validateModuleRouteExtensions(input.id, input.routeExtensions)),
  });
}

export function resolveRelayRouterModuleRouteExtensions(
  input: RelayRouterModuleOptions,
): readonly RelayRouteExtension[] {
  const directExtensions = input.routeExtensions ? [...input.routeExtensions] : [];
  const moduleExtensions: RelayRouteExtension[] = [];
  const seenModuleIds = new Set<string>();

  for (const module of input.modules || []) {
    if (module.kind !== 'relay_router_module') {
      throw new Error('relay router module kind must be relay_router_module');
    }
    const moduleId = normalizeRelayRouterModuleId(module.id);
    if (seenModuleIds.has(moduleId)) {
      throw new Error(`duplicate relay router module id ${moduleId}`);
    }
    seenModuleIds.add(moduleId);
    moduleExtensions.push(...validateModuleRouteExtensions(moduleId, module.routeExtensions));
  }

  return Object.freeze([...directExtensions, ...moduleExtensions]);
}

function normalizeRelayRouterModuleId(id: string): string {
  const normalized = String(id || '').trim();
  if (!normalized) {
    throw new Error('relay router module id is required');
  }
  return normalized;
}

function validateModuleRouteExtensions(
  moduleId: string,
  routeExtensions: readonly RelayRouteExtension[],
): readonly RelayRouteExtension[] {
  if (!Array.isArray(routeExtensions) || routeExtensions.length === 0) {
    throw new Error(`relay router module ${moduleId} must declare at least one route extension`);
  }
  return Object.freeze([...routeExtensions]);
}
