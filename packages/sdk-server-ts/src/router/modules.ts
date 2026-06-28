import type { RouterApiRouteExtension } from './routeExtensions';

export type RouterApiModuleKind = 'router_api_module';

export interface RouterApiModule {
  kind: RouterApiModuleKind;
  id: string;
  routeExtensions: readonly RouterApiRouteExtension[];
}

export interface RouterApiModuleOptions {
  routeExtensions?: readonly RouterApiRouteExtension[];
  modules?: readonly RouterApiModule[];
}

export function createRouterApiModule(input: {
  id: string;
  routeExtensions: readonly RouterApiRouteExtension[];
}): RouterApiModule {
  return Object.freeze({
    kind: 'router_api_module',
    id: normalizeRouterApiModuleId(input.id),
    routeExtensions: Object.freeze(validateModuleRouteExtensions(input.id, input.routeExtensions)),
  });
}

export function resolveRouterApiModuleRouteExtensions(
  input: RouterApiModuleOptions,
): readonly RouterApiRouteExtension[] {
  const directExtensions = input.routeExtensions ? [...input.routeExtensions] : [];
  const moduleExtensions: RouterApiRouteExtension[] = [];
  const seenModuleIds = new Set<string>();

  for (const module of input.modules || []) {
    if (module.kind !== 'router_api_module') {
      throw new Error('Router API module kind must be router_api_module');
    }
    const moduleId = normalizeRouterApiModuleId(module.id);
    if (seenModuleIds.has(moduleId)) {
      throw new Error(`duplicate Router API module id ${moduleId}`);
    }
    seenModuleIds.add(moduleId);
    moduleExtensions.push(...validateModuleRouteExtensions(moduleId, module.routeExtensions));
  }

  return Object.freeze([...directExtensions, ...moduleExtensions]);
}

function normalizeRouterApiModuleId(id: string): string {
  const normalized = String(id || '').trim();
  if (!normalized) {
    throw new Error('Router API module id is required');
  }
  return normalized;
}

function validateModuleRouteExtensions(
  moduleId: string,
  routeExtensions: readonly RouterApiRouteExtension[],
): readonly RouterApiRouteExtension[] {
  if (!Array.isArray(routeExtensions) || routeExtensions.length === 0) {
    throw new Error(`Router API module ${moduleId} must declare at least one route extension`);
  }
  return Object.freeze([...routeExtensions]);
}
