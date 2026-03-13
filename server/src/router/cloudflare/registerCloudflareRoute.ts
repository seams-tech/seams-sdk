import type { RouteDefinition } from '../routeDefinitions';

export type CloudflareRouteHandler<TContext extends { method: string; pathname: string }> = (
  input: {
    context: TContext;
    route: RouteDefinition;
  },
) => Promise<Response | null>;

export function registerCloudflareRoute<TContext extends { method: string; pathname: string }>(
  route: RouteDefinition,
  handler: CloudflareRouteHandler<TContext>,
): (context: TContext) => Promise<Response | null> {
  const paths = new Set([route.path, ...(route.aliases || [])]);
  return async (context: TContext): Promise<Response | null> => {
    if (context.method.toUpperCase() !== route.method) return null;
    if (!paths.has(context.pathname)) return null;
    return handler({ context, route });
  };
}
