import type { Request, Response, Router as ExpressRouter } from 'express';
import type { RouteDefinition } from '../routeDefinitions';

export type ExpressRouteHandler<TContext> = (input: {
  context: TContext;
  req: Request;
  res: Response;
  route: RouteDefinition;
}) => Promise<void> | void;

function registerPath(
  router: ExpressRouter,
  method: RouteDefinition['method'],
  path: string,
  handler: (req: Request, res: Response) => Promise<void> | void,
): void {
  switch (method) {
    case 'GET':
      router.get(path, handler);
      return;
    case 'POST':
      router.post(path, handler);
      return;
    case 'PATCH':
      router.patch(path, handler);
      return;
    case 'PUT':
      router.put(path, handler);
      return;
    case 'DELETE':
      router.delete(path, handler);
      return;
  }
}

export function registerExpressRoute<TContext>(input: {
  context: TContext;
  handler: ExpressRouteHandler<TContext>;
  route: RouteDefinition;
  router: ExpressRouter;
}): void {
  const paths = Array.from(new Set([input.route.path, ...(input.route.aliases || [])]));
  for (const path of paths) {
    registerPath(input.router, input.route.method, path, async (req, res) => {
      await input.handler({
        context: input.context,
        req,
        res,
        route: input.route,
      });
    });
  }
}
