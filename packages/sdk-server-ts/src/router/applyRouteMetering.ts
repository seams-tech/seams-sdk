import type { RouteExecutionContext, RouteServices, RouteResponse } from './routeExecutionContext';
import type { RouteDefinition } from './routeDefinitions';

export interface RouteMeteringHandlers<TServices extends RouteServices = RouteServices> {
  event?: (input: {
    action: string;
    context: RouteExecutionContext<TServices>;
    response: RouteResponse;
    route: RouteDefinition;
  }) => Promise<void> | void;
  gas?: (input: {
    context: RouteExecutionContext<TServices>;
    ledger: 'evm' | 'near_delegate';
    response: RouteResponse;
    route: RouteDefinition;
  }) => Promise<void> | void;
}

export async function applyRouteMetering<TServices extends RouteServices = RouteServices>(input: {
  context: RouteExecutionContext<TServices>;
  handlers?: RouteMeteringHandlers<TServices>;
  response: RouteResponse;
  route: RouteDefinition;
}): Promise<void> {
  switch (input.route.metering.kind) {
    case 'none':
      return;
    case 'event':
      await input.handlers?.event?.({
        action: input.route.metering.action,
        context: input.context,
        response: input.response,
        route: input.route,
      });
      return;
    case 'gas':
      await input.handlers?.gas?.({
        context: input.context,
        ledger: input.route.metering.ledger,
        response: input.response,
        route: input.route,
      });
      return;
  }
}
