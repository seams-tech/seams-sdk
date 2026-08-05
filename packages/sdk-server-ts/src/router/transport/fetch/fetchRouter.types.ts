import type { NormalizedRouterLogger } from '../../logger';
import type { RouterApiServiceBag } from '../../authServicePort';
import type { RouterApiOptions } from '../../routerApi';
import type { RouteDefinition } from '../../routeDefinitions';

export type FetchRouterRuntime =
  | {
      readonly kind: 'inline';
    }
  | {
      readonly kind: 'background';
      readonly waitUntil: (promise: Promise<unknown>) => void;
    };

export interface FetchRouterApiContext {
  request: Request;
  url: URL;
  pathname: string;
  method: string;
  runtime: FetchRouterRuntime;

  service: RouterApiServiceBag;
  opts: RouterApiOptions;
  logger: NormalizedRouterLogger;

  mePath: string;
  routeDefinitions: readonly RouteDefinition[];
}

export type FetchRouterHandler = (request: Request) => Promise<Response>;
