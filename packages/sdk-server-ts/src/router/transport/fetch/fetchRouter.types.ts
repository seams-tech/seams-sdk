import type { NormalizedRouterLogger } from '../../framework/logger';
import type { RouterApiServiceBag } from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import type { RouteDefinition } from '../../framework/routeDefinitions';

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
