import type { RouterApiServiceBag } from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import { createFetchRouter } from '../../transport/fetch/createFetchRouter';
import type { FetchRouterRuntime } from '../../transport/fetch/fetchRouter.types';
import type { CfEnv, CfExecutionContext, FetchHandler } from './cloudflare.types';

export function createCloudflareRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): FetchHandler {
  return async (request: Request, _env?: CfEnv, cfCtx?: CfExecutionContext): Promise<Response> => {
    const runtime: FetchRouterRuntime = cfCtx
      ? {
          kind: 'background',
          waitUntil: (promise) => cfCtx.waitUntil(promise),
        }
      : { kind: 'inline' };
    return await createFetchRouter(service, opts, runtime)(request);
  };
}
