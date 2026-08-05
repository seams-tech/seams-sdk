import type { RouterApiServiceBag } from '../../framework/authServicePort';
import type { RouterApiOptions } from '../../framework/routerApi';
import { createFetchRouter } from '../../transport/fetch/createFetchRouter';
import {
  attachRouterApiRouteSurface,
  getRouterApiRouteSurface,
} from '../../framework/routerApiRouteSurface';
import type { FetchRouterRuntime } from '../../transport/fetch/fetchRouter.types';
import type { CfEnv, CfExecutionContext, FetchHandler } from './cloudflare.types';

export function createCloudflareRouter(
  service: RouterApiServiceBag,
  opts: RouterApiOptions = {},
): FetchHandler {
  const fetchHandler = createFetchRouter(service, opts, { kind: 'inline' });
  const handler: FetchHandler = async (
    request: Request,
    _env?: CfEnv,
    cfCtx?: CfExecutionContext,
  ): Promise<Response> => {
    const runtime: FetchRouterRuntime = cfCtx
      ? {
          kind: 'background',
          waitUntil: (promise) => cfCtx.waitUntil(promise),
        }
      : { kind: 'inline' };
    return await fetchHandler(request, runtime);
  };
  const surface = getRouterApiRouteSurface(fetchHandler);
  if (!surface) {
    throw new Error('[router.cloudflare] Fetch router route surface is unavailable');
  }
  return attachRouterApiRouteSurface(handler, surface);
}
