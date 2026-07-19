export interface CloudflareServiceBindingFetcher {
  fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response>;
}

export interface RouterAbServiceBindingEnv {
  readonly MPC_ROUTER: CloudflareServiceBindingFetcher;
  readonly DERIVER_A: CloudflareServiceBindingFetcher;
  readonly DERIVER_B: CloudflareServiceBindingFetcher;
  readonly SIGNING_WORKER: CloudflareServiceBindingFetcher;
}

export const ROUTER_AB_MPC_ROUTER_ORIGIN = 'https://mpc-router.router-ab.internal';
export const ROUTER_AB_DERIVER_A_ORIGIN = 'https://deriver-a.router-ab.internal';
export const ROUTER_AB_DERIVER_B_ORIGIN = 'https://deriver-b.router-ab.internal';
export const ROUTER_AB_SIGNING_WORKER_ORIGIN = 'https://signing-worker.router-ab.internal';

type RouterAbServiceBindingOrigin =
  | typeof ROUTER_AB_MPC_ROUTER_ORIGIN
  | typeof ROUTER_AB_DERIVER_A_ORIGIN
  | typeof ROUTER_AB_DERIVER_B_ORIGIN
  | typeof ROUTER_AB_SIGNING_WORKER_ORIGIN;

class RouterAbServiceBindingDispatcher {
  constructor(private readonly env: RouterAbServiceBindingEnv) {}

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    const binding = this.bindingForOrigin(new URL(request.url).origin);
    return await binding.fetch(request);
  }

  private bindingForOrigin(origin: string): CloudflareServiceBindingFetcher {
    switch (parseRouterAbServiceBindingOrigin(origin)) {
      case ROUTER_AB_MPC_ROUTER_ORIGIN:
        return this.env.MPC_ROUTER;
      case ROUTER_AB_DERIVER_A_ORIGIN:
        return this.env.DERIVER_A;
      case ROUTER_AB_DERIVER_B_ORIGIN:
        return this.env.DERIVER_B;
      case ROUTER_AB_SIGNING_WORKER_ORIGIN:
        return this.env.SIGNING_WORKER;
    }
  }
}

function parseRouterAbServiceBindingOrigin(origin: string): RouterAbServiceBindingOrigin {
  switch (origin) {
    case ROUTER_AB_MPC_ROUTER_ORIGIN:
    case ROUTER_AB_DERIVER_A_ORIGIN:
    case ROUTER_AB_DERIVER_B_ORIGIN:
    case ROUTER_AB_SIGNING_WORKER_ORIGIN:
      return origin;
    default:
      throw new Error(`Unsupported Router A/B service-binding origin: ${origin}`);
  }
}

export function createRouterAbServiceBindingFetch(
  env: RouterAbServiceBindingEnv,
): typeof globalThis.fetch {
  const dispatcher = new RouterAbServiceBindingDispatcher(env);
  return dispatcher.fetch.bind(dispatcher);
}
