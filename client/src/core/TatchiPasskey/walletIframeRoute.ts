import type { WalletIframeRouter } from '../WalletIframe/client/router';
import type { WalletIframeCoordinator } from './walletIframeCoordinator';

export type WalletIframeRouteDeps = Pick<
  WalletIframeCoordinator,
  'shouldUseWalletIframe' | 'requireRouter'
>;

type WalletIframeRouteArgs<TResult> = {
  walletIframe: WalletIframeRouteDeps;
  nearAccountId?: string;
  local: () => Promise<TResult>;
  remote: (router: WalletIframeRouter) => Promise<TResult>;
  onRemoteError?: (error: unknown) => Promise<never> | never;
};

/**
 * Routes an operation to wallet-iframe router when enabled; otherwise runs the local path.
 * Optional `onRemoteError` only wraps iframe/router failures and never local failures.
 */
export async function routeWalletIframeOrLocal<TResult>(
  args: WalletIframeRouteArgs<TResult>,
): Promise<TResult> {
  if (!args.walletIframe.shouldUseWalletIframe()) {
    return await args.local();
  }

  try {
    const router = await args.walletIframe.requireRouter(args.nearAccountId);
    return await args.remote(router);
  } catch (error: unknown) {
    if (args.onRemoteError) {
      return await args.onRemoteError(error);
    }
    throw error;
  }
}
