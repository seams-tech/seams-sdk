import type { RuntimeWalletHostRoute } from './requestRouter';

export type WalletHostRuntimeModule = typeof import('./runtime');

let runtimePromise: Promise<WalletHostRuntimeModule> | null = null;

export function loadWalletHostRuntime(
  _route: RuntimeWalletHostRoute,
): Promise<WalletHostRuntimeModule> {
  runtimePromise ??= import('./runtime');
  return runtimePromise;
}
