import type { RuntimeWalletHostRoute } from './requestRouter';

export type WalletHostRuntimeModule = typeof import('./runtime');

const runtimePromises: Partial<Record<RuntimeWalletHostRoute['kind'], Promise<WalletHostRuntimeModule>>> =
  {};

export function loadWalletHostRuntime(
  route: RuntimeWalletHostRoute,
): Promise<WalletHostRuntimeModule> {
  runtimePromises[route.kind] ??= loadRuntimeForRoute(route);
  return runtimePromises[route.kind]!;
}

function loadRuntimeForRoute(route: RuntimeWalletHostRoute): Promise<WalletHostRuntimeModule> {
  switch (route.kind) {
    case 'auth':
      return import('./runtime-auth');
    case 'near':
      return import('./runtime-near');
    case 'ecdsa':
      return import('./runtime-ecdsa-tempo');
    case 'email_otp':
      return import('./runtime-email-otp');
    case 'recovery':
      return import('./runtime-recovery');
    case 'export':
      return import('./runtime-export');
    case 'device_link':
      return import('./runtime-device-link');
    case 'preferences':
      return import('./runtime-preferences');
  }
  return assertNever(route);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled wallet host runtime route: ${String(value)}`);
}
