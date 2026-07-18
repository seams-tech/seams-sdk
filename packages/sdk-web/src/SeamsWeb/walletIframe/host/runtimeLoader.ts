import type { RuntimeWalletHostRoute } from './requestRouter';

export type WalletHostRuntimeModule = typeof import('./runtime');
export type WalletHostRegistrationPreparationModule =
  typeof import('./registrationPreparationPreload');
type WalletHostRuntimeKind = RuntimeWalletHostRoute['kind'];

const runtimePromises: Partial<Record<WalletHostRuntimeKind, Promise<WalletHostRuntimeModule>>> =
  {};
let registrationPreparationPromise: Promise<WalletHostRegistrationPreparationModule> | null = null;

export function loadWalletHostRuntime(
  route: RuntimeWalletHostRoute,
): Promise<WalletHostRuntimeModule> {
  runtimePromises[route.kind] ??= loadRuntimeForKind(route.kind);
  return runtimePromises[route.kind]!;
}

export async function preloadWalletHostRegistrationSurface(): Promise<void> {
  runtimePromises.near ??= loadRuntimeForKind('near');
  await Promise.all([runtimePromises.near, preloadRegistrationPreparation()]);
}

export function loadWalletHostRegistrationPreparation(): Promise<WalletHostRegistrationPreparationModule> {
  registrationPreparationPromise ??= import('./registrationPreparationPreload');
  return registrationPreparationPromise;
}

async function preloadRegistrationPreparation(): Promise<void> {
  const registrationPreparation = await loadWalletHostRegistrationPreparation();
  await registrationPreparation.preloadWalletHostRegistrationPreparation();
}

function loadRuntimeForKind(kind: WalletHostRuntimeKind): Promise<WalletHostRuntimeModule> {
  switch (kind) {
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
  return assertNever(kind);
}

function assertNever(value: never): never {
  throw new Error(`Unhandled wallet host runtime route: ${String(value)}`);
}
