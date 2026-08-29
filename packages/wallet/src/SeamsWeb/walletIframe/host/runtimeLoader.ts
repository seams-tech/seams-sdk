import type { RuntimeWalletHostRoute } from './requestRouter';

export type WalletHostRuntimeModule = typeof import('./runtime');
type WalletHostRuntimeKind = RuntimeWalletHostRoute['kind'];

const runtimePromises: Partial<Record<WalletHostRuntimeKind, Promise<WalletHostRuntimeModule>>> =
  {};
let recoveryCodeRuntimePromise: Promise<WalletHostRuntimeModule> | null = null;
let registrationPreparationPromise: Promise<
  typeof import('./registrationPreparationPreload')
> | null = null;
let recoveryCodeSurfacePromise: Promise<void> | null = null;

export function loadWalletHostRuntime(
  route: RuntimeWalletHostRoute,
): Promise<WalletHostRuntimeModule> {
  if (route.type === 'PM_ACKNOWLEDGE_WALLET_RECOVERY_CODE_BACKUP') {
    recoveryCodeRuntimePromise ??= import('./runtime-recovery-codes');
    return recoveryCodeRuntimePromise;
  }
  runtimePromises[route.kind] ??= loadRuntimeForKind(route.kind);
  return runtimePromises[route.kind]!;
}

export async function preloadWalletHostRegistrationSurface(): Promise<void> {
  runtimePromises.near ??= loadRuntimeForKind('near');
  await Promise.all([runtimePromises.near, preloadRegistrationPreparation()]);
}

export async function preloadWalletHostRecoveryCodeSurface(): Promise<void> {
  recoveryCodeRuntimePromise ??= import('./runtime-recovery-codes');
  recoveryCodeSurfacePromise ??= Promise.all([
    recoveryCodeRuntimePromise,
    import('../../../core/signingEngine/uiConfirm/ui/lit-components/RecoveryCodeBackup/host'),
  ]).then(() => undefined);
  await recoveryCodeSurfacePromise;
}

async function preloadRegistrationPreparation(): Promise<void> {
  registrationPreparationPromise ??= import('./registrationPreparationPreload');
  const registrationPreparation = await registrationPreparationPromise;
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
