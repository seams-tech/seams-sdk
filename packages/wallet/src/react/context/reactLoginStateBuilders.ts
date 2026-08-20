import type { WalletSession } from '@/core/types/seams';
import {
  buildNoCurrentWalletAuthMethod,
  buildSelectedCurrentWalletAuthMethod,
} from '@shared/utils/walletCapabilityBindings';
import type { LoginState } from '../types';
import { isWalletSessionReadyForUi } from './walletSessionReadiness';

export type LinkedDeviceManagementPermission =
  | { readonly kind: 'unauthenticated' }
  | { readonly kind: 'owner' }
  | { readonly kind: 'signing_only' };

export type AccountMenuCapabilities =
  | {
      readonly kind: 'signed_out';
      readonly canExportKeys: false;
      readonly canManageLinkedDevices: false;
    }
  | {
      readonly kind: 'owner';
      readonly canExportKeys: true;
      readonly canManageLinkedDevices: true;
    }
  | {
      readonly kind: 'signing_only';
      readonly canExportKeys: false;
      readonly canManageLinkedDevices: false;
    };

export function linkedDeviceManagementPermissionForLoginState(
  state: LoginState,
): LinkedDeviceManagementPermission {
  if (!state.isLoggedIn) return { kind: 'unauthenticated' };
  if (state.currentAuthMethod.kind !== 'selected') return { kind: 'signing_only' };
  return { kind: 'owner' };
}

export function accountMenuCapabilitiesForLoginState(
  state: LoginState,
): AccountMenuCapabilities {
  const management = linkedDeviceManagementPermissionForLoginState(state);
  switch (management.kind) {
    case 'unauthenticated':
      return { kind: 'signed_out', canExportKeys: false, canManageLinkedDevices: false };
    case 'owner':
      return { kind: 'owner', canExportKeys: true, canManageLinkedDevices: true };
    case 'signing_only':
      return { kind: 'signing_only', canExportKeys: false, canManageLinkedDevices: false };
  }
  return assertNeverAccountMenuPermission(management);
}

function assertNeverAccountMenuPermission(value: never): never {
  throw new Error(`Unsupported account-menu permission: ${String(value)}`);
}

export function buildReactLoggedOutLoginState(): LoginState {
  return {
    isLoggedIn: false,
    walletId: null,
    nearAccountId: null,
    nearPublicKey: null,
    currentAuthMethod: buildNoCurrentWalletAuthMethod(),
    authMethods: [],
    thresholdEcdsaEthereumAddress: null,
    thresholdEcdsaPublicKeyB64u: null,
  };
}

export function buildReactLoggedInLoginStateFromSession(session: WalletSession): LoginState | null {
  if (!isWalletSessionReadyForUi({ session })) return null;
  if (session.appIdentity.kind !== 'resolved') return null;
  const appIdentity = session.appIdentity;
  const authentication = session.authentication;
  if (
    authentication.kind === 'authenticated' &&
    session.reusableWalletSession.kind === 'active' &&
    session.appIdentity.authMethods.length === 0
  ) {
    return {
      isLoggedIn: true,
      walletId: String(appIdentity.walletId),
      nearAccountId: appIdentity.nearAccountId ? String(appIdentity.nearAccountId) : null,
      nearPublicKey: appIdentity.nearOperationalPublicKey,
      currentAuthMethod: buildNoCurrentWalletAuthMethod(),
      authMethods: appIdentity.authMethods,
      thresholdEcdsaEthereumAddress: appIdentity.thresholdEcdsaEthereumAddress,
      thresholdEcdsaPublicKeyB64u: appIdentity.thresholdEcdsaPublicKeyB64u,
    };
  }
  if (authentication.kind !== 'authenticated') return null;
  const matchingAuthMethods = appIdentity.authMethods.filter(
    (binding) => binding.kind === authentication.authMethod,
  );
  if (matchingAuthMethods.length === 0) return null;
  const currentAuthMethod = buildSelectedCurrentWalletAuthMethod({
    binding: matchingAuthMethods[0],
  });
  return {
    isLoggedIn: true,
    walletId: String(appIdentity.walletId),
    nearAccountId: appIdentity.nearAccountId ? String(appIdentity.nearAccountId) : null,
    nearPublicKey: appIdentity.nearOperationalPublicKey,
    currentAuthMethod,
    authMethods: appIdentity.authMethods,
    thresholdEcdsaEthereumAddress: appIdentity.thresholdEcdsaEthereumAddress,
    thresholdEcdsaPublicKeyB64u: appIdentity.thresholdEcdsaPublicKeyB64u,
  };
}
