import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { SeamsConfigsReadonly, ThemeMode } from '@/core/types/seams';
import type { WalletAuthDomainDeps } from '@/SeamsWeb/operations/auth/walletAuth';
import { createAuthCapability, type AuthCapabilityDomainMethods } from '@/SeamsWeb/publicApi/auth';
import {
  createDevicesCapability,
  type DevicesCapabilityDomainMethods,
} from '@/SeamsWeb/publicApi/devices';
import { createEvmSignerCapability } from '@/SeamsWeb/publicApi/evm';
import { createNearSignerCapability } from '@/SeamsWeb/publicApi/near';
import { createPreferencesCapability } from '@/SeamsWeb/publicApi/preferences';
import {
  createRecoveryCapability,
  type RecoveryCapabilityDomainMethods,
} from '@/SeamsWeb/publicApi/recovery';
import { createTempoSignerCapability } from '@/SeamsWeb/publicApi/tempo';
import type { PreferencesChangedPayload } from '@/SeamsWeb/walletIframe/shared/messages';
import type { WalletIframeExactSessionState } from '@/SeamsWeb/walletIframe/shared/exactSessionState';
import type {
  AuthCapability,
  DevicesCapability,
  DeviceLinkingWebContext,
  AccountSyncWebContext,
  EcdsaSessionBootstrapSurface,
  NearSigningSurface,
  EvmSignerCapability,
  KeyExportCapability,
  NearSignerCapability,
  PreferencesCapability,
  RegistrationSigningSurface,
  RecoveryCapability,
  RegistrationCapability,
  RpIdSurface,
  TempoSignerCapability,
  TempoSigningSurface,
  UserAccountLookupSurface,
} from '@/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/SeamsWeb/walletIframe/coordinator';
import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import { requireBrowserCapabilityOperation } from '@/SeamsWeb/publicApi/capabilitySelection';
import {
  createCurrentWalletResolver,
  type CurrentWalletResolver,
} from '@/SeamsWeb/publicApi/currentWallet';
import { awaitNearReady } from '@/SeamsWeb/publicApi/awaitNearReady';
import {
  createKeyExportCapability,
  type KeyExportDomainMethods,
} from '@/SeamsWeb/publicApi/keyExport';

type WalletIframeRoutingSurface = Pick<
  WalletIframeCoordinator,
  'shouldUseWalletIframe' | 'requireRouter'
>;

export interface WalletIframeControlCapability {
  initWalletIframe(walletId?: string): Promise<WalletIframeExactSessionState>;
  isWalletIframeReady(): boolean;
  onWalletIframeReady(listener: () => void): () => void;
  onWalletIframeLoginStatusChanged(
    listener: (status: { isLoggedIn: boolean; walletId: string | null }) => void,
  ): () => void;
  onWalletIframePreferencesChanged(
    listener: (payload: PreferencesChangedPayload) => void,
  ): () => void;
}

export type RegistrationCapabilityDomainMethods = {
  resumePendingEcdsaRegistration: RegistrationCapability['resumePendingEcdsaRegistration'];
  getNearProvisioningState: RegistrationCapability['getNearProvisioningState'];
  onNearProvisioningStateChanged: RegistrationCapability['onNearProvisioningStateChanged'];
  addWalletSigner: RegistrationCapability['addWalletSigner'];
  addPasskey: RegistrationCapability['addPasskey'];
  addEmailOtp: RegistrationCapability['addEmailOtp'];
  revokeAuthMethod: RegistrationCapability['revokeAuthMethod'];
  registerWallet: RegistrationCapability['registerWallet'];
  registerPasskey: RegistrationCapability['registerPasskey'];
  requestEmailOtpEnrollmentChallenge: RegistrationCapability['requestEmailOtpEnrollmentChallenge'];
  enrollEmailOtp: RegistrationCapability['enrollEmailOtp'];
};

export type KeyExportCapabilityDomainMethods = KeyExportDomainMethods;

function createWalletIframeRoutingSurface(
  getWalletIframe: () => WalletIframeCoordinator,
): WalletIframeRoutingSurface {
  return {
    shouldUseWalletIframe: () => getWalletIframe().shouldUseWalletIframe(),
    requireRouter: async (walletId?: string) => await getWalletIframe().requireRouter(walletId),
  };
}

export type SeamsWebPublicApi = {
  auth: AuthCapability;
  registration: RegistrationCapability;
  recovery: RecoveryCapability;
  devices: DevicesCapability;
  keys: KeyExportCapability;
  preferences: PreferencesCapability;
  near: NearSignerCapability;
  tempo: TempoSignerCapability;
  evm: EvmSignerCapability;
  walletIframeControls: WalletIframeControlCapability;
};

type PublicApiSigningSurface = RegistrationSigningSurface &
  AccountSyncWebContext['signingEngine'] &
  DeviceLinkingWebContext['signingEngine'] &
  NearSigningSurface &
  UserAccountLookupSurface &
  RpIdSurface &
  TempoSigningSurface &
  EcdsaSessionBootstrapSurface;

export function createPublicApi(deps: {
  signingEngine: PublicApiSigningSurface;
  nearClient: NearClient;
  configs: SeamsConfigsReadonly;
  getTheme: () => ThemeMode;
  userPreferences: UserPreferencesManager;
  getWalletIframe: () => WalletIframeCoordinator;
  getWalletAuthDeps: () => WalletAuthDomainDeps;
  auth: AuthCapabilityDomainMethods;
  registration: RegistrationCapabilityDomainMethods;
  recovery: RecoveryCapabilityDomainMethods;
  devices: DevicesCapabilityDomainMethods;
  keys: KeyExportCapabilityDomainMethods;
}): SeamsWebPublicApi {
  const getAccountSyncContext = (): AccountSyncWebContext => ({
    signingEngine: deps.signingEngine,
    nearClient: deps.nearClient,
    configs: deps.configs,
    theme: deps.getTheme(),
  });
  const getDeviceLinkingContext = (): DeviceLinkingWebContext => ({
    signingEngine: deps.signingEngine,
    nearClient: deps.nearClient,
    configs: deps.configs,
    theme: deps.getTheme(),
  });
  const walletIframeRoutingSurface = createWalletIframeRoutingSurface(deps.getWalletIframe);
  const auth = createAuthCapability({
    getWalletAuthDeps: deps.getWalletAuthDeps,
    domain: deps.auth,
  });
  // Defaults for calls that do not name a wallet come from the authenticated
  // session, never from the `preferences` current-wallet mirror.
  const currentWallet: CurrentWalletResolver = createCurrentWalletResolver({
    getWalletSession: auth.getWalletSession,
  });
  // One EVM-family implementation, reached from `seams.evm` (generic) and still
  // exposed as `seams.tempo` for the deprecated names.
  const evmFamily = createTempoSignerCapability({
    signingEngine: deps.signingEngine,
    nearClient: deps.nearClient,
    configs: deps.configs,
    getTheme: deps.getTheme,
    getWalletIframe: deps.getWalletIframe,
    currentWallet,
  });
  return {
    walletIframeControls: {
      initWalletIframe: async (walletId?: string): Promise<WalletIframeExactSessionState> =>
        await deps.getWalletIframe().init(walletId),
      isWalletIframeReady: (): boolean => deps.getWalletIframe().isReady(),
      onWalletIframeReady: (listener): (() => void) => deps.getWalletIframe().onReady(listener),
      onWalletIframeLoginStatusChanged: (listener): (() => void) =>
        deps.getWalletIframe().onLoginStatusChanged(listener),
      onWalletIframePreferencesChanged: (listener): (() => void) =>
        deps.getWalletIframe().onPreferencesChanged(listener),
    },
    preferences: createPreferencesCapability({
      userPreferences: deps.userPreferences,
      getWalletIframe: deps.getWalletIframe,
    }),
    auth,
    registration: {
      resumePendingEcdsaRegistration: deps.registration.resumePendingEcdsaRegistration,
      getNearProvisioningState: deps.registration.getNearProvisioningState,
      onNearProvisioningStateChanged: deps.registration.onNearProvisioningStateChanged,
      awaitNearReady: async (args) =>
        await awaitNearReady(
          {
            getNearProvisioningState: deps.registration.getNearProvisioningState,
            onNearProvisioningStateChanged: deps.registration.onNearProvisioningStateChanged,
          },
          { ...args, walletId: String(args.walletId) },
        ),
      addWalletSigner: deps.registration.addWalletSigner,
      addPasskey: deps.registration.addPasskey,
      addEmailOtp: deps.registration.addEmailOtp,
      revokeAuthMethod: deps.registration.revokeAuthMethod,
      registerWallet: deps.registration.registerWallet,
      registerWithEmailOtp: deps.registration.registerWallet,
      registerPasskey: deps.registration.registerPasskey,
      requestEmailOtpEnrollmentChallenge: deps.registration.requestEmailOtpEnrollmentChallenge,
      enrollEmailOtp: deps.registration.enrollEmailOtp,
    },
    recovery: createRecoveryCapability({
      getContext: getAccountSyncContext,
      walletIframe: walletIframeRoutingSurface,
      domain: deps.recovery,
    }),
    devices: createDevicesCapability({
      getContext: getDeviceLinkingContext,
      walletIframe: walletIframeRoutingSurface,
      domain: deps.devices,
    }),
    keys: createKeyExportCapability({
      configs: deps.configs,
      currentWallet,
      domain: deps.keys,
    }),
    near: createNearSignerCapability({
      signingEngine: deps.signingEngine,
      nearClient: deps.nearClient,
      configs: deps.configs,
      getTheme: deps.getTheme,
      getWalletIframe: deps.getWalletIframe,
      currentWallet,
    }),
    tempo: evmFamily,
    evm: createEvmSignerCapability({
      signingEngine: deps.signingEngine,
      nearClient: deps.nearClient,
      configs: deps.configs,
      getTheme: deps.getTheme,
      getWalletIframe: deps.getWalletIframe,
      currentWallet,
      evmFamily,
    }),
  };
}
