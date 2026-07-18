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
import type {
  AuthCapability,
  DevicesCapability,
  DeviceLinkingWebContext,
  EmailRecoveryWebContext,
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

type WalletIframeRoutingSurface = Pick<
  WalletIframeCoordinator,
  'shouldUseWalletIframe' | 'requireRouter'
>;

export interface WalletIframeControlCapability {
  initWalletIframe(walletId?: string): Promise<void>;
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
  addWalletSigner: RegistrationCapability['addWalletSigner'];
  registerWallet: RegistrationCapability['registerWallet'];
  registerPasskey: RegistrationCapability['registerPasskey'];
  requestEmailOtpEnrollmentChallenge: RegistrationCapability['requestEmailOtpEnrollmentChallenge'];
  enrollEmailOtp: RegistrationCapability['enrollEmailOtp'];
  enrollAndLoginWithEmailOtpEcdsaCapability: RegistrationCapability['enrollAndLoginWithEmailOtpEcdsaCapability'];
};

export type KeyExportCapabilityDomainMethods = {
  resolveExactKeyExportLane: KeyExportCapability['resolveExactKeyExportLane'];
  exportKeypairWithUI: KeyExportCapability['exportKeypairWithUI'];
};

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
  EmailRecoveryWebContext['signingEngine'] &
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
  const getEmailRecoveryContext = (): EmailRecoveryWebContext => ({
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
  return {
    walletIframeControls: {
      initWalletIframe: async (walletId?: string): Promise<void> => {
        await deps.getWalletIframe().init(walletId);
      },
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
    auth: createAuthCapability({
      getWalletAuthDeps: deps.getWalletAuthDeps,
      domain: deps.auth,
    }),
    registration: {
      addWalletSigner: deps.registration.addWalletSigner,
      registerWallet: deps.registration.registerWallet,
      registerWithEmailOtp: deps.registration.registerWallet,
      registerPasskey: deps.registration.registerPasskey,
      requestEmailOtpEnrollmentChallenge: deps.registration.requestEmailOtpEnrollmentChallenge,
      enrollEmailOtp: deps.registration.enrollEmailOtp,
      enrollAndLoginWithEmailOtpEcdsaCapability:
        deps.registration.enrollAndLoginWithEmailOtpEcdsaCapability,
    },
    recovery: createRecoveryCapability({
      getContext: getEmailRecoveryContext,
      walletIframe: walletIframeRoutingSurface,
      domain: deps.recovery,
    }),
    devices: createDevicesCapability({
      getContext: getDeviceLinkingContext,
      walletIframe: walletIframeRoutingSurface,
      domain: deps.devices,
    }),
    keys: {
      resolveExactKeyExportLane: deps.keys.resolveExactKeyExportLane,
      exportKeypairWithUI: deps.keys.exportKeypairWithUI,
    },
    near: createNearSignerCapability({
      signingEngine: deps.signingEngine,
      nearClient: deps.nearClient,
      configs: deps.configs,
      getTheme: deps.getTheme,
      getWalletIframe: deps.getWalletIframe,
    }),
    tempo: createTempoSignerCapability({
      signingEngine: deps.signingEngine,
      nearClient: deps.nearClient,
      configs: deps.configs,
      getTheme: deps.getTheme,
      getWalletIframe: deps.getWalletIframe,
    }),
    evm: createEvmSignerCapability({
      signingEngine: deps.signingEngine,
      nearClient: deps.nearClient,
      configs: deps.configs,
      getTheme: deps.getTheme,
      getWalletIframe: deps.getWalletIframe,
    }),
  };
}
