import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { UserPreferencesManager } from '@/core/signingEngine/session/userPreferences';
import type { SeamsConfigsReadonly, ThemeName } from '@/core/types/seams';
import type { AuthSessionDomainDeps } from '@/web/SeamsWeb/operations/auth/authSessions';
import { createAuthCapability, type AuthCapabilityDomainMethods } from '@/web/SeamsWeb/publicApi/auth';
import {
  createDevicesCapability,
  type DevicesCapabilityDomainMethods,
} from '@/web/SeamsWeb/publicApi/devices';
import { createEvmSignerCapability } from '@/web/SeamsWeb/publicApi/evm';
import { createNearSignerCapability } from '@/web/SeamsWeb/publicApi/near';
import { createPreferencesCapability } from '@/web/SeamsWeb/publicApi/preferences';
import {
  createRecoveryCapability,
  type RecoveryCapabilityDomainMethods,
} from '@/web/SeamsWeb/publicApi/recovery';
import { createTempoSignerCapability } from '@/web/SeamsWeb/publicApi/tempo';
import type { PreferencesChangedPayload } from '@/web/SeamsWeb/walletIframe/shared/messages';
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
} from '@/web/SeamsWeb/signingSurface/types';
import type { WalletIframeCoordinator } from '@/web/SeamsWeb/walletIframe/coordinator';

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
  exportKeypairWithUI: KeyExportCapability['exportKeypairWithUI'];
  exportThresholdEd25519SeedFromHssReport: KeyExportCapability['exportThresholdEd25519SeedFromHssReport'];
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
  getTheme: () => ThemeName;
  userPreferences: UserPreferencesManager;
  getWalletIframe: () => WalletIframeCoordinator;
  getAuthSessionDeps: () => AuthSessionDomainDeps;
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
      onWalletIframeReady: (listener): (() => void) =>
        deps.getWalletIframe().onReady(listener),
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
      getAuthSessionDeps: deps.getAuthSessionDeps,
      domain: deps.auth,
    }),
    registration: {
      addWalletSigner: deps.registration.addWalletSigner,
      registerWallet: deps.registration.registerWallet,
      registerWithEmailOtp: deps.registration.registerWallet,
      registerPasskey: deps.registration.registerPasskey,
      requestEmailOtpEnrollmentChallenge:
        deps.registration.requestEmailOtpEnrollmentChallenge,
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
      exportKeypairWithUI: deps.keys.exportKeypairWithUI,
      exportThresholdEd25519SeedFromHssReport:
        deps.keys.exportThresholdEd25519SeedFromHssReport,
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
