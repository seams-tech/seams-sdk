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
  getNearProvisioningState: RegistrationCapability['getNearProvisioningState'];
  onNearProvisioningStateChanged: RegistrationCapability['onNearProvisioningStateChanged'];
  addWalletSigner: RegistrationCapability['addWalletSigner'];
  addPasskey: RegistrationCapability['addPasskey'];
  registerWallet: RegistrationCapability['registerWallet'];
  registerPasskey: RegistrationCapability['registerPasskey'];
  requestEmailOtpEnrollmentChallenge: RegistrationCapability['requestEmailOtpEnrollmentChallenge'];
  enrollEmailOtp: RegistrationCapability['enrollEmailOtp'];
};

export type KeyExportCapabilityDomainMethods = {
  resolveExactKeyExportLane: KeyExportCapability['resolveExactKeyExportLane'];
  exportKeypairWithUI: KeyExportCapability['exportKeypairWithUI'];
};

type KeyExportCapabilitySelectionInput =
  | Parameters<KeyExportCapability['resolveExactKeyExportLane']>[0]
  | Parameters<KeyExportCapability['exportKeypairWithUI']>[0];

function requireKeyExportCapability(
  configs: SeamsConfigsReadonly,
  input: KeyExportCapabilitySelectionInput,
): void {
  switch (input.kind) {
    case 'ed25519':
      requireBrowserCapabilityOperation(configs, {
        capabilityKind: CAPABILITY_KINDS.nearEd25519MpcSigning,
        operationKind: NEAR_ED25519_MPC_OPERATION_KINDS.exportKey,
      });
      return;
    case 'ecdsa':
      requireBrowserCapabilityOperation(configs, {
        capabilityKind: CAPABILITY_KINDS.evmEcdsaMpcSigning,
        operationKind: EVM_ECDSA_MPC_OPERATION_KINDS.exportKey,
        chainTarget: input.chainTarget,
      });
      return;
  }
}

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
    auth: createAuthCapability({
      getWalletAuthDeps: deps.getWalletAuthDeps,
      domain: deps.auth,
    }),
    registration: {
      getNearProvisioningState: deps.registration.getNearProvisioningState,
      onNearProvisioningStateChanged: deps.registration.onNearProvisioningStateChanged,
      addWalletSigner: deps.registration.addWalletSigner,
      addPasskey: deps.registration.addPasskey,
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
    keys: {
      resolveExactKeyExportLane: async (input) => {
        requireKeyExportCapability(deps.configs, input);
        return await deps.keys.resolveExactKeyExportLane(input);
      },
      exportKeypairWithUI: async (input) => {
        requireKeyExportCapability(deps.configs, input);
        await deps.keys.exportKeypairWithUI(input);
      },
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
