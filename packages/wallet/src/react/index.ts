/**
 * React Components for Web3Authn Passkey
 *
 * This package provides React components and hooks for integrating Web3Authn Passkey
 * functionality into React applications.
 *
 * **Important:** All React components and hooks must be used inside a SeamsWeb context.
 * Wrap your app with SeamsWebProvider to provide the required context.
 *
 * @example
 * ```tsx
 * import { SeamsWebProvider, QRCodeScanner, AccountMenuButton } from '@seams/wallet/react';
 *
 * function App() {
 *   return (
 *     <SeamsWebProvider configs={passkeyConfigs}>
 *       <div>
 *         <QRCodeScanner onError={(error) => console.error(error)} />
 *         <AccountMenuButton username="alice" onLock={() => console.log('wallet locked')} />
 *       </div>
 *     </SeamsWebProvider>
 *   );
 * }
 * ```
 */

export { SeamsContextProvider, useSeams } from './context';
export { SeamsWebProvider } from './context/SeamsWebProvider';

// === RE-EXPORT CORE TYPES ===
export { SeamsWeb } from '../SeamsWeb';

// === Boundary references (exact subject + target for every wallet operation) ===
export {
  configuredThresholdEcdsaChainTargets,
  nearAccountRefFromAccountId,
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetFromConfig,
  thresholdEcdsaChainTargetFromConfiguredRequest,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  toWalletId,
  walletIdFromWalletProfile,
  walletSessionRefFromSession,
} from '../boundary/walletRefs';
export type {
  EcdsaCommandSubject,
  EvmEip155ChainTarget,
  NearAccountRef,
  NearCommandSubject,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '../boundary/walletRefs';

export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../core/config/defaultConfigs';
export {
  defineSeamsConfig,
  seamsTestnetConfig,
  type DefineSeamsConfigInput,
  type SeamsRequiredConfigInput,
} from '../core/config/defineConfig';
export type {
  EmailOtpAuthPolicy,
  SeamsConfigsReadonly,
  SeamsConfigsInput,
} from '../core/types/seams';
export type {
  AddSignerIntentV1,
  AddSignerSelection,
  RegisterWalletInput,
  RegistrationIntentGrant,
  RegistrationIntentV1,
  RegistrationEvmFamilyEcdsaSignerRequest,
  RegistrationNearEd25519SignerRequest,
  RegistrationSignerRequest,
  RegistrationSignerSetSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletId as RegistrationWalletId,
} from '@shared/utils/registrationIntent';
export type { StoreUserDataInput } from '../core/accountData/near/nearAccountData.types';

// === RE-EXPORT ACTION TYPES ===
// Value export for enum
export { ActionType } from '../core/types/actions';
// Action builders + a ready-made progress logger
export {
  addKey,
  createAccount,
  deleteAccount,
  deleteKey,
  deployContract,
  functionCall,
  stake,
  transfer,
} from '../core/types/actionBuilders';
export { logWalletEvents } from '../core/types/eventLogging';
// Type exports for action shapes
export type {
  ActionArgs,
  FunctionCallAction,
  TransferAction,
  CreateAccountAction,
  DeployContractAction,
  StakeAction,
  AddKeyAction,
  DeleteKeyAction,
  DeleteAccountAction,
} from '../core/types/actions';

// === TYPES ===
export type {
  SeamsContextType,
  SeamsContextProviderProps,
  LoginState,
  LoginResult,
  AddedEvmFamilyEcdsaSignerCapability,
  AddedNearEd25519SignerCapability,
  RegisteredEvmFamilyEcdsaCapability,
  RegisteredNearEd25519Capability,
  RegistrationResult,
  PasskeyRegistrationOptions,
  // Re-exported from SeamsWeb types
  RegistrationHooksOptions,
  LoginHooksOptions,
  SignNEP413HooksOptions,
  ActionHooksOptions,
  // UI State
  AccountInputState,
  UseAccountInputReturn,
} from './types';

////////////////////////////
// === REACT HOOKS ===
////////////////////////////

export { useWallet } from './hooks/useWallet';
export type {
  BoundEvmSigner,
  BoundNearSigner,
  BoundTempoSigner,
  BoundWallet,
  UseWalletResult,
} from './hooks/useWallet';
export { useWalletAuth } from './hooks/useWalletAuth';
export type { UseWalletAuthResult } from './hooks/useWalletAuth';
export { useWalletDevices } from './hooks/useWalletDevices';
export type { UseWalletDevicesResult } from './hooks/useWalletDevices';
export { useNearClient } from './hooks/useNearClient';
export type { NearClient, AccessKeyList } from '../core/rpcClients/near/NearClient';
export { useAccountInput } from './hooks/useAccountInput';
export { useDeviceLinking } from './hooks/useDeviceLinking';
export type { UseDeviceLinkingOptions, UseDeviceLinkingReturn } from './hooks/useDeviceLinking';
export { useQRCamera, QRScanMode } from './hooks/useQRCamera';
export type { UseQRCameraOptions, UseQRCameraReturn } from './hooks/useQRCamera';
export { usePostfixPosition } from './components/SeamsAuthMenu/ui/usePostfixPosition';
export type {
  UsePostfixPositionOptions,
  UsePostfixPositionReturn,
} from './components/SeamsAuthMenu/ui/usePostfixPosition';
export { TxExecutionStatus } from '../core/types/actions';

////////////////////////////
// === REACT COMPONENTS ===
////////////////////////////

export { AccountMenuButton, ProfileSettingsButton } from './components/AccountMenuButton';
export { QRCodeScanner } from './components/QRCodeScanner';
export type { QRCodeScannerProps } from './components/QRCodeScanner';
export { ShowQRCode } from './components/ShowQRCode';
export type { ShowQRCodeProps } from './components/ShowQRCode';
// Sign Up / Sign In menu
export { SeamsAuthMenu, SeamsAuthMenuSkeleton } from './components/SeamsAuthMenu/public';
export type {
  SeamsAuthMenuPasskeyLoginRequest,
  SeamsAuthMenuProps,
  SeamsAuthMenuRegistrationRequest,
  SeamsAuthMenuSocialLoginArgs,
  SeamsAuthMenuSocialLoginHandler,
  SeamsAuthMenuSyncAccountRequest,
} from './components/SeamsAuthMenu/public';
export { AuthMenuMode, AuthMenuModeMap } from './components/SeamsAuthMenu/authMenuTypes';
export type { AuthMenuModeLabel, AuthMenuHeadings } from './components/SeamsAuthMenu/authMenuTypes';
// SSR-safe shell + explicit client entrypoints
export {
  SeamsAuthMenuClient,
  SeamsAuthMenuSkeletonInner,
  preloadSeamsAuthMenu,
} from './components/SeamsAuthMenu';
// Iframe-hosted successor retained alongside the embedded React menu for parity work.
export { HostedSeamsAuthMenu } from './components/HostedSeamsAuthMenu/public';
export type {
  HostedAuthMenuCopy,
  HostedAuthMenuCopyInput,
  HostedAuthMenuExternalAuthBroker,
  HostedAuthMenuExternalAuthEvidence,
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuDemoEmailOtpDelivery,
  HostedAuthMenuDemoEmailOtpHandler,
  HostedAuthMenuExternalProvider,
  HostedAuthMenuMode,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuRegistrationAccountInput,
  HostedAuthMenuSessionId,
  HostedSeamsAuthMenuProps,
} from './components/HostedSeamsAuthMenu/public';
// Small SVG utility icon used in examples
export { default as TouchIcon } from './components/AccountMenuButton/icons/TouchIcon';
export { default as QRCodeIcon } from './components/QRCodeIcon';
export { default as SunIcon } from './components/AccountMenuButton/icons/SunIcon';
export { default as MoonIcon } from './components/AccountMenuButton/icons/MoonIcon';

// Theme components
export { useTheme, Theme } from './components/theme';
export type {
  UseThemeReturn,
  ThemeProps,
  ThemeMode,
  ShapeTokens,
  WalletShapeId,
} from './components/theme';
export {
  LIGHT_TOKENS,
  DARK_TOKENS,
  SHAPE_PRESETS,
  SHAPE_SQUARE,
  SHAPE_ROUNDED,
} from './components/theme';

export type { ActionResult } from '../core/types/seams';
export type { DemoEmailOtpCodeResponse } from '../core/signingEngine/session/emailOtp/publicTypes';
export type {
  GoogleEmailOtpWalletAuthDelivery,
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthFailureCode,
  GoogleEmailOtpWalletAuthFlow,
  GoogleEmailOtpWalletAuthLoginTarget,
  GoogleEmailOtpWalletAuthLoginFlow,
  GoogleEmailOtpWalletAuthPromptCopy,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthRegistrationFlow,
  GoogleEmailOtpWalletAuthRequestedMode,
  GoogleEmailOtpWalletAuthResolvedMode,
  GoogleEmailOtpWalletAuthResult,
  GoogleEmailOtpWalletAuthStartInput,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from '../SeamsWeb';

export {
  AccountSyncEventPhase,
  KeyExportEventPhase,
  LinkDeviceEventPhase,
  RegistrationEventPhase,
  SigningEventPhase,
  UnlockEventPhase,
  WALLET_FLOW_EVENT_MESSAGES,
  WALLET_FLOW_EVENT_STEPS,
  WALLET_FLOW_EVENT_VERSION,
  createAccountSyncFlowEvent,
  createKeyExportFlowEvent,
  createLinkDeviceFlowEvent,
  createRegistrationFlowEvent,
  createSigningFlowEvent,
  createUnlockFlowEvent,
  createWalletFlowEvent,
  isWalletFlowEvent,
} from '../core/types/sdkSentEvents';
export type {
  AccountSyncFlowEvent,
  KeyExportHooksOptions,
  KeyExportFlowEvent,
  LinkDeviceFlowEvent,
  RegistrationFlowEvent,
  SigningFlowEvent,
  UnlockFlowEvent,
  WalletFlowEvent,
  WalletFlowEventBase,
  WalletFlowEventInteraction,
  WalletFlowEventStatus,
} from '../core/types/sdkSentEvents';

// === PROFILE BUTTON TYPES ===
export { PROFILE_MENU_ITEM_IDS } from './components/AccountMenuButton/types';
export type {
  ProfileDimensions,
  ProfileAnimationConfig,
  MenuItem,
  AccountMenuButtonProps,
  DeviceLinkingScannerParams,
  ProfileSettingsButtonProps,
  UserAccountButtonProps,
  ProfileDropdownProps,
  MenuItemProps,
  LockMenuItemProps,
  ProfileRelayerToggleSectionProps,
  ProfileStateRefs,
  ToggleColorProps,
  ProfileSettingsMenuItemId,
  HighlightedProfileMenuItem,
} from './components/AccountMenuButton/types';
