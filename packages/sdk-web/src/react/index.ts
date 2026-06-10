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
 * import { SeamsWebProvider, QRCodeScanner, AccountMenuButton } from '@seams/sdk/react';
 *
 * function App() {
 *   return (
 *     <SeamsWebProvider configs={passkeyConfigs}>
 *       <div>
 *         <QRCodeScanner onDeviceLinked={(result) => console.log(result)} />
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
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from '../core/config/defaultConfigs';
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
  RegistrationSignerSelection,
  ThresholdEcdsaAddSignerSpec,
  ThresholdEd25519AddSignerSpec,
  WalletId as RegistrationWalletId,
} from '@shared/utils/registrationIntent';
export type { StoreUserDataInput } from '../core/accountData/near/types';

// === RE-EXPORT ACTION TYPES ===
// Value export for enum
export { ActionType } from '../core/types/actions';
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
  RegistrationResult,
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

export { useNearClient } from './hooks/useNearClient';
export type { NearClient, AccessKeyList } from '../core/rpcClients/near/NearClient';
export { useAccountInput } from './hooks/useAccountInput';
export { useDeviceLinking } from './hooks/useDeviceLinking';
export type { UseDeviceLinkingOptions, UseDeviceLinkingReturn } from './hooks/useDeviceLinking';
export { useGoogleEmailOtpWalletAuth } from './hooks/useGoogleEmailOtpWalletAuth';
export type {
  UseGoogleEmailOtpWalletAuthOptions,
  UseGoogleEmailOtpWalletAuthResult,
} from './hooks/useGoogleEmailOtpWalletAuth';
export { useQRCamera, QRScanMode } from './hooks/useQRCamera';
export type { UseQRCameraOptions, UseQRCameraReturn } from './hooks/useQRCamera';
export { usePostfixPosition } from './components/PasskeyAuthMenu/ui/usePostfixPosition';
export type {
  UsePostfixPositionOptions,
  UsePostfixPositionReturn,
} from './components/PasskeyAuthMenu/ui/usePostfixPosition';
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
export {
  PasskeyAuthMenu,
  PasskeyAuthMenuSkeleton,
} from './components/PasskeyAuthMenu/passkeyAuthMenuCompat';
export type { PasskeyAuthMenuProps } from './components/PasskeyAuthMenu/passkeyAuthMenuCompat';
export { AuthMenuMode, AuthMenuModeMap } from './components/PasskeyAuthMenu/authMenuTypes';
export type {
  AuthMenuModeLabel,
  AuthMenuHeadings,
} from './components/PasskeyAuthMenu/authMenuTypes';
// SSR-safe shell + explicit client entrypoints
export {
  PasskeyAuthMenuClient,
  PasskeyAuthMenuSkeletonInner,
  preloadPasskeyAuthMenu,
} from './components/PasskeyAuthMenu';
// Small SVG utility icon used in examples
export { default as TouchIcon } from './components/AccountMenuButton/icons/TouchIcon';
export { default as QRCodeIcon } from './components/QRCodeIcon';
export { default as SunIcon } from './components/AccountMenuButton/icons/SunIcon';
export { default as MoonIcon } from './components/AccountMenuButton/icons/MoonIcon';

// Theme components
export { useTheme, Theme } from './components/theme';
export type { UseThemeReturn, ThemeProps, ThemeName } from './components/theme';
export { LIGHT_TOKENS, DARK_TOKENS } from './components/theme';

export type { ActionResult } from '../core/types/seams';
export type {
  GoogleEmailOtpWalletAuthDelivery,
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthFailureCode,
  GoogleEmailOtpWalletAuthFlow,
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
  EmailRecoveryFlowEventPhase,
  KeyExportEventPhase,
  LinkDeviceEventPhase,
  RegistrationEventPhase,
  SigningEventPhase,
  UnlockEventPhase,
  WALLET_FLOW_EVENT_MESSAGES,
  WALLET_FLOW_EVENT_STEPS,
  WALLET_FLOW_EVENT_VERSION,
  createEmailRecoveryFlowEvent,
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
  EmailRecoveryFlowEvent,
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
