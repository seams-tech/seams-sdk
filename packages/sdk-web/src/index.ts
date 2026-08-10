export { SeamsWeb } from './SeamsWeb';
export {
  buildHostedAuthMenuOpenRequest,
  hostedAuthMenuExternalAuthRequestIdFromBoundary,
  hostedAuthMenuSessionIdFromBoundary,
} from './SeamsWeb/walletIframe/shared/messages';
export type {
  HostedAuthMenuCopy,
  HostedAuthMenuCopyInput,
  HostedAuthMenuExternalAuthEvidence,
  HostedAuthMenuExternalAuthRequest,
  HostedAuthMenuExternalAuthRequestId,
  HostedAuthMenuExternalAuthResolutionInput,
  HostedAuthMenuExternalProvider,
  HostedAuthMenuMode,
  HostedAuthMenuOpenRequest,
  HostedAuthMenuOutcome,
  HostedAuthMenuRegistrationAccountInput,
  HostedAuthMenuSessionId,
} from './SeamsWeb/walletIframe/shared/messages';
export { BrowserCapabilityUnavailableError } from './SeamsWeb/publicApi/capabilitySelection';
export type {
  BrowserCapabilitySelectionResult,
  BrowserCapabilityUnavailableReason,
  BrowserCapabilityUnavailableSelection,
} from './SeamsWeb/publicApi/capabilitySelection';
export type {
  WalletIframeExactSessionIdentity,
  WalletIframeExactSessionState,
} from './SeamsWeb/walletIframe/shared/exactSessionState';
export type { WalletAuthenticationRestoreAuth } from './SeamsWeb/signingSurface/ports';

export * from './config';
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from './core/config/defaultConfigs';
export { buildConfigsFromEnv } from './core/config/defaultConfigs';
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

export type {
  SeamsConfigsReadonly,
  SeamsConfigsInput,
  // Registration
  AddedEvmFamilyEcdsaSignerCapability,
  AddedNearEd25519SignerCapability,
  RegisteredEvmFamilyEcdsaCapability,
  RegisteredNearEd25519Capability,
  RegistrationResult,
  NearProvisioningState,
  // Login
  LoginResult,
  LoginAndCreateSessionResult,
  WalletSession,
  SigningSessionStatus,
  // Actions
  ActionResult,
} from './core/types/seams';

export type {
  // Hooks Options
  LoginHooksOptions,
  KeyExportHooksOptions,
  RegistrationHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
  AfterCall,
  EventCallback,
  RegistrationTimingSpanV1,
  NearProvisioningStateChangedEvent,
} from './core/types/sdkSentEvents';

export { DEFAULT_WAIT_STATUS } from './core/types/rpc';

// === Device Linking Types ===
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
} from './core/types/sdkSentEvents';
export type {
  AccountSyncFlowEvent,
  KeyExportFlowEvent,
  LinkDeviceFlowEvent,
  RegistrationFlowEvent,
  SigningFlowEvent,
  UnlockFlowEvent,
  WalletFlowEvent,
  WalletFlowEventBase,
  WalletFlowEventInteraction,
  WalletFlowEventStatus,
} from './core/types/sdkSentEvents';
export type {
  DeviceLinkingSession,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode,
} from './core/types/linkDevice';
export type {
  LinkedDeviceListRequestV1,
  LinkedDeviceListResultV1,
  LinkedDeviceManagementRequestV1,
  LinkedDeviceRevokeRequestV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  QrLinkedDevicePermissionRequest,
  QrLinkedDeviceSessionPayloadV4,
} from '@shared/device-linking';

// === AccountID Types ===
export type { AccountId } from './core/types/accountIds';
export { toAccountId } from './core/types/accountIds';

export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from './core/types/sdkPublicResults';

// === Action Types ===
export { ActionType } from './core/types/actions';
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
} from './core/types/actions';

// === ERROR TYPES ===
export type { PasskeyErrorDetails } from './core/types/errors';

// === CONFIRMATION TYPES ===
export type {
  ConfirmationConfig,
  ConfirmationUIMode,
  ConfirmationBehavior,
} from './core/types/signer-worker';
