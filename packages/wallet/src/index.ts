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

export * from './config';
export {
  defineSeamsConfig,
  seamsTestnetConfig,
  type DefineSeamsConfigInput,
  type SeamsRequiredConfigInput,
} from './core/config/defineConfig';

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
} from './boundary/walletRefs';
export type {
  EcdsaCommandSubject,
  EvmEip155ChainTarget,
  NearAccountRef,
  NearCommandSubject,
  TempoChainTarget,
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from './boundary/walletRefs';

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

// === Email OTP wallet auth flow ===
// The flow is a plain `seams.auth.*` client call with nothing React-specific
// about it, so its types belong on the main entry too.
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
} from './SeamsWeb';
// Re-exported through `./SeamsWeb`: the root entry must not name
// `./core/signingEngine/*` directly (stable/experimental export boundary).
export type { DemoEmailOtpCodeResponse } from './SeamsWeb';
export type { EmailOtpAuthPolicy } from './core/types/seams';
export type { NearClient, AccessKeyList } from './core/rpcClients/near/NearClient';

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
  LinkedDeviceEmailOtpActivationStateV1,
  LinkedDeviceTargetEmailOtpActivationV1,
  LinkedDeviceTargetFactorActivationV1,
  LinkedDeviceTargetFactorV1,
  LinkedDeviceTargetPasskeyActivationV1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
  StartDeviceLinkingOptionsDevice2,
} from './core/types/linkDevice';
export type {
  LinkedDeviceListRequestV1,
  LinkedDeviceListResultV1,
  LinkedDeviceManagementRequestV1,
  LinkedDeviceRevokeRequestV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  QrLinkedDevicePermissionRequest,
  QrLinkedDeviceSessionPayloadV5,
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

// === Action builders ===
export {
  addKey,
  createAccount,
  deleteAccount,
  deleteKey,
  deployContract,
  functionCall,
  stake,
  transfer,
} from './core/types/actionBuilders';

// === Event logging ===
export { logWalletEvents } from './core/types/eventLogging';

// === ERROR TYPES ===
export type { PasskeyErrorDetails } from './core/types/errors';

// === CONFIRMATION TYPES ===
export type {
  ConfirmationConfig,
  ConfirmationUIMode,
  ConfirmationBehavior,
} from './core/types/signer-worker';
