export { SeamsWeb } from './web/SeamsWeb';

export * from './config';
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from './core/config/defaultConfigs';
export { buildConfigsFromEnv } from './core/config/defaultConfigs';
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

export type {
  SeamsConfigsReadonly,
  SeamsConfigsInput,
  // Registration
  RegistrationResult,
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
} from './core/types/sdkSentEvents';

export { DEFAULT_WAIT_STATUS } from './core/types/rpc';

// === Device Linking Types ===
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
} from './core/types/sdkSentEvents';
export type {
  AccountSyncFlowEvent,
  EmailRecoveryFlowEvent,
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
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode,
} from './core/types/linkDevice';

// === AccountID Types ===
export type { AccountId } from './core/types/accountIds';
export { toAccountId } from './core/types/accountIds';

export type { SignNEP413MessageParams, SignNEP413MessageResult } from './core/types/sdkPublicResults';

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
