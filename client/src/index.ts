
export { TatchiPasskey } from './core/TatchiPasskey';
export {
  type NearClient,
  MinimalNearClient,
  encodeSignedTransactionBase64
} from './core/rpcClients/near/NearClient';
export { createWebAuthnLoginOptions, verifyWebAuthnLogin } from './core/rpcClients/near/rpcCalls';

export * from './config';
export { base64UrlEncode, base64UrlDecode } from '@shared/utils/encoders';
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from './core/config/defaultConfigs';
export { buildConfigsFromEnv } from './core/config/defaultConfigs';

export type {
  TatchiConfigs,
  TatchiConfigsInput,
  // Registration
  RegistrationResult,
  // Login
  LoginResult,
  LoginAndCreateSessionResult,
  LoginSession,
  SigningSessionStatus,
  // Actions
  ActionResult,
} from './core/types/tatchi';

export type {
  RegistrationSSEEvent,
  LoginSSEvent,
  // Device Linking
  DeviceLinkingSSEEvent,
  // Hooks Options
  LoginHooksOptions,
  RegistrationHooksOptions,
  ActionHooksOptions,
  SignNEP413HooksOptions,
  AfterCall,
  EventCallback,
} from './core/types/sdkSentEvents';

export { DEFAULT_WAIT_STATUS } from './core/types/rpc';

// === Device Linking Types ===
export {
  DeviceLinkingPhase,
  DeviceLinkingStatus,
} from './core/types/sdkSentEvents';
export type {
  DeviceLinkingQRData,
  DeviceLinkingSession,
  LinkDeviceResult,
  DeviceLinkingError,
  DeviceLinkingErrorCode
} from './core/types/linkDevice';

// === AccountID Types ===
export type { AccountId } from './core/types/accountIds';
export { toAccountId } from './core/types/accountIds';

export type {
  SignNEP413MessageParams,
  SignNEP413MessageResult
} from './core/TatchiPasskey/near';

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
  DeleteAccountAction
} from './core/types/actions';

// === ERROR TYPES ===
export type { PasskeyErrorDetails } from './core/types/errors';

// === CONFIRMATION TYPES ===
export type {
  ConfirmationConfig,
  ConfirmationUIMode,
  ConfirmationBehavior,
} from './core/types/signer-worker';
