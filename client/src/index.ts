export { TatchiPasskey } from './core/TatchiPasskey';
export {
  type NearClient,
  MinimalNearClient,
  encodeSignedTransactionBase64,
} from './core/rpcClients/near/NearClient';
export {
  createEvmClient,
  parseRpcHexQuantity as parseEvmRpcHexQuantity,
  type EvmClient,
  type EvmTransactionReceipt,
  type EvmBlockHeader,
  type EvmJsonRpcError,
  type WaitForEvmTransactionReceiptArgs,
} from './core/rpcClients/evm/EvmClient';

export * from './config';
export { base64UrlEncode, base64UrlDecode } from '@shared/utils/encoders';
export { PASSKEY_MANAGER_DEFAULT_CONFIGS } from './core/config/defaultConfigs';
export { buildConfigsFromEnv } from './core/config/defaultConfigs';

export type {
  TatchiConfigsReadonly,
  TatchiConfigsInput,
  // Registration
  RegistrationResult,
  // Login
  LoginResult,
  LoginAndCreateSessionResult,
  WalletSession,
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
export { createIntentId } from './core/idempotency/createIntentId';
export {
  TEMPO_FEE_MANAGER_CONTRACT,
  TEMPO_FEE_MANAGER_ABI,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_SET_USER_TOKEN_SELECTOR,
  TEMPO_USER_TOKENS_SELECTOR,
  encodeTempoSetUserTokenCalldata,
  encodeTempoUserTokensCalldata,
  decodeTempoUserTokenResult,
  buildTempoSetUserTokenCall,
} from './core/signingEngine/chainAdaptors/tempo/feeToken';

// === Device Linking Types ===
export { DeviceLinkingPhase, DeviceLinkingStatus } from './core/types/sdkSentEvents';
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

export type { SignNEP413MessageParams, SignNEP413MessageResult } from './core/TatchiPasskey/near';

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
