import { TransactionInputWasm } from '@/core/types';
import { ConfirmationConfig } from '@/core/types';
import { TransactionContext } from '@/core/types/rpc';
import { RpcCallPayload } from '@/core/types/signer-worker';
import {
  WebAuthnAuthenticationCredential,
  WebAuthnRegistrationCredential,
} from '@/core/types/webauthn';
import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';
import { isObject, isString } from '@shared/utils/validation';
import type { SigningSessionRetention, WalletAuthMethod } from '@/core/types/tatchi';
import type {
  WalletAuthCurve,
  WalletAuthIntent,
} from '@/core/signingEngine/auth/walletAuthModeResolver';

// === SECURE CONFIRM TYPES (V2) ===

export enum UserConfirmMessageType {
  PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD = 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD',
  USER_PASSKEY_CONFIRM_RESPONSE = 'USER_PASSKEY_CONFIRM_RESPONSE',
  USER_PASSKEY_CONFIRM_PROGRESS = 'USER_PASSKEY_CONFIRM_PROGRESS',
}

export interface UserConfirmProgressEvent {
  requestId: string;
  step: number;
  phase: string;
  status: 'progress' | 'success' | 'error';
  message?: string;
  data?: unknown;
}

export interface UserConfirmPromptEnvelope {
  type: UserConfirmMessageType.PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD;
  requestId: string;
  channelToken?: string;
  data: UserConfirmRequest;
}

/**
 * Type-level guardrail: these secrets must never appear in main-thread
 * request/response envelopes. PRF outputs are extracted from credentials and
 * passed directly to signer-worker payloads in wallet origin only.
 */
export type ForbiddenMainThreadSecrets = {
  prfOutput?: never;
  prf_output?: never;
  wrapKeySeed?: never;
  wrapKeySalt?: never;
  prfKey?: never;
};

export interface UserConfirmDecision extends ForbiddenMainThreadSecrets {
  requestId: string;
  intentDigest?: string;
  confirmed: boolean;
  credential?: SerializableCredential; // Serialized WebAuthn credential
  otpCode?: string;
  emailOtpChallengeId?: string;
  transactionContext?: TransactionContext; // NEAR data fetched during confirmation
  // This is a private field used to close the confirmation modal
  _confirmHandle?: { close: (confirmed: boolean) => void };
  error?: string;
}

export interface UserConfirmResponseEnvelope {
  type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE;
  requestId: string;
  channelToken?: string;
  data: UserConfirmDecision;
}

export interface UserConfirmProgressEnvelope {
  type: UserConfirmMessageType.USER_PASSKEY_CONFIRM_PROGRESS;
  requestId: string;
  channelToken?: string;
  data: UserConfirmProgressEvent;
}

export interface TransactionSummary {
  totalAmount?: string;
  title?: string;
  body?: string;
  method?: string;
  operation?: string;
  warning?: string;
  intentDigest?: string;
  receiverId?: string;
  type?: string;
  delegate?: {
    senderId?: string;
    receiverId?: string;
    nonce?: string;
    maxBlockHeight?: string;
  };
  summary?: unknown;
}

// Payload to return to Rust WASM is snake_case
export interface WorkerConfirmationResponse {
  request_id: string;
  intent_digest?: string;
  confirmed: boolean;
  credential?: SerializableCredential;
  otp_code?: string;
  email_otp_challenge_id?: string;
  transaction_context?: TransactionContext; // NEAR data fetched during confirmation
  error?: string;
}

// ===== V2 MESSAGE TYPES =====

export enum UserConfirmationType {
  SIGN_TRANSACTION = 'signTransaction',
  REGISTER_ACCOUNT = 'registerAccount',
  LINK_DEVICE = 'linkDevice',
  DECRYPT_PRIVATE_KEY_WITH_PRF = 'decryptPrivateKeyWithPrf',
  SIGN_NEP413_MESSAGE = 'signNep413Message',
  SHOW_SECURE_PRIVATE_KEY_UI = 'showSecurePrivateKeyUi',
  SIGN_INTENT_DIGEST = 'signIntentDigest',
}

export type SigningAuthMode = 'webauthn' | 'warmSession' | 'emailOtp';

export interface EmailOtpConfirmPrompt {
  challengeId: string;
  emailHint?: string;
  title?: string;
  body?: string;
  helperText?: string;
}

export type SigningAuthPlan =
  | {
      kind: 'warmSession';
      method: WalletAuthMethod;
      accountId: string;
      intent: WalletAuthIntent;
      curve?: WalletAuthCurve;
      signingRootId?: string;
      sessionId: string;
      retention?: SigningSessionRetention | null;
      expiresAtMs: number;
      remainingUses: number;
    }
  | {
      kind: 'passkeyReauth';
      method: 'passkey';
    }
  | {
      kind: 'emailOtpReauth';
      method: 'email_otp';
      emailOtpPrompt?: EmailOtpConfirmPrompt;
    };

export function signingAuthModeFromSigningAuthPlan(plan: SigningAuthPlan): SigningAuthMode {
  if (plan.kind === 'warmSession') return 'warmSession';
  if (plan.kind === 'emailOtpReauth') return 'emailOtp';
  return 'webauthn';
}

// V2 summaries (render-oriented / UI hints)
export interface TxSummary {
  totalAmount?: string;
  method?: string;
  receiverId?: string;
}
export interface RegistrationSummary {
  nearAccountId: string;
  signerSlot?: number;
  title?: string;
  body?: string;
}
export type ExportOperation = 'Export Private Key' | 'Decrypt Private Key' | 'Export Recovery Key';
export interface ExportSummary {
  operation: ExportOperation;
  accountId: string;
  publicKey: string;
  warning: string;
}
export interface Nep413Summary {
  operation: 'Sign NEP-413 Message';
  message: string;
  recipient: string;
  accountId: string;
}

// V2 request envelope
export type UserConfirmPayloadByType = {
  [UserConfirmationType.SIGN_TRANSACTION]: SignTransactionPayload;
  [UserConfirmationType.REGISTER_ACCOUNT]: RegisterAccountPayload;
  [UserConfirmationType.LINK_DEVICE]: RegisterAccountPayload;
  [UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF]: DecryptPrivateKeyWithPrfPayload;
  [UserConfirmationType.SIGN_NEP413_MESSAGE]: SignNep413Payload;
  [UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI]: ShowSecurePrivateKeyUiPayload;
  [UserConfirmationType.SIGN_INTENT_DIGEST]: SignIntentDigestPayload;
};

export type UserConfirmSummaryByType = {
  [UserConfirmationType.SIGN_TRANSACTION]: TransactionSummary;
  [UserConfirmationType.REGISTER_ACCOUNT]: RegistrationSummary;
  [UserConfirmationType.LINK_DEVICE]: RegistrationSummary;
  [UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF]: ExportSummary;
  [UserConfirmationType.SIGN_NEP413_MESSAGE]: TransactionSummary;
  [UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI]: ExportSummary;
  [UserConfirmationType.SIGN_INTENT_DIGEST]: TransactionSummary;
};

export type UserConfirmPayload = UserConfirmPayloadByType[keyof UserConfirmPayloadByType];
export type UserConfirmSummary = UserConfirmSummaryByType[keyof UserConfirmSummaryByType];

export interface UserConfirmRequest<TPayload = UserConfirmPayload, TSummary = UserConfirmSummary> {
  requestId: string;
  type: UserConfirmationType;
  summary: TSummary;
  payload: TPayload;
  // Allow partial override from callers; effective config is computed later
  confirmationConfig?: Partial<ConfirmationConfig>;
  // Optional intent digest to echo back in responses for flows that
  // do not have a tx-centric payload (e.g., registration/link flows)
  intentDigest?: string;
}

// V2 payloads
export interface SignTransactionPayload {
  txSigningRequests: TransactionInputWasm[];
  intentDigest: string;
  displayModel?: TxDisplayModel;
  rpcCall: RpcCallPayload;
  nearPublicKeyStr?: string;
  /**
   * Optional base64url-encoded 32-byte digest used as the preferred WebAuthn challenge for signing flows.
   *
   * In threshold-signer mode, this is typically the `sessionPolicyDigest32` produced when minting a
   * threshold session token (so the same digest can be used for both session mint + subsequent signing auth).
   */
  sessionPolicyDigest32?: string;
  /**
   * Controls whether touchConfirm signing flow should collect a WebAuthn credential.
   * - `webauthn`: prompt TouchID/FaceID and collect PRF outputs for signer requests.
   * - `warmSession`: skip WebAuthn when a wallet-origin warm session is available (e.g. cached PRF.first).
   */
  signingAuthMode?: SigningAuthMode;
  signingAuthPlan?: SigningAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}

export interface RegisterAccountPayload {
  nearAccountId: string;
  signerSlot?: number;
  rpcCall: RpcCallPayload;
}

export interface DecryptPrivateKeyWithPrfPayload {
  nearAccountId: string;
  publicKey: string;
  challengeB64u?: string;
}

export type ExportPrivateKeyScheme = 'ed25519' | 'secp256k1';

export interface ExportPrivateKeyDisplayEntry {
  scheme: ExportPrivateKeyScheme;
  label: string;
  publicKey: string;
  privateKey: string;
  address?: string;
}

export interface ExportGuidance {
  title: string;
  body?: string;
  steps?: string[];
}

export interface ShowSecurePrivateKeyUiPayload {
  nearAccountId: string;
  publicKey?: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  loading?: boolean;
}

export interface SignNep413Payload {
  nearAccountId: string;
  nearPublicKeyStr?: string;
  message: string;
  recipient: string;
  displayModel?: TxDisplayModel;
  /**
   * Optional base64url-encoded 32-byte digest used as the preferred WebAuthn challenge for this signing flow.
   */
  sessionPolicyDigest32?: string;
  /**
   * Controls whether touchConfirm signing flow should collect a WebAuthn credential for this signing intent.
   * See `SignTransactionPayload.signingAuthMode`.
   */
  signingAuthMode?: SigningAuthMode;
  signingAuthPlan?: SigningAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}

export interface SignIntentDigestPayload {
  nearAccountId: string;
  /**
   * Base64url-encoded 32-byte digest used as WebAuthn challenge when `signingAuthMode='webauthn'`.
   */
  challengeB64u: string;
  displayModel?: TxDisplayModel;
  signingAuthMode?: SigningAuthMode;
  signingAuthPlan?: SigningAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}

// Type guards
export function isUserConfirmRequestV2(x: unknown): x is UserConfirmRequest {
  return (
    isObject(x) &&
    isString((x as { type?: unknown }).type) &&
    isString((x as { requestId?: unknown }).requestId) &&
    (x as { summary?: unknown }).summary != null &&
    (x as { payload?: unknown }).payload != null
  );
}

// Serialized WebAuthn credential (authentication or registration)
export type SerializableCredential =
  | WebAuthnAuthenticationCredential
  | WebAuthnRegistrationCredential;

// Discriminated unions to bind `type` to payload shape
export type UserConfirmRequestByType<TType extends UserConfirmationType> = UserConfirmRequest<
  UserConfirmPayloadByType[TType],
  UserConfirmSummaryByType[TType]
> & { type: TType };

export type LocalOnlyUserConfirmRequest =
  | UserConfirmRequestByType<UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF>
  | UserConfirmRequestByType<UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI>;

export type RegistrationUserConfirmRequest =
  | UserConfirmRequestByType<UserConfirmationType.REGISTER_ACCOUNT>
  | UserConfirmRequestByType<UserConfirmationType.LINK_DEVICE>;

export type SigningUserConfirmRequest =
  | UserConfirmRequestByType<UserConfirmationType.SIGN_TRANSACTION>
  | UserConfirmRequestByType<UserConfirmationType.SIGN_NEP413_MESSAGE>;

export type IntentDigestUserConfirmRequest =
  UserConfirmRequestByType<UserConfirmationType.SIGN_INTENT_DIGEST>;

export type KnownUserConfirmRequest =
  | LocalOnlyUserConfirmRequest
  | RegistrationUserConfirmRequest
  | SigningUserConfirmRequest
  | IntentDigestUserConfirmRequest;
