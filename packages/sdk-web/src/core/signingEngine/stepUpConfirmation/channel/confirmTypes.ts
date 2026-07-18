import { TransactionInputWasm } from '@/core/types';
import { ConfirmationConfig } from '@/core/types';
import { TransactionContext } from '@/core/types/rpc';
import { RpcCallPayload } from '@/core/types/signer-worker';
import type { TxDisplayModel } from '@/core/signingEngine/interfaces/display';
import { isObject, isString } from '@shared/utils/validation';
import type {
  EmailOtpConfirmPrompt,
  RegistrationConfirmationDiagnostics,
  SerializableCredential,
  SigningAuthPlan,
  UserConfirmDecision,
  UserConfirmProgressEvent,
  WebAuthnChallenge,
} from '../types';
import type { NonceLeaseRef } from '../../interfaces/nonceLease';
import type {
  NearFundingRequest,
  NearTransactionReadiness,
} from '../../nonce/nearTransactionReadiness';

export type {
  ForbiddenMainThreadSecrets,
  RegistrationConfirmationDiagnostics,
  SerializableCredential,
  UserConfirmDecision,
  WebAuthnChallenge,
} from '../types';

// === SECURE CONFIRM TYPES (V2) ===

export enum UserConfirmMessageType {
  PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD = 'PROMPT_USER_CONFIRM_IN_JS_MAIN_THREAD',
  USER_PASSKEY_CONFIRM_RESPONSE = 'USER_PASSKEY_CONFIRM_RESPONSE',
  USER_PASSKEY_CONFIRM_PROGRESS = 'USER_PASSKEY_CONFIRM_PROGRESS',
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

type WorkerConfirmationResponseBase = {
  request_id: string;
  intent_digest?: string;
};

type WorkerConfirmationSuccessBase = WorkerConfirmationResponseBase & {
  confirmed: true;
  credential?: SerializableCredential;
  otp_code?: string;
  email_otp_challenge_id?: string;
  registration_diagnostics?: RegistrationConfirmationDiagnostics;
  error?: never;
};

// Payload to return to Rust WASM is snake_case.
export type WorkerConfirmationResponse =
  | (WorkerConfirmationSuccessBase & {
      transaction_context: TransactionContext;
      nonce_leases: NonceLeaseRef[];
      near_transaction_readiness?: never;
    })
  | (WorkerConfirmationSuccessBase & {
      near_transaction_readiness: NearTransactionReadiness;
      transaction_context?: never;
      nonce_leases?: never;
    })
  | (WorkerConfirmationSuccessBase & {
      near_transaction_readiness?: never;
      transaction_context?: never;
      nonce_leases?: never;
    })
  | (WorkerConfirmationResponseBase & {
      confirmed: false;
      error?: string;
      registration_diagnostics?: RegistrationConfirmationDiagnostics;
      credential?: never;
      otp_code?: never;
      email_otp_challenge_id?: never;
      near_transaction_readiness?: never;
      transaction_context?: never;
      nonce_leases?: never;
    });

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

// V2 summaries (render-oriented / UI hints)
export interface TxSummary {
  totalAmount?: string;
  method?: string;
  receiverId?: string;
}
export interface RegistrationSummary {
  walletId: string;
  nearAccountId?: string;
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
type SignTransactionPayloadBase = {
  walletId: string;
  txSigningRequests: TransactionInputWasm[];
  intentDigest: string;
  displayModel?: TxDisplayModel;
  rpcCall: RpcCallPayload;
  nearPublicKeyStr?: string;
};

type NearTransactionSigningPayload = SignTransactionPayloadBase & { signingKind: 'transaction' } & (
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
        nearFundingRequest: NearFundingRequest;
        webauthnChallenge?: never;
        emailOtpPrompt?: never;
      }
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
        nearFundingRequest: NearFundingRequest;
        webauthnChallenge?: WebAuthnChallenge;
        emailOtpPrompt?: never;
      }
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
        nearFundingRequest: NearFundingRequest;
        webauthnChallenge?: never;
        emailOtpPrompt: EmailOtpConfirmPrompt;
      }
  );

type NearDelegateSigningPayload = SignTransactionPayloadBase & {
  signingKind: 'delegate';
  nearFundingRequest?: never;
} & (
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'warmSession' }>;
        webauthnChallenge?: never;
        emailOtpPrompt?: never;
      }
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
        webauthnChallenge?: WebAuthnChallenge;
        emailOtpPrompt?: never;
      }
    | {
        signingAuthPlan: Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>;
        webauthnChallenge?: never;
        emailOtpPrompt: EmailOtpConfirmPrompt;
      }
  );

export type SignTransactionPayload = NearTransactionSigningPayload | NearDelegateSigningPayload;

export interface RegisterAccountPayload {
  walletId: string;
  nearAccountId?: string;
  signerSlot?: number;
  webauthnChallenge?: Extract<WebAuthnChallenge, { kind: 'intent_digest' }>;
};

export type LocalOnlyExportSubject =
  | {
      kind: 'near_wallet';
      nearAccountId: string;
      walletId?: never;
    }
  | {
      kind: 'evm_wallet';
      walletId: string;
      nearAccountId?: never;
    };

export interface DecryptPrivateKeyWithPrfPayload {
  subject: LocalOnlyExportSubject;
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
  subject: LocalOnlyExportSubject;
  viewerSessionId?: string;
  publicKey: string;
  privateKey?: string;
  keys?: ExportPrivateKeyDisplayEntry[];
  guidance?: ExportGuidance;
  variant?: 'drawer' | 'modal';
  theme?: 'dark' | 'light';
  loading?: boolean;
  errorMessage?: string;
  onLifecycle?: (event: 'opened' | 'closed') => void;
}

export interface SignNep413Payload {
  walletId: string;
  nearAccountId: string;
  nearPublicKeyStr?: string;
  message: string;
  recipient: string;
  displayModel?: TxDisplayModel;
  webauthnChallenge?: WebAuthnChallenge;
  signingAuthPlan: SigningAuthPlan;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
}

export type SignIntentDigestSubject =
  | {
      kind: 'near_wallet';
      walletId: string;
      nearAccountId: string;
    }
  | {
      kind: 'evm_wallet';
      walletId: string;
      nearAccountId?: never;
    };

type SignIntentDigestPayloadBase = {
  signingSubject: SignIntentDigestSubject;
  /**
   * Base64url-encoded 32-byte digest used as WebAuthn challenge when the
   * derived signing auth display mode is WebAuthn.
   */
  challengeB64u: string;
  displayModel?: TxDisplayModel;
  emailOtpPrompt?: EmailOtpConfirmPrompt;
};

export type SignIntentDigestPayload =
  | (SignIntentDigestPayloadBase & {
      signingAuthPlan: Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>;
      webauthnChallenge: WebAuthnChallenge;
    })
  | (SignIntentDigestPayloadBase & {
      signingAuthPlan: Exclude<
        SigningAuthPlan,
        Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>
      >;
      webauthnChallenge?: WebAuthnChallenge;
    });

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
