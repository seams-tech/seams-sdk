// Typed RPC messages for the wallet service iframe channel (SeamsWeb-first)
import type { WalletUIRegistry } from '../host/lit-ui/iframe-lit-element-registry';
import type { BootstrapThresholdEcdsaSessionArgs } from '@/SeamsWeb/signingSurface/types';
import { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import { ActionArgs, TransactionInput } from '@/core/types';
import { type DeviceLinkingQRData } from '@/core/types/linkDevice';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { ConfirmationConfig } from '@/core/types/signer-worker';
import type { MultichainSigningRequest } from '@/core/signingEngine/chains/tempo/tempoSigning.types';
import type { EvmSignedResult } from '@/core/signingEngine/chains/evm/evmAdapter';
import type { TempoSignedResult } from '@/core/signingEngine/chains/tempo/tempoAdapter';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '@/core/signingEngine/threshold/crypto/hssClientSignerWasm';
import type {
  NearAccountRef,
  ThresholdEcdsaChainTarget,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { EmailOtpAuthPolicy, SeamsConfigsInput } from '@/core/types/seams';
import type { WalletEmailOtpLoginOperation } from '@shared/utils/emailOtpDomain';
import type { WalletFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  GoogleEmailOtpWalletAuthDelivery,
  GoogleEmailOtpWalletAuthEcdsaTargets,
  GoogleEmailOtpWalletAuthFailure,
  GoogleEmailOtpWalletAuthPromptCopy,
  GoogleEmailOtpWalletAuthRegistrationCompleted,
  GoogleEmailOtpWalletAuthResolvedMode,
  GoogleEmailOtpWalletAuthRequestedMode,
  GoogleEmailOtpWalletAuthSubmitSuccess,
} from '@/SeamsWeb/publicApi/types';
import type {
  AddSignerSelection,
  RegistrationAuthMethodInput,
  RegisterWalletInput,
  RegistrationSignerSelection,
  WalletId,
} from '@shared/utils/registrationIntent';
import type { PMUnlockPayload } from '@/core/types/login.types';
export type {
  PMUnlockOptions,
  PMUnlockPayload,
  WalletIframeUnlockRequest,
} from '@/core/types/login.types';

export type WalletProtocolVersion = '1.0.0';

export type ParentToChildType =
  | 'PING'
  | 'PM_SET_CONFIG'
  | 'PM_CANCEL'
  // SeamsWeb API surface
  | 'PM_REGISTER'
  | 'PM_REGISTRATION_ACTIVATION_PREPARE'
  | 'PM_REGISTRATION_ACTIVATION_CANCEL'
  | 'PM_REGISTER_WALLET'
  | 'PM_ADD_WALLET_SIGNER'
  | 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'
  | 'PM_UNLOCK'
  | 'PM_LOCK'
  | 'PM_GET_WALLET_SESSION'
  | 'PM_REQUEST_EMAIL_OTP_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE'
  | 'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE'
  | 'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION'
  | 'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION'
  | 'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL'
  | 'PM_ENROLL_EMAIL_OTP'
  | 'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'
  | 'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION'
  | 'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY'
  | 'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS'
  | 'PM_SHOW_EMAIL_OTP_RECOVERY_CODES'
  | 'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES'
  | 'PM_GET_RECOVERY_EMAILS'
  | 'PM_SET_RECOVERY_EMAILS'
  | 'PM_SIGN_TX_WITH_ACTIONS'
  | 'PM_SIGN_AND_SEND_TX'
  | 'PM_SEND_TRANSACTION'
  | 'PM_EXECUTE_ACTION'
  | 'PM_SIGN_DELEGATE_ACTION'
  | 'PM_SIGN_NEP413'
  | 'PM_SIGN_TEMPO'
  | 'PM_REPORT_TEMPO_BROADCAST_ACCEPTED'
  | 'PM_REPORT_TEMPO_BROADCAST_REJECTED'
  | 'PM_REPORT_TEMPO_FINALIZED'
  | 'PM_REPORT_TEMPO_DROPPED_OR_REPLACED'
  | 'PM_RECONCILE_TEMPO_NONCE_LANE'
  | 'PM_EXPORT_KEYPAIR_UI'
  | 'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI'
  | 'PM_GET_RECENT_UNLOCKS'
  | 'PM_PREFETCH_BLOCKHEIGHT'
  | 'PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL'
  | 'PM_SET_CONFIRM_BEHAVIOR'
  | 'PM_SET_CONFIRMATION_CONFIG'
  | 'PM_GET_CONFIRMATION_CONFIG'
  | 'PM_SET_THEME'
  | 'PM_HAS_PASSKEY'
  | 'PM_VIEW_ACCESS_KEYS'
  | 'PM_DELETE_DEVICE_KEY'
  | 'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA'
  | 'PM_START_DEVICE2_LINKING_FLOW'
  | 'PM_STOP_DEVICE2_LINKING_FLOW'
  | 'PM_SYNC_ACCOUNT_FLOW'
  | 'PM_START_EMAIL_RECOVERY'
  | 'PM_FINALIZE_EMAIL_RECOVERY'
  | 'PM_STOP_EMAIL_RECOVERY';

export type ChildToParentType =
  | 'READY'
  | 'PONG'
  | 'PROGRESS'
  | 'PREFERENCES_CHANGED'
  | 'PM_REGISTRATION_ACTIVATION_READY'
  | 'PM_REGISTRATION_ACTIVATION_STARTED'
  | 'PM_RESULT'
  | 'ERROR';

export interface RpcEnvelope<T extends string = string, P = unknown> {
  type: T;
  requestId?: string;
  payload?: P;
  options?: {
    onProgress?(payload: ProgressPayload): void;
    sticky?: boolean;
  };
}

// ===== Payloads =====

export interface ReadyPayload {
  protocolVersion: WalletProtocolVersion;
}

export interface PreferencesChangedPayload {
  walletId: string | null;
  confirmationConfig: ConfirmationConfig;
  updatedAt: number;
}

export interface PMSetConfigPayload extends Partial<SeamsConfigsInput> {
  // Absolute base URL for SDK Lit component assets (e.g., https://app.example.com/sdk/)
  assetsBaseUrl?: string;
  // Optional: register wallet-host UI components (Lit tags + bindings)
  uiRegistry?: WalletUIRegistry;
}

export interface PMCancelPayload {
  requestId?: string; // when omitted, host may attempt best-effort global cancel (close UIs)
}

export interface PMRegisterPayload {
  nearAccountId: string;
  uiMode?: 'modal' | 'drawer';
  // Optional per-call confirmation override
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export interface PMRegistrationActivationPreparePayload {
  activationId: string;
  nearAccountId: string;
  expiresAtMs: number;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
  button?: {
    label?: string;
    busyLabel?: string;
  };
}

export interface PMRegistrationActivationCancelPayload {
  activationId: string;
  reason: 'user_cancelled' | 'expired' | 'disposed';
}

export interface PMRegistrationActivationReadyPayload {
  activationId: string;
  expiresAtMs: number;
}

export interface PMRegistrationActivationStartedPayload {
  activationId: string;
}

export interface PMRegisterWalletPayload {
  authMethod: RegistrationAuthMethodInput;
  wallet: RegisterWalletInput;
  rpId: string;
  signerSelection: RegistrationSignerSelection;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export interface PMAddWalletSignerPayload {
  walletId: WalletId | string;
  rpId: string;
  signerSelection: AddSignerSelection;
  confirmationConfig?: Partial<ConfirmationConfig>;
  options?: Record<string, unknown>;
}

export type PMBootstrapThresholdEcdsaSessionPayload = BootstrapThresholdEcdsaSessionArgs;

export type PMGoogleEmailOtpWalletAuthStartPayload = {
  idToken: string;
  mode: GoogleEmailOtpWalletAuthRequestedMode;
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
  ecdsaTargets?: GoogleEmailOtpWalletAuthEcdsaTargets;
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
};

export type PMGoogleEmailOtpWalletAuthHandlePayload = {
  flowHandleId: string;
  flowId: string;
  walletId: string;
  mode: GoogleEmailOtpWalletAuthResolvedMode;
};

export type PMGoogleEmailOtpWalletAuthSubmitPayload = PMGoogleEmailOtpWalletAuthHandlePayload & {
  otpCode: string;
};

export type PMGoogleEmailOtpWalletAuthRegistrationWireFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  state: 'registration_ready';
  flowHandleId: string;
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: 'register';
  walletId: string;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  expiresAtMs: number;
};

export type PMGoogleEmailOtpWalletAuthLoginWireFlow = {
  kind: 'google_email_otp_wallet_auth_flow_v1';
  state: 'challenge_sent';
  flowHandleId: string;
  flowId: string;
  requestedMode: GoogleEmailOtpWalletAuthRequestedMode;
  mode: 'login';
  walletId: string;
  emailHint: string;
  prompt: GoogleEmailOtpWalletAuthPromptCopy;
  delivery: GoogleEmailOtpWalletAuthDelivery;
  expiresAtMs: number;
};

export type PMGoogleEmailOtpWalletAuthWireFlow =
  | PMGoogleEmailOtpWalletAuthRegistrationWireFlow
  | PMGoogleEmailOtpWalletAuthLoginWireFlow;

export type PMGoogleEmailOtpWalletAuthWireResult<T> =
  | { ok: true; value: T }
  | { ok: false; error: GoogleEmailOtpWalletAuthFailure };

export type PMGoogleEmailOtpWalletAuthRegistrationWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<PMGoogleEmailOtpWalletAuthRegistrationWireFlow>;

export type PMGoogleEmailOtpWalletAuthSubmitWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<GoogleEmailOtpWalletAuthSubmitSuccess>;

export type PMGoogleEmailOtpWalletAuthCompleteRegistrationWireResult =
  PMGoogleEmailOtpWalletAuthWireResult<GoogleEmailOtpWalletAuthRegistrationCompleted>;

export interface PMSignTxPayload {
  nearAccountId: string;
  transaction: TransactionInput;
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignAndSendTxPayload {
  nearAccountId: string;
  transaction: TransactionInput;
  options: {
    signerSlot?: number;
    // Keep only serializable fields; functions are bridged via PROGRESS
    waitUntil?:
      | 'NONE'
      | 'INCLUDED'
      | 'INCLUDED_FINAL'
      | 'EXECUTED'
      | 'FINAL'
      | 'EXECUTED_OPTIMISTIC';
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSendTxPayload {
  signedTransaction: SignedTransaction; // SignedTransaction-like
  options?: Record<string, unknown>;
}

export interface PMExecuteActionPayload {
  nearAccountId: string;
  receiverId: string;
  actionArgs: ActionArgs | ActionArgs[];
  options: {
    waitUntil?: unknown;
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignDelegateActionPayload {
  nearAccountId: string;
  delegate: DelegateActionInput;
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignNep413Payload {
  nearAccountId: string;
  params: { message: string; recipient: string; state?: string };
  options: {
    signerSlot?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignTempoPayload {
  walletSession: WalletSessionRef;
  request: MultichainSigningRequest;
  chainTarget: ThresholdEcdsaChainTarget;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
}

export interface PMTempoNonceLifecyclePayloadBase {
  walletSession: WalletSessionRef;
  signedResult: TempoSignedResult | EvmSignedResult;
}

export interface PMReportTempoBroadcastAcceptedPayload extends PMTempoNonceLifecyclePayloadBase {
  txHash?: `0x${string}`;
}

export interface PMReportTempoBroadcastRejectedPayload extends PMTempoNonceLifecyclePayloadBase {
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
}

export interface PMReportTempoFinalizedPayload extends PMTempoNonceLifecyclePayloadBase {
  txHash?: `0x${string}`;
  receiptStatus?: 'success' | 'reverted';
}

export interface PMReportTempoDroppedOrReplacedPayload extends PMTempoNonceLifecyclePayloadBase {
  reason: 'dropped' | 'replaced';
  txHash?: `0x${string}`;
}

export interface PMReconcileTempoNonceLanePayload extends PMTempoNonceLifecyclePayloadBase {}

export type PMExportKeypairUiPayload =
  | {
      kind: 'near';
      nearAccount: NearAccountRef;
      options: {
        chain: 'near';
        variant?: 'modal' | 'drawer';
        theme?: 'dark' | 'light';
      };
    }
  | {
      kind: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSession: WalletSessionRef;
      options: {
        variant?: 'modal' | 'drawer';
        theme?: 'dark' | 'light';
      };
    };

export interface PMExportThresholdEd25519SeedFromHssReportUiPayload {
  nearAccountId: string;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  finalizedReport: ThresholdEd25519HssFinalizedReportEnvelope;
  expectedPublicKey: string;
  variant?: 'modal' | 'drawer';
  theme?: 'dark' | 'light';
}

export interface PMSetConfirmBehaviorPayload {
  behavior: 'requireClick' | 'skipClick';
  walletId?: string;
}

export interface PMSetConfirmationConfigPayload {
  config: Partial<ConfirmationConfig>;
  walletId?: string;
}

export interface PMGetWalletSessionPayload {
  walletId?: string;
}

export interface PMEmailOtpChallengePayload {
  nearAccountId: string;
  relayUrl?: string;
  appSessionJwt?: string;
  operation?: WalletEmailOtpLoginOperation;
}

export interface PMEmailOtpSigningSessionChallengePayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
}

export interface PMExchangeGoogleEmailOtpSessionPayload {
  idToken: string;
  accountMode: 'register' | 'login';
  relayUrl?: string;
  sessionKind?: 'jwt' | 'cookie';
}

export interface PMEnrollEmailOtpPayload {
  nearAccountId: string;
  otpCode: string;
  relayUrl?: string;
  challengeId?: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
}

export interface PMGetEmailOtpRecoveryCodeStatusPayload {
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}

export interface PMShowEmailOtpRecoveryCodesPayload {
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}

export interface PMRotateEmailOtpRecoveryCodesPayload {
  walletId: string;
  relayUrl?: string;
  appSessionJwt?: string;
}

export interface PMEmailOtpEcdsaCapabilityPayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  publicationChainTargets?: readonly ThresholdEcdsaChainTarget[];
  emailOtpAuthPolicy?: EmailOtpAuthPolicy;
  relayUrl?: string;
  challengeId?: string;
  otpCode: string;
  shamirPrimeB64u?: string;
  appSessionJwt?: string;
  registrationAttemptId?: string;
}

export interface PMRefreshEmailOtpSigningSessionPayload {
  walletSession: WalletSessionRef;
  chainTarget: ThresholdEcdsaChainTarget;
  challengeId: string;
  otpCode: string;
  ttlMs?: number;
  remainingUses?: number;
}

export interface PMEmailOtpEcdsaEnrollmentCapabilityPayload extends PMEmailOtpEcdsaCapabilityPayload {}

export interface PMPrefillRouterAbEcdsaHssPresignaturePoolPayload {
  walletSession: WalletSessionRef;
  options: {
    chainTarget: ThresholdEcdsaChainTarget;
    waitForPoolReady?: boolean;
    poolReadyTimeoutMs?: number;
    poolReadyPollIntervalMs?: number;
    minRemainingUsesBeforePrefill?: number;
  };
}

export interface PMSetThemePayload {
  theme: 'dark' | 'light';
}

export interface PMHasPasskeyPayload {
  nearAccountId: string;
}

export interface PMViewAccessKeysPayload {
  accountId: string;
}

export interface PMDeleteDeviceKeyPayload {
  accountId: string;
  publicKeyToDelete: string;
  options: {
    [key: string]: unknown;
  };
}

export interface PMStartEmailRecoveryPayload {
  accountId: string;
  options?: {
    confirmerText?: { title?: string; body?: string };
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
}

export interface PMFinalizeEmailRecoveryPayload {
  accountId: string;
  nearPublicKey?: string;
}

export interface PMStopEmailRecoveryPayload {
  accountId?: string;
  nearPublicKey?: string;
}

export interface PMGetRecoveryEmailsPayload {
  nearAccountId: string;
}

export interface PMSetRecoveryEmailsPayload {
  nearAccountId: string;
  recoveryEmails: string[];
  options: {
    waitUntil?: unknown;
    confirmationConfig?: Partial<ConfirmationConfig>;
    [key: string]: unknown;
  };
}

export type ProgressPayload = WalletFlowEvent;

export interface PMResultPayload {
  ok: boolean;
  result?: unknown;
  error?: string;
}

export interface ErrorPayload {
  code: string;
  message: string;
  details?: unknown;
}

export type ParentToChildEnvelope =
  | RpcEnvelope<'PING'>
  | RpcEnvelope<'PM_SET_CONFIG', PMSetConfigPayload>
  | RpcEnvelope<'PM_CANCEL', PMCancelPayload>
  | RpcEnvelope<'PM_REGISTER', PMRegisterPayload>
  | RpcEnvelope<'PM_REGISTRATION_ACTIVATION_PREPARE', PMRegistrationActivationPreparePayload>
  | RpcEnvelope<'PM_REGISTRATION_ACTIVATION_CANCEL', PMRegistrationActivationCancelPayload>
  | RpcEnvelope<'PM_REGISTER_WALLET', PMRegisterWalletPayload>
  | RpcEnvelope<'PM_ADD_WALLET_SIGNER', PMAddWalletSignerPayload>
  | RpcEnvelope<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION', PMBootstrapThresholdEcdsaSessionPayload>
  | RpcEnvelope<'PM_UNLOCK', PMUnlockPayload>
  | RpcEnvelope<'PM_LOCK'>
  | RpcEnvelope<'PM_GET_WALLET_SESSION', PMGetWalletSessionPayload>
  | RpcEnvelope<'PM_REQUEST_EMAIL_OTP_CHALLENGE', PMEmailOtpChallengePayload>
  | RpcEnvelope<'PM_REQUEST_EMAIL_OTP_ENROLLMENT_CHALLENGE', PMEmailOtpChallengePayload>
  | RpcEnvelope<
      'PM_REQUEST_EMAIL_OTP_SIGNING_SESSION_CHALLENGE',
      PMEmailOtpSigningSessionChallengePayload
    >
  | RpcEnvelope<'PM_EXCHANGE_GOOGLE_EMAIL_OTP_SESSION', PMExchangeGoogleEmailOtpSessionPayload>
  | RpcEnvelope<'PM_BEGIN_GOOGLE_EMAIL_OTP_WALLET_AUTH', PMGoogleEmailOtpWalletAuthStartPayload>
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_RESEND', PMGoogleEmailOtpWalletAuthHandlePayload>
  | RpcEnvelope<
      'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_REROLL_WALLET_ID',
      PMGoogleEmailOtpWalletAuthHandlePayload
    >
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_SUBMIT', PMGoogleEmailOtpWalletAuthSubmitPayload>
  | RpcEnvelope<
      'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_COMPLETE_REGISTRATION',
      PMGoogleEmailOtpWalletAuthHandlePayload
    >
  | RpcEnvelope<'PM_GOOGLE_EMAIL_OTP_WALLET_AUTH_CANCEL', PMGoogleEmailOtpWalletAuthHandlePayload>
  | RpcEnvelope<'PM_ENROLL_EMAIL_OTP', PMEnrollEmailOtpPayload>
  | RpcEnvelope<'PM_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY', PMEmailOtpEcdsaCapabilityPayload>
  | RpcEnvelope<'PM_REFRESH_EMAIL_OTP_SIGNING_SESSION', PMRefreshEmailOtpSigningSessionPayload>
  | RpcEnvelope<
      'PM_ENROLL_LOGIN_EMAIL_OTP_ECDSA_CAPABILITY',
      PMEmailOtpEcdsaEnrollmentCapabilityPayload
    >
  | RpcEnvelope<'PM_GET_EMAIL_OTP_RECOVERY_CODE_STATUS', PMGetEmailOtpRecoveryCodeStatusPayload>
  | RpcEnvelope<'PM_SHOW_EMAIL_OTP_RECOVERY_CODES', PMShowEmailOtpRecoveryCodesPayload>
  | RpcEnvelope<'PM_ROTATE_EMAIL_OTP_RECOVERY_CODES', PMRotateEmailOtpRecoveryCodesPayload>
  | RpcEnvelope<'PM_GET_RECOVERY_EMAILS', PMGetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SET_RECOVERY_EMAILS', PMSetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SIGN_TX_WITH_ACTIONS', PMSignTxPayload>
  | RpcEnvelope<'PM_SIGN_AND_SEND_TX', PMSignAndSendTxPayload>
  | RpcEnvelope<'PM_SEND_TRANSACTION', PMSendTxPayload>
  | RpcEnvelope<'PM_EXECUTE_ACTION', PMExecuteActionPayload>
  | RpcEnvelope<'PM_SIGN_DELEGATE_ACTION', PMSignDelegateActionPayload>
  | RpcEnvelope<'PM_SIGN_NEP413', PMSignNep413Payload>
  | RpcEnvelope<'PM_SIGN_TEMPO', PMSignTempoPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_BROADCAST_ACCEPTED', PMReportTempoBroadcastAcceptedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_BROADCAST_REJECTED', PMReportTempoBroadcastRejectedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_FINALIZED', PMReportTempoFinalizedPayload>
  | RpcEnvelope<'PM_REPORT_TEMPO_DROPPED_OR_REPLACED', PMReportTempoDroppedOrReplacedPayload>
  | RpcEnvelope<'PM_RECONCILE_TEMPO_NONCE_LANE', PMReconcileTempoNonceLanePayload>
  | RpcEnvelope<'PM_EXPORT_KEYPAIR_UI', PMExportKeypairUiPayload>
  | RpcEnvelope<
      'PM_EXPORT_THRESHOLD_ED25519_SEED_FROM_HSS_REPORT_UI',
      PMExportThresholdEd25519SeedFromHssReportUiPayload
    >
  | RpcEnvelope<'PM_GET_RECENT_UNLOCKS'>
  | RpcEnvelope<'PM_PREFETCH_BLOCKHEIGHT'>
  | RpcEnvelope<
      'PM_PREFILL_ROUTER_AB_ECDSA_HSS_PRESIGNATURE_POOL',
      PMPrefillRouterAbEcdsaHssPresignaturePoolPayload
    >
  | RpcEnvelope<'PM_SET_CONFIRM_BEHAVIOR', PMSetConfirmBehaviorPayload>
  | RpcEnvelope<'PM_SET_CONFIRMATION_CONFIG', PMSetConfirmationConfigPayload>
  | RpcEnvelope<'PM_GET_CONFIRMATION_CONFIG'>
  | RpcEnvelope<'PM_SET_THEME', PMSetThemePayload>
  | RpcEnvelope<'PM_HAS_PASSKEY', PMHasPasskeyPayload>
  | RpcEnvelope<'PM_VIEW_ACCESS_KEYS', PMViewAccessKeysPayload>
  | RpcEnvelope<'PM_DELETE_DEVICE_KEY', PMDeleteDeviceKeyPayload>
  | RpcEnvelope<
      'PM_LINK_DEVICE_WITH_SCANNED_QR_DATA',
      {
        qrData: DeviceLinkingQRData;
        fundingAmount: string;
        options?: {
          confirmationConfig?: Partial<ConfirmationConfig>;
          confirmerText?: { title?: string; body?: string };
        };
      }
    >
  | RpcEnvelope<
      'PM_START_DEVICE2_LINKING_FLOW',
      {
        ui?: 'modal' | 'inline';
        cameraId?: string;
        accountId?: string;
        signerSlot?: number;
        options?: {
          confirmationConfig?: Partial<ConfirmationConfig>;
          confirmerText?: { title?: string; body?: string };
        };
      }
    >
  | RpcEnvelope<'PM_STOP_DEVICE2_LINKING_FLOW'>
  | RpcEnvelope<'PM_SYNC_ACCOUNT_FLOW', { accountId?: string }>
  | RpcEnvelope<'PM_START_EMAIL_RECOVERY', PMStartEmailRecoveryPayload>
  | RpcEnvelope<'PM_FINALIZE_EMAIL_RECOVERY', PMFinalizeEmailRecoveryPayload>
  | RpcEnvelope<'PM_STOP_EMAIL_RECOVERY', PMStopEmailRecoveryPayload>;

export type ChildToParentEnvelope =
  | RpcEnvelope<'READY', ReadyPayload>
  | RpcEnvelope<'PONG'>
  | RpcEnvelope<'PROGRESS', ProgressPayload>
  | RpcEnvelope<'PREFERENCES_CHANGED', PreferencesChangedPayload>
  | RpcEnvelope<'PM_REGISTRATION_ACTIVATION_READY', PMRegistrationActivationReadyPayload>
  | RpcEnvelope<'PM_REGISTRATION_ACTIVATION_STARTED', PMRegistrationActivationStartedPayload>
  | RpcEnvelope<'PM_RESULT', PMResultPayload>
  | RpcEnvelope<'ERROR', ErrorPayload>;
