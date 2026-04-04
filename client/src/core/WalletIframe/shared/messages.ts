// Typed RPC messages for the wallet service iframe channel (TatchiPasskey-first)
import type { WalletUIRegistry } from '../host/lit-ui/iframe-lit-element-registry';
import { SignedTransaction } from '../../rpcClients/near/NearClient';
import { ActionArgs, TransactionInput } from '../../types';
import { type DeviceLinkingQRData } from '../../types/linkDevice';
import type { DelegateActionInput } from '../../types/delegate';
import type { ConfirmationConfig } from '../../types/signer-worker';
import type { MultichainSigningRequest } from '../../signingEngine/chainAdaptors/tempo/types';
import type { EvmSignedResult } from '../../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../../signingEngine/chainAdaptors/tempo/tempoAdapter';
import type {
  ThresholdEd25519HssFinalizedReportEnvelope,
  ThresholdEd25519HssPreparedSessionEnvelope,
} from '../../signingEngine/signers/wasm/hssClientSignerWasm';
import type { TatchiConfigsInput } from '../../types/tatchi';

export type WalletProtocolVersion = '1.0.0';

export type ParentToChildType =
  | 'PING'
  | 'PM_SET_CONFIG'
  | 'PM_CANCEL'
  // TatchiPasskey API surface
  | 'PM_REGISTER'
  | 'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION'
  | 'PM_UNLOCK'
  | 'PM_LOCK'
  | 'PM_GET_WALLET_SESSION'
  | 'PM_GET_RECOVERY_EMAILS'
  | 'PM_SET_RECOVERY_EMAILS'
  | 'PM_SIGN_TXS_WITH_ACTIONS'
  | 'PM_SIGN_AND_SEND_TXS'
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
  | 'PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL'
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
  nearAccountId: string | null;
  confirmationConfig: ConfirmationConfig;
  updatedAt: number;
}

export interface PMSetConfigPayload extends Partial<TatchiConfigsInput> {
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

export interface PMBootstrapThresholdEcdsaSessionPayload {
  nearAccountId: string;
  options?: {
    chain?: 'evm' | 'tempo';
    relayerUrl?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    ttlMs?: number;
    remainingUses?: number;
    smartAccount?: {
      chainId: number;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    };
  };
}

export interface PMUnlockPayload {
  nearAccountId: string;
  options?: Record<string, unknown>;
}

export interface PMSignTxsPayload {
  nearAccountId: string;
  transactions: TransactionInput[];
  options: {
    deviceNumber?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignAndSendTxsPayload {
  nearAccountId: string;
  transactions: TransactionInput[];
  options: {
    deviceNumber?: number;
    // Keep only serializable fields; functions are bridged via PROGRESS
    waitUntil?:
      | 'NONE'
      | 'INCLUDED'
      | 'INCLUDED_FINAL'
      | 'EXECUTED'
      | 'FINAL'
      | 'EXECUTED_OPTIMISTIC';
    executionWait?: Record<string, unknown>;
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
    deviceNumber?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignDelegateActionPayload {
  nearAccountId: string;
  delegate: DelegateActionInput;
  options: {
    deviceNumber?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignNep413Payload {
  nearAccountId: string;
  params: { message: string; recipient: string; state?: string };
  options: {
    deviceNumber?: number;
    confirmationConfig?: Partial<ConfirmationConfig>;
    confirmerText?: { title?: string; body?: string };
    [key: string]: unknown;
  };
}

export interface PMSignTempoPayload {
  nearAccountId: string;
  request: MultichainSigningRequest;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
}

export interface PMTempoNonceLifecyclePayloadBase {
  nearAccountId: string;
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

export interface PMExportKeypairUiPayload {
  nearAccountId: string;
  chain: 'near' | 'evm' | 'tempo';
  variant?: 'modal' | 'drawer';
  theme?: 'dark' | 'light';
}

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
  nearAccountId?: string;
}

export interface PMSetConfirmationConfigPayload {
  config: Partial<ConfirmationConfig>;
  nearAccountId?: string;
}

export interface PMGetWalletSessionPayload {
  nearAccountId?: string;
}

export interface PMPrefillThresholdEcdsaPresignPoolPayload {
  nearAccountId: string;
  options?: {
    chain?: 'tempo' | 'evm';
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

export interface ProgressPayload {
  step: number;
  phase: string;
  status: 'progress' | 'success' | 'error';
  message?: string;
  data?: unknown;
}

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
  | RpcEnvelope<'PM_BOOTSTRAP_THRESHOLD_ECDSA_SESSION', PMBootstrapThresholdEcdsaSessionPayload>
  | RpcEnvelope<'PM_UNLOCK', PMUnlockPayload>
  | RpcEnvelope<'PM_LOCK'>
  | RpcEnvelope<'PM_GET_WALLET_SESSION', PMGetWalletSessionPayload>
  | RpcEnvelope<'PM_GET_RECOVERY_EMAILS', PMGetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SET_RECOVERY_EMAILS', PMSetRecoveryEmailsPayload>
  | RpcEnvelope<'PM_SIGN_TXS_WITH_ACTIONS', PMSignTxsPayload>
  | RpcEnvelope<'PM_SIGN_AND_SEND_TXS', PMSignAndSendTxsPayload>
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
      'PM_PREFILL_THRESHOLD_ECDSA_PRESIGN_POOL',
      PMPrefillThresholdEcdsaPresignPoolPayload
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
        deviceNumber?: number;
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
  | RpcEnvelope<'PM_RESULT', PMResultPayload>
  | RpcEnvelope<'ERROR', ErrorPayload>;
