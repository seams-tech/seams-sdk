import type { TxExecutionStatus } from '@near-js/types';
import type { ConfirmationConfig } from './signer-worker';
import type { EcdsaSignerProvisioningDefaults } from './ecdsaSignerProvisioningDefaults';
import type {
  ActionResult,
  DelegateRouterApiResult,
  LoginAndCreateSessionResult,
  LoginResult,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
} from './seams';
import type { SyncAccountResult, SignNEP413MessageResult } from '@/core/types/sdkPublicResults';
import type { RegistrationActivationProof } from '@/core/signingEngine/stepUpConfirmation/channel/confirmTypes';

////////////////////////////
// Wallet Flow Event Model
////////////////////////////

export const WALLET_FLOW_EVENT_VERSION = 2 as const;

export type WalletFlow =
  | 'registration'
  | 'unlock'
  | 'signing'
  | 'link_device'
  | 'email_recovery'
  | 'account_sync'
  | 'key_export';

export type WalletFlowEventStatus =
  | 'started'
  | 'waiting_for_user'
  | 'running'
  | 'succeeded'
  | 'failed'
  | 'cancelled'
  | 'skipped';

export type WalletFlowAuthMethod = 'passkey' | 'email_otp' | 'warm_session';

export type WalletFlowOverlayIntent = 'show' | 'hide' | 'none';

export type WalletFlowInteractionKind =
  | 'none'
  | 'passkey_create'
  | 'passkey_assert'
  | 'otp_input'
  | 'transaction_confirmation'
  | 'qr_scan'
  | 'qr_display'
  | 'email_recovery_link'
  | 'key_export_viewer';

export interface WalletFlowEventInteraction {
  kind: WalletFlowInteractionKind;
  overlay: WalletFlowOverlayIntent;
}

export interface WalletFlowEventError {
  code?: string;
  message: string;
  retryable?: boolean;
}

export interface WalletFlowEventBase<
  TFlow extends WalletFlow = WalletFlow,
  TPhase extends string = string,
> {
  version: typeof WALLET_FLOW_EVENT_VERSION;
  flow: TFlow;
  step: number;
  phase: TPhase;
  status: WalletFlowEventStatus;
  message: string;
  flowId: string;
  requestId?: string;
  accountId?: string;
  authMethod?: WalletFlowAuthMethod;
  interaction?: WalletFlowEventInteraction;
  data?: Record<string, unknown>;
  error?: WalletFlowEventError;
}

export enum RegistrationEventPhase {
  STEP_01_STARTED = 'registration.started',
  STEP_02_ACCOUNT_PREFLIGHT_STARTED = 'registration.account.preflight.started',
  STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED = 'registration.account.preflight.succeeded',
  STEP_03_SESSION_EXCHANGE_STARTED = 'registration.session.exchange.started',
  STEP_03_SESSION_EXCHANGE_SUCCEEDED = 'registration.session.exchange.succeeded',
  STEP_04_PASSKEY_CREATE_STARTED = 'registration.auth.passkey.create.started',
  STEP_04_PASSKEY_CREATE_SUCCEEDED = 'registration.auth.passkey.create.succeeded',
  STEP_04_OTP_CHALLENGE_STARTED = 'registration.otp.challenge.started',
  STEP_04_OTP_CHALLENGE_SENT = 'registration.otp.challenge.sent',
  STEP_04_OTP_INPUT_REQUIRED = 'registration.otp.input.required',
  STEP_04_OTP_VERIFY_STARTED = 'registration.otp.verify.started',
  STEP_04_OTP_VERIFY_SUCCEEDED = 'registration.otp.verify.succeeded',
  STEP_05_ED25519_SIGNER_PREPARE_STARTED = 'registration.signer.ed25519.prepare.started',
  STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED = 'registration.signer.ed25519.prepare.succeeded',
  STEP_05_ED25519_SIGNER_PROVISION_STARTED = 'registration.signer.ed25519.provision.started',
  STEP_05_ED25519_SIGNER_PROVISION_SUCCEEDED = 'registration.signer.ed25519.provision.succeeded',
  STEP_05_ED25519_SIGNER_PROVISION_SKIPPED = 'registration.signer.ed25519.provision.skipped',
  STEP_06_RELAY_BOOTSTRAP_STARTED = 'registration.relay.bootstrap.started',
  STEP_06_RELAY_BOOTSTRAP_SUCCEEDED = 'registration.relay.bootstrap.succeeded',
  STEP_07_ACCOUNT_VERIFY_STARTED = 'registration.account.verify.started',
  STEP_07_ACCOUNT_VERIFY_SUCCEEDED = 'registration.account.verify.succeeded',
  STEP_08_STORAGE_PERSIST_STARTED = 'registration.storage.persist.started',
  STEP_08_STORAGE_PERSIST_SUCCEEDED = 'registration.storage.persist.succeeded',
  STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED = 'registration.signer.email_otp.enroll.started',
  STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED = 'registration.signer.email_otp.enroll.succeeded',
  STEP_10_ECDSA_SIGNER_PROVISION_STARTED = 'registration.signer.ecdsa.provision.started',
  STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED = 'registration.signer.ecdsa.provision.succeeded',
  STEP_10_ECDSA_SIGNER_PROVISION_SKIPPED = 'registration.signer.ecdsa.provision.skipped',
  STEP_10_ECDSA_SIGNER_BOOTSTRAP_STARTED = 'registration.signer.ecdsa.bootstrap.started',
  STEP_10_ECDSA_SIGNER_BOOTSTRAP_SUCCEEDED = 'registration.signer.ecdsa.bootstrap.succeeded',
  STEP_11_COMPLETED = 'registration.completed',
  FAILED = 'registration.failed',
  CANCELLED = 'registration.cancelled',
}

export enum UnlockEventPhase {
  STEP_01_STARTED = 'unlock.started',
  STEP_02_ACCOUNT_LOOKUP_STARTED = 'unlock.account.lookup.started',
  STEP_02_ACCOUNT_LOOKUP_SUCCEEDED = 'unlock.account.lookup.succeeded',
  STEP_03_PASSKEY_CHALLENGE_STARTED = 'unlock.auth.passkey.challenge.started',
  STEP_03_PASSKEY_PROMPT_STARTED = 'unlock.auth.passkey.prompt.started',
  STEP_03_PASSKEY_PROMPT_SUCCEEDED = 'unlock.auth.passkey.prompt.succeeded',
  STEP_03_EMAIL_OTP_CHALLENGE_STARTED = 'unlock.auth.email_otp.challenge.started',
  STEP_03_EMAIL_OTP_CHALLENGE_SENT = 'unlock.auth.email_otp.challenge.sent',
  STEP_03_EMAIL_OTP_INPUT_REQUIRED = 'unlock.auth.email_otp.input.required',
  STEP_03_EMAIL_OTP_VERIFY_STARTED = 'unlock.auth.email_otp.verify.started',
  STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED = 'unlock.auth.email_otp.verify.succeeded',
  STEP_04_APP_SESSION_EXCHANGE_STARTED = 'unlock.app_session.exchange.started',
  STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED = 'unlock.app_session.exchange.succeeded',
  STEP_04_APP_SESSION_EXCHANGE_SKIPPED = 'unlock.app_session.exchange.skipped',
  STEP_05_SIGNING_SESSION_WARMUP_STARTED = 'unlock.signing_session.warmup.started',
  STEP_05_ED25519_SIGNING_SESSION_READY = 'unlock.signing_session.ed25519.ready',
  STEP_05_ECDSA_SIGNING_SESSION_READY = 'unlock.signing_session.ecdsa.ready',
  STEP_06_SESSION_READY = 'unlock.session.ready',
  STEP_07_COMPLETED = 'unlock.completed',
  FAILED = 'unlock.failed',
  CANCELLED = 'unlock.cancelled',
}

export enum SigningEventPhase {
  STEP_01_STARTED = 'signing.started',
  STEP_02_REQUEST_PREPARED = 'signing.request.prepared',
  STEP_03_NONCE_RESERVE_STARTED = 'signing.nonce.reserve.started',
  STEP_03_NONCE_RESERVE_SUCCEEDED = 'signing.nonce.reserve.succeeded',
  STEP_04_ACCOUNT_READINESS_STARTED = 'signing.account.readiness.started',
  STEP_04_ACCOUNT_READINESS_SUCCEEDED = 'signing.account.readiness.succeeded',
  STEP_04_ACCOUNT_READINESS_SKIPPED = 'signing.account.readiness.skipped',
  STEP_05_CONFIRMATION_DISPLAYED = 'signing.confirmation.displayed',
  STEP_05_CONFIRMATION_APPROVED = 'signing.confirmation.approved',
  STEP_05_CONFIRMATION_CANCELLED = 'signing.confirmation.cancelled',
  STEP_06_AUTH_WARM_SESSION_CLAIMED = 'signing.auth.warm_session.claimed',
  STEP_06_AUTH_PASSKEY_PROMPT_STARTED = 'signing.auth.passkey.prompt.started',
  STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED = 'signing.auth.passkey.prompt.succeeded',
  STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED = 'signing.auth.email_otp.challenge.started',
  STEP_06_AUTH_EMAIL_OTP_CHALLENGE_SENT = 'signing.auth.email_otp.challenge.sent',
  STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED = 'signing.auth.email_otp.input.required',
  STEP_06_AUTH_EMAIL_OTP_VERIFY_STARTED = 'signing.auth.email_otp.verify.started',
  STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED = 'signing.auth.email_otp.verify.succeeded',
  STEP_07_AUTHENTICATION_COMPLETE = 'signing.authentication.complete',
  STEP_08_SIGNER_PREPARE_STARTED = 'signing.signer.prepare.started',
  STEP_08_SIGNER_PREPARE_SUCCEEDED = 'signing.signer.prepare.succeeded',
  STEP_08_PRESIGN_REFILL_SCHEDULED = 'signing.presign.refill.scheduled',
  STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED = 'signing.threshold_session.reconnect.started',
  STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED = 'signing.threshold_session.reconnect.succeeded',
  STEP_10_COMMIT_QUEUED = 'signing.commit.queued',
  STEP_10_COMMIT_STARTED = 'signing.commit.started',
  STEP_10_COMMIT_SUCCEEDED = 'signing.commit.succeeded',
  STEP_11_TRANSACTION_SIGNED = 'signing.transaction.signed',
  STEP_12_BROADCAST_STARTED = 'signing.broadcast.started',
  STEP_12_BROADCAST_ACCEPTED = 'signing.broadcast.accepted',
  STEP_12_BROADCAST_REJECTED = 'signing.broadcast.rejected',
  STEP_13_NONCE_RECONCILE_STARTED = 'signing.nonce.reconcile.started',
  STEP_13_NONCE_RECONCILE_SUCCEEDED = 'signing.nonce.reconcile.succeeded',
  STEP_13_RECEIPT_FINALIZED = 'signing.receipt.finalized',
  STEP_13_RECEIPT_REVERTED = 'signing.receipt.reverted',
  STEP_13_TRANSACTION_DROPPED = 'signing.transaction.dropped',
  STEP_13_TRANSACTION_REPLACED = 'signing.transaction.replaced',
  STEP_13_BROADCAST_SKIPPED = 'signing.broadcast.skipped',
  STEP_14_APP_STATE_SYNC_STARTED = 'signing.app_state.sync.started',
  STEP_14_APP_STATE_SYNC_SUCCEEDED = 'signing.app_state.sync.succeeded',
  STEP_15_COMPLETED = 'signing.completed',
  FAILED = 'signing.failed',
  CANCELLED = 'signing.cancelled',
}

export enum LinkDeviceEventPhase {
  STEP_01_QR_PREPARE_STARTED = 'link_device.qr.prepare.started',
  STEP_02_QR_SCAN_STARTED = 'link_device.qr.scan.started',
  FAILED = 'link_device.failed',
  CANCELLED = 'link_device.cancelled',
}

export enum EmailRecoveryFlowEventPhase {
  STEP_01_STARTED = 'email_recovery.started',
  STEP_02_ACCOUNT_LOOKUP_STARTED = 'email_recovery.account.lookup.started',
  STEP_02_ACCOUNT_LOOKUP_SUCCEEDED = 'email_recovery.account.lookup.succeeded',
  STEP_03_PASSKEY_CREATE_STARTED = 'email_recovery.auth.passkey.create.started',
  STEP_03_PASSKEY_CREATE_SUCCEEDED = 'email_recovery.auth.passkey.create.succeeded',
  STEP_04_EMAIL_LINK_SENT = 'email_recovery.email.link.sent',
  STEP_04_EMAIL_LINK_WAITING = 'email_recovery.email.link.waiting',
  STEP_05_RECOVERY_KEY_POLL_STARTED = 'email_recovery.recovery_key.poll.started',
  STEP_05_RECOVERY_KEY_POLL_DETECTED = 'email_recovery.recovery_key.poll.detected',
  STEP_06_FINALIZE_STARTED = 'email_recovery.finalize.started',
  STEP_06_FINALIZE_SUCCEEDED = 'email_recovery.finalize.succeeded',
  STEP_06_AUTO_UNLOCK_SKIPPED = 'email_recovery.auto_unlock.skipped',
  STEP_07_COMPLETED = 'email_recovery.completed',
  STEP_00_RESUMED_PENDING = 'email_recovery.resumed.pending',
  FAILED = 'email_recovery.failed',
  CANCELLED = 'email_recovery.cancelled',
}

export enum AccountSyncEventPhase {
  STEP_01_STARTED = 'account_sync.started',
  STEP_02_PASSKEY_PROMPT_STARTED = 'account_sync.auth.passkey.prompt.started',
  STEP_02_PASSKEY_PROMPT_SUCCEEDED = 'account_sync.auth.passkey.prompt.succeeded',
  STEP_03_RELAY_VERIFY_STARTED = 'account_sync.relay.verify.started',
  STEP_03_RELAY_VERIFY_SUCCEEDED = 'account_sync.relay.verify.succeeded',
  STEP_04_AUTHENTICATOR_SAVED = 'account_sync.authenticator.saved',
  STEP_05_THRESHOLD_SESSION_READY = 'account_sync.threshold_session.ready',
  STEP_06_COMPLETED = 'account_sync.completed',
  FAILED = 'account_sync.failed',
  CANCELLED = 'account_sync.cancelled',
}

export enum KeyExportEventPhase {
  STEP_01_STARTED = 'key_export.started',
  STEP_02_AUTH_PASSKEY_PROMPT_STARTED = 'key_export.auth.passkey.prompt.started',
  STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED = 'key_export.auth.passkey.prompt.succeeded',
  STEP_03_MATERIAL_PREPARE_STARTED = 'key_export.material.prepare.started',
  STEP_03_MATERIAL_PREPARE_SUCCEEDED = 'key_export.material.prepare.succeeded',
  STEP_04_VIEWER_OPENED = 'key_export.viewer.opened',
  STEP_05_VIEWER_CLOSED = 'key_export.viewer.closed',
  STEP_06_COMPLETED = 'key_export.completed',
  FAILED = 'key_export.failed',
  CANCELLED = 'key_export.cancelled',
}

export type WalletFlowEventPhase =
  | RegistrationEventPhase
  | UnlockEventPhase
  | SigningEventPhase
  | LinkDeviceEventPhase
  | EmailRecoveryFlowEventPhase
  | AccountSyncEventPhase
  | KeyExportEventPhase;

export type RegistrationFlowEvent = WalletFlowEventBase<'registration', RegistrationEventPhase>;
export type UnlockFlowEvent = WalletFlowEventBase<'unlock', UnlockEventPhase>;
export type SigningFlowEvent = WalletFlowEventBase<'signing', SigningEventPhase>;
export type LinkDeviceFlowEvent = WalletFlowEventBase<'link_device', LinkDeviceEventPhase>;
export type EmailRecoveryFlowEvent = WalletFlowEventBase<
  'email_recovery',
  EmailRecoveryFlowEventPhase
>;
export type AccountSyncFlowEvent = WalletFlowEventBase<'account_sync', AccountSyncEventPhase>;
export type KeyExportFlowEvent = WalletFlowEventBase<'key_export', KeyExportEventPhase>;

export type WalletFlowEvent =
  | RegistrationFlowEvent
  | UnlockFlowEvent
  | SigningFlowEvent
  | LinkDeviceFlowEvent
  | EmailRecoveryFlowEvent
  | AccountSyncFlowEvent
  | KeyExportFlowEvent;

export const WALLET_FLOW_EVENT_STEPS: Record<WalletFlowEventPhase, number> = {
  [RegistrationEventPhase.STEP_01_STARTED]: 1,
  [RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_STARTED]: 2,
  [RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED]: 2,
  [RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_STARTED]: 3,
  [RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED]: 3,
  [RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED]: 4,
  [RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED]: 4,
  [RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED]: 4,
  [RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT]: 4,
  [RegistrationEventPhase.STEP_04_OTP_INPUT_REQUIRED]: 4,
  [RegistrationEventPhase.STEP_04_OTP_VERIFY_STARTED]: 4,
  [RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED]: 4,
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED]: 5,
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED]: 5,
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_STARTED]: 5,
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_SUCCEEDED]: 5,
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_SKIPPED]: 5,
  [RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_STARTED]: 6,
  [RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_SUCCEEDED]: 6,
  [RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_STARTED]: 7,
  [RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED]: 7,
  [RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED]: 8,
  [RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED]: 8,
  [RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED]: 9,
  [RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED]: 9,
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED]: 10,
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED]: 10,
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SKIPPED]: 10,
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_BOOTSTRAP_STARTED]: 10,
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_BOOTSTRAP_SUCCEEDED]: 10,
  [RegistrationEventPhase.STEP_11_COMPLETED]: 11,
  [RegistrationEventPhase.FAILED]: 0,
  [RegistrationEventPhase.CANCELLED]: 0,
  [UnlockEventPhase.STEP_01_STARTED]: 1,
  [UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED]: 2,
  [UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED]: 2,
  [UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED]: 3,
  [UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED]: 3,
  [UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED]: 3,
  [UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED]: 3,
  [UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT]: 3,
  [UnlockEventPhase.STEP_03_EMAIL_OTP_INPUT_REQUIRED]: 3,
  [UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED]: 3,
  [UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED]: 3,
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED]: 4,
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED]: 4,
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED]: 4,
  [UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED]: 5,
  [UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY]: 5,
  [UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY]: 5,
  [UnlockEventPhase.STEP_06_SESSION_READY]: 6,
  [UnlockEventPhase.STEP_07_COMPLETED]: 7,
  [UnlockEventPhase.FAILED]: 0,
  [UnlockEventPhase.CANCELLED]: 0,
  [SigningEventPhase.STEP_01_STARTED]: 1,
  [SigningEventPhase.STEP_02_REQUEST_PREPARED]: 2,
  [SigningEventPhase.STEP_03_NONCE_RESERVE_STARTED]: 3,
  [SigningEventPhase.STEP_03_NONCE_RESERVE_SUCCEEDED]: 3,
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED]: 4,
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_SUCCEEDED]: 4,
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_SKIPPED]: 4,
  [SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED]: 5,
  [SigningEventPhase.STEP_05_CONFIRMATION_APPROVED]: 5,
  [SigningEventPhase.STEP_05_CONFIRMATION_CANCELLED]: 5,
  [SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED]: 6,
  [SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED]: 6,
  [SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED]: 6,
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED]: 6,
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_SENT]: 6,
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED]: 6,
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_STARTED]: 6,
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED]: 6,
  [SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE]: 7,
  [SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED]: 8,
  [SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED]: 8,
  [SigningEventPhase.STEP_08_PRESIGN_REFILL_SCHEDULED]: 8,
  [SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED]: 9,
  [SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED]: 9,
  [SigningEventPhase.STEP_10_COMMIT_QUEUED]: 10,
  [SigningEventPhase.STEP_10_COMMIT_STARTED]: 10,
  [SigningEventPhase.STEP_10_COMMIT_SUCCEEDED]: 10,
  [SigningEventPhase.STEP_11_TRANSACTION_SIGNED]: 11,
  [SigningEventPhase.STEP_12_BROADCAST_STARTED]: 12,
  [SigningEventPhase.STEP_12_BROADCAST_ACCEPTED]: 12,
  [SigningEventPhase.STEP_12_BROADCAST_REJECTED]: 12,
  [SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED]: 13,
  [SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED]: 13,
  [SigningEventPhase.STEP_13_RECEIPT_FINALIZED]: 13,
  [SigningEventPhase.STEP_13_RECEIPT_REVERTED]: 13,
  [SigningEventPhase.STEP_13_TRANSACTION_DROPPED]: 13,
  [SigningEventPhase.STEP_13_TRANSACTION_REPLACED]: 13,
  [SigningEventPhase.STEP_13_BROADCAST_SKIPPED]: 13,
  [SigningEventPhase.STEP_14_APP_STATE_SYNC_STARTED]: 14,
  [SigningEventPhase.STEP_14_APP_STATE_SYNC_SUCCEEDED]: 14,
  [SigningEventPhase.STEP_15_COMPLETED]: 15,
  [SigningEventPhase.FAILED]: 0,
  [SigningEventPhase.CANCELLED]: 0,
  [LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED]: 1,
  [LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED]: 2,
  [LinkDeviceEventPhase.FAILED]: 0,
  [LinkDeviceEventPhase.CANCELLED]: 0,
  [EmailRecoveryFlowEventPhase.STEP_01_STARTED]: 1,
  [EmailRecoveryFlowEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED]: 2,
  [EmailRecoveryFlowEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED]: 2,
  [EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_STARTED]: 3,
  [EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_SUCCEEDED]: 3,
  [EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_SENT]: 4,
  [EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_WAITING]: 4,
  [EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_STARTED]: 5,
  [EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_DETECTED]: 5,
  [EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_STARTED]: 6,
  [EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_SUCCEEDED]: 6,
  [EmailRecoveryFlowEventPhase.STEP_06_AUTO_UNLOCK_SKIPPED]: 6,
  [EmailRecoveryFlowEventPhase.STEP_07_COMPLETED]: 7,
  [EmailRecoveryFlowEventPhase.STEP_00_RESUMED_PENDING]: 0,
  [EmailRecoveryFlowEventPhase.FAILED]: 0,
  [EmailRecoveryFlowEventPhase.CANCELLED]: 0,
  [AccountSyncEventPhase.STEP_01_STARTED]: 1,
  [AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED]: 2,
  [AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_SUCCEEDED]: 2,
  [AccountSyncEventPhase.STEP_03_RELAY_VERIFY_STARTED]: 3,
  [AccountSyncEventPhase.STEP_03_RELAY_VERIFY_SUCCEEDED]: 3,
  [AccountSyncEventPhase.STEP_04_AUTHENTICATOR_SAVED]: 4,
  [AccountSyncEventPhase.STEP_05_THRESHOLD_SESSION_READY]: 5,
  [AccountSyncEventPhase.STEP_06_COMPLETED]: 6,
  [AccountSyncEventPhase.FAILED]: 0,
  [AccountSyncEventPhase.CANCELLED]: 0,
  [KeyExportEventPhase.STEP_01_STARTED]: 1,
  [KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED]: 2,
  [KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED]: 2,
  [KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED]: 3,
  [KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED]: 3,
  [KeyExportEventPhase.STEP_04_VIEWER_OPENED]: 4,
  [KeyExportEventPhase.STEP_05_VIEWER_CLOSED]: 5,
  [KeyExportEventPhase.STEP_06_COMPLETED]: 6,
  [KeyExportEventPhase.FAILED]: 0,
  [KeyExportEventPhase.CANCELLED]: 0,
};

export const WALLET_FLOW_EVENT_MESSAGES: Record<WalletFlowEventPhase, string> = {
  [RegistrationEventPhase.STEP_01_STARTED]: 'Starting registration',
  [RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_STARTED]: 'Checking account details',
  [RegistrationEventPhase.STEP_02_ACCOUNT_PREFLIGHT_SUCCEEDED]: 'Account details ready',
  [RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_STARTED]: 'Checking registration session',
  [RegistrationEventPhase.STEP_03_SESSION_EXCHANGE_SUCCEEDED]: 'Registration session ready',
  [RegistrationEventPhase.STEP_04_PASSKEY_CREATE_STARTED]: 'Create your passkey',
  [RegistrationEventPhase.STEP_04_PASSKEY_CREATE_SUCCEEDED]: 'Passkey created',
  [RegistrationEventPhase.STEP_04_OTP_CHALLENGE_STARTED]: 'Sending registration email code',
  [RegistrationEventPhase.STEP_04_OTP_CHALLENGE_SENT]: 'Registration email code sent',
  [RegistrationEventPhase.STEP_04_OTP_INPUT_REQUIRED]: 'Enter the registration code',
  [RegistrationEventPhase.STEP_04_OTP_VERIFY_STARTED]: 'Verifying registration code',
  [RegistrationEventPhase.STEP_04_OTP_VERIFY_SUCCEEDED]: 'Registration email verified',
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_STARTED]: 'Preparing NEAR signer',
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PREPARE_SUCCEEDED]: 'NEAR signer ready',
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_STARTED]: 'Preparing NEAR signer',
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_SUCCEEDED]: 'NEAR signer ready',
  [RegistrationEventPhase.STEP_05_ED25519_SIGNER_PROVISION_SKIPPED]: 'NEAR signer setup skipped',
  [RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_STARTED]: 'Creating wallet account',
  [RegistrationEventPhase.STEP_06_RELAY_BOOTSTRAP_SUCCEEDED]: 'Wallet account created',
  [RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_STARTED]: 'Verifying wallet account',
  [RegistrationEventPhase.STEP_07_ACCOUNT_VERIFY_SUCCEEDED]: 'Wallet account verified',
  [RegistrationEventPhase.STEP_08_STORAGE_PERSIST_STARTED]: 'Saving wallet metadata',
  [RegistrationEventPhase.STEP_08_STORAGE_PERSIST_SUCCEEDED]: 'Wallet metadata saved',
  [RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_STARTED]:
    'Securing Email OTP registration',
  [RegistrationEventPhase.STEP_09_EMAIL_OTP_SIGNER_ENROLL_SUCCEEDED]:
    'Email OTP registration secured',
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_STARTED]: 'Preparing EVM signing session',
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SUCCEEDED]: 'EVM signing session ready',
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_PROVISION_SKIPPED]: 'EVM signer setup skipped',
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_BOOTSTRAP_STARTED]: 'Preparing EVM signer',
  [RegistrationEventPhase.STEP_10_ECDSA_SIGNER_BOOTSTRAP_SUCCEEDED]: 'EVM signer ready',
  [RegistrationEventPhase.STEP_11_COMPLETED]: 'Registration complete',
  [RegistrationEventPhase.FAILED]: 'Registration failed',
  [RegistrationEventPhase.CANCELLED]: 'Registration cancelled',
  [UnlockEventPhase.STEP_01_STARTED]: 'Unlocking wallet',
  [UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED]: 'Finding wallet account',
  [UnlockEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED]: 'Wallet account found',
  [UnlockEventPhase.STEP_03_PASSKEY_CHALLENGE_STARTED]: 'Preparing passkey check',
  [UnlockEventPhase.STEP_03_PASSKEY_PROMPT_STARTED]: 'Confirm with passkey',
  [UnlockEventPhase.STEP_03_PASSKEY_PROMPT_SUCCEEDED]: 'Passkey confirmed',
  [UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_STARTED]: 'Sending email code',
  [UnlockEventPhase.STEP_03_EMAIL_OTP_CHALLENGE_SENT]: 'Email code sent',
  [UnlockEventPhase.STEP_03_EMAIL_OTP_INPUT_REQUIRED]: 'Enter the email code',
  [UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_STARTED]: 'Verifying email code',
  [UnlockEventPhase.STEP_03_EMAIL_OTP_VERIFY_SUCCEEDED]: 'Email verified',
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_STARTED]: 'Creating app session',
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SUCCEEDED]: 'App session ready',
  [UnlockEventPhase.STEP_04_APP_SESSION_EXCHANGE_SKIPPED]: 'App session skipped',
  [UnlockEventPhase.STEP_05_SIGNING_SESSION_WARMUP_STARTED]: 'Preparing transaction signing',
  [UnlockEventPhase.STEP_05_ED25519_SIGNING_SESSION_READY]: 'NEAR signing authorization ready',
  [UnlockEventPhase.STEP_05_ECDSA_SIGNING_SESSION_READY]: 'EVM signing session ready',
  [UnlockEventPhase.STEP_06_SESSION_READY]: 'Wallet session ready',
  [UnlockEventPhase.STEP_07_COMPLETED]: 'Wallet unlocked',
  [UnlockEventPhase.FAILED]: 'Wallet unlock failed',
  [UnlockEventPhase.CANCELLED]: 'Wallet unlock cancelled',
  [SigningEventPhase.STEP_01_STARTED]: 'Preparing transaction',
  [SigningEventPhase.STEP_02_REQUEST_PREPARED]: 'Transaction ready for review',
  [SigningEventPhase.STEP_03_NONCE_RESERVE_STARTED]: 'Reserving nonce',
  [SigningEventPhase.STEP_03_NONCE_RESERVE_SUCCEEDED]: 'Nonce reserved',
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_STARTED]: 'Checking account setup',
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_SUCCEEDED]: 'Account setup verified',
  [SigningEventPhase.STEP_04_ACCOUNT_READINESS_SKIPPED]: 'Account setup check skipped',
  [SigningEventPhase.STEP_05_CONFIRMATION_DISPLAYED]: 'Review transaction',
  [SigningEventPhase.STEP_05_CONFIRMATION_APPROVED]: 'Transaction approved',
  [SigningEventPhase.STEP_05_CONFIRMATION_CANCELLED]: 'Transaction rejected',
  [SigningEventPhase.STEP_06_AUTH_WARM_SESSION_CLAIMED]: 'Signing session authorized',
  [SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_STARTED]: 'Confirm with passkey',
  [SigningEventPhase.STEP_06_AUTH_PASSKEY_PROMPT_SUCCEEDED]: 'Passkey confirmed',
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_STARTED]: 'Sending email code',
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_CHALLENGE_SENT]: 'Email code sent',
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_INPUT_REQUIRED]: 'Enter the email code',
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_STARTED]: 'Verifying email code',
  [SigningEventPhase.STEP_06_AUTH_EMAIL_OTP_VERIFY_SUCCEEDED]: 'Email verified',
  [SigningEventPhase.STEP_07_AUTHENTICATION_COMPLETE]: 'Authentication complete',
  [SigningEventPhase.STEP_08_SIGNER_PREPARE_STARTED]: 'Preparing secure signer',
  [SigningEventPhase.STEP_08_SIGNER_PREPARE_SUCCEEDED]: 'Secure signer ready',
  [SigningEventPhase.STEP_08_PRESIGN_REFILL_SCHEDULED]: 'Preparing future signatures',
  [SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_STARTED]: 'Loading secure signer',
  [SigningEventPhase.STEP_09_THRESHOLD_SESSION_RECONNECT_SUCCEEDED]: 'Secure signer loaded',
  [SigningEventPhase.STEP_10_COMMIT_QUEUED]: 'Waiting to sign',
  [SigningEventPhase.STEP_10_COMMIT_STARTED]: 'Signing transaction',
  [SigningEventPhase.STEP_10_COMMIT_SUCCEEDED]: 'Transaction signature ready',
  [SigningEventPhase.STEP_11_TRANSACTION_SIGNED]: 'Transaction signed',
  [SigningEventPhase.STEP_12_BROADCAST_STARTED]: 'Broadcasting transaction',
  [SigningEventPhase.STEP_12_BROADCAST_ACCEPTED]: 'Transaction submitted',
  [SigningEventPhase.STEP_12_BROADCAST_REJECTED]: 'Transaction broadcast failed',
  [SigningEventPhase.STEP_13_NONCE_RECONCILE_STARTED]: 'Checking nonce state',
  [SigningEventPhase.STEP_13_NONCE_RECONCILE_SUCCEEDED]: 'Nonce state updated',
  [SigningEventPhase.STEP_13_RECEIPT_FINALIZED]: 'Transaction finalized',
  [SigningEventPhase.STEP_13_RECEIPT_REVERTED]: 'Transaction reverted',
  [SigningEventPhase.STEP_13_TRANSACTION_DROPPED]: 'Transaction dropped',
  [SigningEventPhase.STEP_13_TRANSACTION_REPLACED]: 'Transaction replaced',
  [SigningEventPhase.STEP_13_BROADCAST_SKIPPED]: 'Broadcast skipped',
  [SigningEventPhase.STEP_14_APP_STATE_SYNC_STARTED]: 'Refreshing app state',
  [SigningEventPhase.STEP_14_APP_STATE_SYNC_SUCCEEDED]: 'App state refreshed',
  [SigningEventPhase.STEP_15_COMPLETED]: 'Transaction complete',
  [SigningEventPhase.FAILED]: 'Transaction signing failed',
  [SigningEventPhase.CANCELLED]: 'Transaction signing cancelled',
  [LinkDeviceEventPhase.STEP_01_QR_PREPARE_STARTED]: 'Preparing device link',
  [LinkDeviceEventPhase.STEP_02_QR_SCAN_STARTED]: 'Scanning QR code',
  [LinkDeviceEventPhase.FAILED]: 'Device link failed',
  [LinkDeviceEventPhase.CANCELLED]: 'Device link cancelled',
  [EmailRecoveryFlowEventPhase.STEP_01_STARTED]: 'Starting email recovery',
  [EmailRecoveryFlowEventPhase.STEP_02_ACCOUNT_LOOKUP_STARTED]: 'Finding wallet account',
  [EmailRecoveryFlowEventPhase.STEP_02_ACCOUNT_LOOKUP_SUCCEEDED]: 'Wallet account found',
  [EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_STARTED]: 'Create your recovery passkey',
  [EmailRecoveryFlowEventPhase.STEP_03_PASSKEY_CREATE_SUCCEEDED]: 'Recovery passkey created',
  [EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_SENT]: 'Recovery email sent',
  [EmailRecoveryFlowEventPhase.STEP_04_EMAIL_LINK_WAITING]: 'Waiting for email confirmation',
  [EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_STARTED]: 'Checking recovery key status',
  [EmailRecoveryFlowEventPhase.STEP_05_RECOVERY_KEY_POLL_DETECTED]: 'Recovery key confirmed',
  [EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_STARTED]: 'Finalizing recovery',
  [EmailRecoveryFlowEventPhase.STEP_06_FINALIZE_SUCCEEDED]: 'Recovery finalized',
  [EmailRecoveryFlowEventPhase.STEP_06_AUTO_UNLOCK_SKIPPED]: 'Local unlock skipped',
  [EmailRecoveryFlowEventPhase.STEP_07_COMPLETED]: 'Email recovery complete',
  [EmailRecoveryFlowEventPhase.STEP_00_RESUMED_PENDING]: 'Resuming email recovery',
  [EmailRecoveryFlowEventPhase.FAILED]: 'Email recovery failed',
  [EmailRecoveryFlowEventPhase.CANCELLED]: 'Email recovery cancelled',
  [AccountSyncEventPhase.STEP_01_STARTED]: 'Starting account sync',
  [AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_STARTED]: 'Confirm with passkey',
  [AccountSyncEventPhase.STEP_02_PASSKEY_PROMPT_SUCCEEDED]: 'Passkey confirmed',
  [AccountSyncEventPhase.STEP_03_RELAY_VERIFY_STARTED]: 'Verifying account access',
  [AccountSyncEventPhase.STEP_03_RELAY_VERIFY_SUCCEEDED]: 'Account access verified',
  [AccountSyncEventPhase.STEP_04_AUTHENTICATOR_SAVED]: 'Passkey saved locally',
  [AccountSyncEventPhase.STEP_05_THRESHOLD_SESSION_READY]: 'Signing session ready',
  [AccountSyncEventPhase.STEP_06_COMPLETED]: 'Account synced',
  [AccountSyncEventPhase.FAILED]: 'Account sync failed',
  [AccountSyncEventPhase.CANCELLED]: 'Account sync cancelled',
  [KeyExportEventPhase.STEP_01_STARTED]: 'Preparing key export',
  [KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_STARTED]: 'Confirm with passkey',
  [KeyExportEventPhase.STEP_02_AUTH_PASSKEY_PROMPT_SUCCEEDED]: 'Passkey confirmed',
  [KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_STARTED]: 'Preparing key material',
  [KeyExportEventPhase.STEP_03_MATERIAL_PREPARE_SUCCEEDED]: 'Key material ready',
  [KeyExportEventPhase.STEP_04_VIEWER_OPENED]: 'Review private key',
  [KeyExportEventPhase.STEP_05_VIEWER_CLOSED]: 'Key export closed',
  [KeyExportEventPhase.STEP_06_COMPLETED]: 'Key export complete',
  [KeyExportEventPhase.FAILED]: 'Key export failed',
  [KeyExportEventPhase.CANCELLED]: 'Key export cancelled',
};

export type CreateWalletFlowEventInput<
  TFlow extends WalletFlow,
  TPhase extends WalletFlowEventPhase,
> = Omit<WalletFlowEventBase<TFlow, TPhase>, 'version' | 'message' | 'step'> & {
  message?: string;
};

export function createWalletFlowEvent<
  TFlow extends WalletFlow,
  TPhase extends WalletFlowEventPhase,
>(input: CreateWalletFlowEventInput<TFlow, TPhase>): WalletFlowEventBase<TFlow, TPhase> {
  const interaction =
    input.interaction ??
    (input.status === 'failed' || input.status === 'cancelled'
      ? ({ kind: 'none', overlay: 'hide' } satisfies WalletFlowEventInteraction)
      : undefined);

  return {
    ...input,
    ...(interaction ? { interaction } : {}),
    version: WALLET_FLOW_EVENT_VERSION,
    step: WALLET_FLOW_EVENT_STEPS[input.phase],
    message: input.message ?? WALLET_FLOW_EVENT_MESSAGES[input.phase],
  };
}

export type CreateSigningFlowEventInput = Omit<
  CreateWalletFlowEventInput<'signing', SigningEventPhase>,
  'flow'
>;

export type CreateRegistrationFlowEventInput = Omit<
  CreateWalletFlowEventInput<'registration', RegistrationEventPhase>,
  'flow'
>;

export type CreateUnlockFlowEventInput = Omit<
  CreateWalletFlowEventInput<'unlock', UnlockEventPhase>,
  'flow'
>;

export type CreateLinkDeviceFlowEventInput = Omit<
  CreateWalletFlowEventInput<'link_device', LinkDeviceEventPhase>,
  'flow'
>;

export type CreateEmailRecoveryFlowEventInput = Omit<
  CreateWalletFlowEventInput<'email_recovery', EmailRecoveryFlowEventPhase>,
  'flow'
>;

export type CreateAccountSyncFlowEventInput = Omit<
  CreateWalletFlowEventInput<'account_sync', AccountSyncEventPhase>,
  'flow'
>;

export type CreateKeyExportFlowEventInput = Omit<
  CreateWalletFlowEventInput<'key_export', KeyExportEventPhase>,
  'flow'
>;

export function createRegistrationFlowEvent(
  input: CreateRegistrationFlowEventInput,
): RegistrationFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'registration',
  });
}

export function createUnlockFlowEvent(input: CreateUnlockFlowEventInput): UnlockFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'unlock',
  });
}

export function createLinkDeviceFlowEvent(
  input: CreateLinkDeviceFlowEventInput,
): LinkDeviceFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'link_device',
  });
}

export function createEmailRecoveryFlowEvent(
  input: CreateEmailRecoveryFlowEventInput,
): EmailRecoveryFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'email_recovery',
  });
}

export function createAccountSyncFlowEvent(
  input: CreateAccountSyncFlowEventInput,
): AccountSyncFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'account_sync',
  });
}

export function createKeyExportFlowEvent(input: CreateKeyExportFlowEventInput): KeyExportFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'key_export',
  });
}

export function createSigningFlowEvent(input: CreateSigningFlowEventInput): SigningFlowEvent {
  return createWalletFlowEvent({
    ...input,
    flow: 'signing',
  });
}

export function isWalletFlowEvent(value: unknown): value is WalletFlowEvent {
  if (!value || typeof value !== 'object') return false;
  const event = value as Partial<WalletFlowEventBase>;
  return event.version === WALLET_FLOW_EVENT_VERSION && typeof event.flow === 'string';
}

// Base event callback type
export type EventCallback<T> = (event: T) => void;

// Users can still supply a single implementation: (success: boolean, result?: T) => ...
export interface AfterCall<T> {
  (success: true, result: T): void | Promise<void>;
  (success: false, result?: undefined, error?: Error): void | Promise<void>;
}

//////////////////////////////////
/// Hooks Options
//////////////////////////////////

// Function Options
export interface RegistrationHooksOptions {
  onEvent?: EventCallback<RegistrationFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<RegistrationResult>;
  // Signer provisioning options used during registration.
  // When omitted, defaults are taken from
  // `SeamsConfigsReadonly.signing.thresholdEcdsa.provisioningDefaults`.
  signerOptions?: EcdsaSignerProvisioningDefaults;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };
  // Per-call confirmation configuration. When provided, overrides user preferences
  // for this request only (not persisted).
  // Accept partial config so callers can pass minimal overrides like { uiMode: 'drawer' }
  confirmationConfig?: Partial<ConfirmationConfig>;
  /** @internal Wallet-host proof that a registration activation click occurred inside the iframe. */
  walletIframeActivation?: RegistrationActivationProof;
}

export interface LoginHooksOptions {
  onEvent?: EventCallback<UnlockFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<LoginAndCreateSessionResult>;
  unlockSelection?:
    | {
        mode: 'ed25519_only';
        ed25519: true;
        ecdsa?: never;
      }
    | {
        mode: 'ecdsa_only';
        ecdsa: true;
        ed25519?: never;
      }
    | {
        mode: 'ed25519_and_ecdsa';
        ed25519: true;
        ecdsa: true;
      };
  ecdsaKeyFactsInventory?:
    | {
        mode: 'app_session';
        appSessionJwt?: string;
        policyTtlMs?: number;
      }
    | {
        mode: 'webauthn';
      };
  /**
   * Optional signer-slot hint.
   *
   * When multiple signers exist for the same `nearAccountId`, providing this hint lets
   * the login flow prioritize the matching `credentialId` when presenting the TouchID
   * (WebAuthn) prompt.
   */
  signerSlot?: number;
  // Optional: request a server session (JWT in body or HttpOnly cookie)
  session?: {
    // 'jwt' returns the token in the JSON body; 'cookie' sets HttpOnly cookie
    kind: 'jwt' | 'cookie';
    // Optional: override relay URL; defaults to SeamsConfigsReadonly.network.relayer.url
    relayUrl?: string;
    // Optional: override route path.
    // - defaults to '/session/exchange'
    // - must target exchange-capable route when `session` is provided
    route?: string;
    // Required exchange input for `POST /session/exchange`.
    exchange?:
      | {
          // BYO auth: external OIDC token -> relay app session mint
          type: 'oidc_jwt';
          token: string;
        }
      | {
          // One-step passkey unlock + app session mint.
          // SDK obtains challenge + WebAuthn assertion before calling `/session/exchange`.
          type: 'passkey_assertion';
          expectedOrigin?: string;
          expected_origin?: string;
        };
  };
  /**
   * Optional: override the warm signing session policy minted during login.
   * Defaults come from `SeamsConfigsReadonly.signing.sessionDefaults`.
   */
  signingSession?: {
    ttlMs?: number;
    remainingUses?: number;
  };
}

export interface KeyExportHooksOptions {
  onEvent?: EventCallback<KeyExportFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<void>;
}

export interface ActionHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;
  waitUntil?: TxExecutionStatus;
  afterCall?: AfterCall<ActionResult>;
  /**
   * Optional signer-slot override for this signing request.
   */
  signerSlot?: number;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };
  // Per-call confirmation configuration. When provided, overrides user preferences
  // for this request only (not persisted).
  // Accept partial config so callers can pass minimal overrides like { uiMode: 'drawer' }
  confirmationConfig?: Partial<ConfirmationConfig>;
}

export interface SignAndSendTransactionHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;
  waitUntil?: TxExecutionStatus;
  /**
   * Optional signer-slot override for this signing request.
   */
  signerSlot?: number;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };

  afterCall?: AfterCall<ActionResult>;
  // Per-call confirmation configuration. When provided, overrides user preferences
  // for this request only (not persisted).
  // Accept partial config so callers can pass minimal overrides like { uiMode: 'drawer' }
  confirmationConfig?: Partial<ConfirmationConfig>;
}

export interface SignTransactionHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;

  afterCall?: AfterCall<SignTransactionResult>;
  waitUntil?: TxExecutionStatus;
  /**
   * Optional signer-slot override for this signing request.
   */
  signerSlot?: number;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };
  // Per-call confirmation configuration (non-persistent)
  // Accept partial config so callers can pass minimal overrides like { uiMode: 'drawer' }
  confirmationConfig?: Partial<ConfirmationConfig>;
}

export interface SendTransactionHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;

  afterCall?: AfterCall<ActionResult>;
  waitUntil?: TxExecutionStatus;
}

export interface DelegateActionHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;
  waitUntil?: TxExecutionStatus;
  afterCall?: AfterCall<SignDelegateActionResult>;
  /**
   * Optional signer-slot override for this signing request.
   */
  signerSlot?: number;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };
  confirmationConfig?: Partial<ConfirmationConfig>;
}

export interface DelegateRelayHooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;
  afterCall?: AfterCall<DelegateRouterApiResult>;
}

export type SignAndSendDelegateActionHooksOptions = Omit<
  DelegateActionHooksOptions,
  'afterCall'
> & {
  afterCall?: AfterCall<SignAndSendDelegateActionResult>;
};

export interface SyncAccountHooksOptions {
  onEvent?: EventCallback<AccountSyncFlowEvent>;
  onError?: (error: Error) => void;
  waitUntil?: TxExecutionStatus;

  afterCall?: AfterCall<SyncAccountResult>;
}

export interface SignNEP413HooksOptions {
  onEvent?: EventCallback<SigningFlowEvent>;
  onError?: (error: Error) => void;

  afterCall?: AfterCall<SignNEP413MessageResult>;
  /**
   * Optional signer-slot override for this signing request.
   */
  signerSlot?: number;
  /**
   * Preferred grouping for per-call confirmer copy.
   */
  confirmerText?: { title?: string; body?: string };
  // Per-call confirmation configuration (non-persistent)
  // Accept partial config so callers can pass minimal overrides like { uiMode: 'drawer' }
  confirmationConfig?: Partial<ConfirmationConfig>;
}
