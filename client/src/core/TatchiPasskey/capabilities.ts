import type { SignedTransaction } from '../near/NearClient';
import type {
  ActionResult,
  DelegateRelayResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
} from '../types/tatchi';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SyncAccountHooksOptions,
} from '../types/sdkSentEvents';
import type { ActionArgs, TransactionInput } from '../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../types/delegate';
import type {
  WasmSignedDelegate,
  ConfirmationBehavior,
  ConfirmationConfig,
  SignerMode,
} from '../types/signer-worker';
import type { SignNEP413MessageParams, SignNEP413MessageResult } from './signNEP413';
import type { AccountId } from '../types/accountIds';
import type {
  TempoSecp256k1SigningRequest,
  TempoSigningRequest,
} from '../signing/chainAdaptors/tempo/types';
import type { TempoSignedResult } from '../signing/chainAdaptors/tempo/tempoAdapter';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../signing/orchestration/types';
import type { ThresholdEcdsaSessionBootstrapResult } from '../signing/api/WebAuthnManager';
import type { SyncAccountResult } from './syncAccount';
import type { EmailRecoveryFlowOptions } from '../types/emailRecovery';
import type {
  DeviceLinkingQRData,
  LinkDeviceResult,
  ScanAndLinkDeviceOptionsDevice1,
  StartDevice2LinkingFlowArgs,
  StartDevice2LinkingFlowResults,
} from '../types/linkDevice';

export type SignTempoArgs = {
  nearAccountId: string;
  request: TempoSigningRequest;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
    thresholdEcdsaKeyRef?: ThresholdEcdsaSecp256k1KeyRef;
    /** Internal host-only cancellation probe; ignored in wallet-router calls. */
    shouldAbort?: () => boolean;
    onEvent?: (event: {
      step: number;
      phase: string;
      status: 'progress' | 'success' | 'error';
      message?: string;
      data?: unknown;
    }) => void;
  };
};

export type SignTempoWithThresholdEcdsaArgs = {
  nearAccountId: string;
  request: TempoSecp256k1SigningRequest;
  thresholdEcdsaKeyRef: ThresholdEcdsaSecp256k1KeyRef;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
  };
};

export type BootstrapThresholdEcdsaSessionArgs = {
  nearAccountId: string;
  options?: {
    chain?: 'evm' | 'tempo';
    relayerUrl?: string;
    participantIds?: number[];
    sessionKind?: 'jwt' | 'cookie';
    ttlMs?: number;
    remainingUses?: number;
    smartAccount?: {
      chainId?: string;
      factory?: string;
      entryPoint?: string;
      salt?: string;
      counterfactualAddress?: string;
    };
  };
};

export interface ThresholdSessionBootstrapCapability {
  bootstrapThresholdEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export interface NearSignerCapability {
  executeAction(args: {
    nearAccountId: string;
    receiverId: string;
    actionArgs: ActionArgs | ActionArgs[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  signAndSendTransactions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult[]>;

  signAndSendTransaction(args: {
    nearAccountId: string;
    receiverId: string;
    actions: ActionArgs[];
    options: SignAndSendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signTransactionsWithActions(args: {
    nearAccountId: string;
    transactions: TransactionInput[];
    options: SignTransactionHooksOptions;
  }): Promise<SignTransactionResult[]>;

  sendTransaction(args: {
    signedTransaction: SignedTransaction;
    options?: SendTransactionHooksOptions;
  }): Promise<ActionResult>;

  signDelegateAction(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    options: DelegateActionHooksOptions;
  }): Promise<SignDelegateActionResult>;

  sendDelegateActionViaRelayer(args: {
    relayerUrl: string;
    signedDelegate: SignedDelegate | WasmSignedDelegate;
    hash: string;
    signal?: AbortSignal;
    options?: DelegateRelayHooksOptions;
  }): Promise<DelegateRelayResult>;

  signAndSendDelegateAction(args: {
    nearAccountId: string;
    delegate: DelegateActionInput;
    relayerUrl: string;
    signal?: AbortSignal;
    options: SignAndSendDelegateActionHooksOptions;
  }): Promise<SignAndSendDelegateActionResult>;

  signNEP413Message(args: {
    nearAccountId: string;
    params: SignNEP413MessageParams;
    options: SignNEP413HooksOptions;
  }): Promise<SignNEP413MessageResult>;
}

export interface TempoSignerCapability extends ThresholdSessionBootstrapCapability {
  signTempo(args: SignTempoArgs): Promise<TempoSignedResult>;
  signTempoWithThresholdEcdsa(
    args: SignTempoWithThresholdEcdsaArgs,
  ): Promise<TempoSignedResult>;
}

export interface EvmSignerCapability extends ThresholdSessionBootstrapCapability {}

export interface EmailRecoveryCapability {
  getRecoveryEmails(accountId: string): Promise<Array<{ hashHex: string; email: string }>>;

  setRecoveryEmails(args: {
    accountId: string;
    recoveryEmails: string[];
    options: ActionHooksOptions;
  }): Promise<ActionResult>;

  syncAccount(args: {
    accountId?: string;
    options?: SyncAccountHooksOptions;
  }): Promise<SyncAccountResult>;

  startEmailRecovery(args: {
    accountId: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<{ mailtoUrl: string; nearPublicKey: string }>;

  finalizeEmailRecovery(args: {
    accountId: string;
    nearPublicKey?: string;
    options?: EmailRecoveryFlowOptions;
  }): Promise<void>;

  cancelEmailRecovery(args?: {
    accountId?: string;
    nearPublicKey?: string;
  }): Promise<void>;
}

export interface DeviceLinkingCapability {
  startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults>;

  stopDevice2LinkingFlow(): Promise<void>;

  linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult>;
}

export type RecoveryCapability = EmailRecoveryCapability & DeviceLinkingCapability;

export interface KeyExportCapability {
  exportPrivateKeysWithUI(
    nearAccountId: string,
    options?: {
      schemes?: Array<'ed25519' | 'secp256k1'>;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
  ): Promise<void>;

  exportNearKeypairWithUI(
    nearAccountId: string,
    options?: { variant?: 'drawer' | 'modal'; theme?: 'dark' | 'light' },
  ): Promise<void>;
}

export interface PreferencesCapability {
  setCurrentUser(nearAccountId: AccountId): void;
  getCurrentUserAccountId(): AccountId;
  onConfirmationConfigChange(callback: (config: ConfirmationConfig) => void): () => void;
  onSignerModeChange(callback: (mode: SignerMode) => void): () => void;
  onCurrentUserChange(callback: (nearAccountId: AccountId | null) => void): () => void;
  setConfirmBehavior(behavior: ConfirmationBehavior): void;
  setConfirmationConfig(config: ConfirmationConfig): void;
  getConfirmationConfig(): ConfirmationConfig;
  setSignerMode(signerMode: SignerMode | SignerMode['mode']): void;
  getSignerMode(): SignerMode;
}
