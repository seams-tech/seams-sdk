import type {
  SigningEnginePublic,
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../signingEngine/SigningEngine';
import type { NearClient, SignedTransaction } from '../rpcClients/near/NearClient';
import type {
  ActionResult,
  DelegateRelayResult,
  GetRecentLoginsResult,
  LoginAndCreateSessionResult,
  LoginSession,
  RegistrationResult,
  SignAndSendDelegateActionResult,
  SignDelegateActionResult,
  SignTransactionResult,
  ThemeName,
  TatchiConfigs,
} from '../types/tatchi';
import type {
  ActionHooksOptions,
  DelegateActionHooksOptions,
  DelegateRelayHooksOptions,
  LoginHooksOptions,
  RegistrationHooksOptions,
  SendTransactionHooksOptions,
  SignAndSendDelegateActionHooksOptions,
  SignAndSendTransactionHooksOptions,
  SignNEP413HooksOptions,
  SignTransactionHooksOptions,
  SyncAccountHooksOptions,
} from '../types/sdkSentEvents';
import type {
  ConfirmationBehavior,
  ConfirmationConfig,
  SignerMode,
  WasmSignedDelegate,
} from '../types/signer-worker';
import type { AccountId } from '../types/accountIds';
import type { ActionArgs, TransactionInput } from '../types/actions';
import type { DelegateActionInput, SignedDelegate } from '../types/delegate';
import type {
  MultichainSigningRequest,
} from '../signingEngine/chainAdaptors/tempo/types';
import type { EvmSignedResult } from '../signingEngine/chainAdaptors/evm/evmAdapter';
import type { TempoSignedResult } from '../signingEngine/chainAdaptors/tempo/tempoAdapter';
import type {
  SignNEP413MessageParams,
  SignNEP413MessageResult,
} from './near/signNEP413';
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
  request: MultichainSigningRequest;
  options?: {
    confirmationConfig?: Partial<ConfirmationConfig>;
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

export type BootstrapThresholdEcdsaSessionArgs = {
  nearAccountId: string;
  options?: {
    chain?: ThresholdEcdsaActivationChain;
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

export interface AuthCapability {
  login(
    nearAccountId: string,
    options?: LoginHooksOptions,
  ): Promise<LoginAndCreateSessionResult>;
  logout(): Promise<void>;
  getSession(nearAccountId?: string): Promise<LoginSession>;
  getRecentLogins(): Promise<GetRecentLoginsResult>;
  hasPasskeyCredential(nearAccountId: AccountId): Promise<boolean>;
}

export interface RegistrationCapability {
  registerPasskey(
    nearAccountId: string,
    options?: RegistrationHooksOptions,
  ): Promise<RegistrationResult>;
  registerPasskeyInternal(
    nearAccountId: string,
    options?: RegistrationHooksOptions,
    confirmationConfigOverride?: ConfirmationConfig,
  ): Promise<RegistrationResult>;
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

export interface TempoSignerCapability {
  signTempo(args: SignTempoArgs): Promise<TempoSignedResult | EvmSignedResult>;
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export interface EvmSignerCapability {
  bootstrapEcdsaSession(
    args: BootstrapThresholdEcdsaSessionArgs,
  ): Promise<ThresholdEcdsaSessionBootstrapResult>;
}

export interface RecoveryCapability {
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
  startDevice2LinkingFlow(
    args: StartDevice2LinkingFlowArgs,
  ): Promise<StartDevice2LinkingFlowResults>;

  stopDevice2LinkingFlow(): Promise<void>;

  linkDeviceWithScannedQRData(
    qrData: DeviceLinkingQRData,
    options: ScanAndLinkDeviceOptionsDevice1,
  ): Promise<LinkDeviceResult>;
}

export type ExportKeypairChain = 'near' | 'evm' | 'tempo';

export interface KeyExportCapability {
  exportKeypairWithUI(
    nearAccountId: string,
    options: {
      chain: ExportKeypairChain;
      variant?: 'drawer' | 'modal';
      theme?: 'dark' | 'light';
    },
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

export interface PasskeyManagerContext {
  signingEngine: SigningEnginePublic;
  nearClient: NearClient;
  configs: TatchiConfigs;
  theme: ThemeName;
}
