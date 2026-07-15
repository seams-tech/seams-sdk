import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { SigningFlowEvent } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  TransactionPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { NearSigningRuntimeDeps } from './runtime';
import type { NearAccountRef, NearCommandSubject } from './ecdsaChainTarget';
import type {
  EmailOtpStepUpAuthorization,
  PasskeyStepUpAuthorization,
  SigningAuthPlan,
  WarmSessionStepUpAuthorization,
} from '../stepUpConfirmation/types';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { SigningOperationId, SigningSessionPlan } from '../session/operationState/types';
import type { NearTransactionSigningLane } from '../session/operationState/lanes';
import type { SelectedEd25519Lane } from '../session/identity/laneIdentity';
import type {
  BudgetAdmittedOperation,
  PreparedTransactionOperation,
} from '../session/operationState/transactionState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
import type { RouterAbEd25519NormalSigningState } from '../threshold/ed25519/routerAbNormalSigningState';
import type { RouterAbEd25519SigningWalletSession } from '../session/routerAbSigningWalletSession';
import type { RouterAbEd25519YaoActiveClientV1 } from '../threshold/ed25519/yaoClient';
export type NearResolvedEd25519WalletSessionAuth = {
  kind: 'wallet_session_jwt';
  walletSessionJwt: string;
};

export type NearPasskeyReconnectPlan = {
  sessionId: string;
  signingGrantId: string;
  sessionPolicyDigest32: string;
};

export type NearEd25519WarmSessionStepUpAuthorization = WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'warmSession' }>
>;

export type NearEd25519PasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>,
  {
    plannedPasskeyReconnect: NearPasskeyReconnectPlan;
  }
>;

export type NearEd25519EmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>
>;

export type NearEd25519StepUpAuthorization =
  | NearEd25519WarmSessionStepUpAuthorization
  | NearEd25519EmailOtpStepUpAuthorization
  | NearEd25519PasskeyStepUpAuthorization;

export type NearResolvedEd25519SigningSessionState = {
  walletSessionAuth: NearResolvedEd25519WalletSessionAuth;
  thresholdSessionId: string;
  signingGrantId: string;
  signingLane: NearTransactionSigningLane;
  remainingUses: number;
  signingRootId: string;
  signingRootVersion: string;
  routerAbNormalSigning: RouterAbEd25519NormalSigningState;
  runtimePolicyScope: ThresholdRuntimePolicyScope;
  relayerUrl: string;
  signingWalletSession: RouterAbEd25519SigningWalletSession;
  sessionKind?: never;
};

export type NearEd25519YaoSigningCapability = {
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
};

export type NearEd25519YaoCapabilitySource =
  | {
      kind: 'active_capability';
      capability: NearEd25519YaoSigningCapability;
      recover?: never;
    }
  | {
      kind: 'capability_recovery';
      recover: () => Promise<NearEd25519YaoSigningCapability>;
      capability?: never;
    }
  | {
      kind: 'email_otp_reconnect';
      capability?: never;
      recover?: never;
    };

export type NearPasskeyEd25519ReconnectHook = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    sessionId: string;
    signingGrantId: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    authorization: NearEd25519PasskeyStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{
    sessionId: string;
    activeClient: RouterAbEd25519YaoActiveClientV1;
    sessionState: NearResolvedEd25519SigningSessionState;
  }>;
};

export type NearEmailOtpEd25519ReconnectHook = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  reconnect: (args: {
    authorization: NearEd25519EmailOtpStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{
    sessionId: string;
    activeClient: RouterAbEd25519YaoActiveClientV1;
    sessionState: NearResolvedEd25519SigningSessionState;
  }>;
};

export type NearSigningSessionFinalizationHook = {
  recordSuccess: () => Promise<void>;
  recordZeroSpend: (error: unknown) => Promise<void> | void;
};

export type NearPreparedSigningSessionFinalizer = (args: {
  status: 'success' | 'zero_spend';
  hooks: NearSigningSessionFinalizationHook;
  result?: unknown;
  error?: unknown;
}) => Promise<void>;

export type NearEd25519TransactionAdmissionBoundary = {
  sessionId: string;
  walletSessionJwt: string;
  signingSessionPlan: SigningSessionPlan;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  initialBudgetAdmittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane> | null;
};

export type NearEd25519TransactionSigningBoundary = NearEd25519TransactionAdmissionBoundary;

export type NearTransactionWithActionsPayload = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  transaction: TransactionInputWasm;
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  signingOperationId?: SigningOperationId;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
  emailOtpEd25519Reconnect?: NearEmailOtpEd25519ReconnectHook;
  sensitivePolicy?: SensitiveOperationPolicy;
  yaoCapabilitySource: NearEd25519YaoCapabilitySource;
};

export type NearDelegateActionPayload = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signingSessionCoordinator: SigningSessionCoordinator;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  operationId: SigningOperationId;
  signerSlot?: number;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
};

export type NearNep413Payload = {
  ctx: NearSigningRuntimeDeps;
  commandSubject: NearCommandSubject;
  nearAccount: NearAccountRef;
  signingSessionCoordinator: SigningSessionCoordinator;
  activeClient: RouterAbEd25519YaoActiveClientV1;
  walletSessionState: NearResolvedEd25519SigningSessionState;
  payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerSlot?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    operationId: SigningOperationId;
    nearRpcUrl?: string;
  };
};

export type NearSigningRequest =
  | {
      chain: 'near';
      kind: 'transactionWithActions';
      payload: NearTransactionWithActionsPayload;
    }
  | {
      chain: 'near';
      kind: 'delegateAction';
      payload: NearDelegateActionPayload;
    }
  | {
      chain: 'near';
      kind: 'nep413';
      payload: NearNep413Payload;
    };

export type NearEd25519SignRequest =
  | {
      kind: 'near-transaction-with-actions';
      algorithm: 'ed25519';
      payload: NearTransactionWithActionsPayload;
    }
  | {
      kind: 'near-delegate-action';
      algorithm: 'ed25519';
      payload: NearDelegateActionPayload;
    }
  | {
      kind: 'near-nep413-message';
      algorithm: 'ed25519';
      payload: NearNep413Payload;
    };

export type NearTransactionWithActionsResult = {
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
};

export type NearDelegateActionResult = {
  signedDelegate: WasmSignedDelegate;
  hash: string;
  nearAccountId: AccountId;
  logs?: string[];
};

export type NearNep413Result = {
  success: boolean;
  accountId: string;
  publicKey: string;
  signature: string;
  state?: string;
  error?: string;
};

export type NearEd25519SignOutput =
  | {
      kind: 'near-transaction-with-actions';
      result: NearTransactionWithActionsResult;
    }
  | {
      kind: 'near-delegate-action';
      result: NearDelegateActionResult;
    }
  | {
      kind: 'near-nep413-message';
      result: NearNep413Result;
    };

export type NearSignedResult = NearEd25519SignOutput['result'];

export type NearIntentResultByKind = {
  transactionWithActions: NearTransactionWithActionsResult;
  delegateAction: NearDelegateActionResult;
  nep413: NearNep413Result;
};

export type NearIntentResult<T extends NearSigningRequest> = T extends { kind: infer K }
  ? K extends keyof NearIntentResultByKind
    ? NearIntentResultByKind[K]
    : never
  : never;

export type NearIntentUiModel =
  | {
      kind: 'transactionWithActions';
      nearAccountId: string;
      totalActionCount: number;
      txSigningRequest: TransactionPayload;
    }
  | {
      kind: 'delegateAction';
      nearAccountId: string;
      receiverId: string;
      actionCount: number;
    }
  | {
      kind: 'nep413';
      nearAccountId: string;
      recipient: string;
    };
