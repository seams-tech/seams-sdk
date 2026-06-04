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
import type { NearAccountRef } from './ecdsaChainTarget';
import type {
  EmailOtpStepUpAuthorization,
  PasskeyStepUpAuthorization,
  SigningAuthPlan,
  WarmSessionStepUpAuthorization,
} from '../stepUpConfirmation/types';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type {
  SigningOperationId,
  SigningSessionPlan,
} from '../session/operationState/types';
import type { NearTransactionSigningLane } from '../session/operationState/lanes';
import type { SelectedEd25519Lane } from '../session/identity/laneIdentity';
import type {
  BudgetAdmittedOperation,
  PreparedTransactionOperation,
} from '../session/operationState/transactionState';
import type { ThresholdRuntimePolicyScope } from '../threshold/sessionPolicy';
type NearResolvedEd25519SessionAuth =
  | {
      sessionKind: 'jwt';
      thresholdSessionAuthToken: string;
    }
  | {
      sessionKind: 'cookie';
      thresholdSessionAuthToken?: undefined;
    };

export type NearPasskeyReconnectPlan = {
  sessionId: string;
  walletSigningSessionId: string;
  sessionPolicyDigest32: string;
};

export type NearEd25519WarmSessionStepUpAuthorization = WarmSessionStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'warmSession' }>
>;

export type NearEd25519EmailOtpStepUpAuthorization = EmailOtpStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'emailOtpReauth' }>
>;

export type NearEd25519PasskeyStepUpAuthorization = PasskeyStepUpAuthorization<
  Extract<SigningAuthPlan, { kind: 'passkeyReauth' }>,
  {
    plannedPasskeyReconnect: NearPasskeyReconnectPlan;
  }
>;

export type NearEd25519StepUpAuthorization =
  | NearEd25519WarmSessionStepUpAuthorization
  | NearEd25519EmailOtpStepUpAuthorization
  | NearEd25519PasskeyStepUpAuthorization;

export type NearResolvedEd25519SigningSessionState = NearResolvedEd25519SessionAuth & {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  signingLane: NearTransactionSigningLane;
  remainingUses: number;
  xClientBaseB64u?: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  signingRootId: string;
  relayerUrl: string;
  persistClientBase: (xClientBaseB64u: string) => boolean;
};

export type NearEmailOtpSigningHook = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  resend?: (args: { requiredSignatureUses: number }) => Promise<{
    challengeId: string;
    emailHint?: string;
  }>;
  complete: (
    authorization: NearEd25519EmailOtpStepUpAuthorization,
  ) => Promise<{ sessionId: string; sessionState?: NearResolvedEd25519SigningSessionState }>;
};

export type NearEd25519WarmupHook = {
  isPending: () => boolean;
  waitForReady: () => Promise<boolean>;
};

export type NearPasskeyEd25519ReconnectHook = {
  prepare: (args: { requiredSignatureUses: number }) => Promise<{
    sessionId: string;
    walletSigningSessionId: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    authorization: NearEd25519PasskeyStepUpAuthorization;
    requiredSignatureUses: number;
  }) => Promise<{ sessionId: string; sessionState?: NearResolvedEd25519SigningSessionState }>;
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
  signingSessionPlan: SigningSessionPlan;
  signingAuthPlan: SigningAuthPlan;
  signingLane: NearTransactionSigningLane;
  initialBudgetAdmittedOperation: BudgetAdmittedOperation<SelectedEd25519Lane> | null;
};

export type NearEd25519TransactionSigningBoundary = NearEd25519TransactionAdmissionBoundary;

export type NearTransactionsWithActionsPayload = {
  ctx: NearSigningRuntimeDeps;
  nearAccount: NearAccountRef;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  emailOtpSigning?: NearEmailOtpSigningHook;
  signingOperationId?: SigningOperationId;
  signingSessionCoordinator: SigningSessionCoordinator;
  transactionOperation: PreparedTransactionOperation<SelectedEd25519Lane>;
  ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  ed25519Warmup?: NearEd25519WarmupHook;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
  sensitivePolicy?: SensitiveOperationPolicy;
};

export type NearDelegateActionPayload = {
  ctx: NearSigningRuntimeDeps;
  nearAccount: NearAccountRef;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  onEvent?: (update: SigningFlowEvent) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  sessionId?: string;
  signerSlot?: number;
};

export type NearNep413Payload = {
  ctx: NearSigningRuntimeDeps;
  nearAccount: NearAccountRef;
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
    sessionId?: string;
  };
};

export type NearSigningRequest =
  | {
      chain: 'near';
      kind: 'transactionsWithActions';
      payload: NearTransactionsWithActionsPayload;
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
      kind: 'near-transactions-with-actions';
      algorithm: 'ed25519';
      payload: NearTransactionsWithActionsPayload;
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

export type NearTransactionsWithActionsResult = Array<{
  signedTransaction: SignedTransaction;
  nearAccountId: AccountId;
  logs?: string[];
}>;

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
      kind: 'near-transactions-with-actions';
      result: NearTransactionsWithActionsResult;
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
  transactionsWithActions: NearTransactionsWithActionsResult;
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
      kind: 'transactionsWithActions';
      nearAccountId: string;
      transactionCount: number;
      totalActionCount: number;
      txSigningRequests: TransactionPayload[];
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
