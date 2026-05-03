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
import type { SigningRuntimeDeps } from './runtime';
import type { SigningAuthPlan } from '../touchConfirm/shared/confirmTypes';
import type { SensitiveOperationPolicy } from '@shared/utils/signerDomain';
import type { WebAuthnAuthenticationCredential } from '@/core/types';
import type { SigningSessionCoordinator } from '../session/SigningSessionCoordinator';
import type { SigningLaneContext, SigningOperationId } from '../session/signingSession/types';
import type { ThresholdEd25519SessionRecord } from '../api/thresholdLifecycle/thresholdSessionStore';
import type {
  BudgetAdmittedOperation,
  NearEd25519TransactionLane,
  PreparedTransactionOperation,
} from '../session/signingSession/transactionState';

export type NearEmailOtpSigningHook = {
  prepare: () => Promise<{ challengeId: string; emailHint?: string }>;
  resend?: () => Promise<{ challengeId: string; emailHint?: string }>;
  complete: (
    otpCode: string,
    challengeId?: string,
  ) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
};

export type NearEd25519WarmupHook = {
  isPending: () => boolean;
  waitForReady: () => Promise<boolean>;
};

export type NearPasskeyEd25519ReconnectHook = {
  prepare?: (args: { usesNeeded: number }) => Promise<{
    sessionId: string;
    walletSigningSessionId?: string;
    sessionPolicyDigest32: string;
  }>;
  reconnect: (args: {
    credential: WebAuthnAuthenticationCredential;
    usesNeeded: number;
    sessionId?: string;
    walletSigningSessionId?: string;
  }) => Promise<{ sessionId: string; record?: ThresholdEd25519SessionRecord }>;
};

export type NearSigningSessionFinalizationHook = {
  recordSuccess: (args?: { alreadyConsumedThresholdSessionIds?: string[] }) => Promise<void>;
  recordZeroSpend: (error: unknown) => Promise<void> | void;
};

export type NearPreparedSigningSessionFinalizer = (args: {
  status: 'success' | 'zero_spend';
  hooks: NearSigningSessionFinalizationHook;
  result?: unknown;
  error?: unknown;
}) => Promise<void>;

export type NearEd25519TransactionAdmissionBoundary =
  {
    sessionId: string;
    signingAuthPlan: SigningAuthPlan;
    signingLane: SigningLaneContext;
    initialBudgetAdmittedOperation: BudgetAdmittedOperation<NearEd25519TransactionLane> | null;
  };

export type NearEd25519TransactionSigningBoundary = NearEd25519TransactionAdmissionBoundary;

export type NearTransactionsWithActionsPayload = {
  ctx: SigningRuntimeDeps;
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
  transactionOperation: PreparedTransactionOperation<NearEd25519TransactionLane>;
  ed25519SigningBoundary: NearEd25519TransactionSigningBoundary;
  finalizePreparedSigningSession?: NearPreparedSigningSessionFinalizer;
  ed25519Warmup?: NearEd25519WarmupHook;
  passkeyEd25519Reconnect?: NearPasskeyEd25519ReconnectHook;
  sensitivePolicy?: SensitiveOperationPolicy;
};

export type NearDelegateActionPayload = {
  ctx: SigningRuntimeDeps;
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
  ctx: SigningRuntimeDeps;
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
