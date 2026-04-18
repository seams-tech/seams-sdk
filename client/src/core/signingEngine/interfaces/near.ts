import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  TransactionPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { SigningRuntimeDeps } from './runtime';
import type { WalletAuthPlan } from '../auth';

export type NearEmailOtpSigningHook = {
  challengeId: string;
  emailHint?: string;
  complete: (otpCode: string) => Promise<{ sessionId: string }>;
  markConsumed?: (thresholdSessionId?: string) => void;
};

export type NearTransactionsWithActionsPayload = {
  ctx: SigningRuntimeDeps;
  sessionId?: string;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signerSlot?: number;
  emailOtpSigning?: NearEmailOtpSigningHook;
  walletAuthPlan?: WalletAuthPlan;
};

export type NearDelegateActionPayload = {
  ctx: SigningRuntimeDeps;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  onEvent?: (update: onProgressEvents) => void;
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
