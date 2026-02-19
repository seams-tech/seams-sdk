import type { SignedTransaction } from '@/core/rpcClients/near/NearClient';
import type { AccountId } from '@/core/types/accountIds';
import type { TransactionInputWasm } from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { onProgressEvents } from '@/core/types/sdkSentEvents';
import type {
  ConfirmationConfig,
  RpcCallPayload,
  SignerMode,
  TransactionPayload,
  WasmSignedDelegate,
} from '@/core/types/signer-worker';
import type { SigningRuntimeDeps } from './runtime';

export type NearTransactionsWithActionsPayload = {
  ctx: SigningRuntimeDeps;
  sessionId?: string;
  transactions: TransactionInputWasm[];
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
  deviceNumber?: number;
};

export type NearDelegateActionPayload = {
  ctx: SigningRuntimeDeps;
  delegate: DelegateActionInput;
  rpcCall: RpcCallPayload;
  signerMode: SignerMode;
  onEvent?: (update: onProgressEvents) => void;
  confirmationConfigOverride?: Partial<ConfirmationConfig>;
  title?: string;
  body?: string;
  signingSessionTtlMs?: number;
  signingSessionRemainingUses?: number;
  sessionId?: string;
  deviceNumber?: number;
};

export type NearNep413Payload = {
  ctx: SigningRuntimeDeps;
  payload: {
    message: string;
    recipient: string;
    nonce: string;
    state: string | null;
    accountId: string;
    signerMode: SignerMode;
    deviceNumber?: number;
    title?: string;
    body?: string;
    confirmationConfigOverride?: Partial<ConfirmationConfig>;
    signingSessionTtlMs?: number;
    signingSessionRemainingUses?: number;
    sessionId?: string;
    contractId?: string;
    nearRpcUrl?: string;
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

/**
 * Adapter-produced NEAR intent sign requests.
 * These carry high-level payloads and are converted by orchestration into
 * execution requests that the ed25519 engine can run.
 */
export type NearEd25519IntentSignRequest =
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

/**
 * Engine-consumable NEAR ed25519 requests.
 * Orchestration prepares these as runnable execution units so the engine
 * does not own SecureConfirm/session orchestration concerns.
 */
export type NearEd25519ExecutionRequest =
  | {
      kind: 'near-transactions-with-actions';
      algorithm: 'ed25519';
      execute: () => Promise<NearTransactionsWithActionsResult>;
    }
  | {
      kind: 'near-delegate-action';
      algorithm: 'ed25519';
      execute: () => Promise<NearDelegateActionResult>;
    }
  | {
      kind: 'near-nep413-message';
      algorithm: 'ed25519';
      execute: () => Promise<NearNep413Result>;
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
