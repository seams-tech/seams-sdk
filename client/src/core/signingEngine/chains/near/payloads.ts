import {
  toActionArgsWasm,
  validateActionArgsWasm,
  type ActionArgsWasm,
  type TransactionInputWasm,
} from '@/core/types/actions';
import type { DelegateActionInput } from '@/core/types/delegate';
import type { TransactionPayload } from '@/core/types/signer-worker';

export type NearTransactionSigningPayloads = {
  txSigningRequests: TransactionPayload[];
  confirmationTransactions: TransactionInputWasm[];
};

export function buildNearTransactionSigningPayloads(args: {
  nearAccountId: string;
  transactions: readonly TransactionInputWasm[];
}): NearTransactionSigningPayloads {
  const transactions = Array.isArray(args.transactions) ? args.transactions : [];
  if (transactions.length === 0) {
    throw new Error('[SigningEngine] transactions must be non-empty');
  }
  const txSigningRequests = transactions.map((tx, txIndex) =>
    normalizeNearTransactionSigningRequest({
      nearAccountId: args.nearAccountId,
      tx,
      txIndex,
    }),
  );
  return {
    txSigningRequests,
    confirmationTransactions: txSigningRequests.map((tx) => ({
      receiverId: tx.receiverId,
      actions: tx.actions,
    })),
  };
}

export type NearDelegateConfirmationPayload = {
  senderId: string;
  receiverId: string;
  actions: ActionArgsWasm[];
  nonce: DelegateActionInput['nonce'];
  maxBlockHeight: DelegateActionInput['maxBlockHeight'];
};

export type NearDelegateWorkerPayload = {
  senderId: string;
  receiverId: string;
  actions: ActionArgsWasm[];
  nonce: string;
  maxBlockHeight: string;
  publicKey: string;
};

export type NearDelegateSigningPayloads = {
  confirmationDelegate: NearDelegateConfirmationPayload;
  workerDelegate: NearDelegateWorkerPayload;
};

export function buildNearDelegateSigningPayloads(args: {
  nearAccountId: string;
  delegate: DelegateActionInput;
  signingPublicKey: string;
}): NearDelegateSigningPayloads {
  const actionsWasm = args.delegate.actions.map(toActionArgsWasm);
  actionsWasm.forEach((action, actionIndex) => {
    try {
      validateActionArgsWasm(action);
    } catch (error) {
      throw new Error(
        `Delegate action ${actionIndex} validation failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  });
  const senderId = args.delegate.senderId || args.nearAccountId;
  const confirmationDelegate = {
    senderId,
    receiverId: args.delegate.receiverId,
    actions: actionsWasm,
    nonce: args.delegate.nonce,
    maxBlockHeight: args.delegate.maxBlockHeight,
  };
  return {
    confirmationDelegate,
    workerDelegate: {
      ...confirmationDelegate,
      nonce: args.delegate.nonce.toString(),
      maxBlockHeight: args.delegate.maxBlockHeight.toString(),
      publicKey: args.signingPublicKey,
    },
  };
}

function normalizeNearTransactionSigningRequest(args: {
  nearAccountId: string;
  tx: TransactionInputWasm;
  txIndex: number;
}): TransactionPayload {
  const receiverId = String(args.tx?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].receiverId is required`);
  }

  const actions = Array.isArray(args.tx?.actions) ? args.tx.actions : [];
  if (actions.length === 0) {
    throw new Error(`[SigningEngine] transactions[${args.txIndex}].actions must be non-empty`);
  }
  for (let i = 0; i < actions.length; i++) {
    validateActionArgsWasm(actions[i]);
  }

  return {
    nearAccountId: args.nearAccountId,
    receiverId,
    actions,
  };
}
