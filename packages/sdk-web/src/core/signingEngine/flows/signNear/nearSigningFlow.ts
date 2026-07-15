import {
  toActionArgsWasm,
  validateActionArgsWasm,
  type TransactionInputWasm,
} from '@/core/types/actions';
import type { NearIntentResult, NearSigningRequest } from '@/core/signingEngine/interfaces/near';
import { runNearTransactionWithActionsSigning } from './signTransactions';
import { runNearDelegateActionSigning } from './signDelegate';
import { signNep413Message } from './signNep413';
import { rejectNearMultiTransactionSigning } from './signatureUses';

export async function signNearWithUiConfirm<TRequest extends NearSigningRequest>(
  request: TRequest,
): Promise<NearIntentResult<TRequest>> {
  if (request.chain !== 'near') {
    throw new Error('[NearSigningFlow] invalid chain');
  }

  if (request.kind === 'transactionWithActions') {
    validateTransactionWithActionsRequest(request.payload);
    return (await runNearTransactionWithActionsSigning(
      request.payload,
    )) as NearIntentResult<TRequest>;
  }

  if (request.kind === 'delegateAction') {
    validateDelegateActionRequest(request.payload);
    return (await runNearDelegateActionSigning(request.payload)) as NearIntentResult<TRequest>;
  }

  if (request.kind === 'nep413') {
    validateNep413Request(request.payload);
    return (await signNep413Message(request.payload)) as NearIntentResult<TRequest>;
  }

  const _exhaustive: never = request;
  return _exhaustive;
}

function validateTransactionWithActionsRequest(
  payload: Extract<NearSigningRequest, { kind: 'transactionWithActions' }>['payload'],
): void {
  const nearAccountId = String(payload.nearAccount?.accountId || '').trim();
  if (!nearAccountId) {
    throw new Error('[NearSigningFlow] nearAccount is required');
  }
  if (String(payload.rpcCall?.nearAccountId || '').trim() !== nearAccountId) {
    throw new Error('[NearSigningFlow] rpcCall.nearAccountId must match nearAccount.accountId');
  }
  const legacyTransactions = (payload as { transactions?: unknown }).transactions;
  if (Array.isArray(legacyTransactions)) {
    rejectNearMultiTransactionSigning(legacyTransactions as TransactionInputWasm[]);
  }
  validateNearTransactionInput(payload.transaction, 0);
}

function validateNearTransactionInput(tx: TransactionInputWasm, txIndex: number): void {
  const receiverId = String(tx?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error(`[NearSigningFlow] transactions[${txIndex}].receiverId is required`);
  }
  const actions = Array.isArray(tx?.actions) ? tx.actions : [];
  if (actions.length === 0) {
    throw new Error(`[NearSigningFlow] transactions[${txIndex}].actions must be non-empty`);
  }
  actions.forEach(validateActionArgsWasm);
}

function validateDelegateActionRequest(
  payload: Extract<NearSigningRequest, { kind: 'delegateAction' }>['payload'],
): void {
  const nearAccountId = String(payload.nearAccount?.accountId || '').trim();
  if (!nearAccountId) {
    throw new Error('[NearSigningFlow] nearAccount is required');
  }
  if (String(payload.rpcCall?.nearAccountId || '').trim() !== nearAccountId) {
    throw new Error('[NearSigningFlow] rpcCall.nearAccountId must match nearAccount.accountId');
  }
  const receiverId = String(payload.delegate?.receiverId || '').trim();
  if (!receiverId) {
    throw new Error('[NearSigningFlow] delegate.receiverId is required');
  }
  const actions = Array.isArray(payload.delegate?.actions) ? payload.delegate.actions : [];
  if (actions.length === 0) {
    throw new Error('[NearSigningFlow] delegate.actions must be non-empty');
  }
  actions.forEach((action) => validateActionArgsWasm(toActionArgsWasm(action)));
}

function validateNep413Request(
  payload: Extract<NearSigningRequest, { kind: 'nep413' }>['payload'],
): void {
  const nearAccountId = String(payload.nearAccount?.accountId || '').trim();
  if (!nearAccountId) {
    throw new Error('[NearSigningFlow] nearAccount is required for NEP-413');
  }
  if (String(payload.payload?.accountId || '').trim() !== nearAccountId) {
    throw new Error('[NearSigningFlow] payload.accountId must match nearAccount.accountId');
  }
  const recipient = String(payload.payload?.recipient || '').trim();
  if (!recipient) {
    throw new Error('[NearSigningFlow] recipient is required for NEP-413');
  }
  const message = String(payload.payload?.message || '').trim();
  if (!message) {
    throw new Error('[NearSigningFlow] message is required for NEP-413');
  }
}
