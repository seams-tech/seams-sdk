import { expect, test } from '@playwright/test';

import { NearRpcError } from '../../packages/sdk-server-ts/src/core/rpcClients/near/NearClient';

test.describe('NearClient structured RPC failure classification', () => {
  test('classifies transaction, account, and access-key absence from structured causes', () => {
    const transaction = NearRpcError.fromRpcResponse('Tx Status', {
      error: {
        name: 'HANDLER_ERROR',
        message: 'Server error',
        data: {
          name: 'HANDLER_ERROR',
          cause: { name: 'UNKNOWN_TRANSACTION', info: { tx_hash: 'hash' } },
        },
      },
    });
    const account = NearRpcError.fromRpcResponse('View Account', {
      error: {
        name: 'HANDLER_ERROR',
        cause: { name: 'UNKNOWN_ACCOUNT', info: { account_id: 'missing.testnet' } },
      },
    });
    const accessKey = NearRpcError.fromRpcResponse('View Access Key', {
      error: {
        name: 'HANDLER_ERROR',
        data: {
          cause: { name: 'UNKNOWN_ACCESS_KEY', info: { public_key: 'ed25519:key' } },
        },
      },
    });

    expect(transaction.failureKind).toBe('transaction_not_found');
    expect(account.failureKind).toBe('account_not_found');
    expect(accessKey.failureKind).toBe('access_key_not_found');
  });

  test('does not infer failure kind from English message text', () => {
    const error = NearRpcError.fromRpcResponse('Tx Status', {
      error: {
        name: 'HANDLER_ERROR',
        message: 'UNKNOWN_TRANSACTION: transaction does not exist',
      },
    });

    expect(error.failureKind).toBe('infrastructure_failure');
  });

  test('classifies InvalidNonce and Expired from structured execution failures', () => {
    const invalidNonce = NearRpcError.fromOutcome(
      'Send Transaction',
      {},
      {
        InvalidTxError: { InvalidNonce: { tx_nonce: 12, ak_nonce: 13 } },
      },
    );
    const expired = NearRpcError.fromRpcResponse('Send Transaction', {
      error: {
        data: {
          TxExecutionError: {
            InvalidTxError: 'Expired',
          },
        },
      },
    });

    expect(invalidNonce.failureKind).toBe('invalid_nonce');
    expect(expired.failureKind).toBe('expired');
  });

  test('classifies other transaction and action failures without message parsing', () => {
    const invalidTransaction = NearRpcError.fromOutcome(
      'Send Transaction',
      {},
      {
        InvalidTxError: { InvalidSignerId: null },
      },
    );
    const action = NearRpcError.fromOutcome(
      'Send Transaction',
      {},
      {
        ActionError: { index: 1, kind: { AccountAlreadyExists: { account_id: 'new.testnet' } } },
      },
    );
    const execution = NearRpcError.fromOutcome(
      'Send Transaction',
      {},
      {
        ReceiptValidationError: { InvalidPredecessorId: null },
      },
    );

    expect(invalidTransaction.failureKind).toBe('invalid_transaction');
    expect(action.failureKind).toBe('action_error');
    expect(execution.failureKind).toBe('execution_failure');
  });
});
