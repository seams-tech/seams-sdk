import { expect, test } from '@playwright/test';

import {
  MinimalNearClient,
  NearRpcError,
  SignedTransaction,
} from '../../packages/wallet-server/src/core/rpcClients/near/NearClient';

const originalFetch = globalThis.fetch;

type RawRpcFailure = 'transport' | 'http' | 'parse';

function rpcJsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function successfulTransactionResponse(): Response {
  return rpcJsonResponse({
    jsonrpc: '2.0',
    id: 'success',
    result: {
      final_execution_status: 'FINAL',
      status: { SuccessValue: '' },
      transaction: { hash: 'transaction-hash' },
      transaction_outcome: {
        id: 'transaction-hash',
        outcome: {
          logs: [],
          receipt_ids: [],
          gas_burnt: 0,
          tokens_burnt: '0',
          executor_id: 'relayer.testnet',
          status: { SuccessValue: '' },
        },
      },
      receipts_outcome: [],
    },
  });
}

function testSignedTransaction(): SignedTransaction {
  return SignedTransaction.fromPlain({
    transaction: null,
    signature: null,
    borsh_bytes: [1, 2, 3],
  });
}

class StructuredSendFetchScenario {
  calls = 0;

  constructor(private readonly kind: 'terminal_with_transient_words' | 'infrastructure_then_ok') {}

  async fetch(): Promise<Response> {
    this.calls += 1;
    if (this.kind === 'infrastructure_then_ok' && this.calls > 1) {
      return successfulTransactionResponse();
    }
    if (this.kind === 'infrastructure_then_ok') {
      return rpcJsonResponse({
        jsonrpc: '2.0',
        id: 'infrastructure',
        error: {
          code: -32000,
          name: 'HANDLER_ERROR',
          message: 'permanent policy wording without a retry hint',
        },
      });
    }
    return rpcJsonResponse({
      jsonrpc: '2.0',
      id: 'terminal',
      error: {
        code: -32000,
        name: 'HANDLER_ERROR',
        message: 'server error timeout temporarily unavailable',
        data: {
          TxExecutionError: {
            InvalidTxError: 'Timeout',
          },
        },
      },
    });
  }
}

class RawFailureFetchScenario {
  constructor(private readonly failure: RawRpcFailure) {}

  async fetch(): Promise<Response> {
    switch (this.failure) {
      case 'transport':
        throw new TypeError('socket closed');
      case 'http':
        return new Response('upstream unavailable', {
          status: 503,
          statusText: 'Unavailable',
        });
      case 'parse':
        return new Response('{', { status: 200 });
      default:
        return assertNever(this.failure);
    }
  }
}

function assertNever(value: never): never {
  throw new Error(`Unexpected raw RPC failure: ${String(value)}`);
}

function restoreFetch(): void {
  globalThis.fetch = originalFetch;
}

async function assertTerminalStructuredFailureDoesNotRetry(): Promise<void> {
  const scenario = new StructuredSendFetchScenario('terminal_with_transient_words');
  globalThis.fetch = scenario.fetch.bind(scenario);
  const client = new MinimalNearClient('https://rpc.example.test');

  await expect(client.sendTransaction(testSignedTransaction())).rejects.toMatchObject({
    failureKind: 'invalid_transaction',
  });
  expect(scenario.calls).toBe(1);
}

async function assertStructuredInfrastructureFailureDoesNotRetry(): Promise<void> {
  const scenario = new StructuredSendFetchScenario('infrastructure_then_ok');
  globalThis.fetch = scenario.fetch.bind(scenario);
  const client = new MinimalNearClient('https://rpc.example.test');

  await expect(client.sendTransaction(testSignedTransaction())).rejects.toMatchObject({
    failureKind: 'infrastructure_failure',
  });
  expect(scenario.calls).toBe(1);
}

async function assertRawFailureIsTyped(failure: RawRpcFailure): Promise<void> {
  const scenario = new RawFailureFetchScenario(failure);
  globalThis.fetch = scenario.fetch.bind(scenario);
  const client = new MinimalNearClient('https://rpc.example.test');

  await expect(client.viewAccount('account.testnet')).rejects.toMatchObject({
    name: 'NearRpcError',
    failureKind: 'infrastructure_failure',
    operation: 'View Account',
  });
}

test.afterEach(restoreFetch);

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

test.describe('MinimalNearClient typed retry behavior', () => {
  test(
    'does not retry a structured terminal failure whose message sounds transient',
    assertTerminalStructuredFailureDoesNotRetry,
  );
  test(
    'does not retry a structured infrastructure failure after an ambiguous submission',
    assertStructuredInfrastructureFailureDoesNotRetry,
  );
  for (const failure of ['transport', 'http', 'parse'] as const) {
    test(
      `normalizes raw ${failure} failures into structured infrastructure errors`,
      assertRawFailureIsTyped.bind(undefined, failure),
    );
  }
});
