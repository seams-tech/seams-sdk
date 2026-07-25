import { expect, test } from '@playwright/test';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import type {
  AccessKeyList,
  AccessKeyView,
  AccountView,
  BlockReference,
  BlockResult,
  FinalExecutionOutcome,
  FinalityReference,
  QueryResponseKind,
  RpcQueryRequest,
} from '@near-js/types';
import { base58Decode, base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import {
  broadcastPreparedSponsoredNearAccountCreation,
  prepareSponsoredNearAccountCreationWithRelayer,
  preparedSponsoredNearAccountCreationArtifactFingerprint,
  type PreparedSponsoredNearAccountCreationV1,
} from '../../packages/sdk-server-ts/src/core/nearRelayerAccountProvisioning';
import {
  NearRpcError,
  type NearClient,
  type NearRpcFailureKind,
  SignedTransaction,
} from '../../packages/sdk-server-ts/src/core/rpcClients/near/NearClient';

const ACCOUNT_ID = 'alice.testnet';
const RELAYER_ACCOUNT_ID = 'relayer.testnet';

function deterministicEd25519Key(seedByte: number): {
  readonly privateKey: string;
  readonly publicKey: string;
} {
  const seed = Uint8Array.from({ length: 32 }, (_, index) => seedByte + index);
  const prefix = Uint8Array.from([48, 46, 2, 1, 0, 48, 5, 6, 3, 43, 101, 112, 4, 34, 4, 32]);
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(prefix);
  pkcs8.set(seed, 16);
  const privateKey = createPrivateKey({ key: Buffer.from(pkcs8), format: 'der', type: 'pkcs8' });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  const publicKeyBytes = new Uint8Array(spki).slice(-32);
  const secretBytes = new Uint8Array(64);
  secretBytes.set(seed);
  secretBytes.set(publicKeyBytes, 32);
  return {
    privateKey: `ed25519:${base58Encode(secretBytes)}`,
    publicKey: `ed25519:${base58Encode(publicKeyBytes)}`,
  };
}

const RELAYER_KEY = deterministicEd25519Key(1);
const ACCOUNT_KEY = deterministicEd25519Key(65);
const PUBLIC_KEY = ACCOUNT_KEY.publicKey;
const BLOCK_HASH = '11111111111111111111111111111111';

async function preparedArtifact(): Promise<PreparedSponsoredNearAccountCreationV1> {
  const prepared = await prepareSponsoredNearAccountCreationWithRelayer({
    walletId: 'wallet',
    accountId: ACCOUNT_ID,
    publicKey: PUBLIC_KEY,
    relayerAccount: RELAYER_ACCOUNT_ID,
    relayerPrivateKey: RELAYER_KEY.privateKey,
    relayerPublicKey: RELAYER_KEY.publicKey,
    nearRpcUrl: 'unused',
    initialBalanceYocto: '1000',
    nearClient: new NearClientFixture({
      viewAccessKey: async () => ({ ...fullAccessKey(), nonce: 6n }),
      viewBlock: async () => ({ header: { hash: BLOCK_HASH } }) as BlockResult,
    }),
  });
  if (!prepared.ok) throw new Error(prepared.error);
  return prepared.prepared;
}

type NearClientOverrides = Partial<{
  readonly txStatus: () => Promise<FinalExecutionOutcome>;
  readonly sendTransaction: (
    signedTransaction: SignedTransaction,
  ) => Promise<FinalExecutionOutcome>;
  readonly viewAccount: () => Promise<AccountView>;
  readonly viewAccessKey: () => Promise<AccessKeyView>;
  readonly viewBlock: () => Promise<BlockResult>;
}>;

class NearClientFixture implements NearClient {
  constructor(private readonly overrides: NearClientOverrides) {}

  async viewAccessKey(
    _accountId: string,
    _publicKey: string,
    _finalityQuery?: FinalityReference,
  ): Promise<AccessKeyView> {
    if (this.overrides.viewAccessKey) return await this.overrides.viewAccessKey();
    throw new Error('viewAccessKey not configured');
  }

  async viewAccessKeyList(
    _accountId: string,
    _finalityQuery?: FinalityReference,
  ): Promise<AccessKeyList> {
    throw new Error('viewAccessKeyList not configured');
  }

  async viewAccount(_accountId: string): Promise<AccountView> {
    if (this.overrides.viewAccount) return await this.overrides.viewAccount();
    throw new Error('viewAccount not configured');
  }

  async viewCode(_accountId: string, _finalityQuery?: FinalityReference): Promise<Uint8Array> {
    throw new Error('viewCode not configured');
  }

  async viewBlock(_params: BlockReference): Promise<BlockResult> {
    if (this.overrides.viewBlock) return await this.overrides.viewBlock();
    throw new Error('viewBlock not configured');
  }

  async sendTransaction(signedTransaction: SignedTransaction): Promise<FinalExecutionOutcome> {
    if (this.overrides.sendTransaction)
      return await this.overrides.sendTransaction(signedTransaction);
    throw new Error('sendTransaction not configured');
  }

  async txStatus(_txHash: string, _senderAccountId: string): Promise<FinalExecutionOutcome> {
    if (this.overrides.txStatus) return await this.overrides.txStatus();
    throw new Error('txStatus not configured');
  }

  async query<T extends QueryResponseKind>(_params: RpcQueryRequest): Promise<T> {
    throw new Error('query not configured');
  }

  async callFunction<A, T>(_accountId: string, _method: string, _args: A): Promise<T> {
    throw new Error('callFunction not configured');
  }

  async view<A, T>(_params: { account: string; method: string; args: A }): Promise<T> {
    throw new Error('view not configured');
  }

  async getAccessKeys(_params: { account: string; block_id?: string }): Promise<{
    fullAccessKeys: never[];
    functionCallAccessKeys: never[];
  }> {
    return { fullAccessKeys: [], functionCallAccessKeys: [] };
  }
}

function outcome(
  status: FinalExecutionOutcome['status'],
  transactionHash = 'unused',
): FinalExecutionOutcome {
  const execution = {
    logs: [],
    receipt_ids: [],
    gas_burnt: 0,
    tokens_burnt: '0',
    executor_id: RELAYER_ACCOUNT_ID,
    status,
  };
  return {
    final_execution_status: 'FINAL',
    status,
    transaction: { hash: transactionHash },
    transaction_outcome: { id: transactionHash, outcome: execution },
    receipts_outcome: [],
  };
}

function rpcError(failureKind: NearRpcFailureKind, message: string): NearRpcError {
  return new NearRpcError({
    message,
    short: 'RpcError',
    failureKind,
    type: 'RpcError',
  });
}

function accountView(): AccountView {
  return {
    amount: 1n,
    locked: 0n,
    code_hash: '11111111111111111111111111111111',
    storage_usage: 0,
    storage_paid_at: 0,
    block_height: 1,
    block_hash: '11111111111111111111111111111111',
  };
}

function fullAccessKey(): AccessKeyView {
  return {
    nonce: 1n,
    permission: 'FullAccess',
    block_height: 1,
    block_hash: '11111111111111111111111111111111',
  };
}

type ReconciliationScenario = {
  readonly transaction:
    | { readonly kind: 'pending' }
    | {
        readonly kind: 'error';
        readonly failureKind: NearRpcFailureKind;
        readonly message: string;
      };
  readonly account:
    | { readonly kind: 'full_access' }
    | { readonly kind: 'account_not_found' }
    | { readonly kind: 'access_key_not_found' }
    | { readonly kind: 'wrong_permission' };
  readonly send:
    | { readonly kind: 'success' }
    | { readonly kind: 'error'; readonly failureKind: NearRpcFailureKind };
  sends: number;
  accountReads: number;
  accessKeyReads: number;
};

function reconciliationScenario(input: {
  readonly transaction: ReconciliationScenario['transaction'];
  readonly account: ReconciliationScenario['account'];
  readonly send?: ReconciliationScenario['send'];
}): ReconciliationScenario {
  return {
    transaction: input.transaction,
    account: input.account,
    send: input.send || { kind: 'success' },
    sends: 0,
    accountReads: 0,
    accessKeyReads: 0,
  };
}

async function scenarioTxStatus(scenario: ReconciliationScenario): Promise<FinalExecutionOutcome> {
  switch (scenario.transaction.kind) {
    case 'pending':
      return outcome({});
    case 'error':
      throw rpcError(scenario.transaction.failureKind, scenario.transaction.message);
  }
}

async function scenarioViewAccount(scenario: ReconciliationScenario): Promise<AccountView> {
  scenario.accountReads += 1;
  if (scenario.account.kind === 'account_not_found') {
    throw rpcError('account_not_found', 'structured account absence');
  }
  return accountView();
}

async function scenarioViewAccessKey(scenario: ReconciliationScenario): Promise<AccessKeyView> {
  scenario.accessKeyReads += 1;
  switch (scenario.account.kind) {
    case 'full_access':
      return fullAccessKey();
    case 'access_key_not_found':
      throw rpcError('access_key_not_found', 'structured access-key absence');
    case 'wrong_permission':
      return {
        ...fullAccessKey(),
        permission: {
          FunctionCall: { allowance: '1', receiver_id: 'contract.testnet', method_names: [] },
        },
      };
    case 'account_not_found':
      throw new Error('access-key read must not follow missing account');
  }
}

async function scenarioSendTransaction(
  scenario: ReconciliationScenario,
): Promise<FinalExecutionOutcome> {
  scenario.sends += 1;
  switch (scenario.send.kind) {
    case 'success':
      return outcome({ SuccessValue: '' });
    case 'error':
      throw rpcError(scenario.send.failureKind, `structured ${scenario.send.failureKind}`);
  }
}

function scenarioNearClient(scenario: ReconciliationScenario): NearClientFixture {
  return new NearClientFixture({
    txStatus: scenarioTxStatus.bind(undefined, scenario),
    viewAccount: scenarioViewAccount.bind(undefined, scenario),
    viewAccessKey: scenarioViewAccessKey.bind(undefined, scenario),
    sendTransaction: scenarioSendTransaction.bind(undefined, scenario),
  });
}

test('real preparation persists canonical bytes and broadcasts those exact bytes', async () => {
  const prepared = await preparedArtifact();
  let sentBytes: number[] | undefined;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    nearClient: new NearClientFixture({
      sendTransaction: async (signedTransaction) => {
        sentBytes = signedTransaction.borsh_bytes;
        return outcome({ SuccessValue: '' }, prepared.transactionHash);
      },
    }),
  });

  expect(result.kind).toBe('created');
  expect(sentBytes).toEqual(Array.from(base64UrlDecode(prepared.signedTransactionBorshB64u)));
  expect(base58Decode(prepared.transactionHash)).toHaveLength(32);
  expect(await preparedSponsoredNearAccountCreationArtifactFingerprint(prepared)).toBe(
    `sponsored-near-account-creation-v1:${prepared.transactionHash}`,
  );
});

test('semantic metadata tampering rejects the persisted transaction before broadcast', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared: { ...prepared, accountId: 'mallory.testnet' },
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    nearClient: new NearClientFixture({
      sendTransaction: async () => {
        sends += 1;
        return outcome({ SuccessValue: '' });
      },
    }),
  });

  expect(result.kind).toBe('rejected');
  expect(sends).toBe(0);
});

test('corrupt signed bytes and mismatched transaction hashes reject before broadcast', async () => {
  const prepared = await preparedArtifact();
  const corruptBytes = Uint8Array.from(base64UrlDecode(prepared.signedTransactionBorshB64u));
  corruptBytes[0] ^= 0xff;
  const invalidArtifacts = [
    { ...prepared, signedTransactionBorshB64u: Buffer.from(corruptBytes).toString('base64url') },
    { ...prepared, transactionHash: base58Encode(Uint8Array.from({ length: 32 }, () => 9)) },
  ];
  let sends = 0;

  for (const invalidArtifact of invalidArtifacts) {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared: invalidArtifact,
      nearRpcUrl: 'https://rpc.testnet.near.org',
      relayerAccountId: RELAYER_ACCOUNT_ID,
      nearClient: new NearClientFixture({
        sendTransaction: async () => {
          sends += 1;
          return outcome({ SuccessValue: '' });
        },
      }),
    });
    expect(result.kind).toBe('rejected');
  }
  expect(sends).toBe(0);
});

test('reconciliation rejects a resolved NEAR failure without rebroadcasting', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () =>
        outcome({ Failure: { error_message: 'account exists', error_type: 'ActionError' } }),
      sendTransaction: async () => {
        sends += 1;
        return outcome({ SuccessValue: '' });
      },
    }),
  });

  expect(result.kind).toBe('rejected');
  expect(sends).toBe(0);
});

test('reconciliation confirms the expected account and key after a lost transaction response', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () => {
        throw rpcError('transaction_not_found', 'unknown transaction');
      },
      viewAccount: async () => accountView(),
      viewAccessKey: async () => fullAccessKey(),
      sendTransaction: async () => {
        sends += 1;
        return outcome({ SuccessValue: '' });
      },
    }),
  });

  expect(result.kind).toBe('created');
  expect(sends).toBe(0);
});

test('an RPC outage remains uncertain and never rebroadcasts blindly', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () => {
        throw new Error('fetch failed');
      },
      sendTransaction: async () => {
        sends += 1;
        return outcome({ SuccessValue: '' });
      },
    }),
  });

  expect(result.kind).toBe('uncertain');
  expect(sends).toBe(0);
});

test('a missing transaction is replayed only after account readback confirms absence', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  let sentBytes: number[] | undefined;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () => {
        throw rpcError('transaction_not_found', 'unknown transaction');
      },
      viewAccount: async () => {
        throw rpcError('account_not_found', 'account does not exist');
      },
      sendTransaction: async (signedTransaction) => {
        sends += 1;
        sentBytes = signedTransaction.borsh_bytes;
        return outcome({ SuccessValue: '' }, prepared.transactionHash);
      },
    }),
  });

  expect(result.kind).toBe('created');
  expect(sends).toBe(1);
  expect(sentBytes).toEqual(Array.from(base64UrlDecode(prepared.signedTransactionBorshB64u)));
});

test('a pending transaction resolves from exact account and full-access-key readback', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: { kind: 'pending' },
    account: { kind: 'full_access' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('created');
  expect(scenario).toMatchObject({ sends: 0, accountReads: 1, accessKeyReads: 1 });
});

test('a pending transaction with absent account remains uncertain without replay', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: { kind: 'pending' },
    account: { kind: 'account_not_found' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('uncertain');
  expect(scenario).toMatchObject({ sends: 0, accountReads: 1, accessKeyReads: 0 });
});

test('transaction-status infrastructure failure resolves from exact account readback', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: {
      kind: 'error',
      failureKind: 'infrastructure_failure',
      message: 'RPC unavailable',
    },
    account: { kind: 'full_access' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('created');
  expect(scenario).toMatchObject({ sends: 0, accountReads: 1, accessKeyReads: 1 });
});

for (const account of [
  { kind: 'access_key_not_found' as const },
  { kind: 'wrong_permission' as const },
]) {
  test(`an existing account with ${account.kind} is rejected without replay`, async () => {
    const prepared = await preparedArtifact();
    const scenario = reconciliationScenario({
      transaction: { kind: 'pending' },
      account,
    });

    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl: 'unused',
      relayerAccountId: RELAYER_ACCOUNT_ID,
      reconcileFirst: true,
      nearClient: scenarioNearClient(scenario),
    });

    expect(result.kind).toBe('rejected');
    expect(scenario).toMatchObject({ sends: 0, accountReads: 1, accessKeyReads: 1 });
  });
}

for (const failureKind of ['invalid_nonce', 'expired'] as const) {
  test(`${failureKind} remains uncertain after exact account absence readback`, async () => {
    const prepared = await preparedArtifact();
    const scenario = reconciliationScenario({
      transaction: { kind: 'pending' },
      account: { kind: 'account_not_found' },
      send: { kind: 'error', failureKind },
    });

    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl: 'unused',
      relayerAccountId: RELAYER_ACCOUNT_ID,
      nearClient: scenarioNearClient(scenario),
    });

    expect(result.kind).toBe('uncertain');
    expect(scenario).toMatchObject({ sends: 1, accountReads: 1, accessKeyReads: 0 });
  });
}

for (const failureKind of ['invalid_transaction', 'action_error', 'execution_failure'] as const) {
  test(`${failureKind} rejects after exact account absence readback`, async () => {
    const prepared = await preparedArtifact();
    const scenario = reconciliationScenario({
      transaction: { kind: 'pending' },
      account: { kind: 'account_not_found' },
      send: { kind: 'error', failureKind },
    });

    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl: 'unused',
      relayerAccountId: RELAYER_ACCOUNT_ID,
      nearClient: scenarioNearClient(scenario),
    });

    expect(result.kind).toBe('rejected');
    expect(scenario).toMatchObject({ sends: 1, accountReads: 1, accessKeyReads: 0 });
  });
}

test('structured transaction absence plus exact account absence permits one exact replay', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: {
      kind: 'error',
      failureKind: 'transaction_not_found',
      message: 'structured transaction absence',
    },
    account: { kind: 'account_not_found' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('created');
  expect(scenario).toMatchObject({ sends: 1, accountReads: 1, accessKeyReads: 0 });
});

test('transaction-not-found English text cannot authorize replay without its structured kind', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: {
      kind: 'error',
      failureKind: 'infrastructure_failure',
      message: 'unknown transaction does not exist',
    },
    account: { kind: 'account_not_found' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('uncertain');
  expect(scenario).toMatchObject({ sends: 0, accountReads: 1, accessKeyReads: 0 });
});
