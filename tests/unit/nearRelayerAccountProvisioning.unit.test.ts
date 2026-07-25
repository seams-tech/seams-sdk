import { expect, test } from '@playwright/test';
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
import { base58Encode } from '../../packages/shared-ts/src/utils/base58';
import { sha256Bytes } from '../../packages/shared-ts/src/utils/digests';
import {
  broadcastPreparedSponsoredNearAccountCreation,
  type PreparedSponsoredNearAccountCreationV1,
} from '../../packages/sdk-server-ts/src/core/nearRelayerAccountProvisioning';
import { NearRpcError, type NearClient, SignedTransaction } from '../../packages/sdk-server-ts/src/core/rpcClients/near/NearClient';

const ACCOUNT_ID = 'alice.testnet';
const PUBLIC_KEY = 'ed25519:expected-public-key';
const RELAYER_ACCOUNT_ID = 'relayer.testnet';

type NearClientOverrides = Partial<{
  readonly txStatus: () => Promise<FinalExecutionOutcome>;
  readonly sendTransaction: () => Promise<FinalExecutionOutcome>;
  readonly viewAccount: () => Promise<AccountView>;
  readonly viewAccessKey: () => Promise<AccessKeyView>;
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

  async viewAccessKeyList(_accountId: string, _finalityQuery?: FinalityReference): Promise<AccessKeyList> {
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
    throw new Error('viewBlock not configured');
  }

  async sendTransaction(
    _signedTransaction: SignedTransaction,
  ): Promise<FinalExecutionOutcome> {
    if (this.overrides.sendTransaction) return await this.overrides.sendTransaction();
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

function outcome(status: FinalExecutionOutcome['status'], transactionHash = 'unused'): FinalExecutionOutcome {
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

async function preparedArtifact(): Promise<PreparedSponsoredNearAccountCreationV1> {
  const borshBytes = [1, 2, 3, 4];
  return {
    kind: 'prepared_sponsored_near_account_creation_v1',
    accountId: ACCOUNT_ID,
    publicKey: PUBLIC_KEY,
    relayerAccountId: RELAYER_ACCOUNT_ID,
    transactionHash: base58Encode(await sha256Bytes(Uint8Array.from(borshBytes))),
    nextNonce: '7',
    blockHash: 'block-hash',
    signedTransaction: {
      transaction: { receiver_id: ACCOUNT_ID },
      signature: { keyType: 0, data: [0, 1, 2] },
      borsh_bytes: borshBytes,
    },
  };
}

function rpcError(message: string): NearRpcError {
  return new NearRpcError({
    message,
    short: 'RpcError',
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

test('reconciliation rejects a resolved NEAR failure without rebroadcasting', async () => {
  const prepared = await preparedArtifact();
  let sends = 0;
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () => outcome({ Failure: { error_message: 'account exists', error_type: 'ActionError' } }),
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
        throw rpcError('unknown transaction');
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
  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'https://rpc.testnet.near.org',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    reconcileFirst: true,
    nearClient: new NearClientFixture({
      txStatus: async () => {
        throw rpcError('unknown transaction');
      },
      viewAccount: async () => {
        throw rpcError('account does not exist');
      },
      sendTransaction: async () => {
        sends += 1;
        return outcome({ SuccessValue: '' }, prepared.transactionHash);
      },
    }),
  });

  expect(result.kind).toBe('created');
  expect(sends).toBe(1);
});
