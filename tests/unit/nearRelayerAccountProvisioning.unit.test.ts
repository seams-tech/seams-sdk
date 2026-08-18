import { expect, test } from '@playwright/test';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { once } from 'node:events';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
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
} from '../../packages/wallet-server/src/core/nearRelayerAccountProvisioning';
import {
  NearRpcError,
  type NearClient,
  type NearRpcFailureKind,
  SignedTransaction,
} from '../../packages/wallet-server/src/core/rpcClients/near/NearClient';

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

type ProductionNearRpcMode =
  | 'send_success'
  | 'send_failure'
  | 'send_pending_created'
  | 'status_failure'
  | 'status_structured_failure'
  | 'status_outage_created'
  | 'status_outage_total'
  | 'exact_replay';

type ProductionNearRpcRequest = {
  readonly id: unknown;
  readonly method: string;
  readonly params: Record<string, unknown>;
};

function isProductionNearRpcRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseProductionNearRpcRequest(value: unknown): ProductionNearRpcRequest {
  if (
    !isProductionNearRpcRecord(value) ||
    typeof value.method !== 'string' ||
    !isProductionNearRpcRecord(value.params)
  ) {
    throw new Error('Production-shaped NEAR RPC fixture received an invalid request');
  }
  return { id: value.id, method: value.method, params: value.params };
}

function writeProductionNearRpcResult(
  response: ServerResponse,
  request: ProductionNearRpcRequest,
  result: unknown,
): void {
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ jsonrpc: '2.0', id: request.id, result }));
}

function writeProductionNearRpcError(
  response: ServerResponse,
  request: ProductionNearRpcRequest,
  data: Record<string, unknown>,
): void {
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(
    JSON.stringify({
      jsonrpc: '2.0',
      id: request.id,
      error: { code: -32000, name: 'HANDLER_ERROR', message: 'Server error', data },
    }),
  );
}

function productionRpcOutcome(
  status: FinalExecutionOutcome['status'],
  transactionHash: string,
): FinalExecutionOutcome {
  return outcome(status, transactionHash);
}

class ProductionNearJsonRpcFixture {
  private readonly server: Server;
  sendCount = 0;
  statusCount = 0;
  accountReadCount = 0;
  accessKeyReadCount = 0;
  sentTransactionBase64 = '';

  constructor(private readonly mode: ProductionNearRpcMode) {
    this.server = createServer(this.handle.bind(this));
  }

  async start(): Promise<string> {
    const listening = once(this.server, 'listening');
    this.server.listen(0, '127.0.0.1');
    await listening;
    const address = this.server.address();
    if (!address || typeof address === 'string') {
      throw new Error('Production-shaped NEAR RPC fixture did not bind a TCP address');
    }
    return `http://127.0.0.1:${address.port}`;
  }

  async close(): Promise<void> {
    const closed = once(this.server, 'close');
    this.server.close();
    await closed;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const chunks: Uint8Array[] = [];
    for await (const chunk of request) {
      chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    const rpc = parseProductionNearRpcRequest(JSON.parse(Buffer.concat(chunks).toString('utf8')));
    switch (rpc.method) {
      case 'send_tx':
        this.handleSend(rpc, response);
        return;
      case 'EXPERIMENTAL_tx_status':
        this.handleStatus(rpc, response);
        return;
      case 'query':
        this.handleQuery(rpc, response);
        return;
      default:
        response.writeHead(500);
        response.end(`Unsupported method: ${rpc.method}`);
    }
  }

  private handleSend(request: ProductionNearRpcRequest, response: ServerResponse): void {
    this.sendCount += 1;
    this.sentTransactionBase64 = String(request.params.signed_tx_base64 || '');
    if (this.mode === 'send_failure') {
      writeProductionNearRpcResult(
        response,
        request,
        productionRpcOutcome(
          { Failure: { ActionError: { index: 0, kind: { AccountAlreadyExists: {} } } } },
          'failed-transaction',
        ),
      );
      return;
    }
    if (this.mode === 'send_pending_created') {
      writeProductionNearRpcResult(
        response,
        request,
        productionRpcOutcome({}, 'pending-transaction'),
      );
      return;
    }
    writeProductionNearRpcResult(
      response,
      request,
      productionRpcOutcome({ SuccessValue: '' }, 'created-transaction'),
    );
  }

  private handleStatus(request: ProductionNearRpcRequest, response: ServerResponse): void {
    this.statusCount += 1;
    if (this.mode === 'status_outage_created' || this.mode === 'status_outage_total') {
      response.writeHead(503, 'Unavailable');
      response.end('upstream unavailable');
      return;
    }
    if (this.mode === 'exact_replay') {
      writeProductionNearRpcError(response, request, {
        name: 'HANDLER_ERROR',
        cause: { name: 'UNKNOWN_TRANSACTION', info: {} },
      });
      return;
    }
    if (this.mode === 'status_structured_failure') {
      writeProductionNearRpcError(response, request, {
        TxExecutionError: {
          ActionError: { index: 0, kind: { AccountAlreadyExists: {} } },
        },
      });
      return;
    }
    writeProductionNearRpcResult(
      response,
      request,
      productionRpcOutcome(
        { Failure: { ActionError: { index: 0, kind: { AccountAlreadyExists: {} } } } },
        'failed-status-transaction',
      ),
    );
  }

  private handleQuery(request: ProductionNearRpcRequest, response: ServerResponse): void {
    const requestType = String(request.params.request_type || '');
    if (requestType === 'view_account') this.accountReadCount += 1;
    if (requestType === 'view_access_key') this.accessKeyReadCount += 1;
    if (this.mode === 'status_outage_total') {
      response.writeHead(503, 'Unavailable');
      response.end('upstream unavailable');
      return;
    }
    const accountExists =
      this.mode === 'send_pending_created' || this.mode === 'status_outage_created';
    if (!accountExists) {
      writeProductionNearRpcError(response, request, {
        name: 'HANDLER_ERROR',
        cause: {
          name: requestType === 'view_access_key' ? 'UNKNOWN_ACCESS_KEY' : 'UNKNOWN_ACCOUNT',
          info: {},
        },
      });
      return;
    }
    if (requestType === 'view_account') {
      writeProductionNearRpcResult(response, request, {
        amount: '1',
        locked: '0',
        code_hash: BLOCK_HASH,
        storage_usage: 0,
        storage_paid_at: 0,
        block_height: 1,
        block_hash: BLOCK_HASH,
      });
      return;
    }
    writeProductionNearRpcResult(response, request, {
      nonce: 1,
      permission: 'FullAccess',
      block_height: 1,
      block_hash: BLOCK_HASH,
    });
  }
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
    | { readonly kind: 'pending' }
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
    case 'pending':
      return outcome({});
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
  expect(await preparedSponsoredNearAccountCreationArtifactFingerprint(prepared)).toMatch(
    /^sponsored-near-account-creation-v1:[A-Za-z0-9_-]{43}$/u,
  );
});

test('prepared artifact fingerprint binds signature bytes beyond the unsigned transaction hash', async () => {
  const prepared = await preparedArtifact();
  const alteredBytes = Uint8Array.from(base64UrlDecode(prepared.signedTransactionBorshB64u));
  alteredBytes[alteredBytes.length - 1] ^= 0x01;
  const altered = {
    ...prepared,
    signedTransactionBorshB64u: Buffer.from(alteredBytes).toString('base64url'),
  };

  expect(altered.transactionHash).toBe(prepared.transactionHash);
  await expect(preparedSponsoredNearAccountCreationArtifactFingerprint(altered)).resolves.not.toBe(
    await preparedSponsoredNearAccountCreationArtifactFingerprint(prepared),
  );
});

test('production NEAR client broadcasts the exact persisted bytes and returns success', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('send_success');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
    });

    expect(result.kind).toBe('created');
    expect(rpc.sendCount).toBe(1);
    expect(rpc.sentTransactionBase64).toBe(
      Buffer.from(base64UrlDecode(prepared.signedTransactionBorshB64u)).toString('base64'),
    );
  } finally {
    await rpc.close();
  }
});

test('production NEAR client classifies a broadcast execution failure as rejected', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('send_failure');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
    });

    expect(result.kind).toBe('rejected');
    expect(rpc).toMatchObject({ sendCount: 1, accountReadCount: 1, accessKeyReadCount: 0 });
  } finally {
    await rpc.close();
  }
});

test('production NEAR client resolves a pending broadcast through exact account-key readback', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('send_pending_created');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
    });

    expect(result.kind).toBe('created');
    expect(rpc).toMatchObject({ sendCount: 1, accountReadCount: 1, accessKeyReadCount: 1 });
  } finally {
    await rpc.close();
  }
});

for (const mode of ['status_failure', 'status_structured_failure'] as const) {
  test(`production NEAR client classifies ${mode} as rejected without replay`, async () => {
    const prepared = await preparedArtifact();
    const rpc = new ProductionNearJsonRpcFixture(mode);
    const nearRpcUrl = await rpc.start();
    try {
      const result = await broadcastPreparedSponsoredNearAccountCreation({
        prepared,
        nearRpcUrl,
        relayerAccountId: RELAYER_ACCOUNT_ID,
        reconcileFirst: true,
      });

      expect(result.kind).toBe('rejected');
      expect(rpc).toMatchObject({ sendCount: 0, statusCount: 1, accountReadCount: 0 });
    } finally {
      await rpc.close();
    }
  });
}

test('production NEAR client resolves a status outage from exact account-key readback', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('status_outage_created');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
      reconcileFirst: true,
    });

    expect(result.kind).toBe('created');
    expect(rpc).toMatchObject({ sendCount: 0, statusCount: 1, accountReadCount: 1 });
  } finally {
    await rpc.close();
  }
});

test('production NEAR client keeps a status and readback outage uncertain', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('status_outage_total');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
      reconcileFirst: true,
    });

    expect(result.kind).toBe('uncertain');
    expect(rpc).toMatchObject({ sendCount: 0, statusCount: 1, accountReadCount: 1 });
  } finally {
    await rpc.close();
  }
});

test('production NEAR client replays the exact bytes after typed transaction and account absence', async () => {
  const prepared = await preparedArtifact();
  const rpc = new ProductionNearJsonRpcFixture('exact_replay');
  const nearRpcUrl = await rpc.start();
  try {
    const result = await broadcastPreparedSponsoredNearAccountCreation({
      prepared,
      nearRpcUrl,
      relayerAccountId: RELAYER_ACCOUNT_ID,
      reconcileFirst: true,
    });

    expect(result.kind).toBe('created');
    expect(rpc).toMatchObject({ sendCount: 1, statusCount: 1, accountReadCount: 1 });
    expect(rpc.sentTransactionBase64).toBe(
      Buffer.from(base64UrlDecode(prepared.signedTransactionBorshB64u)).toString('base64'),
    );
  } finally {
    await rpc.close();
  }
});

test('a nonterminal initial send resolves only through exact account and key readback', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: { kind: 'pending' },
    account: { kind: 'full_access' },
    send: { kind: 'pending' },
  });

  const result = await broadcastPreparedSponsoredNearAccountCreation({
    prepared,
    nearRpcUrl: 'unused',
    relayerAccountId: RELAYER_ACCOUNT_ID,
    nearClient: scenarioNearClient(scenario),
  });

  expect(result.kind).toBe('created');
  expect(scenario).toMatchObject({ sends: 1, accountReads: 1, accessKeyReads: 1 });
});

test('a nonterminal initial send with absent account remains uncertain', async () => {
  const prepared = await preparedArtifact();
  const scenario = reconciliationScenario({
    transaction: { kind: 'pending' },
    account: { kind: 'account_not_found' },
    send: { kind: 'pending' },
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
