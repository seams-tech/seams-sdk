import type {
  AccountView,
  AccessKeyInfoView,
  AccessKeyList,
  AccessKeyView,
  BlockReference,
  BlockResult,
  FinalExecutionOutcome,
  FinalityReference,
  FunctionCallPermissionView,
  QueryResponseKind,
  RpcQueryRequest,
  TxExecutionStatus,
} from '@near-js/types';
import { base64Decode, base64Encode } from '@shared/utils/base64';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { isFunction } from '@shared/utils/validation';

export type { AccessKeyList } from '@near-js/types';

type RpcResponse = {
  error?: {
    code?: number;
    name?: string;
    data?: unknown;
    message?: string;
  };
  result?: any;
};

type NearRpcErrorType =
  | 'InvalidTxError'
  | 'ActionError'
  | 'TxExecutionError'
  | 'RpcError'
  | 'Failure'
  | 'Unknown';

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function firstKey(o: Record<string, unknown> | undefined): string | undefined {
  if (!o) return undefined;
  const keys = Object.keys(o);
  return keys.length ? keys[0] : undefined;
}

class NearRpcError extends Error {
  code?: number;
  type: NearRpcErrorType;
  kind?: string;
  index?: number;
  short: string;
  details?: unknown;
  operation?: string;

  constructor(params: {
    message: string;
    short: string;
    type?: NearRpcErrorType;
    kind?: string;
    index?: number;
    code?: number;
    name?: string;
    operation?: string;
    details?: unknown;
  }) {
    super(params.message);
    this.name = params.name || 'NearRpcError';
    this.code = params.code;
    this.type = params.type || 'Unknown';
    this.kind = params.kind;
    this.index = params.index;
    this.short = params.short;
    this.details = params.details;
    this.operation = params.operation;
  }

  static fromRpcResponse(operationName: string, rpc: RpcResponse): NearRpcError {
    const err = rpc.error || {};
    const details = err.data as unknown;
    const rpcMessage = typeof err.message === 'string' ? err.message : '';
    const { message, type, kind, index, short } = describeDetails(
      operationName,
      details,
      rpcMessage,
    );
    return new NearRpcError({
      message: message || rpcMessage || `${operationName} RPC error`,
      short: short || kind || 'RPC error',
      type: type || 'RpcError',
      kind,
      index,
      code: err.code,
      name: err.name || 'NearRpcError',
      operation: operationName,
      details,
    });
  }

  static fromOutcome(operationName: string, outcome: any, failure: any): NearRpcError {
    const { message, type, kind, index, short } = describeFailure(operationName, failure);
    return new NearRpcError({
      message: message || `${operationName} failed`,
      short: short || kind || 'TxExecutionError',
      type: type || 'Failure',
      kind,
      index,
      name: 'TxExecutionFailure',
      operation: operationName,
      details: { Failure: failure, outcome },
    });
  }
}

function describeDetails(
  operationName: string,
  details: unknown,
  rpcMessage = '',
): {
  message: string;
  type?: NearRpcErrorType;
  kind?: string;
  index?: number;
  short?: string;
} {
  const d = isObj(details) ? details : undefined;
  const txExec = isObj(d?.TxExecutionError)
    ? (d!.TxExecutionError as Record<string, unknown>)
    : undefined;
  if (!txExec) {
    const detail =
      typeof details === 'string' && details.trim()
        ? details.trim()
        : d
          ? JSON.stringify(d)
          : rpcMessage.trim();
    const suffix = detail ? `: ${detail}` : '';
    return { message: `${operationName} RPC error${suffix}` };
  }
  return describeTxExecution(operationName, txExec);
}

function describeFailure(
  operationName: string,
  failure: any,
): {
  message: string;
  type?: NearRpcErrorType;
  kind?: string;
  index?: number;
  short?: string;
} {
  const f = isObj(failure) ? (failure as Record<string, unknown>) : undefined;
  if (!f) return { message: `${operationName} failed (Unknown Failure)` };
  return describeTxExecution(operationName, f);
}

function describeTxExecution(
  operationName: string,
  exec: Record<string, unknown>,
): {
  message: string;
  type?: NearRpcErrorType;
  kind?: string;
  index?: number;
  short?: string;
} {
  if (isObj(exec.InvalidTxError)) {
    const inv = exec.InvalidTxError as Record<string, unknown>;
    let kind = firstKey(inv) || 'InvalidTxError';
    if (isObj(inv.ActionsValidation)) {
      kind = `ActionsValidation.${firstKey(inv.ActionsValidation as Record<string, unknown>)}`;
    }
    const short = kind.startsWith('ActionsValidation.')
      ? `InvalidTxError: ${kind.split('.')[1] || 'ActionsValidation'}`
      : `InvalidTxError: ${kind}`;
    return {
      message: `${operationName} failed (InvalidTxError: ${kind})`,
      type: 'InvalidTxError',
      kind,
      short,
    };
  }

  if (isObj(exec.ActionError)) {
    const ae = exec.ActionError as Record<string, unknown>;
    const idx = typeof (ae.index as unknown) === 'number' ? (ae.index as number) : undefined;
    const kobj = isObj(ae.kind) ? (ae.kind as Record<string, unknown>) : undefined;
    const kind = firstKey(kobj) || 'ActionError';
    const idxStr = typeof idx === 'number' ? ` at action ${idx}` : '';
    return {
      message: `${operationName} failed${idxStr} (ActionError: ${kind})`,
      type: 'ActionError',
      kind,
      index: idx,
      short: `ActionError: ${kind}`,
    };
  }

  return {
    message: `${operationName} failed (TxExecutionError)`,
    type: 'TxExecutionError',
    kind: 'TxExecutionError',
    short: 'TxExecutionError',
  };
}

export interface ViewAccountParams {
  account: string;
  block_id?: string;
}

export type FullAccessKey = Omit<AccessKeyInfoView, 'access_key'> & {
  access_key: Omit<AccessKeyView, 'permission'> & { permission: 'FullAccess' };
};

export type FunctionCallAccessKey = Omit<AccessKeyInfoView, 'access_key'> & {
  access_key: Omit<AccessKeyView, 'permission'> & { permission: FunctionCallPermissionView };
};

export interface ContractResult<T> extends QueryResponseKind {
  result?: T | string | number;
  logs: string[];
}

export enum RpcCallType {
  Query = 'query',
  View = 'view',
  Send = 'send_tx',
  Block = 'block',
  Call = 'call_function',
}

const DEFAULT_WAIT_STATUS = {
  executeAction: 'EXECUTED_OPTIMISTIC' as TxExecutionStatus,
};

export class SignedTransaction {
  transaction: unknown;
  signature: unknown;
  borsh_bytes: number[];
  nonceLease?: unknown;
  serverDispatch?: {
    transactionHash: string;
    rpcResult: unknown;
  };

  constructor(data: {
    transaction: unknown;
    signature: unknown;
    borsh_bytes: number[];
    nonceLease?: unknown;
    serverDispatch?: {
      transactionHash: string;
      rpcResult: unknown;
    };
  }) {
    this.transaction = data.transaction;
    this.signature = data.signature;
    this.borsh_bytes = data.borsh_bytes;
    if (data.nonceLease) this.nonceLease = data.nonceLease;
    if (data.serverDispatch) this.serverDispatch = data.serverDispatch;
  }

  static fromPlain(input: {
    transaction: unknown;
    signature: unknown;
    borsh_bytes: number[];
    nonceLease?: unknown;
    serverDispatch?: {
      transactionHash: string;
      rpcResult: unknown;
    };
  }): SignedTransaction {
    return new SignedTransaction({
      transaction: input.transaction,
      signature: input.signature,
      borsh_bytes: input.borsh_bytes,
      ...(input.nonceLease ? { nonceLease: input.nonceLease } : {}),
      ...(input.serverDispatch ? { serverDispatch: input.serverDispatch } : {}),
    });
  }

  encode(): ArrayBuffer {
    return new Uint8Array(this.borsh_bytes).buffer;
  }

  base64Encode(): string {
    return base64Encode(this.encode());
  }
}

type EncodableSignedTx =
  | SignedTransaction
  | {
      borsh_bytes?: unknown;
      borshBytes?: unknown;
      encode?: () => ArrayBuffer;
      base64Encode?: () => string;
    };

function toArrayBufferFromUnknownBytes(
  bytes: unknown,
): ArrayBuffer | SharedArrayBuffer | null {
  if (!bytes) return null;
  if (Array.isArray(bytes)) return new Uint8Array(bytes as number[]).buffer;
  if (ArrayBuffer.isView(bytes)) {
    const view = bytes as ArrayBufferView;
    return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  }
  if (bytes instanceof ArrayBuffer) return bytes;
  return null;
}

function encodeSignedTransactionBase64(signed: EncodableSignedTx): string {
  const maybeSigned = (signed as any)?.signedTransaction;
  const txPayload: EncodableSignedTx =
    maybeSigned && typeof maybeSigned === 'object' ? (maybeSigned as EncodableSignedTx) : signed;
  const maybeBase64 = (txPayload as { base64Encode?: unknown }).base64Encode;
  if (isFunction(maybeBase64)) {
    return (maybeBase64 as () => string).call(txPayload);
  }
  const maybeEncode = (txPayload as { encode?: unknown }).encode;
  if (isFunction(maybeEncode)) {
    return base64Encode((maybeEncode as () => ArrayBuffer).call(txPayload));
  }
  const snakeBuf = toArrayBufferFromUnknownBytes(
    (txPayload as { borsh_bytes?: unknown }).borsh_bytes,
  );
  if (snakeBuf) return base64Encode(snakeBuf);
  const camelBuf = toArrayBufferFromUnknownBytes(
    (txPayload as { borshBytes?: unknown }).borshBytes,
  );
  if (camelBuf) return base64Encode(camelBuf);
  throw new Error('Invalid signed transaction payload: cannot serialize to base64');
}

export interface NearClient {
  viewAccessKey(
    accountId: string,
    publicKey: string,
    finalityQuery?: FinalityReference,
  ): Promise<AccessKeyView>;
  viewAccessKeyList(accountId: string, finalityQuery?: FinalityReference): Promise<AccessKeyList>;
  viewAccount(accountId: string): Promise<AccountView>;
  viewCode(accountId: string, finalityQuery?: FinalityReference): Promise<Uint8Array>;
  viewBlock(params: BlockReference): Promise<BlockResult>;
  sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil?: TxExecutionStatus,
  ): Promise<FinalExecutionOutcome>;
  txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome>;
  query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T>;
  callFunction<A, T>(
    accountId: string,
    method: string,
    args: A,
    blockQuery?: BlockReference,
  ): Promise<T>;
  view<A, T>(params: { account: string; method: string; args: A }): Promise<T>;
  getAccessKeys(params: ViewAccountParams): Promise<{
    fullAccessKeys: FullAccessKey[];
    functionCallAccessKeys: FunctionCallAccessKey[];
  }>;
}

export class MinimalNearClient implements NearClient {
  private readonly rpcUrls: string[];

  constructor(rpcUrl: string | string[]) {
    this.rpcUrls = MinimalNearClient.normalizeRpcUrls(rpcUrl);
  }

  private static normalizeRpcUrls(input: string | string[]): string[] {
    const urls = Array.isArray(input)
      ? input
      : input
          .split(/[\s,]+/)
          .map((url) => url.trim())
          .filter(Boolean);
    const normalized = urls.map((url) => {
      try {
        return new URL(url).toString();
      } catch (err) {
        throw new Error(errorMessage(err) || `Invalid NEAR RPC URL: ${url}`);
      }
    });
    if (!normalized.length) throw new Error('NEAR RPC URL cannot be empty');
    return Array.from(new Set(normalized));
  }

  private buildRequestBody<P>(method: string, params: P): string {
    return JSON.stringify({
      jsonrpc: '2.0',
      id: secureRandomId('near-rpc', 32, 'NEAR JSON-RPC request IDs'),
      method,
      params,
    });
  }

  private async postOnce(url: string, requestBody: string): Promise<RpcResponse> {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: requestBody,
    });
    if (!response.ok) throw new Error(`RPC request failed: ${response.status} ${response.statusText}`);
    const text = await response.text();
    if (!text?.trim()) throw new Error('Empty response from RPC server');
    return JSON.parse(text) as RpcResponse;
  }

  private async requestWithFallback(requestBody: string): Promise<RpcResponse> {
    let lastError: unknown;
    for (const [index, url] of this.rpcUrls.entries()) {
      try {
        const result = await this.postOnce(url, requestBody);
        if (index > 0) console.warn(`[NearClient] RPC succeeded via fallback: ${url}`);
        return result;
      } catch (err) {
        lastError = err;
        const remaining = index < this.rpcUrls.length - 1;
        console.warn(
          `[NearClient] RPC call to ${url} failed${remaining ? ', trying next' : ''}: ${errorMessage(err) || 'RPC request failed'}`,
        );
        if (!remaining) throw err instanceof Error ? err : new Error(String(err));
      }
    }
    throw new Error(errorMessage(lastError) || 'RPC request failed');
  }

  private unwrapRpcResult<T>(rpc: RpcResponse, operationName: string): T {
    if (rpc.error) throw NearRpcError.fromRpcResponse(operationName, rpc);
    const result = rpc.result as any;
    if (result?.error) {
      const msg = typeof result.error === 'string' ? result.error : JSON.stringify(result.error);
      throw new NearRpcError({
        message: `${operationName} Error: ${msg}`,
        short: 'RpcError',
        type: 'RpcError',
      });
    }
    return rpc.result as T;
  }

  private async makeRpcCall<P, T>(method: string, params: P, operationName: string): Promise<T> {
    const requestBody = this.buildRequestBody(method, params);
    return this.unwrapRpcResult<T>(await this.requestWithFallback(requestBody), operationName);
  }

  async query<T extends QueryResponseKind>(params: RpcQueryRequest): Promise<T> {
    return this.makeRpcCall<RpcQueryRequest, T>(RpcCallType.Query, params, 'Query');
  }

  async viewAccessKey(
    accountId: string,
    publicKey: string,
    finalityQuery?: FinalityReference,
  ): Promise<AccessKeyView> {
    const params = {
      request_type: 'view_access_key',
      finality: finalityQuery?.finality || 'final',
      account_id: accountId,
      public_key: publicKey,
    };
    return this.makeRpcCall<typeof params, AccessKeyView>(
      RpcCallType.Query,
      params,
      'View Access Key',
    );
  }

  async viewAccessKeyList(
    accountId: string,
    finalityQuery?: FinalityReference,
  ): Promise<AccessKeyList> {
    const params = {
      request_type: 'view_access_key_list',
      finality: finalityQuery?.finality || 'final',
      account_id: accountId,
    };
    return this.makeRpcCall<typeof params, AccessKeyList>(
      RpcCallType.Query,
      params,
      'View Access Key List',
    );
  }

  async viewAccount(accountId: string): Promise<AccountView> {
    const params = { request_type: 'view_account', finality: 'final', account_id: accountId };
    return this.makeRpcCall<typeof params, AccountView>(RpcCallType.Query, params, 'View Account');
  }

  async viewCode(accountId: string, finalityQuery?: FinalityReference): Promise<Uint8Array> {
    const params = {
      request_type: 'view_code',
      finality: finalityQuery?.finality || 'final',
      account_id: accountId,
    };
    const result = await this.makeRpcCall<typeof params, any>(
      RpcCallType.Query,
      params,
      'View Code',
    );
    const codeBase64 = result?.code_base64;
    if (typeof codeBase64 !== 'string' || !codeBase64.length) {
      throw new Error('Invalid View Code response: missing code_base64');
    }
    return base64Decode(codeBase64);
  }

  async viewBlock(params: BlockReference): Promise<BlockResult> {
    return this.makeRpcCall<BlockReference, BlockResult>(RpcCallType.Block, params, 'View Block');
  }

  async sendTransaction(
    signedTransaction: SignedTransaction,
    waitUntil: TxExecutionStatus = DEFAULT_WAIT_STATUS.executeAction,
  ): Promise<FinalExecutionOutcome> {
    const params = {
      signed_tx_base64: encodeSignedTransactionBase64(signedTransaction),
      wait_until: waitUntil,
    };
    const maxAttempts = 5;
    let lastError: unknown = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const outcome = await this.makeRpcCall<typeof params, FinalExecutionOutcome>(
          RpcCallType.Send,
          params,
          'Send Transaction',
        );
        const status = (outcome as any)?.status;
        if (status && typeof status === 'object' && 'Failure' in status) {
          throw NearRpcError.fromOutcome('Send Transaction', outcome, (status as any).Failure);
        }
        return outcome;
      } catch (err: unknown) {
        lastError = err;
        const msg = errorMessage(err);
        const retryable =
          /server error|internal|temporar|timeout|too many requests|429|unavailable|bad gateway|gateway timeout/i.test(
            msg || '',
          );
        if (!retryable || attempt === maxAttempts) throw err;
        const base = 200 * Math.pow(2, attempt - 1);
        const jitter = Math.floor(Math.random() * 150);
        await new Promise((resolve) => setTimeout(resolve, base + jitter));
      }
    }
    throw lastError instanceof Error ? lastError : new Error(String(lastError));
  }

  async txStatus(txHash: string, senderAccountId: string): Promise<FinalExecutionOutcome> {
    return this.makeRpcCall(
      'EXPERIMENTAL_tx_status',
      { tx_hash: txHash, sender_account_id: senderAccountId },
      'Tx Status',
    );
  }

  async callFunction<A, T>(
    accountId: string,
    method: string,
    args: A,
    blockQuery?: BlockReference,
  ): Promise<T> {
    const rpcParams = {
      request_type: 'call_function',
      finality: 'final',
      account_id: accountId,
      method_name: method,
      args_base64: base64Encode(new TextEncoder().encode(JSON.stringify(args)).buffer),
    };
    const result = await this.makeRpcCall<typeof rpcParams, ContractResult<T>>(
      RpcCallType.Query,
      rpcParams,
      'View Function',
    );
    const resultBytes = result.result;
    if (!Array.isArray(resultBytes)) return result as unknown as T;
    const resultString = String.fromCharCode(...resultBytes);
    if (!resultString.trim()) return null as T;
    try {
      return JSON.parse(resultString) as T;
    } catch {
      return resultString.replace(/^"|"$/g, '') as T;
    }
  }

  async view<A, T>(params: { account: string; method: string; args: A }): Promise<T> {
    return this.callFunction<A, T>(params.account, params.method, params.args);
  }

  async getAccessKeys({ account, block_id }: ViewAccountParams): Promise<{
    fullAccessKeys: FullAccessKey[];
    functionCallAccessKeys: FunctionCallAccessKey[];
  }> {
    const params: Record<string, unknown> = {
      request_type: 'view_access_key_list',
      account_id: account,
      finality: 'final',
    };
    if (block_id) params.block_id = block_id;
    const result = await this.makeRpcCall<typeof params, AccessKeyList>(
      RpcCallType.Query,
      params,
      'Get Access Keys',
    );
    const keys = result.keys || [];
    const fullAccessKeys: FullAccessKey[] = [];
    const functionCallAccessKeys: FunctionCallAccessKey[] = [];
    for (const key of keys) {
      const permission = key.access_key.permission;
      if (permission === 'FullAccess') {
        fullAccessKeys.push(key as FullAccessKey);
      } else if (typeof permission === 'object' && 'FunctionCall' in permission) {
        functionCallAccessKeys.push(key as FunctionCallAccessKey);
      }
    }
    return { fullAccessKeys, functionCallAccessKeys };
  }
}
