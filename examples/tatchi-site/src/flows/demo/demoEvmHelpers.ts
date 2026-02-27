import {
  buildTempoSetUserTokenCall,
  decodeTempoUserTokenResult,
  encodeTempoUserTokensCalldata,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_FEE_MANAGER_CONTRACT,
  TEMPO_FEE_MANAGER_ABI,
} from '@tatchi-xyz/sdk';

import { FRONTEND_CONFIG } from '@/config';
import faucetAbi from '@/assets/abis/Faucet.json';

export { TEMPO_ALPHA_USD_FEE_TOKEN, TEMPO_FEE_MANAGER_CONTRACT, TEMPO_FEE_MANAGER_ABI };

export const TEMPO_GREETING_CONTRACT = '0xbb85080E6953f25197ec68798360667140EbAf4b' as `0x${string}`;
export const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691' as `0x${string}`;
export const SET_GREETING_SELECTOR = '0xa4136862';
export const TEMPO_GREETING_SELECTOR = '0xef690cc0';
export const ARC_GREET_SELECTOR = '0xcfae3217';
export const TEMPO_DRIP_SELECTOR = '0x428dc451';
export const EVM_TX_FINALITY_TIMEOUT_MS = 90_000;
export const EVM_TX_RECEIPT_POLL_INTERVAL_MS = 1_250;
export const EVM_RPC_REQUEST_TIMEOUT_MS = 15_000;
export const EIP1559_FEE_CAP_REFRESH_INTERVAL_MS = 20_000;
export const EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS = 180_000;
export const EVM_SET_USER_TOKEN_POLL_INTERVAL_MS = 500;
export const DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n; // 2 gwei
export const DEFAULT_DEMO_MAX_FEE_PER_GAS = 40_000_000_000n; // 40 gwei
export const DEFAULT_DEMO_EIP1559_FEE_CAPS: Eip1559FeeCaps = {
  maxPriorityFeePerGas: DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS,
  maxFeePerGas: DEFAULT_DEMO_MAX_FEE_PER_GAS,
};
// `setUserToken` can trigger fee-token routing paths that exceed 350k gas.
export const TEMPO_SET_USER_TOKEN_GAS_LIMIT = 1_000_000n;
export const TEMPO_DRIP_GAS_LIMIT = 300_000n;

export type Eip1559FeeCaps = {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
};

export function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

export function hexToUtf8(value: string): string {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (hex.length === 0) return '';
  if (hex.length % 2 !== 0) throw new Error('Invalid hex payload length');

  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

export function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting);
  const messageBytesLength = messageHex.length / 2;
  const dataWordLength = Math.ceil(messageBytesLength / 32) * 64;
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = messageBytesLength.toString(16).padStart(64, '0');
  const dataHex = messageHex.padEnd(dataWordLength, '0');
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${dataHex}` as `0x${string}`;
}

export function encodeTempoDripInput(tokenAddresses: readonly `0x${string}`[]): `0x${string}` {
  if (tokenAddresses.length === 0) {
    throw new Error('drip(address[]) requires at least one token address');
  }
  const encodedAddresses = tokenAddresses
    .map((address) => {
      if (!isEvmAddress(address)) {
        throw new Error(`Invalid drip token address: ${address}`);
      }
      return address.slice(2).toLowerCase().padStart(64, '0');
    })
    .join('');
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = tokenAddresses.length.toString(16).padStart(64, '0');
  return `0x${TEMPO_DRIP_SELECTOR.slice(2)}${offsetHex}${lengthHex}${encodedAddresses}` as `0x${string}`;
}

export function decodeStringResultData(rawHex: string): string {
  const resultHex = rawHex.startsWith('0x') ? rawHex.slice(2) : rawHex;
  if (resultHex.length < 128) {
    throw new Error('Invalid RPC result payload');
  }

  const dataOffsetBytes = Number.parseInt(resultHex.slice(0, 64), 16);
  if (!Number.isFinite(dataOffsetBytes) || dataOffsetBytes < 0) {
    throw new Error('Invalid ABI offset');
  }

  const dataOffsetHex = dataOffsetBytes * 2;
  const lengthStart = dataOffsetHex;
  const lengthEnd = lengthStart + 64;
  if (lengthEnd > resultHex.length) {
    throw new Error('Invalid ABI string length offset');
  }

  const stringLengthBytes = Number.parseInt(resultHex.slice(lengthStart, lengthEnd), 16);
  if (!Number.isFinite(stringLengthBytes) || stringLengthBytes < 0) {
    throw new Error('Invalid ABI string length');
  }

  const dataStart = lengthEnd;
  const dataEnd = dataStart + stringLengthBytes * 2;
  if (dataEnd > resultHex.length) {
    throw new Error('Invalid ABI string data');
  }

  return hexToUtf8(resultHex.slice(dataStart, dataEnd));
}

export type EvmJsonRpcError = {
  code?: number | string;
  message?: string;
  data?: unknown;
};

export type EvmTransactionReceipt = {
  blockNumber?: string | null;
  status?: string | null;
  gasUsed?: string | null;
};

export type EvmTransactionResponse = {
  from?: string | null;
  to?: string | null;
  input?: string | null;
  value?: string | null;
};

export async function withPromiseTimeout<T>(args: {
  promise: Promise<T>;
  timeoutMs: number;
  label: string;
  onTimeout?: () => void;
}): Promise<T> {
  const timeoutMs = Math.max(1, Math.floor(Number(args.timeoutMs) || 0));
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let settled = false;

  try {
    return await new Promise<T>((resolve, reject) => {
      timeoutId = setTimeout(() => {
        if (settled) return;
        settled = true;
        try {
          args.onTimeout?.();
        } catch {}
        reject(new Error(`${args.label} timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      args.promise.then(
        (value) => {
          if (settled) return;
          settled = true;
          if (timeoutId) clearTimeout(timeoutId);
          resolve(value);
        },
        (error: unknown) => {
          if (settled) return;
          settled = true;
          if (timeoutId) clearTimeout(timeoutId);
          reject(error);
        },
      );
    });
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
  }
}

export async function callEvmJsonRpc<T>(args: {
  rpcUrl: string;
  method: string;
  params: unknown[];
  timeoutMs?: number;
}): Promise<T> {
  const { rpcUrl, method, params } = args;
  if (!rpcUrl) {
    throw new Error('RPC URL is not configured');
  }

  const timeoutMs = args.timeoutMs ?? EVM_RPC_REQUEST_TIMEOUT_MS;
  const startedAt = Date.now();
  const remainingTimeoutMs = (): number =>
    Math.max(1, timeoutMs - Math.max(0, Date.now() - startedAt));
  const controller = new AbortController();
  const fetchPromise = fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: Date.now(),
      method,
      params,
    }),
    signal: controller.signal,
  });

  let response: Response;
  try {
    response = await withPromiseTimeout({
      promise: fetchPromise,
      timeoutMs: remainingTimeoutMs(),
      label: `${method} request`,
      onTimeout: () => {
        controller.abort();
      },
    });
  } catch (error: unknown) {
    const maybeAbort = error as { name?: string };
    if (maybeAbort?.name === 'AbortError') {
      throw new Error(`${method} request timed out after ${timeoutMs}ms`);
    }
    throw error;
  }

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}`);
  }

  const payload = (await withPromiseTimeout({
    promise: response.json() as Promise<{
      error?: EvmJsonRpcError;
      result?: T;
    }>,
    timeoutMs: remainingTimeoutMs(),
    label: `${method} response`,
    onTimeout: () => {
      controller.abort();
      try {
        response.body?.cancel();
      } catch {}
    },
  }).catch((error: unknown) => {
    const maybeAbort = error as { name?: string };
    if (maybeAbort?.name === 'AbortError') {
      throw new Error(`${method} response timed out after ${timeoutMs}ms`);
    }
    throw error;
  })) as {
    error?: EvmJsonRpcError;
    result?: T;
  };
  if (payload.error) {
    const message = String(payload.error.message || `${method} failed`).trim();
    const code =
      payload.error.code !== undefined && payload.error.code !== null
        ? String(payload.error.code).trim()
        : '';
    const data =
      payload.error.data !== undefined
        ? (() => {
            try {
              return JSON.stringify(payload.error.data);
            } catch {
              return String(payload.error.data);
            }
          })()
        : '';
    const parts = [message];
    if (code) parts.push(`code=${code}`);
    if (data) parts.push(`data=${data}`);
    const err = new Error(parts.join(' | ')) as Error & {
      code?: string;
      data?: unknown;
      rpcMethod?: string;
    };
    if (code) err.code = code;
    if (payload.error.data !== undefined) err.data = payload.error.data;
    err.rpcMethod = method;
    throw err;
  }
  if (!('result' in payload)) {
    throw new Error(`Invalid ${method} response`);
  }

  return payload.result as T;
}

export async function readEvmGreeting(params: {
  rpcUrl: string;
  contract: `0x${string}`;
  selector: `0x${string}`;
  timeoutMs?: number;
}): Promise<string> {
  const { rpcUrl, contract, selector } = params;
  const result = await callEvmJsonRpc<string>({
    rpcUrl,
    method: 'eth_call',
    params: [{ to: contract, data: selector }, 'latest'],
    timeoutMs: params.timeoutMs,
  });

  if (typeof result !== 'string' || !result.startsWith('0x')) {
    throw new Error('Invalid eth_call response');
  }

  return decodeStringResultData(result);
}

export async function sendRawEvmTransaction(args: {
  rpcUrl: string;
  rawTxHex: string;
}): Promise<`0x${string}`> {
  const txHash = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_sendRawTransaction',
    params: [args.rawTxHex],
  });
  if (typeof txHash !== 'string' || !txHash.startsWith('0x')) {
    throw new Error('Invalid eth_sendRawTransaction response');
  }
  return txHash as `0x${string}`;
}

export async function waitForEvmTransactionFinalization(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  gasLimitHint?: bigint;
  maxFeePerGasHint?: bigint;
  timeoutMs?: number;
  pollIntervalMs?: number;
}): Promise<EvmTransactionReceipt> {
  const timeoutMs = args.timeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS;
  const pollIntervalMs = args.pollIntervalMs ?? EVM_TX_RECEIPT_POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;
  let lastRpcError: string | null = null;
  let underpricedSinceMs: number | null = null;

  while (Date.now() < deadline) {
    let receipt: EvmTransactionReceipt | null = null;
    try {
      const remainingMs = Math.max(1, deadline - Date.now());
      receipt = await callEvmJsonRpc<EvmTransactionReceipt | null>({
        rpcUrl: args.rpcUrl,
        method: 'eth_getTransactionReceipt',
        params: [args.txHash],
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, remainingMs),
      });
      lastRpcError = null;
    } catch (error: unknown) {
      lastRpcError = error instanceof Error ? error.message : String(error);
    }

    if (receipt && typeof receipt === 'object' && typeof receipt.blockNumber === 'string') {
      const status = String(receipt.status || '').toLowerCase();
      if (status && status !== '0x1' && status !== '0x01') {
        const revertMessage = await describeEvmRevert({
          rpcUrl: args.rpcUrl,
          txHash: args.txHash,
          receipt,
        }).catch(() => null);
        const gasUsedInfo = String(receipt.gasUsed || '').trim();
        const gasUsed = (() => {
          try {
            return gasUsedInfo ? parseRpcHexQuantity(gasUsedInfo, 'receipt.gasUsed') : null;
          } catch {
            return null;
          }
        })();
        const gasUsedSuffix = gasUsedInfo ? `, gasUsed=${gasUsedInfo}` : '';
        const outOfGasSuffix =
          typeof args.gasLimitHint === 'bigint' && gasUsed !== null && gasUsed >= args.gasLimitHint
            ? '; likely out of gas (gasUsed reached gasLimit)'
            : '';
        const revertSuffix = revertMessage ? `; ${revertMessage}` : '';
        throw new Error(
          `Transaction reverted with status ${receipt.status}${gasUsedSuffix}${outOfGasSuffix}${revertSuffix}`,
        );
      }
      return receipt;
    }

    if (typeof args.maxFeePerGasHint === 'bigint') {
      const remainingMs = Math.max(1, deadline - Date.now());
      const latestBlock = await callEvmJsonRpc<{ baseFeePerGas?: string | null }>({
        rpcUrl: args.rpcUrl,
        method: 'eth_getBlockByNumber',
        params: ['latest', false],
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, remainingMs),
      }).catch(() => null);
      const baseFeeHex = String(latestBlock?.baseFeePerGas || '').trim();
      if (/^0x[0-9a-fA-F]+$/.test(baseFeeHex)) {
        let baseFeePerGas: bigint | null = null;
        try {
          baseFeePerGas = parseRpcHexQuantity(baseFeeHex, 'baseFeePerGas');
        } catch {
          baseFeePerGas = null;
        }
        if (baseFeePerGas !== null && baseFeePerGas > args.maxFeePerGasHint) {
          if (underpricedSinceMs === null) {
            underpricedSinceMs = Date.now();
          }
          const requiredUnderpricedDurationMs = Math.min(30_000, Math.floor(timeoutMs / 3));
          if (Date.now() - underpricedSinceMs >= requiredUnderpricedDurationMs) {
            throw new Error(
              `Transaction pending due to underpriced fees: maxFeePerGas=${formatWeiToGwei(args.maxFeePerGasHint)} gwei, latest baseFee=${formatWeiToGwei(baseFeePerGas)} gwei. Retry to re-sign with refreshed fee caps.`,
            );
          }
        } else {
          underpricedSinceMs = null;
        }
      }
    }

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, pollIntervalMs);
    });
  }

  const details = lastRpcError ? `; last RPC error: ${lastRpcError}` : '';
  throw new Error(`Timed out waiting for tx finalization after ${timeoutMs}ms${details}`);
}

export async function waitForTempoUserTokenMatch(args: {
  rpcUrl: string;
  userAddress: `0x${string}`;
  expectedToken: `0x${string}`;
  timeoutMs?: number;
  pollIntervalMs?: number;
}): Promise<`0x${string}`> {
  const timeoutMs = args.timeoutMs ?? EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS;
  const pollIntervalMs = args.pollIntervalMs ?? EVM_SET_USER_TOKEN_POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;
  let lastObservedToken: `0x${string}` | null = null;
  let lastRpcError: string | null = null;

  while (Date.now() < deadline) {
    try {
      const remainingMs = Math.max(1, deadline - Date.now());
      const token = await readTempoUserFeeToken({
        rpcUrl: args.rpcUrl,
        userAddress: args.userAddress,
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, remainingMs),
      });
      lastRpcError = null;
      lastObservedToken = token;
      if (token && token.toLowerCase() === args.expectedToken.toLowerCase()) {
        return token;
      }
    } catch (error: unknown) {
      lastRpcError = error instanceof Error ? error.message : String(error);
    }

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, pollIntervalMs);
    });
  }

  const observed = lastObservedToken ? compactHex(lastObservedToken) : 'not set';
  const details = lastRpcError ? `; last RPC error: ${lastRpcError}` : '';
  throw new Error(
    `Timed out waiting for userTokens(address) to become ${compactHex(args.expectedToken)}; observed ${observed}${details}`,
  );
}

export async function waitForEvmGreetingMatch(args: {
  rpcUrl: string;
  contract: `0x${string}`;
  selector: `0x${string}`;
  expectedGreeting: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
}): Promise<string> {
  const timeoutMs = args.timeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS;
  const pollIntervalMs = args.pollIntervalMs ?? EVM_TX_RECEIPT_POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;
  let lastObservedGreeting: string | null = null;
  let lastRpcError: string | null = null;

  while (Date.now() < deadline) {
    try {
      const remainingMs = Math.max(1, deadline - Date.now());
      const greeting = await readEvmGreeting({
        rpcUrl: args.rpcUrl,
        contract: args.contract,
        selector: args.selector,
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, remainingMs),
      });
      lastRpcError = null;
      lastObservedGreeting = greeting;
      if (greeting === args.expectedGreeting) {
        return greeting;
      }
    } catch (error: unknown) {
      lastRpcError = error instanceof Error ? error.message : String(error);
    }

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, pollIntervalMs);
    });
  }

  const observed = lastObservedGreeting == null ? 'unavailable' : `"${lastObservedGreeting}"`;
  const details = lastRpcError ? `; last RPC error: ${lastRpcError}` : '';
  throw new Error(
    `Timed out waiting for greeting update to "${args.expectedGreeting}". Last observed ${observed}${details}`,
  );
}

export async function readEvmTransactionByHash(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
}): Promise<EvmTransactionResponse | null> {
  return await callEvmJsonRpc<EvmTransactionResponse | null>({
    rpcUrl: args.rpcUrl,
    method: 'eth_getTransactionByHash',
    params: [args.txHash],
  });
}

export async function describeEvmRevert(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
  receipt: EvmTransactionReceipt;
}): Promise<string | null> {
  const tx = await readEvmTransactionByHash({
    rpcUrl: args.rpcUrl,
    txHash: args.txHash,
  });
  const from = String(tx?.from || '').trim();
  const to = String(tx?.to || '').trim();
  const data = String(tx?.input || '').trim();
  const value = String(tx?.value || '').trim();
  const blockTag = String(args.receipt.blockNumber || '').trim() || 'latest';
  if (!isEvmAddress(from) || !isEvmAddress(to) || !/^0x[0-9a-fA-F]*$/.test(data)) {
    return null;
  }
  try {
    await callEvmJsonRpc<string>({
      rpcUrl: args.rpcUrl,
      method: 'eth_call',
      params: [
        {
          from,
          to,
          data,
          value: /^0x[0-9a-fA-F]+$/.test(value) ? value : '0x0',
        },
        blockTag,
      ],
    });
    return null;
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    return message ? `replay eth_call error: ${message}` : null;
  }
}

export function parseRpcHexQuantity(value: string, label: string): bigint {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`Invalid ${label} quantity`);
  }
  return BigInt(normalized);
}

export function isEvmAddress(value: string): value is `0x${string}` {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

export async function readEvmNativeBalance(args: {
  rpcUrl: string;
  address: `0x${string}`;
  blockTag?: 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';
}): Promise<bigint> {
  const blockTag = args.blockTag ?? 'latest';
  const balanceHex = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_getBalance',
    params: [args.address, blockTag],
  });
  return parseRpcHexQuantity(balanceHex, 'eth_getBalance');
}

export async function readTempoUserFeeToken(args: {
  rpcUrl: string;
  userAddress: `0x${string}`;
  timeoutMs?: number;
}): Promise<`0x${string}` | null> {
  const result = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_call',
    params: [
      {
        to: TEMPO_FEE_MANAGER_CONTRACT,
        data: encodeTempoUserTokensCalldata(args.userAddress),
      },
      'latest',
    ],
    timeoutMs: args.timeoutMs,
  });

  if (typeof result !== 'string' || !result.startsWith('0x')) {
    throw new Error('Invalid userTokens(address) eth_call response');
  }

  return decodeTempoUserTokenResult(result);
}

export async function readTempoTokenBalanceRaw(args: {
  rpcUrl: string;
  userAddress: `0x${string}`;
  tokenAddress: `0x${string}`;
}): Promise<bigint> {
  const balanceOfSelector = '0x70a08231';
  const encodedUser = args.userAddress.slice(2).toLowerCase().padStart(64, '0');
  const result = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_call',
    params: [
      {
        to: args.tokenAddress,
        data: `${balanceOfSelector}${encodedUser}`,
      },
      'latest',
    ],
  });
  if (typeof result !== 'string' || !/^0x[0-9a-fA-F]+$/.test(result)) {
    throw new Error('Invalid TIP-20 balanceOf response');
  }
  return BigInt(result);
}

export async function resolveEip1559FeeCaps(rpcUrl: string): Promise<Eip1559FeeCaps> {
  try {
    const [latestBlock, maxPriorityFeeHex, gasPriceHex] = await Promise.all([
      callEvmJsonRpc<{ baseFeePerGas?: string | null }>({
        rpcUrl,
        method: 'eth_getBlockByNumber',
        params: ['latest', false],
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
      }).catch(() => null),
      callEvmJsonRpc<string>({
        rpcUrl,
        method: 'eth_maxPriorityFeePerGas',
        params: [],
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
      }).catch(() => null),
      callEvmJsonRpc<string>({
        rpcUrl,
        method: 'eth_gasPrice',
        params: [],
        timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
      }).catch(() => null),
    ]);

    const parsedBaseFee = (() => {
      const raw = String(latestBlock?.baseFeePerGas || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseRpcHexQuantity(raw, 'baseFeePerGas');
      } catch {
        return null;
      }
    })();
    const parsedGasPrice = (() => {
      const raw = String(gasPriceHex || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseRpcHexQuantity(raw, 'eth_gasPrice');
      } catch {
        return null;
      }
    })();
    const parsedPriority = (() => {
      const raw = String(maxPriorityFeeHex || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseRpcHexQuantity(raw, 'eth_maxPriorityFeePerGas');
      } catch {
        return null;
      }
    })();

    const baseCandidate = parsedBaseFee ?? parsedGasPrice;
    const priorityCandidate =
      parsedPriority ??
      (parsedGasPrice && parsedGasPrice > 0n ? parsedGasPrice / 10n : DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS);
    const maxPriorityFeePerGas =
      priorityCandidate > DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS
        ? priorityCandidate
        : DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS;
    const dynamicMaxFeePerGas =
      baseCandidate && baseCandidate > 0n
        ? baseCandidate * 2n + maxPriorityFeePerGas
        : parsedGasPrice && parsedGasPrice > 0n
          ? parsedGasPrice * 2n
          : 0n;
    const maxFeePerGas =
      dynamicMaxFeePerGas > DEFAULT_DEMO_MAX_FEE_PER_GAS
        ? dynamicMaxFeePerGas
        : DEFAULT_DEMO_MAX_FEE_PER_GAS;
    return {
      maxPriorityFeePerGas:
        maxPriorityFeePerGas < maxFeePerGas ? maxPriorityFeePerGas : maxFeePerGas / 2n,
      maxFeePerGas,
    };
  } catch {
    return DEFAULT_DEMO_EIP1559_FEE_CAPS;
  }
}

export function buildTempoEip1559GreetingRequest(greeting: string, feeCaps: Eip1559FeeCaps) {
  const data = encodeSetGreetingInput(greeting);
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431,
      maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: feeCaps.maxFeePerGas,
      gasLimit: 200_000n,
      to: TEMPO_GREETING_CONTRACT,
      value: 0n,
      data,
      abi: faucetAbi,
      accessList: [],
    },
  };
}

export function buildTempoEip1559DripRequest(args: {
  feeCaps: Eip1559FeeCaps;
  tokenAddresses: readonly `0x${string}`[];
}) {
  const data = encodeTempoDripInput(args.tokenAddresses);
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431,
      maxPriorityFeePerGas: args.feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: args.feeCaps.maxFeePerGas,
      gasLimit: TEMPO_DRIP_GAS_LIMIT,
      to: TEMPO_GREETING_CONTRACT,
      value: 0n,
      data,
      abi: faucetAbi,
      accessList: [],
    },
  };
}

export function buildEip1559SetUserTokenRequest(args: {
  feeCaps: Eip1559FeeCaps;
  feeToken: `0x${string}`;
}) {
  const setUserTokenCall = buildTempoSetUserTokenCall({
    token: args.feeToken,
    feeManager: TEMPO_FEE_MANAGER_CONTRACT,
  });
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431,
      maxPriorityFeePerGas: args.feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: args.feeCaps.maxFeePerGas,
      gasLimit: TEMPO_SET_USER_TOKEN_GAS_LIMIT,
      to: setUserTokenCall.to,
      value: 0n,
      data: setUserTokenCall.input || '0x',
      abi: setUserTokenCall.abi || TEMPO_FEE_MANAGER_ABI,
      accessList: [],
    },
  };
}

export function buildDemoEip1559Request(greeting: string, feeCaps: Eip1559FeeCaps) {
  const data = encodeSetGreetingInput(greeting);
  return {
    chain: 'evm' as const,
    kind: 'eip1559' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 5042002,
      maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: feeCaps.maxFeePerGas,
      gasLimit: 200_000n,
      to: ARC_TESTNET_GREETING_CONTRACT,
      value: 0n,
      data,
      abi: faucetAbi,
      accessList: [],
    },
  };
}

export function createChainDefaultGreeting(chainLabel: string): string {
  return `Hello ${chainLabel} [${new Date().toLocaleTimeString()}]`;
}

export function compactHex(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

export function isUserCancellationError(error: unknown): boolean {
  const maybeError = error as { code?: unknown; message?: unknown } | null | undefined;
  const normalizedCode = String(maybeError?.code || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (
    normalizedCode === 'cancelled' ||
    normalizedCode === 'canceled' ||
    normalizedCode === 'cancel' ||
    normalizedCode === '4001' ||
    normalizedCode === 'action_rejected' ||
    normalizedCode === 'user_rejected' ||
    normalizedCode === 'user_rejected_request' ||
    normalizedCode === 'request_rejected' ||
    normalizedCode === 'rejected_by_user' ||
    normalizedCode === 'user_denied' ||
    normalizedCode === 'user_denied_request'
  ) {
    return true;
  }

  const normalizedMessage = String(maybeError?.message ?? error ?? '')
    .trim()
    .toLowerCase();
  return (
    normalizedMessage.includes('cancelled') ||
    normalizedMessage.includes('canceled') ||
    normalizedMessage.includes('user rejected') ||
    normalizedMessage.includes('rejected by user') ||
    normalizedMessage.includes('rejected by the user') ||
    normalizedMessage.includes('the user rejected') ||
    normalizedMessage.includes('user denied') ||
    normalizedMessage.includes('denied by user')
  );
}

export function parseInsufficientFundsError(message: string): {
  haveWei: bigint;
  wantWei: bigint;
} | null {
  const match = /insufficient funds.*have\s+(\d+)\s+want\s+(\d+)/i.exec(message);
  if (!match) return null;
  try {
    return {
      haveWei: BigInt(match[1]!),
      wantWei: BigInt(match[2]!),
    };
  } catch {
    return null;
  }
}

export function formatWeiToEth(wei: bigint, precision = 6): string {
  const base = 10n ** 18n;
  const whole = wei / base;
  const fraction = wei % base;
  if (fraction === 0n) return whole.toString();
  const fractionRaw = fraction.toString().padStart(18, '0').slice(0, precision);
  const fractionTrimmed = fractionRaw.replace(/0+$/, '');
  return fractionTrimmed ? `${whole.toString()}.${fractionTrimmed}` : whole.toString();
}

export function formatWeiToGwei(wei: bigint, precision = 3): string {
  const base = 10n ** 9n;
  const whole = wei / base;
  const fraction = wei % base;
  if (fraction === 0n) return whole.toString();
  const fractionRaw = fraction.toString().padStart(9, '0').slice(0, precision);
  const fractionTrimmed = fractionRaw.replace(/0+$/, '');
  return fractionTrimmed ? `${whole.toString()}.${fractionTrimmed}` : whole.toString();
}

export function getRawTxTypePrefix(rawTxHex: string): string {
  const normalized = String(rawTxHex || '')
    .trim()
    .toLowerCase();
  if (!normalized.startsWith('0x') || normalized.length < 4) return 'unknown';
  return normalized.slice(0, 4);
}

export function assertRawTxTypePrefix(args: {
  requestKind: 'eip1559';
  rawTxHex: string;
}): void {
  const expected = '0x02';
  const actual = getRawTxTypePrefix(args.rawTxHex);
  if (actual !== expected) {
    throw new Error(
      `Unexpected raw tx type prefix ${actual} for ${args.requestKind}; expected ${expected}.`,
    );
  }
}
