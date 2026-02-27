import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import {
  buildTempoSetUserTokenCall,
  decodeTempoUserTokenResult,
  encodeTempoUserTokensCalldata,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_FEE_MANAGER_CONTRACT,
} from '@tatchi-xyz/sdk';

import {
  ActionPhase,
  ActionResult,
  ActionType,
  TxExecutionStatus,
  useTatchi,
} from '@tatchi-xyz/sdk/react';
import type { ActionArgs, FunctionCallAction } from '@tatchi-xyz/sdk/react';

import { LoadingButton } from './LoadingButton';
import Refresh from './icons/Refresh';
import { CopyButton } from './CopyButton';
import { useSetGreeting } from '../hooks/useSetGreeting';
import { DEMO_CONTRACT_ID, NEAR_EXPLORER_BASE_URL } from '../types';
import { FRONTEND_CONFIG } from '../config';
import faucetAbi from '../assets/abis/Faucet.json';
import './DemoPage.css';

const TEMPO_GREETING_CONTRACT = '0xbb85080E6953f25197ec68798360667140EbAf4b' as `0x${string}`;
const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691' as `0x${string}`;
const SET_GREETING_SELECTOR = '0xa4136862';
const TEMPO_GREETING_SELECTOR = '0xef690cc0';
const ARC_GREET_SELECTOR = '0xcfae3217';
const TEMPO_DRIP_SELECTOR = '0x428dc451';
const EVM_TX_FINALITY_TIMEOUT_MS = 90_000;
const EVM_TX_RECEIPT_POLL_INTERVAL_MS = 1_250;
const EVM_RPC_REQUEST_TIMEOUT_MS = 15_000;
const EIP1559_FEE_CAP_REFRESH_INTERVAL_MS = 20_000;
const EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS = 180_000;
const EVM_SET_USER_TOKEN_POLL_INTERVAL_MS = 500;
const DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n; // 2 gwei
const DEFAULT_DEMO_MAX_FEE_PER_GAS = 40_000_000_000n; // 40 gwei
const DEFAULT_DEMO_EIP1559_FEE_CAPS: Eip1559FeeCaps = {
  maxPriorityFeePerGas: DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS,
  maxFeePerGas: DEFAULT_DEMO_MAX_FEE_PER_GAS,
};
// `setUserToken` can trigger fee-token routing paths that exceed 350k gas.
const TEMPO_SET_USER_TOKEN_GAS_LIMIT = 1_000_000n;
const TEMPO_DRIP_GAS_LIMIT = 300_000n;

type Eip1559FeeCaps = {
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
};

function utf8ToHex(value: string): string {
  return Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');
}

function hexToUtf8(value: string): string {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  if (hex.length === 0) return '';
  if (hex.length % 2 !== 0) throw new Error('Invalid hex payload length');

  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < hex.length; index += 2) {
    bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

function encodeSetGreetingInput(greeting: string): `0x${string}` {
  const messageHex = utf8ToHex(greeting);
  const messageBytesLength = messageHex.length / 2;
  const dataWordLength = Math.ceil(messageBytesLength / 32) * 64;
  const offsetHex = (32).toString(16).padStart(64, '0');
  const lengthHex = messageBytesLength.toString(16).padStart(64, '0');
  const dataHex = messageHex.padEnd(dataWordLength, '0');
  return `0x${SET_GREETING_SELECTOR.slice(2)}${offsetHex}${lengthHex}${dataHex}` as `0x${string}`;
}

function encodeTempoDripInput(tokenAddresses: readonly `0x${string}`[]): `0x${string}` {
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

function decodeStringResultData(rawHex: string): string {
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

type EvmJsonRpcError = {
  code?: number | string;
  message?: string;
  data?: unknown;
};

type EvmTransactionReceipt = {
  blockNumber?: string | null;
  status?: string | null;
  gasUsed?: string | null;
};

type EvmTransactionResponse = {
  from?: string | null;
  to?: string | null;
  input?: string | null;
  value?: string | null;
};

async function withPromiseTimeout<T>(args: {
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

async function callEvmJsonRpc<T>(args: {
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

async function readEvmGreeting(params: {
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

async function sendRawEvmTransaction(args: {
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

async function waitForEvmTransactionFinalization(args: {
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

async function waitForTempoUserTokenMatch(args: {
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

async function waitForEvmGreetingMatch(args: {
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

async function readEvmTransactionByHash(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
}): Promise<EvmTransactionResponse | null> {
  return await callEvmJsonRpc<EvmTransactionResponse | null>({
    rpcUrl: args.rpcUrl,
    method: 'eth_getTransactionByHash',
    params: [args.txHash],
  });
}

async function describeEvmRevert(args: {
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

function parseRpcHexQuantity(value: string, label: string): bigint {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`Invalid ${label} quantity`);
  }
  return BigInt(normalized);
}

function isEvmAddress(value: string): value is `0x${string}` {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

async function readEvmNativeBalance(args: {
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

async function readTempoUserFeeToken(args: {
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

async function readTempoTokenBalanceRaw(args: {
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

async function resolveEip1559FeeCaps(rpcUrl: string): Promise<Eip1559FeeCaps> {
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

function buildTempoEip1559GreetingRequest(greeting: string, feeCaps: Eip1559FeeCaps) {
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

function buildTempoEip1559DripRequest(args: {
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

function buildEip1559SetUserTokenRequest(args: {
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
      accessList: [],
    },
  };
}

function buildDemoEip1559Request(greeting: string, feeCaps: Eip1559FeeCaps) {
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

function createChainDefaultGreeting(chainLabel: string): string {
  return `Hello ${chainLabel} [${new Date().toLocaleTimeString()}]`;
}

function compactHex(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

function isUserCancellationError(error: unknown): boolean {
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

function parseInsufficientFundsError(message: string): {
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

function formatWeiToEth(wei: bigint, precision = 6): string {
  const base = 10n ** 18n;
  const whole = wei / base;
  const fraction = wei % base;
  if (fraction === 0n) return whole.toString();
  const fractionRaw = fraction.toString().padStart(18, '0').slice(0, precision);
  const fractionTrimmed = fractionRaw.replace(/0+$/, '');
  return fractionTrimmed ? `${whole.toString()}.${fractionTrimmed}` : whole.toString();
}

function formatWeiToGwei(wei: bigint, precision = 3): string {
  const base = 10n ** 9n;
  const whole = wei / base;
  const fraction = wei % base;
  if (fraction === 0n) return whole.toString();
  const fractionRaw = fraction.toString().padStart(9, '0').slice(0, precision);
  const fractionTrimmed = fractionRaw.replace(/0+$/, '');
  return fractionTrimmed ? `${whole.toString()}.${fractionTrimmed}` : whole.toString();
}

function getRawTxTypePrefix(rawTxHex: string): string {
  const normalized = String(rawTxHex || '')
    .trim()
    .toLowerCase();
  if (!normalized.startsWith('0x') || normalized.length < 4) return 'unknown';
  return normalized.slice(0, 4);
}

function assertRawTxTypePrefix(args: {
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

type DemoPageTestOverrides = {
  useTatchiHook?: typeof useTatchi;
  useSetGreetingHook?: typeof useSetGreeting;
};

type DemoPageProps = {
  __testOverrides?: DemoPageTestOverrides;
};

export const DemoPage: React.FC<DemoPageProps> = (props) => {
  const useTatchiHook = props.__testOverrides?.useTatchiHook || useTatchi;
  const useSetGreetingHook = props.__testOverrides?.useSetGreetingHook || useSetGreeting;

  const [clockMs, setClockMs] = useState(() => Date.now());

  // Lightweight clock for TTL countdown display
  useEffect(() => {
    const id = window.setInterval(() => setClockMs(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const {
    loginState: { isLoggedIn, nearAccountId },
    tatchi,
  } = useTatchiHook();

  const { onchainGreeting, isLoading, fetchGreeting, error } = useSetGreetingHook();

  const [greetingInput, setGreetingInput] = useState('Hello from Tatchi!');
  const [tempoGreetingInput, setTempoGreetingInput] = useState(() =>
    createChainDefaultGreeting('Tempo'),
  );
  const [arcGreetingInput, setArcGreetingInput] = useState(() => createChainDefaultGreeting('Arc'));
  const [txLoading, setTxLoading] = useState(false);
  const [delegateLoading, setDelegateLoading] = useState(false);
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [sessionRemainingUsesInput, setSessionRemainingUsesInput] = useState(3);
  const [sessionTtlSecondsInput, setSessionTtlSecondsInput] = useState(300);
  const [sessionStatus, setSessionStatus] = useState<{
    sessionId: string;
    status: 'active' | 'exhausted' | 'expired' | 'not_found';
    remainingUses?: number;
    expiresAtMs?: number;
    createdAtMs?: number;
  } | null>(null);

  const [tempoThresholdSignLoading, setTempoThresholdSignLoading] = useState(false);
  const [tempoDripLoading, setTempoDripLoading] = useState(false);
  const [tempoFeeTokenConfigLoading, setTempoFeeTokenConfigLoading] = useState(false);
  const [tempoFeeTokenConfigTarget, setTempoFeeTokenConfigTarget] = useState<'alpha' | null>(
    null,
  );
  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);
  const [tempoGreeting, setTempoGreeting] = useState<string | null>(null);
  const [arcGreeting, setArcGreeting] = useState<string | null>(null);
  const [tempoGreetingLoading, setTempoGreetingLoading] = useState(false);
  const [arcGreetingLoading, setArcGreetingLoading] = useState(false);
  const [tempoGreetingError, setTempoGreetingError] = useState<string | null>(null);
  const [arcGreetingError, setArcGreetingError] = useState<string | null>(null);
  const [thresholdEvmFundingAddress, setThresholdEvmFundingAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<`0x${string}` | null>(null);
  const [tempoEip1559FeeCaps, setTempoEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );
  const [arcEip1559FeeCaps, setArcEip1559FeeCaps] = useState<Eip1559FeeCaps>(
    DEFAULT_DEMO_EIP1559_FEE_CAPS,
  );

  const refreshSessionStatus = useCallback(async () => {
    if (!nearAccountId) return;
    try {
      const sess = await tatchi.auth.getSession(nearAccountId);
      setSessionStatus(sess?.signingSession || null);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Failed to fetch session status: ${message}`, { id: 'session-status' });
    }
  }, [nearAccountId, tatchi]);

  // Fetch session status on mount/account change (best-effort; errors are toast-only)
  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void refreshSessionStatus();
  }, [isLoggedIn, nearAccountId, refreshSessionStatus]);

  useEffect(() => {
    let cancelled = false;
    const refreshFeeCaps = async (): Promise<void> => {
      const [tempoCaps, arcCaps] = await Promise.all([
        resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl).catch(
          () => DEFAULT_DEMO_EIP1559_FEE_CAPS,
        ),
        resolveEip1559FeeCaps(FRONTEND_CONFIG.arcRpcUrl).catch(() => DEFAULT_DEMO_EIP1559_FEE_CAPS),
      ]);
      if (cancelled) return;
      setTempoEip1559FeeCaps(tempoCaps);
      setArcEip1559FeeCaps(arcCaps);
    };

    void refreshFeeCaps();
    const intervalId = window.setInterval(() => {
      void refreshFeeCaps();
    }, EIP1559_FEE_CAP_REFRESH_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  const handleUnlockSession = useCallback(async () => {
    if (!nearAccountId) return;

    const remainingUses = Number.isFinite(sessionRemainingUsesInput)
      ? Math.max(0, Math.floor(sessionRemainingUsesInput))
      : undefined;
    const ttlSeconds = Number.isFinite(sessionTtlSecondsInput)
      ? Math.max(0, Math.floor(sessionTtlSecondsInput))
      : undefined;
    const ttlMs = typeof ttlSeconds === 'number' ? ttlSeconds * 1000 : undefined;

    setUnlockLoading(true);
    toast.loading('Logging in & creating session…', { id: 'unlock-session' });
    try {
      await tatchi.auth.login(nearAccountId, {
        signingSession: { ttlMs, remainingUses },
      });
      await refreshSessionStatus();
      toast.success('Session ready', { id: 'unlock-session' });
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Failed to create session: ${message}`, { id: 'unlock-session' });
    } finally {
      setUnlockLoading(false);
    }
  }, [
    nearAccountId,
    refreshSessionStatus,
    sessionRemainingUsesInput,
    sessionTtlSecondsInput,
    tatchi,
  ]);

  const canExecuteGreeting = useCallback(
    (val: string, loggedIn: boolean, accountId?: string | null) =>
      Boolean(val?.trim()) && loggedIn && Boolean(accountId),
    [],
  );

  const handleRefreshGreeting = async () => {
    await fetchGreeting();
  };

  const createGreetingAction = useCallback(
    (greeting: string, opts?: { postfix?: string }): ActionArgs => {
      const base = greeting.trim();
      const parts = [base];
      if (opts?.postfix && opts.postfix.trim()) parts.push(`[${opts.postfix.trim()}]`);
      parts.push(`[${new Date().toLocaleTimeString()}]`);
      const message = parts.join(' ');
      return {
        type: ActionType.FunctionCall,
        methodName: 'set_greeting',
        args: { greeting: message },
        gas: '30000000000000',
        deposit: '0',
      };
    },
    [],
  );

  const handleSetGreeting = useCallback(async () => {
    if (!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId)) return;
    const actionToExecute: FunctionCallAction = createGreetingAction(
      greetingInput,
    ) as FunctionCallAction;
    const secondActionToExecute: FunctionCallAction = createGreetingAction(greetingInput, {
      postfix: 'Tx 2',
    }) as FunctionCallAction;

    setTxLoading(true);
    let signingFailureMessage: string | null = null;
    try {
      await tatchi.near.signAndSendTransactions({
        nearAccountId: nearAccountId!,
        transactions: [
          {
            receiverId: DEMO_CONTRACT_ID,
            actions: [actionToExecute, actionToExecute],
          },
          {
            receiverId: DEMO_CONTRACT_ID,
            actions: [secondActionToExecute],
          },
        ],
        options: {
          onEvent: (event) => {
            switch (event.phase) {
              case ActionPhase.STEP_1_PREPARATION:
              case ActionPhase.STEP_3_WEBAUTHN_AUTHENTICATION:
              case ActionPhase.STEP_4_AUTHENTICATION_COMPLETE:
              case ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS:
              case ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE:
                toast.loading(event.message, { id: 'greeting' });
                break;
              case ActionPhase.STEP_7_BROADCASTING:
                toast.loading(event.message, { id: 'greeting' });
                break;
              case ActionPhase.ACTION_ERROR:
              case ActionPhase.WASM_ERROR:
                toast.error(`Transaction failed: ${event.error}`, { id: 'greeting' });
                break;
            }
          },
          onError: (error: unknown) => {
            const message = String((error as { message?: unknown })?.message || error || '').trim();
            if (message) signingFailureMessage = message;
          },
          waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
          afterCall: (success: boolean, results?: ActionResult[], error?: Error) => {
            try {
              toast.dismiss('greeting');
            } catch {}
            const normalizedResults = Array.isArray(results) ? results : [];
            const successfulResults = normalizedResults.filter((item) => item?.success !== false);
            const latestTxId =
              successfulResults.at(-1)?.transactionId || normalizedResults.at(-1)?.transactionId;
            const isSuccess = success && successfulResults.length > 0;
            if (isSuccess && latestTxId) {
              const txLink = `${NEAR_EXPLORER_BASE_URL}/transactions/${latestTxId}`;
              toast.success('Greeting updated on-chain', {
                description: (
                  <a href={txLink} target="_blank" rel="noopener noreferrer">
                    View transaction on NearBlocks
                  </a>
                ),
              });
              setGreetingInput('');
              setTimeout(() => fetchGreeting(), 1000);
            } else {
              const callbackErrorMessage = String(error?.message || '').trim();
              const message =
                normalizedResults.find((item) => item?.error)?.error ||
                callbackErrorMessage ||
                signingFailureMessage ||
                (isSuccess ? 'Missing transaction ID' : 'Unknown error');
              toast.error(`Greeting update failed: ${message}`);
            }
            setTxLoading(false);
          },
        },
      });
    } catch (error: unknown) {
      if (!signingFailureMessage) {
        const fallbackMessage = String(
          (error as { message?: unknown })?.message || error || 'Unknown error',
        );
        toast.error(`Greeting update failed: ${fallbackMessage}`);
      }
      setTxLoading(false);
    }
  }, [
    canExecuteGreeting,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    tatchi,
  ]);

  const handleSignDelegateGreeting = useCallback(async () => {
    if (!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId)) return;

    const { login: loginState } = await tatchi.auth.getSession();

    setDelegateLoading(true);
    try {
      const relayerUrl = tatchi.configs.network?.relayer?.url;
      if (!relayerUrl) {
        toast.error('Relayer URL is not configured: VITE_RELAYER_URL', {
          id: 'delegate-greeting',
        });
        return;
      }

      const delegateAction = createGreetingAction(greetingInput, { postfix: 'Delegate' });
      const result = await tatchi.near.signDelegateAction({
        nearAccountId: nearAccountId!,
        delegate: {
          senderId: nearAccountId!,
          receiverId: DEMO_CONTRACT_ID,
          actions: [delegateAction],
          nonce: Date.now(),
          maxBlockHeight: 0,
          publicKey: loginState.publicKey!,
        },
        options: {
          onEvent: (event) => {
            switch (event.phase) {
              case ActionPhase.STEP_1_PREPARATION:
              case ActionPhase.STEP_2_USER_CONFIRMATION:
              case ActionPhase.STEP_5_TRANSACTION_SIGNING_PROGRESS:
                toast.loading(event.message, { id: 'delegate-greeting' });
                break;
              case ActionPhase.STEP_6_TRANSACTION_SIGNING_COMPLETE:
                toast.success('Delegate action signed', { id: 'delegate-greeting' });
                break;
              case ActionPhase.ACTION_ERROR:
              case ActionPhase.WASM_ERROR:
                toast.error(`Delegate signing failed: ${event.error}`, { id: 'delegate-greeting' });
                break;
            }
          },
        },
      });

      toast.success('Signed delegate for set_greeting', {
        description: (
          <span>
            Delegate hash:&nbsp;
            <code>{result.hash.slice(0, 16)}…</code>
          </span>
        ),
      });

      toast.loading('Submitting delegate to relayer…', { id: 'delegate-relay' });
      const relayResult = await tatchi.near.sendDelegateActionViaRelayer({
        relayerUrl,
        hash: result.hash,
        signedDelegate: result.signedDelegate as unknown as Record<string, unknown>,
        options: {
          afterCall: (success: boolean, res?: { ok?: boolean }) => {
            if (success && res?.ok !== false) {
              setTimeout(() => fetchGreeting(), 1000);
            }
          },
        },
      });

      toast.dismiss('delegate-relay');

      if (!relayResult.ok) {
        toast.error(`Relayer execution failed: ${relayResult.error || 'Unknown error'}`, {
          id: 'delegate-greeting',
        });
        return;
      }

      const txId = relayResult.relayerTxHash;
      if (txId) {
        const txLink = `${NEAR_EXPLORER_BASE_URL}/transactions/${txId}`;
        toast.success('Delegate executed via relayer', {
          description: (
            <a href={txLink} target="_blank" rel="noopener noreferrer">
              View transaction on NearBlocks
            </a>
          ),
          id: 'delegate-greeting',
        });
      } else {
        toast.success('Delegate submitted via relayer (no TxID)', { id: 'delegate-greeting' });
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      toast.error(`Delegate signing failed: ${message}`, { id: 'delegate-greeting' });
    } finally {
      setDelegateLoading(false);
    }
  }, [
    canExecuteGreeting,
    createGreetingAction,
    fetchGreeting,
    greetingInput,
    isLoggedIn,
    nearAccountId,
    tatchi,
  ]);

  const fetchTempoGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setTempoGreetingLoading(true);
    setTempoGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
        selector: TEMPO_GREETING_SELECTOR,
      });
      setTempoGreeting(greeting);
      return greeting;
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setTempoGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Tempo greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setTempoGreetingLoading(false);
    }
  }, []);

  const fetchArcGreeting = useCallback(async (opts?: { silent?: boolean }) => {
    setArcGreetingLoading(true);
    setArcGreetingError(null);
    try {
      const greeting = await readEvmGreeting({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        contract: ARC_TESTNET_GREETING_CONTRACT,
        selector: ARC_GREET_SELECTOR,
      });
      setArcGreeting(greeting);
      return greeting;
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : String(e);
      setArcGreetingError(message);
      if (!opts?.silent) {
        toast.error(`Arc greeting fetch failed: ${message}`);
      }
      return null;
    } finally {
      setArcGreetingLoading(false);
    }
  }, []);

  const refreshThresholdEvmFundingAddress = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) {
      setThresholdEvmFundingAddress(null);
      return null;
    }
    try {
      const session = await tatchi.auth.getSession(nearAccountId);
      const address = String(session.login.thresholdEcdsaEthereumAddress || '').trim();
      setThresholdEvmFundingAddress(address || null);
      return address || null;
    } catch {
      setThresholdEvmFundingAddress(null);
      return null;
    }
  }, [isLoggedIn, nearAccountId, tatchi]);

  const resolveThresholdSenderForEvmFamily = useCallback(async (): Promise<`0x${string}`> => {
    const thresholdSender =
      thresholdEvmFundingAddress || (await refreshThresholdEvmFundingAddress());
    if (!thresholdSender || !isEvmAddress(thresholdSender)) {
      throw new Error('Threshold EVM sender address is unavailable');
    }
    return thresholdSender;
  }, [refreshThresholdEvmFundingAddress, thresholdEvmFundingAddress]);

  const refreshTempoUserFeeToken = useCallback(
    async (opts?: { silent?: boolean; userAddress?: `0x${string}` | null }) => {
      const maybeAddress = String(opts?.userAddress || thresholdEvmFundingAddress || '').trim();
      if (!isEvmAddress(maybeAddress)) {
        setTempoUserFeeToken(null);
        return null;
      }

      try {
        const token = await readTempoUserFeeToken({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          userAddress: maybeAddress,
        });
        setTempoUserFeeToken(token);
        return token;
      } catch (e: unknown) {
        const message = e instanceof Error ? e.message : String(e);
        setTempoUserFeeToken(null);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token check failed: ${message}`);
        }
        return null;
      }
    },
    [thresholdEvmFundingAddress],
  );

  const refreshTempoUserFeeTokenBalance = useCallback(
    async (opts?: {
      silent?: boolean;
      userAddress?: `0x${string}` | null;
      feeToken?: `0x${string}` | null;
    }) => {
      const maybeAddress = String(opts?.userAddress || thresholdEvmFundingAddress || '').trim();
      const maybeToken = String(opts?.feeToken || tempoUserFeeToken || '').trim();
      if (!isEvmAddress(maybeAddress) || !isEvmAddress(maybeToken)) {
        return null;
      }
      try {
        const balance = await readTempoTokenBalanceRaw({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          userAddress: maybeAddress,
          tokenAddress: maybeToken,
        });
        return balance;
      } catch (e: unknown) {
        const message = e instanceof Error ? e.message : String(e);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token balance check failed: ${message}`);
        }
        return null;
      }
    },
    [tempoUserFeeToken, thresholdEvmFundingAddress],
  );

  const configureTempoFeeToken = useCallback(
    async (args: {
      token: `0x${string}`;
      label: string;
      target: 'alpha';
    }) => {
      if (!isLoggedIn || !nearAccountId) return;
      const toastId = 'tempo-set-fee-token';
      try {
        toast.dismiss(toastId);
      } catch {}
      setTempoFeeTokenConfigLoading(true);
      setTempoFeeTokenConfigTarget(args.target);
      toast.loading(`Configuring Tempo fee token to ${args.label}…`, { id: toastId });
      let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null =
        null;
      let thresholdSenderForAttempt: `0x${string}` | null = null;
      let selectedFeeTokenBalanceRaw: bigint | null = null;
      let senderNativeBalanceRaw: bigint | null = null;
      try {
        const tempoFeeToken = args.token;
        const request = buildEip1559SetUserTokenRequest({
          feeCaps: tempoEip1559FeeCaps,
          feeToken: tempoFeeToken,
        });
        const thresholdSenderPromise = resolveThresholdSenderForEvmFamily()
          .then((sender) => {
            thresholdSenderForAttempt = sender;
            return sender;
          })
          .catch(() => null);
        const diagnosticsPromise = (async () => {
          const thresholdSender = await thresholdSenderPromise;
          if (!thresholdSender) return;
          selectedFeeTokenBalanceRaw = await readTempoTokenBalanceRaw({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            userAddress: thresholdSender,
            tokenAddress: tempoFeeToken,
          }).catch(() => null);
          senderNativeBalanceRaw = await readEvmNativeBalance({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            address: thresholdSender,
            blockTag: 'latest',
          }).catch(() => null);
        })().catch(() => undefined);

        const signed = await tatchi.tempo.signTempo({
          nearAccountId,
          request,
        });
        signedResultForBroadcast = signed;
        if (signed.kind !== 'eip1559') {
          throw new Error(`Unexpected signing result kind: ${signed.kind}`);
        }
        assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

        toast.loading('Dispatching setUserToken transaction…', { id: toastId });
        const txHash = await sendRawEvmTransaction({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          rawTxHex: signed.rawTxHex,
        });
        await tatchi.tempo.reportBroadcastResult({
          nearAccountId,
          signedResult: signed,
          status: 'success',
          txHash,
        });

        toast.loading('Waiting for setUserToken finalization…', { id: toastId });
        const thresholdSender = await thresholdSenderPromise;
        const receiptConfirmationResultPromise = waitForEvmTransactionFinalization({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          txHash,
          gasLimitHint: request.tx.gasLimit,
          maxFeePerGasHint: request.tx.maxFeePerGas,
          timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
          pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
        })
          .then(
            () =>
              ({
                ok: true as const,
                mode: 'receipt' as const,
              }) as const,
          )
          .catch(
            (error: unknown) =>
              ({
                ok: false as const,
                source: 'receipt' as const,
                error,
              }) as const,
          );
        const tokenConfirmationResultPromise = thresholdSender
          ? waitForTempoUserTokenMatch({
              rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
              userAddress: thresholdSender,
              expectedToken: tempoFeeToken,
              timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS,
              pollIntervalMs: EVM_SET_USER_TOKEN_POLL_INTERVAL_MS,
            })
              .then(
                () =>
                  ({
                    ok: true as const,
                    mode: 'userToken' as const,
                  }) as const,
              )
              .catch(
                (error: unknown) =>
                  ({
                    ok: false as const,
                    source: 'userToken' as const,
                    error,
                  }) as const,
              )
          : Promise.resolve({
              ok: false as const,
              source: 'userToken' as const,
              error: new Error('Threshold EVM sender unavailable for userTokens confirmation'),
            });
        const firstConfirmationResult = await withPromiseTimeout({
          promise: Promise.race([
            receiptConfirmationResultPromise,
            tokenConfirmationResultPromise,
          ]),
          timeoutMs: EVM_SET_USER_TOKEN_FINALITY_TIMEOUT_MS + EVM_RPC_REQUEST_TIMEOUT_MS + 5_000,
          label: 'setUserToken finalization confirmation',
        });
        let confirmationMode: 'receipt' | 'userToken';
        if (firstConfirmationResult.ok) {
          confirmationMode = firstConfirmationResult.mode;
        } else {
          const secondConfirmationResult =
            firstConfirmationResult.source === 'receipt'
              ? await tokenConfirmationResultPromise
              : await receiptConfirmationResultPromise;
          if (secondConfirmationResult.ok) {
            confirmationMode = secondConfirmationResult.mode;
          } else {
            const receiptError =
              firstConfirmationResult.source === 'receipt'
                ? firstConfirmationResult.error
                : secondConfirmationResult.error;
            const userTokenError =
              firstConfirmationResult.source === 'userToken'
                ? firstConfirmationResult.error
                : secondConfirmationResult.error;
            const receiptErrorMessage =
              receiptError instanceof Error ? receiptError.message : String(receiptError);
            const userTokenErrorMessage =
              userTokenError instanceof Error ? userTokenError.message : String(userTokenError);
            throw new Error(
              `Unable to confirm setUserToken to ${args.label}. Receipt check failed: ${receiptErrorMessage}. userTokens(address) check failed: ${userTokenErrorMessage}.`,
            );
          }
        }
        const refreshedFeeToken = thresholdSender
          ? await refreshTempoUserFeeToken({
              silent: true,
              userAddress: thresholdSender,
            })
          : null;
        if (thresholdSender) {
          await refreshTempoUserFeeTokenBalance({
            silent: true,
            userAddress: thresholdSender,
            feeToken: tempoFeeToken,
          });
        }
        const refreshedMatchesTarget =
          !!refreshedFeeToken &&
          refreshedFeeToken.toLowerCase() === tempoFeeToken.toLowerCase();
        if (thresholdSender && !refreshedMatchesTarget) {
          throw new Error(
            `setUserToken confirmation (${confirmationMode}) completed, but refreshed userTokens(address) reports ${refreshedFeeToken ? compactHex(refreshedFeeToken) : 'not set'} instead of ${compactHex(tempoFeeToken)}. Tx hash: ${txHash}`,
          );
        }
        await diagnosticsPromise;

        toast.success(
          confirmationMode === 'userToken'
            ? 'Tempo fee token configured (confirmed via userTokens)'
            : 'Tempo fee token configured',
          {
            id: toastId,
            description: (
              <span>
                Token:&nbsp;
                <code>{args.label}</code>&nbsp;
                <code>{compactHex(tempoFeeToken)}</code>
                <br />
                Tx hash:&nbsp;
                <code>{compactHex(txHash)}</code>
                {confirmationMode === 'userToken' ? (
                  <>
                    <br />
                    Confirmed from `userTokens(address)` before receipt finalization.
                  </>
                ) : null}
              </span>
            ),
          },
        );
      } catch (e: unknown) {
        const resolvedError: unknown = e;
        if (signedResultForBroadcast) {
          try {
            await tatchi.tempo.reportBroadcastResult({
              nearAccountId,
              signedResult: signedResultForBroadcast,
              status: 'failure',
              error: resolvedError,
            });
          } catch (reportError: unknown) {
            console.error('[DemoPage][BroadcastReportError]', {
              atIso: new Date().toISOString(),
              flow: 'tempo-set-fee-token',
              originalError: resolvedError,
              reportError,
            });
          }
        }
        const errorDetails =
          resolvedError && typeof resolvedError === 'object' && 'details' in resolvedError
            ? (resolvedError as { details?: unknown }).details
            : undefined;
        console.error('[DemoPage][TempoSetFeeTokenError]', {
          atIso: new Date().toISOString(),
          label: args.label,
          error: resolvedError,
          details: errorDetails,
        });
        if (isUserCancellationError(resolvedError)) {
          toast.error(`Tempo fee token setup to ${args.label} cancelled by user.`, { id: toastId });
          return;
        }
        const message =
          resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
        const insufficient = parseInsufficientFundsError(message);
        if (insufficient && insufficient.haveWei === 0n) {
          const senderText = thresholdSenderForAttempt
            ? compactHex(thresholdSenderForAttempt)
            : 'unknown sender';
          const nativeBalanceText =
            typeof senderNativeBalanceRaw === 'bigint'
              ? (senderNativeBalanceRaw as bigint).toString()
              : 'unknown';
          const selectedBalanceText =
            typeof selectedFeeTokenBalanceRaw === 'bigint'
              ? (selectedFeeTokenBalanceRaw as bigint).toString()
              : 'unknown';
          toast.error(
            `Tempo fee token setup to ${args.label} failed: insufficient native gas for EIP-1559 bootstrap tx (have 0, need ${insufficient.wantWei.toString()}). Sender ${senderText} native balance is ${nativeBalanceText}; ${args.label} token balance is ${selectedBalanceText}.`,
            { id: toastId },
          );
          return;
        }
        toast.error(`Tempo fee token setup to ${args.label} failed: ${message}`, { id: toastId });
      } finally {
        setTempoFeeTokenConfigLoading(false);
        setTempoFeeTokenConfigTarget(null);
      }
    },
    [
      isLoggedIn,
      nearAccountId,
      refreshTempoUserFeeToken,
      refreshTempoUserFeeTokenBalance,
      resolveThresholdSenderForEvmFamily,
      tatchi,
      tempoEip1559FeeCaps,
    ],
  );

  const handleSetTempoFeeTokenAlphaUsd = useCallback(
    async () =>
      await configureTempoFeeToken({
        token: TEMPO_ALPHA_USD_FEE_TOKEN,
        label: 'AlphaUSD',
        target: 'alpha',
      }),
    [configureTempoFeeToken],
  );

  const handleTempoDripToken = useCallback(async () => {
    if (!isLoggedIn || !nearAccountId) return;
    const toastId = 'tempo-drip-token';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoDripLoading(true);
    toast.loading('Requesting Tempo token drip…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    let dripTokensForAttempt: `0x${string}`[] = [];
    let senderNativeBalanceRaw: bigint | null = null;
    try {
      const configuredTokenRaw = String(tempoUserFeeToken || '').trim();
      const dripToken = isEvmAddress(configuredTokenRaw)
        ? configuredTokenRaw
        : TEMPO_ALPHA_USD_FEE_TOKEN;
      dripTokensForAttempt = [dripToken];
      const thresholdSenderPromise = resolveThresholdSenderForEvmFamily().catch(() => null);
      const senderNativeBalancePromise = thresholdSenderPromise.then(async (thresholdSender) => {
        if (!thresholdSender) return null;
        return await readEvmNativeBalance({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          address: thresholdSender,
          blockTag: 'latest',
        }).catch(() => null);
      });
      const request = buildTempoEip1559DripRequest({
        feeCaps: tempoEip1559FeeCaps,
        tokenAddresses: dripTokensForAttempt,
      });
      const signed = await tatchi.tempo.signTempo({
        nearAccountId,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching Tempo drip transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId,
        signedResult: signed,
        status: 'success',
        txHash,
      });

      toast.loading('Tempo drip transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
      });
      const thresholdSender = await thresholdSenderPromise;
      if (thresholdSender) {
        await refreshTempoUserFeeTokenBalance({
          silent: true,
          userAddress: thresholdSender,
          feeToken: dripToken,
        });
      }
      senderNativeBalanceRaw = await senderNativeBalancePromise;

      toast.success('Tempo drip finalized', {
        id: toastId,
        description: (
          <span>
            Token:&nbsp;
            <code>{compactHex(dripToken)}</code>
            <br />
            Tx hash:&nbsp;
            <code>{compactHex(txHash)}</code>
          </span>
        ),
      });
    } catch (e: unknown) {
      const resolvedError: unknown = e;
      if (signedResultForBroadcast) {
        try {
          await tatchi.tempo.reportBroadcastResult({
            nearAccountId,
            signedResult: signedResultForBroadcast,
            status: 'failure',
            error: resolvedError,
          });
        } catch (reportError: unknown) {
          console.error('[DemoPage][BroadcastReportError]', {
            atIso: new Date().toISOString(),
            flow: 'tempo-drip-token',
            originalError: resolvedError,
            reportError,
          });
        }
      }
      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo drip cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`Tempo drip failed: ${message}`, { id: toastId });
      }
      console.error('[DemoPage][TempoDripError]', {
        atIso: new Date().toISOString(),
        error: resolvedError,
        message,
        senderNativeBalanceRaw,
        dripTokensForAttempt,
      });
    } finally {
      setTempoDripLoading(false);
    }
  }, [
    isLoggedIn,
    nearAccountId,
    refreshTempoUserFeeTokenBalance,
    resolveThresholdSenderForEvmFamily,
    tatchi,
    tempoEip1559FeeCaps,
    tempoUserFeeToken,
  ]);

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(tempoGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'tempo-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    try {
      const requestedGreeting = tempoGreetingInput.trim();
      const request = buildTempoEip1559GreetingRequest(
        requestedGreeting,
        tempoEip1559FeeCaps,
      );

      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching Tempo transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId: nearAccountId!,
        signedResult: signedResultForBroadcast,
        status: 'success',
        txHash,
      });

      toast.loading('Tempo transaction broadcasted, waiting for finalization…', { id: toastId });
      const receiptConfirmationResultPromise = waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
      })
        .then(
          () =>
            ({
              ok: true as const,
              mode: 'receipt' as const,
            }) as const,
        )
        .catch(
          (error: unknown) =>
            ({
              ok: false as const,
              source: 'receipt' as const,
              error,
            }) as const,
        );
      const greetingConfirmationResultPromise = waitForEvmGreetingMatch({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        contract: TEMPO_GREETING_CONTRACT,
        selector: TEMPO_GREETING_SELECTOR,
        expectedGreeting: requestedGreeting,
      })
        .then(
          () =>
            ({
              ok: true as const,
              mode: 'greeting' as const,
            }) as const,
        )
        .catch(
          (error: unknown) =>
            ({
              ok: false as const,
              source: 'greeting' as const,
              error,
            }) as const,
        );
      const firstConfirmationResult = await withPromiseTimeout({
        promise: Promise.race([
          receiptConfirmationResultPromise,
          greetingConfirmationResultPromise,
        ]),
        timeoutMs: EVM_TX_FINALITY_TIMEOUT_MS + EVM_RPC_REQUEST_TIMEOUT_MS + 5_000,
        label: 'Tempo greeting finalization confirmation',
      });
      let confirmationMode: 'receipt' | 'greeting';
      if (firstConfirmationResult.ok) {
        confirmationMode = firstConfirmationResult.mode;
      } else {
        const secondConfirmationResult =
          firstConfirmationResult.source === 'receipt'
            ? await greetingConfirmationResultPromise
            : await receiptConfirmationResultPromise;
        if (secondConfirmationResult.ok) {
          confirmationMode = secondConfirmationResult.mode;
        } else {
          const receiptError =
            firstConfirmationResult.source === 'receipt'
              ? firstConfirmationResult.error
              : secondConfirmationResult.error;
          const greetingError =
            firstConfirmationResult.source === 'greeting'
              ? firstConfirmationResult.error
              : secondConfirmationResult.error;
          const receiptErrorMessage =
            receiptError instanceof Error ? receiptError.message : String(receiptError);
          const greetingErrorMessage =
            greetingError instanceof Error ? greetingError.message : String(greetingError);
          throw new Error(
            `Unable to confirm Tempo transaction finalization. Receipt check failed: ${receiptErrorMessage}. Greeting check failed: ${greetingErrorMessage}. Tx hash: ${txHash}`,
          );
        }
      }
      await fetchTempoGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success(
        confirmationMode === 'greeting'
          ? 'Tempo transaction confirmed (via greeting update)'
          : 'Tempo transaction finalized',
        {
          id: toastId,
          description: (
            <span>
              Tx hash:&nbsp;
              <code>{compactHex(txHash)}</code>
            </span>
          ),
        },
      );
    } catch (e: unknown) {
      const resolvedError: unknown = e;
      if (signedResultForBroadcast && nearAccountId) {
        try {
          await tatchi.tempo.reportBroadcastResult({
            nearAccountId,
            signedResult: signedResultForBroadcast,
            status: 'failure',
            error: resolvedError,
          });
        } catch (reportError: unknown) {
          console.error('[DemoPage][BroadcastReportError]', {
            atIso: new Date().toISOString(),
            flow: 'tempo-sign',
            originalError: resolvedError,
            reportError,
          });
        }
      }

      if (isUserCancellationError(resolvedError)) {
        toast.error('Tempo transaction cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      console.error('[DemoPage][TempoSignError]', {
        atIso: new Date().toISOString(),
        message,
        error: resolvedError,
      });
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `Tempo sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`Tempo transaction failed: ${message}`, { id: toastId });
      }
    } finally {
      setTempoThresholdSignLoading(false);
    }
  }, [
    canExecuteGreeting,
    fetchTempoGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
    tempoEip1559FeeCaps,
    tempoGreetingInput,
  ]);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(arcGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'evm-threshold-sign';
    try {
      toast.dismiss(toastId);
    } catch {}
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    try {
      const request = buildDemoEip1559Request(arcGreetingInput.trim(), arcEip1559FeeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });

      toast.loading('Dispatching EVM transaction…', { id: toastId });
      const txHash = await sendRawEvmTransaction({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        rawTxHex: signed.rawTxHex,
      });
      await tatchi.tempo.reportBroadcastResult({
        nearAccountId: nearAccountId!,
        signedResult: signedResultForBroadcast,
        status: 'success',
        txHash,
      });

      toast.loading('EVM transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
        maxFeePerGasHint: request.tx.maxFeePerGas,
      });
      await fetchArcGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('EVM transaction finalized', {
        id: toastId,
        description: (
          <span>
            Tx hash:&nbsp;
            <code>{compactHex(txHash)}</code>
          </span>
        ),
      });
    } catch (e: unknown) {
      const resolvedError: unknown = e;
      if (signedResultForBroadcast && nearAccountId) {
        try {
          await tatchi.tempo.reportBroadcastResult({
            nearAccountId,
            signedResult: signedResultForBroadcast,
            status: 'failure',
            error: resolvedError,
          });
        } catch (reportError: unknown) {
          console.error('[DemoPage][BroadcastReportError]', {
            atIso: new Date().toISOString(),
            flow: 'evm-sign',
            originalError: resolvedError,
            reportError,
          });
        }
      }

      if (isUserCancellationError(resolvedError)) {
        toast.error('EVM transaction cancelled by user.', { id: toastId });
        return;
      }
      const message =
        resolvedError instanceof Error ? resolvedError.message : String(resolvedError);
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient) {
        toast.error(
          `ARC sender has insufficient native gas balance (have ${formatWeiToEth(insufficient.haveWei)}, need ${formatWeiToEth(insufficient.wantWei)} native tokens).`,
          { id: toastId },
        );
      } else {
        toast.error(`EVM transaction failed: ${message}`, { id: toastId });
      }
    } finally {
      setEvmThresholdSignLoading(false);
    }
  }, [
    arcEip1559FeeCaps,
    arcGreetingInput,
    canExecuteGreeting,
    fetchArcGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    tatchi,
  ]);

  useEffect(() => {
    if (!isLoggedIn || !nearAccountId) return;
    void fetchTempoGreeting({ silent: true });
    void fetchArcGreeting({ silent: true });
    void refreshThresholdEvmFundingAddress();
  }, [
    fetchArcGreeting,
    fetchTempoGreeting,
    isLoggedIn,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
  ]);

  useEffect(() => {
    if (!thresholdEvmFundingAddress || !isEvmAddress(thresholdEvmFundingAddress)) {
      setTempoUserFeeToken(null);
      return;
    }
    void refreshTempoUserFeeToken({ silent: true, userAddress: thresholdEvmFundingAddress });
  }, [refreshTempoUserFeeToken, thresholdEvmFundingAddress]);

  if (!isLoggedIn || !nearAccountId) {
    return null;
  }

  const accountName = nearAccountId.split('.')?.[0];
  const tempoFeeTokenIsAlpha =
    String(tempoUserFeeToken || '').toLowerCase() === TEMPO_ALPHA_USD_FEE_TOKEN.toLowerCase();
  const expiresInSec =
    sessionStatus?.expiresAtMs != null
      ? Math.max(0, Math.ceil((sessionStatus.expiresAtMs - clockMs) / 1000))
      : null;

  return (
    <div>
      <div className="action-section">
        <div className="demo-page-header">
          <h2 className="demo-title">Welcome, {accountName}</h2>
        </div>
      </div>

      <div className="action-section">
        <h2 className="demo-subtitle">Sign Transactions with TouchId</h2>
        <div className="action-text">Sign transactions securely in an cross-origin iframe.</div>

        <div className="greeting-controls-box">
          <div className="on-chain-greeting-box">
            <button
              onClick={handleRefreshGreeting}
              disabled={isLoading}
              title="Refresh Greeting"
              className="refresh-icon-button"
              aria-busy={isLoading}
            >
              <Refresh size={22} strokeWidth={2} />
            </button>
            <p>
              <strong>{onchainGreeting ?? '...'}</strong>
            </p>
          </div>

          <div className="greeting-input-group">
            <input
              type="text"
              name="greeting"
              value={greetingInput}
              onChange={(e) => setGreetingInput(e.target.value)}
              placeholder="Enter new greeting"
            />
          </div>
          <LoadingButton
            onClick={handleSetGreeting}
            loading={txLoading}
            loadingText="Processing..."
            variant="primary"
            size="medium"
            className="greeting-btn"
            disabled={!canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId) || txLoading}
            style={{ width: 200 }}
          >
            Set Greeting
          </LoadingButton>
          <LoadingButton
            onClick={handleSignDelegateGreeting}
            loading={delegateLoading}
            loadingText="Signing delegate..."
            variant="secondary"
            size="medium"
            className="greeting-btn"
            disabled={
              !canExecuteGreeting(greetingInput, isLoggedIn, nearAccountId) || delegateLoading
            }
            style={{ width: 200, marginTop: '0.5rem' }}
          >
            Send Delegate Action
          </LoadingButton>

          {error && <div className="error-message">Error: {error}</div>}
        </div>
      </div>

      <div className="action-section">
        <div className="demo-divider" aria-hidden="true" />
        <h2 className="demo-subtitle">Tempo + EVM Threshold Signers</h2>
        <div className="action-text funding-instructions">
          <span>
            Fund this threshold EVM signer address with Arc native gas. Tempo setUserToken is
            configured via the buttons below.
          </span>
          <div className="funding-address-row">
            <span className="funding-address-text">
              {thresholdEvmFundingAddress ||
                'Address unavailable. Sign once to bootstrap threshold ECDSA.'}
            </span>
            {thresholdEvmFundingAddress ? (
              <CopyButton
                text={thresholdEvmFundingAddress}
                ariaLabel="Copy funding address"
                className="funding-address-copy"
                size={18}
                onCopy={() => {
                  toast.success('Address copied');
                }}
              />
            ) : (
              <span className="funding-address-copy-placeholder" aria-hidden="true" />
            )}
          </div>
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 10,
              marginTop: 10,
            }}
          >
            <LoadingButton
              onClick={handleSetTempoFeeTokenAlphaUsd}
              loading={tempoFeeTokenConfigLoading && tempoFeeTokenConfigTarget === 'alpha'}
              loadingText="Configuring..."
              variant="secondary"
              size="medium"
              style={{ width: '100%' }}
              disabled={tempoFeeTokenConfigLoading || tempoFeeTokenIsAlpha}
            >
              Set Tempo Fee Token
            </LoadingButton>
            <LoadingButton
              onClick={handleTempoDripToken}
              loading={tempoDripLoading}
              loadingText="Dripping..."
              variant="secondary"
              size="medium"
              style={{ width: '100%' }}
              disabled={tempoDripLoading || tempoFeeTokenConfigLoading}
            >
              Drip Fee Tokens
            </LoadingButton>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
          <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
            <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              Tempo Greeting
            </div>
            <div className="on-chain-greeting-box">
              <button
                onClick={() => void fetchTempoGreeting()}
                disabled={tempoGreetingLoading}
                title="Refresh Tempo Greeting"
                className="refresh-icon-button"
                aria-busy={tempoGreetingLoading}
              >
                <Refresh size={22} strokeWidth={2} />
              </button>
              <p>
                <strong>{tempoGreeting ?? '...'}</strong>
              </p>
            </div>
            <div className="greeting-input-group" style={{ marginBottom: 0 }}>
              <input
                type="text"
                name="tempo-greeting"
                value={tempoGreetingInput}
                onChange={(event) => setTempoGreetingInput(event.target.value)}
                placeholder="Enter Tempo greeting"
              />
            </div>
          </div>
          {tempoGreetingError ? (
            <div className="error-message">Tempo greeting error: {tempoGreetingError}</div>
          ) : null}
          <LoadingButton
            onClick={handleSignTempoThresholdTx}
            loading={tempoThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
            disabled={
              !canExecuteGreeting(tempoGreetingInput, isLoggedIn, nearAccountId) ||
              tempoThresholdSignLoading
            }
          >
            Sign Tempo Transaction
          </LoadingButton>

          <div className="evm-greeting-stack" style={{ display: 'grid', gap: 8 }}>
            <div style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              Arc Greeting
            </div>
            <div className="on-chain-greeting-box">
              <button
                onClick={() => void fetchArcGreeting()}
                disabled={arcGreetingLoading}
                title="Refresh Arc Greeting"
                className="refresh-icon-button"
                aria-busy={arcGreetingLoading}
              >
                <Refresh size={22} strokeWidth={2} />
              </button>
              <p>
                <strong>{arcGreeting ?? '...'}</strong>
              </p>
            </div>
            <div className="greeting-input-group" style={{ marginBottom: 0 }}>
              <input
                type="text"
                name="arc-greeting"
                value={arcGreetingInput}
                onChange={(event) => setArcGreetingInput(event.target.value)}
                placeholder="Enter Arc greeting"
              />
            </div>
          </div>
          {arcGreetingError ? (
            <div className="error-message">Arc greeting error: {arcGreetingError}</div>
          ) : null}

          <LoadingButton
            onClick={handleSignEvmThresholdTx}
            loading={evmThresholdSignLoading}
            loadingText="Signing..."
            variant="primary"
            size="medium"
            style={{ width: '100%' }}
            disabled={
              !canExecuteGreeting(arcGreetingInput, isLoggedIn, nearAccountId) ||
              evmThresholdSignLoading
            }
          >
            Sign EVM Transaction
          </LoadingButton>
        </div>
      </div>

      <div className="action-section">
        <div className="demo-divider" aria-hidden="true" />
        <h2 className="demo-subtitle">Signing Session</h2>
        <div className="action-text">
          Create a warm signing session with configurable <code>remaining_uses</code> and TTL. Touch
          once, then sign multiple times while the session is active.
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, alignItems: 'flex-end' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
            <label style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              Remaining uses
            </label>
            <input
              type="number"
              min={0}
              step={1}
              value={sessionRemainingUsesInput}
              onChange={(e) => setSessionRemainingUsesInput(parseInt(e.target.value || '0', 10))}
              style={{
                height: 44,
                padding: '0 12px',
                backgroundColor: 'var(--w3a-colors-surface2)',
                border: '1px solid var(--fe-border)',
                borderRadius: 'var(--fe-radius-lg)',
                color: 'var(--fe-input-text)',
                fontSize: '0.9rem',
              }}
            />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 180, flex: 1 }}>
            <label style={{ fontSize: '0.9rem', color: 'var(--fe-text-secondary)' }}>
              TTL (seconds)
            </label>
            <input
              type="number"
              min={0}
              step={1}
              value={sessionTtlSecondsInput}
              onChange={(e) => setSessionTtlSecondsInput(parseInt(e.target.value || '0', 10))}
              style={{
                height: 44,
                padding: '0 12px',
                backgroundColor: 'var(--w3a-colors-surface2)',
                border: '1px solid var(--fe-border)',
                borderRadius: 'var(--fe-radius-lg)',
                color: 'var(--fe-input-text)',
                fontSize: '0.9rem',
              }}
            />
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <LoadingButton
              onClick={handleUnlockSession}
              loading={unlockLoading}
              loadingText="Creating..."
              variant="primary"
              size="medium"
              style={{ width: 180 }}
            >
              Create Session
            </LoadingButton>
          </div>
        </div>

        <div
          style={{
            marginTop: 12,
            background: 'var(--fe-bg-secondary)',
            border: '1px solid var(--fe-border)',
            borderRadius: 'var(--fe-radius-lg)',
            padding: 'var(--fe-gap-3)',
            fontSize: '0.9rem',
            color: 'var(--fe-text)',
          }}
        >
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
            <div>
              <strong>Status:</strong>&nbsp;{sessionStatus?.status ?? '…'}
            </div>
            <div>
              <strong>Remaining uses:</strong>&nbsp;
              {typeof sessionStatus?.remainingUses === 'number' ? sessionStatus.remainingUses : '—'}
            </div>
            <div>
              <strong>TTL:</strong>&nbsp;
              {expiresInSec == null
                ? '—'
                : sessionStatus?.status === 'active'
                  ? `${expiresInSec}s remaining`
                  : `${expiresInSec}s`}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DemoPage;
