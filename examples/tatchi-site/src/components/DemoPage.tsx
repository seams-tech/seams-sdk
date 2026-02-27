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
import './DemoPage.css';

const TEMPO_GREETING_CONTRACT = '0x96cFE92241481954AdA6410409a86AcB6E76a00e' as `0x${string}`;
const ARC_TESTNET_GREETING_CONTRACT = '0xeB7aB5A6F761072C96147A54B8a15F012e836691' as `0x${string}`;
const SET_GREETING_SELECTOR = '0xa4136862';
const GREET_SELECTOR = '0xcfae3217';
const TEMPO_VALIDATOR_TOKENS_SELECTOR = '0x6dc54a7a';
const EVM_TX_FINALITY_TIMEOUT_MS = 90_000;
const EVM_TX_RECEIPT_POLL_INTERVAL_MS = 1_250;
const EVM_RPC_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n; // 2 gwei
const DEFAULT_DEMO_MAX_FEE_PER_GAS = 40_000_000_000n; // 40 gwei
// `setUserToken` can trigger fee-token routing paths that exceed 350k gas.
const TEMPO_SET_USER_TOKEN_GAS_LIMIT = 1_000_000n;
const TEMPO_PATH_USD_FEE_TOKEN = '0x20c0000000000000000000000000000000000000' as `0x${string}`;

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
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(rpcUrl, {
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
  } catch (error: unknown) {
    const maybeAbort = error as { name?: string };
    if (maybeAbort?.name === 'AbortError') {
      throw new Error(`${method} request timed out after ${timeoutMs}ms`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }

  if (!response.ok) {
    throw new Error(`RPC HTTP ${response.status}`);
  }

  const payload = (await response.json()) as {
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
}): Promise<string> {
  const { rpcUrl, contract } = params;
  const result = await callEvmJsonRpc<string>({
    rpcUrl,
    method: 'eth_call',
    params: [{ to: contract, data: GREET_SELECTOR }, 'latest'],
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
  timeoutMs?: number;
  pollIntervalMs?: number;
}): Promise<EvmTransactionReceipt> {
  const timeoutMs = args.timeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS;
  const pollIntervalMs = args.pollIntervalMs ?? EVM_TX_RECEIPT_POLL_INTERVAL_MS;
  const deadline = Date.now() + timeoutMs;
  let lastRpcError: string | null = null;

  while (Date.now() < deadline) {
    let receipt: EvmTransactionReceipt | null = null;
    try {
      receipt = await callEvmJsonRpc<EvmTransactionReceipt | null>({
        rpcUrl: args.rpcUrl,
        method: 'eth_getTransactionReceipt',
        params: [args.txHash],
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

    await new Promise<void>((resolve) => {
      window.setTimeout(resolve, pollIntervalMs);
    });
  }

  const details = lastRpcError ? `; last RPC error: ${lastRpcError}` : '';
  throw new Error(`Timed out waiting for tx finalization after ${timeoutMs}ms${details}`);
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

async function readEvmTransactionSender(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
}): Promise<`0x${string}` | null> {
  const tx = await readEvmTransactionByHash(args);
  const sender = String(tx?.from || '').trim();
  return isEvmAddress(sender) ? sender : null;
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

function getPreferredTempoFeeToken(): `0x${string}` {
  const token = String(FRONTEND_CONFIG.tempoFeeToken || '').trim();
  if (isEvmAddress(token)) return token;
  return TEMPO_ALPHA_USD_FEE_TOKEN;
}

async function resolveEvmAccountNonce(args: {
  rpcUrl: string;
  address: `0x${string}`;
  blockTag?: 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';
}): Promise<bigint> {
  const blockTag = args.blockTag ?? 'pending';
  const nonceHex = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_getTransactionCount',
    params: [args.address, blockTag],
  });
  return parseRpcHexQuantity(nonceHex, 'eth_getTransactionCount');
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
  });

  if (typeof result !== 'string' || !result.startsWith('0x')) {
    throw new Error('Invalid userTokens(address) eth_call response');
  }

  return decodeTempoUserTokenResult(result);
}

function encodeSingleAddressCalldata(
  selector: `0x${string}`,
  address: `0x${string}`,
): `0x${string}` {
  const encodedAddress = address.slice(2).toLowerCase().padStart(64, '0');
  return `${selector}${encodedAddress}` as `0x${string}`;
}

async function readLatestEvmBlockMiner(args: { rpcUrl: string }): Promise<`0x${string}` | null> {
  const block = await callEvmJsonRpc<{ miner?: string | null }>({
    rpcUrl: args.rpcUrl,
    method: 'eth_getBlockByNumber',
    params: ['latest', false],
  });
  const miner = String(block?.miner || '').trim();
  return isEvmAddress(miner) ? miner : null;
}

async function readTempoValidatorFeeToken(args: {
  rpcUrl: string;
  validatorAddress: `0x${string}`;
}): Promise<`0x${string}` | null> {
  const result = await callEvmJsonRpc<string>({
    rpcUrl: args.rpcUrl,
    method: 'eth_call',
    params: [
      {
        to: TEMPO_FEE_MANAGER_CONTRACT,
        data: encodeSingleAddressCalldata(TEMPO_VALIDATOR_TOKENS_SELECTOR, args.validatorAddress),
      },
      'latest',
    ],
  });
  if (typeof result !== 'string' || !result.startsWith('0x')) {
    throw new Error('Invalid validatorTokens(address) eth_call response');
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
    const gasPriceHex = await callEvmJsonRpc<string>({
      rpcUrl,
      method: 'eth_gasPrice',
      params: [],
    });
    const gasPrice = parseRpcHexQuantity(gasPriceHex, 'eth_gasPrice');
    if (gasPrice <= 0n) {
      throw new Error('eth_gasPrice returned non-positive value');
    }

    const maxFeePerGas =
      gasPrice * 2n > DEFAULT_DEMO_MAX_FEE_PER_GAS ? gasPrice * 2n : DEFAULT_DEMO_MAX_FEE_PER_GAS;
    const suggestedPriority =
      gasPrice / 10n > DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS
        ? gasPrice / 10n
        : DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS;
    const maxPriorityFeePerGas =
      suggestedPriority < maxFeePerGas ? suggestedPriority : maxFeePerGas / 2n;
    return {
      maxPriorityFeePerGas,
      maxFeePerGas,
    };
  } catch {
    return {
      maxPriorityFeePerGas: DEFAULT_DEMO_MAX_PRIORITY_FEE_PER_GAS,
      maxFeePerGas: DEFAULT_DEMO_MAX_FEE_PER_GAS,
    };
  }
}

function buildDemoTempoTransactionRequest(
  greeting: string,
  feeCaps: Eip1559FeeCaps,
  feeToken: `0x${string}`,
) {
  const setGreetingInput = encodeSetGreetingInput(greeting);
  return {
    chain: 'tempo' as const,
    kind: 'tempoTransaction' as const,
    senderSignatureAlgorithm: 'secp256k1' as const,
    tx: {
      chainId: 42431,
      maxPriorityFeePerGas: feeCaps.maxPriorityFeePerGas,
      maxFeePerGas: feeCaps.maxFeePerGas,
      gasLimit: 200_000n,
      calls: [{ to: TEMPO_GREETING_CONTRACT, value: 0n, input: setGreetingInput }],
      accessList: [],
      nonceKey: 0n,
      validBefore: null,
      validAfter: null,
      feeToken,
      feePayerSignature: { kind: 'none' as const },
      aaAuthorizationList: [],
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

type TxSendDebugContext = {
  atIso: string;
  flow: 'tempo-set-fee-token' | 'tempo-sign' | 'evm-sign';
  sender: `0x${string}`;
  chain: 'tempo' | 'evm';
  requestKind: 'tempoTransaction' | 'eip1559';
  nonce: bigint;
  chainPendingNonce?: bigint;
  gasLimit?: bigint;
  feeToken?: `0x${string}` | null;
  feeTokenSelectionReason?: string;
  rawTxTypePrefix?: string;
  txHashHint?: `0x${string}`;
  txHash?: `0x${string}`;
  recoveredSenderFromRaw?: `0x${string}` | null;
  recoveredSenderMatchesSender?: boolean | null;
  nodeReportedFrom?: `0x${string}` | null;
  nodeReportedFromMatchesSender?: boolean | null;
};

type TempoFeeDiagnostics = {
  atIso: string;
  sender: `0x${string}`;
  onChainFeeToken: `0x${string}`;
  onChainFeeTokenBalanceRaw?: bigint | null;
  alphaFeeTokenBalanceRaw?: bigint | null;
  txFeeToken: `0x${string}`;
  txFeeTokenBalanceRaw?: bigint | null;
  txFeeTokenSelectionReason?: string;
  preferredFeeToken?: `0x${string}` | null;
  preferredFeeTokenBalanceRaw?: bigint | null;
  validatorAddress?: `0x${string}` | null;
  validatorFeeToken?: `0x${string}` | null;
  validatorFeeTokenBalanceRaw?: bigint | null;
  rpcUrl: string;
  balanceRaw: bigint;
  chainPendingNonce: bigint;
  nonce?: bigint;
  gasLimit: bigint;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
};

function readManagedNonceFromSignedResult(signed: {
  managedNonce?: { nonce?: string } | null | undefined;
}): bigint | null {
  const raw = String(signed.managedNonce?.nonce || '').trim();
  if (!raw) return null;
  try {
    return BigInt(raw);
  } catch {
    return null;
  }
}

function getRawTxTypePrefix(rawTxHex: string): string {
  const normalized = String(rawTxHex || '')
    .trim()
    .toLowerCase();
  if (!normalized.startsWith('0x') || normalized.length < 4) return 'unknown';
  return normalized.slice(0, 4);
}

function assertRawTxTypePrefix(args: {
  requestKind: 'tempoTransaction' | 'eip1559';
  rawTxHex: string;
}): void {
  const expected = args.requestKind === 'tempoTransaction' ? '0x76' : '0x02';
  const actual = getRawTxTypePrefix(args.rawTxHex);
  if (actual !== expected) {
    throw new Error(
      `Unexpected raw tx type prefix ${actual} for ${args.requestKind}; expected ${expected}.`,
    );
  }
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = String(hex || '')
    .trim()
    .replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('Invalid hex bytes');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < normalized.length; i += 2) {
    out[i / 2] = Number.parseInt(normalized.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function extractTempoSenderSignature65Hex(rawTxHex: string): `0x${string}` | null {
  const normalized = String(rawTxHex || '')
    .trim()
    .toLowerCase()
    .replace(/^0x/, '');
  if (!normalized.startsWith('76')) return null;
  const match = /b841([0-9a-f]{130})$/.exec(normalized);
  if (!match?.[1]) return null;
  return `0x${match[1]}` as `0x${string}`;
}

async function recoverEvmAddressFromDigestAndSignature(args: {
  digest32Hex: `0x${string}`;
  signature65Hex: `0x${string}`;
}): Promise<`0x${string}` | null> {
  const digest32 = hexToBytes(args.digest32Hex);
  const signature = hexToBytes(args.signature65Hex);
  if (digest32.length !== 32 || signature.length !== 65) return null;
  const recoveryId = signature[64]!;
  if (recoveryId !== 0 && recoveryId !== 1) return null;
  const compact = signature.slice(0, 64);

  const [{ secp256k1 }, { keccak_256 }] = await Promise.all([
    import('@noble/curves/secp256k1'),
    import('@noble/hashes/sha3'),
  ]);
  const publicKey = secp256k1.Signature.fromCompact(compact)
    .addRecoveryBit(recoveryId)
    .recoverPublicKey(digest32)
    .toRawBytes(false);
  if (publicKey.length !== 65 || publicKey[0] !== 0x04) return null;
  const addressHash = keccak_256(publicKey.slice(1));
  const addressHex = bytesToHex(addressHash.slice(-20));
  return `0x${addressHex}` as `0x${string}`;
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
  const [tempoFeeTokenConfigLoading, setTempoFeeTokenConfigLoading] = useState(false);
  const [tempoFeeTokenConfigTarget, setTempoFeeTokenConfigTarget] = useState<
    'alpha' | 'path' | null
  >(null);
  const [evmThresholdSignLoading, setEvmThresholdSignLoading] = useState(false);
  const [tempoGreeting, setTempoGreeting] = useState<string | null>(null);
  const [arcGreeting, setArcGreeting] = useState<string | null>(null);
  const [tempoGreetingLoading, setTempoGreetingLoading] = useState(false);
  const [arcGreetingLoading, setArcGreetingLoading] = useState(false);
  const [tempoGreetingError, setTempoGreetingError] = useState<string | null>(null);
  const [arcGreetingError, setArcGreetingError] = useState<string | null>(null);
  const [thresholdEvmFundingAddress, setThresholdEvmFundingAddress] = useState<string | null>(null);
  const [tempoUserFeeToken, setTempoUserFeeToken] = useState<`0x${string}` | null>(null);
  const [tempoUserFeeTokenLoading, setTempoUserFeeTokenLoading] = useState(false);
  const [tempoUserFeeTokenError, setTempoUserFeeTokenError] = useState<string | null>(null);
  const [tempoUserFeeTokenBalanceRaw, setTempoUserFeeTokenBalanceRaw] = useState<bigint | null>(
    null,
  );
  const [tempoUserFeeTokenBalanceLoading, setTempoUserFeeTokenBalanceLoading] = useState(false);
  const [tempoUserFeeTokenBalanceError, setTempoUserFeeTokenBalanceError] = useState<string | null>(
    null,
  );
  const [lastTxSendDebug, setLastTxSendDebug] = useState<TxSendDebugContext | null>(null);
  const [lastTempoFeeDiagnostics, setLastTempoFeeDiagnostics] =
    useState<TempoFeeDiagnostics | null>(null);

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
      console.log('[DemoPage][ThresholdAddressResolved]', {
        nearAccountId,
        thresholdEcdsaEthereumAddress: address || null,
      });
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
        setTempoUserFeeTokenError(null);
        return null;
      }

      setTempoUserFeeTokenLoading(true);
      setTempoUserFeeTokenError(null);
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
        setTempoUserFeeTokenError(message);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token check failed: ${message}`);
        }
        return null;
      } finally {
        setTempoUserFeeTokenLoading(false);
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
        setTempoUserFeeTokenBalanceRaw(null);
        setTempoUserFeeTokenBalanceError(null);
        return null;
      }
      setTempoUserFeeTokenBalanceLoading(true);
      setTempoUserFeeTokenBalanceError(null);
      try {
        const balance = await readTempoTokenBalanceRaw({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          userAddress: maybeAddress,
          tokenAddress: maybeToken,
        });
        setTempoUserFeeTokenBalanceRaw(balance);
        return balance;
      } catch (e: unknown) {
        const message = e instanceof Error ? e.message : String(e);
        setTempoUserFeeTokenBalanceRaw(null);
        setTempoUserFeeTokenBalanceError(message);
        if (!opts?.silent) {
          toast.error(`Tempo fee-token balance check failed: ${message}`);
        }
        return null;
      } finally {
        setTempoUserFeeTokenBalanceLoading(false);
      }
    },
    [tempoUserFeeToken, thresholdEvmFundingAddress],
  );

  const configureTempoFeeToken = useCallback(
    async (args: { token: `0x${string}`; label: string; target: 'alpha' | 'path' }) => {
      if (!isLoggedIn || !nearAccountId) return;
      const toastId = 'tempo-set-fee-token';
      setTempoFeeTokenConfigLoading(true);
      setTempoFeeTokenConfigTarget(args.target);
      toast.loading(`Configuring Tempo fee token to ${args.label}…`, { id: toastId });
      let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null =
        null;
      let thresholdSenderForAttempt: `0x${string}` | null = null;
      let selectedFeeTokenBalanceRaw: bigint | null = null;
      let senderNativeBalanceRaw: bigint | null = null;
      let latestValidatorAddress: `0x${string}` | null = null;
      let latestValidatorFeeToken: `0x${string}` | null = null;
      try {
        const tempoFeeToken = args.token;
        const thresholdSender = await resolveThresholdSenderForEvmFamily();
        thresholdSenderForAttempt = thresholdSender;
        latestValidatorAddress = await readLatestEvmBlockMiner({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        }).catch(() => null);
        latestValidatorFeeToken = latestValidatorAddress
          ? await readTempoValidatorFeeToken({
              rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
              validatorAddress: latestValidatorAddress,
            }).catch(() => null)
          : null;
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
        console.log('[DemoPage][TempoSetFeeTokenPreflight]', {
          atIso: new Date().toISOString(),
          sender: thresholdSender,
          selectedFeeToken: tempoFeeToken,
          selectedFeeTokenBalanceRaw,
          senderNativeBalanceRaw,
          latestValidatorAddress,
          latestValidatorFeeToken,
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        });
        if (selectedFeeTokenBalanceRaw === 0n) {
          const validatorTokenHint = latestValidatorFeeToken
            ? ` Latest validator token is ${latestValidatorFeeToken}.`
            : '';
          throw new Error(
            `Selected fee token ${args.label} (${tempoFeeToken}) balance is 0 for ${thresholdSender}.${validatorTokenHint} Fund ${args.label} before setUserToken().`,
          );
        }
        const feeCaps = await resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl);
        const request = buildEip1559SetUserTokenRequest({
          feeCaps,
          feeToken: tempoFeeToken,
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
        const nonce = readManagedNonceFromSignedResult(signed) ?? 0n;
        const recoveredSenderFromRaw: `0x${string}` | null = null;
        const recoveredSenderMatchesSender: boolean | null = null;

        const debugContext: TxSendDebugContext = {
          atIso: new Date().toISOString(),
          flow: 'tempo-set-fee-token',
          sender: thresholdSender,
          chain: request.chain,
          requestKind: request.kind,
          nonce,
          gasLimit: request.tx.gasLimit,
          feeToken: tempoFeeToken,
          rawTxTypePrefix: getRawTxTypePrefix(signed.rawTxHex),
          txHashHint: signed.txHashHex as `0x${string}`,
          recoveredSenderFromRaw,
          recoveredSenderMatchesSender,
        };
        setLastTxSendDebug(debugContext);
        console.log('[DemoPage][TxSendContext]', debugContext);

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
        const nodeReportedFrom = await readEvmTransactionSender({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          txHash,
        }).catch(() => null);
        const nodeReportedFromMatchesSender = nodeReportedFrom
          ? nodeReportedFrom.toLowerCase() === thresholdSender.toLowerCase()
          : null;
        const finalizedDebugContext: TxSendDebugContext = {
          ...debugContext,
          txHash,
          nodeReportedFrom,
          nodeReportedFromMatchesSender,
        };
        setLastTxSendDebug(finalizedDebugContext);
        console.log('[DemoPage][TxSendContext]', finalizedDebugContext);

        toast.loading('Waiting for setUserToken finalization…', { id: toastId });
        await waitForEvmTransactionFinalization({
          rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
          txHash,
          gasLimitHint: request.tx.gasLimit,
        });
        await refreshTempoUserFeeToken({ silent: true, userAddress: thresholdSender });
        await refreshTempoUserFeeTokenBalance({
          silent: true,
          userAddress: thresholdSender,
          feeToken: tempoFeeToken,
        });

        toast.success('Tempo fee token configured', {
          id: toastId,
          description: (
            <span>
              Token:&nbsp;
              <code>{args.label}</code>&nbsp;
              <code>{compactHex(tempoFeeToken)}</code>
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
            senderNativeBalanceRaw == null ? 'unknown' : senderNativeBalanceRaw.toString();
          const selectedBalanceText =
            selectedFeeTokenBalanceRaw == null ? 'unknown' : selectedFeeTokenBalanceRaw.toString();
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

  const handleSetTempoFeeTokenPathUsd = useCallback(
    async () =>
      await configureTempoFeeToken({
        token: TEMPO_PATH_USD_FEE_TOKEN,
        label: 'PathUSD',
        target: 'path',
      }),
    [configureTempoFeeToken],
  );

  const handleSignTempoThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(tempoGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'tempo-threshold-sign';
    setTempoThresholdSignLoading(true);
    toast.loading('Signing Tempo transaction…', { id: toastId });
    let onChainFeeToken: `0x${string}` | null = null;
    let txFeeTokenForAttempt: `0x${string}` | null = null;
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    let feeDiagnosticsForAttempt: TempoFeeDiagnostics | null = null;
    let txSendDebugForAttempt: TxSendDebugContext | null = null;
    try {
      const thresholdSender = await resolveThresholdSenderForEvmFamily();
      const feeCaps = await resolveEip1559FeeCaps(FRONTEND_CONFIG.tempoRpcUrl);
      const chainPendingNonce = await resolveEvmAccountNonce({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        address: thresholdSender,
        blockTag: 'pending',
      });
      onChainFeeToken = await refreshTempoUserFeeToken({
        silent: true,
        userAddress: thresholdSender,
      });
      if (!onChainFeeToken) {
        throw new Error(
          `Tempo on-chain fee token is not set for ${thresholdSender}; configure setUserToken(address) first.`,
        );
      }
      const preferredFeeToken = getPreferredTempoFeeToken();
      const preferredFeeTokenDiffers =
        preferredFeeToken.toLowerCase() !== onChainFeeToken.toLowerCase();
      const isModeratoRpc = FRONTEND_CONFIG.tempoRpcUrl.toLowerCase().includes('moderato.tempo.xyz');
      const onChainIsPathUsd = onChainFeeToken.toLowerCase() === TEMPO_PATH_USD_FEE_TOKEN.toLowerCase();
      const latestValidatorAddress = await readLatestEvmBlockMiner({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
      }).catch(() => null);
      const latestValidatorFeeToken = latestValidatorAddress
        ? await readTempoValidatorFeeToken({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            validatorAddress: latestValidatorAddress,
          }).catch(() => null)
        : null;
      const latestValidatorFeeTokenBalanceRaw = latestValidatorFeeToken
        ? await readTempoTokenBalanceRaw({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            userAddress: thresholdSender,
            tokenAddress: latestValidatorFeeToken,
          }).catch(() => null)
        : null;
      const onChainFeeTokenBalanceRaw = await refreshTempoUserFeeTokenBalance({
        silent: true,
        userAddress: thresholdSender,
        feeToken: onChainFeeToken,
      });
      if (onChainFeeTokenBalanceRaw == null) {
        throw new Error(
          `Unable to read configured fee-token balance for ${thresholdSender} on ${FRONTEND_CONFIG.tempoRpcUrl}.`,
        );
      }
      const alphaFeeTokenBalanceRaw =
        onChainFeeToken.toLowerCase() === TEMPO_ALPHA_USD_FEE_TOKEN.toLowerCase()
          ? onChainFeeTokenBalanceRaw
          : await readTempoTokenBalanceRaw({
              rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
              userAddress: thresholdSender,
              tokenAddress: TEMPO_ALPHA_USD_FEE_TOKEN,
            }).catch(() => null);
      const preferredFeeTokenBalanceRaw = preferredFeeTokenDiffers
        ? await readTempoTokenBalanceRaw({
            rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
            userAddress: thresholdSender,
            tokenAddress: preferredFeeToken,
          }).catch(() => null)
        : onChainFeeTokenBalanceRaw;
      let txFeeToken = onChainFeeToken;
      let txFeeTokenBalanceRaw = onChainFeeTokenBalanceRaw;
      let txFeeTokenSelectionReason = 'account-level fee token (userTokens(address))';
      if (
        isModeratoRpc &&
        onChainIsPathUsd &&
        typeof alphaFeeTokenBalanceRaw === 'bigint' &&
        alphaFeeTokenBalanceRaw > 0n
      ) {
        txFeeToken = TEMPO_ALPHA_USD_FEE_TOKEN;
        txFeeTokenBalanceRaw = alphaFeeTokenBalanceRaw;
        txFeeTokenSelectionReason =
          'moderato PathUSD spendability guard: using AlphaUSD as tx-level fee token';
      } else if (
        preferredFeeTokenDiffers &&
        onChainFeeTokenBalanceRaw === 0n &&
        typeof preferredFeeTokenBalanceRaw === 'bigint' &&
        preferredFeeTokenBalanceRaw > 0n
      ) {
        txFeeToken = preferredFeeToken;
        txFeeTokenBalanceRaw = preferredFeeTokenBalanceRaw;
        txFeeTokenSelectionReason = `fallback to app-preferred fee token (${preferredFeeToken}) because on-chain token balance is zero`;
      }
      txFeeTokenForAttempt = txFeeToken;
      const request = buildDemoTempoTransactionRequest(tempoGreetingInput.trim(), feeCaps, txFeeToken);
      feeDiagnosticsForAttempt = {
        atIso: new Date().toISOString(),
        sender: thresholdSender,
        onChainFeeToken,
        onChainFeeTokenBalanceRaw,
        alphaFeeTokenBalanceRaw,
        txFeeToken,
        txFeeTokenBalanceRaw,
        txFeeTokenSelectionReason,
        preferredFeeToken,
        preferredFeeTokenBalanceRaw,
        validatorAddress: latestValidatorAddress,
        validatorFeeToken: latestValidatorFeeToken,
        validatorFeeTokenBalanceRaw: latestValidatorFeeTokenBalanceRaw,
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        balanceRaw: txFeeTokenBalanceRaw,
        chainPendingNonce,
        gasLimit: request.tx.gasLimit,
        maxPriorityFeePerGas: request.tx.maxPriorityFeePerGas,
        maxFeePerGas: request.tx.maxFeePerGas,
      };
      setLastTempoFeeDiagnostics(feeDiagnosticsForAttempt);
      console.log('[DemoPage][TempoFeeDiagnostics]', feeDiagnosticsForAttempt);
      if (txFeeTokenBalanceRaw === 0n) {
        throw new Error(
          `Selected transaction fee token ${txFeeToken} has zero balance on configured RPC ${FRONTEND_CONFIG.tempoRpcUrl}.`,
        );
      }
      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'tempoTransaction') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });
      const nonce = readManagedNonceFromSignedResult(signed) ?? 0n;
      const senderSignature65Hex = extractTempoSenderSignature65Hex(signed.rawTxHex);
      const recoveredSenderFromRaw = senderSignature65Hex
        ? await recoverEvmAddressFromDigestAndSignature({
            digest32Hex: signed.senderHashHex as `0x${string}`,
            signature65Hex: senderSignature65Hex,
          }).catch(() => null)
        : null;
      const recoveredSenderMatchesSender = recoveredSenderFromRaw
        ? recoveredSenderFromRaw.toLowerCase() === thresholdSender.toLowerCase()
        : null;
      if (feeDiagnosticsForAttempt) {
        feeDiagnosticsForAttempt = {
          ...feeDiagnosticsForAttempt,
          nonce,
        };
        setLastTempoFeeDiagnostics(feeDiagnosticsForAttempt);
      }

      const debugContext: TxSendDebugContext = {
        atIso: new Date().toISOString(),
        flow: 'tempo-sign',
        sender: thresholdSender,
        chain: request.chain,
        requestKind: request.kind,
        nonce,
        chainPendingNonce,
        gasLimit: request.tx.gasLimit,
        feeToken: txFeeToken,
        feeTokenSelectionReason: txFeeTokenSelectionReason,
        rawTxTypePrefix: getRawTxTypePrefix(signed.rawTxHex),
        txHashHint: signed.senderHashHex as `0x${string}`,
        recoveredSenderFromRaw,
        recoveredSenderMatchesSender,
      };
      txSendDebugForAttempt = debugContext;
      setLastTxSendDebug(debugContext);
      console.log('[DemoPage][TxSendContext]', debugContext);

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
      const nodeReportedFrom = await readEvmTransactionSender({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
      }).catch(() => null);
      const nodeReportedFromMatchesSender = nodeReportedFrom
        ? nodeReportedFrom.toLowerCase() === thresholdSender.toLowerCase()
        : null;
      const finalizedDebugContext: TxSendDebugContext = {
        ...debugContext,
        txHash,
        nodeReportedFrom,
        nodeReportedFromMatchesSender,
      };
      setLastTxSendDebug(finalizedDebugContext);
      console.log('[DemoPage][TxSendContext]', finalizedDebugContext);

      toast.loading('Tempo transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.tempoRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
      });
      await fetchTempoGreeting({ silent: true });
      await refreshThresholdEvmFundingAddress();

      toast.success('Tempo transaction finalized', {
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
      const feeDiagnostics = feeDiagnosticsForAttempt || lastTempoFeeDiagnostics;
      const attemptedFeeToken = feeDiagnostics?.txFeeToken || txFeeTokenForAttempt || onChainFeeToken;
      console.error('[DemoPage][TempoSignError]', {
        atIso: new Date().toISOString(),
        message,
        error: resolvedError,
        feeDiagnostics,
        lastTxSendDebug: txSendDebugForAttempt || lastTxSendDebug,
      });
      const insufficient = parseInsufficientFundsError(message);
      if (insufficient && insufficient.haveWei === 0n && insufficient.wantWei === 0n) {
        const tokenHint = onChainFeeToken
          ? `account fee token ${compactHex(onChainFeeToken)}`
          : `fee token ${compactHex(getPreferredTempoFeeToken())}`;
        toast.error(
          `Tempo transaction failed: ${message}. Tempo has no native gas token; configure setUserToken(address) on ${compactHex(TEMPO_FEE_MANAGER_CONTRACT)} with ${tokenHint}.`,
          { id: toastId },
        );
      } else if (insufficient && insufficient.haveWei === 0n && attemptedFeeToken) {
        const validatorFeeToken = feeDiagnostics?.validatorFeeToken;
        const validatorTokenDiffers =
          !!validatorFeeToken && validatorFeeToken.toLowerCase() !== attemptedFeeToken.toLowerCase();
        const attemptedIsPathUsd =
          attemptedFeeToken.toLowerCase() === TEMPO_PATH_USD_FEE_TOKEN.toLowerCase();
        const isModeratoRpc = FRONTEND_CONFIG.tempoRpcUrl.toLowerCase().includes('moderato.tempo.xyz');
        if (attemptedIsPathUsd && isModeratoRpc) {
          toast.error(
            `Tempo fee precheck rejected PathUSD as spendable (have 0, need ${insufficient.wantWei.toString()}). This usually means validator-token conversion liquidity is unavailable for the current block proposer on Moderato. Try AlphaUSD as transaction fee token.`,
            { id: toastId },
          );
        } else if (validatorTokenDiffers) {
          const validatorAddressText = feeDiagnostics?.validatorAddress
            ? compactHex(feeDiagnostics.validatorAddress)
            : 'latest validator';
          const validatorBalanceText =
            typeof feeDiagnostics?.validatorFeeTokenBalanceRaw === 'bigint'
              ? feeDiagnostics.validatorFeeTokenBalanceRaw.toString()
              : 'unavailable';
          toast.error(
            `Tempo spendable fee balance is 0 for selected transaction token ${compactHex(attemptedFeeToken)} (need ${insufficient.wantWei.toString()}). Latest validator ${validatorAddressText} prefers ${compactHex(validatorFeeToken!)}; sender balance for that validator token is ${validatorBalanceText}. Cross-token fee conversion likely has no available route/liquidity right now.`,
            { id: toastId },
          );
        } else if (feeDiagnostics && feeDiagnostics.balanceRaw > 0n) {
          const selectionHint = feeDiagnostics.txFeeTokenSelectionReason
            ? ` (${feeDiagnostics.txFeeTokenSelectionReason})`
            : '';
          toast.error(
            `Tempo reported spendable fee balance 0 for selected transaction token ${compactHex(attemptedFeeToken)}${selectionHint} (need ${insufficient.wantWei.toString()}) even though balanceOf(${compactHex(feeDiagnostics.sender)}) on configured RPC is ${feeDiagnostics.balanceRaw.toString()}.`,
            { id: toastId },
          );
        } else {
          toast.error(
            `Tempo reported zero spendable fee balance for selected transaction token ${compactHex(attemptedFeeToken)} (need ${insufficient.wantWei.toString()}).`,
            { id: toastId },
          );
        }
      } else if (insufficient) {
        toast.error(
          `Tempo sender has insufficient fee balance (have ${insufficient.haveWei.toString()}, need ${insufficient.wantWei.toString()}).`,
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
    lastTempoFeeDiagnostics,
    lastTxSendDebug,
    nearAccountId,
    refreshThresholdEvmFundingAddress,
    refreshTempoUserFeeTokenBalance,
    refreshTempoUserFeeToken,
    resolveThresholdSenderForEvmFamily,
    tatchi,
    tempoGreetingInput,
  ]);

  const handleSignEvmThresholdTx = useCallback(async () => {
    if (!canExecuteGreeting(arcGreetingInput, isLoggedIn, nearAccountId)) return;
    const toastId = 'evm-threshold-sign';
    setEvmThresholdSignLoading(true);
    toast.loading('Signing EVM transaction…', { id: toastId });
    let signedResultForBroadcast: Awaited<ReturnType<typeof tatchi.tempo.signTempo>> | null = null;
    try {
      const thresholdSender = await resolveThresholdSenderForEvmFamily();

      const feeCaps = await resolveEip1559FeeCaps(FRONTEND_CONFIG.arcRpcUrl);
      const request = buildDemoEip1559Request(arcGreetingInput.trim(), feeCaps);
      const signed = await tatchi.tempo.signTempo({
        nearAccountId: nearAccountId!,
        request,
      });
      signedResultForBroadcast = signed;

      if (signed.kind !== 'eip1559') {
        throw new Error(`Unexpected signing result kind: ${signed.kind}`);
      }
      assertRawTxTypePrefix({ requestKind: request.kind, rawTxHex: signed.rawTxHex });
      const nonce = readManagedNonceFromSignedResult(signed) ?? 0n;

      const debugContext: TxSendDebugContext = {
        atIso: new Date().toISOString(),
        flow: 'evm-sign',
        sender: thresholdSender,
        chain: request.chain,
        requestKind: request.kind,
        nonce,
        gasLimit: request.tx.gasLimit,
        feeToken: null,
        rawTxTypePrefix: getRawTxTypePrefix(signed.rawTxHex),
        txHashHint: signed.txHashHex as `0x${string}`,
      };
      setLastTxSendDebug(debugContext);
      console.log('[DemoPage][TxSendContext]', debugContext);

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
      const nodeReportedFrom = await readEvmTransactionSender({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
      }).catch(() => null);
      const nodeReportedFromMatchesSender = nodeReportedFrom
        ? nodeReportedFrom.toLowerCase() === thresholdSender.toLowerCase()
        : null;
      const finalizedDebugContext: TxSendDebugContext = {
        ...debugContext,
        txHash,
        nodeReportedFrom,
        nodeReportedFromMatchesSender,
      };
      setLastTxSendDebug(finalizedDebugContext);
      console.log('[DemoPage][TxSendContext]', finalizedDebugContext);

      toast.loading('EVM transaction broadcasted, waiting for finalization…', { id: toastId });
      await waitForEvmTransactionFinalization({
        rpcUrl: FRONTEND_CONFIG.arcRpcUrl,
        txHash,
        gasLimitHint: request.tx.gasLimit,
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
    arcGreetingInput,
    canExecuteGreeting,
    fetchArcGreeting,
    isLoggedIn,
    nearAccountId,
    resolveThresholdSenderForEvmFamily,
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
      setTempoUserFeeTokenError(null);
      setLastTempoFeeDiagnostics(null);
      return;
    }
    void refreshTempoUserFeeToken({ silent: true, userAddress: thresholdEvmFundingAddress });
  }, [refreshTempoUserFeeToken, thresholdEvmFundingAddress]);

  useEffect(() => {
    if (
      !thresholdEvmFundingAddress ||
      !isEvmAddress(thresholdEvmFundingAddress) ||
      !tempoUserFeeToken
    ) {
      setTempoUserFeeTokenBalanceRaw(null);
      setTempoUserFeeTokenBalanceError(null);
      return;
    }
    void refreshTempoUserFeeTokenBalance({
      silent: true,
      userAddress: thresholdEvmFundingAddress,
      feeToken: tempoUserFeeToken,
    });
  }, [refreshTempoUserFeeTokenBalance, tempoUserFeeToken, thresholdEvmFundingAddress]);

  if (!isLoggedIn || !nearAccountId) {
    return null;
  }

  const accountName = nearAccountId.split('.')?.[0];
  const preferredTempoFeeToken = getPreferredTempoFeeToken();
  const tempoFeeTokenIsAlpha =
    String(tempoUserFeeToken || '').toLowerCase() === TEMPO_ALPHA_USD_FEE_TOKEN.toLowerCase();
  const tempoFeeTokenIsPath =
    String(tempoUserFeeToken || '').toLowerCase() === TEMPO_PATH_USD_FEE_TOKEN.toLowerCase();
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
            Fund this threshold EVM signer address with Arc native gas and a Tempo fee token.
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
          <div style={{ fontSize: '0.85rem', color: 'var(--fe-text-secondary)' }}>
            App-preferred Tempo fee token: <code>{preferredTempoFeeToken}</code>
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--fe-text-secondary)' }}>
            Tempo on-chain user fee token:{' '}
            {tempoUserFeeTokenLoading ? (
              'Checking…'
            ) : tempoUserFeeToken ? (
              <code>{tempoUserFeeToken}</code>
            ) : (
              'Not set'
            )}
          </div>
          <div style={{ fontSize: '0.85rem', color: 'var(--fe-text-secondary)' }}>
            Tempo fee-token balance on configured RPC ({compactHex(FRONTEND_CONFIG.tempoRpcUrl)}):{' '}
            {tempoUserFeeTokenBalanceLoading ? (
              'Checking…'
            ) : tempoUserFeeTokenBalanceRaw != null ? (
              <code>{tempoUserFeeTokenBalanceRaw.toString()}</code>
            ) : (
              'Unavailable'
            )}
          </div>
          {lastTempoFeeDiagnostics ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--fe-text-secondary)' }}>
              Last Tempo fee preflight:&nbsp;
              <code>{lastTempoFeeDiagnostics.atIso}</code>
              &nbsp;sender&nbsp;
              <code>{lastTempoFeeDiagnostics.sender}</code>
              &nbsp;onChainToken&nbsp;
              <code>{lastTempoFeeDiagnostics.onChainFeeToken}</code>
              &nbsp;txFeeToken&nbsp;
              <code>{lastTempoFeeDiagnostics.txFeeToken}</code>
              {lastTempoFeeDiagnostics.txFeeTokenSelectionReason ? (
                <>
                  &nbsp;selection&nbsp;
                  <code>{lastTempoFeeDiagnostics.txFeeTokenSelectionReason}</code>
                </>
              ) : null}
              {typeof lastTempoFeeDiagnostics.onChainFeeTokenBalanceRaw === 'bigint' ? (
                <>
                  &nbsp;onChainBalanceRaw&nbsp;
                  <code>{lastTempoFeeDiagnostics.onChainFeeTokenBalanceRaw.toString()}</code>
                </>
              ) : null}
              {typeof lastTempoFeeDiagnostics.alphaFeeTokenBalanceRaw === 'bigint' ? (
                <>
                  &nbsp;alphaBalanceRaw&nbsp;
                  <code>{lastTempoFeeDiagnostics.alphaFeeTokenBalanceRaw.toString()}</code>
                </>
              ) : null}
              {typeof lastTempoFeeDiagnostics.txFeeTokenBalanceRaw === 'bigint' ? (
                <>
                  &nbsp;txTokenBalanceRaw&nbsp;
                  <code>{lastTempoFeeDiagnostics.txFeeTokenBalanceRaw.toString()}</code>
                </>
              ) : null}
              &nbsp;balanceRaw&nbsp;
              <code>{lastTempoFeeDiagnostics.balanceRaw.toString()}</code>
              &nbsp;chainPendingNonce&nbsp;
              <code>{lastTempoFeeDiagnostics.chainPendingNonce.toString()}</code>
              {typeof lastTempoFeeDiagnostics.nonce === 'bigint' ? (
                <>
                  &nbsp;nonce&nbsp;
                  <code>{lastTempoFeeDiagnostics.nonce.toString()}</code>
                </>
              ) : null}
              &nbsp;gasLimit&nbsp;
              <code>{lastTempoFeeDiagnostics.gasLimit.toString()}</code>
              &nbsp;maxPriorityFeePerGas&nbsp;
              <code>{lastTempoFeeDiagnostics.maxPriorityFeePerGas.toString()}</code>
              &nbsp;maxFeePerGas&nbsp;
              <code>{lastTempoFeeDiagnostics.maxFeePerGas.toString()}</code>
              {lastTempoFeeDiagnostics.validatorAddress ? (
                <>
                  &nbsp;validator&nbsp;
                  <code>{lastTempoFeeDiagnostics.validatorAddress}</code>
                </>
              ) : null}
              {lastTempoFeeDiagnostics.validatorFeeToken ? (
                <>
                  &nbsp;validatorFeeToken&nbsp;
                  <code>{lastTempoFeeDiagnostics.validatorFeeToken}</code>
                </>
              ) : null}
              {typeof lastTempoFeeDiagnostics.validatorFeeTokenBalanceRaw === 'bigint' ? (
                <>
                  &nbsp;validatorTokenBalanceRaw&nbsp;
                  <code>{lastTempoFeeDiagnostics.validatorFeeTokenBalanceRaw.toString()}</code>
                </>
              ) : null}
            </div>
          ) : null}
          {tempoUserFeeTokenError ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--fe-text-secondary)' }}>
              Fee-token check error: {tempoUserFeeTokenError}
            </div>
          ) : null}
          {tempoUserFeeTokenBalanceError ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--fe-text-secondary)' }}>
              Fee-token balance check error: {tempoUserFeeTokenBalanceError}
            </div>
          ) : null}
          {lastTxSendDebug ? (
            <div style={{ fontSize: '0.8rem', color: 'var(--fe-text-secondary)' }}>
              Last send:&nbsp;
              <code>{lastTxSendDebug.flow}</code>
              &nbsp;from&nbsp;
              <code>{lastTxSendDebug.sender}</code>
              &nbsp;kind&nbsp;
              <code>
                {lastTxSendDebug.chain}:{lastTxSendDebug.requestKind}
              </code>
              &nbsp;nonce&nbsp;
              <code>{lastTxSendDebug.nonce.toString()}</code>
              {typeof lastTxSendDebug.chainPendingNonce === 'bigint' ? (
                <>
                  &nbsp;chainPendingNonce&nbsp;
                  <code>{lastTxSendDebug.chainPendingNonce.toString()}</code>
                </>
              ) : null}
              {typeof lastTxSendDebug.gasLimit === 'bigint' ? (
                <>
                  &nbsp;gasLimit&nbsp;
                  <code>{lastTxSendDebug.gasLimit.toString()}</code>
                </>
              ) : null}
              {lastTxSendDebug.feeToken ? (
                <>
                  &nbsp;feeToken&nbsp;
                  <code>{lastTxSendDebug.feeToken}</code>
                </>
              ) : null}
              {lastTxSendDebug.feeTokenSelectionReason ? (
                <>
                  &nbsp;selection&nbsp;
                  <code>{lastTxSendDebug.feeTokenSelectionReason}</code>
                </>
              ) : null}
              {lastTxSendDebug.rawTxTypePrefix ? (
                <>
                  &nbsp;rawType&nbsp;
                  <code>{lastTxSendDebug.rawTxTypePrefix}</code>
                </>
              ) : null}
              {lastTxSendDebug.recoveredSenderFromRaw ? (
                <>
                  &nbsp;recoveredFromRaw&nbsp;
                  <code>{lastTxSendDebug.recoveredSenderFromRaw}</code>
                  &nbsp;match&nbsp;
                  <code>{String(lastTxSendDebug.recoveredSenderMatchesSender ?? false)}</code>
                </>
              ) : null}
              {lastTxSendDebug.txHash ? (
                <>
                  &nbsp;txHash&nbsp;
                  <code>{compactHex(lastTxSendDebug.txHash)}</code>
                </>
              ) : null}
              {lastTxSendDebug.nodeReportedFrom ? (
                <>
                  &nbsp;nodeFrom&nbsp;
                  <code>{lastTxSendDebug.nodeReportedFrom}</code>
                  &nbsp;match&nbsp;
                  <code>{String(lastTxSendDebug.nodeReportedFromMatchesSender ?? false)}</code>
                </>
              ) : null}
            </div>
          ) : null}
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
            onClick={handleSetTempoFeeTokenAlphaUsd}
            loading={tempoFeeTokenConfigLoading && tempoFeeTokenConfigTarget === 'alpha'}
            loadingText="Configuring..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={tempoFeeTokenConfigLoading || tempoFeeTokenIsAlpha}
          >
            {tempoFeeTokenIsAlpha
              ? 'Fee Token: AlphaUSD (Configured)'
              : 'Set Tempo Fee Token to AlphaUSD'}
          </LoadingButton>
          <LoadingButton
            onClick={handleSetTempoFeeTokenPathUsd}
            loading={tempoFeeTokenConfigLoading && tempoFeeTokenConfigTarget === 'path'}
            loadingText="Configuring..."
            variant="secondary"
            size="medium"
            style={{ width: '100%' }}
            disabled={tempoFeeTokenConfigLoading || tempoFeeTokenIsPath}
          >
            {tempoFeeTokenIsPath
              ? 'Fee Token: PathUSD (Configured)'
              : 'Set Tempo Fee Token to PathUSD'}
          </LoadingButton>
          {!tempoUserFeeTokenLoading && !tempoUserFeeToken ? (
            <LoadingButton
              onClick={handleSetTempoFeeTokenPathUsd}
              loading={tempoFeeTokenConfigLoading && tempoFeeTokenConfigTarget === 'path'}
              loadingText="Configuring..."
              variant="secondary"
              size="medium"
              style={{ width: '100%' }}
              disabled={tempoFeeTokenConfigLoading}
            >
              Recommended on Moderato: Set Fee Token to PathUSD
            </LoadingButton>
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
