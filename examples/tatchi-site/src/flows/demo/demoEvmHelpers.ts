import {
  buildTempoSetUserTokenCall,
  createEvmPublicClient,
  decodeTempoUserTokenResult,
  encodeTempoUserTokensCalldata,
  parseEvmRpcHexQuantity,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_FEE_MANAGER_CONTRACT,
  TEMPO_FEE_MANAGER_ABI,
  type EvmPublicClient,
  type EvmPublicTransactionReceipt,
} from '@tatchi-xyz/sdk';
import {
  normalizeLowercaseString,
  normalizeTrimmedString,
} from '../../../../../shared/src/utils/normalize';

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
export const EVM_TX_FINALITY_CONFIRMATIONS = 1;
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

export type ManagedNonceHints = {
  senderHint?: `0x${string}`;
  nonceHint?: bigint;
};

export type EvmFinalizationBranch =
  | 'receipt_confirmed'
  | 'receipt_reverted'
  | 'dropped_nonce_advanced'
  | 'dropped_hash_disappeared'
  | 'underpriced_fee'
  | 'timeout'
  | 'aborted'
  | 'unknown_error';

export type EvmFinalizationDebugEvent = {
  branch: EvmFinalizationBranch;
  txHash: `0x${string}`;
  message: string;
  chain?: 'tempo' | 'evm';
  chainId?: number;
  sender?: `0x${string}`;
  nonce?: string;
  errorCode?: string;
  reason?: 'dropped' | 'replaced';
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

export type EvmTransactionReceipt = EvmPublicTransactionReceipt;

export type EvmTransactionResponse = {
  from?: string | null;
  to?: string | null;
  input?: string | null;
  value?: string | null;
};

function createDemoEvmPublicClient(args: {
  rpcUrl: string;
  requestTimeoutMs?: number;
}): EvmPublicClient {
  return createEvmPublicClient({
    rpcUrl: args.rpcUrl,
    requestTimeoutMs: args.requestTimeoutMs ?? EVM_RPC_REQUEST_TIMEOUT_MS,
  });
}

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

export async function readEvmGreeting(params: {
  rpcUrl: string;
  contract: `0x${string}`;
  selector: `0x${string}`;
  timeoutMs?: number;
}): Promise<string> {
  const { rpcUrl, contract, selector } = params;
  const client = createDemoEvmPublicClient({
    rpcUrl,
    ...(params.timeoutMs != null ? { requestTimeoutMs: params.timeoutMs } : {}),
  });
  const result = await client.request<string>({
    method: 'eth_call',
    params: [{ to: contract, data: selector }, 'latest'],
    ...(params.timeoutMs != null ? { timeoutMs: params.timeoutMs } : {}),
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
  const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
  const txHash = await client.request<string>({
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
  chain?: 'tempo' | 'evm';
  chainId?: number;
  gasLimitHint?: bigint;
  maxFeePerGasHint?: bigint;
  senderHint?: `0x${string}`;
  nonceHint?: bigint;
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
  onFinalizationDebugEvent?: (event: EvmFinalizationDebugEvent) => void;
}): Promise<EvmTransactionReceipt> {
  const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
  const emitDebugEvent = (argsEvent: {
    branch: EvmFinalizationBranch;
    message: string;
    errorCode?: string;
    reason?: 'dropped' | 'replaced';
  }): void => {
    try {
      args.onFinalizationDebugEvent?.({
        branch: argsEvent.branch,
        txHash: args.txHash,
        message: argsEvent.message,
        ...(args.chain ? { chain: args.chain } : {}),
        ...(typeof args.chainId === 'number' ? { chainId: args.chainId } : {}),
        ...(args.senderHint ? { sender: args.senderHint } : {}),
        ...(typeof args.nonceHint === 'bigint' ? { nonce: args.nonceHint.toString() } : {}),
        ...(argsEvent.errorCode ? { errorCode: argsEvent.errorCode } : {}),
        ...(argsEvent.reason ? { reason: argsEvent.reason } : {}),
      });
    } catch {}
  };

  const extractErrorCode = (error: unknown): string | undefined => {
    const code = normalizeLowercaseString(
      error && typeof error === 'object' && 'code' in error
        ? (error as { code?: unknown }).code
        : '',
    );
    return code || undefined;
  };

  const extractDroppedOrReplacedReason = (error: unknown): 'dropped' | 'replaced' | undefined => {
    const reason = normalizeLowercaseString(
      error && typeof error === 'object' && 'reason' in error
        ? (error as { reason?: unknown }).reason
        : '',
    );
    if (reason === 'replaced') return 'replaced';
    if (reason === 'dropped') return 'dropped';
    return undefined;
  };

  const classifyFinalizationErrorBranch = (error: unknown): EvmFinalizationBranch => {
    const explicitBranch = normalizeLowercaseString(
      error && typeof error === 'object' && 'finalizationBranch' in error
        ? (error as { finalizationBranch?: unknown }).finalizationBranch
        : '',
    );
    if (
      explicitBranch === 'dropped_nonce_advanced' ||
      explicitBranch === 'dropped_hash_disappeared' ||
      explicitBranch === 'underpriced_fee' ||
      explicitBranch === 'timeout'
    ) {
      return explicitBranch;
    }
    const message = normalizeLowercaseString(error instanceof Error ? error.message : error || '');
    const code = normalizeLowercaseString(
      error && typeof error === 'object' && 'code' in error
        ? (error as { code?: unknown }).code
        : '',
    );
    if (code === 'aborted') return 'aborted';
    if (code === 'tx_dropped_or_replaced') {
      if (message.includes('account nonce advanced past tx nonce')) {
        return 'dropped_nonce_advanced';
      }
      if (message.includes('hash disappeared from pending pool')) {
        return 'dropped_hash_disappeared';
      }
      return 'unknown_error';
    }
    if (message.includes('pending due to underpriced fees')) {
      return 'underpriced_fee';
    }
    if (message.includes('timed out waiting for tx receipt')) {
      return 'timeout';
    }
    return 'unknown_error';
  };

  let receipt: EvmTransactionReceipt;
  try {
    receipt = await client.waitForTransactionReceipt({
      txHash: args.txHash,
      timeoutMs: args.timeoutMs ?? EVM_TX_FINALITY_TIMEOUT_MS,
      pollIntervalMs: args.pollIntervalMs ?? EVM_TX_RECEIPT_POLL_INTERVAL_MS,
      confirmations: EVM_TX_FINALITY_CONFIRMATIONS,
      signal: args.signal,
      ...(args.senderHint ? { senderHint: args.senderHint } : {}),
      ...(typeof args.nonceHint === 'bigint' ? { nonceHint: args.nonceHint } : {}),
      ...(typeof args.maxFeePerGasHint === 'bigint'
        ? { maxFeePerGasHint: args.maxFeePerGasHint }
        : {}),
    });
  } catch (error: unknown) {
    emitDebugEvent({
      branch: classifyFinalizationErrorBranch(error),
      message: String(error instanceof Error ? error.message : error || ''),
      errorCode: extractErrorCode(error),
      reason: extractDroppedOrReplacedReason(error),
    });
    throw error;
  }
  const status = normalizeLowercaseString(receipt.status || '');
  if (status && status !== '0x1' && status !== '0x01') {
    emitDebugEvent({
      branch: 'receipt_reverted',
      message: `Transaction receipt reported status ${receipt.status}`,
    });
    const revertMessage = await describeEvmRevert({
      rpcUrl: args.rpcUrl,
      txHash: args.txHash,
      receipt,
    }).catch(() => null);
    const gasUsedInfo = String(receipt.gasUsed || '').trim();
    const gasUsed = (() => {
      try {
        return gasUsedInfo ? parseEvmRpcHexQuantity(gasUsedInfo, 'receipt.gasUsed') : null;
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
  emitDebugEvent({
    branch: 'receipt_confirmed',
    message: 'Transaction receipt confirmed',
  });
  return receipt;
}

export async function readEvmTransactionByHash(args: {
  rpcUrl: string;
  txHash: `0x${string}`;
}): Promise<EvmTransactionResponse | null> {
  const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
  return await client.request<EvmTransactionResponse | null>({
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
    const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
    await client.request<string>({
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

export function isEvmAddress(value: string): value is `0x${string}` {
  return /^0x[0-9a-fA-F]{40}$/.test(String(value || '').trim());
}

export function extractManagedNonceHints(
  signedResult:
    | { managedNonce?: { sender?: string; nonce?: string } | null }
    | null
    | undefined,
): ManagedNonceHints {
  const senderRaw = String(signedResult?.managedNonce?.sender || '').trim();
  const senderHint = isEvmAddress(senderRaw) ? senderRaw : undefined;
  let nonceHint: bigint | undefined;
  try {
    const nonceRaw = String(signedResult?.managedNonce?.nonce || '').trim();
    if (nonceRaw) {
      const parsed = BigInt(nonceRaw);
      if (parsed >= 0n) {
        nonceHint = parsed;
      }
    }
  } catch {}
  return {
    ...(senderHint ? { senderHint } : {}),
    ...(typeof nonceHint === 'bigint' ? { nonceHint } : {}),
  };
}

export async function readEvmNativeBalance(args: {
  rpcUrl: string;
  address: `0x${string}`;
  blockTag?: 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';
}): Promise<bigint> {
  const blockTag = args.blockTag ?? 'latest';
  const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
  const balanceHex = await client.request<string>({
    method: 'eth_getBalance',
    params: [args.address, blockTag],
  });
  return parseEvmRpcHexQuantity(balanceHex, 'eth_getBalance');
}

export async function readTempoUserFeeToken(args: {
  rpcUrl: string;
  userAddress: `0x${string}`;
  timeoutMs?: number;
}): Promise<`0x${string}` | null> {
  const client = createDemoEvmPublicClient({
    rpcUrl: args.rpcUrl,
    ...(args.timeoutMs != null ? { requestTimeoutMs: args.timeoutMs } : {}),
  });
  const result = await client.request<string>({
    method: 'eth_call',
    params: [
      {
        to: TEMPO_FEE_MANAGER_CONTRACT,
        data: encodeTempoUserTokensCalldata(args.userAddress),
      },
      'latest',
    ],
    ...(args.timeoutMs != null ? { timeoutMs: args.timeoutMs } : {}),
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
  const client = createDemoEvmPublicClient({ rpcUrl: args.rpcUrl });
  const result = await client.request<string>({
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
    const client = createDemoEvmPublicClient({
      rpcUrl,
      requestTimeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
    });
    const [latestBlock, maxPriorityFeeHex, gasPriceHex] = await Promise.all([
      client
        .getBlockByNumber({
          blockTag: 'latest',
          timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
        })
        .catch(() => null),
      client
        .request<string>({
          method: 'eth_maxPriorityFeePerGas',
          params: [],
          timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
        })
        .catch(() => null),
      client
        .request<string>({
          method: 'eth_gasPrice',
          params: [],
          timeoutMs: Math.min(EVM_RPC_REQUEST_TIMEOUT_MS, 6_000),
        })
        .catch(() => null),
    ]);

    const parsedBaseFee = (() => {
      const raw = String(latestBlock?.baseFeePerGas || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseEvmRpcHexQuantity(raw, 'baseFeePerGas');
      } catch {
        return null;
      }
    })();
    const parsedGasPrice = (() => {
      const raw = String(gasPriceHex || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseEvmRpcHexQuantity(raw, 'eth_gasPrice');
      } catch {
        return null;
      }
    })();
    const parsedPriority = (() => {
      const raw = String(maxPriorityFeeHex || '').trim();
      if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
      try {
        return parseEvmRpcHexQuantity(raw, 'eth_maxPriorityFeePerGas');
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

export function buildEvmExplorerTxUrl(args: {
  explorerBaseUrl: string;
  txHash: `0x${string}`;
}): string | null {
  const baseUrl = normalizeTrimmedString(args.explorerBaseUrl || '').replace(/\/+$/, '');
  const txHash = normalizeTrimmedString(args.txHash || '');
  if (!baseUrl || !/^0x[0-9a-fA-F]{64}$/.test(txHash)) return null;
  return `${baseUrl}/tx/${txHash}`;
}

export function compactHex(value: string): string {
  if (value.length <= 20) return value;
  return `${value.slice(0, 10)}…${value.slice(-8)}`;
}

export function isUserCancellationError(error: unknown): boolean {
  const maybeError = error as { code?: unknown; message?: unknown } | null | undefined;
  const normalizedCode = normalizeLowercaseString(maybeError?.code || '').replace(/[\s-]+/g, '_');
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

  const normalizedMessage = normalizeLowercaseString(maybeError?.message ?? error ?? '');
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
