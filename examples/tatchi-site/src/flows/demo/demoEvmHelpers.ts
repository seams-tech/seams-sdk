import {
  buildTempoSetUserTokenCall,
  createEvmClient,
  decodeTempoUserTokenResult,
  encodeTempoUserTokensCalldata,
  parseEvmRpcHexQuantity,
  TEMPO_ALPHA_USD_FEE_TOKEN,
  TEMPO_FEE_MANAGER_CONTRACT,
  TEMPO_FEE_MANAGER_ABI,
  type EvmClient,
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

function createDemoEvmClient(args: {
  rpcUrl: string;
  requestTimeoutMs?: number;
}): EvmClient {
  return createEvmClient({
    rpcUrl: args.rpcUrl,
    requestTimeoutMs: args.requestTimeoutMs ?? EVM_RPC_REQUEST_TIMEOUT_MS,
  });
}

export async function readEvmGreeting(params: {
  rpcUrl: string;
  contract: `0x${string}`;
  selector: `0x${string}`;
  timeoutMs?: number;
}): Promise<string> {
  const { rpcUrl, contract, selector } = params;
  const client = createDemoEvmClient({
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

async function sleepWithAbortSignal(ms: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted) {
    const aborted = new Error(String(signal.reason || 'Operation aborted')) as Error & {
      code?: string;
    };
    aborted.code = 'aborted';
    throw aborted;
  }
  await new Promise<void>((resolve, reject) => {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    const cleanup = () => {
      if (timeoutId) {
        clearTimeout(timeoutId);
        timeoutId = null;
      }
      signal?.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      cleanup();
      const aborted = new Error(String(signal?.reason || 'Operation aborted')) as Error & {
        code?: string;
      };
      aborted.code = 'aborted';
      reject(aborted);
    };
    timeoutId = setTimeout(() => {
      cleanup();
      resolve();
    }, Math.max(1, Math.floor(Number(ms) || 0)));
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

export async function waitForExpectedGreeting(args: {
  fetchGreeting: (opts?: { silent?: boolean }) => Promise<string | null>;
  expectedGreeting: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
}): Promise<string | null> {
  const expectedGreeting = String(args.expectedGreeting || '').trim();
  const timeoutMs = Math.max(1, Math.floor(Number(args.timeoutMs ?? 12_000) || 0));
  const pollIntervalMs = Math.max(1, Math.floor(Number(args.pollIntervalMs ?? 750) || 0));
  const deadline = Date.now() + timeoutMs;
  let lastObserved: string | null = null;
  let attempts = 0;

  while (Date.now() <= deadline) {
    if (args.signal?.aborted) {
      const aborted = new Error(String(args.signal.reason || 'Operation aborted')) as Error & {
        code?: string;
      };
      aborted.code = 'aborted';
      throw aborted;
    }

    const observed = await args.fetchGreeting({ silent: true });
    lastObserved = observed;
    attempts += 1;
    if (String(observed || '').trim() === expectedGreeting) {
      return observed;
    }
    if (Date.now() >= deadline) {
      break;
    }
    await sleepWithAbortSignal(pollIntervalMs, args.signal);
  }

  const mismatch = new Error(
    `Post-finalization greeting mismatch: expected "${expectedGreeting}" after ${attempts} checks.`,
  ) as Error & { code?: string; details?: unknown };
  mismatch.code = 'post_finalization_state_mismatch';
  mismatch.details = {
    expectedGreeting,
    observedGreeting: lastObserved,
    attempts,
    timeoutMs,
  };
  throw mismatch;
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

export async function resolveClickTimeEip1559FeeCaps(args: {
  rpcUrl: string;
  fallbackFeeCaps: Eip1559FeeCaps;
}): Promise<Eip1559FeeCaps> {
  return await resolveEip1559FeeCaps(args.rpcUrl).catch(() => args.fallbackFeeCaps);
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
