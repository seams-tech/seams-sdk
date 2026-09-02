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

export type EvmTransactionByHash = {
  blockNumber?: string | null;
  from?: string | null;
  nonce?: string | null;
};

export type EvmBlockHeader = {
  number?: string | null;
  baseFeePerGas?: string | null;
};

export type EvmBlockTag = 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';

export type WaitForEvmTransactionReceiptArgs = {
  txHash: `0x${string}`;
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
  maxFeePerGasHint?: bigint;
  confirmations?: number;
  transactionSenderAddress?: `0x${string}`;
  nonceHint?: bigint;
};

export type EvmClient = {
  request<T>(args: { method: string; params: unknown[]; timeoutMs?: number }): Promise<T>;
  getTransactionReceipt(args: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionReceipt | null>;
  getBlockByNumber(args: {
    blockTag: EvmBlockTag;
    timeoutMs?: number;
  }): Promise<EvmBlockHeader | null>;
  getTransactionByHash(args: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionByHash | null>;
  getTransactionCount(args: {
    address: `0x${string}`;
    blockTag?: EvmBlockTag;
    timeoutMs?: number;
  }): Promise<bigint>;
  waitForTransactionReceipt(args: WaitForEvmTransactionReceiptArgs): Promise<EvmTransactionReceipt>;
};

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_WAIT_TIMEOUT_MS = 90_000;
const DEFAULT_POLL_INTERVAL_MS = 1_250;
const DEFAULT_CONFIRMATIONS = 1;

type EvmWaitError = Error & {
  code?: string;
  reason?: 'dropped' | 'replaced';
  txNonce?: string;
  latestNonce?: string;
  txFrom?: string;
  finalizationBranch?:
    | 'dropped_nonce_advanced'
    | 'dropped_hash_disappeared'
    | 'dropped_nonce_gap'
    | 'underpriced_fee'
    | 'timeout';
};

function toAbortError(signal?: AbortSignal): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) return reason;
  const error = new Error(String(reason || '').trim() || 'Operation aborted') as Error & {
    code?: string;
  };
  error.code = 'aborted';
  return error;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw toAbortError(signal);
}

async function sleepWithAbort(ms: number, signal?: AbortSignal): Promise<void> {
  throwIfAborted(signal);
  const delayMs = Math.max(0, Math.floor(Number(ms) || 0));
  await new Promise<void>((resolve, reject) => {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;
    const cleanup = () => {
      if (timeoutId) {
        globalThis.clearTimeout(timeoutId);
        timeoutId = null;
      }
      signal?.removeEventListener('abort', onAbort);
    };
    const onAbort = () => {
      cleanup();
      reject(toAbortError(signal));
    };
    timeoutId = globalThis.setTimeout(() => {
      cleanup();
      resolve();
    }, delayMs);
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function formatWeiToGwei(value: bigint): string {
  const gwei = value / 1_000_000_000n;
  const remainder = value % 1_000_000_000n;
  if (remainder === 0n) return gwei.toString();
  return `${gwei.toString()}.${remainder.toString().padStart(9, '0').replace(/0+$/, '')}`;
}

function toAddressOrNull(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

function toHexQuantityOrNull(value: unknown): string | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]+$/.test(normalized) ? normalized : null;
}

export function parseRpcHexQuantity(value: string, label: string): bigint {
  const normalized = String(value || '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(normalized)) {
    throw new Error(`Invalid ${label} quantity`);
  }
  return BigInt(normalized);
}

export function createEvmClient(args: {
  rpcUrl: string;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
}): EvmClient {
  const rpcUrl = String(args.rpcUrl || '').trim();
  if (!rpcUrl) throw new Error('RPC URL is not configured');
  const fetchImpl = args.fetchImpl || fetch.bind(globalThis);
  const requestTimeoutMs = Math.max(
    1,
    Math.floor(Number(args.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS) || 0),
  );

  const request = async <T>(requestArgs: {
    method: string;
    params: unknown[];
    timeoutMs?: number;
  }): Promise<T> => {
    const timeoutMs = Math.max(
      1,
      Math.floor(Number(requestArgs.timeoutMs ?? requestTimeoutMs) || 0),
    );
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetchImpl(rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: requestArgs.method,
          params: requestArgs.params,
        }),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`RPC HTTP ${response.status}`);
      const payload = (await response.json()) as {
        error?: EvmJsonRpcError;
        result?: T;
      };
      if (payload.error) {
        const message = String(payload.error.message || `${requestArgs.method} failed`).trim();
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
        const error = new Error(parts.join(' | ')) as Error & {
          code?: string;
          data?: unknown;
          rpcMethod?: string;
        };
        if (code) error.code = code;
        if (payload.error.data !== undefined) error.data = payload.error.data;
        error.rpcMethod = requestArgs.method;
        throw error;
      }
      if (!('result' in payload)) throw new Error(`Invalid ${requestArgs.method} response`);
      return payload.result as T;
    } catch (error: unknown) {
      const maybeAbort = error as { name?: string };
      if (maybeAbort?.name === 'AbortError') {
        throw new Error(`${requestArgs.method} request timed out after ${timeoutMs}ms`);
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  };

  const getTransactionReceipt = async (receiptArgs: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionReceipt | null> =>
    request<EvmTransactionReceipt | null>({
      method: 'eth_getTransactionReceipt',
      params: [receiptArgs.txHash],
      ...(receiptArgs.timeoutMs != null ? { timeoutMs: receiptArgs.timeoutMs } : {}),
    });

  const getBlockByNumber = async (blockArgs: {
    blockTag: EvmBlockTag;
    timeoutMs?: number;
  }): Promise<EvmBlockHeader | null> =>
    request<EvmBlockHeader | null>({
      method: 'eth_getBlockByNumber',
      params: [blockArgs.blockTag, false],
      ...(blockArgs.timeoutMs != null ? { timeoutMs: blockArgs.timeoutMs } : {}),
    });

  const getTransactionByHash = async (txArgs: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionByHash | null> =>
    request<EvmTransactionByHash | null>({
      method: 'eth_getTransactionByHash',
      params: [txArgs.txHash],
      ...(txArgs.timeoutMs != null ? { timeoutMs: txArgs.timeoutMs } : {}),
    });

  const getTransactionCount = async (countArgs: {
    address: `0x${string}`;
    blockTag?: EvmBlockTag;
    timeoutMs?: number;
  }): Promise<bigint> => {
    const quantity = await request<string>({
      method: 'eth_getTransactionCount',
      params: [countArgs.address, countArgs.blockTag ?? 'latest'],
      ...(countArgs.timeoutMs != null ? { timeoutMs: countArgs.timeoutMs } : {}),
    });
    return parseRpcHexQuantity(quantity, 'eth_getTransactionCount');
  };

  const waitForTransactionReceipt = async (
    waitArgs: WaitForEvmTransactionReceiptArgs,
  ): Promise<EvmTransactionReceipt> => {
    const timeoutMs = Math.max(
      1,
      Math.floor(Number(waitArgs.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS) || 0),
    );
    const pollIntervalMs = Math.max(
      1,
      Math.floor(Number(waitArgs.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS) || 0),
    );
    const confirmations = Math.max(
      1,
      Math.floor(Number(waitArgs.confirmations ?? DEFAULT_CONFIRMATIONS) || 0),
    );
    const deadline = Date.now() + timeoutMs;
    const waitStartedAtMs = Date.now();
    const missingNeverSeenMinDurationMs = Math.min(
      30_000,
      Math.max(pollIntervalMs * 3, Math.floor(timeoutMs / 3)),
    );
    let lastRpcError: string | null = null;
    let underpricedSinceMs: number | null = null;
    let observedTxFrom = toAddressOrNull(waitArgs.transactionSenderAddress);
    let observedTxNonce =
      typeof waitArgs.nonceHint === 'bigint' && waitArgs.nonceHint >= 0n
        ? waitArgs.nonceHint
        : null;
    let txSeenByHash = false;
    let txMissingWithoutEverSeenStreak = 0;
    let nonceAdvancedStreak = 0;

    while (Date.now() < deadline) {
      throwIfAborted(waitArgs.signal);
      let receipt: EvmTransactionReceipt | null = null;
      try {
        receipt = await getTransactionReceipt({
          txHash: waitArgs.txHash,
          timeoutMs: Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
        });
        lastRpcError = null;
      } catch (error: unknown) {
        lastRpcError = error instanceof Error ? error.message : String(error);
      }

      if (receipt && typeof receipt.blockNumber === 'string') {
        const receiptBlockHex = toHexQuantityOrNull(receipt.blockNumber);
        if (!receiptBlockHex) throw new Error('Receipt missing valid blockNumber');
        if (confirmations <= 1) return receipt;
        const receiptBlockNumber = parseRpcHexQuantity(receiptBlockHex, 'receipt.blockNumber');
        const latestBlock = await getBlockByNumber({
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
        }).catch(() => null);
        const latestBlockHex = toHexQuantityOrNull(latestBlock?.number);
        if (latestBlockHex) {
          const latestBlockNumber = parseRpcHexQuantity(latestBlockHex, 'latest.number');
          if (latestBlockNumber - receiptBlockNumber + 1n >= BigInt(confirmations)) {
            return receipt;
          }
        }
      }

      const tx = await getTransactionByHash({
        txHash: waitArgs.txHash,
        timeoutMs: Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
      }).catch(() => null);
      const txFrom = toAddressOrNull(tx?.from);
      const txNonceHex = toHexQuantityOrNull(tx?.nonce);
      if (txFrom && txNonceHex) {
        const txNonce = parseRpcHexQuantity(txNonceHex, 'tx.nonce');
        observedTxFrom ||= txFrom;
        observedTxNonce ??= txNonce;
        if (
          observedTxFrom.toLowerCase() === txFrom.toLowerCase() &&
          observedTxNonce === txNonce
        ) {
          txSeenByHash = true;
          txMissingWithoutEverSeenStreak = 0;
        }
      }

      if (observedTxFrom && observedTxNonce !== null) {
        const latestNonce = await getTransactionCount({
          address: observedTxFrom,
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
        }).catch(() => null);
        if (latestNonce !== null && latestNonce > observedTxNonce && !txSeenByHash) {
          nonceAdvancedStreak += 1;
          if (nonceAdvancedStreak >= 2) {
            const error = new Error(
              `Transaction dropped or replaced: account nonce advanced past tx nonce (${observedTxNonce.toString()} -> ${latestNonce.toString()}).`,
            ) as EvmWaitError;
            error.code = 'tx_dropped_or_replaced';
            error.reason = 'dropped';
            error.txNonce = observedTxNonce.toString();
            error.latestNonce = latestNonce.toString();
            error.txFrom = observedTxFrom;
            error.finalizationBranch = 'dropped_nonce_advanced';
            throw error;
          }
        } else {
          nonceAdvancedStreak = 0;
        }
      }

      if (!txSeenByHash) {
        txMissingWithoutEverSeenStreak += 1;
        const waitedMs = Date.now() - waitStartedAtMs;
        if (txMissingWithoutEverSeenStreak >= 3 && waitedMs >= missingNeverSeenMinDurationMs) {
          const error = new Error(
            'Transaction dropped or replaced: tx hash never became visible to RPC pending pool.',
          ) as EvmWaitError;
          error.code = 'tx_dropped_or_replaced';
          error.reason = 'dropped';
          error.finalizationBranch = 'dropped_hash_disappeared';
          throw error;
        }
      }

      if (typeof waitArgs.maxFeePerGasHint === 'bigint') {
        const latestBlock = await getBlockByNumber({
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, Math.max(1, deadline - Date.now())),
        }).catch(() => null);
        const baseFeeHex = String(latestBlock?.baseFeePerGas || '').trim();
        if (/^0x[0-9a-fA-F]+$/.test(baseFeeHex)) {
          const baseFeePerGas = parseRpcHexQuantity(baseFeeHex, 'baseFeePerGas');
          if (baseFeePerGas > waitArgs.maxFeePerGasHint) {
            underpricedSinceMs ??= Date.now();
            if (Date.now() - underpricedSinceMs >= Math.min(30_000, Math.floor(timeoutMs / 3))) {
              const error = new Error(
                `Transaction pending due to underpriced fees: maxFeePerGas=${formatWeiToGwei(waitArgs.maxFeePerGasHint)} gwei, latest baseFee=${formatWeiToGwei(baseFeePerGas)} gwei. Retry to re-sign with refreshed fee caps.`,
              ) as EvmWaitError;
              error.finalizationBranch = 'underpriced_fee';
              throw error;
            }
          } else {
            underpricedSinceMs = null;
          }
        }
      }

      await sleepWithAbort(pollIntervalMs, waitArgs.signal);
    }

    throwIfAborted(waitArgs.signal);
    const details = lastRpcError ? `; last RPC error: ${lastRpcError}` : '';
    const timeoutError = new Error(
      `Timed out waiting for tx receipt after ${timeoutMs}ms${details}`,
    ) as EvmWaitError;
    timeoutError.finalizationBranch = 'timeout';
    throw timeoutError;
  };

  return {
    request,
    getTransactionReceipt,
    getBlockByNumber,
    getTransactionByHash,
    getTransactionCount,
    waitForTransactionReceipt,
  };
}
