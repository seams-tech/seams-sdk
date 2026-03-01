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
  to?: string | null;
  input?: string | null;
  value?: string | null;
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
  senderHint?: `0x${string}`;
  nonceHint?: bigint;
};

export type EvmTransactionWaitErrorBranch =
  | 'dropped_nonce_advanced'
  | 'dropped_hash_disappeared'
  | 'underpriced_fee'
  | 'timeout';

export interface EvmPublicClient {
  request<T>(args: {
    method: string;
    params: unknown[];
    timeoutMs?: number;
  }): Promise<T>;
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
}

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
  finalizationBranch?: EvmTransactionWaitErrorBranch;
};

function toAbortError(signal?: AbortSignal): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) return reason;
  const message = String(reason || '').trim() || 'Operation aborted';
  const error = new Error(message) as Error & { code?: string };
  error.code = 'aborted';
  return error;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw toAbortError(signal);
  }
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
  const fractional = remainder.toString().padStart(9, '0').replace(/0+$/, '');
  return `${gwei.toString()}.${fractional}`;
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

export function createEvmPublicClient(args: {
  rpcUrl: string;
  fetchImpl?: typeof fetch;
  requestTimeoutMs?: number;
}): EvmPublicClient {
  const rpcUrl = String(args.rpcUrl || '').trim();
  if (!rpcUrl) {
    throw new Error('RPC URL is not configured');
  }
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
    const startedAt = Date.now();
    const remainingTimeoutMs = (): number =>
      Math.max(1, timeoutMs - Math.max(0, Date.now() - startedAt));
    const controller = new AbortController();

    const withPromiseTimeout = async <V>(timeoutArgs: {
      promise: Promise<V>;
      label: string;
      onTimeout?: () => void;
    }): Promise<V> => {
      const timeoutWindowMs = remainingTimeoutMs();
      let timeoutId: ReturnType<typeof setTimeout> | null = null;
      let settled = false;
      try {
        return await new Promise<V>((resolve, reject) => {
          timeoutId = setTimeout(() => {
            if (settled) return;
            settled = true;
            try {
              timeoutArgs.onTimeout?.();
            } catch {}
            reject(new Error(`${timeoutArgs.label} timed out after ${timeoutMs}ms`));
          }, timeoutWindowMs);
          timeoutArgs.promise.then(
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
    };

    const fetchPromise = fetchImpl(rpcUrl, {
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

    let response: Response;
    try {
      response = await withPromiseTimeout({
        promise: fetchPromise,
        label: `${requestArgs.method} request`,
        onTimeout: () => {
          controller.abort();
        },
      });
    } catch (error: unknown) {
      const maybeAbort = error as { name?: string };
      if (maybeAbort?.name === 'AbortError') {
        throw new Error(`${requestArgs.method} request timed out after ${timeoutMs}ms`);
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
      label: `${requestArgs.method} response`,
      onTimeout: () => {
        controller.abort();
        try {
          response.body?.cancel();
        } catch {}
      },
    }).catch((error: unknown) => {
      const maybeAbort = error as { name?: string };
      if (maybeAbort?.name === 'AbortError') {
        throw new Error(`${requestArgs.method} response timed out after ${timeoutMs}ms`);
      }
      throw error;
    })) as {
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
    if (!('result' in payload)) {
      throw new Error(`Invalid ${requestArgs.method} response`);
    }

    return payload.result as T;
  };

  const getTransactionReceipt = async (receiptArgs: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionReceipt | null> =>
    await request<EvmTransactionReceipt | null>({
      method: 'eth_getTransactionReceipt',
      params: [receiptArgs.txHash],
      ...(receiptArgs.timeoutMs != null ? { timeoutMs: receiptArgs.timeoutMs } : {}),
    });

  const getBlockByNumber = async (blockArgs: {
    blockTag: EvmBlockTag;
    timeoutMs?: number;
  }): Promise<EvmBlockHeader | null> =>
    await request<EvmBlockHeader | null>({
      method: 'eth_getBlockByNumber',
      params: [blockArgs.blockTag, false],
      ...(blockArgs.timeoutMs != null ? { timeoutMs: blockArgs.timeoutMs } : {}),
    });

  const getTransactionByHash = async (txArgs: {
    txHash: `0x${string}`;
    timeoutMs?: number;
  }): Promise<EvmTransactionByHash | null> =>
    await request<EvmTransactionByHash | null>({
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
    const missingLikelyReplacedMinDurationMs = Math.min(
      15_000,
      Math.max(pollIntervalMs * 3, Math.floor(timeoutMs / 6)),
    );
    let lastRpcError: string | null = null;
    let underpricedSinceMs: number | null = null;
    let observedTxFrom: `0x${string}` | null = null;
    let observedTxNonce: bigint | null = null;
    let nonceAdvancedStreak = 0;
    let txSeenByHash = false;
    let txMissingAfterSeenStreak = 0;
    let txMissingWithoutEverSeenStreak = 0;
    let txMissingLikelyReplacedStreak = 0;
    if (toAddressOrNull(waitArgs.senderHint)) {
      observedTxFrom = waitArgs.senderHint as `0x${string}`;
    }
    if (typeof waitArgs.nonceHint === 'bigint' && waitArgs.nonceHint >= 0n) {
      observedTxNonce = waitArgs.nonceHint;
    }

    while (Date.now() < deadline) {
      throwIfAborted(waitArgs.signal);
      let receipt: EvmTransactionReceipt | null = null;
      try {
        const remainingMs = Math.max(1, deadline - Date.now());
        receipt = await getTransactionReceipt({
          txHash: waitArgs.txHash,
          timeoutMs: Math.min(requestTimeoutMs, remainingMs),
        });
        lastRpcError = null;
      } catch (error: unknown) {
        lastRpcError = error instanceof Error ? error.message : String(error);
      }

      if (receipt && typeof receipt === 'object' && typeof receipt.blockNumber === 'string') {
        const receiptBlockHex = toHexQuantityOrNull(receipt.blockNumber);
        if (!receiptBlockHex) {
          throw new Error('Receipt missing valid blockNumber');
        }
        const receiptBlockNumber = parseRpcHexQuantity(receiptBlockHex, 'receipt.blockNumber');
        if (confirmations <= 1) {
          return receipt;
        }
        const remainingMs = Math.max(1, deadline - Date.now());
        const latestBlock = await getBlockByNumber({
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, remainingMs),
        }).catch(() => null);
        const latestBlockHex = toHexQuantityOrNull(latestBlock?.number);
        if (latestBlockHex) {
          const latestBlockNumber = parseRpcHexQuantity(latestBlockHex, 'latest.number');
          if (latestBlockNumber >= receiptBlockNumber) {
            const minedDepth = latestBlockNumber - receiptBlockNumber + 1n;
            if (minedDepth >= BigInt(confirmations)) {
              return receipt;
            }
          }
        }
        await sleepWithAbort(pollIntervalMs, waitArgs.signal);
        continue;
      }

      let txByHashSnapshot: EvmTransactionByHash | null | undefined = undefined;
      if (observedTxFrom === null || observedTxNonce === null || !txSeenByHash) {
        const remainingMs = Math.max(1, deadline - Date.now());
        const tx = await getTransactionByHash({
          txHash: waitArgs.txHash,
          timeoutMs: Math.min(requestTimeoutMs, remainingMs),
        }).catch(() => null);
        txByHashSnapshot = tx;
        const txFrom = toAddressOrNull(tx?.from);
        const txNonceHex = toHexQuantityOrNull(tx?.nonce);
        if (txFrom && txNonceHex) {
          const txNonce = parseRpcHexQuantity(txNonceHex, 'tx.nonce');
          if (observedTxFrom === null) {
            observedTxFrom = txFrom;
          }
          if (observedTxNonce === null) {
            observedTxNonce = txNonce;
          }
          if (
            observedTxFrom.toLowerCase() === txFrom.toLowerCase() &&
            observedTxNonce === txNonce
          ) {
            txSeenByHash = true;
            txMissingAfterSeenStreak = 0;
            txMissingWithoutEverSeenStreak = 0;
            txMissingLikelyReplacedStreak = 0;
          }
        }
      }

      if (observedTxFrom && observedTxNonce !== null) {
        const observedFrom = observedTxFrom;
        const observedNonce = observedTxNonce;
        const txMatchesObservedNonce = (tx: EvmTransactionByHash | null): boolean => {
          const txFrom = toAddressOrNull(tx?.from);
          const txNonceHex = toHexQuantityOrNull(tx?.nonce);
          if (!txFrom || !txNonceHex) return false;
          if (txFrom.toLowerCase() !== observedFrom.toLowerCase()) return false;
          try {
            return parseRpcHexQuantity(txNonceHex, 'tx.nonce') === observedNonce;
          } catch {
            return false;
          }
        };

        const remainingMs = Math.max(1, deadline - Date.now());
        const latestNonce = await getTransactionCount({
          address: observedTxFrom,
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, remainingMs),
        }).catch(() => null);
        if (latestNonce !== null && latestNonce > observedTxNonce) {
          const txLookupRemainingMs = Math.max(1, deadline - Date.now());
          const tx =
            txByHashSnapshot === undefined
              ? await getTransactionByHash({
                  txHash: waitArgs.txHash,
                  timeoutMs: Math.min(requestTimeoutMs, txLookupRemainingMs),
                }).catch(() => null)
              : txByHashSnapshot;
          txByHashSnapshot = tx;
          const txBlockNumberHex = toHexQuantityOrNull(tx?.blockNumber);
          if (txMatchesObservedNonce(tx)) {
            txSeenByHash = true;
          }
          if (txBlockNumberHex) {
            // Receipt propagation can lag transaction indexing on some RPCs.
            // Keep polling when transaction is already mined by hash.
            nonceAdvancedStreak = 0;
            txMissingAfterSeenStreak = 0;
            txMissingWithoutEverSeenStreak = 0;
            txMissingLikelyReplacedStreak = 0;
          } else {
            if (txMatchesObservedNonce(tx)) {
              // Original tx is still visible; do not classify as dropped/replaced yet.
              nonceAdvancedStreak = 0;
              txMissingAfterSeenStreak = 0;
              txMissingWithoutEverSeenStreak = 0;
              txMissingLikelyReplacedStreak = 0;
            } else {
              const pendingNonceRemainingMs = Math.max(1, deadline - Date.now());
              const pendingNonce = await getTransactionCount({
                address: observedTxFrom,
                blockTag: 'pending',
                timeoutMs: Math.min(requestTimeoutMs, pendingNonceRemainingMs),
              }).catch(() => null);
              if (pendingNonce !== null && pendingNonce <= observedTxNonce) {
                nonceAdvancedStreak = 0;
                txMissingLikelyReplacedStreak = 0;
              } else {
                nonceAdvancedStreak += 1;
                txMissingLikelyReplacedStreak = 0;
              }
            }
          }

          if (nonceAdvancedStreak >= 2) {
            const finalReceiptRemainingMs = Math.max(1, deadline - Date.now());
            const finalReceipt = await getTransactionReceipt({
              txHash: waitArgs.txHash,
              timeoutMs: Math.min(requestTimeoutMs, finalReceiptRemainingMs),
            }).catch(() => null);
            if (finalReceipt && typeof finalReceipt.blockNumber === 'string') {
              const finalReceiptBlockHex = toHexQuantityOrNull(finalReceipt.blockNumber);
              if (finalReceiptBlockHex) {
                const finalReceiptBlock = parseRpcHexQuantity(
                  finalReceiptBlockHex,
                  'receipt.blockNumber',
                );
                if (confirmations <= 1) {
                  return finalReceipt;
                }
                const latestBlockRemainingMs = Math.max(1, deadline - Date.now());
                const latestBlock = await getBlockByNumber({
                  blockTag: 'latest',
                  timeoutMs: Math.min(requestTimeoutMs, latestBlockRemainingMs),
                }).catch(() => null);
                const latestBlockHex = toHexQuantityOrNull(latestBlock?.number);
                if (latestBlockHex) {
                  const latestBlockNumber = parseRpcHexQuantity(latestBlockHex, 'latest.number');
                  if (latestBlockNumber >= finalReceiptBlock) {
                    const minedDepth = latestBlockNumber - finalReceiptBlock + 1n;
                    if (minedDepth >= BigInt(confirmations)) {
                      return finalReceipt;
                    }
                  }
                }
                nonceAdvancedStreak = 0;
              }
            }
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
          }
        } else if (latestNonce !== null && latestNonce <= observedTxNonce) {
          nonceAdvancedStreak = 0;
          if (txSeenByHash) {
            const txLookupRemainingMs = Math.max(1, deadline - Date.now());
            const tx =
              txByHashSnapshot === undefined
                ? await getTransactionByHash({
                    txHash: waitArgs.txHash,
                    timeoutMs: Math.min(requestTimeoutMs, txLookupRemainingMs),
                  }).catch(() => null)
                : txByHashSnapshot;
            txByHashSnapshot = tx;
            const txMatchesObservedNonceNow = txMatchesObservedNonce(tx);

            if (txMatchesObservedNonceNow) {
              txMissingAfterSeenStreak = 0;
              txMissingWithoutEverSeenStreak = 0;
              txMissingLikelyReplacedStreak = 0;
            } else {
              const pendingNonceRemainingMs = Math.max(1, deadline - Date.now());
              const pendingNonce = await getTransactionCount({
                address: observedTxFrom,
                blockTag: 'pending',
                timeoutMs: Math.min(requestTimeoutMs, pendingNonceRemainingMs),
              }).catch(() => null);
              if (pendingNonce !== null && pendingNonce <= observedTxNonce) {
                txMissingAfterSeenStreak += 1;
                txMissingLikelyReplacedStreak = 0;
              } else if (pendingNonce !== null && pendingNonce > observedTxNonce) {
                txMissingAfterSeenStreak = 0;
                txMissingLikelyReplacedStreak += 1;
              } else {
                txMissingAfterSeenStreak = 0;
                txMissingLikelyReplacedStreak = 0;
              }
            }

            if (txMissingAfterSeenStreak >= 2) {
              const error = new Error(
                `Transaction dropped or replaced: tx hash disappeared from pending pool at nonce ${observedTxNonce.toString()}.`,
              ) as EvmWaitError;
              error.code = 'tx_dropped_or_replaced';
              error.reason = 'dropped';
              error.txNonce = observedTxNonce.toString();
              error.latestNonce = latestNonce.toString();
              error.txFrom = observedTxFrom;
              error.finalizationBranch = 'dropped_hash_disappeared';
              throw error;
            }

            const waitedMs = Date.now() - waitStartedAtMs;
            if (
              txMissingLikelyReplacedStreak >= 2 &&
              waitedMs >= missingLikelyReplacedMinDurationMs
            ) {
              const error = new Error(
                `Transaction dropped or replaced: tx hash disappeared and pending nonce moved ahead of tx nonce (${observedTxNonce.toString()}).`,
              ) as EvmWaitError;
              error.code = 'tx_dropped_or_replaced';
              error.reason = 'replaced';
              error.txNonce = observedTxNonce.toString();
              error.latestNonce = latestNonce.toString();
              error.txFrom = observedTxFrom;
              error.finalizationBranch = 'dropped_hash_disappeared';
              throw error;
            }
          }
          if (!txSeenByHash) {
            const txLookupRemainingMs = Math.max(1, deadline - Date.now());
            const tx =
              txByHashSnapshot === undefined
                ? await getTransactionByHash({
                    txHash: waitArgs.txHash,
                    timeoutMs: Math.min(requestTimeoutMs, txLookupRemainingMs),
                  }).catch(() => null)
                : txByHashSnapshot;
            txByHashSnapshot = tx;
            if (txMatchesObservedNonce(tx)) {
              txSeenByHash = true;
              txMissingWithoutEverSeenStreak = 0;
              txMissingLikelyReplacedStreak = 0;
            } else {
              const pendingNonceRemainingMs = Math.max(1, deadline - Date.now());
              const pendingNonce = await getTransactionCount({
                address: observedTxFrom,
                blockTag: 'pending',
                timeoutMs: Math.min(requestTimeoutMs, pendingNonceRemainingMs),
              }).catch(() => null);
              if (pendingNonce !== null && pendingNonce <= observedTxNonce) {
                txMissingWithoutEverSeenStreak += 1;
                txMissingLikelyReplacedStreak = 0;
              } else if (pendingNonce !== null && pendingNonce > observedTxNonce) {
                txMissingWithoutEverSeenStreak = 0;
                txMissingLikelyReplacedStreak += 1;
              } else {
                txMissingWithoutEverSeenStreak = 0;
                txMissingLikelyReplacedStreak = 0;
              }
            }

            const waitedMs = Date.now() - waitStartedAtMs;
            if (
              txMissingWithoutEverSeenStreak >= 3 &&
              waitedMs >= missingNeverSeenMinDurationMs
            ) {
              const error = new Error(
                `Transaction dropped or replaced: tx hash never became visible to RPC pending pool at nonce ${observedTxNonce.toString()}.`,
              ) as EvmWaitError;
              error.code = 'tx_dropped_or_replaced';
              error.reason = 'dropped';
              error.txNonce = observedTxNonce.toString();
              error.latestNonce = latestNonce.toString();
              error.txFrom = observedTxFrom;
              error.finalizationBranch = 'dropped_hash_disappeared';
              throw error;
            }
            if (
              txMissingLikelyReplacedStreak >= 2 &&
              waitedMs >= missingLikelyReplacedMinDurationMs
            ) {
              const error = new Error(
                `Transaction dropped or replaced: tx hash never became visible and pending nonce moved ahead of tx nonce (${observedTxNonce.toString()}).`,
              ) as EvmWaitError;
              error.code = 'tx_dropped_or_replaced';
              error.reason = 'replaced';
              error.txNonce = observedTxNonce.toString();
              error.latestNonce = latestNonce.toString();
              error.txFrom = observedTxFrom;
              error.finalizationBranch = 'dropped_hash_disappeared';
              throw error;
            }
          }
        }
      }

      if (typeof waitArgs.maxFeePerGasHint === 'bigint') {
        const remainingMs = Math.max(1, deadline - Date.now());
        const latestBlock = await getBlockByNumber({
          blockTag: 'latest',
          timeoutMs: Math.min(requestTimeoutMs, remainingMs),
        }).catch(() => null);
        const baseFeeHex = String(latestBlock?.baseFeePerGas || '').trim();
        if (/^0x[0-9a-fA-F]+$/.test(baseFeeHex)) {
          let baseFeePerGas: bigint | null = null;
          try {
            baseFeePerGas = parseRpcHexQuantity(baseFeeHex, 'baseFeePerGas');
          } catch {
            baseFeePerGas = null;
          }
          if (baseFeePerGas !== null && baseFeePerGas > waitArgs.maxFeePerGasHint) {
            if (underpricedSinceMs === null) {
              underpricedSinceMs = Date.now();
            }
            const requiredUnderpricedDurationMs = Math.min(30_000, Math.floor(timeoutMs / 3));
            if (Date.now() - underpricedSinceMs >= requiredUnderpricedDurationMs) {
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
