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

export type EvmBlockHeader = {
  number?: string | null;
  baseFeePerGas?: string | null;
};

export type WaitForEvmTransactionReceiptArgs = {
  txHash: `0x${string}`;
  timeoutMs?: number;
  pollIntervalMs?: number;
  signal?: AbortSignal;
  maxFeePerGasHint?: bigint;
};

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
    blockTag: 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';
    timeoutMs?: number;
  }): Promise<EvmBlockHeader | null>;
  waitForTransactionReceipt(args: WaitForEvmTransactionReceiptArgs): Promise<EvmTransactionReceipt>;
}

const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;
const DEFAULT_WAIT_TIMEOUT_MS = 90_000;
const DEFAULT_POLL_INTERVAL_MS = 1_250;

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
    blockTag: 'latest' | 'pending' | 'safe' | 'finalized' | 'earliest';
    timeoutMs?: number;
  }): Promise<EvmBlockHeader | null> =>
    await request<EvmBlockHeader | null>({
      method: 'eth_getBlockByNumber',
      params: [blockArgs.blockTag, false],
      ...(blockArgs.timeoutMs != null ? { timeoutMs: blockArgs.timeoutMs } : {}),
    });

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
    const deadline = Date.now() + timeoutMs;
    let lastRpcError: string | null = null;
    let underpricedSinceMs: number | null = null;

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
        return receipt;
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
              throw new Error(
                `Transaction pending due to underpriced fees: maxFeePerGas=${formatWeiToGwei(waitArgs.maxFeePerGasHint)} gwei, latest baseFee=${formatWeiToGwei(baseFeePerGas)} gwei. Retry to re-sign with refreshed fee caps.`,
              );
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
    throw new Error(`Timed out waiting for tx receipt after ${timeoutMs}ms${details}`);
  };

  return {
    request,
    getTransactionReceipt,
    getBlockByNumber,
    waitForTransactionReceipt,
  };
}
