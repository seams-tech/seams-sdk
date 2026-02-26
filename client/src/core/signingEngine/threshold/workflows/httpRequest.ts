export const DEFAULT_THRESHOLD_ECDSA_REQUEST_TIMEOUT_MS = 20_000;

function resolveRequestTimeoutMs(timeoutMs: number | undefined): number {
  const parsed = Math.floor(Number(timeoutMs));
  if (Number.isFinite(parsed) && parsed > 0) return parsed;
  return DEFAULT_THRESHOLD_ECDSA_REQUEST_TIMEOUT_MS;
}

function toErrorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

function createThresholdEcdsaTimeoutError(args: { operation: string; timeoutMs: number }): Error {
  return new Error(
    `[threshold-ecdsa] ${args.operation} request timed out after ${args.timeoutMs}ms`,
  );
}

export async function fetchThresholdEcdsaJson<TData = unknown>(args: {
  url: string;
  operation: string;
  init: RequestInit;
  timeoutMs?: number;
}): Promise<{ response: Response; data: TData }> {
  const timeoutMs = resolveRequestTimeoutMs(args.timeoutMs);
  const abortController = typeof AbortController === 'function' ? new AbortController() : null;
  const baseInit: RequestInit = { ...args.init };
  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  let abortCleanup: (() => void) | null = null;
  let didTimeout = false;

  try {
    let response: Response;

    if (abortController) {
      const upstreamSignal = args.init.signal;
      if (upstreamSignal) {
        if (upstreamSignal.aborted) {
          abortController.abort();
        } else if (typeof upstreamSignal.addEventListener === 'function') {
          const onAbort = () => abortController.abort();
          upstreamSignal.addEventListener('abort', onAbort, { once: true });
          abortCleanup = () => upstreamSignal.removeEventListener('abort', onAbort);
        }
      }

      timeoutId = setTimeout(() => {
        didTimeout = true;
        abortController.abort();
      }, timeoutMs);

      response = await fetch(args.url, { ...baseInit, signal: abortController.signal });
    } else {
      response = await Promise.race([
        fetch(args.url, baseInit),
        new Promise<Response>((_, reject) => {
          timeoutId = setTimeout(() => {
            didTimeout = true;
            reject(createThresholdEcdsaTimeoutError({ operation: args.operation, timeoutMs }));
          }, timeoutMs);
        }),
      ]);
    }

    const data = (await response.json().catch(() => ({}))) as TData;
    return { response, data };
  } catch (error: unknown) {
    if (didTimeout) {
      throw createThresholdEcdsaTimeoutError({ operation: args.operation, timeoutMs });
    }
    const message = toErrorMessage(error);
    throw new Error(message || `[threshold-ecdsa] ${args.operation} request failed`);
  } finally {
    if (timeoutId) clearTimeout(timeoutId);
    abortCleanup?.();
  }
}
