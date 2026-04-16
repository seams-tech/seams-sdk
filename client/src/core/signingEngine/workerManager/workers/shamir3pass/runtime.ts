import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';

export type Shamir3PassClientKeyHandle = {
  keyHandle: string;
};

export interface Shamir3PassRuntime {
  createClientKeyHandle(args: { shamirPrimeB64u: string }): Promise<Shamir3PassClientKeyHandle>;
  destroyClientKeyHandle(args: { keyHandle: string }): Promise<void>;
  addClientSealWithKeyHandle(input: {
    ciphertextB64u: string;
    keyHandle: string;
  }): Promise<string>;
  addClientSealBytesWithKeyHandle?(input: {
    ciphertext: Uint8Array;
    keyHandle: string;
  }): Promise<string>;
  removeClientSealWithKeyHandle(input: {
    ciphertextB64u: string;
    keyHandle: string;
  }): Promise<string>;
  removeClientSealWithKeyHandleToBytes?(input: {
    ciphertextB64u: string;
    keyHandle: string;
  }): Promise<Uint8Array>;
}

let runtimeSingletonPromise: Promise<Shamir3PassRuntime> | null = null;
let shamirWorkerSingleton: Worker | null = null;
let requestCounter = 0;

type Shamir3PassWorkerRequestType =
  | 'createClientKeyHandle'
  | 'destroyClientKeyHandle'
  | 'addClientSealWithKeyHandle'
  | 'addClientSealBytesWithKeyHandle'
  | 'removeClientSealWithKeyHandle'
  | 'removeClientSealWithKeyHandleToBytes';
type Shamir3PassWorkerRequest = {
  id: string;
  type: Shamir3PassWorkerRequestType;
  payload: Record<string, unknown>;
};
type Shamir3PassWorkerResponse =
  | {
      id: string;
      ok: true;
      result: unknown;
    }
  | {
      id: string;
      ok: false;
      error: string;
      code?: string;
    };

type PendingWorkerRequest = {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
  timeoutId: ReturnType<typeof setTimeout>;
};

const pendingByRequestId = new Map<string, PendingWorkerRequest>();
const WORKER_REQUEST_TIMEOUT_MS = 15_000;

function normalizeNonEmptyString(input: unknown, label: string): string {
  const value = typeof input === 'string' ? input.trim() : '';
  if (!value) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

function normalizeClientKeyHandle(value: unknown): Shamir3PassClientKeyHandle {
  if (!isObjectRecord(value)) {
    throw new Error('Invalid Shamir3Pass key handle response');
  }
  return {
    keyHandle: normalizeNonEmptyString(value.keyHandle, 'keyHandle'),
  };
}

function toWorkerError(
  response: Extract<Shamir3PassWorkerResponse, { ok: false }>,
): Error {
  const code = String(response.code || '').trim();
  const message = normalizeNonEmptyString(response.error, 'error');
  return new Error(
    code
      ? `[shamir3pass-worker] ${code}: ${message}`
      : `[shamir3pass-worker] ${message}`,
  );
}

function normalizeWorkerResponse(value: unknown): Shamir3PassWorkerResponse | null {
  if (!isObjectRecord(value)) return null;
  const id = String(value.id || '').trim();
  if (!id || typeof value.ok !== 'boolean') return null;
  if (value.ok) {
    return { id, ok: true, result: value.result };
  }
  return {
    id,
    ok: false,
    error: String(value.error || 'Worker request failed'),
    ...(String(value.code || '').trim() ? { code: String(value.code).trim() } : {}),
  };
}

function nextRequestId(): string {
  requestCounter += 1;
  return `shamir3pass-${Date.now()}-${requestCounter}`;
}

function rejectAllPending(reason: string): void {
  const pending = Array.from(pendingByRequestId.values());
  pendingByRequestId.clear();
  for (const entry of pending) {
    clearTimeout(entry.timeoutId);
    try {
      entry.reject(new Error(reason));
    } catch {}
  }
}

function resetWorker(reason: string): void {
  const worker = shamirWorkerSingleton;
  shamirWorkerSingleton = null;
  if (worker) {
    try {
      worker.terminate();
    } catch {}
  }
  rejectAllPending(reason);
}

function resolveWorkerConstructor(): typeof Worker {
  const workerCtor = (globalThis as { Worker?: typeof Worker }).Worker;
  if (typeof workerCtor !== 'function') {
    throw new Error('Shamir3Pass worker is unavailable in this runtime');
  }
  return workerCtor;
}

function getOrCreateShamirWorker(): Worker {
  if (shamirWorkerSingleton) return shamirWorkerSingleton;
  const WorkerCtor = resolveWorkerConstructor();
  const workerUrl = resolveWasmUrl('shamir3pass.worker.js', 'Shamir3Pass Worker');
  const worker = new WorkerCtor(workerUrl, { type: 'module', name: 'shamir3pass-worker' });

  worker.onmessage = (event: MessageEvent) => {
    const parsed = normalizeWorkerResponse(event.data);
    if (!parsed) return;
    const pending = pendingByRequestId.get(parsed.id);
    if (!pending) return;
    pendingByRequestId.delete(parsed.id);
    clearTimeout(pending.timeoutId);
    if (parsed.ok) {
      pending.resolve(parsed.result);
      return;
    }
    pending.reject(toWorkerError(parsed));
  };

  worker.onerror = (event: ErrorEvent) => {
    const message = String(event?.message || 'Unknown worker error').trim();
    resetWorker(`[shamir3pass-worker] ${message || 'Worker crashed'}`);
  };
  worker.onmessageerror = () => {
    resetWorker('[shamir3pass-worker] Failed to deserialize worker message');
  };

  shamirWorkerSingleton = worker;
  return worker;
}

function sendWorkerRequest(
  type: Shamir3PassWorkerRequestType,
  payload: Record<string, unknown>,
  transfer?: Transferable[],
): Promise<unknown> {
  const requestId = nextRequestId();
  const worker = getOrCreateShamirWorker();
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      pendingByRequestId.delete(requestId);
      reject(new Error(`[shamir3pass-worker] Request timed out after ${WORKER_REQUEST_TIMEOUT_MS}ms`));
    }, WORKER_REQUEST_TIMEOUT_MS);

    pendingByRequestId.set(requestId, {
      resolve,
      reject,
      timeoutId,
    });

    const request: Shamir3PassWorkerRequest = {
      id: requestId,
      type,
      payload,
    };

    try {
      worker.postMessage(request, transfer || []);
    } catch (error: unknown) {
      const pending = pendingByRequestId.get(requestId);
      if (pending) {
        pendingByRequestId.delete(requestId);
        clearTimeout(pending.timeoutId);
      }
      reject(error instanceof Error ? error : new Error(String(error || 'Worker postMessage failed')));
    }
  });
}

function createShamir3PassRuntime(): Shamir3PassRuntime {
  return {
    createClientKeyHandle: async ({ shamirPrimeB64u }) =>
      normalizeClientKeyHandle(
        await sendWorkerRequest('createClientKeyHandle', {
          shamirPrimeB64u,
        }),
      ),
    destroyClientKeyHandle: async ({ keyHandle }) => {
      await sendWorkerRequest('destroyClientKeyHandle', {
        keyHandle,
      });
    },
    addClientSealWithKeyHandle: async ({ ciphertextB64u, keyHandle }) =>
      normalizeNonEmptyString(
        await sendWorkerRequest('addClientSealWithKeyHandle', {
          ciphertextB64u,
          keyHandle,
        }),
        'ciphertextB64u',
      ),
    addClientSealBytesWithKeyHandle: async ({ ciphertext, keyHandle }) => {
      const ciphertextCopy = ciphertext.slice();
      return normalizeNonEmptyString(
        await sendWorkerRequest(
          'addClientSealBytesWithKeyHandle',
          {
            ciphertext: ciphertextCopy.buffer,
            keyHandle,
          },
          [ciphertextCopy.buffer],
        ),
        'ciphertextB64u',
      );
    },
    removeClientSealWithKeyHandle: async ({ ciphertextB64u, keyHandle }) =>
      normalizeNonEmptyString(
        await sendWorkerRequest('removeClientSealWithKeyHandle', {
          ciphertextB64u,
          keyHandle,
        }),
        'ciphertextB64u',
      ),
    removeClientSealWithKeyHandleToBytes: async ({ ciphertextB64u, keyHandle }) => {
      const result = await sendWorkerRequest('removeClientSealWithKeyHandleToBytes', {
        ciphertextB64u,
        keyHandle,
      });
      if (!(result instanceof ArrayBuffer)) {
        throw new Error('ciphertext bytes response must be an ArrayBuffer');
      }
      return new Uint8Array(result);
    },
  };
}

export async function getShamir3PassRuntime(): Promise<Shamir3PassRuntime> {
  if (!runtimeSingletonPromise) {
    runtimeSingletonPromise = Promise.resolve(createShamir3PassRuntime()).catch((error) => {
      runtimeSingletonPromise = null;
      throw error;
    });
  }
  return runtimeSingletonPromise;
}
