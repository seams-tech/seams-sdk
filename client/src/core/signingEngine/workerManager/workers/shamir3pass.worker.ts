import init, {
  init_shamir3pass_runtime,
  shamir3pass_add_lock,
  shamir3pass_generate_client_lock_keys,
  shamir3pass_remove_lock,
} from '../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { WorkerControlMessage } from '../workerTypes';

type Shamir3PassWorkerRequest =
  | { id: string; type: 'generateClientKeypair'; payload: { shamirPrimeB64u: unknown } }
  | {
      id: string;
      type: 'addClientSeal';
      payload: {
        ciphertextB64u: unknown;
        exponentB64u: unknown;
        shamirPrimeB64u: unknown;
      };
    }
  | {
      id: string;
      type: 'removeClientSeal';
      payload: {
        ciphertextB64u: unknown;
        exponentB64u: unknown;
        shamirPrimeB64u: unknown;
      };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
};

const wasmUrl = resolveWasmUrl('shamir3pass_runtime_bg.wasm', 'Shamir3Pass Runtime');
let wasmInitPromise: Promise<void> | null = null;

function asWorkerErrorPayload(err: unknown): WorkerErrorPayload {
  if (err && typeof err === 'object') {
    const message =
      typeof (err as { message?: unknown }).message === 'string'
        ? String((err as { message?: string }).message).trim()
        : '';
    const code =
      typeof (err as { code?: unknown }).code === 'string'
        ? String((err as { code?: string }).code).trim()
        : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function asNonEmptyString(value: unknown, label: string): string {
  const normalized = typeof value === 'string' ? value.trim() : '';
  if (!normalized) throw new Error(`${label} must be a non-empty string`);
  return normalized;
}

function asCipherInput(payload: {
  ciphertextB64u: unknown;
  exponentB64u: unknown;
  shamirPrimeB64u: unknown;
}): {
  ciphertextB64u: string;
  exponentB64u: string;
  shamirPrimeB64u: string;
} {
  return {
    ciphertextB64u: asNonEmptyString(payload.ciphertextB64u, 'ciphertextB64u'),
    exponentB64u: asNonEmptyString(payload.exponentB64u, 'exponentB64u'),
    shamirPrimeB64u: asNonEmptyString(payload.shamirPrimeB64u, 'shamirPrimeB64u'),
  };
}

function postToMainThread(message: unknown): void {
  const workerSelf = self as unknown as {
    postMessage: (message: unknown) => void;
  };
  workerSelf.postMessage(message);
}

async function ensureWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Shamir3Pass Runtime',
      wasmUrl,
      initFunction: init as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_shamir3pass_runtime(),
    });
  })();
  return wasmInitPromise;
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as Shamir3PassWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    await ensureWasm();
    switch (msg.type) {
      case 'generateClientKeypair': {
        const shamirPrimeB64u = asNonEmptyString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u');
        const result = shamir3pass_generate_client_lock_keys(shamirPrimeB64u);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'addClientSeal': {
        const input = asCipherInput(msg.payload);
        const result = shamir3pass_add_lock(
          input.ciphertextB64u,
          input.exponentB64u,
          input.shamirPrimeB64u,
        );
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'removeClientSeal': {
        const input = asCipherInput(msg.payload);
        const result = shamir3pass_remove_lock(
          input.ciphertextB64u,
          input.exponentB64u,
          input.shamirPrimeB64u,
        );
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      default: {
        throw new Error('Unsupported Shamir3Pass worker operation type');
      }
    }
  } catch (e) {
    const err = asWorkerErrorPayload(e);
    postToMainThread({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
    });
  }
});
