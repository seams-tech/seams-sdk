import init, {
  init_shamir3pass_runtime,
  shamir3pass_add_lock,
  shamir3pass_add_lock_bytes,
  shamir3pass_destroy_lock_key_handle,
  shamir3pass_generate_lock_key_handle,
  shamir3pass_remove_lock,
  shamir3pass_remove_lock_to_bytes,
} from '../../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { WorkerControlMessage } from '../workerTypes';

type Shamir3PassWorkerRequest =
  | { id: string; type: 'warmup'; payload?: never }
  | { id: string; type: 'createClientKeyHandle'; payload: { groupId: unknown } }
  | { id: string; type: 'destroyClientKeyHandle'; payload: { keyHandle: unknown } }
  | {
      id: string;
      type: 'addClientSealWithKeyHandle';
      payload: {
        ciphertextB64u: unknown;
        keyHandle: unknown;
      };
    }
  | {
      id: string;
      type: 'addClientSealBytesWithKeyHandle';
      payload: {
        ciphertext: unknown;
        keyHandle: unknown;
      };
    }
  | {
      id: string;
      type: 'removeClientSealWithKeyHandle';
      payload: {
        ciphertextB64u: unknown;
        keyHandle: unknown;
      };
    }
  | {
      id: string;
      type: 'removeClientSealWithKeyHandleToBytes';
      payload: {
        ciphertextB64u: unknown;
        keyHandle: unknown;
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

function asBytes(value: unknown, label: string): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new Error(`${label} must be an ArrayBuffer or TypedArray`);
}

function requireKeyHandle(value: unknown): number {
  const parsed = Number(asNonEmptyString(value, 'keyHandle'));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error('keyHandle must identify an active Shamir 3-pass key');
  }
  return parsed;
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  const workerSelf = self as unknown as {
    postMessage: (message: unknown, transfer?: Transferable[]) => void;
  };
  workerSelf.postMessage(message, transfer);
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
      // Prewarm: ensureWasm() above already did the work (worker spawn + 422KB
      // WASM instantiate). Responding proves the runtime is ready.
      case 'warmup': {
        postToMainThread({ id: msg.id, ok: true, result: { ready: true } });
        return;
      }
      case 'createClientKeyHandle': {
        const groupId = asNonEmptyString(msg.payload.groupId, 'groupId');
        const keyHandle = shamir3pass_generate_lock_key_handle(groupId);
        postToMainThread({ id: msg.id, ok: true, result: { keyHandle: String(keyHandle) } });
        return;
      }
      case 'destroyClientKeyHandle': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        postToMainThread({
          id: msg.id,
          ok: true,
          result: shamir3pass_destroy_lock_key_handle(keyHandle),
        });
        return;
      }
      case 'addClientSealWithKeyHandle': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const result = shamir3pass_add_lock(keyHandle, ciphertextB64u);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'addClientSealBytesWithKeyHandle': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        const ciphertext = asBytes(msg.payload.ciphertext, 'ciphertext');
        try {
          const result = shamir3pass_add_lock_bytes(keyHandle, ciphertext);
          postToMainThread({ id: msg.id, ok: true, result });
        } finally {
          ciphertext.fill(0);
        }
        return;
      }
      case 'removeClientSealWithKeyHandle': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const result = shamir3pass_remove_lock(keyHandle, ciphertextB64u);
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'removeClientSealWithKeyHandleToBytes': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const out = shamir3pass_remove_lock_to_bytes(keyHandle, ciphertextB64u);
        const outBuffer = out.slice().buffer;
        out.fill(0);
        postToMainThread({ id: msg.id, ok: true, result: outBuffer }, [outBuffer]);
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
