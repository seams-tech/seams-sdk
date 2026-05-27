import init, {
  init_shamir3pass_runtime,
  shamir3pass_add_lock,
  shamir3pass_add_lock_bytes,
  shamir3pass_generate_client_lock_keys,
  shamir3pass_remove_lock,
  shamir3pass_remove_lock_to_bytes,
} from '../../../../../../wasm/shamir3pass_runtime/pkg/shamir3pass_runtime.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { secureRandomId } from '@shared/utils/secureRandomId';
import { WorkerControlMessage } from '../workerTypes';

type Shamir3PassWorkerRequest =
  | { id: string; type: 'createClientKeyHandle'; payload: { shamirPrimeB64u: unknown } }
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
let keyHandleCounter = 0;
const keypairsByHandle = new Map<
  string,
  {
    shamirPrimeB64u: string;
    clientEncryptExponentB64u: string;
    clientDecryptExponentB64u: string;
  }
>();

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

function nextKeyHandle(): string {
  keyHandleCounter += 1;
  return `${secureRandomId('shamir3pass-key', 32, 'Shamir 3-pass key handles')}-${keyHandleCounter}`;
}

function requireKeyHandle(value: unknown): string {
  return asNonEmptyString(value, 'keyHandle');
}

function getStoredKeypair(keyHandleRaw: unknown): {
  shamirPrimeB64u: string;
  clientEncryptExponentB64u: string;
  clientDecryptExponentB64u: string;
} {
  const keyHandle = requireKeyHandle(keyHandleRaw);
  const stored = keypairsByHandle.get(keyHandle);
  if (!stored) {
    throw new Error('Unknown Shamir3Pass key handle');
  }
  return stored;
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
      case 'createClientKeyHandle': {
        const shamirPrimeB64u = asNonEmptyString(msg.payload.shamirPrimeB64u, 'shamirPrimeB64u');
        const result = shamir3pass_generate_client_lock_keys(shamirPrimeB64u) as {
          shamirPrimeB64u: string;
          clientEncryptExponentB64u: string;
          clientDecryptExponentB64u: string;
        };
        const keyHandle = nextKeyHandle();
        keypairsByHandle.set(keyHandle, {
          shamirPrimeB64u: asNonEmptyString(result.shamirPrimeB64u, 'shamirPrimeB64u'),
          clientEncryptExponentB64u: asNonEmptyString(
            result.clientEncryptExponentB64u,
            'clientEncryptExponentB64u',
          ),
          clientDecryptExponentB64u: asNonEmptyString(
            result.clientDecryptExponentB64u,
            'clientDecryptExponentB64u',
          ),
        });
        postToMainThread({ id: msg.id, ok: true, result: { keyHandle } });
        return;
      }
      case 'destroyClientKeyHandle': {
        const keyHandle = requireKeyHandle(msg.payload.keyHandle);
        keypairsByHandle.delete(keyHandle);
        postToMainThread({ id: msg.id, ok: true, result: true });
        return;
      }
      case 'addClientSealWithKeyHandle': {
        const stored = getStoredKeypair(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const result = shamir3pass_add_lock(
          ciphertextB64u,
          stored.clientEncryptExponentB64u,
          stored.shamirPrimeB64u,
        );
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'addClientSealBytesWithKeyHandle': {
        const stored = getStoredKeypair(msg.payload.keyHandle);
        const ciphertext = asBytes(msg.payload.ciphertext, 'ciphertext');
        try {
          const result = shamir3pass_add_lock_bytes(
            ciphertext,
            stored.clientEncryptExponentB64u,
            stored.shamirPrimeB64u,
          );
          postToMainThread({ id: msg.id, ok: true, result });
        } finally {
          ciphertext.fill(0);
        }
        return;
      }
      case 'removeClientSealWithKeyHandle': {
        const stored = getStoredKeypair(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const result = shamir3pass_remove_lock(
          ciphertextB64u,
          stored.clientDecryptExponentB64u,
          stored.shamirPrimeB64u,
        );
        postToMainThread({ id: msg.id, ok: true, result });
        return;
      }
      case 'removeClientSealWithKeyHandleToBytes': {
        const stored = getStoredKeypair(msg.payload.keyHandle);
        const ciphertextB64u = asNonEmptyString(msg.payload.ciphertextB64u, 'ciphertextB64u');
        const out = shamir3pass_remove_lock_to_bytes(
          ciphertextB64u,
          stored.clientDecryptExponentB64u,
          stored.shamirPrimeB64u,
        );
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
