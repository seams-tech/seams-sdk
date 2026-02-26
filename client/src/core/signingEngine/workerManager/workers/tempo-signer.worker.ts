import init, {
  compute_tempo_sender_hash,
  encode_tempo_signed_tx,
  init_tempo_signer,
} from '../../../../../../wasm/tempo_signer/pkg/tempo_signer.js';
import { initializeWasm, resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { errorMessage } from '@shared/utils/errors';
import { WorkerControlMessage } from '../workerTypes';

type TempoSignerWorkerRequest =
  | { id: string; type: 'computeTempoSenderHash'; payload: { tx: unknown } }
  | {
      id: string;
      type: 'encodeTempoSignedTx';
      payload: { tx: unknown; senderSignature: unknown };
    };

type WorkerErrorPayload = {
  message: string;
  code?: string;
  coreCode?: string;
};

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
    const coreCode =
      typeof (err as { coreCode?: unknown }).coreCode === 'string'
        ? String((err as { coreCode?: string }).coreCode).trim()
        : '';
    return {
      message: message || errorMessage(err),
      ...(code ? { code } : {}),
      ...(coreCode ? { coreCode } : {}),
    };
  }
  return { message: errorMessage(err) };
}

function toU8(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset, v.byteLength);
  throw new Error('expected bytes');
}

function postToMainThread(message: unknown, transfer?: Transferable[]): void {
  const workerSelf = self as unknown as {
    postMessage: (message: unknown, transfer?: Transferable[]) => void;
  };
  if (transfer && transfer.length > 0) {
    workerSelf.postMessage(message, transfer);
    return;
  }
  workerSelf.postMessage(message);
}

const wasmUrl = resolveWasmUrl('tempo_signer.wasm', 'Tempo Signer');
let wasmInitPromise: Promise<void> | null = null;

async function ensureWasm(): Promise<void> {
  if (wasmInitPromise) return wasmInitPromise;
  wasmInitPromise = (async () => {
    await initializeWasm({
      workerName: 'Tempo Signer',
      wasmUrl,
      initFunction: init as unknown as (wasmModule?: unknown) => Promise<void>,
      validateFunction: () => init_tempo_signer(),
    });
  })();
  return wasmInitPromise;
}

setTimeout(() => {
  postToMainThread({ type: WorkerControlMessage.WORKER_READY, ready: true });
}, 0);

self.addEventListener('message', async (event: MessageEvent) => {
  const msg = event.data as TempoSignerWorkerRequest;
  if (!msg?.id || !msg?.type) return;

  try {
    await ensureWasm();
    switch (msg.type) {
      case 'computeTempoSenderHash': {
        const out = compute_tempo_sender_hash(msg.payload.tx) as Uint8Array;
        const ab = out.slice().buffer;
        postToMainThread({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
      case 'encodeTempoSignedTx': {
        const out = encode_tempo_signed_tx(
          msg.payload.tx,
          toU8(msg.payload.senderSignature),
        ) as Uint8Array;
        const ab = out.slice().buffer;
        postToMainThread({ id: msg.id, ok: true, result: ab }, [ab]);
        return;
      }
      default: {
        throw new Error(
          `Unsupported tempoSigner worker operation type: ${String((msg as { type?: unknown }).type)}`,
        );
      }
    }
  } catch (e) {
    const err = asWorkerErrorPayload(e);
    postToMainThread({
      id: msg.id,
      ok: false,
      error: err.message,
      ...(err.code ? { code: err.code } : {}),
      ...(err.coreCode ? { coreCode: err.coreCode } : {}),
    });
  }
});
