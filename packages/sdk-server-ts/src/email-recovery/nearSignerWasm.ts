import initSignerWasm, {
  email_recovery_chacha20poly1305_decrypt,
  email_recovery_chacha20poly1305_encrypt,
  email_recovery_hkdf_sha256_32,
  email_recovery_sha256,
  email_recovery_x25519_public_key_from_secret,
  email_recovery_x25519_shared_secret,
  init_worker,
} from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import type { InitInput } from '../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

const SIGNER_WASM_PATH_CANDIDATES = [
  '../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
  '../../../../wasm/near_signer/pkg/wasm_signer_worker_bg.wasm',
];

let signerWasmInitPromise: Promise<void> | null = null;
let signerWasmReady = false;
const capturedFetch =
  typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null;

function isNodeEnvironment(): boolean {
  const processObj = (globalThis as unknown as { process?: { versions?: { node?: string } } })
    .process;
  const isNode = Boolean(processObj?.versions?.node);
  const webSocketPair = (globalThis as unknown as { WebSocketPair?: unknown }).WebSocketPair;
  const nav = (globalThis as unknown as { navigator?: { userAgent?: unknown } }).navigator;
  const isCloudflareWorker =
    typeof webSocketPair !== 'undefined' ||
    (typeof nav?.userAgent === 'string' && nav.userAgent.includes('Cloudflare-Workers'));
  return isNode && !isCloudflareWorker;
}

function getSignerWasmUrls(): URL[] {
  const baseUrl = import.meta.url;
  const resolved: URL[] = [];
  for (const path of SIGNER_WASM_PATH_CANDIDATES) {
    try {
      resolved.push(new URL(path, baseUrl));
    } catch {
      // ignore invalid URL candidate
    }
  }
  return resolved;
}

async function initSignerFromCompiledModule(module: WebAssembly.Module): Promise<void> {
  await initSignerWasm({ module_or_path: module as unknown as InitInput });
  init_worker();
  signerWasmReady = true;
}

async function compileWasmFromUrl(url: URL): Promise<WebAssembly.Module> {
  const fetchFn =
    capturedFetch ??
    (typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : null);
  if (!fetchFn) {
    throw new Error('[email-recovery] fetch is not available to load signer WASM');
  }
  const response = await fetchFn(url.toString());
  if (!response || typeof (response as any).arrayBuffer !== 'function') {
    throw new Error('[email-recovery] signer WASM fetch returned a non-Response object');
  }
  const status = typeof (response as any).status === 'number' ? (response as any).status : 0;
  const ok =
    typeof (response as any).ok === 'boolean'
      ? (response as any).ok
      : status === 0 || (status >= 200 && status < 300);
  if (!ok) {
    throw new Error(`[email-recovery] signer WASM fetch failed with status ${status}`);
  }
  const bytes = await response.arrayBuffer();
  return WebAssembly.compile(bytes);
}

export async function ensureEmailRecoverySignerWasm(): Promise<void> {
  if (signerWasmInitPromise) return signerWasmInitPromise;
  signerWasmInitPromise = (async () => {
    const urls = getSignerWasmUrls();
    if (isNodeEnvironment()) {
      const { fileURLToPath } = await import('node:url');
      const { readFile } = await import('node:fs/promises');
      for (const url of urls) {
        try {
          const filePath = fileURLToPath(url);
          const bytes = await readFile(filePath);
          const ab = new ArrayBuffer(bytes.byteLength);
          new Uint8Array(ab).set(bytes);
          const module = await WebAssembly.compile(ab);
          await initSignerFromCompiledModule(module);
          return;
        } catch {
          // try next candidate
        }
      }
      throw new Error(
        '[email-recovery] Failed to initialize signer WASM from filesystem candidates',
      );
    }

    let lastErr: unknown = null;
    for (const url of urls) {
      try {
        const module = await compileWasmFromUrl(url);
        await initSignerFromCompiledModule(module);
        return;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error
      ? lastErr
      : new Error(String(lastErr || 'Failed to initialize signer WASM'));
  })();
  return signerWasmInitPromise;
}

function requireReady(): void {
  if (!signerWasmReady) {
    throw new Error('[email-recovery] signer WASM is not initialized');
  }
}

function checkedBytes(label: string, value: Uint8Array, expectedLength: number): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} must return Uint8Array`);
  }
  if (value.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes (got ${value.length})`);
  }
  return value;
}

export async function x25519PublicKeyFromSecret(secretKey32: Uint8Array): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_x25519_public_key_from_secret(secretKey32) as Uint8Array;
  return checkedBytes('email_recovery_x25519_public_key_from_secret', out, 32);
}

export async function x25519SharedSecret(input: {
  secretKey32: Uint8Array;
  peerPublicKey32: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_x25519_shared_secret(
    input.secretKey32,
    input.peerPublicKey32,
  ) as Uint8Array;
  return checkedBytes('email_recovery_x25519_shared_secret', out, 32);
}

export async function hkdfSha25632(input: {
  ikm: Uint8Array;
  info: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_hkdf_sha256_32(input.ikm, input.info) as Uint8Array;
  return checkedBytes('email_recovery_hkdf_sha256_32', out, 32);
}

export async function chacha20poly1305Encrypt(input: {
  key32: Uint8Array;
  nonce12: Uint8Array;
  aad: Uint8Array;
  plaintext: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_chacha20poly1305_encrypt(
    input.key32,
    input.nonce12,
    input.aad,
    input.plaintext,
  ) as Uint8Array;
  if (!(out instanceof Uint8Array) || out.length === 0) {
    throw new Error('email_recovery_chacha20poly1305_encrypt returned empty ciphertext');
  }
  return out;
}

export async function chacha20poly1305Decrypt(input: {
  key32: Uint8Array;
  nonce12: Uint8Array;
  aad: Uint8Array;
  ciphertext: Uint8Array;
}): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  const out = email_recovery_chacha20poly1305_decrypt(
    input.key32,
    input.nonce12,
    input.aad,
    input.ciphertext,
  ) as Uint8Array;
  if (!(out instanceof Uint8Array)) {
    throw new Error('email_recovery_chacha20poly1305_decrypt must return Uint8Array');
  }
  return out;
}

export async function sha256Bytes(input: Uint8Array): Promise<Uint8Array> {
  await ensureEmailRecoverySignerWasm();
  requireReady();
  const out = email_recovery_sha256(input) as Uint8Array;
  return checkedBytes('email_recovery_sha256', out, 32);
}
