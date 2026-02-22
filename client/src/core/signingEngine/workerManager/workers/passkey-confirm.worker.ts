/**
 * UserConfirm Web Worker
 *
 * Hosts the UserConfirm handshake runtime (`awaitUserConfirmationV2`) and the
 * threshold PRF.first warm-session cache.
 */
import { toAccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ExportKeypairChain,
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import {
  WorkerRequestType,
  WorkerResponseType,
} from '@/core/types/signer-worker';
import { bytesToHex } from '../../chainAdaptors/evm/bytes';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/base64';
import {
  awaitUserConfirmationV2,
} from '../../touchConfirm/awaitUserConfirmation';
import {
  UserConfirmationType,
  UserConfirmMessageType,
  type ExportPrivateKeyDisplayEntry,
  type UserConfirmRequest,
  type UserConfirmDecision,
} from '../../touchConfirm/shared/confirmTypes';
import initNearSigner, {
  handle_signer_message,
} from '../../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';
import initEthSigner, {
  derive_secp256k1_keypair_from_prf_second,
  init_eth_signer,
} from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';

// Expose the confirmation bridge under the JS name expected by wasm-bindgen.
// awaitUserConfirmationV2 expects a UserConfirmRequest object.
type UserConfirmWorkerGlobal = typeof globalThis & {
  awaitUserConfirmationV2?: typeof awaitUserConfirmationV2;
};
(globalThis as UserConfirmWorkerGlobal).awaitUserConfirmationV2 = awaitUserConfirmationV2;

type ThresholdPrfFirstCacheEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };

const prfFirstSessionCache = new Map<string, ThresholdPrfFirstCacheEntry>();
const nearSignerWasmUrl = resolveWasmUrl('wasm_signer_worker_bg.wasm', 'Signer Worker');
const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'Eth Signer');

let nearSignerWasmInitPromise: Promise<void> | null = null;
let ethSignerWasmInitPromise: Promise<void> | null = null;

type UserConfirmWorkerIncomingMessage = {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
};

function asIncomingMessage(value: unknown): UserConfirmWorkerIncomingMessage {
  if (!value || typeof value !== 'object') return {};
  return value as UserConfirmWorkerIncomingMessage;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
}

function nowMs(): number {
  return Date.now();
}

function normalizeSessionId(input: unknown): string {
  return typeof input === 'string' ? input.trim() : '';
}

function normalizeB64u(input: unknown): string {
  return typeof input === 'string' ? input.trim() : '';
}

function toSessionId(prefix: string): string {
  const value = String(prefix || '').trim() || 'session';
  return `${value}:${Date.now()}:${Math.floor(Math.random() * 1_000_000)}`;
}

function isCancellationLikeError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  const lowered = message.toLowerCase();
  return lowered.includes('notallowederror')
    || lowered.includes('aborterror')
    || lowered.includes('user cancelled')
    || lowered.includes('user canceled')
    || lowered.includes('user aborted')
    || lowered.includes('rejected');
}

function coerceTheme(value: unknown): 'dark' | 'light' | undefined {
  return value === 'dark' || value === 'light' ? value : undefined;
}

function coerceVariant(value: unknown): 'drawer' | 'modal' | undefined {
  return value === 'drawer' || value === 'modal' ? value : undefined;
}

function coerceExportChain(value: unknown): ExportKeypairChain | null {
  if (value === 'near' || value === 'evm' || value === 'tempo') return value;
  return null;
}

function schemeForExportChain(chain: ExportKeypairChain): 'ed25519' | 'secp256k1' {
  return chain === 'near' ? 'ed25519' : 'secp256k1';
}

function secp256k1LabelForExportChain(chain: ExportKeypairChain): string {
  return chain === 'tempo' ? 'Tempo secp256k1' : 'EVM secp256k1';
}

function parseExportLocalKeyMaterial(
  value: unknown,
): ExportPrivateKeysWithUiWorkerPayload['localKeyMaterial'] | undefined {
  const material = asRecord(value);
  if (!material) return undefined;
  const encryptedSk = normalizeB64u(material.encryptedSk);
  const chacha20NonceB64u = normalizeB64u(material.chacha20NonceB64u);
  const wrapKeySalt = normalizeB64u(material.wrapKeySalt);
  if (!encryptedSk || !chacha20NonceB64u || !wrapKeySalt) return undefined;
  return {
    encryptedSk,
    chacha20NonceB64u,
    wrapKeySalt,
    ...(typeof material.publicKey === 'string' && material.publicKey.trim()
      ? { publicKey: material.publicKey.trim() }
      : {}),
  };
}

function parseExportRequestPayload(value: unknown): ExportPrivateKeysWithUiWorkerPayload | null {
  const payload = asRecord(value);
  if (!payload) return null;
  const nearAccountId = normalizeSessionId(payload.nearAccountId);
  const deviceNumber = Math.floor(Number(payload.deviceNumber));
  const chain = coerceExportChain(payload.chain);
  if (!nearAccountId || !Number.isFinite(deviceNumber) || deviceNumber < 1) return null;
  if (!chain) return null;
  const localKeyMaterial = parseExportLocalKeyMaterial(payload.localKeyMaterial);
  const hasThresholdKeyMaterial = payload.hasThresholdKeyMaterial === true;
  if (!localKeyMaterial && !hasThresholdKeyMaterial) return null;
  return {
    nearAccountId,
    deviceNumber,
    chain,
    hasThresholdKeyMaterial,
    localKeyMaterial,
    variant: coerceVariant(payload.variant),
    theme: coerceTheme(payload.theme),
    ...(typeof payload.publicKeyHint === 'string' && payload.publicKeyHint.trim()
      ? { publicKeyHint: payload.publicKeyHint.trim() }
      : {}),
  };
}

function randomWrapKeySaltB64u(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64UrlEncode(bytes);
}

function extractPayloadError(payload: unknown): string {
  const record = asRecord(payload);
  if (!record) return '';
  return typeof record.error === 'string' ? record.error : '';
}

function requirePrfB64uFromCredential(
  credential: WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const results = asRecord((credential as unknown as { clientExtensionResults?: unknown }).clientExtensionResults);
  const prf = asRecord(results?.prf);
  const prfResults = asRecord(prf?.results);
  const value = normalizeB64u(prfResults?.[output]);
  if (!value) {
    throw new Error(`Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`);
  }
  return value;
}

async function ensureNearSignerWasmReady(): Promise<void> {
  if (nearSignerWasmInitPromise) return nearSignerWasmInitPromise;
  nearSignerWasmInitPromise = (async () => {
    try {
      await initNearSigner({ module_or_path: nearSignerWasmUrl });
    } catch (error: unknown) {
      nearSignerWasmInitPromise = null;
      throw error;
    }
  })();
  return nearSignerWasmInitPromise;
}

async function ensureEthSignerWasmReady(): Promise<void> {
  if (ethSignerWasmInitPromise) return ethSignerWasmInitPromise;
  ethSignerWasmInitPromise = (async () => {
    try {
      await initEthSigner({ module_or_path: ethSignerWasmUrl });
      init_eth_signer();
    } catch (error: unknown) {
      ethSignerWasmInitPromise = null;
      throw error;
    }
  })();
  return ethSignerWasmInitPromise;
}

async function callNearSignerWorkerMessage(args: {
  type: WorkerRequestType;
  payload: Record<string, unknown>;
}): Promise<{ responseType: number; payload: unknown }> {
  await ensureNearSignerWasmReady();
  const response = await handle_signer_message({
    type: args.type,
    payload: args.payload,
  });
  const parsed = asRecord(response);
  const responseType = Number(parsed?.type);
  if (!Number.isFinite(responseType)) {
    throw new Error('Invalid near signer worker response type');
  }
  return { responseType, payload: parsed?.payload };
}

async function decryptPrivateKeyWithPrfInWorker(args: {
  nearAccountId: string;
  sessionId: string;
  encryptedPrivateKeyData: string;
  encryptedPrivateKeyChacha20NonceB64u: string;
  prfFirstB64u: string;
  wrapKeySalt: string;
}): Promise<{ privateKey: string; nearAccountId: string }> {
  const response = await callNearSignerWorkerMessage({
    type: WorkerRequestType.DecryptPrivateKeyWithPrf,
    payload: {
      nearAccountId: args.nearAccountId,
      encryptedPrivateKeyData: args.encryptedPrivateKeyData,
      encryptedPrivateKeyChacha20NonceB64u: args.encryptedPrivateKeyChacha20NonceB64u,
      prfFirstB64u: args.prfFirstB64u,
      wrapKeySalt: args.wrapKeySalt,
      sessionId: args.sessionId,
    },
  });
  if (response.responseType !== WorkerResponseType.DecryptPrivateKeyWithPrfSuccess) {
    const payloadError = extractPayloadError(response.payload);
    throw new Error(payloadError || 'Private key decryption failed');
  }
  const payload = asRecord(response.payload);
  const privateKey = typeof payload?.privateKey === 'string' ? payload.privateKey.trim() : '';
  const nearAccountId = typeof payload?.nearAccountId === 'string' ? payload.nearAccountId.trim() : '';
  if (!privateKey || !nearAccountId) {
    throw new Error('Private key decryption failed: invalid response payload');
  }
  return { privateKey, nearAccountId };
}

async function recoverKeypairFromPasskeyInWorker(args: {
  credential: WebAuthnAuthenticationCredential;
  accountIdHint: string;
  sessionId: string;
  prfFirstB64u: string;
  prfSecondB64u: string;
}): Promise<{
  publicKey: string;
  encryptedPrivateKey: string;
  chacha20NonceB64u: string;
  wrapKeySalt: string;
}> {
  const wrapKeySalt = randomWrapKeySaltB64u();
  const response = await callNearSignerWorkerMessage({
    type: WorkerRequestType.RecoverKeypairFromPasskey,
    payload: {
      credential: args.credential,
      accountIdHint: args.accountIdHint,
      prfFirstB64u: args.prfFirstB64u,
      prfSecondB64u: args.prfSecondB64u,
      wrapKeySalt,
      sessionId: args.sessionId,
    },
  });
  if (response.responseType !== WorkerResponseType.RecoverKeypairFromPasskeySuccess) {
    const payloadError = extractPayloadError(response.payload);
    throw new Error(payloadError || 'Keypair recovery failed');
  }
  const payload = asRecord(response.payload);
  const publicKey = typeof payload?.publicKey === 'string' ? payload.publicKey.trim() : '';
  const encryptedPrivateKey =
    typeof payload?.encryptedData === 'string' ? payload.encryptedData.trim() : '';
  const chacha20NonceB64u =
    typeof payload?.chacha20NonceB64u === 'string' ? payload.chacha20NonceB64u.trim() : '';
  const recoveredWrapKeySalt =
    typeof payload?.wrapKeySalt === 'string' ? payload.wrapKeySalt.trim() : '';
  if (!publicKey || !encryptedPrivateKey || !chacha20NonceB64u || !recoveredWrapKeySalt) {
    throw new Error('Keypair recovery failed: invalid response payload');
  }
  return {
    publicKey,
    encryptedPrivateKey,
    chacha20NonceB64u,
    wrapKeySalt: recoveredWrapKeySalt,
  };
}

async function deriveSecp256k1FromPrfSecondInWorker(args: {
  prfSecondB64u: string;
  nearAccountId: string;
}): Promise<{ privateKeyHex: string; publicKeyHex: string; ethereumAddress: string }> {
  await ensureEthSignerWasmReady();
  const prfSecond = base64UrlDecode(args.prfSecondB64u);
  try {
    const out = derive_secp256k1_keypair_from_prf_second(prfSecond, args.nearAccountId);
    if (out.length !== 85) {
      throw new Error(`derive_secp256k1_keypair_from_prf_second must return 85 bytes (got ${out.length})`);
    }
    const privateKey32 = out.slice(0, 32);
    const publicKey33 = out.slice(32, 65);
    const ethereumAddress20 = out.slice(65, 85);
    return {
      privateKeyHex: bytesToHex(privateKey32),
      publicKeyHex: bytesToHex(publicKey33),
      ethereumAddress: bytesToHex(ethereumAddress20),
    };
  } finally {
    prfSecond.fill(0);
  }
}

async function runExportPrivateKeysWithUi(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): Promise<ExportPrivateKeysWithUiWorkerResult> {
  // Worker-owned export flow boundary:
  // only this runtime initiates export confirmations via awaitUserConfirmationV2.
  const nearAccountId = toAccountId(payload.nearAccountId);
  const exportChain = coerceExportChain(payload.chain);
  if (!exportChain) throw new Error('Invalid export chain');
  const exportScheme = schemeForExportChain(exportChain);

  const localKeyMaterial = payload.localKeyMaterial;
  if (!localKeyMaterial && !payload.hasThresholdKeyMaterial) {
    throw new Error(`No key material found for account ${nearAccountId} device ${payload.deviceNumber}`);
  }

  const publicKeyHint = String(
    payload.publicKeyHint
    || localKeyMaterial?.publicKey
    || '',
  ).trim();
  const requestId = toSessionId('export-keys');
  const intentDigest = `export-keys:${nearAccountId}:${payload.deviceNumber}`;

  let prfFirstB64u = '';
  let prfSecondB64u = '';
  const exportKeys: ExportPrivateKeyDisplayEntry[] = [];
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: 'Export Private Key',
        accountId: nearAccountId,
        publicKey: publicKeyHint || '(derived from passkey)',
        warning: 'Authenticate with your passkey to prepare export keys.',
      },
      payload: {
        nearAccountId,
        publicKey: publicKeyHint,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!decision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: nearAccountId,
        exportedSchemes: [],
        error: decision.error || 'User cancelled export request',
      };
    }
    const credential = decision.credential as WebAuthnAuthenticationCredential | undefined;
    if (!credential) {
      throw new Error('Missing WebAuthn credential for export request');
    }

    prfFirstB64u = requirePrfB64uFromCredential(credential, 'first');
    if (exportScheme === 'secp256k1' || !localKeyMaterial) {
      prfSecondB64u = requirePrfB64uFromCredential(credential, 'second');
    }

    if (exportScheme === 'ed25519') {
      if (localKeyMaterial) {
        const decrypted = await decryptPrivateKeyWithPrfInWorker({
          nearAccountId,
          sessionId: `${requestId}:ed25519`,
          encryptedPrivateKeyData: localKeyMaterial.encryptedSk,
          encryptedPrivateKeyChacha20NonceB64u: localKeyMaterial.chacha20NonceB64u,
          prfFirstB64u,
          wrapKeySalt: localKeyMaterial.wrapKeySalt,
        });
        exportKeys.push({
          scheme: 'ed25519',
          label: 'NEAR Ed25519',
          publicKey: String(localKeyMaterial.publicKey || publicKeyHint || '').trim(),
          privateKey: decrypted.privateKey,
        });
      } else {
        const recovered = await recoverKeypairFromPasskeyInWorker({
          credential,
          accountIdHint: nearAccountId,
          sessionId: `${requestId}:recover`,
          prfFirstB64u,
          prfSecondB64u,
        });
        const decrypted = await decryptPrivateKeyWithPrfInWorker({
          nearAccountId,
          sessionId: `${requestId}:recover-decrypt`,
          encryptedPrivateKeyData: recovered.encryptedPrivateKey,
          encryptedPrivateKeyChacha20NonceB64u: recovered.chacha20NonceB64u,
          prfFirstB64u,
          wrapKeySalt: recovered.wrapKeySalt,
        });
        exportKeys.push({
          scheme: 'ed25519',
          label: 'NEAR Ed25519',
          publicKey: recovered.publicKey,
          privateKey: decrypted.privateKey,
        });
      }
    }

    if (exportScheme === 'secp256k1') {
      const derived = await deriveSecp256k1FromPrfSecondInWorker({
        prfSecondB64u,
        nearAccountId,
      });
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportChain(exportChain),
        publicKey: derived.publicKeyHex,
        privateKey: derived.privateKeyHex,
        address: derived.ethereumAddress,
      });
    }

    if (!exportKeys.length) {
      throw new Error('No exportable keys were produced');
    }

    const first = exportKeys[0]!;
    const showDecision = await awaitUserConfirmationV2({
      requestId: `${requestId}-show`,
      type: UserConfirmationType.SHOW_SECURE_PRIVATE_KEY_UI,
      summary: {
        operation: 'Export Private Key',
        accountId: nearAccountId,
        publicKey: first.publicKey,
        warning: 'Anyone with your private key can fully control your account. Never share it.',
      },
      payload: {
        nearAccountId,
        publicKey: first.publicKey,
        privateKey: first.privateKey,
        keys: exportKeys,
        variant: payload.variant,
        theme: payload.theme,
      },
      intentDigest,
    } satisfies UserConfirmRequest);

    if (!showDecision.confirmed) {
      return {
        ok: false,
        cancelled: true,
        accountId: nearAccountId,
        exportedSchemes: [],
        error: showDecision.error || 'User cancelled export viewer',
      };
    }

    return {
      ok: true,
      accountId: nearAccountId,
      exportedSchemes: exportKeys.map((entry) => entry.scheme),
    };
  } catch (error: unknown) {
    if (isCancellationLikeError(error)) {
      return {
        ok: false,
        cancelled: true,
        accountId: nearAccountId,
        exportedSchemes: [],
        error: error instanceof Error ? error.message : String(error || 'User cancelled export request'),
      };
    }
    throw error;
  } finally {
    prfFirstB64u = '';
    prfSecondB64u = '';
    for (const key of exportKeys) {
      key.privateKey = '';
    }
    exportKeys.length = 0;
  }
}

function peekPrfFirstEntry(sessionId: string): OkResult | ErrResult {
  if (!sessionId) return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) return { ok: false, code: 'not_found', message: 'PRF.first not cached for threshold session' };
  if (nowMs() >= entry.expiresAtMs) {
    prfFirstSessionCache.delete(sessionId);
    return { ok: false, code: 'expired', message: 'PRF.first cache expired for threshold session' };
  }
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
    return { ok: false, code: 'exhausted', message: 'PRF.first cache exhausted for threshold session' };
  }
  return { ok: true, remainingUses: entry.remainingUses, expiresAtMs: entry.expiresAtMs };
}

function dispensePrfFirstEntry(sessionId: string, uses: number): OkDispenseResult | ErrResult {
  const peek = peekPrfFirstEntry(sessionId);
  if (!peek.ok) return peek;
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) return { ok: false, code: 'not_found', message: 'PRF.first not cached for threshold session' };
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return { ok: false, code: 'exhausted', message: 'PRF.first cache exhausted for threshold session' };
  }
  entry.remainingUses -= usesNeeded;
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
  } else {
    prfFirstSessionCache.set(sessionId, entry);
  }
  return { ok: true, prfFirstB64u: entry.prfFirstB64u, remainingUses: entry.remainingUses, expiresAtMs: entry.expiresAtMs };
}

function postUserConfirmWorkerResponse(id: unknown, payload: { success: boolean; data?: unknown; error?: string }): void {
  const response = {
    ...(typeof id === 'string' && id.trim() ? { id: id.trim() } : {}),
    success: !!payload.success,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    ...(payload.error ? { error: payload.error } : {}),
  };
  try { self.postMessage(response); } catch {}
}

function toDecisionFromWorkerResponse(response: Awaited<ReturnType<typeof awaitUserConfirmationV2>>): UserConfirmDecision {
  return {
    requestId: String(response.request_id || '').trim(),
    intentDigest: response.intent_digest,
    confirmed: !!response.confirmed,
    credential: response.credential,
    transactionContext: response.transaction_context,
    error: response.error,
  };
}

// This worker intentionally ignores USER_PASSKEY_CONFIRM_RESPONSE at the
// `onmessage` level so awaitUserConfirmationV2's listener can consume it.
self.onmessage = (event: MessageEvent) => {
  const incoming = asIncomingMessage(event.data);
  const eventType = incoming.type;
  if (eventType === UserConfirmMessageType.USER_PASSKEY_CONFIRM_RESPONSE) return;

  const id = incoming.id;

  // Health check / liveness
  if (eventType === 'PING') {
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'SECURE_CONFIRM_REQUEST') {
    void (async () => {
      try {
        const payload = asRecord(incoming.payload);
        const requestInput = payload?.request;
        if (!requestInput || typeof requestInput !== 'object') {
          postUserConfirmWorkerResponse(id, {
            success: false,
            error: 'Invalid SECURE_CONFIRM_REQUEST payload: missing request object',
          });
          return;
        }
        const workerResponse = await awaitUserConfirmationV2(requestInput as UserConfirmRequest);
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: toDecisionFromWorkerResponse(workerResponse),
        });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        postUserConfirmWorkerResponse(id, { success: false, error: msg });
      }
    })();
    return;
  }

  if (eventType === 'EXPORT_PRIVATE_KEYS_WITH_UI') {
    void (async () => {
      try {
        const payload = parseExportRequestPayload(incoming.payload);
        if (!payload) {
          postUserConfirmWorkerResponse(id, {
            success: false,
            error: 'Invalid EXPORT_PRIVATE_KEYS_WITH_UI payload',
          });
          return;
        }
        const result = await runExportPrivateKeysWithUi(payload);
        postUserConfirmWorkerResponse(id, { success: true, data: result });
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        postUserConfirmWorkerResponse(id, { success: false, error: msg });
      }
    })();
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_PUT') {
    try {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeSessionId(payload?.sessionId);
      const prfFirstB64u = normalizeB64u(payload?.prfFirstB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      if (!sessionId || !prfFirstB64u) {
        postUserConfirmWorkerResponse(id, { success: true, data: { ok: false, code: 'invalid_args', message: 'Missing sessionId or prfFirstB64u' } satisfies ErrResult });
        return;
      }
      if (expiresAtMs <= nowMs() || remainingUses <= 0) {
        postUserConfirmWorkerResponse(id, { success: true, data: { ok: false, code: 'invalid_args', message: 'Invalid expiresAtMs or remainingUses' } satisfies ErrResult });
        return;
      }
      prfFirstSessionCache.set(sessionId, { prfFirstB64u, expiresAtMs, remainingUses });
      postUserConfirmWorkerResponse(id, { success: true, data: { ok: true, remainingUses, expiresAtMs } satisfies OkResult });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      postUserConfirmWorkerResponse(id, { success: false, error: msg });
    }
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_PEEK') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeSessionId(payload?.sessionId);
    postUserConfirmWorkerResponse(id, { success: true, data: peekPrfFirstEntry(sessionId) });
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_DISPENSE') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeSessionId(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postUserConfirmWorkerResponse(id, { success: true, data: dispensePrfFirstEntry(sessionId, uses) });
    return;
  }

  if (eventType === 'THRESHOLD_PRF_FIRST_CACHE_CLEAR') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeSessionId(payload?.sessionId);
    if (sessionId) prfFirstSessionCache.delete(sessionId);
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  // Unknown message types: respond with an explicit error (prevents sendMessage timeouts).
  if (typeof id === 'string' && id.trim()) {
    postUserConfirmWorkerResponse(id, { success: false, error: `Unsupported UserConfirm worker message type: ${String(eventType)}` });
  }
};

// === GLOBAL ERROR MONITORING ===

self.onerror = (error) => {
  console.error('[secure-confirm-worker] error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[secure-confirm-worker] Unhandled promise rejection:', event.reason);
  event.preventDefault();
};
