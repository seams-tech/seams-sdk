/**
 * UserConfirm Web Worker
 *
 * Hosts the UserConfirm handshake runtime (`awaitUserConfirmationV2`) and the
 * threshold warm-session material cache.
 */
import { toAccountId } from '@/core/types/accountIds';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import type {
  ExportKeypairChain,
  ExportPrivateKeysWithUiWorkerPayload,
  ExportPrivateKeysWithUiWorkerResult,
} from '@/core/types/secure-confirm-worker';
import { bytesToHex } from '../../chainAdaptors/evm/bytes';
import { resolveWasmUrl } from '@/core/walletRuntimePaths/wasm-loader';
import { base64UrlDecode } from '@shared/utils/base64';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalTrimmedString,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { awaitUserConfirmationV2 } from '../../touchConfirm/awaitUserConfirmation';
import { getShamir3PassRuntime } from './shamir3pass/runtime';
import {
  UserConfirmationType,
  UserConfirmMessageType,
  type ExportPrivateKeyDisplayEntry,
  type UserConfirmRequest,
  type UserConfirmDecision,
} from '../../touchConfirm/shared/confirmTypes';
import initEthSigner, {
  derive_secp256k1_keypair_from_prf_second,
  init_eth_signer,
} from '../../../../../../wasm/eth_signer/pkg/eth_signer.js';
import initHssClientSigner, {
  threshold_ed25519_seed_export_artifact_from_seed,
} from '../../../../../../wasm/hss_client_signer/pkg/hss_client_signer.js';

// Expose the confirmation bridge under the JS name expected by wasm-bindgen.
// awaitUserConfirmationV2 expects a UserConfirmRequest object.
type UserConfirmWorkerGlobal = typeof globalThis & {
  awaitUserConfirmationV2?: typeof awaitUserConfirmationV2;
};
(globalThis as UserConfirmWorkerGlobal).awaitUserConfirmationV2 = awaitUserConfirmationV2;

type WarmSessionMaterialEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkSealResult = OkResult & { sealedSecretB64u: string; keyVersion?: string };
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };

type SigningSessionSealTransport = {
  relayerUrl: string;
  thresholdSessionJwt?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
};

type SigningSessionSealRouteResult =
  | {
      ok: true;
      ciphertext: string;
      keyVersion?: string;
      expiresAtMs?: number;
      remainingUses?: number;
    }
  | ErrResult;

const prfFirstSessionCache = new Map<string, WarmSessionMaterialEntry>();
const signingSessionSealApplyInFlight = new Map<string, Promise<OkSealResult | ErrResult>>();
const signingSessionSealRemoveInFlight = new Map<string, Promise<OkResult | ErrResult>>();
const ethSignerWasmUrl = resolveWasmUrl('eth_signer.wasm', 'Eth Signer');
const hssClientSignerWasmUrl = resolveWasmUrl('hss_client_signer_bg.wasm', 'HSS Client Signer');
const SIGNING_SESSION_SEAL_BASE_PATH = '/threshold/signing-session-seal';
type NearSeedExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { chain: 'near'; artifactKind: 'near-ed25519-seed-v1' }
>;
type EcdsaHssThresholdExportWorkerPayload = Extract<
  ExportPrivateKeysWithUiWorkerPayload,
  { artifactKind: 'ecdsa-hss-secp256k1-key-v1' }
>;

let ethSignerWasmInitPromise: Promise<void> | null = null;
let hssClientSignerInitPromise: Promise<void> | null = null;

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

function overwriteBytes(bytes: Uint8Array | null | undefined): void {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  bytes.fill(0);
}

function toSessionId(prefix: string): string {
  const value = String(prefix || '').trim() || 'session';
  return `${value}:${Date.now()}:${Math.floor(Math.random() * 1_000_000)}`;
}

function isCancellationLikeError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error || '');
  const lowered = message.toLowerCase();
  return (
    lowered.includes('notallowederror') ||
    lowered.includes('aborterror') ||
    lowered.includes('user cancelled') ||
    lowered.includes('user canceled') ||
    lowered.includes('user aborted') ||
    lowered.includes('rejected')
  );
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

function parseExportRequestPayload(value: unknown): ExportPrivateKeysWithUiWorkerPayload | null {
  const payload = asRecord(value);
  if (!payload) return null;
  const nearAccountId = normalizeOptionalTrimmedString(payload.nearAccountId);
  const signerSlot = Math.floor(Number(payload.signerSlot));
  const chain = coerceExportChain(payload.chain);
  const artifactKind = normalizeOptionalNonEmptyString(payload.artifactKind);
  if (!nearAccountId || !Number.isFinite(signerSlot) || signerSlot < 1) return null;
  if (!chain) return null;
  const variant = coerceVariant(payload.variant);
  const theme = coerceTheme(payload.theme);
  if (chain === 'near') {
    const expectedPublicKey = normalizeOptionalNonEmptyString(payload.expectedPublicKey);
    const seedB64u = normalizeOptionalNonEmptyString(payload.seedB64u);
    if (artifactKind === 'near-ed25519-seed-v1') {
      if (!expectedPublicKey || !seedB64u) {
        return null;
      }
      return {
        nearAccountId,
        signerSlot,
        chain: 'near',
        artifactKind,
        expectedPublicKey,
        seedB64u,
        variant,
        theme,
      };
    }
    return null;
  }
  if (artifactKind === 'ecdsa-hss-secp256k1-key-v1') {
    const publicKeyHex = normalizeOptionalNonEmptyString(payload.publicKeyHex);
    const privateKeyHex = normalizeOptionalNonEmptyString(payload.privateKeyHex);
    const ethereumAddress = normalizeOptionalNonEmptyString(payload.ethereumAddress);
    if (!publicKeyHex || !privateKeyHex || !ethereumAddress) {
      return null;
    }
    return {
      nearAccountId,
      signerSlot,
      chain,
      artifactKind,
      publicKeyHex,
      privateKeyHex,
      ethereumAddress,
      variant,
      theme,
    };
  }
  return {
    nearAccountId,
    signerSlot,
    chain,
    variant,
    theme,
  };
}

function requireNearSeedExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): NearSeedExportWorkerPayload {
  if (payload.chain !== 'near' || payload.artifactKind !== 'near-ed25519-seed-v1') {
    throw new Error('Threshold Ed25519 seed export metadata missing or invalid');
  }
  return payload;
}

function requireEcdsaHssThresholdExportPayload(
  payload: ExportPrivateKeysWithUiWorkerPayload,
): EcdsaHssThresholdExportWorkerPayload {
  const artifactKind = 'artifactKind' in payload ? payload.artifactKind : undefined;
  if (
    (payload.chain !== 'evm' && payload.chain !== 'tempo') ||
    artifactKind !== 'ecdsa-hss-secp256k1-key-v1'
  ) {
    throw new Error('ecdsa-hss secp256k1 export artifact metadata missing or invalid');
  }
  return payload as EcdsaHssThresholdExportWorkerPayload;
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = asRecord(value);
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(transport.thresholdSessionJwt);
  const keyVersion = normalizeOptionalNonEmptyString(transport.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(transport.shamirPrimeB64u);
  if (!relayerUrl) return null;
  return {
    relayerUrl,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
  };
}

function parseSigningSessionSealRouteResult(value: unknown): SigningSessionSealRouteResult {
  const result = asRecord(value);
  if (!result || typeof result.ok !== 'boolean') {
    return { ok: false, code: 'invalid_response', message: 'Invalid signing-session seal response' };
  }
  if (!result.ok) {
    return {
      ok: false,
      code: typeof result.code === 'string' ? result.code : 'request_failed',
      message:
        typeof result.message === 'string'
          ? result.message
          : 'Signing-session seal request failed',
    };
  }
  const ciphertext = normalizeOptionalTrimmedString(result.ciphertext);
  const keyVersion = normalizeOptionalNonEmptyString(result.keyVersion);
  const expiresAtMs = normalizePositiveInteger(result.expiresAtMs);
  const remainingUses = normalizeNonNegativeInteger(result.remainingUses);
  if (!ciphertext) {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Missing ciphertext in signing-session seal response',
    };
  }
  return {
    ok: true,
    ciphertext,
    ...(keyVersion ? { keyVersion } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    ...(remainingUses != null ? { remainingUses } : {}),
  };
}

function makeSigningSessionSealSingleFlightKey(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  sessionId: string;
  relayerUrl: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  payloadB64u?: string;
}): string {
  const operation =
    args.operation === 'apply-server-seal' ? 'apply-server-seal' : 'remove-server-seal';
  const sessionId = normalizeOptionalTrimmedString(args.sessionId) || '';
  const relayerUrl = normalizeOptionalTrimmedString(args.relayerUrl) || '';
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion) || '';
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.shamirPrimeB64u) || '';
  const payloadB64u = normalizeOptionalNonEmptyString(args.payloadB64u) || '';
  return `${operation}|${sessionId}|${relayerUrl}|${keyVersion}|${shamirPrimeB64u}|${payloadB64u}`;
}

async function callSigningSessionSealRoute(args: {
  operation: 'apply-server-seal' | 'remove-server-seal';
  transport: SigningSessionSealTransport;
  thresholdSessionId: string;
  ciphertext: string;
  keyVersion?: string;
}): Promise<SigningSessionSealRouteResult> {
  const routePath =
    args.operation === 'apply-server-seal' ? 'apply-server-seal' : 'remove-server-seal';
  const url = joinNormalizedUrl(
    args.transport.relayerUrl,
    `${SIGNING_SESSION_SEAL_BASE_PATH}/${routePath}`,
  );

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const thresholdSessionJwt = normalizeOptionalNonEmptyString(args.transport.thresholdSessionJwt);
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    if (thresholdSessionJwt) {
      headers.Authorization = `Bearer ${thresholdSessionJwt}`;
    }
    const response = await fetch(url, {
      method: 'POST',
      credentials: thresholdSessionJwt ? 'omit' : 'include',
      headers,
      body: JSON.stringify({
        thresholdSessionId: args.thresholdSessionId,
        ciphertext: args.ciphertext,
        ...(keyVersion ? { keyVersion } : {}),
      }),
    });
    const data = await response.json().catch(() => null);
    const parsed = parseSigningSessionSealRouteResult(data);
    if (!response.ok && parsed.ok) {
      return {
        ok: false,
        code: 'http_error',
        message: `Signing-session seal route returned HTTP ${response.status}`,
      };
    }
    if (!parsed.ok) return parsed;
    return parsed;
  } catch (error: unknown) {
    return {
      ok: false,
      code: 'network_error',
      message:
        error instanceof Error
          ? error.message
          : String(error || 'Signing-session seal request failed'),
    };
  }
}

function resolvePolicyFromServerAndLocal(args: {
  localRemainingUses: number;
  localExpiresAtMs: number;
  serverRemainingUses?: number;
  serverExpiresAtMs?: number;
}): OkResult | ErrResult {
  const localRemainingUses = Math.max(0, Math.floor(Number(args.localRemainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.localExpiresAtMs) || 0));
  const serverRemainingUses =
    normalizeNonNegativeInteger(args.serverRemainingUses) ?? localRemainingUses;
  const serverExpiresAtMs = normalizePositiveInteger(args.serverExpiresAtMs) || localExpiresAtMs;
  const remainingUses = Math.min(localRemainingUses, serverRemainingUses);
  const expiresAtMs = Math.min(localExpiresAtMs, serverExpiresAtMs);
  if (remainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (expiresAtMs <= nowMs()) {
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  return { ok: true, remainingUses, expiresAtMs };
}

function requirePrfB64uFromCredential(
  credential: WebAuthnAuthenticationCredential,
  output: 'first' | 'second',
): string {
  const results = asRecord(
    (credential as unknown as { clientExtensionResults?: unknown }).clientExtensionResults,
  );
  const prf = asRecord(results?.prf);
  const prfResults = asRecord(prf?.results);
  const value = normalizeOptionalTrimmedString(prfResults?.[output]);
  if (!value) {
    throw new Error(
      `Missing PRF.${output} output from credential (requires a PRF-enabled passkey)`,
    );
  }
  return value;
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

async function ensureHssClientSignerWasmReady(): Promise<void> {
  if (hssClientSignerInitPromise) return hssClientSignerInitPromise;
  hssClientSignerInitPromise = (async () => {
    try {
      await initHssClientSigner({ module_or_path: hssClientSignerWasmUrl });
    } catch (error: unknown) {
      hssClientSignerInitPromise = null;
      throw error;
    }
  })();
  return hssClientSignerInitPromise;
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
      throw new Error(
        `derive_secp256k1_keypair_from_prf_second must return 85 bytes (got ${out.length})`,
      );
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

async function buildNearEd25519SeedExportArtifactInWorker(args: {
  seedB64u: string;
  expectedPublicKey: string;
}): Promise<{ publicKey: string; privateKey: string }> {
  await ensureHssClientSignerWasmReady();
  const artifact = threshold_ed25519_seed_export_artifact_from_seed({
    seedB64u: args.seedB64u,
    expectedPublicKey: args.expectedPublicKey,
  }) as {
    artifactKind?: unknown;
    publicKey?: unknown;
    privateKey?: unknown;
  } | null;
  const publicKey = String(artifact?.publicKey || '').trim();
  const privateKey = String(artifact?.privateKey || '').trim();
  const artifactKind = String(artifact?.artifactKind || '').trim();
  if (artifactKind !== 'near-ed25519-seed-v1') {
    throw new Error('NEAR seed export artifact builder returned an unexpected artifactKind');
  }
  if (!publicKey || !privateKey) {
    throw new Error('NEAR seed export artifact builder returned an incomplete keypair');
  }
  if (publicKey !== args.expectedPublicKey) {
    throw new Error('NEAR seed export artifact builder returned an unexpected public key');
  }
  return { publicKey, privateKey };
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
  const nearSeedPayload =
    exportScheme === 'ed25519' &&
    payload.chain === 'near' &&
    payload.artifactKind === 'near-ed25519-seed-v1'
      ? requireNearSeedExportPayload(payload)
      : null;
  const ecdsaHssExportPayload =
    exportScheme === 'secp256k1' &&
    (payload.chain === 'evm' || payload.chain === 'tempo') &&
    'artifactKind' in payload &&
    payload.artifactKind === 'ecdsa-hss-secp256k1-key-v1'
      ? requireEcdsaHssThresholdExportPayload(payload)
      : null;
  const exportOperation = 'Export Private Key';
  const exportPublicKey =
    nearSeedPayload?.expectedPublicKey || ecdsaHssExportPayload?.publicKeyHex || '';
  const requestId = toSessionId('export-keys');
  const intentDigest = `export-keys:${nearAccountId}:${payload.signerSlot}`;

  let prfSecondB64u = '';
  const exportKeys: ExportPrivateKeyDisplayEntry[] = [];
  try {
    const decision = await awaitUserConfirmationV2({
      requestId,
      type: UserConfirmationType.DECRYPT_PRIVATE_KEY_WITH_PRF,
      summary: {
        operation: exportOperation,
        accountId: nearAccountId,
        publicKey: exportPublicKey || '(threshold export key)',
        warning:
          exportScheme === 'ed25519'
            ? 'Confirm to reveal your NEAR private key export.'
            : ecdsaHssExportPayload
              ? 'Confirm to reveal your EVM private key export.'
              : 'Authenticate with your passkey to prepare export keys.',
      },
      payload: {
        nearAccountId,
        publicKey: exportPublicKey,
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
    if (exportScheme === 'secp256k1' && !ecdsaHssExportPayload) {
      if (!credential) {
        throw new Error('Export confirmation did not return a WebAuthn authentication credential');
      }
      prfSecondB64u = requirePrfB64uFromCredential(credential, 'second');
    }

    if (exportScheme === 'ed25519') {
      if (!nearSeedPayload) {
        throw new Error('NEAR Ed25519 export now requires a canonical seed export artifact');
      }
      const derived = await buildNearEd25519SeedExportArtifactInWorker({
        seedB64u: nearSeedPayload.seedB64u,
        expectedPublicKey: nearSeedPayload.expectedPublicKey,
      });
      exportKeys.push({
        scheme: 'ed25519',
        label: 'NEAR private key',
        publicKey: derived.publicKey,
        privateKey: derived.privateKey,
      });
    }

    if (exportScheme === 'secp256k1' && ecdsaHssExportPayload) {
      exportKeys.push({
        scheme: 'secp256k1',
        label: secp256k1LabelForExportChain(exportChain),
        publicKey: ecdsaHssExportPayload.publicKeyHex,
        privateKey: ecdsaHssExportPayload.privateKeyHex,
        address: ecdsaHssExportPayload.ethereumAddress,
      });
    }

    if (exportScheme === 'secp256k1' && !ecdsaHssExportPayload) {
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
        operation: exportOperation,
        accountId: nearAccountId,
        publicKey: first.publicKey,
        warning:
          exportScheme === 'ed25519'
            ? 'Anyone with your private key can fully control your account. Never share it.'
            : 'Anyone with your private key can fully control your account. Never share it.',
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
        error:
          error instanceof Error ? error.message : String(error || 'User cancelled export request'),
      };
    }
    throw error;
  } finally {
    prfSecondB64u = '';
    for (const key of exportKeys) {
      key.privateKey = '';
    }
    exportKeys.length = 0;
  }
}

function readWarmSessionClaimEntry(sessionId: string): OkResult | ErrResult {
  if (!sessionId)
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry)
    return { ok: false, code: 'not_found', message: 'Warm-session material is not available for threshold session' };
  if (nowMs() >= entry.expiresAtMs) {
    prfFirstSessionCache.delete(sessionId);
    return { ok: false, code: 'expired', message: 'Warm-session material expired for threshold session' };
  }
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  return { ok: true, remainingUses: entry.remainingUses, expiresAtMs: entry.expiresAtMs };
}

function claimWarmSessionMaterialEntry(sessionId: string, uses: number): OkDispenseResult | ErrResult {
  const statusRead = readWarmSessionClaimEntry(sessionId);
  if (!statusRead.ok) return statusRead;
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    };
  }
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  entry.remainingUses -= usesNeeded;
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
  } else {
    prfFirstSessionCache.set(sessionId, entry);
  }
  return {
    ok: true,
    prfFirstB64u: entry.prfFirstB64u,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function consumeWarmSessionMaterialEntry(sessionId: string, uses: number): OkResult | ErrResult {
  const statusRead = readWarmSessionClaimEntry(sessionId);
  if (!statusRead.ok) return statusRead;
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) {
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    };
  }
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  entry.remainingUses -= usesNeeded;
  if (entry.remainingUses <= 0) {
    prfFirstSessionCache.delete(sessionId);
  } else {
    prfFirstSessionCache.set(sessionId, entry);
  }
  return {
    ok: true,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

async function runSigningSessionSealAndPersist(args: {
  sessionId: string;
  transport: SigningSessionSealTransport;
}): Promise<OkSealResult | ErrResult> {
  const sessionId = normalizeOptionalTrimmedString(args.sessionId);
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session seal',
    };
  }
  const statusRead = readWarmSessionClaimEntry(sessionId);
  if (!statusRead.ok) return statusRead;
  const entry = prfFirstSessionCache.get(sessionId);
  if (!entry) {
    return { ok: false, code: 'not_found', message: 'Warm-session material is not available for threshold session' };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'apply-server-seal',
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    shamirPrimeB64u,
    payloadB64u: entry.prfFirstB64u,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkSealResult | ErrResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: entry.prfFirstB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });

        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: args.transport.keyVersion,
        });
        if (!applied.ok) return applied;

        const sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: applied.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses: entry.remainingUses,
          localExpiresAtMs: entry.expiresAtMs,
          serverRemainingUses: applied.remainingUses,
          serverExpiresAtMs: applied.expiresAtMs,
        });
        if (!policy.ok) {
          prfFirstSessionCache.delete(sessionId);
          return policy;
        }
        prfFirstSessionCache.set(sessionId, {
          prfFirstB64u: entry.prfFirstB64u,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        const keyVersion = normalizeOptionalNonEmptyString(applied.keyVersion);
        return {
          ok: true,
          sealedSecretB64u,
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        };
      } finally {
        await runtime.destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle }).catch(
          () => undefined,
        );
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : String(error || 'Failed to apply server seal'),
      };
    }
  })().finally(() => {
    signingSessionSealApplyInFlight.delete(singleFlightKey);
  });

  signingSessionSealApplyInFlight.set(singleFlightKey, task);
  return await task;
}

async function runSigningSessionRehydrate(args: {
  sessionId: string;
  sealedSecretB64u: string;
  keyVersion?: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
}): Promise<OkResult | ErrResult> {
  const sessionId = normalizeOptionalTrimmedString(args.sessionId);
  if (!sessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  }
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  if (!sealedSecretB64u) {
    return { ok: false, code: 'invalid_args', message: 'Missing sealedSecretB64u' };
  }
  const localRemainingUses = Math.max(0, Math.floor(Number(args.remainingUses) || 0));
  const localExpiresAtMs = Math.max(0, Math.floor(Number(args.expiresAtMs) || 0));
  if (localRemainingUses <= 0) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (localExpiresAtMs <= nowMs()) {
    return { ok: false, code: 'expired', message: 'Warm-session material expired for threshold session' };
  }
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(args.transport.shamirPrimeB64u);
  if (!shamirPrimeB64u) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing shamirPrimeB64u for signing-session rehydrate',
    };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    sessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.keyVersion || args.transport.keyVersion,
    shamirPrimeB64u,
    payloadB64u: sealedSecretB64u,
  });
  const inFlight = signingSessionSealRemoveInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkResult | ErrResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({ shamirPrimeB64u });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });

        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport: args.transport,
          thresholdSessionId: sessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: normalizeOptionalNonEmptyString(args.keyVersion) || args.transport.keyVersion,
        });
        if (!removed.ok) return removed;

        const prfFirstB64u = await runtime.removeClientSealWithKeyHandle({
          ciphertextB64u: removed.ciphertext,
          keyHandle: clientKeyHandle.keyHandle,
        });
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses,
          localExpiresAtMs,
          serverRemainingUses: removed.remainingUses,
          serverExpiresAtMs: removed.expiresAtMs,
        });
        if (!policy.ok) return policy;

        prfFirstSessionCache.set(sessionId, {
          prfFirstB64u,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        return policy;
      } finally {
        await runtime.destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle }).catch(
          () => undefined,
        );
      }
    } catch (error: unknown) {
      return {
        ok: false,
        code: 'internal',
        message:
          error instanceof Error ? error.message : String(error || 'Failed to remove server seal'),
      };
    }
  })().finally(() => {
    signingSessionSealRemoveInFlight.delete(singleFlightKey);
  });

  signingSessionSealRemoveInFlight.set(singleFlightKey, task);
  return await task;
}

function postUserConfirmWorkerResponse(
  id: unknown,
  payload: { success: boolean; data?: unknown; error?: string },
): void {
  const response = {
    ...(typeof id === 'string' && id.trim() ? { id: id.trim() } : {}),
    success: !!payload.success,
    ...(payload.data !== undefined ? { data: payload.data } : {}),
    ...(payload.error ? { error: payload.error } : {}),
  };
  try {
    self.postMessage(response);
  } catch {}
}

function toDecisionFromWorkerResponse(
  response: Awaited<ReturnType<typeof awaitUserConfirmationV2>>,
): UserConfirmDecision {
  return {
    requestId: String(response.request_id || '').trim(),
    intentDigest: response.intent_digest,
    confirmed: !!response.confirmed,
    credential: response.credential,
    otpCode: response.otp_code,
    emailOtpChallengeId: response.email_otp_challenge_id,
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

  if (eventType === 'WARM_SESSION_MATERIAL_PUT') {
    try {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const prfFirstB64u = normalizeOptionalTrimmedString(payload?.prfFirstB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      if (!sessionId || !prfFirstB64u) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Missing sessionId or prfFirstB64u',
          } satisfies ErrResult,
        });
        return;
      }
      if (expiresAtMs <= nowMs() || remainingUses <= 0) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid expiresAtMs or remainingUses',
          } satisfies ErrResult,
        });
        return;
      }
      prfFirstSessionCache.set(sessionId, { prfFirstB64u, expiresAtMs, remainingUses });
      postUserConfirmWorkerResponse(id, {
        success: true,
        data: { ok: true, remainingUses, expiresAtMs } satisfies OkResult,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      postUserConfirmWorkerResponse(id, { success: false, error: msg });
    }
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_READ') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    postUserConfirmWorkerResponse(id, { success: true, data: readWarmSessionClaimEntry(sessionId) });
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_BATCH_READ') {
    const payload = asRecord(incoming.payload);
    const sessionIds = Array.isArray(payload?.sessionIds)
      ? Array.from(
          new Set(
            payload.sessionIds
              .map((value) => normalizeOptionalTrimmedString(value))
              .filter((value): value is string => !!value),
          ),
        )
      : [];
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: {
        results: sessionIds.map((sessionId) => ({
          sessionId,
          result: readWarmSessionClaimEntry(sessionId),
        })),
      },
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CLAIM') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: claimWarmSessionMaterialEntry(sessionId, uses),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CONSUME') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postUserConfirmWorkerResponse(id, {
      success: true,
      data: consumeWarmSessionMaterialEntry(sessionId, uses),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CLEAR') {
    const payload = asRecord(incoming.payload);
    const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
    if (sessionId) prfFirstSessionCache.delete(sessionId);
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CLEAR_ALL') {
    prfFirstSessionCache.clear();
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_SEAL_AND_PERSIST') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (!sessionId || !transport) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid WARM_SESSION_SEAL_AND_PERSIST payload',
          } satisfies ErrResult,
        });
        return;
      }
      const result = await runSigningSessionSealAndPersist({ sessionId, transport });
      postUserConfirmWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_REHYDRATE') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const sessionId = normalizeOptionalTrimmedString(payload?.sessionId);
      const sealedSecretB64u = normalizeOptionalTrimmedString(payload?.sealedSecretB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      const keyVersion = normalizeOptionalNonEmptyString(payload?.keyVersion);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (
        !sessionId ||
        !sealedSecretB64u ||
        !transport ||
        expiresAtMs <= 0 ||
        remainingUses <= 0
      ) {
        postUserConfirmWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid WARM_SESSION_REHYDRATE payload',
          } satisfies ErrResult,
        });
        return;
      }
      const result = await runSigningSessionRehydrate({
        sessionId,
        sealedSecretB64u,
        expiresAtMs,
        remainingUses,
        ...(keyVersion ? { keyVersion } : {}),
        transport,
      });
      postUserConfirmWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_DELETE_PERSISTED') {
    postUserConfirmWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  // Unknown message types: respond with an explicit error (prevents sendMessage timeouts).
  if (typeof id === 'string' && id.trim()) {
    postUserConfirmWorkerResponse(id, {
      success: false,
      error: `Unsupported UserConfirm worker message type: ${String(eventType)}`,
    });
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
