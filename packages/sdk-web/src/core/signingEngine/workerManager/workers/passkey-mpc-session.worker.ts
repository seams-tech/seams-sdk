/** Passkey MPC warm-session material worker. */
import type { WarmSessionSealAndPersistDiagnostics } from '@/core/types/secure-confirm-worker';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseClearVolatileWarmMaterialCommand } from '@/core/signingEngine/session/warmCapabilities/volatileWarmMaterialCommands';
import { bytesToHex } from '../../chains/evm/bytes';
import { secureRandomBase64Url } from '@shared/utils/secureRandomId';
import {
  SIGNING_SESSION_SEAL_GROUP_ID,
  WALLET_SESSION_SEAL_BASE_PATH,
} from '@shared/utils/signingSessionSeal';
import {
  joinNormalizedUrl,
  normalizeNonNegativeInteger,
  normalizeOptionalTrimmedString,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { getShamir3PassRuntime, warmupShamir3PassRuntime } from './shamir3pass/runtime';

type WarmSessionMaterialEntry = {
  prfFirstHandle: string;
  expiresAtMs: number;
  remainingUses: number;
};

type PasskeyPrfFirstHandleEntry = {
  prfFirstB64u: string;
  expiresAtMs: number;
};

type PasskeyServerSealedSecretCacheEntry = {
  sealedSecretB64u: string;
  expiresAtMs: number;
};

type PasskeyServerSealedSecretCacheScope = {
  kind: 'passkey_registration';
  walletId: string;
  credentialIdB64u: string;
  walletSessionId: string;
  quotaId: string;
};

type OkResult = { ok: true; remainingUses: number; expiresAtMs: number };
type OkSealResult = OkResult & {
  sealedSecretB64u: string;
  keyVersion?: string;
  diagnostics?: WarmSessionSealAndPersistDiagnostics;
};
type OkDispenseResult = OkResult & { prfFirstB64u: string };
type ErrResult = { ok: false; code: string; message: string };
type WarmSessionMaterialReadResult =
  | ({ ok: true; entry: WarmSessionMaterialEntry; secret: PasskeyPrfFirstHandleEntry } & OkResult)
  | ErrResult;

const PASSKEY_SERVER_SEALED_SECRET_CACHE_MAX_ENTRIES = 32;

type SigningSessionSealTransport = {
  relayerUrl: string;
  walletSessionToken?: string;
  keyVersion?: string;
  serverSealedSecretCacheScope?: PasskeyServerSealedSecretCacheScope;
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

const warmSessionPrfHandleCache = new Map<string, WarmSessionMaterialEntry>();
const passkeyPrfFirstHandleStore = new Map<string, PasskeyPrfFirstHandleEntry>();
const passkeyServerSealedSecretCache = new Map<string, PasskeyServerSealedSecretCacheEntry>();
const signingSessionSealApplyInFlight = new Map<string, Promise<OkSealResult | ErrResult>>();
const signingSessionSealRemoveInFlight = new Map<string, Promise<OkResult | ErrResult>>();
const SIGNING_SESSION_SEAL_BASE_PATH = WALLET_SESSION_SEAL_BASE_PATH;
const SIGNING_SESSION_SEAL_ROUTE_TIMEOUT_MS = 15_000;

function abortSigningSessionSealRoute(controller: AbortController): void {
  controller.abort('timeout');
}

type PasskeyMpcSessionWorkerIncomingMessage = {
  id?: unknown;
  type?: unknown;
  payload?: unknown;
};

function asIncomingMessage(value: unknown): PasskeyMpcSessionWorkerIncomingMessage {
  const record = asRecord(value);
  if (!record) return {};
  return {
    id: record.id,
    type: record.type,
    payload: record.payload,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return isRecord(value) ? value : null;
}

function nowMs(): number {
  return Date.now();
}

function roundWorkerDurationMs(startedAt: number): number {
  return Math.max(0, Math.round(performance.now() - startedAt));
}

function createWarmSessionSealAndPersistDiagnostics(): WarmSessionSealAndPersistDiagnostics {
  return {
    runtimeSetupMs: 0,
    clientSealMs: 0,
    serverSealRouteMs: 0,
    clientUnsealMs: 0,
    policyUpdateMs: 0,
  };
}

function recordWarmSessionSealAndPersistDiagnosticDuration(args: {
  diagnostics: WarmSessionSealAndPersistDiagnostics;
  bucket: keyof WarmSessionSealAndPersistDiagnostics;
  startedAt: number;
}): void {
  args.diagnostics[args.bucket] += roundWorkerDurationMs(args.startedAt);
}

function overwriteBytes(bytes: Uint8Array | null | undefined): void {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return;
  bytes.fill(0);
}

function toSessionId(prefix: string): string {
  const value = String(prefix || '').trim() || 'session';
  return `${value}:${secureRandomBase64Url(32, 'passkey confirm worker session IDs')}`;
}

function createPasskeyPrfFirstHandle(args: { prfFirstB64u: string; expiresAtMs: number }): string {
  const prfFirstB64u = normalizeOptionalTrimmedString(args.prfFirstB64u);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!prfFirstB64u || expiresAtMs <= nowMs()) {
    throw new Error('Invalid passkey PRF material handle input');
  }
  const prfFirstHandle = toSessionId('passkey-prf-first');
  passkeyPrfFirstHandleStore.set(prfFirstHandle, {
    prfFirstB64u,
    expiresAtMs,
  });
  return prfFirstHandle;
}

async function sha256HexUtf8(value: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bytesToHex(new Uint8Array(digest));
}

async function passkeyServerSealedSecretCacheKey(args: {
  prfFirstB64u: string;
  relayerUrl: string;
  keyVersion: string;
  cacheScope: PasskeyServerSealedSecretCacheScope | undefined;
}): Promise<string | null> {
  const prfFirstB64u = normalizeOptionalTrimmedString(args.prfFirstB64u);
  const relayerUrl = normalizeOptionalTrimmedString(args.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
  const cacheScope = args.cacheScope;
  if (!prfFirstB64u || !relayerUrl || !keyVersion || !cacheScope) return null;
  const prfDigestHex = await sha256HexUtf8(prfFirstB64u);
  return [
    'passkey-server-sealed-secret-v1',
    relayerUrl,
    keyVersion,
    SIGNING_SESSION_SEAL_GROUP_ID,
    cacheScope.walletId,
    cacheScope.credentialIdB64u,
    cacheScope.walletSessionId,
    cacheScope.quotaId,
    prfDigestHex,
  ].join('|');
}

function prunePasskeyServerSealedSecretCache(): void {
  const now = nowMs();
  for (const [key, entry] of passkeyServerSealedSecretCache) {
    if (entry.expiresAtMs <= now) passkeyServerSealedSecretCache.delete(key);
  }
  while (passkeyServerSealedSecretCache.size > PASSKEY_SERVER_SEALED_SECRET_CACHE_MAX_ENTRIES) {
    const firstKey = passkeyServerSealedSecretCache.keys().next().value;
    if (typeof firstKey !== 'string') return;
    passkeyServerSealedSecretCache.delete(firstKey);
  }
}

function readPasskeyServerSealedSecretCache(
  cacheKey: string | null,
): PasskeyServerSealedSecretCacheEntry | null {
  if (!cacheKey) return null;
  prunePasskeyServerSealedSecretCache();
  const entry = passkeyServerSealedSecretCache.get(cacheKey);
  if (!entry || entry.expiresAtMs <= nowMs()) {
    if (entry) passkeyServerSealedSecretCache.delete(cacheKey);
    return null;
  }
  return entry;
}

function writePasskeyServerSealedSecretCache(args: {
  cacheKey: string | null;
  sealedSecretB64u: string;
  expiresAtMs: number;
}): void {
  if (!args.cacheKey) return;
  const sealedSecretB64u = normalizeOptionalTrimmedString(args.sealedSecretB64u);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!sealedSecretB64u || expiresAtMs <= nowMs()) return;
  passkeyServerSealedSecretCache.set(args.cacheKey, { sealedSecretB64u, expiresAtMs });
  prunePasskeyServerSealedSecretCache();
}

function deleteWarmSessionPrfHandle(thresholdSessionId: string): void {
  const entry = warmSessionPrfHandleCache.get(thresholdSessionId);
  if (entry) passkeyPrfFirstHandleStore.delete(entry.prfFirstHandle);
  warmSessionPrfHandleCache.delete(thresholdSessionId);
}

function clearWarmSessionPrfHandles(): void {
  warmSessionPrfHandleCache.clear();
  passkeyPrfFirstHandleStore.clear();
  passkeyServerSealedSecretCache.clear();
}

function storeWarmSessionPrfHandle(args: {
  thresholdSessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
}): WarmSessionMaterialEntry {
  const thresholdSessionId = normalizeOptionalTrimmedString(args.thresholdSessionId);
  const remainingUses = Math.floor(Number(args.remainingUses) || 0);
  const expiresAtMs = Math.floor(Number(args.expiresAtMs) || 0);
  if (!thresholdSessionId || remainingUses <= 0 || expiresAtMs <= nowMs()) {
    throw new Error('Invalid warm-session PRF handle input');
  }
  deleteWarmSessionPrfHandle(thresholdSessionId);
  const prfFirstHandle = createPasskeyPrfFirstHandle({
    prfFirstB64u: args.prfFirstB64u,
    expiresAtMs,
  });
  const entry = { prfFirstHandle, expiresAtMs, remainingUses };
  warmSessionPrfHandleCache.set(thresholdSessionId, entry);
  return entry;
}

function updateWarmSessionPrfHandlePolicy(
  thresholdSessionId: string,
  entry: WarmSessionMaterialEntry,
  policy: OkResult,
): WarmSessionMaterialEntry {
  const nextEntry = {
    prfFirstHandle: entry.prfFirstHandle,
    remainingUses: policy.remainingUses,
    expiresAtMs: policy.expiresAtMs,
  };
  const secret = passkeyPrfFirstHandleStore.get(entry.prfFirstHandle);
  if (secret) {
    passkeyPrfFirstHandleStore.set(entry.prfFirstHandle, {
      prfFirstB64u: secret.prfFirstB64u,
      expiresAtMs: policy.expiresAtMs,
    });
  }
  warmSessionPrfHandleCache.set(thresholdSessionId, nextEntry);
  return nextEntry;
}

function parseSigningSessionSealTransport(value: unknown): SigningSessionSealTransport | null {
  const transport = asRecord(value);
  if (!transport) return null;
  const relayerUrl = normalizeOptionalNonEmptyString(transport.relayerUrl);
  const walletSessionToken = normalizeOptionalNonEmptyString(transport.walletSessionToken);
  const keyVersion = normalizeOptionalNonEmptyString(transport.signingSessionSealKeyVersion);
  const serverSealedSecretCacheScope = parsePasskeyServerSealedSecretCacheScope(
    transport.serverSealedSecretCacheScope,
  );
  if (!relayerUrl) return null;
  return {
    relayerUrl,
    ...(walletSessionToken ? { walletSessionToken } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(serverSealedSecretCacheScope ? { serverSealedSecretCacheScope } : {}),
  };
}

function parsePasskeyServerSealedSecretCacheScope(
  value: unknown,
): PasskeyServerSealedSecretCacheScope | undefined {
  const scope = asRecord(value);
  if (!scope || scope.kind !== 'passkey_registration') return undefined;
  const walletId = normalizeOptionalNonEmptyString(scope.walletId);
  const credentialIdB64u = normalizeOptionalNonEmptyString(scope.credentialIdB64u);
  const walletSessionId = normalizeOptionalNonEmptyString(scope.walletSessionId);
  const quotaId = normalizeOptionalNonEmptyString(scope.quotaId);
  if (!walletId || !credentialIdB64u || !walletSessionId || !quotaId) return undefined;
  return {
    kind: 'passkey_registration',
    walletId,
    credentialIdB64u,
    walletSessionId,
    quotaId,
  };
}

function parseSigningSessionSealRouteResult(value: unknown): SigningSessionSealRouteResult {
  const result = asRecord(value);
  if (!result || typeof result.ok !== 'boolean') {
    return {
      ok: false,
      code: 'invalid_response',
      message: 'Invalid signing-session seal response',
    };
  }
  if (!result.ok) {
    return {
      ok: false,
      code: typeof result.code === 'string' ? result.code : 'request_failed',
      message:
        typeof result.message === 'string' ? result.message : 'Signing-session seal request failed',
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
  thresholdSessionId: string;
  relayerUrl: string;
  keyVersion?: string;
  payloadKey?: string;
}): string {
  const operation =
    args.operation === 'apply-server-seal' ? 'apply-server-seal' : 'remove-server-seal';
  const thresholdSessionId = normalizeOptionalTrimmedString(args.thresholdSessionId) || '';
  const relayerUrl = normalizeOptionalTrimmedString(args.relayerUrl) || '';
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion) || '';
  const payloadKey = normalizeOptionalNonEmptyString(args.payloadKey) || '';
  return `${operation}|${thresholdSessionId}|${relayerUrl}|${keyVersion}|${SIGNING_SESSION_SEAL_GROUP_ID}|${payloadKey}`;
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
  const controller = new AbortController();
  const timeoutId = setTimeout(
    abortSigningSessionSealRoute,
    SIGNING_SESSION_SEAL_ROUTE_TIMEOUT_MS,
    controller,
  );

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const walletSessionToken = normalizeOptionalNonEmptyString(args.transport.walletSessionToken);
    const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
    if (walletSessionToken) {
      headers.Authorization = `Bearer ${walletSessionToken}`;
    }
    const response = await fetch(url, {
      method: 'POST',
      credentials: walletSessionToken ? 'omit' : 'include',
      headers,
      signal: controller.signal,
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
      code: controller.signal.aborted ? 'timeout' : 'network_error',
      message: controller.signal.aborted
        ? `Signing-session seal request timed out after ${SIGNING_SESSION_SEAL_ROUTE_TIMEOUT_MS}ms`
        : error instanceof Error
          ? error.message
          : String(error || 'Signing-session seal request failed'),
    };
  } finally {
    clearTimeout(timeoutId);
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

function readWarmSessionMaterialEntry(thresholdSessionId: string): WarmSessionMaterialReadResult {
  if (!thresholdSessionId)
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  const entry = warmSessionPrfHandleCache.get(thresholdSessionId);
  if (!entry)
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material is not available for threshold session',
    };
  if (nowMs() >= entry.expiresAtMs) {
    deleteWarmSessionPrfHandle(thresholdSessionId);
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  if (entry.remainingUses <= 0) {
    deleteWarmSessionPrfHandle(thresholdSessionId);
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  const secret = passkeyPrfFirstHandleStore.get(entry.prfFirstHandle);
  if (!secret || nowMs() >= secret.expiresAtMs) {
    deleteWarmSessionPrfHandle(thresholdSessionId);
    return {
      ok: false,
      code: 'not_found',
      message: 'Warm-session material handle is not available for threshold session',
    };
  }
  return {
    ok: true,
    entry,
    secret,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function readWarmSessionClaimEntry(thresholdSessionId: string): OkResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(thresholdSessionId);
  if (!activeEntry.ok) return activeEntry;
  return {
    ok: true,
    remainingUses: activeEntry.remainingUses,
    expiresAtMs: activeEntry.expiresAtMs,
  };
}

function claimWarmSessionMaterialEntry(
  thresholdSessionId: string,
  uses: number,
  consume: boolean,
): OkDispenseResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(thresholdSessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
  const usesNeeded = Math.max(1, Math.floor(Number(uses) || 1));
  if (entry.remainingUses < usesNeeded) {
    return {
      ok: false,
      code: 'exhausted',
      message: 'Warm-session material exhausted for threshold session',
    };
  }
  if (consume) {
    entry.remainingUses -= usesNeeded;
    if (entry.remainingUses <= 0) {
      deleteWarmSessionPrfHandle(thresholdSessionId);
    } else {
      warmSessionPrfHandleCache.set(thresholdSessionId, entry);
    }
  }
  return {
    ok: true,
    prfFirstB64u: activeEntry.secret.prfFirstB64u,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

function consumeWarmSessionMaterialEntry(thresholdSessionId: string, uses: number): OkResult | ErrResult {
  const activeEntry = readWarmSessionMaterialEntry(thresholdSessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
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
    deleteWarmSessionPrfHandle(thresholdSessionId);
  } else {
    warmSessionPrfHandleCache.set(thresholdSessionId, entry);
  }
  return {
    ok: true,
    remainingUses: entry.remainingUses,
    expiresAtMs: entry.expiresAtMs,
  };
}

async function runSigningSessionSealAndPersist(args: {
  thresholdSessionId: string;
  transport: SigningSessionSealTransport;
}): Promise<OkSealResult | ErrResult> {
  const thresholdSessionId = normalizeOptionalTrimmedString(args.thresholdSessionId);
  if (!thresholdSessionId) {
    return { ok: false, code: 'invalid_args', message: 'Missing threshold sessionId' };
  }
  const activeEntry = readWarmSessionMaterialEntry(thresholdSessionId);
  if (!activeEntry.ok) return activeEntry;
  const entry = activeEntry.entry;
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'apply-server-seal',
    thresholdSessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.transport.keyVersion,
    payloadKey: entry.prfFirstHandle,
  });
  const inFlight = signingSessionSealApplyInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkSealResult | ErrResult> => {
    const diagnostics = createWarmSessionSealAndPersistDiagnostics();
    try {
      const runtimeSetupStartedAt = performance.now();
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      });
      recordWarmSessionSealAndPersistDiagnosticDuration({
        diagnostics,
        bucket: 'runtimeSetupMs',
        startedAt: runtimeSetupStartedAt,
      });
      try {
        const clientSealStartedAt = performance.now();
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: activeEntry.secret.prfFirstB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'clientSealMs',
          startedAt: clientSealStartedAt,
        });

        const serverSealRouteStartedAt = performance.now();
        const applied = await callSigningSessionSealRoute({
          operation: 'apply-server-seal',
          transport: args.transport,
          thresholdSessionId,
          ciphertext: clientEncryptedCiphertext,
          keyVersion: args.transport.keyVersion,
        });
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'serverSealRouteMs',
          startedAt: serverSealRouteStartedAt,
        });
        if (!applied.ok) return applied;
        const policyUpdateStartedAt = performance.now();
        const policy = resolvePolicyFromServerAndLocal({
          localRemainingUses: entry.remainingUses,
          localExpiresAtMs: entry.expiresAtMs,
          serverRemainingUses: applied.remainingUses,
          serverExpiresAtMs: applied.expiresAtMs,
        });
        if (!policy.ok) {
          deleteWarmSessionPrfHandle(thresholdSessionId);
          return policy;
        }
        updateWarmSessionPrfHandlePolicy(thresholdSessionId, entry, policy);
        recordWarmSessionSealAndPersistDiagnosticDuration({
          diagnostics,
          bucket: 'policyUpdateMs',
          startedAt: policyUpdateStartedAt,
        });
        const keyVersion =
          normalizeOptionalNonEmptyString(applied.keyVersion) ||
          normalizeOptionalNonEmptyString(args.transport.keyVersion);
        const sealedSecretCacheKey = keyVersion
          ? await passkeyServerSealedSecretCacheKey({
              prfFirstB64u: activeEntry.secret.prfFirstB64u,
              relayerUrl: args.transport.relayerUrl,
              keyVersion,
              cacheScope: args.transport.serverSealedSecretCacheScope,
            })
          : null;
        const cachedSealedSecret = readPasskeyServerSealedSecretCache(sealedSecretCacheKey);
        let sealedSecretB64u = cachedSealedSecret?.sealedSecretB64u || '';
        if (!sealedSecretB64u) {
          const clientUnsealStartedAt = performance.now();
          sealedSecretB64u = await runtime.removeClientSealWithKeyHandle({
            ciphertextB64u: applied.ciphertext,
            keyHandle: clientKeyHandle.keyHandle,
          });
          recordWarmSessionSealAndPersistDiagnosticDuration({
            diagnostics,
            bucket: 'clientUnsealMs',
            startedAt: clientUnsealStartedAt,
          });
          writePasskeyServerSealedSecretCache({
            cacheKey: sealedSecretCacheKey,
            sealedSecretB64u,
            expiresAtMs: policy.expiresAtMs,
          });
        }
        return {
          ok: true,
          sealedSecretB64u,
          ...(keyVersion ? { keyVersion } : {}),
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
          diagnostics,
        };
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
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
  thresholdSessionId: string;
  sealedSecretB64u: string;
  keyVersion?: string;
  remainingUses: number;
  expiresAtMs: number;
  transport: SigningSessionSealTransport;
}): Promise<OkResult | ErrResult> {
  const thresholdSessionId = normalizeOptionalTrimmedString(args.thresholdSessionId);
  if (!thresholdSessionId) {
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
    return {
      ok: false,
      code: 'expired',
      message: 'Warm-session material expired for threshold session',
    };
  }
  const singleFlightKey = makeSigningSessionSealSingleFlightKey({
    operation: 'remove-server-seal',
    thresholdSessionId,
    relayerUrl: args.transport.relayerUrl,
    keyVersion: args.keyVersion || args.transport.keyVersion,
    payloadKey: sealedSecretB64u,
  });
  const inFlight = signingSessionSealRemoveInFlight.get(singleFlightKey);
  if (inFlight) return await inFlight;

  const task = (async (): Promise<OkResult | ErrResult> => {
    try {
      const runtime = await getShamir3PassRuntime();
      const clientKeyHandle = await runtime.createClientKeyHandle({
        groupId: SIGNING_SESSION_SEAL_GROUP_ID,
      });
      try {
        const clientEncryptedCiphertext = await runtime.addClientSealWithKeyHandle({
          ciphertextB64u: sealedSecretB64u,
          keyHandle: clientKeyHandle.keyHandle,
        });

        const removed = await callSigningSessionSealRoute({
          operation: 'remove-server-seal',
          transport: args.transport,
          thresholdSessionId,
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

        storeWarmSessionPrfHandle({
          thresholdSessionId,
          prfFirstB64u,
          remainingUses: policy.remainingUses,
          expiresAtMs: policy.expiresAtMs,
        });
        return policy;
      } finally {
        await runtime
          .destroyClientKeyHandle({ keyHandle: clientKeyHandle.keyHandle })
          .catch(() => undefined);
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

function postPasskeyMpcSessionWorkerResponse(
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

self.onmessage = (event: MessageEvent) => {
  const incoming = asIncomingMessage(event.data);
  const eventType = incoming.type;
  const id = incoming.id;

  // Health check / liveness
  if (eventType === 'PING') {
    postPasskeyMpcSessionWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'PREWARM_SHAMIR3PASS') {
    void (async () => {
      // warmupShamir3PassRuntime never rejects; it reports failure as data.
      const outcome = await warmupShamir3PassRuntime();
      postPasskeyMpcSessionWorkerResponse(id, { success: true, data: outcome });
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_PUT') {
    try {
      const payload = asRecord(incoming.payload);
      const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
      const prfFirstB64u = normalizeOptionalTrimmedString(payload?.prfFirstB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      if (!thresholdSessionId || !prfFirstB64u) {
        postPasskeyMpcSessionWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Missing thresholdSessionId or prfFirstB64u',
          } satisfies ErrResult,
        });
        return;
      }
      if (expiresAtMs <= nowMs() || remainingUses <= 0) {
        postPasskeyMpcSessionWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid expiresAtMs or remainingUses',
          } satisfies ErrResult,
        });
        return;
      }
      storeWarmSessionPrfHandle({ thresholdSessionId, prfFirstB64u, expiresAtMs, remainingUses });
      postPasskeyMpcSessionWorkerResponse(id, {
        success: true,
        data: { ok: true, remainingUses, expiresAtMs } satisfies OkResult,
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      postPasskeyMpcSessionWorkerResponse(id, { success: false, error: msg });
    }
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_READ') {
    const payload = asRecord(incoming.payload);
    const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
    postPasskeyMpcSessionWorkerResponse(id, {
      success: true,
      data: readWarmSessionClaimEntry(thresholdSessionId),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_STATUS_BATCH_READ') {
    const payload = asRecord(incoming.payload);
    const thresholdSessionIds = Array.isArray(payload?.thresholdSessionIds)
      ? Array.from(
          new Set(
            payload.thresholdSessionIds
              .map((value) => normalizeOptionalTrimmedString(value))
              .filter((value): value is string => !!value),
          ),
        )
      : [];
    postPasskeyMpcSessionWorkerResponse(id, {
      success: true,
      data: {
        results: thresholdSessionIds.map((thresholdSessionId) => ({
          thresholdSessionId,
          result: readWarmSessionClaimEntry(thresholdSessionId),
        })),
      },
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CLAIM') {
    const payload = asRecord(incoming.payload);
    const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    const consume = payload?.consume !== false;
    postPasskeyMpcSessionWorkerResponse(id, {
      success: true,
      data: claimWarmSessionMaterialEntry(thresholdSessionId, uses, consume),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_MATERIAL_CONSUME') {
    const payload = asRecord(incoming.payload);
    const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
    const uses = Math.max(1, Math.floor(Number(payload?.uses) || 1));
    postPasskeyMpcSessionWorkerResponse(id, {
      success: true,
      data: consumeWarmSessionMaterialEntry(thresholdSessionId, uses),
    });
    return;
  }

  if (eventType === 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR') {
    const command = parseClearVolatileWarmMaterialCommand(incoming.payload);
    if (command?.scope.kind === 'session') {
      deleteWarmSessionPrfHandle(String(command.scope.thresholdSessionId));
    }
    postPasskeyMpcSessionWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_VOLATILE_MATERIAL_CLEAR_ALL') {
    clearWarmSessionPrfHandles();
    postPasskeyMpcSessionWorkerResponse(id, { success: true, data: { ok: true } });
    return;
  }

  if (eventType === 'WARM_SESSION_SEAL_AND_PERSIST') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (!thresholdSessionId || !transport) {
        postPasskeyMpcSessionWorkerResponse(id, {
          success: true,
          data: {
            ok: false,
            code: 'invalid_args',
            message: 'Invalid WARM_SESSION_SEAL_AND_PERSIST payload',
          } satisfies ErrResult,
        });
        return;
      }
      const result = await runSigningSessionSealAndPersist({ thresholdSessionId, transport });
      postPasskeyMpcSessionWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  if (eventType === 'WARM_SESSION_REHYDRATE') {
    void (async () => {
      const payload = asRecord(incoming.payload);
      const thresholdSessionId = normalizeOptionalTrimmedString(payload?.thresholdSessionId);
      const sealedSecretB64u = normalizeOptionalTrimmedString(payload?.sealedSecretB64u);
      const expiresAtMs = Math.floor(Number(payload?.expiresAtMs) || 0);
      const remainingUses = Math.floor(Number(payload?.remainingUses) || 0);
      const keyVersion = normalizeOptionalNonEmptyString(payload?.signingSessionSealKeyVersion);
      const transport = parseSigningSessionSealTransport(payload?.transport);
      if (
        !thresholdSessionId ||
        !sealedSecretB64u ||
        !transport ||
        expiresAtMs <= 0 ||
        remainingUses <= 0
      ) {
        postPasskeyMpcSessionWorkerResponse(id, {
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
        thresholdSessionId,
        sealedSecretB64u,
        expiresAtMs,
        remainingUses,
        ...(keyVersion ? { keyVersion } : {}),
        transport,
      });
      postPasskeyMpcSessionWorkerResponse(id, { success: true, data: result });
    })();
    return;
  }

  // Unknown message types: respond with an explicit error (prevents sendMessage timeouts).
  if (typeof id === 'string' && id.trim()) {
    postPasskeyMpcSessionWorkerResponse(id, {
      success: false,
      error: `Unsupported Passkey MPC session worker message type: ${String(eventType)}`,
    });
  }
};

// === GLOBAL ERROR MONITORING ===

self.onerror = (error) => {
  console.error('[passkey-mpc-session-worker] error:', error);
};

self.onunhandledrejection = (event) => {
  console.error('[passkey-mpc-session-worker] Unhandled promise rejection:', event.reason);
  event.preventDefault();
};
