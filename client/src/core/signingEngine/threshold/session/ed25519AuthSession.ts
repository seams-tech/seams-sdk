import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import type { Ed25519SessionPolicy } from './sessionPolicy';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { redactCredentialExtensionOutputs } from '../webauthn';

export type Ed25519SessionKind = 'jwt' | 'cookie';

export type Ed25519AuthSession = {
  sessionKind: Ed25519SessionKind;
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type Ed25519AuthSessionCacheEntry = Ed25519AuthSession;

const authSessionCache = new Map<string, Ed25519AuthSessionCacheEntry>();
const authSessionBySessionId = new Map<string, Ed25519AuthSessionCacheEntry>();
type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
type PersistedEd25519AuthSessionRecord = {
  v: 1;
  sessionId: string;
  jwt: string;
  expiresAtMs?: number;
  updatedAtMs: number;
};

const STORAGE_KEY_PREFIX = 'tatchi:threshold-ed25519-auth-session:v1';
const STORAGE_INDEX_KEY = `${STORAGE_KEY_PREFIX}:index`;

function storageKeyForSessionId(sessionId: string): string {
  return `${STORAGE_KEY_PREFIX}:${sessionId}`;
}

function getSessionStorageSafe(): SessionStoragePort | null {
  const globalObj = globalThis as { sessionStorage?: SessionStoragePort };
  if (!globalObj?.sessionStorage) return null;
  try {
    const storage = globalObj.sessionStorage;
    storage.getItem('__tatchi_threshold_ed25519_auth_session_probe__');
    return storage;
  } catch {
    return null;
  }
}

function toOptionalTrimmedString(value: unknown): string | undefined {
  const normalized = String(value || '').trim();
  return normalized || undefined;
}

function toOptionalFiniteNumber(value: unknown): number | undefined {
  const normalized = Number(value);
  if (!Number.isFinite(normalized)) return undefined;
  return Math.floor(normalized);
}

function readStorageIndex(storage: SessionStoragePort): string[] {
  try {
    const raw = storage.getItem(STORAGE_INDEX_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((value) => String(value || '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function writeStorageIndex(storage: SessionStoragePort, sessionIds: string[]): void {
  try {
    storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(sessionIds));
  } catch {}
}

function addToStorageIndex(storage: SessionStoragePort, sessionId: string): void {
  const normalizedSessionId = String(sessionId || '').trim();
  if (!normalizedSessionId) return;
  const current = readStorageIndex(storage);
  if (current.includes(normalizedSessionId)) return;
  writeStorageIndex(storage, [...current, normalizedSessionId]);
}

function removeFromStorageIndex(storage: SessionStoragePort, sessionId: string): void {
  const normalizedSessionId = String(sessionId || '').trim();
  if (!normalizedSessionId) return;
  const current = readStorageIndex(storage);
  const next = current.filter((entry) => entry !== normalizedSessionId);
  if (next.length === current.length) return;
  writeStorageIndex(storage, next);
}

function normalizePersistedEd25519AuthSessionRecord(
  value: unknown,
): PersistedEd25519AuthSessionRecord | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (Number(obj.v) !== 1) return null;
  const sessionId = String(obj.sessionId || '').trim();
  const jwt = String(obj.jwt || '').trim();
  const updatedAtMs = toOptionalFiniteNumber(obj.updatedAtMs);
  const expiresAtMs = toOptionalFiniteNumber(obj.expiresAtMs);
  if (!sessionId || !jwt || !updatedAtMs || updatedAtMs <= 0) return null;
  if (expiresAtMs != null && expiresAtMs <= 0) return null;
  return {
    v: 1,
    sessionId,
    jwt,
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    updatedAtMs,
  };
}

function writePersistedEd25519AuthSessionJwt(args: {
  sessionId: string;
  jwt: string;
  expiresAtMs?: number;
}): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  const sessionId = String(args.sessionId || '').trim();
  const jwt = String(args.jwt || '').trim();
  const expiresAtMs = toOptionalFiniteNumber(args.expiresAtMs);
  if (!sessionId || !jwt) return;
  if (expiresAtMs != null && expiresAtMs <= 0) return;
  try {
    const record: PersistedEd25519AuthSessionRecord = {
      v: 1,
      sessionId,
      jwt,
      ...(expiresAtMs != null ? { expiresAtMs } : {}),
      updatedAtMs: Date.now(),
    };
    storage.setItem(storageKeyForSessionId(sessionId), JSON.stringify(record));
    addToStorageIndex(storage, sessionId);
  } catch {}
}

function readPersistedEd25519AuthSessionJwt(
  sessionIdRaw: string,
): PersistedEd25519AuthSessionRecord | null {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) return null;
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  try {
    const raw = storage.getItem(storageKeyForSessionId(sessionId));
    if (!raw) return null;
    return normalizePersistedEd25519AuthSessionRecord(JSON.parse(raw));
  } catch {
    return null;
  }
}

function deletePersistedEd25519AuthSessionJwt(sessionIdRaw: string): void {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) return;
  const storage = getSessionStorageSafe();
  if (!storage) return;
  try {
    storage.removeItem(storageKeyForSessionId(sessionId));
  } catch {}
  removeFromStorageIndex(storage, sessionId);
}

function clearAllPersistedEd25519AuthSessionJwts(): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  const sessionIds = readStorageIndex(storage);
  for (const sessionId of sessionIds) {
    try {
      storage.removeItem(storageKeyForSessionId(sessionId));
    } catch {}
  }
  try {
    storage.removeItem(STORAGE_INDEX_KEY);
  } catch {}
}

function toSessionId(value: unknown): string {
  return String(value || '').trim();
}

function clearAuthSessionBySessionId(entry: Ed25519AuthSessionCacheEntry | undefined): void {
  const sessionId = toSessionId(entry?.policy?.sessionId);
  if (!sessionId) return;
  authSessionBySessionId.delete(sessionId);
  deletePersistedEd25519AuthSessionJwt(sessionId);
}

function persistAuthSessionBySessionId(entry: Ed25519AuthSessionCacheEntry): void {
  if (entry.sessionKind !== 'jwt') return;
  const sessionId = toSessionId(entry?.policy?.sessionId);
  const jwt = toOptionalTrimmedString(entry?.jwt);
  if (!sessionId || !jwt) return;
  writePersistedEd25519AuthSessionJwt({
    sessionId,
    jwt,
    ...(typeof entry.expiresAtMs === 'number' && Number.isFinite(entry.expiresAtMs)
      ? { expiresAtMs: entry.expiresAtMs }
      : {}),
  });
}

export function makeEd25519AuthSessionCacheKey(args: {
  nearAccountId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds?: number[];
}): string {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds);
  return [
    String(args.nearAccountId || '').trim(),
    String(args.rpId || '').trim(),
    relayerUrl,
    String(args.relayerKeyId || '').trim(),
    ...(participantIds ? [participantIds.join(',')] : []),
  ].join('|');
}

export function getCachedEd25519AuthSession(cacheKey: string): Ed25519AuthSession | null {
  const entry = authSessionCache.get(cacheKey);
  if (!entry) return null;

  if (
    typeof entry.expiresAtMs === 'number' &&
    Number.isFinite(entry.expiresAtMs) &&
    Date.now() >= entry.expiresAtMs
  ) {
    authSessionCache.delete(cacheKey);
    clearAuthSessionBySessionId(entry);
    return null;
  }

  return entry;
}

export function putCachedEd25519AuthSession(cacheKey: string, entry: Ed25519AuthSession): void {
  const previous = authSessionCache.get(cacheKey);
  if (previous) clearAuthSessionBySessionId(previous);
  authSessionCache.set(cacheKey, entry);
  const sessionId = toSessionId(entry?.policy?.sessionId);
  if (sessionId) {
    authSessionBySessionId.set(sessionId, entry);
  }
  persistAuthSessionBySessionId(entry);
}

export function clearCachedEd25519AuthSession(cacheKey: string): void {
  const entry = authSessionCache.get(cacheKey);
  authSessionCache.delete(cacheKey);
  clearAuthSessionBySessionId(entry);
}

export function clearAllCachedEd25519AuthSessions(): void {
  authSessionCache.clear();
  authSessionBySessionId.clear();
  clearAllPersistedEd25519AuthSessionJwts();
}

export function getCachedEd25519AuthSessionJwt(cacheKey: string): string | undefined {
  const cached = getCachedEd25519AuthSession(cacheKey);
  const jwt = cached?.jwt;
  if (typeof jwt === 'string') {
    const trimmed = jwt.trim();
    if (trimmed) return trimmed;
  }
  if (cached) clearCachedEd25519AuthSession(cacheKey);
  return undefined;
}

export function getCachedEd25519AuthSessionBySessionId(
  sessionIdRaw: string,
): Ed25519AuthSession | null {
  const sessionId = toSessionId(sessionIdRaw);
  if (!sessionId) return null;

  const entry = authSessionBySessionId.get(sessionId);
  if (!entry) return null;

  if (
    typeof entry.expiresAtMs === 'number' &&
    Number.isFinite(entry.expiresAtMs) &&
    Date.now() >= entry.expiresAtMs
  ) {
    authSessionBySessionId.delete(sessionId);
    for (const [cacheKey, candidate] of authSessionCache.entries()) {
      if (candidate === entry) authSessionCache.delete(cacheKey);
    }
    return null;
  }

  return entry;
}

export function getCachedEd25519AuthSessionJwtBySessionId(
  sessionIdRaw: string,
): string | undefined {
  const cached = getCachedEd25519AuthSessionBySessionId(sessionIdRaw);
  const jwt = cached?.jwt;
  const trimmedCachedJwt = toOptionalTrimmedString(jwt);
  if (trimmedCachedJwt) return trimmedCachedJwt;

  const persisted = readPersistedEd25519AuthSessionJwt(sessionIdRaw);
  if (!persisted) return undefined;
  if (
    typeof persisted.expiresAtMs === 'number' &&
    Number.isFinite(persisted.expiresAtMs) &&
    Date.now() >= persisted.expiresAtMs
  ) {
    deletePersistedEd25519AuthSessionJwt(sessionIdRaw);
    return undefined;
  }
  return toOptionalTrimmedString(persisted.jwt);
}

/**
 * WebAuthn-only threshold session mint.
 *
 * The server verifies the WebAuthn assertion directly and binds the session to the
 * `sessionPolicyDigest32` by using it as the WebAuthn challenge bytes (base64url string).
 *
 * Notes:
 * - Callers must ensure the WebAuthn `challenge` equals `sessionPolicyDigest32`.
 * - PRF outputs must never be sent to the relay; they should be used only in wallet origin.
 */
export async function mintEd25519AuthSession(args: {
  relayerUrl: string;
  sessionKind: Ed25519SessionKind;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  sessionPolicy: Ed25519SessionPolicy;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  jwt?: string;
  code?: string;
  message?: string;
}> {
  const relayerUrl = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  if (!relayerUrl) {
    return {
      ok: false,
      code: 'invalid_args',
      message: 'Missing relayerUrl for threshold session mint',
    };
  }

  if (typeof fetch !== 'function') {
    return {
      ok: false,
      code: 'unsupported',
      message: 'fetch is not available for threshold session mint',
    };
  }

  // Never send PRF outputs to the relay.
  const webauthn_authentication = redactCredentialExtensionOutputs(args.webauthnAuthentication);

  type ThresholdEd25519SessionMintResponseBody = Partial<{
    ok: boolean;
    sessionId: string;
    expiresAt: string;
    remainingUses: number;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ed25519/session`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: args.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind: args.sessionKind,
        relayerKeyId: args.relayerKeyId,
        clientVerifyingShareB64u: args.clientVerifyingShareB64u,
        sessionPolicy: args.sessionPolicy,
        webauthn_authentication,
      }),
    });

    const data = (await response
      .json()
      .catch(() => ({}))) as ThresholdEd25519SessionMintResponseBody;
    if (!response.ok) {
      return {
        ok: false,
        code: data.code || 'http_error',
        message: data.message || `HTTP ${response.status}`,
      };
    }

    const expiresAtMs = (() => {
      const raw = data.expiresAt ? Date.parse(data.expiresAt) : NaN;
      return Number.isFinite(raw) ? raw : undefined;
    })();

    return {
      ok: data.ok === true,
      sessionId: data.sessionId,
      expiresAtMs,
      remainingUses: data.remainingUses,
      jwt: data.jwt,
      ...(data.code ? { code: data.code } : {}),
      ...(data.message ? { message: data.message } : {}),
    };
  } catch (e: unknown) {
    const msg = String(
      e && typeof e === 'object' && 'message' in e
        ? (e as { message?: unknown }).message
        : e || 'Failed to mint threshold session',
    );
    return { ok: false, code: 'network_error', message: msg };
  }
}
