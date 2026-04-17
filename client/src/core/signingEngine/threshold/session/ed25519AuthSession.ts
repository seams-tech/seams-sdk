import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';
import {
  normalizeJwtCookieSessionKind,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import {
  buildEd25519SessionPolicy,
  parseThresholdRuntimePolicyScopeFromJwt,
  type Ed25519SessionPolicy,
  type ThresholdRuntimePolicyScope,
} from './sessionPolicy';
import type { Ed25519SessionKind } from './ed25519SessionTypes';
import type { WebAuthnAuthenticationCredential } from '@/core/types/webauthn';
import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { redactCredentialExtensionOutputs } from '../webauthn';
import {
  getStoredThresholdEd25519SessionRecordByThresholdSessionId,
  type ThresholdEd25519SessionStoreSource,
} from '../../api/thresholdLifecycle/thresholdSessionStore';
import { persistWarmSessionEd25519Capability } from '../../session/warmSessionPersistence';

export type Ed25519AuthSession = {
  sessionKind: Ed25519SessionKind;
  policy: Ed25519SessionPolicy;
  policyJson: string;
  sessionPolicyDigest32: string;
  jwt?: string;
  expiresAtMs?: number;
};

type Ed25519AuthSessionCacheEntry = Ed25519AuthSession;

export type Ed25519ResolvedAuthSession = {
  sessionKind: Ed25519SessionKind;
  jwt?: string;
};

const authSessionCache = new Map<string, Ed25519AuthSessionCacheEntry>();
const authSessionBySessionId = new Map<string, Ed25519AuthSessionCacheEntry>();

function toSessionId(value: unknown): string {
  return String(value || '').trim();
}

function clearAuthSessionBySessionId(entry: Ed25519AuthSessionCacheEntry | undefined): void {
  const sessionId = toSessionId(entry?.policy?.sessionId);
  if (!sessionId) return;
  authSessionBySessionId.delete(sessionId);
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
}

export async function buildAndCacheEd25519AuthSession(args: {
  nearAccountId: string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  participantIds?: number[];
  sessionKind?: Ed25519SessionKind;
  sessionId: string;
  expiresAtMs: number;
  remainingUses: number;
  jwt?: string;
  policyTtlMs?: number;
  policyRemainingUses?: number;
  source?: ThresholdEd25519SessionStoreSource;
}): Promise<Ed25519AuthSession> {
  const sessionId = String(args.sessionId || '').trim();
  const expiresAtMs = Math.floor(Number(args.expiresAtMs));
  const remainingUses = normalizePositiveInteger(args.remainingUses) ?? 0;
  if (!sessionId) throw new Error('Missing sessionId for Ed25519 auth-session cache');
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('Invalid expiresAtMs for Ed25519 auth-session cache');
  }
  if (remainingUses <= 0) {
    throw new Error('Invalid remainingUses for Ed25519 auth-session cache');
  }

  const policyTtlMs = (() => {
    const explicit = normalizePositiveInteger(args.policyTtlMs) ?? 0;
    if (explicit > 0) return explicit;
    return Math.max(1, Math.floor(expiresAtMs - Date.now()));
  })();
  const policyRemainingUses = (() => {
    const explicit = normalizePositiveInteger(args.policyRemainingUses) ?? 0;
    if (explicit > 0) return explicit;
    return remainingUses;
  })();
  const participantIds = normalizeThresholdEd25519ParticipantIds(args.participantIds) || undefined;
  const runtimePolicyScope =
    args.runtimePolicyScope ||
    parseThresholdRuntimePolicyScopeFromJwt(String(args.jwt || '').trim());

  const { policy, policyJson, sessionPolicyDigest32 } = await buildEd25519SessionPolicy({
    nearAccountId: String(args.nearAccountId || '').trim(),
    rpId: String(args.rpId || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    participantIds,
    sessionId,
    ttlMs: policyTtlMs,
    remainingUses: policyRemainingUses,
  });

  const entry: Ed25519AuthSession = {
    sessionKind: normalizeJwtCookieSessionKind(args.sessionKind),
    policy,
    policyJson,
    sessionPolicyDigest32,
    ...(String(args.jwt || '').trim() ? { jwt: String(args.jwt || '').trim() } : {}),
    expiresAtMs,
  };

  const cacheKey = makeEd25519AuthSessionCacheKey({
    nearAccountId: String(args.nearAccountId || '').trim(),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds,
  });
  putCachedEd25519AuthSession(cacheKey, entry);
  persistWarmSessionEd25519Capability({
    nearAccountId: String(args.nearAccountId || '').trim(),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    participantIds,
    sessionKind: entry.sessionKind,
    sessionId,
    ...(String(entry.jwt || '').trim() ? { jwt: String(entry.jwt || '').trim() } : {}),
    expiresAtMs,
    remainingUses,
    updatedAtMs: Date.now(),
    source: args.source || 'manual-connect',
  });

  return entry;
}

export function clearCachedEd25519AuthSession(cacheKey: string): void {
  const entry = authSessionCache.get(cacheKey);
  authSessionCache.delete(cacheKey);
  clearAuthSessionBySessionId(entry);
}

export function clearAllCachedEd25519AuthSessions(): void {
  authSessionCache.clear();
  authSessionBySessionId.clear();
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

function toResolvedEd25519AuthSession(
  entry: Ed25519AuthSession | null | undefined,
): Ed25519ResolvedAuthSession | null {
  if (!entry) return null;
  const sessionKind: Ed25519SessionKind = entry.sessionKind === 'cookie' ? 'cookie' : 'jwt';
  if (sessionKind === 'cookie') {
    return { sessionKind: 'cookie' };
  }
  const jwt = normalizeOptionalNonEmptyString(entry.jwt);
  if (!jwt) return null;
  return {
    sessionKind: 'jwt',
    jwt,
  };
}

export async function resolveEd25519AuthSessionBySessionId(
  sessionIdRaw: string,
): Promise<Ed25519ResolvedAuthSession | null> {
  const sessionId = toSessionId(sessionIdRaw);
  if (!sessionId) return null;

  const cached = toResolvedEd25519AuthSession(getCachedEd25519AuthSessionBySessionId(sessionId));
  if (cached) return cached;

  const record = getStoredThresholdEd25519SessionRecordByThresholdSessionId(sessionId);
  if (!record) return null;
  const recordSessionKind: Ed25519SessionKind =
    record.thresholdSessionKind === 'cookie' ? 'cookie' : 'jwt';
  const recordJwt = normalizeOptionalNonEmptyString(record.thresholdSessionJwt);
  if (recordSessionKind === 'jwt' && !recordJwt) return null;
  if (
    typeof record.expiresAtMs !== 'number' ||
    !Number.isFinite(record.expiresAtMs) ||
    record.expiresAtMs <= 0 ||
    Date.now() >= record.expiresAtMs
  ) {
    return null;
  }

  const rehydratedTtlMs = Math.max(1, Math.floor(record.expiresAtMs - Date.now()));
  const rehydratedRemainingUses = Math.max(1, normalizePositiveInteger(record.remainingUses) || 1);
  try {
    await buildAndCacheEd25519AuthSession({
      nearAccountId: String(record.nearAccountId || '').trim(),
      rpId: String(record.rpId || '').trim(),
      relayerUrl: String(record.relayerUrl || '').trim(),
      relayerKeyId: String(record.relayerKeyId || '').trim(),
      ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
      participantIds: record.participantIds,
      sessionKind: recordSessionKind,
      sessionId: String(record.thresholdSessionId || '').trim(),
      expiresAtMs: Math.floor(record.expiresAtMs),
      remainingUses: rehydratedRemainingUses,
      jwt: recordJwt,
      policyTtlMs: rehydratedTtlMs,
      policyRemainingUses: rehydratedRemainingUses,
      source: record.source,
    });
  } catch {
    return null;
  }

  const hydrated = toResolvedEd25519AuthSession(
    getCachedEd25519AuthSessionBySessionId(record.thresholdSessionId),
  );
  const resolved: Ed25519ResolvedAuthSession | null =
    hydrated ||
    (recordSessionKind === 'cookie'
      ? { sessionKind: 'cookie' }
      : recordJwt
        ? { sessionKind: 'jwt', jwt: recordJwt }
        : null);
  return resolved;
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
  sessionPolicy: Ed25519SessionPolicy;
  webauthnAuthentication: WebAuthnAuthenticationCredential;
  runtimeEnvironmentId?: string;
  publishableKey?: string;
}): Promise<{
  ok: boolean;
  sessionId?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
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
    runtimePolicyScope: ThresholdRuntimePolicyScope;
    jwt: string;
    code: string;
    message: string;
  }>;

  try {
    const url = `${relayerUrl}/threshold-ed25519/session`;
    const runtimeEnvironmentId = String(args.runtimeEnvironmentId || '').trim() || undefined;
    const publishableKey = String(args.publishableKey || '').trim() || undefined;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...(publishableKey ? { Authorization: `Bearer ${publishableKey}` } : {}),
      },
      credentials: args.sessionKind === 'cookie' ? 'include' : 'omit',
      body: JSON.stringify({
        sessionKind: args.sessionKind,
        relayerKeyId: args.relayerKeyId,
        sessionPolicy: args.sessionPolicy,
        ...(runtimeEnvironmentId ? { runtimeEnvironmentId } : {}),
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
      ...(data.runtimePolicyScope ? { runtimePolicyScope: data.runtimePolicyScope } : {}),
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
