import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type {
  ThresholdPrfFirstCacheClearPort,
  ThresholdPrfFirstCachePeekPort,
  ThresholdPrfFirstCacheWriterPort,
} from '../../touchConfirm';

export type SigningSessionPolicy = { ttlMs: number; remainingUses: number };
export type ActiveSigningSessionKind =
  | 'threshold-ed25519'
  | 'threshold-ecdsa-tempo'
  | 'threshold-ecdsa-evm';
export type SigningSessionCacheEntry = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
};

type SigningSessionPrfCacheWriter = ThresholdPrfFirstCacheWriterPort;
type SigningSessionPrfCacheClearer = ThresholdPrfFirstCacheClearPort;

export type SigningSessionStateDeps = {
  activeSigningSessionIds: Map<string, string>;
  touchConfirm: ThresholdPrfFirstCacheWriterPort &
    ThresholdPrfFirstCachePeekPort &
    ThresholdPrfFirstCacheClearPort;
  createSessionId: (prefix: string) => string;
  signingSessionDefaults: SigningSessionPolicy;
  resolveCanonicalSigningSessionIdForKind?: (args: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
  }) => string | null;
};

export type HydrateSigningSessionArgs = SigningSessionCacheEntry & {
  nearAccountId: AccountId | string;
  signerKind: ActiveSigningSessionKind;
  setActiveSigningSessionId?: boolean;
};

function toNonNegativeInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

export function generateSessionId(prefix: string): string {
  return typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export function serializeActiveSigningSessionKey(args: {
  nearAccountId: AccountId | string;
  signerKind: ActiveSigningSessionKind;
}): string {
  const nearAccountId = String(toAccountId(args.nearAccountId)).trim();
  const signerKind = String(args.signerKind || '').trim();
  if (!nearAccountId || !signerKind) {
    throw new Error('Invalid active signing session key input');
  }
  return `${nearAccountId}|${signerKind}`;
}

function normalizeSigningSessionCacheEntry(
  args: SigningSessionCacheEntry,
): SigningSessionCacheEntry {
  const sessionId = String(args.sessionId || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const expiresAtMsRaw = Number(args.expiresAtMs);
  const remainingUses = toNonNegativeInt(args.remainingUses);
  if (!sessionId || !prfFirstB64u) {
    throw new Error('Missing sessionId or prfFirstB64u for signing session hydration');
  }
  if (!Number.isFinite(expiresAtMsRaw) || expiresAtMsRaw <= 0) {
    throw new Error('Invalid expiresAtMs for signing session hydration');
  }
  if (remainingUses == null) {
    throw new Error('Invalid remainingUses for signing session hydration');
  }
  return {
    sessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMsRaw),
    remainingUses,
  };
}

async function cacheSigningSessionPrfFirst(
  writer: SigningSessionPrfCacheWriter,
  args: SigningSessionCacheEntry,
): Promise<void> {
  const normalized = normalizeSigningSessionCacheEntry(args);
  await writer.putPrfFirstForThresholdSession({
    sessionId: normalized.sessionId,
    prfFirstB64u: normalized.prfFirstB64u,
    expiresAtMs: normalized.expiresAtMs,
    remainingUses: normalized.remainingUses,
  });
}

export async function cacheSigningSessionPrfFirstBestEffort(
  writer: SigningSessionPrfCacheWriter,
  args: SigningSessionCacheEntry,
): Promise<void> {
  await cacheSigningSessionPrfFirst(writer, args).catch(() => undefined);
}

export async function clearSigningSessionPrfFirstBestEffort(
  clearer: SigningSessionPrfCacheClearer,
  sessionIdRaw: string,
): Promise<void> {
  const sessionId = String(sessionIdRaw || '').trim();
  if (!sessionId) return;
  await clearer.clearPrfFirstForThresholdSession({ sessionId }).catch(() => undefined);
}

export function getOrCreateActiveSigningSessionIdForKind(
  deps: SigningSessionStateDeps,
  args: {
    nearAccountId: AccountId;
    signerKind: ActiveSigningSessionKind;
  },
): string {
  const key = serializeActiveSigningSessionKey({
    nearAccountId: args.nearAccountId,
    signerKind: args.signerKind,
  });
  const existing = deps.activeSigningSessionIds.get(key);
  if (existing) return existing;
  if (typeof deps.resolveCanonicalSigningSessionIdForKind === 'function') {
    const canonicalSessionId = String(
      deps.resolveCanonicalSigningSessionIdForKind({
        nearAccountId: args.nearAccountId,
        signerKind: args.signerKind,
      }) || '',
    ).trim();
    if (canonicalSessionId) {
      deps.activeSigningSessionIds.set(key, canonicalSessionId);
      return canonicalSessionId;
    }
  }
  const sessionId = deps.createSessionId(args.signerKind);
  deps.activeSigningSessionIds.set(key, sessionId);
  return sessionId;
}

export function setActiveSigningSessionIdForKind(
  deps: SigningSessionStateDeps,
  args: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
    sessionId: string;
  },
): void {
  const key = serializeActiveSigningSessionKey({
    nearAccountId: args.nearAccountId,
    signerKind: args.signerKind,
  });
  const normalizedSessionId = String(args.sessionId || '').trim();
  if (!normalizedSessionId) {
    deps.activeSigningSessionIds.delete(key);
    return;
  }
  deps.activeSigningSessionIds.set(key, normalizedSessionId);
}

export function clearActiveSigningSessionIdForKind(
  deps: SigningSessionStateDeps,
  args: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
  },
): string | null {
  const key = serializeActiveSigningSessionKey({
    nearAccountId: args.nearAccountId,
    signerKind: args.signerKind,
  });
  const existing = String(deps.activeSigningSessionIds.get(key) || '').trim();
  deps.activeSigningSessionIds.delete(key);
  return existing || null;
}

export function clearAllActiveSigningSessionIdsForAccount(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId | string,
): string[] {
  const normalizedNearAccountId = String(toAccountId(nearAccountId)).trim();
  const sessionIds: string[] = [];
  for (const [key, sessionIdRaw] of deps.activeSigningSessionIds.entries()) {
    if (!key.startsWith(`${normalizedNearAccountId}|`)) continue;
    const sessionId = String(sessionIdRaw || '').trim();
    if (sessionId) sessionIds.push(sessionId);
    deps.activeSigningSessionIds.delete(key);
  }
  return sessionIds;
}

export function clearAllActiveSigningSessionIds(deps: SigningSessionStateDeps): string[] {
  const sessionIds: string[] = [];
  for (const sessionIdRaw of deps.activeSigningSessionIds.values()) {
    const sessionId = String(sessionIdRaw || '').trim();
    if (sessionId) sessionIds.push(sessionId);
  }
  deps.activeSigningSessionIds.clear();
  return sessionIds;
}

export async function hydrateSigningSession(
  deps: SigningSessionStateDeps,
  args: HydrateSigningSessionArgs,
): Promise<void> {
  const normalized = normalizeSigningSessionCacheEntry(args);
  await cacheSigningSessionPrfFirst(deps.touchConfirm, normalized);

  if (args.setActiveSigningSessionId !== false) {
    setActiveSigningSessionIdForKind(deps, {
      nearAccountId: args.nearAccountId,
      signerKind: args.signerKind,
      sessionId: normalized.sessionId,
    });
  }
}

export async function getWarmSigningSessionStatusForKind(
  deps: SigningSessionStateDeps,
  args: {
    nearAccountId: AccountId | string;
    signerKind: ActiveSigningSessionKind;
  },
): Promise<SigningSessionStatus | null> {
  try {
    const key = serializeActiveSigningSessionKey({
      nearAccountId: args.nearAccountId,
      signerKind: args.signerKind,
    });
    let sessionId = deps.activeSigningSessionIds.get(key);
    if (!sessionId && typeof deps.resolveCanonicalSigningSessionIdForKind === 'function') {
      const canonicalSessionId = String(
        deps.resolveCanonicalSigningSessionIdForKind({
          nearAccountId: args.nearAccountId,
          signerKind: args.signerKind,
        }) || '',
      ).trim();
      if (canonicalSessionId) {
        deps.activeSigningSessionIds.set(key, canonicalSessionId);
        sessionId = canonicalSessionId;
      }
    }
    if (!sessionId) return null;

    const peek = await deps.touchConfirm.peekPrfFirstForThresholdSession({ sessionId });
    if (peek.ok) {
      return {
        sessionId,
        status: 'active',
        remainingUses: peek.remainingUses,
        expiresAtMs: peek.expiresAtMs,
      };
    }

    let status: SigningSessionStatus['status'] = 'not_found';
    if (peek.code === 'expired') {
      status = 'expired';
    } else if (peek.code === 'exhausted') {
      status = 'exhausted';
    }
    return { sessionId, status };
  } catch {
    return null;
  }
}
