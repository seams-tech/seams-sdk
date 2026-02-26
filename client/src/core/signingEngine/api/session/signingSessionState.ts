import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { SigningSessionStatus } from '@/core/types/tatchi';
import type {
  ThresholdPrfFirstCacheClearPort,
  ThresholdPrfFirstCachePeekPort,
  ThresholdPrfFirstCacheWriterPort,
} from '../../touchConfirm';

export type SigningSessionPolicy = { ttlMs: number; remainingUses: number };
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
  touchConfirm: ThresholdPrfFirstCacheWriterPort
    & ThresholdPrfFirstCachePeekPort
    & ThresholdPrfFirstCacheClearPort;
  createSessionId: (prefix: string) => string;
  signingSessionDefaults: SigningSessionPolicy;
};

export type HydrateSigningSessionArgs = SigningSessionCacheEntry & {
  nearAccountId: AccountId | string;
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

export function getOrCreateActiveSigningSessionId(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId,
): string {
  const key = String(toAccountId(nearAccountId));
  const existing = deps.activeSigningSessionIds.get(key);
  if (existing) return existing;
  const sessionId = deps.createSessionId('signing-session');
  deps.activeSigningSessionIds.set(key, sessionId);
  return sessionId;
}

export function setActiveSigningSessionId(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId | string,
  sessionId: string,
): void {
  const key = String(toAccountId(nearAccountId));
  const normalizedSessionId = String(sessionId || '').trim();
  if (!normalizedSessionId) {
    deps.activeSigningSessionIds.delete(key);
    return;
  }
  deps.activeSigningSessionIds.set(key, normalizedSessionId);
}

export function clearActiveSigningSessionId(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId | string,
): string | null {
  const key = String(toAccountId(nearAccountId));
  const existing = String(deps.activeSigningSessionIds.get(key) || '').trim();
  deps.activeSigningSessionIds.delete(key);
  return existing || null;
}

export function clearAllActiveSigningSessionIds(
  deps: SigningSessionStateDeps,
): string[] {
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
    setActiveSigningSessionId(deps, args.nearAccountId, normalized.sessionId);
  }
}

export async function getWarmSigningSessionStatus(
  deps: SigningSessionStateDeps,
  nearAccountId: AccountId | string,
): Promise<SigningSessionStatus | null> {
  try {
    const key = String(toAccountId(nearAccountId));
    const sessionId = deps.activeSigningSessionIds.get(key);
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
