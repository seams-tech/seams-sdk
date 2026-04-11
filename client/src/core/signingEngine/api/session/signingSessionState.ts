import type {
  WarmSessionMaterialClearer,
  WarmSessionMaterialWriter,
} from '../../touchConfirm';

export type SigningSessionCacheEntry = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: {
    curve?: 'ed25519' | 'ecdsa';
    relayerUrl?: string;
    thresholdSessionJwt?: string;
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
};

type SigningSessionPrfCacheWriter = WarmSessionMaterialWriter;
type SigningSessionPrfCacheClearer = WarmSessionMaterialClearer;

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

export async function cacheSigningSessionPrfFirst(
  writer: SigningSessionPrfCacheWriter,
  args: SigningSessionCacheEntry,
): Promise<void> {
  const normalized = normalizeSigningSessionCacheEntry(args);
  await writer.putWarmSessionMaterial({
    sessionId: normalized.sessionId,
    prfFirstB64u: normalized.prfFirstB64u,
    expiresAtMs: normalized.expiresAtMs,
    remainingUses: normalized.remainingUses,
    ...(args.transport ? { transport: args.transport } : {}),
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
  await clearer.clearWarmSessionMaterial({ sessionId }).catch(() => undefined);
}
