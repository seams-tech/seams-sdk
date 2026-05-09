import type { Ed25519AuthSessionStore } from '../../../../core/ThresholdService/stores/AuthSessionStore';
import type {
  SigningSessionSealConsumeUseResult,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionRecord,
} from '../types';

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

function normalizeSessionRecord(
  thresholdSessionId: string,
  raw: Awaited<ReturnType<Ed25519AuthSessionStore['getSession']>>,
): SigningSessionSealThresholdSessionRecord | null {
  if (!raw) return null;
  const userId = String(raw.userId || '').trim();
  const expiresAtMs = Number(raw.expiresAtMs);
  if (!userId || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return null;
  return {
    thresholdSessionId,
    userId,
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function normalizeSessionStatus(
  thresholdSessionId: string,
  raw: Awaited<ReturnType<Ed25519AuthSessionStore['getSessionStatus']>>,
): SigningSessionSealThresholdSessionStatus | null {
  if (!raw) return null;
  const normalized = normalizeSessionRecord(thresholdSessionId, raw.record);
  const remainingUses = toNonNegativeInt(raw.remainingUses);
  if (!normalized || remainingUses === undefined) return null;
  return {
    ...normalized,
    expiresAtMs: Math.floor(Number(raw.expiresAtMs) || normalized.expiresAtMs),
    remainingUses,
    record: raw.record,
  };
}

function normalizeConsumeResult(
  raw: Awaited<ReturnType<Ed25519AuthSessionStore['consumeUseCount']>>,
): SigningSessionSealConsumeUseResult {
  if (!raw.ok) {
    return {
      ok: false,
      code: String(raw.code || 'unauthorized'),
      message: String(raw.message || 'threshold session rejected'),
    };
  }
  return {
    ok: true,
    remainingUses: toNonNegativeInt(raw.remainingUses),
  };
}

function normalizeStoreResult(
  thresholdSessionId: string,
  stores: readonly Ed25519AuthSessionStore[],
): Promise<SigningSessionSealThresholdSessionRecord | null> {
  return (async () => {
    for (const store of stores) {
      const normalized = normalizeSessionRecord(thresholdSessionId, await store.getSession(thresholdSessionId));
      if (normalized) return normalized;
    }
    return null;
  })();
}

function normalizeStatusAcrossStores(
  thresholdSessionId: string,
  stores: readonly Ed25519AuthSessionStore[],
): Promise<SigningSessionSealThresholdSessionStatus | null> {
  return (async () => {
    for (const store of stores) {
      const normalized = normalizeSessionStatus(
        thresholdSessionId,
        await store.getSessionStatus(thresholdSessionId),
      );
      if (normalized) return normalized;
    }
    return null;
  })();
}

function normalizeStatusesAcrossStores(
  thresholdSessionId: string,
  stores: readonly Ed25519AuthSessionStore[],
): Promise<SigningSessionSealThresholdSessionStatus[]> {
  return (async () => {
    const statuses: SigningSessionSealThresholdSessionStatus[] = [];
    for (const store of stores) {
      const normalized = normalizeSessionStatus(
        thresholdSessionId,
        await store.getSessionStatus(thresholdSessionId),
      );
      if (normalized) statuses.push(normalized);
    }
    return statuses;
  })();
}

function normalizeConsumeAcrossStores(
  thresholdSessionId: string,
  stores: readonly Ed25519AuthSessionStore[],
): Promise<SigningSessionSealConsumeUseResult> {
  return (async () => {
    for (const store of stores) {
      const raw = await store.getSession(thresholdSessionId);
      if (!raw) continue;
      return normalizeConsumeResult(await store.consumeUseCount(thresholdSessionId));
    }
    return {
      ok: false,
      code: 'not_found',
      message: 'Unknown or expired threshold session',
    };
  })();
}

export function createSigningSessionSealPolicyFromThresholdAuthSessionStores(input: {
  stores: readonly Ed25519AuthSessionStore[];
}): SigningSessionSealThresholdSessionPolicy {
  const stores = input.stores.filter(Boolean);
  return {
    getSession: async (thresholdSessionId: string) =>
      await normalizeStoreResult(thresholdSessionId, stores),
    getSessionStatus: async (thresholdSessionId: string) =>
      await normalizeStatusAcrossStores(thresholdSessionId, stores),
    getSessionStatuses: async (thresholdSessionId: string) =>
      await normalizeStatusesAcrossStores(thresholdSessionId, stores),
    consumeUseCount: async (thresholdSessionId: string) =>
      await normalizeConsumeAcrossStores(thresholdSessionId, stores),
  };
}
