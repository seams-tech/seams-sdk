import type { Ed25519AuthSessionStore } from '../../../../core/ThresholdService/stores/AuthSessionStore';
import type {
  PrfSessionSealConsumeUseResult,
  PrfSessionSealThresholdSessionPolicy,
  PrfSessionSealThresholdSessionRecord,
} from '../types';

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

function normalizeSessionRecord(
  thresholdSessionId: string,
  raw: Awaited<ReturnType<Ed25519AuthSessionStore['getSession']>>,
): PrfSessionSealThresholdSessionRecord | null {
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

function normalizeConsumeResult(
  raw: Awaited<ReturnType<Ed25519AuthSessionStore['consumeUseCount']>>,
): PrfSessionSealConsumeUseResult {
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

export function createPrfSessionSealPolicyFromEcdsaAuthSessionStore(
  store: Ed25519AuthSessionStore,
): PrfSessionSealThresholdSessionPolicy {
  return {
    getSession: async (thresholdSessionId: string) =>
      normalizeSessionRecord(thresholdSessionId, await store.getSession(thresholdSessionId)),
    consumeUseCount: async (thresholdSessionId: string) =>
      normalizeConsumeResult(await store.consumeUseCount(thresholdSessionId)),
  };
}
