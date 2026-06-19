import type { Ed25519WalletSessionStore } from '../../../../core/ThresholdService/stores/WalletSessionStore';
import { walletSigningBudgetSessionId } from '../../../../core/ThresholdService/walletSigningBudget';
import type {
  SigningSessionSealCurve,
  SigningSessionSealConsumeUseResult,
  SigningSessionSealThresholdSessionStatus,
  SigningSessionSealThresholdSessionPolicy,
  SigningSessionSealThresholdSessionRecord,
  SigningSessionSealThresholdStatusLookup,
  SigningSessionSealWalletBudgetStatus,
  SigningSessionSealWalletBudgetStatusLookup,
} from '../types';

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

function normalizeSessionRecord(
  input: {
    curve: SigningSessionSealCurve;
    thresholdSessionId: string;
  },
  raw: Awaited<ReturnType<Ed25519WalletSessionStore['getSession']>>,
): SigningSessionSealThresholdSessionRecord | null {
  if (!raw) return null;
  const userId = String(raw.userId || '').trim();
  const expiresAtMs = Number(raw.expiresAtMs);
  const relayerKeyId = String(raw.relayerKeyId || '').trim();
  const rpId = String(raw.rpId || '').trim();
  const participantIds = Array.isArray(raw.participantIds)
    ? raw.participantIds.map((value) => Math.floor(Number(value))).filter(Number.isFinite)
    : [];
  if (
    !userId ||
    !relayerKeyId ||
    !rpId ||
    participantIds.length < 2 ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  return {
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    userId,
    expiresAtMs: Math.floor(expiresAtMs),
    relayerKeyId,
    rpId,
    participantIds,
    ...(typeof raw.signingRootId === 'string' && raw.signingRootId.trim()
      ? { signingRootId: raw.signingRootId.trim() }
      : {}),
    ...(typeof raw.signingRootVersion === 'string' && raw.signingRootVersion.trim()
      ? { signingRootVersion: raw.signingRootVersion.trim() }
      : {}),
  };
}

function normalizeThresholdSessionStatus(
  input: {
    curve: SigningSessionSealCurve;
    thresholdSessionId: string;
  },
  raw: Awaited<ReturnType<Ed25519WalletSessionStore['getSessionStatus']>>,
): SigningSessionSealThresholdSessionStatus | null {
  if (!raw) return null;
  const normalized = normalizeSessionRecord(input, raw.record);
  const remainingUses = toNonNegativeInt(raw.remainingUses);
  if (!normalized || remainingUses === undefined) return null;
  return {
    ...normalized,
    kind: 'wallet_session',
    expiresAtMs: Math.floor(Number(raw.expiresAtMs) || normalized.expiresAtMs),
    remainingUses,
  };
}

function normalizeWalletBudgetStatus(
  input: {
    curve: SigningSessionSealCurve;
    walletSigningSessionId: string;
    thresholdSessionId: string;
  },
  raw: Awaited<ReturnType<Ed25519WalletSessionStore['getSessionStatus']>>,
): SigningSessionSealWalletBudgetStatus | null {
  if (!raw) return null;
  const normalized = normalizeSessionRecord(
    {
      curve: input.curve,
      thresholdSessionId: input.thresholdSessionId,
    },
    raw.record,
  );
  const committedRemainingUses = toNonNegativeInt(raw.committedRemainingUses);
  const reservedUses = toNonNegativeInt(raw.reservedUses);
  const availableUses = toNonNegativeInt(raw.availableUses);
  const remainingUses = toNonNegativeInt(raw.remainingUses);
  if (!normalized || remainingUses === undefined) return null;
  return {
    ...normalized,
    kind: 'wallet_budget',
    walletSigningSessionId: input.walletSigningSessionId,
    expiresAtMs: Math.floor(Number(raw.expiresAtMs) || normalized.expiresAtMs),
    committedRemainingUses: committedRemainingUses ?? remainingUses,
    reservedUses: reservedUses ?? 0,
    availableUses: availableUses ?? remainingUses,
    remainingUses,
  };
}

function normalizeConsumeResult(
  raw: Awaited<ReturnType<Ed25519WalletSessionStore['consumeUseCount']>>,
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
  input: SigningSessionSealThresholdStatusLookup,
  stores: readonly Ed25519WalletSessionStore[],
): Promise<SigningSessionSealThresholdSessionRecord | null> {
  return (async () => {
    for (const store of stores) {
      const normalized = normalizeSessionRecord(input, await store.getSession(input.thresholdSessionId));
      if (normalized) return normalized;
    }
    return null;
  })();
}

function normalizeStatusesAcrossStores(
  input: SigningSessionSealThresholdStatusLookup,
  stores: readonly Ed25519WalletSessionStore[],
): Promise<SigningSessionSealThresholdSessionStatus[]> {
  return (async () => {
    const statuses: SigningSessionSealThresholdSessionStatus[] = [];
    for (const store of stores) {
      const normalized = normalizeThresholdSessionStatus(
        input,
        await store.getSessionStatus(input.thresholdSessionId),
      );
      if (normalized) statuses.push(normalized);
    }
    return statuses;
  })();
}

function normalizeWalletBudgetStatusAcrossStores(
  input: SigningSessionSealWalletBudgetStatusLookup,
  stores: readonly Ed25519WalletSessionStore[],
): Promise<SigningSessionSealWalletBudgetStatus | null> {
  return (async () => {
    const thresholdSessionId = walletSigningBudgetSessionId(input.walletSigningSessionId);
    for (const store of stores) {
      const normalized = normalizeWalletBudgetStatus(
        input,
        await store.getSessionStatus(thresholdSessionId),
      );
      if (normalized) return normalized;
    }
    return null;
  })();
}

function normalizeConsumeAcrossStores(
  input: SigningSessionSealThresholdStatusLookup,
  stores: readonly Ed25519WalletSessionStore[],
): Promise<SigningSessionSealConsumeUseResult> {
  return (async () => {
    for (const store of stores) {
      const raw = await store.getSession(input.thresholdSessionId);
      if (!raw) continue;
      return normalizeConsumeResult(await store.consumeUseCount(input.thresholdSessionId));
    }
    return {
      ok: false,
      code: 'not_found',
      message: 'Unknown or expired threshold session',
    };
  })();
}

export function createSigningSessionSealPolicyFromWalletSessionStores(input: {
  ed25519Stores?: readonly Ed25519WalletSessionStore[] | null;
  ecdsaStores?: readonly Ed25519WalletSessionStore[] | null;
  walletBudgetStores: readonly Ed25519WalletSessionStore[];
}): SigningSessionSealThresholdSessionPolicy {
  const ed25519Stores = (input.ed25519Stores || []).filter(Boolean);
  const ecdsaStores = (input.ecdsaStores || []).filter(Boolean);
  const walletBudgetStores = input.walletBudgetStores.filter(Boolean);

  function storesForLookup(
    input: SigningSessionSealThresholdStatusLookup | SigningSessionSealWalletBudgetStatusLookup,
  ): readonly Ed25519WalletSessionStore[] {
    return input.curve === 'ecdsa' ? ecdsaStores : ed25519Stores;
  }

  return {
    getThresholdSession: async (input: SigningSessionSealThresholdStatusLookup) =>
      await normalizeStoreResult(input, storesForLookup(input)),
    getThresholdSessionStatuses: async (input: SigningSessionSealThresholdStatusLookup) =>
      await normalizeStatusesAcrossStores(input, storesForLookup(input)),
    getWalletBudgetStatus: async (input: SigningSessionSealWalletBudgetStatusLookup) =>
      await normalizeWalletBudgetStatusAcrossStores(input, walletBudgetStores),
    consumeUseCount: async (input: SigningSessionSealThresholdStatusLookup) =>
      await normalizeConsumeAcrossStores(input, storesForLookup(input)),
  };
}
