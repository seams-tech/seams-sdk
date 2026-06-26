import type {
  EcdsaWalletSessionRecord,
  EcdsaWalletSessionStatus,
  EcdsaWalletSessionStore,
  Ed25519WalletSessionRecord,
  Ed25519WalletSessionStatus,
  Ed25519WalletSessionStore,
  WalletSessionConsumeUsesResult,
  WalletSigningBudgetSessionRecord,
  WalletSigningBudgetSessionStatus,
  WalletSigningBudgetSessionStore,
} from '../../../../core/ThresholdService/stores/WalletSessionStore';
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
} from '../signingSessionSeal.types';

function toNonNegativeInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  return Math.max(0, Math.floor(parsed));
}

type SigningSessionSealWalletSessionRecord =
  | Ed25519WalletSessionRecord
  | EcdsaWalletSessionRecord;

type SigningSessionSealWalletSessionStatus =
  | Ed25519WalletSessionStatus
  | EcdsaWalletSessionStatus;

type SigningSessionSealWalletSessionStore = {
  getSession(id: string): Promise<SigningSessionSealWalletSessionRecord | null>;
  getSessionStatus(id: string): Promise<SigningSessionSealWalletSessionStatus | null>;
  consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult>;
};

function normalizeSessionRecord(
  input: {
    curve: SigningSessionSealCurve;
    thresholdSessionId: string;
  },
  raw: SigningSessionSealWalletSessionRecord | null,
): SigningSessionSealThresholdSessionRecord | null {
  if (!raw) return null;
  const expiresAtMs = Number(raw.expiresAtMs);
  const relayerKeyId = String(raw.relayerKeyId || '').trim();
  const participantIds = Array.isArray(raw.participantIds)
    ? raw.participantIds.map((value) => Math.floor(Number(value))).filter(Number.isFinite)
    : [];
  if (!relayerKeyId || participantIds.length < 2 || !Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    return null;
  }
  const base = {
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    expiresAtMs: Math.floor(expiresAtMs),
    relayerKeyId,
    participantIds,
  };
  switch (input.curve) {
    case 'ecdsa': {
      if (!('walletKeyId' in raw)) return null;
      const userId = String(raw.walletId || '').trim();
      const walletKeyId = String(raw.walletKeyId || '').trim();
      if (!userId || !walletKeyId) return null;
      return {
        ...base,
        curve: 'ecdsa',
        userId,
        walletKeyId,
      };
    }
    case 'ed25519': {
      if (!('userId' in raw)) return null;
      const userId = String(raw.userId || '').trim();
      const rpId = String(raw.rpId || '').trim();
      if (!userId || !rpId) return null;
      return {
        ...base,
        curve: 'ed25519',
        userId,
        rpId,
      };
    }
  }
}

function normalizeWalletBudgetRecord(
  input: {
    curve: SigningSessionSealCurve;
    thresholdSessionId: string;
  },
  raw: WalletSigningBudgetSessionRecord | null,
): SigningSessionSealThresholdSessionRecord | null {
  if (!raw) return null;
  const userId = String(raw.walletId || '').trim();
  const expiresAtMs = Number(raw.expiresAtMs);
  const relayerKeyId = String(raw.relayerKeyId || '').trim();
  const participantIds = Array.isArray(raw.participantIds)
    ? raw.participantIds.map((value) => Math.floor(Number(value))).filter(Number.isFinite)
    : [];
  const bindingMatches =
    raw.binding.curve === input.curve && raw.binding.thresholdSessionId === input.thresholdSessionId;
  if (
    !userId ||
    !relayerKeyId ||
    !bindingMatches ||
    participantIds.length < 2 ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= 0
  ) {
    return null;
  }
  const base = {
    curve: input.curve,
    thresholdSessionId: input.thresholdSessionId,
    userId,
    expiresAtMs: Math.floor(expiresAtMs),
    relayerKeyId,
    participantIds,
  };
  switch (input.curve) {
    case 'ecdsa':
      if (raw.budgetScope.kind !== 'wallet_key') return null;
      return {
        ...base,
        curve: 'ecdsa',
        walletKeyId: raw.budgetScope.walletKeyId,
      };
    case 'ed25519':
      if (raw.budgetScope.kind !== 'passkey_rp') return null;
      return {
        ...base,
        curve: 'ed25519',
        rpId: raw.budgetScope.rpId,
      };
  }
}

function normalizeThresholdSessionStatus(
  input: {
    curve: SigningSessionSealCurve;
    thresholdSessionId: string;
  },
  raw: SigningSessionSealWalletSessionStatus | null,
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
    signingGrantId: string;
    thresholdSessionId: string;
  },
  raw: WalletSigningBudgetSessionStatus | null,
): SigningSessionSealWalletBudgetStatus | null {
  if (!raw) return null;
  const normalized = normalizeWalletBudgetRecord(
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
    signingGrantId: input.signingGrantId,
    expiresAtMs: Math.floor(Number(raw.expiresAtMs) || normalized.expiresAtMs),
    committedRemainingUses: committedRemainingUses ?? remainingUses,
    reservedUses: reservedUses ?? 0,
    availableUses: availableUses ?? remainingUses,
    remainingUses,
  };
}

function normalizeConsumeResult(
  raw: WalletSessionConsumeUsesResult,
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
  stores: readonly SigningSessionSealWalletSessionStore[],
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
  stores: readonly SigningSessionSealWalletSessionStore[],
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
  stores: readonly WalletSigningBudgetSessionStore[],
): Promise<SigningSessionSealWalletBudgetStatus | null> {
  return (async () => {
    const thresholdSessionId = walletSigningBudgetSessionId({
      curve: input.curve,
      signingGrantId: input.signingGrantId,
    });
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
  stores: readonly SigningSessionSealWalletSessionStore[],
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
  ecdsaStores?: readonly EcdsaWalletSessionStore[] | null;
  walletBudgetStores: readonly WalletSigningBudgetSessionStore[];
}): SigningSessionSealThresholdSessionPolicy {
  const ed25519Stores = (input.ed25519Stores || []).filter(Boolean);
  const ecdsaStores = (input.ecdsaStores || []).filter(Boolean);
  const walletBudgetStores = input.walletBudgetStores.filter(Boolean);

  function storesForLookup(
    input: SigningSessionSealThresholdStatusLookup | SigningSessionSealWalletBudgetStatusLookup,
  ): readonly SigningSessionSealWalletSessionStore[] {
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
