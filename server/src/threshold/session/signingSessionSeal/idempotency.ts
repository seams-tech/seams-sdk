import type {
  SigningSessionSealIdempotencyGetInput,
  SigningSessionSealIdempotencySetInput,
  SigningSessionSealIdempotencyStore,
} from './types';

type InMemoryIdempotencyEntry = {
  result: SigningSessionSealIdempotencySetInput['result'];
  expiresAtMs: number;
};

function trimExpired(
  entries: Map<string, InMemoryIdempotencyEntry>,
  nowMs: number,
): void {
  for (const [key, entry] of entries.entries()) {
    if (entry.expiresAtMs > nowMs) continue;
    entries.delete(key);
  }
}

export function createInMemorySigningSessionSealIdempotencyStore(): SigningSessionSealIdempotencyStore {
  const entries = new Map<string, InMemoryIdempotencyEntry>();

  return {
    get: async (input: SigningSessionSealIdempotencyGetInput) => {
      trimExpired(entries, input.nowMs);
      const key = String(input.key || '').trim();
      if (!key) return null;
      const entry = entries.get(key);
      if (!entry) return null;
      if (entry.expiresAtMs <= input.nowMs) {
        entries.delete(key);
        return null;
      }
      return entry.result;
    },
    set: async (input: SigningSessionSealIdempotencySetInput) => {
      const key = String(input.key || '').trim();
      if (!key) return;
      const expiresAtMs = Number(input.expiresAtMs);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) return;
      entries.set(key, {
        result: input.result,
        expiresAtMs: Math.floor(expiresAtMs),
      });
    },
  };
}

