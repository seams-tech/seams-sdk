import type {
  PrfSessionSealIdempotencyBeginResult,
  PrfSessionSealIdempotencyStore,
  PrfSessionSealRouteResult,
} from '../types';

type InMemoryIdempotencyEntry = {
  state: 'pending' | 'done';
  expiresAtMs: number;
  result?: PrfSessionSealRouteResult;
};

export class InMemoryPrfSessionSealIdempotencyStore implements PrfSessionSealIdempotencyStore {
  private readonly entries = new Map<string, InMemoryIdempotencyEntry>();

  private gc(nowMs: number): void {
    for (const [key, entry] of this.entries.entries()) {
      if (entry.expiresAtMs > nowMs) continue;
      this.entries.delete(key);
    }
  }

  async begin(input: {
    key: string;
    nowMs: number;
    pendingTtlMs: number;
  }): Promise<PrfSessionSealIdempotencyBeginResult> {
    const key = String(input.key || '').trim();
    if (!key) return { acquired: true };

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    this.gc(nowMs);
    const existing = this.entries.get(key);
    if (!existing) {
      this.entries.set(key, {
        state: 'pending',
        expiresAtMs: nowMs + Math.max(1, Math.floor(Number(input.pendingTtlMs) || 0)),
      });
      return { acquired: true };
    }

    if (existing.state === 'done' && existing.result) {
      return { acquired: false, result: existing.result };
    }
    return { acquired: false, pending: true };
  }

  async getResult(input: { key: string; nowMs: number }): Promise<PrfSessionSealRouteResult | null> {
    const key = String(input.key || '').trim();
    if (!key) return null;

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    this.gc(nowMs);
    const existing = this.entries.get(key);
    if (!existing || existing.state !== 'done' || !existing.result) return null;
    return existing.result;
  }

  async complete(input: {
    key: string;
    nowMs: number;
    resultTtlMs: number;
    result: PrfSessionSealRouteResult;
  }): Promise<void> {
    const key = String(input.key || '').trim();
    if (!key) return;

    const nowMs = Math.max(0, Math.floor(Number(input.nowMs) || 0));
    this.gc(nowMs);
    this.entries.set(key, {
      state: 'done',
      expiresAtMs: nowMs + Math.max(1, Math.floor(Number(input.resultTtlMs) || 0)),
      result: input.result,
    });
  }
}

export function createInMemoryPrfSessionSealIdempotencyStore(): PrfSessionSealIdempotencyStore {
  return new InMemoryPrfSessionSealIdempotencyStore();
}

