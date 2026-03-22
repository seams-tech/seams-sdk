import { stripTrailingSlashes, toTrimmedString } from '@shared/utils/validation';

export type Ed25519HealthzResponse =
  | { ok: true; configured: true }
  | { ok: false; configured: false; code?: string; message?: string };

const DEFAULT_CACHE_TTL_MS = 60_000;
const cache = new Map<string, { configured: boolean; expiresAtMs: number }>();
const inFlight = new Map<string, Promise<boolean>>();
export async function isRelayerEd25519Configured(
  relayerUrl: string,
  opts?: { cacheTtlMs?: number },
): Promise<boolean> {
  const base = stripTrailingSlashes(toTrimmedString(relayerUrl));
  return isRelayerEd25519ConfiguredBase(base, opts);
}

async function isRelayerEd25519ConfiguredBase(
  base: string,
  opts?: { cacheTtlMs?: number },
): Promise<boolean> {
  if (!base) return false;
  if (typeof fetch !== 'function') return false;

  const ttlMs = Math.max(0, Number(opts?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS));
  const now = Date.now();
  const cached = cache.get(base);
  if (cached && cached.expiresAtMs > now) return cached.configured;

  const existing = inFlight.get(base);
  if (existing) return existing;

  const req = (async (): Promise<boolean> => {
    try {
      const res = await fetch(`${base}/threshold-ed25519/healthz`, { method: 'GET' });
      if (!res.ok) {
        cache.set(base, { configured: false, expiresAtMs: now + ttlMs });
        return false;
      }
      const data = (await res.json().catch(() => null)) as Ed25519HealthzResponse | null;
      const configured = data?.configured === true;
      cache.set(base, { configured, expiresAtMs: now + ttlMs });
      return configured;
    } catch {
      cache.set(base, { configured: false, expiresAtMs: now + ttlMs });
      return false;
    } finally {
      inFlight.delete(base);
    }
  })();

  inFlight.set(base, req);
  return req;
}

export async function assertThresholdSigningAvailable(args: {
  relayerUrl: string;
  cacheTtlMs?: number;
}): Promise<void> {
  const base = stripTrailingSlashes(toTrimmedString(args.relayerUrl));
  const configured = await isRelayerEd25519ConfiguredBase(base, { cacheTtlMs: args.cacheTtlMs });
  if (!configured) {
    throw new Error(
      '[SigningEngine] relayer does not support threshold signing',
    );
  }
}
