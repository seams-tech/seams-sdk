import type {
  WarmSessionMaterialWriter,
  WarmSessionMaterialWriteDiagnostics,
} from './warmSessionMaterialWriter';
import { secureRandomId } from '@shared/utils/secureRandomId';

type SigningSessionCacheTransport = Parameters<
  WarmSessionMaterialWriter['putWarmSessionMaterial']
>[0]['transport'];

export type SigningSessionCacheEntry = {
  thresholdSessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: SigningSessionCacheTransport;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
};

function toNonNegativeInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

export function generateSessionId(prefix: string): string {
  return secureRandomId(prefix, 32, 'passkey PRF cache session IDs');
}

function normalizeSigningSessionCacheEntry(
  args: SigningSessionCacheEntry,
): SigningSessionCacheEntry {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const prfFirstB64u = String(args.prfFirstB64u || '').trim();
  const expiresAtMsRaw = Number(args.expiresAtMs);
  const remainingUses = toNonNegativeInt(args.remainingUses);
  if (!thresholdSessionId || !prfFirstB64u) {
    throw new Error('Missing thresholdSessionId or prfFirstB64u for signing session hydration');
  }
  if (!Number.isFinite(expiresAtMsRaw) || expiresAtMsRaw <= 0) {
    throw new Error('Invalid expiresAtMs for signing session hydration');
  }
  if (remainingUses == null) {
    throw new Error('Invalid remainingUses for signing session hydration');
  }
  return {
    thresholdSessionId,
    prfFirstB64u,
    expiresAtMs: Math.floor(expiresAtMsRaw),
    remainingUses,
    ...(args.transport ? { transport: args.transport } : {}),
  };
}

export async function cacheCredentialBoundarySetupExportPrfFirst(
  writer: WarmSessionMaterialWriter,
  args: SigningSessionCacheEntry,
): Promise<void> {
  const normalized = normalizeSigningSessionCacheEntry(args);
  await writer.putWarmSessionMaterial({
    thresholdSessionId: normalized.thresholdSessionId,
    prfFirstB64u: normalized.prfFirstB64u,
    expiresAtMs: normalized.expiresAtMs,
    remainingUses: normalized.remainingUses,
    ...(args.transport ? { transport: args.transport } : {}),
    ...(args.diagnostics ? { diagnostics: args.diagnostics } : {}),
  });
}
