import type {
  WarmSessionMaterialWriter,
  WarmSessionMaterialWriteDiagnostics,
} from './warmSessionMaterialWriter';
import { secureRandomId } from '@shared/utils/secureRandomId';

type SigningSessionCacheTransport = Parameters<
  WarmSessionMaterialWriter['putWarmSessionMaterial']
>[0]['transport'];

export type SigningSessionCacheEntry = {
  sessionId: string;
  prfFirstB64u: string;
  expiresAtMs: number;
  remainingUses: number;
  transport?: SigningSessionCacheTransport;
  diagnostics?: WarmSessionMaterialWriteDiagnostics;
};

type SigningSessionPrfCacheWriter = WarmSessionMaterialWriter;

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
    ...(args.transport ? { transport: args.transport } : {}),
  };
}

export async function cacheCredentialBoundarySetupExportPrfFirst(
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
    ...(args.diagnostics ? { diagnostics: args.diagnostics } : {}),
  });
}

export async function cacheCredentialBoundarySetupExportPrfFirstBestEffort(
  writer: SigningSessionPrfCacheWriter,
  args: SigningSessionCacheEntry,
): Promise<void> {
  await cacheCredentialBoundarySetupExportPrfFirst(writer, args).catch(() => undefined);
}
