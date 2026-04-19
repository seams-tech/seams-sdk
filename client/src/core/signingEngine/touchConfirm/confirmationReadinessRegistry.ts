export type ConfirmationReadiness = {
  promise: Promise<unknown>;
  body?: string;
};

const DEFAULT_CONFIRMATION_READINESS_TTL_MS = 2 * 60 * 1000;

type ConfirmationReadinessEntry = {
  readiness: ConfirmationReadiness;
  cleanupTimer: ReturnType<typeof setTimeout> | null;
};

const readinessByRequestId = new Map<string, ConfirmationReadinessEntry>();

function clearReadinessEntryTimer(entry: ConfirmationReadinessEntry | undefined): void {
  if (!entry?.cleanupTimer) return;
  clearTimeout(entry.cleanupTimer);
  entry.cleanupTimer = null;
}

export function registerConfirmationReadiness(args: {
  requestId: string;
  readiness: ConfirmationReadiness;
  ttlMs?: number;
}): void {
  const requestId = String(args.requestId || '').trim();
  if (!requestId) return;

  clearReadinessEntryTimer(readinessByRequestId.get(requestId));
  const ttlMs =
    Number.isFinite(args.ttlMs) && Number(args.ttlMs) > 0
      ? Number(args.ttlMs)
      : DEFAULT_CONFIRMATION_READINESS_TTL_MS;
  const entry: ConfirmationReadinessEntry = {
    readiness: args.readiness,
    cleanupTimer: null,
  };
  entry.cleanupTimer = setTimeout(() => {
    if (readinessByRequestId.get(requestId) !== entry) return;
    readinessByRequestId.delete(requestId);
  }, ttlMs);
  readinessByRequestId.set(requestId, entry);
}

export function consumeConfirmationReadiness(
  requestIdRaw: string,
): ConfirmationReadiness | undefined {
  const requestId = String(requestIdRaw || '').trim();
  if (!requestId) return undefined;
  const entry = readinessByRequestId.get(requestId);
  readinessByRequestId.delete(requestId);
  clearReadinessEntryTimer(entry);
  return entry?.readiness;
}

export function clearConfirmationReadiness(requestIdRaw: string): void {
  const requestId = String(requestIdRaw || '').trim();
  if (!requestId) return;
  clearReadinessEntryTimer(readinessByRequestId.get(requestId));
  readinessByRequestId.delete(requestId);
}
