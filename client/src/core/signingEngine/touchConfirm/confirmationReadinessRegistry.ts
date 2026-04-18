export type ConfirmationReadiness = {
  promise: Promise<unknown>;
  body?: string;
};

const readinessByRequestId = new Map<string, ConfirmationReadiness>();

export function registerConfirmationReadiness(args: {
  requestId: string;
  readiness: ConfirmationReadiness;
}): void {
  const requestId = String(args.requestId || '').trim();
  if (!requestId) return;
  readinessByRequestId.set(requestId, args.readiness);
}

export function consumeConfirmationReadiness(
  requestIdRaw: string,
): ConfirmationReadiness | undefined {
  const requestId = String(requestIdRaw || '').trim();
  if (!requestId) return undefined;
  const readiness = readinessByRequestId.get(requestId);
  readinessByRequestId.delete(requestId);
  return readiness;
}

export function clearConfirmationReadiness(requestIdRaw: string): void {
  const requestId = String(requestIdRaw || '').trim();
  if (!requestId) return;
  readinessByRequestId.delete(requestId);
}
