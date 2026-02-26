import type { TxDisplayModel } from '@/core/signingEngine/touchConfirm/shared/displayModel';

export type IntentDigestPreparationResult = {
  intentDigest: string;
  challengeB64u: string;
  displayModel?: TxDisplayModel;
  title?: string;
  body?: string;
};

// Base64url-encoded 32 zero bytes. Used only as a temporary placeholder while
// the real challenge is prepared and pushed through the registry.
export const PENDING_CHALLENGE_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
export const PENDING_INTENT_DIGEST = 'pending-intent-digest';

const pendingIntentPreparations = new Map<string, Promise<IntentDigestPreparationResult>>();

function normalizeRequestId(value: unknown): string {
  return String(value || '').trim();
}

export function registerIntentDigestPreparation(args: {
  requestId: string;
  preparation: Promise<IntentDigestPreparationResult>;
}): void {
  const requestId = normalizeRequestId(args.requestId);
  if (!requestId) return;
  pendingIntentPreparations.set(requestId, args.preparation);
}

export function consumeIntentDigestPreparation(
  requestIdRaw: string,
): Promise<IntentDigestPreparationResult> | undefined {
  const requestId = normalizeRequestId(requestIdRaw);
  if (!requestId) return undefined;
  const preparation = pendingIntentPreparations.get(requestId);
  if (!preparation) return undefined;
  pendingIntentPreparations.delete(requestId);
  return preparation;
}

export function clearIntentDigestPreparation(requestIdRaw: string): void {
  const requestId = normalizeRequestId(requestIdRaw);
  if (!requestId) return;
  pendingIntentPreparations.delete(requestId);
}
