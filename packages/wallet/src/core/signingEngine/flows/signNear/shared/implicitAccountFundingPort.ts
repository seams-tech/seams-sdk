import type {
  NearImplicitAccountFundingPort,
  NearImplicitAccountFundingResult,
} from '@/core/signingEngine/interfaces/implicitAccountFunding';
import type { NearFundingRequest } from '@/core/signingEngine/nonce/nearTransactionReadiness';

/**
 * Per-request funder registry behind NearImplicitAccountFundingPort — the same
 * shape as the operation step-up builder registry: the signing side registers a
 * funder (it holds the Wallet Session and the request-integrity checks) before
 * opening the confirmation, and clears it when the confirmation settles. The
 * confirmation flow reaches the funder only through the port.
 */
type NearImplicitAccountFunder = (
  request: NearFundingRequest,
) => Promise<NearImplicitAccountFundingResult>;

const pendingFunders = new Map<string, NearImplicitAccountFunder>();

function requireFunderRequestId(value: unknown): string {
  const normalized = String(value || '').trim();
  if (!normalized) throw new Error('[SigningEngine][near] requestId is required');
  return normalized;
}

export function registerNearImplicitAccountFunder(input: {
  requestId: string;
  fund: NearImplicitAccountFunder;
}): void {
  pendingFunders.set(requireFunderRequestId(input.requestId), input.fund);
}

export function clearNearImplicitAccountFunder(requestId: string): void {
  pendingFunders.delete(String(requestId || '').trim());
}

export const nearImplicitAccountFundingPort: NearImplicitAccountFundingPort = {
  async fund(input) {
    const requestId = requireFunderRequestId(input.requestId);
    const funder = pendingFunders.get(requestId);
    if (!funder) {
      throw new Error('[SigningEngine][near] implicit-account funding is unavailable');
    }
    // Single-use, like a step-up builder: one funding per confirmation.
    pendingFunders.delete(requestId);
    return await funder(input.request);
  },
};
