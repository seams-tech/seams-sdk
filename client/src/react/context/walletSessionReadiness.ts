import type { WalletSession } from '@/core/types/tatchi';

function isThresholdSignerMode(signerMode: unknown): boolean {
  if (!signerMode || typeof signerMode !== 'object') return false;
  const mode = String((signerMode as { mode?: unknown }).mode || '').trim().toLowerCase();
  return mode === 'threshold-signer';
}

/**
 * UI wallet-session readiness gate:
 * - For threshold signer mode, the wallet session is ready only when warm signing session is active.
 * - For other signer modes, readiness follows the canonical wallet-session snapshot only.
 */
export function isWalletSessionReadyForUi(args: {
  session: Pick<WalletSession, 'login' | 'signingSession'>;
  signerMode: unknown;
}): boolean {
  const { session, signerMode } = args;
  if (!session?.login?.isLoggedIn || !session?.login?.nearAccountId) return false;
  if (!isThresholdSignerMode(signerMode)) return true;
  return session?.signingSession?.status === 'active';
}
