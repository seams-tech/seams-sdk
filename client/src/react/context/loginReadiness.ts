import type { LoginSession } from '@/core/types/tatchi';

function isThresholdSignerMode(signerMode: unknown): boolean {
  if (!signerMode || typeof signerMode !== 'object') return false;
  const mode = String((signerMode as { mode?: unknown }).mode || '').trim().toLowerCase();
  return mode === 'threshold-signer';
}

/**
 * UI login readiness gate:
 * - For threshold signer mode, login is ready only when warm signing session is active.
 * - For other signer modes, login readiness follows the canonical login snapshot only.
 */
export function isLoginSessionReadyForUi(args: {
  session: Pick<LoginSession, 'login' | 'signingSession'>;
  signerMode: unknown;
}): boolean {
  const { session, signerMode } = args;
  if (!session?.login?.isLoggedIn || !session?.login?.nearAccountId) return false;
  if (!isThresholdSignerMode(signerMode)) return true;
  return session?.signingSession?.status === 'active';
}
