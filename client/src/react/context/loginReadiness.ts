import type { LoginSession } from '@/core/types/tatchi';

type SignerModeName = 'threshold-signer' | 'local-signer' | string;

function resolveSignerModeName(mode: unknown): SignerModeName {
  if (!mode || typeof mode !== 'object') return 'local-signer';
  const value = (mode as { mode?: unknown }).mode;
  return typeof value === 'string' && value.trim().length > 0
    ? (value.trim() as SignerModeName)
    : 'local-signer';
}

/**
 * UI login readiness gate:
 * - For threshold-signer mode, login requires active warm signing session.
 * - For other modes, login snapshot alone is sufficient.
 */
export function isLoginSessionReadyForUi(args: {
  session: Pick<LoginSession, 'login' | 'signingSession'>;
  signerMode: unknown;
}): boolean {
  const { session, signerMode } = args;
  if (!session?.login?.isLoggedIn || !session?.login?.nearAccountId) return false;
  if (resolveSignerModeName(signerMode) !== 'threshold-signer') return true;
  return session.signingSession?.status === 'active';
}
