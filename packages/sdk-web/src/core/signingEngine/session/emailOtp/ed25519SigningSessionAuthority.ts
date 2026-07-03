import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpEd25519SigningSessionAuthority = {
  authLane: Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ed25519' }>;
  authority: EmailOtpWalletAuthAuthority;
};

export function buildEmailOtpEd25519SigningSessionAuthority(args: {
  authLane: EmailOtpAuthLane | null | undefined;
  authority: EmailOtpWalletAuthAuthority;
}): EmailOtpEd25519SigningSessionAuthority | null {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ed25519') return null;
  return {
    authLane,
    authority: args.authority,
  };
}
