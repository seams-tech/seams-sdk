import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type { EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

export type EmailOtpEcdsaSigningSessionAuthority = {
  authLane: Extract<EmailOtpAuthLane, { kind: 'signing_session'; curve: 'ecdsa' }>;
  authority: EmailOtpWalletAuthAuthority;
};

export function buildEmailOtpEcdsaSigningSessionAuthority(args: {
  authLane: EmailOtpAuthLane | null | undefined;
  authority: EmailOtpWalletAuthAuthority;
}): EmailOtpEcdsaSigningSessionAuthority | null {
  const authLane = args.authLane;
  if (authLane?.kind !== 'signing_session' || authLane.curve !== 'ecdsa') return null;
  return {
    authLane,
    authority: args.authority,
  };
}
