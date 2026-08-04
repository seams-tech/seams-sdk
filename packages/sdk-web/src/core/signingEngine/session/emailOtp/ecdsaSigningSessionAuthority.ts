import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import { type EmailOtpAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import {
  walletSessionJwtForCurve,
  type ActiveWalletSessionAuthorizationProjection,
} from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

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

export type EmailOtpEcdsaSigningSessionAuthorityResolution =
  | {
      kind: 'ready';
      authority: EmailOtpEcdsaSigningSessionAuthority;
    }
  | {
      kind: 'record_missing';
      authority?: never;
    }
  | {
      kind: 'wallet_session_auth_unavailable';
      reason: 'cookie_session' | 'missing_wallet_session_jwt';
      authority?: never;
    }
  | {
      kind: 'missing_session_identity';
      authority?: never;
    }
  | {
      kind: 'authority_not_ecdsa_signing_session';
      authority?: never;
    };

/** Canonical counterpart of the record-backed resolver: the Email OTP authority
 * comes from the sealed runtime's auth binding, and the signing-session lane is
 * completed by the independently-resolved reusable Wallet Session. Material
 * identity plays no part here -- it is proven separately by the manifest.  */
export function resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime(args: {
  runtime: ExactEcdsaSealedRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): EmailOtpEcdsaSigningSessionAuthorityResolution {
  const authBinding = args.runtime.authBinding;
  if (authBinding.kind !== 'email_otp') {
    // A passkey-bound runtime is not an Email OTP signing session; report the
    // missing lane rather than inventing a store source for it.
    return { kind: 'record_missing' };
  }
  const walletSessionJwt = walletSessionJwtForCurve(args.authorization, 'ecdsa');
  if (!walletSessionJwt) {
    return { kind: 'wallet_session_auth_unavailable', reason: 'missing_wallet_session_jwt' };
  }
  const authority = buildEmailOtpEcdsaSigningSessionAuthority({
    authority: authBinding.emailOtpAuthority,
    authLane: {
      kind: 'signing_session',
      jwt: walletSessionJwt,
      thresholdSessionId: args.runtime.sealedRecord.thresholdSessionId,
      curve: 'ecdsa',
      chainTarget: args.runtime.chainTarget,
    },
  });
  if (!authority) return { kind: 'authority_not_ecdsa_signing_session' };
  return { kind: 'ready', authority };
}
