import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  toAuthorizingSigningGrantId,
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';

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

export type EmailOtpEcdsaSigningSessionAuthorityRecordResolution =
  | {
      kind: 'ready';
      authority: EmailOtpEcdsaSigningSessionAuthority;
    }
  | {
      kind: 'record_missing';
      authority?: never;
    }
  | {
      kind: 'not_email_otp_record';
      source: ThresholdEcdsaSessionStoreSource;
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

export function resolveEmailOtpEcdsaSigningSessionAuthorityFromRecord(
  record: ThresholdEcdsaSessionRecord | null | undefined,
): EmailOtpEcdsaSigningSessionAuthorityRecordResolution {
  if (!record) return { kind: 'record_missing' };
  if (record.source !== 'email_otp') {
    return { kind: 'not_email_otp_record', source: record.source };
  }
  const walletSessionAuth = resolveRouterAbEcdsaWalletSessionAuthFromRecord(record);
  if (walletSessionAuth.kind !== 'ready') {
    if (walletSessionAuth.reason === 'missing_session_identity') {
      return { kind: 'missing_session_identity' };
    }
    return {
      kind: 'wallet_session_auth_unavailable',
      reason: walletSessionAuth.reason,
    };
  }
  const authority = buildEmailOtpEcdsaSigningSessionAuthority({
    authority: record.emailOtpAuthContext.authority,
    authLane: {
      kind: 'signing_session',
      jwt: walletSessionAuth.walletSessionJwt,
      thresholdSessionId: walletSessionAuth.identity.thresholdSessionId,
      authorizingSigningGrantId: toAuthorizingSigningGrantId(
        walletSessionAuth.identity.signingGrantId,
      ),
      curve: 'ecdsa',
      chainTarget: record.chainTarget,
    },
  });
  if (!authority) return { kind: 'authority_not_ecdsa_signing_session' };
  return { kind: 'ready', authority };
}
