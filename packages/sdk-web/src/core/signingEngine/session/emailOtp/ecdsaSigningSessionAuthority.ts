import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import {
  type EmailOtpAuthLane,
} from '../../stepUpConfirmation/otpPrompt/authLane';
import type { ThresholdEcdsaSessionRecord } from '../persistence/records';
import type { ThresholdEcdsaSessionStoreSource } from '../identity/laneIdentity';
import { resolveRouterAbEcdsaWalletSessionAuthFromRecord } from '../warmCapabilities/routerAbEcdsaWalletSessionAuth';
import type { ExactEcdsaSealedRuntime } from '../material/ecdsaSealedRuntime';
import type { ActiveWalletSessionAuthorizationProjection } from '@/core/indexedDB/seamsWalletDB/walletSessionAuthorizationStore';

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
      curve: 'ecdsa',
      chainTarget: record.chainTarget,
    },
  });
  if (!authority) return { kind: 'authority_not_ecdsa_signing_session' };
  return { kind: 'ready', authority };
}

/** Canonical counterpart of the record-backed resolver: the Email OTP authority
 * comes from the sealed runtime's auth binding, and the signing-session lane is
 * completed by the independently-resolved reusable Wallet Session. Material
 * identity plays no part here -- it is proven separately by the manifest.  */
export function resolveEmailOtpEcdsaSigningSessionAuthorityFromRuntime(args: {
  runtime: ExactEcdsaSealedRuntime;
  authorization: ActiveWalletSessionAuthorizationProjection;
}): EmailOtpEcdsaSigningSessionAuthorityRecordResolution {
  const authBinding = args.runtime.authBinding;
  if (authBinding.kind !== 'email_otp') {
    // A passkey-bound runtime is not an Email OTP signing session; report the
    // missing lane rather than inventing a store source for it.
    return { kind: 'record_missing' };
  }
  const walletSessionJwt = String(args.authorization.walletSessionJwt || '').trim();
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
