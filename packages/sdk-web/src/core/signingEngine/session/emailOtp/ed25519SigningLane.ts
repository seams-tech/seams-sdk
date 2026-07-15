import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { EmailOtpSigningSessionAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import {
  walletAuthAuthoritiesMatch,
  type EmailOtpWalletAuthAuthority,
} from '@shared/utils/walletAuthAuthority';
import type { EmailOtpEd25519SigningSessionAuthority } from './ed25519SigningSessionAuthority';

export type EmailOtpEd25519CommittedSessionRecord = ThresholdEd25519SessionRecord & {
  source: 'email_otp';
  signingGrantId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

export type Ed25519SigningLane = {
  source: 'record_backed';
  record: EmailOtpEd25519CommittedSessionRecord;
  authority: EmailOtpWalletAuthAuthority;
  authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
  walletSessionAuthority: {
    kind: 'wallet_session_authority';
    walletSessionJwt: string;
    thresholdSessionId: string;
    signingGrantId: string;
  };
};

function isEmailOtpEd25519CommittedSessionRecord(
  record: ThresholdEd25519SessionRecord,
): record is EmailOtpEd25519CommittedSessionRecord {
  return (
    record.source === 'email_otp' &&
    Boolean(record.emailOtpAuthContext) &&
    Boolean(String(record.signingGrantId || '').trim())
  );
}

export function buildEd25519SigningLane(args: {
  record: ThresholdEd25519SessionRecord;
  authority: EmailOtpEd25519SigningSessionAuthority;
}): Ed25519SigningLane {
  if (!isEmailOtpEd25519CommittedSessionRecord(args.record)) {
    throw new Error('Email OTP Ed25519 signing lane requires bound Email OTP authority');
  }
  const thresholdSessionId = String(args.record.thresholdSessionId || '').trim();
  const signingGrantId = String(args.record.signingGrantId || '').trim();
  if (!thresholdSessionId || !signingGrantId) {
    throw new Error('Email OTP Ed25519 signing lane requires session identity');
  }
  if (
    !walletAuthAuthoritiesMatch(
      args.record.emailOtpAuthContext.authority,
      args.authority.authority,
    ) ||
    args.authority.authLane.thresholdSessionId !== thresholdSessionId ||
    args.authority.authLane.authorizingSigningGrantId !== signingGrantId
  ) {
    throw new Error('Email OTP Ed25519 signing lane authority drifted');
  }
  return {
    source: 'record_backed',
    record: args.record,
    authority: args.authority.authority,
    authLane: args.authority.authLane,
    walletSessionAuthority: {
      kind: 'wallet_session_authority',
      walletSessionJwt: args.authority.authLane.jwt,
      thresholdSessionId,
      signingGrantId,
    },
  };
}
