import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';
import type { ThresholdEcdsaEmailOtpAuthContext } from '@/core/signingEngine/session/identity/laneIdentity';
import type { EmailOtpSigningSessionAuthLane } from '@/core/signingEngine/stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';

export type EmailOtpEd25519CommittedSessionRecord = ThresholdEd25519SessionRecord & {
  source: 'email_otp';
  signingGrantId: string;
  emailOtpAuthContext: ThresholdEcdsaEmailOtpAuthContext;
};

export type Ed25519CommittedLaneWalletSessionAuthority = {
  kind: 'wallet_session_authority';
  walletSessionJwt: string;
  thresholdSessionId: string;
  signingGrantId: string;
};

export type RecordBackedEd25519CommittedLane<
  SessionRecord extends EmailOtpEd25519CommittedSessionRecord = EmailOtpEd25519CommittedSessionRecord,
  Facts extends object = {},
> = {
  source: 'record_backed';
  record: SessionRecord;
  authority: EmailOtpWalletAuthAuthority;
  authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
  walletSessionAuthority: Ed25519CommittedLaneWalletSessionAuthority;
} & Facts;
