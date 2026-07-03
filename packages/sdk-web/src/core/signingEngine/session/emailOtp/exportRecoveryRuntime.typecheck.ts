import type { AccountId } from '@/core/types/accountIds';
import type { ThresholdEd25519SessionRecord } from '../persistence/records';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';
import type { EmailOtpWalletAuthAuthority } from '@shared/utils/walletAuthAuthority';
import type {
  Ed25519ExportLane,
  EmailOtpEd25519ExportSessionRecord,
  ExportEd25519SeedWithAuthorizationArgs,
} from './exportRecoveryRuntime';

declare const nearAccountId: AccountId;
declare const record: ThresholdEd25519SessionRecord;
declare const committedLane: Ed25519ExportLane;
declare const committedRecord: EmailOtpEd25519ExportSessionRecord;
declare const authLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ed25519' }>;
declare const authority: EmailOtpWalletAuthAuthority;

const recordBackedExportLane: Ed25519ExportLane = {
  source: 'record_backed',
  record: committedRecord,
  authority,
  authLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  participantIds: [1, 2],
  relayerKeyId: 'ed25519:relayer',
  expectedPublicKey: 'ed25519:public',
};
void recordBackedExportLane;

// @ts-expect-error Ed25519 export lanes require the bound Email OTP authority.
const recordBackedExportLaneWithoutAuthority: Ed25519ExportLane = {
  source: 'record_backed',
  record: committedRecord,
  authLane,
  walletSessionAuthority: {
    kind: 'wallet_session_authority',
    walletSessionJwt: 'wallet-session-jwt',
    thresholdSessionId: 'threshold-session-1',
    signingGrantId: 'signing-grant-1',
  },
  participantIds: [1, 2],
  relayerKeyId: 'ed25519:relayer',
  expectedPublicKey: 'ed25519:public',
};
void recordBackedExportLaneWithoutAuthority;

const ed25519ExportWithCommittedLane: ExportEd25519SeedWithAuthorizationArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
};
void ed25519ExportWithCommittedLane;

const ed25519ExportWithLooseRecord: ExportEd25519SeedWithAuthorizationArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  // @ts-expect-error Ed25519 Email OTP export carries records through the committed lane.
  record,
};
void ed25519ExportWithLooseRecord;

const ed25519ExportWithLooseWalletSessionJwt: ExportEd25519SeedWithAuthorizationArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  committedLane,
  // @ts-expect-error Ed25519 Email OTP export carries wallet-session authority through the committed lane.
  walletSessionJwt: 'wallet-session-jwt',
};
void ed25519ExportWithLooseWalletSessionJwt;

export {};
