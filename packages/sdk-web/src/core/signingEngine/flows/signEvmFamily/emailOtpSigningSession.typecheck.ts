import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EmailOtpEcdsaChallengeAuthority,
  EmailOtpEcdsaSigningSessionDeps,
  EmailOtpEcdsaStepUpAuthority,
} from './emailOtpSigningSession';
import type {
  EmailOtpEcdsaCommittedLane,
  EmailOtpEcdsaPublicReauthLane,
} from './ecdsaSelection';
import type { EmailOtpPublicDeps } from './emailOtpPublic';
import { requestEmailOtpSigningSessionChallenge } from './emailOtpPublic';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const deps: EmailOtpPublicDeps;
declare const signingSessionDeps: EmailOtpEcdsaSigningSessionDeps;
declare const walletId: WalletId;
declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const ecdsaAuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
declare const committedLane: EmailOtpEcdsaCommittedLane;
declare const publicReauthLane: EmailOtpEcdsaPublicReauthLane;

const publicStepUpAuthority: EmailOtpEcdsaStepUpAuthority = {
  kind: 'public_reauth_anchor',
  reauthLane: publicReauthLane,
};
void publicStepUpAuthority;

// @ts-expect-error public reauth challenge rejects an exhausted Wallet Session auth lane.
const invalidPublicChallengeWithOldAuthLane: EmailOtpEcdsaChallengeAuthority = {
  kind: 'public_reauth_anchor',
  reauthLane: publicReauthLane,
  authLane: ecdsaAuthLane,
};
void invalidPublicChallengeWithOldAuthLane;

// @ts-expect-error live authority and public reauth authority are mutually exclusive.
const invalidLiveStepUpWithPublicLane: EmailOtpEcdsaStepUpAuthority = {
  kind: 'live_session',
  committedLane,
  reauthLane: publicReauthLane,
};
void invalidLiveStepUpWithPublicLane;

type WalletSessionSigningChallengeArgs = Parameters<
  EmailOtpEcdsaSigningSessionDeps['emailOtpSessions']['requestTransactionSigningChallenge']
>[0];

const validWalletSessionSigningChallengeArgs: WalletSessionSigningChallengeArgs = {
  kind: 'wallet_session_challenge',
  walletSession,
  chain: 'evm',
  authLane: ecdsaAuthLane,
};
void validWalletSessionSigningChallengeArgs;

const invalidNearAccountSigningChallengeArgs: WalletSessionSigningChallengeArgs = {
  // @ts-expect-error ECDSA signing-session challenge bridge is wallet-session only.
  kind: 'near_account_challenge',
  walletSession,
  chain: 'near',
};
void invalidNearAccountSigningChallengeArgs;

void signingSessionDeps;

void requestEmailOtpSigningSessionChallenge(deps, {
  walletSession,
  chainTarget,
});

void requestEmailOtpSigningSessionChallenge(deps, {
  walletSession: {
    ...walletSession,
    // @ts-expect-error ECDSA signing-session auth resolution requires a normalized WalletId.
    walletId: 'wallet.testnet',
  },
  chainTarget,
});

void walletId;

export {};
