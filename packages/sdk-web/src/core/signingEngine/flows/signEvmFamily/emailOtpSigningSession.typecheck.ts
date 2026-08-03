import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EmailOtpEcdsaSigningSessionDeps,
  EmailOtpEcdsaStepUpAuthority,
} from './emailOtpSigningSession';
import type { EcdsaCommittedLane } from './ecdsaSelection';
import type { EmailOtpPublicDeps } from './emailOtpPublic';
import { requestEmailOtpSigningSessionChallenge } from './emailOtpPublic';
import type { EmailOtpSigningSessionAuthLane } from '../../stepUpConfirmation/otpPrompt/authLane';

declare const deps: EmailOtpPublicDeps;
declare const signingSessionDeps: EmailOtpEcdsaSigningSessionDeps;
declare const walletId: WalletId;
declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const ecdsaAuthLane: Extract<EmailOtpSigningSessionAuthLane, { curve: 'ecdsa' }>;
declare const committedLane: EcdsaCommittedLane;
const invalidLiveStepUpWithPublicLane: EmailOtpEcdsaStepUpAuthority = {
  kind: 'live_session',
  committedLane,
  // @ts-expect-error live authority cannot carry a second reauth lane.
  reauthLane: committedLane,
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
