import type { AccountId } from '@/core/types/accountIds';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type { ThresholdEd25519SessionRecord } from '@/core/signingEngine/session/persistence/records';

type EmailOtpChallengeWorkerArgs =
  Parameters<typeof import('./exportRecovery')['requestTransactionSigningChallenge']>[1];
type RecoverEd25519ExportPrfFirstArgs =
  import('./exportRecoveryRuntime').RecoverEd25519ExportPrfFirstArgs;

declare const walletId: WalletId;
declare const nearAccountId: AccountId;
declare const ed25519Record: ThresholdEd25519SessionRecord;

const walletSessionChallenge: Extract<
  EmailOtpChallengeWorkerArgs,
  { kind: 'wallet_session_challenge' }
> = {
  kind: 'wallet_session_challenge',
  walletSession: {
    walletId,
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
};
void walletSessionChallenge;

const nearAccountChallenge: Extract<EmailOtpChallengeWorkerArgs, { kind: 'near_account_challenge' }> =
  {
    kind: 'near_account_challenge',
    nearAccountId,
    chain: 'near',
  };
void nearAccountChallenge;

const invalidWalletSessionChallenge: Extract<
  EmailOtpChallengeWorkerArgs,
  { kind: 'wallet_session_challenge' }
> = {
  kind: 'wallet_session_challenge',
  walletSession: {
    // @ts-expect-error wallet-session Email OTP challenge requires WalletId.
    walletId: 'alice.testnet',
    walletSessionUserId: 'user-1',
  },
  chain: 'evm',
};
void invalidWalletSessionChallenge;

const validRecoverEd25519ExportArgs: RecoverEd25519ExportPrfFirstArgs = {
  nearAccountId,
  challengeId: 'challenge-1',
  otpCode: '123456',
  record: ed25519Record,
};
void validRecoverEd25519ExportArgs;

export {};
