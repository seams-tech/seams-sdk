import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaSigningListLookupArgs,
  EcdsaSigningLookupArgs,
  EvmFamilySigningDeps,
  NearSigningApiDeps,
} from './operationDeps';

declare const nearAccountId: AccountId;
declare const walletId: WalletId;
declare const chainTarget: ThresholdEcdsaChainTarget;

const ecdsaSigningLookupArgs: EcdsaSigningLookupArgs = {
  walletId,
  chainTarget,
};
void ecdsaSigningLookupArgs;

const ecdsaSigningListLookupArgs: EcdsaSigningListLookupArgs = {
  walletId,
  chainTarget,
};
void ecdsaSigningListLookupArgs;

const invalidEcdsaSigningLookupArgs: EcdsaSigningLookupArgs = {
  // @ts-expect-error ECDSA signing lookup requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
};
void invalidEcdsaSigningLookupArgs;

const invalidEcdsaSigningListLookupArgs: EcdsaSigningListLookupArgs = {
  // @ts-expect-error ECDSA signing list lookup requires WalletId.
  walletId: 'alice.testnet',
  chainTarget,
};
void invalidEcdsaSigningListLookupArgs;

declare const signingDeps: EvmFamilySigningDeps;
declare const nearSigningDeps: NearSigningApiDeps;

signingDeps.resolveEmailOtpSigningSessionAuthLane?.({
  walletId,
  thresholdSessionId: 'threshold-session-id',
  curve: 'ecdsa',
  chain: 'tempo',
  chainTarget,
});

nearSigningDeps.requestEmailOtpTransactionSigningChallenge?.({
  nearAccountId,
  chain: 'near',
});

nearSigningDeps.getWarmThresholdEd25519SessionStatusForSession?.({
  nearAccountId,
  thresholdSessionId: 'threshold-session-id',
});

signingDeps.resolveEmailOtpSigningSessionAuthLane?.({
  // @ts-expect-error ECDSA Email OTP signing-session auth resolution requires WalletId.
  walletId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-id',
  curve: 'ecdsa',
  chain: 'tempo',
  chainTarget,
});
