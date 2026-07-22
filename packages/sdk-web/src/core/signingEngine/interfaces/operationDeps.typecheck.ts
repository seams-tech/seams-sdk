import type { AccountId } from '@/core/types/accountIds';
import type {
  ThresholdEcdsaChainTarget,
  WalletId,
  WalletSessionRef,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  EcdsaSigningListLookupArgs,
  EcdsaSigningLookupArgs,
  EvmFamilySigningDeps,
  NearSigningApiDeps,
} from './operationDeps';
import type { ExactEcdsaSigningLaneIdentity } from '../session/identity/exactSigningLaneIdentity';

declare const nearAccountId: AccountId;
declare const walletId: WalletId;
declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const exactEcdsaLane: ExactEcdsaSigningLaneIdentity;

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
declare const nearSigningDepsWithoutAuthResolver: Omit<
  NearSigningApiDeps,
  'resolveAccountAuthMethodForSigning'
>;

// @ts-expect-error NEAR signing must resolve the wallet auth method before auth-specific preparation.
const invalidNearSigningDeps: NearSigningApiDeps = nearSigningDepsWithoutAuthResolver;
void invalidNearSigningDeps;

signingDeps.resolveDurableEmailOtpEcdsaSigningSessionAuthority({
  lane: exactEcdsaLane,
  chain: 'tempo',
});

nearSigningDeps.getWarmThresholdEd25519SessionStatusForSession?.({
  nearAccountId,
  thresholdSessionId: 'threshold-session-id',
});

signingDeps.resolveDurableEmailOtpEcdsaSigningSessionAuthority({
  // @ts-expect-error ECDSA Email OTP signing-session auth resolution requires exact lane identity.
  walletId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-id',
  curve: 'ecdsa',
  chain: 'tempo',
  chainTarget,
});
