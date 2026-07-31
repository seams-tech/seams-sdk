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
import type {
  ExactEcdsaSigningLaneIdentity,
  ExactEd25519SigningLaneIdentity,
} from '../session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '../session/identity/signingLaneAuthBinding';
import type { NearEd25519MaterialIdentity } from './operationDeps';

declare const nearAccountId: AccountId;
declare const walletId: WalletId;
declare const walletSession: WalletSessionRef;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const exactEcdsaLane: ExactEcdsaSigningLaneIdentity;
declare const exactEd25519Lane: ExactEd25519SigningLaneIdentity;
declare const ed25519Auth: SigningLaneAuthBinding;

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
signingDeps.resolveDurableEmailOtpEcdsaSigningSessionAuthority({
  lane: exactEcdsaLane,
  chain: 'tempo',
});

nearSigningDeps.prepareNearEd25519YaoMaterialBoundary({
  walletId,
  nearAccountId,
  laneIdentity: exactEd25519Lane,
  auth: ed25519Auth,
});
const nearEd25519MaterialIdentity: NearEd25519MaterialIdentity = {
  kind: 'near_ed25519_material_identity',
  signer: exactEd25519Lane.signer,
  auth: exactEd25519Lane.auth,
  thresholdSessionId: exactEd25519Lane.thresholdSessionId,
};
nearSigningDeps.prepareNearEd25519YaoMaterialBoundary({
  walletId,
  nearAccountId,
  materialIdentity: nearEd25519MaterialIdentity,
});
// @ts-expect-error material identity and an authorized lane cannot coexist.
nearSigningDeps.prepareNearEd25519YaoMaterialBoundary({
  walletId,
  nearAccountId,
  laneIdentity: exactEd25519Lane,
  auth: ed25519Auth,
  materialIdentity: nearEd25519MaterialIdentity,
});
// @ts-expect-error material preparation requires an authorized lane or material identity.
nearSigningDeps.prepareNearEd25519YaoMaterialBoundary({
  walletId,
  nearAccountId,
  auth: ed25519Auth,
});
// @ts-expect-error Factor-specific material preparation is private to the capability owner.
nearSigningDeps.prepareNearEd25519YaoSigning;
// @ts-expect-error Factor-specific Passkey rehydration is private to the capability owner.
nearSigningDeps.rehydratePasskeyEd25519YaoCapabilityForSigning;
// @ts-expect-error Factor-specific Email OTP recovery is private to the capability owner.
nearSigningDeps.recoverEmailOtpEd25519YaoCapabilitySilentlyForSigning;

signingDeps.resolveDurableEmailOtpEcdsaSigningSessionAuthority({
  // @ts-expect-error ECDSA Email OTP signing-session auth resolution requires exact lane identity.
  walletId: 'alice.testnet',
  thresholdSessionId: 'threshold-session-id',
  curve: 'ecdsa',
  chain: 'tempo',
  chainTarget,
});
