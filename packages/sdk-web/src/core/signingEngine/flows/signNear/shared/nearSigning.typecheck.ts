import type { NamedNearAccountId } from '@shared/utils/near';
import type { NearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  buildNamedNearAccountBinding,
  buildNearEd25519SignerBinding,
  buildWalletIdentity,
} from '@shared/utils/walletCapabilityBindings';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  ExactEd25519SigningLaneIdentity,
  ExactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import type { SigningLaneAuthBinding } from '@/core/signingEngine/session/identity/signingLaneAuthBinding';
import type {
  SigningGrantId,
  ThresholdEd25519SessionId,
} from '@/core/signingEngine/session/operationState/types';

declare const walletId: WalletId;
declare const nearAccountId: NamedNearAccountId;
declare const nearEd25519SigningKeyId: NearEd25519SigningKeyId;
declare const auth: SigningLaneAuthBinding;
declare const signingGrantId: SigningGrantId;
declare const thresholdSessionId: ThresholdEd25519SessionId;
declare const ecdsaLane: ExactEcdsaSigningLaneIdentity;

const wallet = buildWalletIdentity({ walletId });
const account = buildNamedNearAccountBinding({
  wallet,
  nearAccountId,
});
const signer = buildNearEd25519SignerBinding({
  account,
  nearEd25519SigningKeyId,
  signerSlot: 1,
});

const ed25519Lane: ExactEd25519SigningLaneIdentity = {
  kind: 'exact_signing_lane',
  signer,
  auth,
  signingGrantId,
  thresholdSessionId,
};
void ed25519Lane;

// @ts-expect-error NEAR Ed25519 signing requires an Ed25519 exact lane.
const wrongCurveLane: ExactEd25519SigningLaneIdentity = ecdsaLane;
void wrongCurveLane;

const ed25519LaneWithLegacyAccountId: ExactEd25519SigningLaneIdentity = {
  kind: 'exact_signing_lane',
  signer,
  auth,
  signingGrantId,
  thresholdSessionId,
  // @ts-expect-error Exact Ed25519 lane carries NEAR account identity under signer.account.
  accountId: nearAccountId,
};
void ed25519LaneWithLegacyAccountId;

export {};
