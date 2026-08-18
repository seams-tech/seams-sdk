import type { ThresholdEcdsaChainTarget } from '../../interfaces/ecdsaChainTarget';
import {
  buildEcdsaRoleLocalSigningMaterialHandle,
  type BuildEcdsaRoleLocalSigningMaterialHandleInput,
} from './ecdsaDerivationSigningMaterialHandle';
import type { EcdsaActiveStateId, WalletId } from '@shared/utils/domainIds';
import type {
  EcdsaClientVerifyingPublicKey33B64u,
  EcdsaClientVerifyingShareB64u,
  EcdsaKeyHandle,
  EcdsaRelayerKeyId,
  EcdsaThresholdKeyId,
} from '../keyMaterialBrands';
import type { ThresholdEcdsaSessionId } from '../operationState/types';

declare const keyHandle: EcdsaKeyHandle;
declare const clientVerifyingPublicKey33B64u: EcdsaClientVerifyingPublicKey33B64u;
declare const clientVerifyingShareB64u: EcdsaClientVerifyingShareB64u;
declare const ecdsaThresholdKeyId: EcdsaThresholdKeyId;
declare const relayerKeyId: EcdsaRelayerKeyId;
declare const chainTarget: ThresholdEcdsaChainTarget;
declare const walletId: WalletId;
declare const thresholdSessionId: ThresholdEcdsaSessionId;
declare const activeStateId: EcdsaActiveStateId;

const materialIdentity: BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  keyHandle,
  clientVerifyingPublicKey33B64u,
  ecdsaThresholdKeyId,
  participantIds: [1, 2],
  relayerKeyId,
};

buildEcdsaRoleLocalSigningMaterialHandle(materialIdentity);

const materialIdentityWithUnvalidatedVerifyingShare = {
  ...materialIdentity,
  clientVerifyingPublicKey33B64u: clientVerifyingShareB64u,
};

// @ts-expect-error the legacy non-empty share brand is not a validated compressed public key.
buildEcdsaRoleLocalSigningMaterialHandle(materialIdentityWithUnvalidatedVerifyingShare);

const materialIdentityWithChainTarget = {
  ...materialIdentity,
  chainTarget,
};

// @ts-expect-error chain targets are operation-lane identity, including through broad inputs.
buildEcdsaRoleLocalSigningMaterialHandle(materialIdentityWithChainTarget);

const materialIdentityWithWallet = {
  ...materialIdentity,
  walletId,
};

// @ts-expect-error wallet identity is owned by signer authority, including through broad inputs.
buildEcdsaRoleLocalSigningMaterialHandle(materialIdentityWithWallet);

const materialIdentityWithThresholdSession = {
  ...materialIdentity,
  thresholdSessionId,
};

// @ts-expect-error threshold sessions do not identify material, including through broad inputs.
buildEcdsaRoleLocalSigningMaterialHandle(materialIdentityWithThresholdSession);

const materialIdentityWithActiveState = {
  ...materialIdentity,
  activeStateId,
};

// @ts-expect-error Router A/B active state does not identify material through broad inputs.
buildEcdsaRoleLocalSigningMaterialHandle(materialIdentityWithActiveState);

const missingParticipantIds: BuildEcdsaRoleLocalSigningMaterialHandleInput = {
  ...materialIdentity,
  // @ts-expect-error material identity requires a non-empty participant set.
  participantIds: [],
};
void missingParticipantIds;
