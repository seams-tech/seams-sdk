import type {
  EcdsaDerivationAdditiveShareResponse,
  RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
} from './ecdsaClientWorkerChannels';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../session/keyMaterialBrands';

const additiveShare32 = new ArrayBuffer(32);
declare const authority: WalletAuthAuthorityRef;
declare const materialActivation: MpcMaterialActivationRef;
declare const materialRef: EcdsaRoleLocalPersistedMaterialRef;

void ({
  kind: 'open_ecdsa_role_local_signing_material_v1',
  authority,
  materialActivation,
} satisfies RehydrateEcdsaRoleLocalSigningMaterialRequestV1);

void ({
  kind: 'open_ecdsa_role_local_signing_material_v1',
  authority,
  materialActivation,
  // @ts-expect-error Worker-open requests cannot select material by caller-provided durable ref.
  materialRef,
} satisfies RehydrateEcdsaRoleLocalSigningMaterialRequestV1);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-success',
  ok: true,
  additiveShare32,
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-failure',
  ok: false,
  error: 'material unavailable',
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-ambiguous',
  ok: true,
  // @ts-expect-error The retired ambiguous field cannot cross the derivation/presign boundary.
  signingShare32: additiveShare32,
} satisfies EcdsaDerivationAdditiveShareResponse);

void ({
  kind: 'ecdsa_derivation_additive_share_result_v1',
  requestId: 'request-invalid-failure',
  ok: false,
  additiveShare32,
  error: 'material unavailable',
  // @ts-expect-error Failure responses cannot carry secret share material.
} satisfies EcdsaDerivationAdditiveShareResponse);
