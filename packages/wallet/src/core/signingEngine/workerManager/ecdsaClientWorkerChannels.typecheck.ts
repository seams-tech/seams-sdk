import type {
  OpaqueEcdsaPresignAuthorityResponseV1,
  PrepareEcdsaAdditiveLaneHolderRequestV1,
  PrepareEcdsaAdditiveLaneHolderResultV1,
  RehydrateEcdsaRoleLocalSigningMaterialRequestV1,
} from './ecdsaClientWorkerChannels';
import type { EcdsaAdditiveLaneJobV1 } from '@shared/signing-lanes/rotation';
import type { MpcMaterialActivationRef } from '@shared/utils/domainIds';
import type { WalletAuthAuthorityRef } from '@shared/utils/walletAuthAuthority';
import type { EcdsaRoleLocalPersistedMaterialRef } from '../session/keyMaterialBrands';

declare const authority: WalletAuthAuthorityRef;
declare const materialActivation: MpcMaterialActivationRef;
declare const materialRef: EcdsaRoleLocalPersistedMaterialRef;
declare const ecdsaLaneJob: EcdsaAdditiveLaneJobV1;
declare const ecdsaLaneHolderResult: PrepareEcdsaAdditiveLaneHolderResultV1;

void ({
  kind: 'prepare_ecdsa_additive_lane_holder_v1',
  job: ecdsaLaneJob,
  holderCommittedAtMs: 2_000,
} satisfies PrepareEcdsaAdditiveLaneHolderRequestV1);

void ({
  kind: 'prepare_ecdsa_additive_lane_holder_v1',
  job: ecdsaLaneJob,
  holderCommittedAtMs: 2_000,
  // @ts-expect-error Ready-state blobs stay inside the derivation worker.
  stateBlobB64u: 'forbidden-secret',
} satisfies PrepareEcdsaAdditiveLaneHolderRequestV1);

// @ts-expect-error Lane holder results never expose a source scalar.
void ecdsaLaneHolderResult.sourceShare32B64u;

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
  kind: 'opaque_ecdsa_presign_authority_result_v1',
  requestId: 'request-success',
  ok: true,
  result: {
    kind: 'progress',
    progress: {
      stage: 'triples',
      event: 'none',
      outgoingMessages: [],
    },
  },
} satisfies OpaqueEcdsaPresignAuthorityResponseV1);

void ({
  kind: 'opaque_ecdsa_presign_authority_result_v1',
  requestId: 'request-failure',
  ok: false,
  error: 'material unavailable',
} satisfies OpaqueEcdsaPresignAuthorityResponseV1);
