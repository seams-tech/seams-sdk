import {
  requireRouterAbEcdsaHssNormalSigningStateV1,
  routerAbEcdsaHssActiveStateSessionId,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';

export type RouterAbEcdsaHssSigningMaterialRef = {
  kind: 'router_ab_ecdsa_hss_signing_material_ref_v1';
  routerAbStateSessionId: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion: string;
  signingWorkerId: string;
  clientVerifier33B64u: EcdsaClientVerifyingShareB64u;
  serverVerifier33B64u: string;
  thresholdVerifier33B64u: string;
  keyHandle?: never;
  clientVerifyingShareB64u?: never;
  client_public_key33_b64u?: never;
  clientSigningShare32?: never;
};

export function buildRouterAbEcdsaHssSigningMaterialRef(args: {
  routerAbState: RouterAbEcdsaHssNormalSigningStateV1;
}): RouterAbEcdsaHssSigningMaterialRef {
  const routerAbState = requireRouterAbEcdsaHssNormalSigningStateV1(args.routerAbState);
  return {
    kind: 'router_ab_ecdsa_hss_signing_material_ref_v1',
    routerAbStateSessionId: routerAbEcdsaHssActiveStateSessionId(routerAbState),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(
      routerAbState.scope.context.ecdsa_threshold_key_id,
    ),
    signingRootId: routerAbState.scope.context.signing_root_id,
    signingRootVersion: routerAbState.scope.context.signing_root_version,
    signingWorkerId: routerAbState.scope.signing_worker.server_id,
    clientVerifier33B64u: parseEcdsaClientVerifyingShareB64u(
      routerAbState.scope.public_identity.client_public_key33_b64u,
    ),
    serverVerifier33B64u: routerAbState.scope.public_identity.server_public_key33_b64u,
    thresholdVerifier33B64u: routerAbState.scope.public_identity.threshold_public_key33_b64u,
  };
}
