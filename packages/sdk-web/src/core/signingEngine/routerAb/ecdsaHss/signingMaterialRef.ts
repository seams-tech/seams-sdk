import {
  requireRouterAbEcdsaHssNormalSigningStateV1,
  routerAbEcdsaHssActiveStateSessionId,
  type RouterAbEcdsaHssNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaHss';

export type RouterAbEcdsaHssSigningMaterialRef = {
  kind: 'router_ab_ecdsa_hss_signing_material_ref_v1';
  routerAbStateSessionId: string;
  clientVerifier33B64u: string;
  serverVerifier33B64u: string;
  thresholdVerifier33B64u: string;
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
    clientVerifier33B64u: routerAbState.scope.public_identity.client_public_key33_b64u,
    serverVerifier33B64u: routerAbState.scope.public_identity.server_public_key33_b64u,
    thresholdVerifier33B64u: routerAbState.scope.public_identity.threshold_public_key33_b64u,
  };
}
