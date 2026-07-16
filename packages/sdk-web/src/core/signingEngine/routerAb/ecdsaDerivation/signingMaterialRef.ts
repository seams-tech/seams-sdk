import {
  requireRouterAbEcdsaDerivationNormalSigningStateV1,
  routerAbEcdsaDerivationActiveStateSessionId,
  type RouterAbEcdsaDerivationNormalSigningStateV1,
} from '@shared/utils/routerAbEcdsaDerivation';
import {
  parseEcdsaClientVerifyingShareB64u,
  parseEcdsaThresholdKeyId,
  type EcdsaClientVerifyingShareB64u,
  type EcdsaThresholdKeyId,
} from '../../session/keyMaterialBrands';

export type RouterAbEcdsaDerivationSigningMaterialRef = {
  kind: 'router_ab_ecdsa_derivation_signing_material_ref_v1';
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
  derivation_client_share_public_key33_b64u?: never;
  clientSigningShare32?: never;
};

export function buildRouterAbEcdsaDerivationSigningMaterialRef(args: {
  routerAbState: RouterAbEcdsaDerivationNormalSigningStateV1;
}): RouterAbEcdsaDerivationSigningMaterialRef {
  const routerAbState = requireRouterAbEcdsaDerivationNormalSigningStateV1(args.routerAbState);
  return {
    kind: 'router_ab_ecdsa_derivation_signing_material_ref_v1',
    routerAbStateSessionId: routerAbEcdsaDerivationActiveStateSessionId(routerAbState),
    ecdsaThresholdKeyId: parseEcdsaThresholdKeyId(routerAbState.scope.ecdsa_threshold_key_id),
    signingRootId: routerAbState.scope.signing_root_id,
    signingRootVersion: routerAbState.scope.signing_root_version,
    signingWorkerId: routerAbState.scope.signing_worker.server_id,
    clientVerifier33B64u: parseEcdsaClientVerifyingShareB64u(
      routerAbState.scope.public_identity.derivation_client_share_public_key33_b64u,
    ),
    serverVerifier33B64u: routerAbState.scope.public_identity.server_public_key33_b64u,
    thresholdVerifier33B64u: routerAbState.scope.public_identity.threshold_public_key33_b64u,
  };
}
