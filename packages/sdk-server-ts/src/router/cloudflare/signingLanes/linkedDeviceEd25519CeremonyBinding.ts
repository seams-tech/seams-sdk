import type { Ed25519YaoLaneJobV1 } from '@shared/signing-lanes';
import { computeEd25519YaoLaneSessionDigestV1 } from '@shared/signing-lanes/rotationDigests';
import { base64UrlDecode } from '@shared/utils/base64';
import { routerAbMpcMaterialActivationRefToWire } from '@shared/utils/routerAbNormalSigningIdentity';
import type { RouterAbEd25519YaoCeremonyBindingV1 } from '@shared/utils/routerAbEd25519Yao';
import type { Ed25519YaoLaneBindingResolverPortV1 } from './cloudflareLaneProtocolCommitter';

export function createLinkedDeviceEd25519CeremonyBindingResolverV1(): Ed25519YaoLaneBindingResolverPortV1 {
  return {
    async resolveBindingV1({ job }) {
      return await buildLinkedDeviceEd25519CeremonyBindingV1(job);
    },
  };
}

export async function buildLinkedDeviceEd25519CeremonyBindingV1(
  job: Ed25519YaoLaneJobV1,
): Promise<RouterAbEd25519YaoCeremonyBindingV1> {
  const laneProvisioning = job.yaoRequestKind === 'lane_provisioning';
  return {
    lifecycle: {
      lifecycle_id: job.operationId,
      work_kind: laneProvisioning ? 'registration_prepare' : 'server_share_refresh',
      primitive_request_kind: laneProvisioning ? 'registration' : 'refresh',
      root_share_epoch: job.source.laneShareEpoch,
      account_id: job.walletId,
      session_id: job.operationId,
      signer_set_id: job.source.participantBindingDigestB64u,
      selected_server_id: job.source.materialActivation.signingWorker,
    },
    operation: job.yaoRequestKind,
    session_id: Array.from(base64UrlDecode(await computeEd25519YaoLaneSessionDigestV1(job))),
    stable_key_context_binding: Array.from(base64UrlDecode(job.stableContextBindingB64u)),
    material_activation: routerAbMpcMaterialActivationRefToWire(job.source.materialActivation),
  };
}
