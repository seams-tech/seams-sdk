import type {
  NearEd25519OperationStepUpGrant,
  NearEd25519YaoOperationMaterial,
} from '@/core/signingEngine/interfaces/near';
import type { NearOperationStepUpMaterial } from '@/core/signingEngine/flows/signNear/shared/ed25519YaoCapabilityResolution';
import { nearEd25519SignerBindingFromBoundaryFields } from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  parseThresholdEd25519SessionId,
  type MpcMaterialActivationRef,
} from '@shared/utils/domainIds';
import type { RouterAbNormalSigningPrepareRequestV2Wire } from '@/core/rpcClients/relayer/routerAbNormalSigning';
import type { Ed25519OperationStepUpProof } from '@/core/signingEngine/threshold/ed25519/walletSession';

export function nearEd25519OperationMaterialFixture(args: {
  activeClient: NearEd25519YaoOperationMaterial['activeClient'];
  thresholdSessionId: string;
  walletId: string;
  nearAccountId: string;
  signerSlot: number;
}): NearEd25519YaoOperationMaterial {
  const thresholdSessionId = parseThresholdEd25519SessionId(args.thresholdSessionId);
  if (!thresholdSessionId.ok) throw new Error(thresholdSessionId.error.message);
  return {
    activeClient: args.activeClient,
    facts: {
      thresholdSessionId: thresholdSessionId.value,
      signer: nearEd25519SignerBindingFromBoundaryFields({
        walletId: toWalletId(args.walletId),
        nearAccountId: toAccountId(args.nearAccountId),
        nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString(
          'near-operation-material-key',
        ),
        signerSlot: args.signerSlot,
      }),
      signingRootId: 'near-operation-material-root',
      signingRootVersion: 'root-v1',
      routerAbNormalSigning: {
        kind: 'router_ab_ed25519_normal_signing_v1',
        signingWorkerId: 'near-operation-material-worker',
      },
      runtimePolicyScope: {
        orgId: 'near-operation-material-org',
        projectId: 'near-operation-material-project',
        envId: 'test',
        signingRootVersion: 'root-v1',
      },
      relayerUrl: 'https://relay.example.test',
    },
  };
}

export function sealedEmailOtpNearOperationMaterialFixture(args: {
  materialActivation: MpcMaterialActivationRef;
  material: NearEd25519YaoOperationMaterial;
  issuedGrant: NearEd25519OperationStepUpGrant;
  onAuthorize: (args: {
    normalSigningRequest: RouterAbNormalSigningPrepareRequestV2Wire;
    displayDigest: string;
    proof: Extract<Ed25519OperationStepUpProof, { kind: 'email_otp' }>;
  }) => void;
}): Extract<NearOperationStepUpMaterial, { kind: 'email_otp_sealed' }> {
  return {
    kind: 'email_otp_sealed',
    materialActivation: args.materialActivation,
    facts: args.material.facts,
    authorizeAndRehydrate: async (authorization) => {
      args.onAuthorize(authorization);
      return {
        material: args.material,
        issuedGrant: args.issuedGrant,
      };
    },
  };
}
