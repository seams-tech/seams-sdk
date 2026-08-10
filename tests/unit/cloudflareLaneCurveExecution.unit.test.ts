import { expect, test } from '@playwright/test';
import { parseEcdsaAdditiveLaneHolderRoundV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { CloudflareEd25519LaneProtocolTransportV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/signingLanes/cloudflareLaneProtocolCommitter';
import {
  createCloudflareLaneCurveExecutionPortsV1,
  type SigningWorkerLaneMaterialReceiptPortV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/signingLanes/cloudflareLaneCurveExecution';
import {
  buildR102EcdsaLaneJob,
  buildR102HolderDeliveryReceipt,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';

const DIGEST_B64U = Buffer.alloc(32, 0x33).toString('base64url');

function unsupported(): Promise<never> {
  return Promise.reject(new Error('unsupported test operation'));
}

test('projects only exact public receipts from the private SigningWorker lane journal', async () => {
  const rawJob = buildR102EcdsaLaneJob('curve-execution');
  if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const job = rawJob;
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  const activationReceipt = buildR102ServerActivationReceipt(job);
  const calls: string[] = [];
  const signingWorker: SigningWorkerLaneMaterialReceiptPortV1 = {
    async commitEcdsaProtocolV1() {
      calls.push('commit.replayed');
      return {
        kind: 'signing_worker_lane_protocol_commit_projection_v1',
        outcome: 'replayed',
        receipt: protocolReceipt,
      };
    },
    async activateServerMaterialV1() {
      calls.push('activate.applied');
      return {
        kind: 'signing_worker_lane_server_activation_projection_v1',
        outcome: 'applied',
        receipt: activationReceipt,
      };
    },
    retireServerMaterialV1: unsupported,
  };
  const execution = createCloudflareLaneCurveExecutionPortsV1({
    ed25519Transport: new CloudflareEd25519LaneProtocolTransportV1({
      router: { fetch: unsupported },
      internalServiceAuth: 'unused-ed25519-secret',
      bindingResolver: { resolveBindingV1: unsupported },
    }),
    signingWorker,
  });
  const holderRound = parseEcdsaAdditiveLaneHolderRoundV1({
    kind: 'ecdsa_additive_lane_holder_round_v1',
    preambleHashB64u: DIGEST_B64U,
    targetHolderPublicCommitment33B64u: job.thresholdPublicKey33B64u,
    encryptedDeltaCiphertextDigestB64u: DIGEST_B64U,
    sealedTargetHolderMaterialDigestB64u: DIGEST_B64U,
    holderAttestationB64u: 'holder-attestation-r102',
    holderCommittedAtMs: 1_500,
  });

  const committed = await execution.ecdsa.executeProtocolCommitV1({
    job,
    holderRound,
    encryptedDeltaPackageJson: '{"opaque":"delta"}',
  });
  const activated = await execution.ecdsa.executeServerActivationV1({
    job,
    protocolCommitReceipt: protocolReceipt,
    holderDeliveryReceipt: buildR102HolderDeliveryReceipt(job),
  });

  expect(committed).toEqual(protocolReceipt);
  expect(activated).toEqual(activationReceipt);
  expect(calls).toEqual(['commit.replayed', 'activate.applied']);
  expect(Object.keys(committed)).not.toContain('record');
  expect(Object.keys(activated)).not.toContain('record');
});
