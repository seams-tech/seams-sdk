import { expect, test } from '@playwright/test';
import { parseEcdsaAdditiveLaneHolderRoundV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { CloudflareEd25519LaneProtocolTransportV1 } from '../../packages/sdk-server-ts/src/router/cloudflare/signingLanes/cloudflareLaneProtocolCommitter';
import {
  createCloudflareLaneCurveExecutionPortsV1,
  CloudflareSigningWorkerEcdsaLaneTransportV1,
  LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1,
  type SigningWorkerLaneMaterialReceiptPortV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/signingLanes/cloudflareLaneCurveExecution';
import {
  buildR102EcdsaLaneJob,
  buildR102LaneJob,
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
    holderPackage: {
      kind: 'ecdsa_additive_lane_holder_package_v1',
      ecdsaEncryptedMaterialEnvelopeJson: '{"opaque":"holder"}',
    },
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

test('linked-device source requires an exact active lane product', async () => {
  const rawJob = buildR102EcdsaLaneJob('missing-linked-source', {
    sourceLaneKind: 'linked_device',
  });
  if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const resolver = new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1({
    async getProductEpoch() {
      return null;
    },
    getProtocol: unsupported,
  });

  await expect(resolver.resolveSourceMaterialV1({ job: rawJob })).rejects.toThrow(
    'lane-backed source product epoch is missing',
  );
});

test('target activation binds the admitted target SigningWorker', async () => {
  const rawJob = buildR102EcdsaLaneJob('target-worker-binding');
  if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const resolver = new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1({
    getProductEpoch: unsupported,
    getProtocol: unsupported,
  });

  const binding = await resolver.resolveActivationBindingV1({
    job: rawJob,
    protocolCommitReceipt: buildR102ProtocolCommitReceipt(rawJob),
  });

  expect(binding.targetMaterialActivation.signingWorker).toBe(
    rawJob.targetSigningWorker.participantId,
  );
  expect(binding.targetMaterialActivation.signingWorker).not.toBe(
    rawJob.source.materialActivation.signingWorker,
  );
});

test('composite SigningWorker transport routes Ed25519 activation to its private lane path', async () => {
  const job = buildR102LaneJob('ed25519-activation-route');
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  const holderDeliveryReceipt = buildR102HolderDeliveryReceipt(job);
  const activationReceipt = buildR102ServerActivationReceipt(job);
  let request: Request | undefined;
  const transport = new CloudflareSigningWorkerEcdsaLaneTransportV1({
    signingWorker: {
      async fetch(input) {
        request = input;
        return new Response(
          JSON.stringify({ outcome: 'applied', receipt: activationReceipt }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    },
    internalServiceAuth: 'ed25519-activation-route-secret',
    bindingResolver: {
      resolveSourceMaterialV1: unsupported,
      resolveActivationBindingV1: unsupported,
      resolveRetirementBindingV1: unsupported,
    },
    retirementTransport: { retireServerMaterialV1: unsupported },
  });

  const projection = await transport.activateServerMaterialV1({
    curve: 'ed25519_yao',
    job,
    protocolCommitReceipt: protocolReceipt,
    holderDeliveryReceipt,
  });

  expect(projection.receipt).toEqual(activationReceipt);
  expect(request).toBeDefined();
  expect(new URL(request!.url).pathname).toBe(
    '/router-ab/internal/signing-worker/ed25519-yao-lane/activate',
  );
  const body = JSON.parse(await request!.text()) as {
    readonly identity: { readonly keyFamily: string };
  };
  expect(body.identity.keyFamily).toBe('ed25519');
});
