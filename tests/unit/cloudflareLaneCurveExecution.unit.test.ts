import { expect, test } from '@playwright/test';
import { parseEcdsaAdditiveLaneHolderRoundV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { CloudflareEd25519LaneProtocolTransportV1 } from '../../packages/wallet-server/src/router/cloudflare/signingLanes/cloudflareLaneProtocolCommitter';
import {
  createCloudflareLaneCurveExecutionPortsV1,
  CloudflareSigningWorkerEcdsaLaneTransportV1,
  CloudflareSigningWorkerEcdsaRetirementTransportV1,
  LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1,
  LaneLifecycleStoreNormalSigningLaneMaterialResolverV1,
  type SigningWorkerLaneMaterialReceiptPortV1,
} from '../../packages/wallet-server/src/router/cloudflare/signingLanes/cloudflareLaneCurveExecution';
import {
  buildR102EcdsaLaneJob,
  buildR102LaneJob,
  buildR102HolderDeliveryReceipt,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
  buildR102ActiveProductEpoch,
  buildR102LaneEnrollmentFixture,
  buildR102EnrollmentAdmissionRecordFixture,
  buildR102ActiveProtocolAdmissionRecordFixture,
  buildR102RevokedProductEpoch,
} from './helpers/r102LaneGateway.fixtures';
import { buildRevokeSigningLaneV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildR102Ed25519LaneMaterialIdentityFixture,
  buildR102Ed25519ServerRetirementReceiptFixture,
} from './helpers/ed25519ServerRetirement.fixtures';

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
  const resolver = new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1(
    {
      async getProductEpoch() {
        return null;
      },
      getProtocol: unsupported,
    },
    {
      listWalletEcdsaCustodyContinuity: unsupported,
    },
  );

  await expect(resolver.resolveSourceMaterialV1({ job: rawJob })).rejects.toThrow(
    'lane-backed source product epoch is missing',
  );
});

async function activeLaneResolverFixture(curve: 'ed25519' | 'ecdsa_secp256k1') {
  const job =
    curve === 'ed25519'
      ? buildR102LaneJob('normal-resolver-ed')
      : buildR102EcdsaLaneJob('normal-resolver-ecdsa');
  const product = await buildR102ActiveProductEpoch(job);
  const enrollmentFixture = buildR102LaneEnrollmentFixture();
  const enrollmentRecord = await buildR102EnrollmentAdmissionRecordFixture(enrollmentFixture);
  const enrollment = {
    ...enrollmentRecord,
    value: {
      ...enrollmentRecord.value,
      lifecycle: {
        ...enrollmentRecord.value.lifecycle,
        manifestDigestB64u: product.aggregateManifestDigestB64u,
      },
    },
  };
  const protocol = buildR102ActiveProtocolAdmissionRecordFixture(
    job,
    parseDigestB64u(DIGEST_B64U),
    4_000,
  );
  return { job, product, enrollment, protocol };
}

for (const curve of ['ed25519', 'ecdsa_secp256k1'] as const) {
  test(`normal-signing resolver emits exact ${curve} lane source`, async () => {
    const fixture = await activeLaneResolverFixture(curve);
    const resolver = new LaneLifecycleStoreNormalSigningLaneMaterialResolverV1({
      async getProductEpoch() {
        return fixture.product;
      },
      async getEnrollment() {
        return fixture.enrollment;
      },
      async getProtocol() {
        return fixture.protocol;
      },
    });
    const admission = await resolver.resolveV1({
      lookup: {
        walletId: fixture.product.walletId,
        walletKeyId: fixture.product.walletKeyId,
        laneId: fixture.product.laneId,
        laneShareEpoch: fixture.product.laneShareEpoch,
      },
      materialActivation: fixture.product.materialActivation,
      keyFamily: curve,
    });
    expect(admission.source.kind).toBe('rotatable_lane');
    expect(admission.source.lookup.identity.targetLaneId).toBe(fixture.product.laneId);
    expect(admission.source.lookup.admittedLaneIdentityDigestB64u).toBeTruthy();
  });
}

test('normal-signing resolver rejects a revoked lane before protocol lookup', async () => {
  const active = await buildR102ActiveProductEpoch(buildR102LaneJob('normal-revoked'));
  const command = buildRevokeSigningLaneV1({
    walletId: active.walletId,
    walletKeyId: active.walletKeyId,
    laneId: active.laneId,
    laneShareEpoch: active.laneShareEpoch,
    expectedRevocationEpoch: active.revocationEpoch,
    reason: 'user_revoked',
    retirementCorrelationId: parseCorrelationId('normal-revoked'),
    retirementRequestDigestB64u: parseDigestB64u(DIGEST_B64U),
    retirementEffectBindingDigestB64u: parseDigestB64u(DIGEST_B64U),
    requestedAtMs: 8_000,
  });
  const revoked = buildR102RevokedProductEpoch(active, command);
  let protocolLookups = 0;
  const resolver = new LaneLifecycleStoreNormalSigningLaneMaterialResolverV1({
    async getProductEpoch() {
      return revoked;
    },
    async getEnrollment() {
      throw new Error('revoked lane must fail before enrollment lookup');
    },
    async getProtocol() {
      protocolLookups += 1;
      throw new Error('revoked lane must fail before protocol lookup');
    },
  });
  await expect(
    resolver.resolveV1({
      lookup: {
        walletId: active.walletId,
        walletKeyId: active.walletKeyId,
        laneId: active.laneId,
        laneShareEpoch: active.laneShareEpoch,
      },
      materialActivation: active.materialActivation,
      keyFamily: active.keyFamily,
    }),
  ).rejects.toThrow('exact active child');
  expect(protocolLookups).toBe(0);
});

test('target activation binds the admitted target SigningWorker', async () => {
  const rawJob = buildR102EcdsaLaneJob('target-worker-binding');
  if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  const resolver = new LaneLifecycleStoreEcdsaLanePrivateBindingResolverV1(
    {
      getProductEpoch: unsupported,
      getProtocol: unsupported,
    },
    {
      listWalletEcdsaCustodyContinuity: unsupported,
    },
  );

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
        return new Response(JSON.stringify({ outcome: 'applied', receipt: activationReceipt }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
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

test('composite SigningWorker transport surfaces a bounded private protocol error body', async () => {
  const job = buildR102LaneJob('ed25519-activation-error-detail');
  const protocolReceipt = buildR102ProtocolCommitReceipt(job);
  const holderDeliveryReceipt = buildR102HolderDeliveryReceipt(job);
  const privateProtocolError = `  MalformedWirePayload: ${'x'.repeat(700)}\n`;
  const transport = new CloudflareSigningWorkerEcdsaLaneTransportV1({
    signingWorker: {
      async fetch() {
        return new Response(privateProtocolError, { status: 500 });
      },
    },
    internalServiceAuth: 'ed25519-activation-error-detail-secret',
    bindingResolver: {
      resolveSourceMaterialV1: unsupported,
      resolveActivationBindingV1: unsupported,
      resolveRetirementBindingV1: unsupported,
    },
    retirementTransport: { retireServerMaterialV1: unsupported },
  });

  const error = await transport
    .activateServerMaterialV1({
      curve: 'ed25519_yao',
      job,
      protocolCommitReceipt: protocolReceipt,
      holderDeliveryReceipt,
    })
    .then(
      () => undefined,
      (caught: unknown) => caught,
    );

  expect(error).toBeInstanceOf(Error);
  const message = error instanceof Error ? error.message : '';
  expect(message).toContain('SigningWorker lane endpoint returned HTTP 500: MalformedWirePayload:');
  expect(message).toHaveLength('SigningWorker lane endpoint returned HTTP 500: '.length + 512);
  expect(message.endsWith('…')).toBe(true);
  expect(message).not.toContain('x'.repeat(513));
});

test('ECDSA lane transport serializes registration source lookups for the Rust worker wire', async () => {
  const rawJob = buildR102EcdsaLaneJob('registration-source-wire');
  if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  if (rawJob.source.sourceKind !== 'owner_registration') {
    throw new Error('fixture source kind changed');
  }
  const protocolReceipt = buildR102ProtocolCommitReceipt(rawJob);
  let request: Request | undefined;
  const transport = new CloudflareSigningWorkerEcdsaLaneTransportV1({
    signingWorker: {
      async fetch(input) {
        request = input;
        return new Response(JSON.stringify({ outcome: 'replayed', receipt: protocolReceipt }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    },
    internalServiceAuth: 'ecdsa-source-wire-secret',
    bindingResolver: {
      async resolveSourceMaterialV1() {
        return {
          kind: 'registration_activation' as const,
          lookup: {
            accountId: rawJob.walletId,
            materialActivationId: rawJob.source.materialActivation.activationId,
            signingWorkerId: rawJob.source.ownerParticipantContinuity.signingWorkerId,
          },
          sourceDerivation: {
            applicationBindingDigestB64u: DIGEST_B64U,
            clientShareRetryCounter: 0,
          },
        };
      },
      resolveActivationBindingV1: unsupported,
      resolveRetirementBindingV1: unsupported,
    },
    retirementTransport: { retireServerMaterialV1: unsupported },
  });
  const holderRound = parseEcdsaAdditiveLaneHolderRoundV1({
    kind: 'ecdsa_additive_lane_holder_round_v1',
    preambleHashB64u: DIGEST_B64U,
    targetHolderPublicCommitment33B64u: rawJob.thresholdPublicKey33B64u,
    encryptedDeltaCiphertextDigestB64u: DIGEST_B64U,
    sealedTargetHolderMaterialDigestB64u: DIGEST_B64U,
    holderAttestationB64u: 'holder-attestation-source-wire',
    holderCommittedAtMs: 1_500,
  });

  await transport.commitEcdsaProtocolV1({
    job: rawJob,
    holderRound,
    holderPackage: {
      kind: 'ecdsa_additive_lane_holder_package_v1',
      ecdsaEncryptedMaterialEnvelopeJson: JSON.stringify({
        kind: 'ecdsa_additive_lane_encrypted_payload_v1',
        recipientPublicKeyB64u: DIGEST_B64U,
        aadDigestB64u: DIGEST_B64U,
        encappedKeyB64u: DIGEST_B64U,
        ciphertextB64u: DIGEST_B64U,
      }),
    },
    encryptedDeltaPackageJson: JSON.stringify({
      kind: 'ecdsa_additive_lane_encrypted_payload_v1',
      recipientPublicKeyB64u: DIGEST_B64U,
      aadDigestB64u: DIGEST_B64U,
      encappedKeyB64u: DIGEST_B64U,
      ciphertextB64u: DIGEST_B64U,
    }),
  });

  expect(request).toBeDefined();
  const body = JSON.parse(await request!.text()) as {
    readonly sourceMaterial: {
      readonly kind: string;
      readonly lookup: Record<string, unknown>;
    };
  };
  expect(body.sourceMaterial).toEqual({
    kind: 'registration_activation',
    lookup: {
      account_id: rawJob.walletId,
      material_activation_id: rawJob.source.materialActivation.activationId,
      signing_worker_id: rawJob.source.ownerParticipantContinuity.signingWorkerId,
    },
    sourceDerivation: {
      application_binding_digest_b64u: DIGEST_B64U,
      client_share_retry_counter: 0,
    },
  });
});

test('routes Ed25519 retirement and returns only the verified exact receipt', async () => {
  const identity = await buildR102Ed25519LaneMaterialIdentityFixture();
  const command = buildRevokeSigningLaneV1({
    walletId: identity.walletId,
    walletKeyId: identity.walletKeyId,
    laneId: identity.targetLaneId,
    laneShareEpoch: identity.targetLaneShareEpoch,
    expectedRevocationEpoch: 2,
    reason: 'user_revoked',
    retirementCorrelationId: parseCorrelationId('ed25519-private-retirement'),
    retirementRequestDigestB64u: parseDigestB64u(Buffer.alloc(32, 6).toString('base64url')),
    retirementEffectBindingDigestB64u: parseDigestB64u(Buffer.alloc(32, 7).toString('base64url')),
    requestedAtMs: 9_000,
  });
  const receipt = await buildR102Ed25519ServerRetirementReceiptFixture({ command, identity });
  let request: Request | undefined;
  const transport = new CloudflareSigningWorkerEcdsaRetirementTransportV1({
    signingWorker: {
      async fetch(input) {
        request = input;
        return new Response(JSON.stringify({ outcome: 'applied', receipt }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      },
    },
    internalServiceAuth: 'ed25519-retirement-secret',
    bindingResolver: { resolveRetirementBindingV1: unsupported },
    ed25519BindingResolver: {
      async resolveRetirementBindingV1() {
        return { identity };
      },
    },
  });

  const projection = await transport.retireServerMaterialV1({
    curve: 'ed25519_yao',
    command,
  });

  expect(projection.retirementReceipt).toEqual(receipt);
  expect(Object.keys(projection)).not.toContain('record');
  expect(request).toBeDefined();
  expect(new URL(request!.url).pathname).toBe(
    '/router-ab/internal/signing-worker/ed25519-yao-lane/retire',
  );
});
