import { expect, test } from '@playwright/test';
import type {
  LaneEnrollmentGatewayV1,
  LaneProtocolCommitReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes';
import { parseEcdsaAdditiveLaneHolderRoundV1 } from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import type {
  LaneLifecycleAuthorizationPortV1,
  LaneLifecycleCurveExecutionPortsV1,
} from '../../packages/sdk-server-ts/src/core/signingLanes/LaneLifecycleApplicationService';
import {
  CloudflareEd25519LaneProtocolTransportV1,
  CloudflareLaneProtocolCommitterV1,
  type CloudflareLaneServiceBindingV1,
  type Ed25519YaoLaneBindingResolverPortV1,
} from '../../packages/sdk-server-ts/src/router/cloudflare/signingLanes/cloudflareLaneProtocolCommitter';
import {
  buildR102EcdsaLaneJob,
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
} from './helpers/r102LaneGateway.fixtures';

const DIGEST_B64U = Buffer.alloc(32, 0x42).toString('base64url');

function unsupported(): Promise<never> {
  return Promise.reject(new Error('unsupported test operation'));
}

function gateway(order: string[], received: LaneProtocolCommitReceiptV1[]): LaneEnrollmentGatewayV1 {
  return {
    prepareLaneEnrollmentV1: unsupported,
    resumeLaneProtocolOperationV1: unsupported,
    recordLaneProtocolCommitV1: async ({ receipt, expectedVersion }) => {
      order.push('gateway');
      received.push(receipt);
      return {
        outcome: 'conflict',
        expectedVersion,
        actualVersion: expectedVersion + 1,
        requestedCommandDigestB64u: DIGEST_B64U,
        storedCommandDigestB64u: DIGEST_B64U,
      };
    },
    recordLaneHolderDeliveryV1: unsupported,
    activateLaneServerMaterialV1: unsupported,
    commitLaneEnrollmentActivationV1: unsupported,
    fenceSigningLaneRevocationV1: unsupported,
    completeSigningLaneRevocationV1: unsupported,
  };
}

function authorization(order: string[]): LaneLifecycleAuthorizationPortV1 {
  return {
    async authorizeLaneLifecycleV1() {
      order.push('authorize');
    },
  };
}

function unusedExecution(): LaneLifecycleCurveExecutionPortsV1 {
  return {
    ed25519: {
      executeProtocolCommitV1: unsupported,
      executeServerActivationV1: unsupported,
      executeServerRetirementV1: unsupported,
    },
    ecdsa: {
      executeProtocolCommitV1: unsupported,
      executeServerActivationV1: unsupported,
      executeServerRetirementV1: unsupported,
    },
  };
}

function bindingResolver(order: string[]): Ed25519YaoLaneBindingResolverPortV1 {
  return {
    async resolveBindingV1({ job }) {
      order.push('resolve_binding');
      return {
        lifecycle: {
          lifecycle_id: `lane-lifecycle:${job.operationId}`,
          work_kind: 'server_share_refresh',
          primitive_request_kind: 'refresh',
          root_share_epoch: String(job.source.laneShareEpoch),
          account_id: String(job.source.materialActivation.materialOwner),
          session_id: `lane-session:${job.operationId}`,
          signer_set_id: 'lane-signer-set',
          selected_server_id: String(job.source.materialActivation.signingWorker),
        },
        operation: 'refresh',
        session_id: [...Buffer.alloc(32, 0x11)],
        stable_key_context_binding: [...Buffer.alloc(32, 0x22)],
        material_activation: {
          kind: 'mpc_material_activation_ref',
          activation_id: String(job.source.materialActivation.activationId),
          capability: job.source.materialActivation.capability,
          material_owner: String(job.source.materialActivation.materialOwner),
          key_binding: job.source.materialActivation.keyBinding,
          lifecycle_binding: job.source.materialActivation.lifecycleBinding,
          signing_worker: job.source.materialActivation.signingWorker,
        },
      };
    },
  };
}

function dispatchJson(job: ReturnType<typeof buildR102LaneJob>): string {
  return JSON.stringify({
    job,
    deriverAInput: { opaque: 'deriver-a' },
    deriverBInput: { opaque: 'deriver-b' },
  });
}

function routerResult(job: ReturnType<typeof buildR102LaneJob>, receipt: LaneProtocolCommitReceiptV1) {
  return {
    job,
    transcriptHashB64u: receipt.transcriptHashB64u,
    publicIdentityDigestB64u: receipt.publicIdentityDigestB64u,
    targetHolderPublicCommitmentB64u: receipt.targetHolderPublicCommitmentB64u,
    targetServerPublicCommitmentB64u: receipt.targetServerPublicCommitmentB64u,
    targetHolderCiphertextDigestSetB64u: receipt.targetHolderCiphertextDigestSetB64u,
    targetServerCiphertextDigestSetB64u: receipt.targetServerCiphertextDigestSetB64u,
    holderRecipientKeyDigestB64u: receipt.holderRecipientKeyDigestB64u,
    serverRecipientKeyDigestB64u: receipt.serverRecipientKeyDigestB64u,
    deriverAHolderPackage: { opaque: 'a-holder' },
    deriverBHolderPackage: { opaque: 'b-holder' },
    deriverASigningWorkerPackage: { opaque: 'a-worker' },
    deriverBSigningWorkerPackage: { opaque: 'b-worker' },
    committedAtMs: receipt.committedAtMs,
  };
}

function committer(input: {
  readonly order: string[];
  readonly binding: CloudflareLaneServiceBindingV1;
  readonly received: LaneProtocolCommitReceiptV1[];
  readonly execution?: LaneLifecycleCurveExecutionPortsV1;
}): CloudflareLaneProtocolCommitterV1 {
  return new CloudflareLaneProtocolCommitterV1({
    gateway: gateway(input.order, input.received),
    authorization: authorization(input.order),
    execution: input.execution ?? unusedExecution(),
    ed25519Transport: new CloudflareEd25519LaneProtocolTransportV1({
      router: input.binding,
      internalServiceAuth: 'internal-lane-secret',
      bindingResolver: bindingResolver(input.order),
    }),
  });
}

test.describe('R102 Cloudflare lane protocol committer', () => {
  test('forwards the encrypted client dispatch with its admitted binding, then records the exact receipt', async () => {
    const rawJob = buildR102LaneJob('cloudflare-committer');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const receipt = buildR102ProtocolCommitReceipt(job);
    const order: string[] = [];
    const requests: Request[] = [];
    const received: LaneProtocolCommitReceiptV1[] = [];
    const binding: CloudflareLaneServiceBindingV1 = {
      async fetch(request) {
        order.push('dispatch');
        requests.push(request);
        return Response.json({ result: routerResult(job, receipt), receipt });
      },
    };

    const result = await committer({ order, binding, received }).executeAndRecordEd25519YaoLaneV1(
      {
        job,
        requestJson: dispatchJson(job),
        expectedVersion: 1,
      },
    );

    expect(order).toEqual(['authorize', 'resolve_binding', 'dispatch', 'gateway']);
    expect(received).toEqual([receipt]);
    expect(result.receipt).toEqual(receipt);
    expect(result.protocolCasResult.outcome).toBe('conflict');
    expect(JSON.parse(result.responseJson)).toEqual(routerResult(job, receipt));
    expect(requests).toHaveLength(1);
    expect(requests[0]?.url).toBe(
      'https://router.router-ab.internal/router-ab/internal/ed25519-yao/lane/execute',
    );
    expect(requests[0]?.headers.get('x-router-ab-internal-service-auth')).toBe(
      'internal-lane-secret',
    );
    const body = await requests[0]?.json();
    expect(body).toMatchObject({
      request: {
        job,
        deriverAInput: { opaque: 'deriver-a' },
        deriverBInput: { opaque: 'deriver-b' },
      },
    });
  });

  test('retries one ambiguous transport failure with byte-identical input and a replay marker', async () => {
    const rawJob = buildR102LaneJob('cloudflare-committer-replay');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const receipt = buildR102ProtocolCommitReceipt(job);
    const order: string[] = [];
    const requests: Request[] = [];
    const bodies: string[] = [];
    const received: LaneProtocolCommitReceiptV1[] = [];
    const binding: CloudflareLaneServiceBindingV1 = {
      async fetch(request) {
        requests.push(request);
        bodies.push(await request.clone().text());
        if (requests.length === 1) throw new Error('ambiguous service-binding failure');
        order.push('dispatch');
        return Response.json({ result: routerResult(job, receipt), receipt });
      },
    };

    await committer({ order, binding, received }).executeAndRecordEd25519YaoLaneV1({
      job,
      requestJson: dispatchJson(job),
      expectedVersion: 1,
    });

    expect(requests).toHaveLength(2);
    expect(bodies[0]).toBe(bodies[1]);
    expect(requests[0]?.headers.get('x-seams-lane-replay')).toBeNull();
    expect(requests[1]?.headers.get('x-seams-lane-replay')).toBe('1');
    expect(received).toEqual([receipt]);
  });

  test('rejects a receipt substituted across the exact Router result before Gateway CAS', async () => {
    const rawJob = buildR102LaneJob('cloudflare-committer-substitution');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const receipt = buildR102ProtocolCommitReceipt(job);
    const substituted = { ...receipt, transcriptHashB64u: DIGEST_B64U };
    const order: string[] = [];
    const received: LaneProtocolCommitReceiptV1[] = [];
    const binding: CloudflareLaneServiceBindingV1 = {
      async fetch() {
        order.push('dispatch');
        return Response.json({ result: routerResult(job, receipt), receipt: substituted });
      },
    };

    await expect(
      committer({ order, binding, received }).executeAndRecordEd25519YaoLaneV1({
        job,
        requestJson: dispatchJson(job),
        expectedVersion: 1,
      }),
    ).rejects.toThrow('receipt does not match the committed result');
    expect(received).toEqual([]);
    expect(order).toEqual(['authorize', 'resolve_binding', 'dispatch']);
  });

  test('records an idempotently replayed ECDSA SigningWorker receipt through the same Gateway CAS', async () => {
    const rawJob = buildR102EcdsaLaneJob('cloudflare-committer-ecdsa');
    if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
    const job = rawJob;
    const receipt = buildR102ProtocolCommitReceipt(job);
    const order: string[] = [];
    const received: LaneProtocolCommitReceiptV1[] = [];
    const base = unusedExecution();
    const execution: LaneLifecycleCurveExecutionPortsV1 = {
      ed25519: base.ed25519,
      ecdsa: {
        async executeProtocolCommitV1() {
          order.push('ecdsa_effect_replayed');
          return receipt;
        },
        executeServerActivationV1: base.ecdsa.executeServerActivationV1,
        executeServerRetirementV1: base.ecdsa.executeServerRetirementV1,
      },
    };
    const holderRound = parseEcdsaAdditiveLaneHolderRoundV1({
      kind: 'ecdsa_additive_lane_holder_round_v1',
      preambleHashB64u: DIGEST_B64U,
      targetHolderPublicCommitment33B64u: job.thresholdPublicKey33B64u,
      encryptedDeltaCiphertextDigestB64u: DIGEST_B64U,
      sealedTargetHolderMaterialDigestB64u: DIGEST_B64U,
      holderAttestationB64u: 'holder-attestation-r102',
      holderCommittedAtMs: 1_500,
    });

    const result = await committer({
      order,
      binding: { fetch: unsupported },
      received,
      execution,
    }).executeAndRecordEcdsaAdditiveLaneV1({
      job,
      holderRound,
      encryptedDeltaPackageJson: '{"opaque":"delta"}',
      expectedVersion: 1,
    });

    expect(order).toEqual(['authorize', 'ecdsa_effect_replayed', 'gateway']);
    expect(received).toEqual([receipt]);
    expect(result.receipt).toEqual(receipt);
    expect(result.protocolCasResult.outcome).toBe('conflict');
  });
});
