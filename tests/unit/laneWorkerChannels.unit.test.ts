import { expect, test } from '@playwright/test';
import {
  createAuthorizedLaneHolderWorkerRequestHandlerV1,
  createLaneHolderWorkerTransportV1,
  type LaneHolderWorkerEndpointV1,
} from '../../packages/wallet/src/core/signingEngine/workerManager/laneWorkerChannels';
import type {
  LaneHolderPackageWireV1,
  LaneHolderRecipientWorkerV1,
} from '../../packages/shared-ts/src/signing-lanes/rotation';
import {
  bindR102TargetHolderParticipantV1,
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import {
  parseLaneHolderPackageWireV1,
  parseLaneProtocolCommitReceiptV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import { parseLaneHolderRecipientHandleV1 } from '../../packages/shared-ts/src/utils/domainIds';

const DIGEST_B64U = Buffer.alloc(32, 0).toString('base64url');
const SEALED_MATERIAL_B64U = Buffer.from('sealed-lane-holder').toString('base64url');

function value<T>(
  result:
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
): T {
  if (result.ok) return result.value;
  throw new Error(result.error.message);
}

function ed25519HolderPackage(): LaneHolderPackageWireV1 {
  return parseLaneHolderPackageWireV1({
    kind: 'ed25519_yao_lane_holder_package_set_v1',
    deriverAEncryptedPackageJson: '{}',
    deriverBEncryptedPackageJson: '{}',
  });
}

type BackendCalls = {
  readonly create: string[];
  readonly open: string[];
  readonly verify: string[];
  readonly discard: string[];
  readonly invalidate: string[];
};

function backendCalls(): BackendCalls {
  return { create: [], open: [], verify: [], discard: [], invalidate: [] };
}

function authorizedBackend(
  job: ReturnType<typeof buildR102LaneJob>,
  calls: BackendCalls,
): LaneHolderRecipientWorkerV1 {
  return {
    createLaneHolderRecipientV1: async (input) => {
      calls.create.push(String(input.operationId));
      const recipientHandle = value(
        parseLaneHolderRecipientHandleV1(`recipient-handle:${String(input.operationId)}`),
      );
      return {
        recipientHandle,
        hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
        hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      };
    },
    openAndSealLaneHolderPackageV1: async (input) => {
      calls.open.push(String(input.job.operationId));
      return {
        sealedHolderMaterialB64u: SEALED_MATERIAL_B64U,
        sealedHolderRecordDigestB64u: DIGEST_B64U,
        verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U,
      };
    },
    verifyLaneHolderPackageCommitmentV1: async (input) => {
      calls.verify.push(String(input.job.operationId));
      return { verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U };
    },
    discardLaneHolderRecipientV1: async (input) => {
      calls.discard.push(String(input.operationId));
    },
    invalidateLaneMaterialV1: async (input) => {
      calls.invalidate.push(String(input.laneId));
    },
  };
}

function recipientCreateRequest(job: ReturnType<typeof buildR102LaneJob>) {
  return {
    kind: 'lane_holder_recipient_create_v1' as const,
    input: {
      operationId: job.operationId,
      enrollmentId: job.enrollmentId,
      walletKeyId: job.walletKeyId,
      targetLaneId: job.target.laneId,
      targetLaneShareEpoch: job.target.laneShareEpoch,
      targetMaterialActivationId: job.targetMaterialActivationId,
      targetHolderParticipantId: job.targetHolder.participantId,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
    },
  };
}

class FakeLaneHolderWorkerEndpoint implements LaneHolderWorkerEndpointV1 {
  private messageListener: ((event: MessageEvent) => void) | null = null;
  private errorListener: ((event: ErrorEvent) => void) | null = null;
  private readonly pending = new Set<string>();

  postMessage(message: unknown): void {
    if (!message || typeof message !== 'object' || Array.isArray(message)) {
      throw new Error('test frame is invalid');
    }
    const frame = message as { id?: unknown };
    if (typeof frame.id !== 'string') throw new Error('test frame id is missing');
    this.pending.add(frame.id);
  }

  addEventListener(
    type: 'message' | 'error',
    listener: ((event: MessageEvent) => void) | ((event: ErrorEvent) => void),
  ): void {
    if (type === 'message') this.messageListener = listener as (event: MessageEvent) => void;
    else this.errorListener = listener as (event: ErrorEvent) => void;
  }

  removeEventListener(type: 'message' | 'error'): void {
    if (type === 'message') this.messageListener = null;
    else this.errorListener = null;
  }

  terminate(): void {
    this.messageListener = null;
    this.errorListener = null;
  }

  resolve(result: unknown): void {
    const [id] = this.pending;
    if (!id || !this.messageListener) return;
    this.pending.delete(id);
    this.messageListener({ data: { id, ok: true, result } } as MessageEvent);
  }

  reject(message: string): void {
    const [id] = this.pending;
    if (!id || !this.messageListener) return;
    this.pending.delete(id);
    this.messageListener({ data: { id, ok: false, error: message } } as MessageEvent);
  }
}

test.describe('R102 lane holder worker transport', () => {
  test('carries only request frames and resolves the exact response id', async () => {
    const endpoint = new FakeLaneHolderWorkerEndpoint();
    const transport = createLaneHolderWorkerTransportV1({ endpoint, timeoutMs: 500 });
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-transport'),
    );
    const response = transport.request({
      kind: 'lane_holder_recipient_create_v1',
      input: {
        operationId: job.operationId,
        enrollmentId: job.enrollmentId,
        walletKeyId: job.walletKeyId,
        targetLaneId: job.target.laneId,
        targetLaneShareEpoch: job.target.laneShareEpoch,
        targetMaterialActivationId: job.targetMaterialActivationId,
        targetHolderParticipantId: job.targetHolder.participantId,
        custodyBindingId: job.targetHolder.custodyBindingId,
        custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      },
    });
    endpoint.resolve({ kind: 'opaque-worker-result-v1' });
    await expect(response).resolves.toEqual({ kind: 'opaque-worker-result-v1' });
    transport.close();
  });

  test('rejects pending requests when the transport closes', async () => {
    const endpoint = new FakeLaneHolderWorkerEndpoint();
    const transport = createLaneHolderWorkerTransportV1({ endpoint, timeoutMs: 500 });
    const job = await bindR102TargetHolderParticipantV1(buildR102LaneJob('worker-close'));
    const response = transport.request({
      kind: 'lane_holder_recipient_create_v1',
      input: {
        operationId: job.operationId,
        enrollmentId: job.enrollmentId,
        walletKeyId: job.walletKeyId,
        targetLaneId: job.target.laneId,
        targetLaneShareEpoch: job.target.laneShareEpoch,
        targetMaterialActivationId: job.targetMaterialActivationId,
        targetHolderParticipantId: job.targetHolder.participantId,
        custodyBindingId: job.targetHolder.custodyBindingId,
        custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      },
    });
    transport.close();
    await expect(response).rejects.toThrow('transport is closed');
  });
});

test.describe('R102 authorized lane holder worker request handler', () => {
  test('enforces open, sealing, sealed, and discarded recipient states', async () => {
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-states'),
    );
    const commit = buildR102ProtocolCommitReceipt(job);
    const calls = backendCalls();
    const handler = createAuthorizedLaneHolderWorkerRequestHandlerV1(authorizedBackend(job, calls));
    const descriptor = (await handler.request(recipientCreateRequest(job))) as {
      recipientHandle: string;
    };
    const request = {
      kind: 'lane_holder_package_open_seal_v1' as const,
      job,
      protocolCommitReceipt: commit,
      holderPackage: ed25519HolderPackage(),
      recipientHandle: descriptor.recipientHandle,
    };
    await expect(handler.request(request)).resolves.toMatchObject({
      verifiedHolderCiphertextDigestSetB64u: DIGEST_B64U,
    });
    await expect(handler.request(request)).rejects.toThrow('cannot seal from sealed state');
    await handler.request({
      kind: 'lane_holder_recipient_discard_v1',
      recipientHandle: descriptor.recipientHandle,
      operationId: job.operationId,
    });
    expect(calls.create).toEqual([String(job.operationId)]);
    expect(calls.open).toEqual([String(job.operationId)]);
    expect(calls.discard).toEqual([String(job.operationId)]);
    await handler.close();
  });

  test('rejects receipt substitution before crypto and discards the recipient', async () => {
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-substitution'),
    );
    const commit = buildR102ProtocolCommitReceipt(job);
    const substitutedCommit = parseLaneProtocolCommitReceiptV1({
      ...commit,
      walletKeyId: 'wallet-key-r102-substituted',
    });
    const calls = backendCalls();
    const handler = createAuthorizedLaneHolderWorkerRequestHandlerV1(authorizedBackend(job, calls));
    const descriptor = (await handler.request(recipientCreateRequest(job))) as {
      recipientHandle: string;
    };
    await expect(
      handler.request({
        kind: 'lane_holder_package_open_seal_v1',
        job,
        protocolCommitReceipt: substitutedCommit,
        holderPackage: ed25519HolderPackage(),
        recipientHandle: descriptor.recipientHandle,
      }),
    ).rejects.toThrow('does not match its exact job and protocol receipt');
    expect(calls.open).toEqual([]);
    expect(calls.discard).toEqual([String(job.operationId)]);
    await expect(
      handler.request({
        kind: 'lane_holder_package_open_seal_v1',
        job,
        protocolCommitReceipt: commit,
        holderPackage: ed25519HolderPackage(),
        recipientHandle: descriptor.recipientHandle,
      }),
    ).rejects.toThrow('unknown or discarded');
    await handler.close();
  });

  test('rejects a backend digest that is outside the committed transcript', async () => {
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-digest'),
    );
    const calls = backendCalls();
    const backend = authorizedBackend(job, calls);
    const substitutedDigest = Buffer.alloc(32, 1).toString('base64url');
    backend.verifyLaneHolderPackageCommitmentV1 = async () => ({
      verifiedHolderCiphertextDigestSetB64u: substitutedDigest,
    });
    const handler = createAuthorizedLaneHolderWorkerRequestHandlerV1(backend);
    await expect(
      handler.request({
        kind: 'lane_holder_package_verify_v1',
        job,
        protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
        holderPackage: ed25519HolderPackage(),
      }),
    ).rejects.toThrow('does not match the committed transcript');
    await handler.close();
  });

  test('invalidates the exact material and releases matching open recipients', async () => {
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-invalidate'),
    );
    const unrelatedJob = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-unrelated'),
    );
    const calls = backendCalls();
    const handler = createAuthorizedLaneHolderWorkerRequestHandlerV1(authorizedBackend(job, calls));
    const descriptor = (await handler.request(recipientCreateRequest(job))) as {
      recipientHandle: string;
    };
    const unrelatedDescriptor = (await handler.request(recipientCreateRequest(unrelatedJob))) as {
      recipientHandle: string;
    };
    await handler.request({
      kind: 'lane_holder_package_open_seal_v1',
      job,
      protocolCommitReceipt: buildR102ProtocolCommitReceipt(job),
      holderPackage: ed25519HolderPackage(),
      recipientHandle: descriptor.recipientHandle,
    });
    await handler.request({
      kind: 'lane_holder_package_open_seal_v1',
      job: unrelatedJob,
      protocolCommitReceipt: buildR102ProtocolCommitReceipt(unrelatedJob),
      holderPackage: ed25519HolderPackage(),
      recipientHandle: unrelatedDescriptor.recipientHandle,
    });
    await handler.request({
      kind: 'lane_material_invalidate_v1',
      walletKeyId: job.walletKeyId,
      laneId: job.target.laneId,
      laneShareEpoch: job.target.laneShareEpoch,
      materialActivation: buildR102ServerActivationReceipt(job).targetMaterialActivation,
    });
    expect(calls.invalidate).toEqual([String(job.target.laneId)]);
    expect(calls.discard).toEqual([String(job.operationId)]);
    await handler.close();
    expect(calls.discard).toEqual([String(job.operationId), String(unrelatedJob.operationId)]);
  });

  test('fails closed on unknown fields and releases open recipients at shutdown', async () => {
    const job = await bindR102TargetHolderParticipantV1(
      buildR102LaneJob('worker-handler-close'),
    );
    const calls = backendCalls();
    const handler = createAuthorizedLaneHolderWorkerRequestHandlerV1(authorizedBackend(job, calls));
    await expect(
      handler.request({ ...recipientCreateRequest(job), unexpected: true }),
    ).rejects.toThrow('unexpected is not supported');
    await handler.request(recipientCreateRequest(job));
    await handler.close();
    expect(calls.discard).toEqual([String(job.operationId)]);
    await expect(handler.request(recipientCreateRequest(job))).rejects.toThrow('is closed');
  });
});
