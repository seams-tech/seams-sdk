import { expect, test } from '@playwright/test';
import { LaneLifecycleApplicationService } from '../../packages/sdk-server-ts/src/core/signingLanes/LaneLifecycleApplicationService';
import type {
  LaneLifecycleAuthorizationPortV1,
  LaneLifecycleCurveExecutionPortsV1,
  LaneLifecycleRetirementExecutionV1,
} from '../../packages/sdk-server-ts/src/core/signingLanes/LaneLifecycleApplicationService';
import type {
  LaneEnrollmentGatewayV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  LaneServerRetirementReceiptV1,
  LaneSigningLaneRevocationFenceResultV1,
  LaneSigningLaneRevocationResultV1,
  RevokeSigningLaneV1,
  RotatableSigningLaneJobV1,
} from '../../packages/shared-ts/src/signing-lanes';
import {
  buildLaneProductEpochRevocationPendingV1,
  buildLaneProductEpochRevokedV1,
  buildRevokeSigningLaneV1,
} from '../../packages/shared-ts/src/signing-lanes/rotationParsers';
import {
  parseLaneHolderParticipantRecordV1,
  parseSigningWorkerParticipantRecordV1,
} from '../../packages/shared-ts/src/signing-lanes/participants';
import {
  parseCorrelationId,
  parseDigestB64u,
} from '../../packages/shared-ts/src/utils/canonicalPrimitives';
import {
  buildR102HolderDeliveryReceipt,
  buildR102EcdsaLaneJob,
  buildR102LaneJob,
  buildR102ProtocolCommitReceipt,
  buildR102ServerActivationReceipt,
} from './helpers/r102LaneGateway.fixtures';
import { buildR102EcdsaServerRetirementReceipt } from './helpers/ecdsaServerRetirement.fixtures';

const DIGEST_B64U = parseDigestB64u(Buffer.alloc(32, 0).toString('base64url'));
const OTHER_DIGEST_B64U = parseDigestB64u(Buffer.alloc(32, 1).toString('base64url'));

function unsupported(): Promise<never> {
  return Promise.reject(new Error('unsupported test gateway operation'));
}

function protocolConflict(): LaneProtocolCasResultV1 {
  return {
    outcome: 'conflict',
    expectedVersion: 1,
    actualVersion: 2,
    requestedCommandDigestB64u: DIGEST_B64U,
    storedCommandDigestB64u: DIGEST_B64U,
  };
}

function laneRevocationConflict(
  command: RevokeSigningLaneV1,
): LaneSigningLaneRevocationFenceResultV1 {
  return {
    kind: 'lane_signing_lane_revocation_fence_result_v1',
    outcome: 'conflict',
    walletKeyId: command.walletKeyId,
    laneId: command.laneId,
    laneShareEpoch: command.laneShareEpoch,
    expectedVersion: 1,
    actualVersion: 2,
    requestedCommandDigestB64u: DIGEST_B64U,
    storedCommandDigestB64u: DIGEST_B64U,
  };
}

function gateway(
  calls: {
    protocolCommits: LaneProtocolCommitReceiptV1[];
    activations: LaneServerActivationReceiptV1[];
    revocations: string[];
    order: string[];
  },
  revocationFence: (
    command: RevokeSigningLaneV1,
  ) => LaneSigningLaneRevocationFenceResultV1 = laneRevocationConflict,
  revocationCompletion: (
    input: Parameters<LaneEnrollmentGatewayV1['completeSigningLaneRevocationV1']>[0],
  ) => LaneSigningLaneRevocationResultV1 = () => {
    throw new Error('unexpected revocation completion');
  },
): LaneEnrollmentGatewayV1 {
  return {
    prepareLaneEnrollmentV1: unsupported,
    resumeLaneProtocolOperationV1: unsupported,
    recordLaneProtocolCommitV1: async ({ receipt }) => {
      calls.protocolCommits.push(receipt);
      return protocolConflict();
    },
    recordLaneHolderDeliveryV1: unsupported,
    activateLaneServerMaterialV1: async ({ receipt }) => {
      calls.activations.push(receipt);
      return protocolConflict();
    },
    commitLaneEnrollmentActivationV1: unsupported,
    fenceSigningLaneRevocationV1: async (command) => {
      calls.order.push('gateway.revocation.fence');
      calls.revocations.push(command.retirementEffectBindingDigestB64u);
      return revocationFence(command);
    },
    completeSigningLaneRevocationV1: async (input) => {
      calls.order.push('gateway.revocation.complete');
      return revocationCompletion(input);
    },
    revokeLaneEnrollmentV1: unsupported,
  };
}

function laneRevocationFencePending(
  job: RotatableSigningLaneJobV1,
  command: RevokeSigningLaneV1,
): LaneSigningLaneRevocationFenceResultV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  const activation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
  const productEpoch = buildLaneProductEpochRevocationPendingV1({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneKind: job.target.laneKind,
    laneShareEpoch: job.target.laneShareEpoch,
    keyFamily: job.keyFamily,
    enrollmentId: job.enrollmentId,
    operationId: job.operationId,
    targetMaterialActivationId: job.targetMaterialActivationId,
    materialActivation: activation,
    publicIdentityDigestB64u: DIGEST_B64U,
    holderParticipant: parseLaneHolderParticipantRecordV1({
      kind: 'lane_holder_participant_v1',
      participantId: job.targetHolder.participantId,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    }),
    signingWorkerParticipant: parseSigningWorkerParticipantRecordV1({
      kind: 'signing_worker_participant_v1',
      participantId: job.targetSigningWorker.participantId,
      recipientKeyId: job.targetSigningWorker.recipientKeyId,
      hpkePublicKeyB64u: job.targetSigningWorker.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
      participantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
    }),
    participantSetBindingDigestB64u: DIGEST_B64U,
    revocationEpoch: command.expectedRevocationEpoch + 1,
    createdAtMs: 1_000,
    revocationReason: command.reason,
    retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
    revocationRequestedAtMs: command.requestedAtMs,
  });
  return {
    kind: 'lane_signing_lane_revocation_fence_result_v1',
    outcome: 'applied',
    walletKeyId: command.walletKeyId,
    laneId: command.laneId,
    laneShareEpoch: command.laneShareEpoch,
    version: 2,
    commandDigestB64u: DIGEST_B64U,
    productEpoch,
  };
}

function laneRevocationApplied(
  job: RotatableSigningLaneJobV1,
  command: RevokeSigningLaneV1,
  retirementReceipt: LaneServerRetirementReceiptV1,
): LaneSigningLaneRevocationResultV1 {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  const activation = buildR102ServerActivationReceipt(job).targetMaterialActivation;
  const productEpoch = buildLaneProductEpochRevokedV1({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneKind: job.target.laneKind,
    laneShareEpoch: job.target.laneShareEpoch,
    keyFamily: job.keyFamily,
    enrollmentId: job.enrollmentId,
    operationId: job.operationId,
    targetMaterialActivationId: job.targetMaterialActivationId,
    materialActivation: activation,
    publicIdentityDigestB64u: DIGEST_B64U,
    holderParticipant: parseLaneHolderParticipantRecordV1({
      kind: 'lane_holder_participant_v1',
      participantId: job.targetHolder.participantId,
      custodyBindingId: job.targetHolder.custodyBindingId,
      custodyBindingDigestB64u: job.targetHolder.custodyBindingDigestB64u,
      hpkePublicKeyB64u: job.targetHolder.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: job.targetHolder.hpkePublicKeyDigestB64u,
      participantBindingDigestB64u: job.targetHolder.participantBindingDigestB64u,
    }),
    signingWorkerParticipant: parseSigningWorkerParticipantRecordV1({
      kind: 'signing_worker_participant_v1',
      participantId: job.targetSigningWorker.participantId,
      recipientKeyId: job.targetSigningWorker.recipientKeyId,
      hpkePublicKeyB64u: job.targetSigningWorker.hpkePublicKeyB64u,
      hpkePublicKeyDigestB64u: job.targetSigningWorker.hpkePublicKeyDigestB64u,
      participantBindingDigestB64u: job.targetSigningWorker.participantBindingDigestB64u,
    }),
    participantSetBindingDigestB64u: DIGEST_B64U,
    revocationEpoch: command.expectedRevocationEpoch + 1,
    createdAtMs: 1_000,
    revocationReason: command.reason,
    retirementEffectBindingDigestB64u: command.retirementEffectBindingDigestB64u,
    revocationReceiptDigestB64u: retirementReceipt.receiptDigestB64u,
    revokedAtMs: command.requestedAtMs,
  });
  return {
    kind: 'lane_signing_lane_revocation_result_v1',
    outcome: 'applied',
    walletKeyId: command.walletKeyId,
    laneId: command.laneId,
    laneShareEpoch: command.laneShareEpoch,
    version: 2,
    commandDigestB64u: DIGEST_B64U,
    productEpoch,
    retirementReceipt,
  };
}

function executionPorts(input: {
  readonly protocolReceipt: LaneProtocolCommitReceiptV1;
  readonly activationReceipt: LaneServerActivationReceiptV1;
  readonly retirementCommand: LaneLifecycleRetirementExecutionV1;
  readonly calls: string[];
}): LaneLifecycleCurveExecutionPortsV1 {
  const ed25519 = {
    executeProtocolCommitV1: async () => {
      input.calls.push('ed25519.protocol');
      return input.protocolReceipt;
    },
    executeServerActivationV1: async () => {
      input.calls.push('ed25519.activation');
      return input.activationReceipt;
    },
    executeServerRetirementV1: async () => {
      input.calls.push('ed25519.retirement');
      return input.retirementCommand;
    },
  } satisfies LaneLifecycleCurveExecutionPortsV1['ed25519'];
  const ecdsa = {
    executeProtocolCommitV1: unsupported,
    executeServerActivationV1: unsupported,
    executeServerRetirementV1: unsupported,
  } satisfies LaneLifecycleCurveExecutionPortsV1['ecdsa'];
  return { ed25519, ecdsa };
}

function ecdsaRetirementExecutionPorts(input: {
  readonly retirementCommand: LaneLifecycleRetirementExecutionV1;
  readonly calls: string[];
}): LaneLifecycleCurveExecutionPortsV1 {
  return {
    ed25519: {
      executeProtocolCommitV1: unsupported,
      executeServerActivationV1: unsupported,
      executeServerRetirementV1: unsupported,
    },
    ecdsa: {
      executeProtocolCommitV1: unsupported,
      executeServerActivationV1: unsupported,
      async executeServerRetirementV1() {
        input.calls.push('ecdsa.retirement');
        return input.retirementCommand;
      },
    },
  };
}

function commandFor(job: RotatableSigningLaneJobV1) {
  if (job.target.operation !== 'create_lane') throw new Error('fixture target must be creation');
  return buildRevokeSigningLaneV1({
    walletId: job.walletId,
    walletKeyId: job.walletKeyId,
    laneId: job.target.laneId,
    laneShareEpoch: job.target.laneShareEpoch,
    expectedRevocationEpoch: 1,
    reason: 'rotation',
    retirementCorrelationId: parseCorrelationId('correlation-r102-application'),
    retirementRequestDigestB64u: DIGEST_B64U,
    retirementEffectBindingDigestB64u: DIGEST_B64U,
    requestedAtMs: 5_000,
  });
}

function authorization(calls: string[], denied = false): LaneLifecycleAuthorizationPortV1 {
  return {
    async authorizeLaneLifecycleV1(input) {
      calls.push(input.kind);
      if (denied) throw new Error('lane lifecycle authorization denied');
    },
  };
}

type ApplicationCalls = {
  readonly protocolCommits: LaneProtocolCommitReceiptV1[];
  readonly activations: LaneServerActivationReceiptV1[];
  readonly revocations: string[];
  readonly order: string[];
};

function applicationCalls(): ApplicationCalls {
  return { protocolCommits: [], activations: [], revocations: [], order: [] };
}

async function exactRetirementReceipt(suffix: string): Promise<LaneServerRetirementReceiptV1> {
  const job = buildR102EcdsaLaneJob(`receipt-${suffix}`);
  if (job.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
  return await buildR102EcdsaServerRetirementReceipt(job);
}

test.describe('R102 server-internal lane lifecycle application service', () => {
  test('authorizes before curve execution and records the exact protocol CAS result', async () => {
    const rawJob = buildR102LaneJob('application');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const protocolReceipt = buildR102ProtocolCommitReceipt(job);
    const activationReceipt = buildR102ServerActivationReceipt(job);
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(calls),
      authorization: authorization(calls.order),
      execution: executionPorts({
        protocolReceipt,
        activationReceipt,
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command: commandFor(job),
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt: await exactRetirementReceipt('protocol'),
        },
        calls: calls.order,
      }),
    });

    const result = await service.recordLaneProtocolCommitV1({
      curve: 'ed25519_yao',
      job,
      requestJson: '{}',
      expectedVersion: 1,
    });
    expect(result.outcome).toBe('conflict');
    expect(calls.order).toEqual(['record_lane_protocol_commit_v1', 'ed25519.protocol']);
    expect(calls.protocolCommits).toEqual([protocolReceipt]);
  });

  test('keeps server activation behind receipt identity checks and propagates Gateway replay/conflict', async () => {
    const rawJob = buildR102LaneJob('activation');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const protocolReceipt = buildR102ProtocolCommitReceipt(job);
    const holderReceipt = buildR102HolderDeliveryReceipt(job);
    const activationReceipt = buildR102ServerActivationReceipt(job);
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(calls),
      authorization: authorization(calls.order),
      execution: executionPorts({
        protocolReceipt,
        activationReceipt,
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command: commandFor(job),
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt: await exactRetirementReceipt('activation'),
        },
        calls: calls.order,
      }),
    });

    const result = await service.activateLaneServerMaterialV1({
      curve: 'ed25519_yao',
      job,
      protocolCommitReceipt: protocolReceipt,
      holderDeliveryReceipt: holderReceipt,
      expectedVersion: 2,
    });
    expect(result.outcome).toBe('conflict');
    expect(calls.order).toEqual(['activate_lane_server_material_v1', 'ed25519.activation']);
    expect(calls.activations).toEqual([activationReceipt]);
  });

  test('fences admission before rejecting a substituted retirement command', async () => {
    const rawJob = buildR102LaneJob('application-revocation');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const command = commandFor(job);
    const substitutedCommand = { ...command, requestedAtMs: command.requestedAtMs + 1 };
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(
        calls,
        (fencedCommand) => laneRevocationFencePending(job, fencedCommand),
        (completion) =>
          laneRevocationApplied(job, completion.command, completion.retirementReceipt),
      ),
      authorization: authorization(calls.order),
      execution: executionPorts({
        protocolReceipt: buildR102ProtocolCommitReceipt(job),
        activationReceipt: buildR102ServerActivationReceipt(job),
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command: substitutedCommand,
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt: await exactRetirementReceipt('substituted-command'),
        },
        calls: calls.order,
      }),
    });

    await expect(service.revokeSigningLaneV1({ curve: 'ed25519_yao', command })).rejects.toThrow(
      'changed the authorized command',
    );
    expect(calls.order).toEqual([
      'revoke_signing_lane_v1',
      'gateway.revocation.fence',
      'ed25519.retirement',
    ]);
    expect(calls.revocations).toEqual([DIGEST_B64U]);
  });

  test('requires the exact retirement effect binding after the revocation fence', async () => {
    const rawJob = buildR102LaneJob('application-revocation-digest');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const command = commandFor(job);
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(
        calls,
        (fencedCommand) => laneRevocationFencePending(job, fencedCommand),
        (completion) =>
          laneRevocationApplied(job, completion.command, completion.retirementReceipt),
      ),
      authorization: authorization(calls.order),
      execution: executionPorts({
        protocolReceipt: buildR102ProtocolCommitReceipt(job),
        activationReceipt: buildR102ServerActivationReceipt(job),
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command,
          retirementEffectBindingDigestB64u: OTHER_DIGEST_B64U,
          retirementReceipt: await exactRetirementReceipt('effect-substitution'),
        },
        calls: calls.order,
      }),
    });

    await expect(service.revokeSigningLaneV1({ curve: 'ed25519_yao', command })).rejects.toThrow(
      'effect binding digest does not match',
    );
    expect(calls.order).toEqual([
      'revoke_signing_lane_v1',
      'gateway.revocation.fence',
      'ed25519.retirement',
    ]);
  });

  test('completes ECDSA retirement after the durable Gateway fence', async () => {
    const rawJob = buildR102EcdsaLaneJob('application-ecdsa-retirement');
    if (rawJob.keyFamily !== 'ecdsa_secp256k1') throw new Error('fixture key family changed');
    const command = commandFor(rawJob);
    const retirementReceipt = await buildR102EcdsaServerRetirementReceipt(rawJob);
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(
        calls,
        (fencedCommand) => laneRevocationFencePending(rawJob, fencedCommand),
        (completion) => {
          expect(completion.retirementReceipt).toEqual(retirementReceipt);
          return laneRevocationApplied(rawJob, completion.command, completion.retirementReceipt);
        },
      ),
      authorization: authorization(calls.order),
      execution: ecdsaRetirementExecutionPorts({
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command,
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt,
        },
        calls: calls.order,
      }),
    });

    const result = await service.revokeSigningLaneV1({ curve: 'ecdsa_additive', command });

    expect(result.outcome).toBe('applied');
    expect(calls.order).toEqual([
      'revoke_signing_lane_v1',
      'gateway.revocation.fence',
      'ecdsa.retirement',
      'gateway.revocation.complete',
    ]);
  });

  test('returns an exact completed replay without re-dispatching retirement', async () => {
    const rawJob = buildR102LaneJob('application-completed-replay');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const command = commandFor(rawJob);
    const retirementReceipt = await exactRetirementReceipt('completed-replay');
    const completed = laneRevocationApplied(rawJob, command, retirementReceipt);
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(calls, () => ({
        kind: 'lane_signing_lane_revocation_fence_result_v1',
        outcome: 'already_completed',
        walletKeyId: command.walletKeyId,
        laneId: command.laneId,
        laneShareEpoch: command.laneShareEpoch,
        version: completed.version,
        commandDigestB64u: completed.commandDigestB64u,
        productEpoch: completed.productEpoch,
        retirementReceipt: completed.retirementReceipt,
      })),
      authorization: authorization(calls.order),
      execution: executionPorts({
        protocolReceipt: buildR102ProtocolCommitReceipt(rawJob),
        activationReceipt: buildR102ServerActivationReceipt(rawJob),
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command,
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt,
        },
        calls: calls.order,
      }),
    });

    const result = await service.revokeSigningLaneV1({ curve: 'ed25519_yao', command });

    expect(result.outcome).toBe('replayed');
    expect(result.productEpoch).toEqual(completed.productEpoch);
    expect(calls.order).toEqual(['revoke_signing_lane_v1', 'gateway.revocation.fence']);
  });

  test('does not execute curve work when internal authorization denies the request', async () => {
    const rawJob = buildR102LaneJob('denied');
    if (rawJob.keyFamily !== 'ed25519') throw new Error('fixture key family changed');
    const job = rawJob;
    const calls = applicationCalls();
    const service = new LaneLifecycleApplicationService({
      gateway: gateway(calls),
      authorization: authorization(calls.order, true),
      execution: executionPorts({
        protocolReceipt: buildR102ProtocolCommitReceipt(job),
        activationReceipt: buildR102ServerActivationReceipt(job),
        retirementCommand: {
          kind: 'lane_lifecycle_retirement_execution_v1',
          command: commandFor(job),
          retirementEffectBindingDigestB64u: DIGEST_B64U,
          retirementReceipt: await exactRetirementReceipt('denied'),
        },
        calls: calls.order,
      }),
    });

    await expect(
      service.recordLaneProtocolCommitV1({
        curve: 'ed25519_yao',
        job,
        requestJson: '{}',
        expectedVersion: 1,
      }),
    ).rejects.toThrow('authorization denied');
    expect(calls.order).toEqual(['record_lane_protocol_commit_v1']);
    expect(calls.protocolCommits).toEqual([]);
    expect(calls.revocations).toEqual([]);
  });
});
