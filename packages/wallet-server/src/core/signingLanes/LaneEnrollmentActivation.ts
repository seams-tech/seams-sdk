import {
  buildLaneProtocolRecordV1,
  parseLaneHolderDeliveryReceiptV1,
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
} from '@shared/signing-lanes/rotationParsers';
import {
  computeLaneEnrollmentManifestDigestV1,
  encodeLaneHolderDeliveryReceiptV1,
  encodeLaneProtocolCommitReceiptV1,
  encodeLaneServerActivationReceiptV1,
} from '@shared/signing-lanes/rotationDigests';
import { transitionLaneProtocolLifecycleV1 } from '@shared/signing-lanes/rotationLifecycle';
import type {
  ActivateLaneServerMaterialV1,
  CommitLaneEnrollmentActivationV1,
  LaneEnrollmentActivationResultV1,
  LaneEnrollmentGatewayV1,
  LaneEnrollmentPreparationResultV1,
  LaneProtocolCasResultV1,
  LaneProtocolLifecycle,
  PreparedLaneProtocolRecordV1,
  PrepareLaneEnrollmentV1,
  RecordLaneHolderDeliveryV1,
  RecordLaneProtocolCommitV1,
  ResumeLaneProtocolOperationV1,
} from '@shared/signing-lanes';
import { base64UrlEncode } from '@shared/utils/base64';
import { parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { sha256Bytes, sha256BytesUtf8 } from '@shared/utils/digests';
import type { LaneEnrollmentAdmissionInput, LaneLifecycleStore } from './LaneLifecycleStore';

export class LaneEnrollmentActivation implements Pick<
  LaneEnrollmentGatewayV1,
  | 'prepareLaneEnrollmentV1'
  | 'resumeLaneProtocolOperationV1'
  | 'recordLaneProtocolCommitV1'
  | 'recordLaneHolderDeliveryV1'
  | 'activateLaneServerMaterialV1'
  | 'commitLaneEnrollmentActivationV1'
> {
  constructor(private readonly lifecycleStore: LaneLifecycleStore) {}

  async prepareLaneEnrollmentV1(
    input: PrepareLaneEnrollmentV1,
  ): Promise<LaneEnrollmentPreparationResultV1> {
    const commandDigestB64u = await computeLaneEnrollmentManifestDigestV1(input.manifest);
    const lifecycle: Extract<
      import('@shared/signing-lanes').LaneEnrollmentLifecycleV1,
      { state: 'preparing' }
    > = {
      state: 'preparing',
      manifestDigestB64u: commandDigestB64u,
      startedAtMs: input.manifest.createdAtMs,
    };
    const admissionInput: LaneEnrollmentAdmissionInput = {
      manifest: input.manifest,
      children: input.children.map((job) =>
        buildLaneProtocolRecordV1({
          job,
          lifecycle: {
            state: 'awaiting_protocol_commitment',
            startedAtMs: input.manifest.createdAtMs,
          },
        }),
      ),
      commandDigestB64u,
      lifecycle,
    };
    const admitted = await this.lifecycleStore.putEnrollmentAdmission(admissionInput);
    if (admitted.outcome === 'conflict') {
      return {
        kind: 'lane_enrollment_preparation_result_v1',
        outcome: 'conflict',
        enrollmentId: input.manifest.enrollmentId,
        expectedVersion: admitted.expectedVersion ?? 0,
        actualVersion: admitted.actualVersion,
        requestedCommandDigestB64u: parseDigestB64u(admitted.requestedCommandDigestB64u),
        storedCommandDigestB64u: parseDigestB64u(admitted.storedCommandDigestB64u),
      };
    }
    const orderedProtocols = await readOrderedProtocols(this.lifecycleStore, input.children);
    return {
      kind: 'lane_enrollment_preparation_result_v1',
      outcome: admitted.outcome,
      enrollmentId: input.manifest.enrollmentId,
      version: admitted.version,
      commandDigestB64u: parseDigestB64u(admitted.commandDigestB64u),
      lifecycle: admitted.value.lifecycle,
      orderedProtocols,
    };
  }

  async recordLaneProtocolCommitV1(
    input: RecordLaneProtocolCommitV1,
  ): Promise<LaneProtocolCasResultV1> {
    const receipt = parseLaneProtocolCommitReceiptV1(input.receipt);
    const current = await this.lifecycleStore.getProtocol(receipt.operationId);
    if (!current || String(current.value.job.enrollmentId) !== String(receipt.enrollmentId)) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current?.version ?? 0,
        requestedCommandDigestB64u: await digestReceipt(receipt),
        storedCommandDigestB64u: current?.commandDigestB64u ?? '',
      };
    }
    const receiptDigestB64u = await digestReceipt(receipt);
    if (current.value.lifecycle.state !== 'awaiting_protocol_commitment') {
      if (
        (current.value.lifecycle.state === 'committed_awaiting_holder_delivery' ||
          current.value.lifecycle.state === 'awaiting_server_activation' ||
          current.value.lifecycle.state === 'ready_for_parent_visibility' ||
          current.value.lifecycle.state === 'active') &&
        current.value.lifecycle.protocolCommitReceiptDigestB64u === receiptDigestB64u
      ) {
        return {
          outcome: 'replayed',
          version: current.version,
          commandDigestB64u: current.commandDigestB64u,
          record: current.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current.version,
        requestedCommandDigestB64u: receiptDigestB64u,
        storedCommandDigestB64u: current.commandDigestB64u,
      };
    }
    const persistedReceipt = await this.lifecycleStore.putProtocolCommitReceipt(
      receipt,
      receiptDigestB64u,
    );
    if (persistedReceipt.outcome === 'conflict') {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: persistedReceipt.actualVersion,
        requestedCommandDigestB64u: persistedReceipt.requestedCommandDigestB64u,
        storedCommandDigestB64u: persistedReceipt.storedCommandDigestB64u,
      };
    }
    const lifecycle = transitionLaneProtocolLifecycleV1(current.value.lifecycle, {
      action: 'record_commit',
      committedAtMs: receipt.committedAtMs,
      transcriptHashB64u: receipt.transcriptHashB64u,
      protocolCommitReceiptDigestB64u: receiptDigestB64u,
    });
    if (lifecycle.state !== 'committed_awaiting_holder_delivery')
      throw new Error('protocol commit transition did not produce holder-delivery state');
    const cas = await this.lifecycleStore.compareAndSetProtocolLifecycle({
      operationId: receipt.operationId,
      expectedVersion: input.expectedVersion,
      commandDigestB64u: receiptDigestB64u,
      lifecycle,
    });
    return cas.outcome === 'conflict'
      ? await reconcileProtocolCas(
          this.lifecycleStore,
          receipt.operationId,
          cas,
          receiptDigestB64u,
          'protocol',
        )
      : cas;
  }

  async resumeLaneProtocolOperationV1(
    input: ResumeLaneProtocolOperationV1,
  ): Promise<LaneProtocolCasResultV1> {
    const current = await this.lifecycleStore.getProtocol(input.operationId);
    if (
      !current ||
      String(current.value.job.enrollmentId) !== String(input.enrollmentId) ||
      String(current.value.job.idempotencyKey) !== String(input.idempotencyKey)
    ) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current?.version ?? 0,
        requestedCommandDigestB64u: await digestResumeCommand(input),
        storedCommandDigestB64u: current?.commandDigestB64u ?? '',
      };
    }
    if (
      current.value.lifecycle.state !== 'preparing' &&
      current.value.lifecycle.state !== 'committed_completion_required'
    ) {
      return {
        outcome: 'replayed',
        version: current.version,
        commandDigestB64u: current.commandDigestB64u,
        record: current.value,
      };
    }
    const lifecycle = nextResumeLifecycle(current.value.lifecycle);
    return await this.lifecycleStore.compareAndSetProtocolLifecycle({
      operationId: input.operationId,
      expectedVersion: input.expectedVersion,
      commandDigestB64u: await digestResumeCommand(input),
      lifecycle,
    });
  }

  async recordLaneHolderDeliveryV1(
    input: RecordLaneHolderDeliveryV1,
  ): Promise<LaneProtocolCasResultV1> {
    const receipt = parseLaneHolderDeliveryReceiptV1(input.receipt);
    const current = await this.lifecycleStore.getProtocol(receipt.operationId);
    if (!current || String(current.value.job.enrollmentId) !== String(receipt.enrollmentId)) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current?.version ?? 0,
        requestedCommandDigestB64u: await digestHolderReceipt(receipt),
        storedCommandDigestB64u: current?.commandDigestB64u ?? '',
      };
    }
    const receiptDigestB64u = await digestHolderReceipt(receipt);
    if (current.value.lifecycle.state !== 'committed_awaiting_holder_delivery') {
      if (
        (current.value.lifecycle.state === 'awaiting_server_activation' ||
          current.value.lifecycle.state === 'ready_for_parent_visibility' ||
          current.value.lifecycle.state === 'active') &&
        current.value.lifecycle.holderDeliveryReceiptDigestB64u === receiptDigestB64u
      ) {
        return {
          outcome: 'replayed',
          version: current.version,
          commandDigestB64u: current.commandDigestB64u,
          record: current.value,
        };
      }
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current.version,
        requestedCommandDigestB64u: receiptDigestB64u,
        storedCommandDigestB64u: current.commandDigestB64u,
      };
    }
    const persistedReceipt = await this.lifecycleStore.putHolderDeliveryReceipt(
      receipt,
      receiptDigestB64u,
    );
    if (persistedReceipt.outcome === 'conflict') {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: persistedReceipt.actualVersion,
        requestedCommandDigestB64u: persistedReceipt.requestedCommandDigestB64u,
        storedCommandDigestB64u: persistedReceipt.storedCommandDigestB64u,
      };
    }
    const lifecycle = transitionLaneProtocolLifecycleV1(current.value.lifecycle, {
      action: 'record_holder_delivery',
      holderReceiptAtMs: receipt.acknowledgedAtMs,
      holderDeliveryReceiptDigestB64u: receiptDigestB64u,
    });
    if (lifecycle.state !== 'awaiting_server_activation') {
      throw new Error('holder delivery transition did not produce awaiting server activation');
    }
    const cas = await this.lifecycleStore.compareAndSetProtocolLifecycle({
      operationId: receipt.operationId,
      expectedVersion: input.expectedVersion,
      commandDigestB64u: receiptDigestB64u,
      lifecycle,
    });
    return cas.outcome === 'conflict'
      ? await reconcileProtocolCas(
          this.lifecycleStore,
          receipt.operationId,
          cas,
          receiptDigestB64u,
          'holder',
        )
      : cas;
  }

  async activateLaneServerMaterialV1(
    input: ActivateLaneServerMaterialV1,
  ): Promise<LaneProtocolCasResultV1> {
    const receipt = parseLaneServerActivationReceiptV1(input.receipt);
    const current = await this.lifecycleStore.getProtocol(receipt.operationId);
    if (!current || String(current.value.job.enrollmentId) !== String(receipt.enrollmentId)) {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current?.version ?? 0,
        requestedCommandDigestB64u: await digestServerReceipt(receipt),
        storedCommandDigestB64u: current?.commandDigestB64u ?? '',
      };
    }
    const receiptDigestB64u = await digestServerReceipt(receipt);
    if (
      current.value.lifecycle.state === 'ready_for_parent_visibility' ||
      current.value.lifecycle.state === 'active'
    ) {
      if (current.value.lifecycle.serverActivationReceiptDigestB64u !== receiptDigestB64u) {
        return {
          outcome: 'conflict',
          expectedVersion: input.expectedVersion,
          actualVersion: current.version,
          requestedCommandDigestB64u: receiptDigestB64u,
          storedCommandDigestB64u: current.commandDigestB64u,
        };
      }
      return {
        outcome: 'replayed',
        version: current.version,
        commandDigestB64u: current.commandDigestB64u,
        record: current.value,
      };
    }
    if (current.value.lifecycle.state !== 'awaiting_server_activation') {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: current.version,
        requestedCommandDigestB64u: receiptDigestB64u,
        storedCommandDigestB64u: current.commandDigestB64u,
      };
    }
    const persistedReceipt = await this.lifecycleStore.putServerActivationReceipt(
      receipt,
      receiptDigestB64u,
    );
    if (persistedReceipt.outcome === 'conflict') {
      return {
        outcome: 'conflict',
        expectedVersion: input.expectedVersion,
        actualVersion: persistedReceipt.actualVersion,
        requestedCommandDigestB64u: persistedReceipt.requestedCommandDigestB64u,
        storedCommandDigestB64u: persistedReceipt.storedCommandDigestB64u,
      };
    }
    const lifecycle = transitionLaneProtocolLifecycleV1(current.value.lifecycle, {
      action: 'record_server_activation',
      serverActivatedAtMs: receipt.activatedAtMs,
      serverActivationReceiptDigestB64u: receiptDigestB64u,
    });
    if (lifecycle.state !== 'ready_for_parent_visibility') {
      throw new Error('server activation transition did not produce ready-for-parent-visibility');
    }
    const cas = await this.lifecycleStore.compareAndSetProtocolLifecycle({
      operationId: receipt.operationId,
      expectedVersion: input.expectedVersion,
      commandDigestB64u: receiptDigestB64u,
      lifecycle,
    });
    return cas.outcome === 'conflict'
      ? await reconcileProtocolCas(
          this.lifecycleStore,
          receipt.operationId,
          cas,
          receiptDigestB64u,
          'server',
        )
      : cas;
  }

  async commitLaneEnrollmentActivationV1(
    input: CommitLaneEnrollmentActivationV1,
  ): Promise<LaneEnrollmentActivationResultV1> {
    const result = await this.lifecycleStore.commitEnrollmentVisibility(input);
    if (result.outcome === 'conflict') {
      return { kind: 'lane_enrollment_activation_result_v1', ...result };
    }
    const productEpochs = requireActiveProductEpochs(result.productEpochs);
    return {
      kind: 'lane_enrollment_activation_result_v1',
      outcome: result.outcome,
      enrollmentId: input.enrollmentId,
      version: result.version,
      commandDigestB64u: result.commandDigestB64u,
      receipt: result.receipt,
      lifecycle: result.lifecycle,
      productEpochs,
    };
  }
}

function nextResumeLifecycle(lifecycle: LaneProtocolLifecycle): LaneProtocolLifecycle {
  switch (lifecycle.state) {
    case 'preparing':
      return transitionLaneProtocolLifecycleV1(lifecycle, {
        action: 'await_protocol_commitment',
        atMs: lifecycle.startedAtMs,
      });
    case 'awaiting_protocol_commitment':
    case 'committed_awaiting_holder_delivery':
    case 'awaiting_server_activation':
    case 'ready_for_parent_visibility':
    case 'active':
    case 'aborted_precommit':
      return lifecycle;
    case 'committed_completion_required':
      return transitionLaneProtocolLifecycleV1(lifecycle, {
        action: 'resume_completion',
        atMs: lifecycle.committedAtMs,
      });
    default:
      return assertNeverLifecycle(lifecycle);
  }
}

function assertNeverLifecycle(value: never): never {
  throw new Error(`Unhandled lane protocol lifecycle ${JSON.stringify(value)}`);
}

async function digestResumeCommand(input: ResumeLaneProtocolOperationV1): Promise<string> {
  const encoded = [
    'seams/rotatable-signing-lanes/resume-protocol-operation/v1',
    String(input.operationId),
    String(input.enrollmentId),
    String(input.idempotencyKey),
    String(input.expectedVersion),
  ].join('\u0000');
  return base64UrlEncode(await sha256BytesUtf8(encoded));
}

async function encodedDigest<T>(value: T, encode: (value: T) => Uint8Array): Promise<string> {
  return base64UrlEncode(await sha256Bytes(encode(value)));
}

async function digestReceipt(
  receipt: import('@shared/signing-lanes').LaneProtocolCommitReceiptV1,
): Promise<string> {
  return encodedDigest(receipt, (value) => encodeLaneProtocolCommitReceiptV1(value));
}

async function digestHolderReceipt(
  receipt: import('@shared/signing-lanes').LaneHolderDeliveryReceiptV1,
): Promise<string> {
  return encodedDigest(receipt, (value) => encodeLaneHolderDeliveryReceiptV1(value));
}

async function digestServerReceipt(
  receipt: import('@shared/signing-lanes').LaneServerActivationReceiptV1,
): Promise<string> {
  return encodedDigest(receipt, (value) => encodeLaneServerActivationReceiptV1(value));
}

async function readOrderedProtocols(
  store: LaneLifecycleStore,
  children: PrepareLaneEnrollmentV1['children'],
): Promise<readonly [PreparedLaneProtocolRecordV1, ...PreparedLaneProtocolRecordV1[]]> {
  const protocols: PreparedLaneProtocolRecordV1[] = [];
  for (const child of children) {
    const protocol = await store.getProtocol(child.operationId);
    if (!protocol)
      throw new Error(`lane protocol admission did not persist ${String(child.operationId)}`);
    protocols.push({
      version: protocol.version,
      commandDigestB64u: parseDigestB64u(protocol.commandDigestB64u),
      record: protocol.value,
    });
  }
  const first = protocols[0];
  if (!first) throw new Error('lane enrollment requires at least one child');
  return [first, ...protocols.slice(1)];
}

async function reconcileProtocolCas(
  store: LaneLifecycleStore,
  operationId: import('@shared/signing-lanes').LaneOperationId,
  conflict: Extract<LaneProtocolCasResultV1, { outcome: 'conflict' }>,
  digestB64u: string,
  stage: 'protocol' | 'holder' | 'server',
): Promise<LaneProtocolCasResultV1> {
  const raced = await store.getProtocol(operationId);
  if (!raced) return conflict;
  const lifecycle = raced.value.lifecycle;
  const replay =
    (stage === 'protocol' &&
      (lifecycle.state === 'committed_awaiting_holder_delivery' ||
        lifecycle.state === 'awaiting_server_activation' ||
        lifecycle.state === 'ready_for_parent_visibility' ||
        lifecycle.state === 'active') &&
      lifecycle.protocolCommitReceiptDigestB64u === digestB64u) ||
    (stage === 'holder' &&
      (lifecycle.state === 'awaiting_server_activation' ||
        lifecycle.state === 'ready_for_parent_visibility' ||
        lifecycle.state === 'active') &&
      lifecycle.holderDeliveryReceiptDigestB64u === digestB64u) ||
    (stage === 'server' &&
      (lifecycle.state === 'ready_for_parent_visibility' || lifecycle.state === 'active') &&
      lifecycle.serverActivationReceiptDigestB64u === digestB64u);
  return replay
    ? {
        outcome: 'replayed',
        version: raced.version,
        commandDigestB64u: raced.commandDigestB64u,
        record: raced.value,
      }
    : conflict;
}

function requireActiveProductEpochs(
  values: readonly import('@shared/signing-lanes').LaneProductEpochRecordV1[],
): readonly [
  import('@shared/signing-lanes').LaneProductEpochActiveV1,
  ...import('@shared/signing-lanes').LaneProductEpochActiveV1[],
] {
  const active = values.filter(
    (value): value is import('@shared/signing-lanes').LaneProductEpochActiveV1 =>
      value.state === 'active',
  );
  const first = active[0];
  if (!first) throw new Error('lane activation returned no active product epochs');
  return [first, ...active.slice(1)];
}
