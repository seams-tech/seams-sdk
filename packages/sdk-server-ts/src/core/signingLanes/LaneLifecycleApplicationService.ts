import {
  buildRevokeSigningLaneV1,
  parseLaneRefreshPredecessorRetirementV1,
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseRevokeSigningLaneV1,
} from '@shared/signing-lanes/rotationParsers';
import { encodeLaneProtocolCommitReceiptV1 } from '@shared/signing-lanes/rotationDigests';
import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  LaneServerRetirementReceiptV1,
  LaneRefreshPredecessorRetirementV1,
  LaneHolderPackageWireV1,
  LaneProductEpochRevocationPendingV1,
  LaneSigningLaneRevocationFenceResultV1,
  LaneSigningLaneRevocationResultV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import { parseCorrelationId, parseDigestB64u } from '@shared/utils/canonicalPrimitives';
import { base64UrlEncode } from '@shared/utils/base64';
import { sha256Bytes } from '@shared/utils/digests';

export type LaneLifecycleProtocolCommitRequestV1 =
  | {
      readonly curve: 'ed25519_yao';
      readonly job: Ed25519YaoLaneJobV1;
      readonly requestJson: string;
      readonly expectedVersion: number;
    }
  | {
      readonly curve: 'ecdsa_additive';
      readonly job: EcdsaAdditiveLaneJobV1;
      readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
      readonly holderPackage: Extract<
        LaneHolderPackageWireV1,
        { kind: 'ecdsa_additive_lane_holder_package_v1' }
      >;
      readonly encryptedDeltaPackageJson: string;
      readonly expectedVersion: number;
    };

export type LaneLifecycleServerActivationRequestV1 =
  | {
      readonly curve: 'ed25519_yao';
      readonly job: Ed25519YaoLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
      readonly expectedVersion: number;
    }
  | {
      readonly curve: 'ecdsa_additive';
      readonly job: EcdsaAdditiveLaneJobV1;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
      readonly expectedVersion: number;
    };

export type LaneLifecycleRevocationRequestV1 = {
  readonly curve: 'ed25519_yao' | 'ecdsa_additive';
  readonly command: RevokeSigningLaneV1;
};

export type LaneLifecycleRefreshPredecessorRetirementRequestV1 =
  | {
      readonly curve: 'ed25519_yao';
      readonly job: Extract<Ed25519YaoLaneJobV1, { target: { operation: 'refresh_lane' } }>;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly requestedAtMs: number;
    }
  | {
      readonly curve: 'ecdsa_additive';
      readonly job: Extract<EcdsaAdditiveLaneJobV1, { target: { operation: 'refresh_lane' } }>;
      readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
      readonly requestedAtMs: number;
    };

export type LaneLifecycleAuthorizationRequestV1 =
  | {
      readonly kind: 'record_lane_protocol_commit_v1';
      readonly curve: 'ed25519_yao';
      readonly job: Ed25519YaoLaneJobV1;
      readonly expectedVersion: number;
    }
  | {
      readonly kind: 'record_lane_protocol_commit_v1';
      readonly curve: 'ecdsa_additive';
      readonly job: EcdsaAdditiveLaneJobV1;
      readonly expectedVersion: number;
    }
  | {
      readonly kind: 'activate_lane_server_material_v1';
      readonly curve: 'ed25519_yao';
      readonly job: Ed25519YaoLaneJobV1;
      readonly expectedVersion: number;
    }
  | {
      readonly kind: 'activate_lane_server_material_v1';
      readonly curve: 'ecdsa_additive';
      readonly job: EcdsaAdditiveLaneJobV1;
      readonly expectedVersion: number;
    }
  | {
      readonly kind: 'revoke_signing_lane_v1';
      readonly curve: 'ed25519_yao';
      readonly command: RevokeSigningLaneV1;
    }
  | {
      readonly kind: 'revoke_signing_lane_v1';
      readonly curve: 'ecdsa_additive';
      readonly command: RevokeSigningLaneV1;
    };

export type LaneLifecycleApplicationServiceOptionsV1 = {
  readonly gateway: LaneEnrollmentGatewayV1;
  readonly authorization: LaneLifecycleAuthorizationPortV1;
  readonly execution: LaneLifecycleCurveExecutionPortsV1;
};

export interface LaneLifecycleAuthorizationPortV1 {
  authorizeLaneLifecycleV1(input: LaneLifecycleAuthorizationRequestV1): Promise<void>;
}

export type LaneLifecycleRetirementExecutionV1 = {
  readonly kind: 'lane_lifecycle_retirement_execution_v1';
  readonly command: RevokeSigningLaneV1;
  readonly retirementEffectBindingDigestB64u: DigestB64u;
  readonly retirementReceipt: LaneServerRetirementReceiptV1;
};

export type LaneLifecycleEd25519ExecutionPortV1 = {
  executeProtocolCommitV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly requestJson: string;
  }): Promise<LaneProtocolCommitReceiptV1>;
  executeServerActivationV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
  }): Promise<LaneServerActivationReceiptV1>;
  executeServerRetirementV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<LaneLifecycleRetirementExecutionV1>;
};

export type LaneLifecycleEcdsaExecutionPortV1 = {
  executeProtocolCommitV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly holderPackage: Extract<
      LaneHolderPackageWireV1,
      { kind: 'ecdsa_additive_lane_holder_package_v1' }
    >;
    readonly encryptedDeltaPackageJson: string;
  }): Promise<LaneProtocolCommitReceiptV1>;
  executeServerActivationV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    readonly holderDeliveryReceipt: LaneHolderDeliveryReceiptV1;
  }): Promise<LaneServerActivationReceiptV1>;
  executeServerRetirementV1(input: {
    readonly command: RevokeSigningLaneV1;
  }): Promise<LaneLifecycleRetirementExecutionV1>;
};

export type LaneLifecycleCurveExecutionPortsV1 = {
  readonly ed25519: LaneLifecycleEd25519ExecutionPortV1;
  readonly ecdsa: LaneLifecycleEcdsaExecutionPortV1;
};

export class LaneLifecycleApplicationService {
  constructor(private readonly input: LaneLifecycleApplicationServiceOptionsV1) {}

  async recordLaneProtocolCommitV1(
    request: LaneLifecycleProtocolCommitRequestV1,
  ): Promise<LaneProtocolCasResultV1> {
    await authorizeProtocolCommit(this.input.authorization, request);

    const receipt =
      request.curve === 'ed25519_yao'
        ? await this.input.execution.ed25519.executeProtocolCommitV1({
            job: request.job,
            requestJson: requireJson(request.requestJson, 'requestJson'),
          })
        : await this.input.execution.ecdsa.executeProtocolCommitV1({
            job: request.job,
            holderRound: request.holderRound,
            holderPackage: request.holderPackage,
            encryptedDeltaPackageJson: requireJson(
              request.encryptedDeltaPackageJson,
              'encryptedDeltaPackageJson',
            ),
          });
    const parsedReceipt = parseLaneProtocolCommitReceiptV1(receipt);
    assertProtocolReceiptMatchesJob(parsedReceipt, request.job);
    return await this.input.gateway.recordLaneProtocolCommitV1({
      receipt: parsedReceipt,
      expectedVersion: request.expectedVersion,
    });
  }

  async activateLaneServerMaterialV1(
    request: LaneLifecycleServerActivationRequestV1,
  ): Promise<LaneProtocolCasResultV1> {
    assertProtocolReceiptMatchesJob(request.protocolCommitReceipt, request.job);
    assertHolderDeliveryReceiptMatchesJob(request.holderDeliveryReceipt, request.job);
    await authorizeServerActivation(this.input.authorization, request);

    const receipt =
      request.curve === 'ed25519_yao'
        ? await this.input.execution.ed25519.executeServerActivationV1({
            job: request.job,
            protocolCommitReceipt: request.protocolCommitReceipt,
            holderDeliveryReceipt: request.holderDeliveryReceipt,
          })
        : await this.input.execution.ecdsa.executeServerActivationV1({
            job: request.job,
            protocolCommitReceipt: request.protocolCommitReceipt,
            holderDeliveryReceipt: request.holderDeliveryReceipt,
          });
    const parsedReceipt = parseLaneServerActivationReceiptV1(receipt);
    assertServerActivationReceiptMatchesJob(parsedReceipt, request.job);
    return await this.input.gateway.activateLaneServerMaterialV1({
      receipt: parsedReceipt,
      expectedVersion: request.expectedVersion,
    });
  }

  async revokeSigningLaneV1(
    request: LaneLifecycleRevocationRequestV1,
  ): Promise<LaneSigningLaneRevocationResultV1> {
    const command = parseRevokeSigningLaneV1(request.command);
    await this.input.authorization.authorizeLaneLifecycleV1({
      kind: 'revoke_signing_lane_v1',
      curve: request.curve,
      command,
    });

    const fenced = await this.input.gateway.fenceSigningLaneRevocationV1(command);
    if (fenced.outcome === 'conflict') return revocationConflict(command, fenced);
    if (fenced.outcome === 'already_completed') return completedRevocation(command, fenced);
    assertRevocationFenceMatchesCommand(fenced.productEpoch, command);

    const execution =
      request.curve === 'ed25519_yao'
        ? await this.input.execution.ed25519.executeServerRetirementV1({ command })
        : await this.input.execution.ecdsa.executeServerRetirementV1({ command });
    assertRetirementExecutionMatchesCommand(execution, command);
    return await this.input.gateway.completeSigningLaneRevocationV1({
      kind: 'complete_signing_lane_revocation_v1',
      command,
      expectedVersion: fenced.version,
      commandDigestB64u: fenced.commandDigestB64u,
      retirementReceipt: execution.retirementReceipt,
      revokedAtMs: command.requestedAtMs,
    });
  }

  async retireLaneRefreshPredecessorV1(
    request: LaneLifecycleRefreshPredecessorRetirementRequestV1,
  ): Promise<LaneRefreshPredecessorRetirementV1> {
    const protocolCommitReceipt = parseLaneProtocolCommitReceiptV1(request.protocolCommitReceipt);
    assertProtocolReceiptMatchesJob(protocolCommitReceipt, request.job);
    const retirementRequestDigestB64u = parseDigestB64u(
      base64UrlEncode(await sha256Bytes(encodeLaneProtocolCommitReceiptV1(protocolCommitReceipt))),
    );
    const command = buildRevokeSigningLaneV1({
      walletId: request.job.walletId,
      walletKeyId: request.job.walletKeyId,
      laneId: request.job.source.laneId,
      laneShareEpoch: request.job.source.laneShareEpoch,
      expectedRevocationEpoch: request.job.source.revocationEpoch,
      reason: 'rotation',
      retirementCorrelationId: parseCorrelationId(request.job.operationId),
      retirementRequestDigestB64u,
      retirementEffectBindingDigestB64u: request.job.authorization.ownerLaneRefreshDigestB64u,
      requestedAtMs: request.requestedAtMs,
    });
    await this.input.authorization.authorizeLaneLifecycleV1({
      kind: 'revoke_signing_lane_v1',
      curve: request.curve,
      command,
    });
    const fenced = await this.input.gateway.fenceSigningLaneRevocationV1(command);
    if (fenced.outcome === 'conflict') {
      throw new Error('lane refresh predecessor revocation fence conflicted');
    }
    if (fenced.outcome === 'already_completed') {
      return parseLaneRefreshPredecessorRetirementV1({
        refreshOperationId: request.job.operationId,
        sourceLaneId: request.job.source.laneId,
        sourceLaneShareEpoch: request.job.source.laneShareEpoch,
        sourceMaterialActivation: request.job.source.materialActivation,
        retirementEffectBindingDigestB64u: request.job.authorization.ownerLaneRefreshDigestB64u,
        retirementReceipt: fenced.retirementReceipt,
      });
    }
    assertRevocationFenceMatchesCommand(fenced.productEpoch, command);
    const execution =
      request.curve === 'ed25519_yao'
        ? await this.input.execution.ed25519.executeServerRetirementV1({ command })
        : await this.input.execution.ecdsa.executeServerRetirementV1({ command });
    assertRetirementExecutionMatchesCommand(execution, command);
    return parseLaneRefreshPredecessorRetirementV1({
      refreshOperationId: request.job.operationId,
      sourceLaneId: request.job.source.laneId,
      sourceLaneShareEpoch: request.job.source.laneShareEpoch,
      sourceMaterialActivation: request.job.source.materialActivation,
      retirementEffectBindingDigestB64u: execution.retirementEffectBindingDigestB64u,
      retirementReceipt: execution.retirementReceipt,
    });
  }
}

function assertRetirementExecutionMatchesCommand(
  execution: LaneLifecycleRetirementExecutionV1,
  command: RevokeSigningLaneV1,
): void {
  if (execution.kind !== 'lane_lifecycle_retirement_execution_v1') {
    throw new Error('lane retirement execution result kind is invalid');
  }
  if (execution.retirementEffectBindingDigestB64u !== command.retirementEffectBindingDigestB64u) {
    throw new Error(
      'lane retirement effect binding digest does not match the authorized effect binding',
    );
  }
  assertRevokeSigningLaneCommandEqual(command, parseRevokeSigningLaneV1(execution.command));
}

function revocationConflict(
  command: RevokeSigningLaneV1,
  result: Extract<LaneSigningLaneRevocationFenceResultV1, { outcome: 'conflict' }>,
): LaneSigningLaneRevocationResultV1 {
  return {
    kind: 'lane_signing_lane_revocation_result_v1',
    outcome: 'conflict',
    walletKeyId: command.walletKeyId,
    laneId: command.laneId,
    laneShareEpoch: command.laneShareEpoch,
    expectedVersion: result.expectedVersion,
    actualVersion: result.actualVersion,
    requestedCommandDigestB64u: result.requestedCommandDigestB64u,
    storedCommandDigestB64u: result.storedCommandDigestB64u,
  };
}

function completedRevocation(
  command: RevokeSigningLaneV1,
  result: Extract<LaneSigningLaneRevocationFenceResultV1, { outcome: 'already_completed' }>,
): Extract<LaneSigningLaneRevocationResultV1, { outcome: 'replayed' }> {
  return {
    kind: 'lane_signing_lane_revocation_result_v1',
    outcome: 'replayed',
    walletKeyId: command.walletKeyId,
    laneId: command.laneId,
    laneShareEpoch: command.laneShareEpoch,
    version: result.version,
    commandDigestB64u: result.commandDigestB64u,
    productEpoch: result.productEpoch,
    retirementReceipt: result.retirementReceipt,
  };
}

function assertRevocationFenceMatchesCommand(
  product: LaneProductEpochRevocationPendingV1,
  command: RevokeSigningLaneV1,
): void {
  if (
    String(product.walletId) !== String(command.walletId) ||
    String(product.walletKeyId) !== String(command.walletKeyId) ||
    String(product.laneId) !== String(command.laneId) ||
    String(product.laneShareEpoch) !== String(command.laneShareEpoch) ||
    product.revocationEpoch !== command.expectedRevocationEpoch + 1 ||
    product.revocationReason !== command.reason ||
    product.retirementEffectBindingDigestB64u !== command.retirementEffectBindingDigestB64u
  ) {
    throw new Error('lane revocation fence does not match the authorized command');
  }
}

async function authorizeProtocolCommit(
  authorization: LaneLifecycleAuthorizationPortV1,
  request: LaneLifecycleProtocolCommitRequestV1,
): Promise<void> {
  if (request.curve === 'ed25519_yao') {
    await authorization.authorizeLaneLifecycleV1({
      kind: 'record_lane_protocol_commit_v1',
      curve: request.curve,
      job: request.job,
      expectedVersion: request.expectedVersion,
    });
    return;
  }
  await authorization.authorizeLaneLifecycleV1({
    kind: 'record_lane_protocol_commit_v1',
    curve: request.curve,
    job: request.job,
    expectedVersion: request.expectedVersion,
  });
}

async function authorizeServerActivation(
  authorization: LaneLifecycleAuthorizationPortV1,
  request: LaneLifecycleServerActivationRequestV1,
): Promise<void> {
  if (request.curve === 'ed25519_yao') {
    await authorization.authorizeLaneLifecycleV1({
      kind: 'activate_lane_server_material_v1',
      curve: request.curve,
      job: request.job,
      expectedVersion: request.expectedVersion,
    });
    return;
  }
  await authorization.authorizeLaneLifecycleV1({
    kind: 'activate_lane_server_material_v1',
    curve: request.curve,
    job: request.job,
    expectedVersion: request.expectedVersion,
  });
}

function requireJson(value: string, label: string): string {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${label} is required`);
  }
  return value;
}

function assertProtocolReceiptMatchesJob(
  receipt: LaneProtocolCommitReceiptV1,
  job: Ed25519YaoLaneJobV1 | EcdsaAdditiveLaneJobV1,
): void {
  if (
    receipt.operationId !== job.operationId ||
    receipt.enrollmentId !== job.enrollmentId ||
    receipt.walletId !== job.walletId ||
    receipt.walletKeyId !== job.walletKeyId ||
    receipt.targetLaneId !== job.target.laneId ||
    receipt.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    receipt.targetMaterialActivationId !== job.targetMaterialActivationId ||
    receipt.keyFamily !== job.keyFamily
  ) {
    throw new Error('lane protocol commit receipt does not match the admitted job');
  }
}

function assertHolderDeliveryReceiptMatchesJob(
  receipt: LaneHolderDeliveryReceiptV1,
  job: Ed25519YaoLaneJobV1 | EcdsaAdditiveLaneJobV1,
): void {
  if (
    receipt.operationId !== job.operationId ||
    receipt.enrollmentId !== job.enrollmentId ||
    receipt.targetLaneId !== job.target.laneId ||
    receipt.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    receipt.targetMaterialActivationId !== job.targetMaterialActivationId
  ) {
    throw new Error('lane holder delivery receipt does not match the admitted job');
  }
}

function assertServerActivationReceiptMatchesJob(
  receipt: LaneServerActivationReceiptV1,
  job: Ed25519YaoLaneJobV1 | EcdsaAdditiveLaneJobV1,
): void {
  if (
    receipt.operationId !== job.operationId ||
    receipt.enrollmentId !== job.enrollmentId ||
    receipt.targetLaneId !== job.target.laneId ||
    receipt.targetLaneShareEpoch !== job.target.laneShareEpoch ||
    receipt.targetMaterialActivation.activationId !== job.targetMaterialActivationId ||
    receipt.targetMaterialActivation.capability !== job.source.materialActivation.capability ||
    receipt.targetMaterialActivation.materialOwner !==
      job.source.materialActivation.materialOwner ||
    receipt.targetMaterialActivation.keyBinding !== job.source.materialActivation.keyBinding ||
    receipt.targetMaterialActivation.lifecycleBinding !==
      job.source.materialActivation.lifecycleBinding ||
    String(receipt.targetMaterialActivation.signingWorker) !==
      String(job.targetSigningWorker.participantId)
  ) {
    throw new Error('lane server activation receipt does not match the admitted job');
  }
}

function assertRevokeSigningLaneCommandEqual(
  expected: RevokeSigningLaneV1,
  actual: RevokeSigningLaneV1,
): void {
  if (
    expected.kind !== actual.kind ||
    expected.walletId !== actual.walletId ||
    expected.walletKeyId !== actual.walletKeyId ||
    expected.laneId !== actual.laneId ||
    expected.laneShareEpoch !== actual.laneShareEpoch ||
    expected.expectedRevocationEpoch !== actual.expectedRevocationEpoch ||
    expected.reason !== actual.reason ||
    expected.retirementCorrelationId !== actual.retirementCorrelationId ||
    expected.retirementRequestDigestB64u !== actual.retirementRequestDigestB64u ||
    expected.retirementEffectBindingDigestB64u !== actual.retirementEffectBindingDigestB64u ||
    expected.requestedAtMs !== actual.requestedAtMs
  ) {
    throw new Error('lane retirement execution changed the authorized command');
  }
}
