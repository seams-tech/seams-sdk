import {
  parseLaneProtocolCommitReceiptV1,
  parseLaneServerActivationReceiptV1,
  parseRevokeSigningLaneV1,
} from '@shared/signing-lanes/rotationParsers';
import type {
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneJobV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneHolderDeliveryReceiptV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  LaneServerActivationReceiptV1,
  LaneHolderPackageWireV1,
  LaneSigningLaneRevocationResultV1,
  RevokeSigningLaneV1,
} from '@shared/signing-lanes';

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
  readonly retirementReceiptDigestB64u: string;
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

    const fenced = await this.input.gateway.revokeSigningLaneV1(command);
    if (fenced.outcome === 'conflict') return fenced;

    const execution =
      request.curve === 'ed25519_yao'
        ? await this.input.execution.ed25519.executeServerRetirementV1({ command })
        : await this.input.execution.ecdsa.executeServerRetirementV1({ command });
    if (execution.kind !== 'lane_lifecycle_retirement_execution_v1') {
      throw new Error('lane retirement execution result kind is invalid');
    }
    if (execution.retirementReceiptDigestB64u !== command.retirementEffectBindingDigestB64u) {
      throw new Error(
        'lane retirement receipt digest does not match the authorized effect binding',
      );
    }
    const executedCommand = parseRevokeSigningLaneV1(execution.command);
    assertRevokeSigningLaneCommandEqual(command, executedCommand);
    return fenced;
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
    receipt.targetMaterialActivation.activationId !== job.targetMaterialActivationId
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
