import type {
  EcdsaAdditiveLaneJobV1,
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaLaneProtocolWasmV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneHolderRecipientWorkerV1,
  LaneProtocolCasResultV1,
  LaneProtocolCommitReceiptV1,
  LaneHolderPackageWireV1,
  RotatableSigningLaneJobV1,
  WasmEd25519YaoLaneClientV1,
} from '@shared/signing-lanes/rotation';

/**
 * The browser owns orchestration state while curve material stays behind one
 * of these ports. The port types deliberately expose only transcript records
 * and opaque ciphertexts.
 */
export type LaneOperationWasmPortsV1 = {
  readonly ecdsa: EcdsaLaneProtocolWasmV1;
  readonly ed25519Yao: WasmEd25519YaoLaneClientV1;
};

export type LaneProtocolCommitterV1 = {
  executeAndRecordEcdsaAdditiveLaneV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly holderPackage: Extract<
      LaneHolderPackageWireV1,
      { kind: 'ecdsa_additive_lane_holder_package_v1' }
    >;
    readonly encryptedDeltaPackageJson: string;
    readonly expectedVersion: number;
  }): Promise<LaneProtocolCommitExecutionResultV1>;
  executeAndRecordEd25519YaoLaneV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly requestJson: string;
    readonly expectedVersion: number;
  }): Promise<LaneEd25519ProtocolCommitExecutionResultV1>;
};

export type LaneProtocolCommitExecutionResultV1 = {
  readonly receipt: LaneProtocolCommitReceiptV1;
  readonly protocolCasResult: LaneProtocolCasResultV1;
};

export type LaneEd25519ProtocolCommitExecutionResultV1 = LaneProtocolCommitExecutionResultV1 & {
  readonly responseJson: string;
};

export type LaneOperationGatewayV1 = LaneEnrollmentGatewayV1;
export type LaneOperationRecipientWorkerV1 = LaneHolderRecipientWorkerV1;

export type LaneOperationClockV1 = {
  readonly nowMs: () => number;
};

export type LaneOperationSourcePortsV1 = LaneOperationClockV1 & {
  readonly gateway: LaneOperationGatewayV1;
  readonly wasm: LaneOperationWasmPortsV1;
  readonly protocolCommitter: LaneProtocolCommitterV1;
  readonly reconcileEcdsaActivationJournalV1: (input: {
    readonly walletKeyId: RotatableSigningLaneJobV1['walletKeyId'];
    readonly laneId: RotatableSigningLaneJobV1['target']['laneId'];
    readonly laneShareEpoch: RotatableSigningLaneJobV1['target']['laneShareEpoch'];
  }) => Promise<void>;
};
