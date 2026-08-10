import type {
  EcdsaAdditiveLaneJobV1,
  EcdsaAdditiveLaneHolderRoundV1,
  EcdsaAdditiveLaneServerRoundV1,
  EcdsaLaneProtocolWasmV1,
  Ed25519YaoLaneJobV1,
  LaneEnrollmentGatewayV1,
  LaneHolderRecipientWorkerV1,
  LaneProtocolCommitReceiptV1,
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
  commitEcdsaAdditiveLaneV1(input: {
    readonly job: EcdsaAdditiveLaneJobV1;
    readonly holderRound: EcdsaAdditiveLaneHolderRoundV1;
    readonly serverRound: EcdsaAdditiveLaneServerRoundV1;
  }): Promise<unknown>;
  commitEd25519YaoLaneV1(input: {
    readonly job: Ed25519YaoLaneJobV1;
    readonly protocolReceipt: LaneProtocolCommitReceiptV1;
  }): Promise<unknown>;
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
