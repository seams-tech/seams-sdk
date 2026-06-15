import type { WalletId } from '../utils/domainIds';
import type {
  LaneShareEpoch,
  RotationOperationId,
  SigningLaneId,
  WalletKeyId,
} from './ids';

export type RotationFailureReason =
  | 'parity_mismatch'
  | 'holder_delivery_failed'
  | 'server_share_seal_failed'
  | 'revoked_during_rotation'
  | 'activation_failed';

export type RotationJobLifecycle =
  | {
      state: 'preparing';
      operationId: RotationOperationId;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'ready_to_activate';
      operationId: RotationOperationId;
      activatedAtMs?: never;
      failedAtMs?: never;
    }
  | {
      state: 'activated';
      operationId: RotationOperationId;
      activatedAtMs: number;
      failedAtMs?: never;
    }
  | {
      state: 'failed';
      operationId: RotationOperationId;
      failedAtMs: number;
      failureReason: RotationFailureReason;
      activatedAtMs?: never;
    };

export type AdditiveDeltaReshareCommitment = {
  kind: 'additive_delta_reshare_commitment_v1';
  holderCommitmentB64u: string;
  serverCommitmentB64u: string;
  walletPublicKeyB64u: string;
  transcriptHashB64u: string;
};

export type SigningLaneCreationJob = {
  kind: 'signing_lane_creation';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  sourceLaneId: SigningLaneId;
  sourceLaneShareEpoch: LaneShareEpoch;
  targetLaneId: SigningLaneId;
  targetLaneKind: 'delegated_agent' | 'linked_device';
  targetLaneShareEpoch: LaneShareEpoch;
  permissionPolicyDigest: string;
  lifecycle: RotationJobLifecycle;
};

export type LaneShareRefreshJob = {
  kind: 'lane_share_refresh';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  fromLaneShareEpoch: LaneShareEpoch;
  toLaneShareEpoch: LaneShareEpoch;
  rotationReason:
    | 'passkey_migration'
    | 'holder_compromise'
    | 'policy_refresh'
    | 'agent_custody_rotation'
    | 'linked_device_rotation';
  lifecycle: RotationJobLifecycle;
};

export type HolderEnvelopeRewrapJob = {
  kind: 'holder_envelope_rewrap';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  targetEnvelopeVersion: string;
};

export type ServerInternalCustodyRotationJob = {
  kind: 'server_internal_custody_rotation';
  signingRootId: string;
  rootShareEpoch: string;
  rotationReason: 'k_org_rotation' | 'deployment_key_rotation' | 'custody_move';
};

export type ShareRotationJob =
  | SigningLaneCreationJob
  | LaneShareRefreshJob
  | HolderEnvelopeRewrapJob
  | ServerInternalCustodyRotationJob;

export type LaneActivationDecision =
  | {
      kind: 'activate_new_epoch';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      activeLaneShareEpoch: LaneShareEpoch;
      retiredLaneShareEpoch: LaneShareEpoch;
    }
  | {
      kind: 'keep_current_epoch';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      activeLaneShareEpoch: LaneShareEpoch;
      failureReason: RotationFailureReason;
    };
