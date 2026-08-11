import type { AuthorizedOperationId, CapabilityId } from '../authorization/capabilityKinds';
import type { CapabilityOperationFingerprintDigest } from '../authorization/operationFingerprint';
import type { DomainId, MpcMaterialActivationRef } from '../utils/domainIds';
import type { LinkedDeviceEnrollmentId } from './ids';
import type { LinkedDeviceId, LaneShareEpoch, SigningLaneId, WalletKeyId } from './ids';
import type { ActiveSigningLaneReference, DelegatedSpendAuthorizationId } from './records';
import {
  routerAbMpcMaterialActivationRefToWire,
  type RouterAbMpcMaterialActivationRefWire,
} from '../utils/routerAbNormalSigningIdentity';

export type LinkedDeviceExecutionEnvelopeV1 = {
  readonly kind: 'linked_device_execution_v1';
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly materialActivation: RouterAbMpcMaterialActivationRefWire;
};

export function buildLinkedDeviceExecutionEnvelopeV1(input: {
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly walletKeyId: WalletKeyId;
  readonly laneId: SigningLaneId;
  readonly laneShareEpoch: LaneShareEpoch;
  readonly materialActivation: MpcMaterialActivationRef;
}): LinkedDeviceExecutionEnvelopeV1 {
  return {
    kind: 'linked_device_execution_v1',
    enrollmentId: input.enrollmentId,
    deviceId: input.deviceId,
    walletKeyId: input.walletKeyId,
    laneId: input.laneId,
    laneShareEpoch: input.laneShareEpoch,
    materialActivation: routerAbMpcMaterialActivationRefToWire(input.materialActivation),
  };
}

export type DelegatedBudgetClaimId = DomainId<'DelegatedBudgetClaimId'>;

export type ClaimedWalletExecutionAuthorization = {
  readonly kind: 'claimed_wallet_execution_authorization_v1';
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly operationFingerprintDigest: CapabilityOperationFingerprintDigest;
  readonly capabilityId: CapabilityId;
};

export type ReservedDelegatedBudgetClaim = {
  readonly kind: 'reserved_delegated_budget_claim_v1';
  readonly budgetClaimId: DelegatedBudgetClaimId;
};

type PreparedWalletExecutionBase = {
  readonly authorization: ClaimedWalletExecutionAuthorization;
  readonly materialActivation: MpcMaterialActivationRef;
};

export type PreparedOwnerWalletExecution = PreparedWalletExecutionBase & {
  readonly kind: 'prepared_owner_wallet_execution';
  readonly laneKind: 'owner_passkey' | 'owner_email_otp' | 'recovery' | 'break_glass';
  readonly lane: ActiveSigningLaneReference & {
    readonly laneKind: PreparedOwnerWalletExecution['laneKind'];
  };
  readonly linkedDeviceEnrollmentId?: never;
  readonly delegatedAuthorizationId?: never;
  readonly budgetClaim?: never;
};

export type PreparedLinkedDeviceWalletExecution = PreparedWalletExecutionBase & {
  readonly kind: 'prepared_linked_device_wallet_execution';
  readonly laneKind: 'linked_device';
  readonly lane: ActiveSigningLaneReference & { readonly laneKind: 'linked_device' };
  readonly linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
  readonly delegatedAuthorizationId?: never;
  readonly budgetClaim?: never;
};

export type PreparedDelegatedWalletExecution = PreparedWalletExecutionBase & {
  readonly kind: 'prepared_delegated_wallet_execution';
  readonly laneKind: 'delegated_execution';
  readonly lane: ActiveSigningLaneReference & { readonly laneKind: 'delegated_execution' };
  readonly delegatedAuthorizationId: DelegatedSpendAuthorizationId;
  readonly budgetClaim: ReservedDelegatedBudgetClaim;
  readonly linkedDeviceEnrollmentId?: never;
};

export type PreparedWalletExecution =
  | PreparedOwnerWalletExecution
  | PreparedLinkedDeviceWalletExecution
  | PreparedDelegatedWalletExecution;

export function buildPreparedOwnerWalletExecution(input: {
  readonly authorization: ClaimedWalletExecutionAuthorization;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly lane: PreparedOwnerWalletExecution['lane'];
}): PreparedOwnerWalletExecution {
  return {
    kind: 'prepared_owner_wallet_execution',
    laneKind: input.lane.laneKind,
    authorization: input.authorization,
    materialActivation: input.materialActivation,
    lane: input.lane,
  };
}

export function buildPreparedLinkedDeviceWalletExecution(input: {
  readonly authorization: ClaimedWalletExecutionAuthorization;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly lane: PreparedLinkedDeviceWalletExecution['lane'];
  readonly linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
}): PreparedLinkedDeviceWalletExecution {
  return {
    kind: 'prepared_linked_device_wallet_execution',
    laneKind: 'linked_device',
    authorization: input.authorization,
    materialActivation: input.materialActivation,
    lane: input.lane,
    linkedDeviceEnrollmentId: input.linkedDeviceEnrollmentId,
  };
}

export function buildPreparedDelegatedWalletExecution(input: {
  readonly authorization: ClaimedWalletExecutionAuthorization;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly lane: PreparedDelegatedWalletExecution['lane'];
  readonly delegatedAuthorizationId: DelegatedSpendAuthorizationId;
  readonly budgetClaim: ReservedDelegatedBudgetClaim;
}): PreparedDelegatedWalletExecution {
  return {
    kind: 'prepared_delegated_wallet_execution',
    laneKind: 'delegated_execution',
    authorization: input.authorization,
    materialActivation: input.materialActivation,
    lane: input.lane,
    delegatedAuthorizationId: input.delegatedAuthorizationId,
    budgetClaim: input.budgetClaim,
  };
}

export function assertNeverPreparedWalletExecution(value: never): never {
  throw new Error(`Unsupported prepared wallet execution: ${String(value)}`);
}
