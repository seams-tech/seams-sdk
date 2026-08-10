import {
  buildPreparedDelegatedWalletExecution,
  buildPreparedLinkedDeviceWalletExecution,
  buildPreparedOwnerWalletExecution,
  type ClaimedWalletExecutionAuthorization,
  type PreparedDelegatedWalletExecution,
  type PreparedLinkedDeviceWalletExecution,
  type PreparedOwnerWalletExecution,
  type ReservedDelegatedBudgetClaim,
} from './execution';
import type { LinkedDeviceEnrollmentId } from './ids';
import type { DelegatedSpendAuthorizationId } from './records';
import type { MpcMaterialActivationRef } from '../utils/domainIds';

declare const authorization: ClaimedWalletExecutionAuthorization;
declare const materialActivation: MpcMaterialActivationRef;
declare const ownerLane: PreparedOwnerWalletExecution['lane'];
declare const linkedLane: PreparedLinkedDeviceWalletExecution['lane'];
declare const delegatedLane: PreparedDelegatedWalletExecution['lane'];
declare const linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
declare const delegatedAuthorizationId: DelegatedSpendAuthorizationId;
declare const budgetClaim: ReservedDelegatedBudgetClaim;

buildPreparedOwnerWalletExecution({ authorization, materialActivation, lane: ownerLane });
buildPreparedLinkedDeviceWalletExecution({
  authorization,
  materialActivation,
  lane: linkedLane,
  linkedDeviceEnrollmentId,
});
buildPreparedDelegatedWalletExecution({
  authorization,
  materialActivation,
  lane: delegatedLane,
  delegatedAuthorizationId,
  budgetClaim,
});

buildPreparedOwnerWalletExecution({
  authorization,
  materialActivation,
  // @ts-expect-error linked-device lanes cannot construct owner execution
  lane: linkedLane,
});
buildPreparedLinkedDeviceWalletExecution({
  authorization,
  materialActivation,
  // @ts-expect-error owner lanes cannot construct linked-device execution
  lane: ownerLane,
  linkedDeviceEnrollmentId,
});
buildPreparedDelegatedWalletExecution({
  authorization,
  materialActivation,
  // @ts-expect-error owner lanes cannot construct delegated execution
  lane: ownerLane,
  delegatedAuthorizationId,
  budgetClaim,
});
// @ts-expect-error delegated execution requires an atomically reserved budget claim
buildPreparedDelegatedWalletExecution({
  authorization,
  materialActivation,
  lane: delegatedLane,
  delegatedAuthorizationId,
});
