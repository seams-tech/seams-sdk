import type { WalletId } from '../utils/domainIds';
import type {
  AgentPrincipalId,
  LaneShareEpoch,
  LinkedDeviceId,
  MandatePolicyId,
  RotationOperationId,
  SigningLaneId,
  WalletKeyId,
} from './ids';
import type {
  DelegatedAgentSigningLaneRecord,
  LinkedDeviceSigningLaneRecord,
  OwnerPasskeySigningLaneRecord,
} from './records';
import type { DelegatedMandatePolicy, LinkedDevicePermissionPolicy } from './policies';
import type { SigningLaneCreationJob } from './rotation';

declare const walletId: WalletId;
declare const walletKeyId: WalletKeyId;
declare const ownerLaneId: SigningLaneId;
declare const targetLaneId: SigningLaneId;
declare const laneShareEpoch: LaneShareEpoch;
declare const targetLaneShareEpoch: LaneShareEpoch;
declare const linkedDeviceId: LinkedDeviceId;
declare const agentPrincipalId: AgentPrincipalId;
declare const mandatePolicyId: MandatePolicyId;
declare const rotationOperationId: RotationOperationId;

const mandatePolicy: DelegatedMandatePolicy = {
  kind: 'delegated_mandate_policy_v1',
  policyId: mandatePolicyId,
  policyVersion: 'policy-v1',
  allowedIntents: ['specific_purchase_payment_v1'],
  chainScope: { kind: 'chain_scope_v1', chainIds: ['eip155:1'] },
  assetScope: { kind: 'asset_scope_v1', assetIds: ['eip155:1/slip44:60'] },
  counterpartyScope: { kind: 'counterparty_scope_v1', counterpartyIds: ['merchant:demo'] },
  perOperationLimit: {
    kind: 'atomic_value_limit_v1',
    amountAtomic: '100',
    assetId: 'eip155:1/slip44:60',
  },
  aggregateBudget: {
    kind: 'atomic_value_limit_v1',
    amountAtomic: '1000',
    assetId: 'eip155:1/slip44:60',
  },
  expiresAtMs: 1,
  requiredIntentDigest: 'exact_payment_intent_v1',
  replayPolicy: { kind: 'delegated_replay_policy_v1', nonceScope: 'wallet_key_lane' },
  feePolicy: {
    kind: 'delegated_fee_policy_v1',
    maxFeeAtomic: '10',
    feeAssetId: 'eip155:1/slip44:60',
    sponsorship: 'allowed',
  },
  outOfPolicyAction: 'deny',
};

const ownerEquivalentDevicePolicy: LinkedDevicePermissionPolicy = {
  kind: 'owner_equivalent_device_permission_v1',
  requiresLocalUserPresence: true,
  signingScope: 'full_wallet_signing',
  administrationScope: 'signing_only',
};
void ownerEquivalentDevicePolicy;

const scopedDevicePolicy: LinkedDevicePermissionPolicy = {
  kind: 'scoped_device_permission_v1',
  requiresLocalUserPresence: true,
  administrationScope: 'no_account_admin',
  mandatePolicy,
};
void scopedDevicePolicy;

// @ts-expect-error Owner-equivalent linked-device policy must not carry a mandate.
const invalidOwnerEquivalentDevicePolicy: LinkedDevicePermissionPolicy = {
  kind: 'owner_equivalent_device_permission_v1',
  requiresLocalUserPresence: true,
  signingScope: 'full_wallet_signing',
  administrationScope: 'signing_only',
  mandatePolicy,
};
void invalidOwnerEquivalentDevicePolicy;

// @ts-expect-error Scoped linked-device policy cannot grant account administration.
const invalidScopedDevicePolicy: LinkedDevicePermissionPolicy = {
  kind: 'scoped_device_permission_v1',
  requiresLocalUserPresence: true,
  administrationScope: 'device_management',
  mandatePolicy,
};
void invalidScopedDevicePolicy;

const ownerPasskeyLane: OwnerPasskeySigningLaneRecord = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId: ownerLaneId,
  laneKind: 'owner_passkey',
  laneShareEpoch,
  holderPrincipal: {
    kind: 'passkey_credential',
    rpId: 'example.localhost',
    credentialIdB64u: 'credential',
  },
  revocation: { status: 'active', revocationEpoch: 1 },
};
void ownerPasskeyLane;

const invalidOwnerPasskeyLane: OwnerPasskeySigningLaneRecord = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId: ownerLaneId,
  laneKind: 'owner_passkey',
  laneShareEpoch,
  holderPrincipal: {
    kind: 'passkey_credential',
    rpId: 'example.localhost',
    credentialIdB64u: 'credential',
  },
  revocation: { status: 'active', revocationEpoch: 1 },
  // @ts-expect-error Owner lanes must not carry delegate principals.
  delegatePrincipal: { agentId: agentPrincipalId, displayName: 'Agent', operatorId: null },
};
void invalidOwnerPasskeyLane;

const linkedDeviceLane: LinkedDeviceSigningLaneRecord = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId: targetLaneId,
  laneKind: 'linked_device',
  laneShareEpoch: targetLaneShareEpoch,
  holderPrincipal: {
    kind: 'linked_device_passkey',
    deviceId: linkedDeviceId,
    rpId: 'example.localhost',
    credentialIdB64u: 'credential',
    devicePublicKeyB64u: 'device-key',
  },
  devicePrincipal: {
    deviceId: linkedDeviceId,
    displayName: 'Laptop',
    platform: 'web',
  },
  permissionPolicy: ownerEquivalentDevicePolicy,
  revocation: { status: 'active', revocationEpoch: 1 },
};
void linkedDeviceLane;

const invalidLinkedDeviceLane: LinkedDeviceSigningLaneRecord = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId: targetLaneId,
  laneKind: 'linked_device',
  laneShareEpoch: targetLaneShareEpoch,
  holderPrincipal: {
    kind: 'linked_device_passkey',
    deviceId: linkedDeviceId,
    rpId: 'example.localhost',
    credentialIdB64u: 'credential',
    devicePublicKeyB64u: 'device-key',
  },
  permissionPolicy: ownerEquivalentDevicePolicy,
  revocation: { status: 'active', revocationEpoch: 1 },
  // @ts-expect-error Linked-device lanes must not carry delegate principals.
  delegatePrincipal: { agentId: agentPrincipalId, displayName: 'Agent', operatorId: null },
};
void invalidLinkedDeviceLane;

const delegatedAgentLane: DelegatedAgentSigningLaneRecord = {
  kind: 'signing_lane_reference_v1',
  walletId,
  walletKeyId,
  laneId: targetLaneId,
  laneKind: 'delegated_agent',
  laneShareEpoch: targetLaneShareEpoch,
  holderPrincipal: {
    kind: 'agent_custody_boundary',
    agentId: agentPrincipalId,
    custodyKeyId: 'custody-key',
    custodyRuntime: 'managed_service',
  },
  delegatePrincipal: { agentId: agentPrincipalId, displayName: 'Agent', operatorId: null },
  mandatePolicy,
  revocation: { status: 'active', revocationEpoch: 1 },
};
void delegatedAgentLane;

const laneCreationJob: SigningLaneCreationJob = {
  kind: 'signing_lane_creation',
  walletId,
  walletKeyId,
  sourceLaneId: ownerLaneId,
  sourceLaneShareEpoch: laneShareEpoch,
  targetLaneId,
  targetLaneKind: 'linked_device',
  targetLaneShareEpoch,
  permissionPolicyDigest: 'policy-digest',
  lifecycle: { state: 'preparing', operationId: rotationOperationId },
};
void laneCreationJob;

const invalidLaneCreationJob: SigningLaneCreationJob = {
  kind: 'signing_lane_creation',
  walletId,
  walletKeyId,
  sourceLaneId: ownerLaneId,
  sourceLaneShareEpoch: laneShareEpoch,
  targetLaneId,
  targetLaneKind: 'linked_device',
  permissionPolicyDigest: 'policy-digest',
  lifecycle: { state: 'preparing', operationId: rotationOperationId },
  // @ts-expect-error Lane creation uses targetLaneShareEpoch, not a generic laneShareEpoch.
  laneShareEpoch: targetLaneShareEpoch,
};
void invalidLaneCreationJob;

export {};
